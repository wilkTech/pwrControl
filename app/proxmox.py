# app/proxmox.py
# -*- coding: utf-8 -*-
from typing import List, Dict, Any
import time
import logging
import socket

try:
    from proxmoxer import ProxmoxAPI
    from proxmoxer.core import ResourceException
    _PROXMOX_AVAILABLE = True
except Exception:
    ProxmoxAPI = None
    ResourceException = Exception
    _PROXMOX_AVAILABLE = False

# opcjonalny WOL
try:
    from wakeonlan import send_magic_packet
    _WOL_AVAILABLE = True
except Exception:
    _WOL_AVAILABLE = False

# opcjonalny SSH fallback
try:
    import paramiko
    _PARAMIKO_AVAILABLE = True
except Exception:
    paramiko = None
    _PARAMIKO_AVAILABLE = False

import requests  # proxmoxer may raise requests exceptions
logger = logging.getLogger(__name__)


def _tcp_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


class ProxmoxHelper:
    def __init__(self, cfg: Any, logger_obj: logging.Logger = None):
        """
        Helper do komunikacji z Proxmox + opcjonalne WOL/SSH fallbacky.
        cfg: moĹźe byÄ AppConfig lub dict z kluczem 'proxmox'
        """
        self.cfg = cfg
        self.logger = logger_obj or logger

        prox_cfg = {}
        if hasattr(cfg, "proxmox"):
            prox_cfg = getattr(cfg, "proxmox") or {}
        elif isinstance(cfg, dict):
            prox_cfg = cfg.get("proxmox", {}) or {}

        self.nodes: Dict[str, str] = prox_cfg.get("nodes", {}) or {}
        self.nodes_mac: Dict[str, str] = prox_cfg.get("nodes_mac", {}) or {}
        self.node_creds: Dict[str, Dict[str, Any]] = prox_cfg.get("node_credentials", {}) or {}
        self.user = prox_cfg.get("user", "root@pam")
        self.token_name = prox_cfg.get("token_name", "")
        self.token_value = prox_cfg.get("token_value", "")
        self.password = prox_cfg.get("password", "")
        self.verify_ssl = prox_cfg.get("verify_ssl", False)
        self.timeout = int(prox_cfg.get("timeout", 10))
        self.cooldown = int(prox_cfg.get("cooldown_seconds", 60))

        # optional logging control (kept for compatibility with previous suggestions)
        self.log_reachability: bool = bool(prox_cfg.get("log_reachability", True))
        nodes_quiet = prox_cfg.get("nodes_quiet", []) or []
        try:
            self.nodes_quiet = set([str(x) for x in nodes_quiet])
        except Exception:
            self.nodes_quiet = set()

        # internal state
        self.node_fail_until: Dict[str, float] = {}
        self.node_state: Dict[str, str] = {}

    @classmethod
    def is_available(cls) -> bool:
        return _PROXMOX_AVAILABLE

    def _ensure_available(self):
        if not _PROXMOX_AVAILABLE:
            raise RuntimeError("proxmoxer not installed")

    def _connect(self, host: str):
        """Stara logika retry connect (z proxmoxer)."""
        self._ensure_available()
        def do_connect():
            if self.token_name and self.token_value:
                return ProxmoxAPI(host,
                                  user=self.user,
                                  token_name=self.token_name,
                                  token_value=self.token_value,
                                  verify_ssl=self.verify_ssl,
                                  timeout=self.timeout)
            return ProxmoxAPI(host,
                              user=self.user,
                              password=self.password,
                              verify_ssl=self.verify_ssl,
                              timeout=self.timeout)

        tries = 3
        wait = 0.5
        while True:
            try:
                return do_connect()
            except Exception as e:
                tries -= 1
                self.logger.warning("Proxmox connect error to %s: %s (%s tries left)", host, e, tries)
                if tries <= 0:
                    raise
                time.sleep(wait)
                wait *= 2

    def get_vm_ips(self, node: str, vmtype: str, vmid: int) -> List[str]:
        """
        Pobiera adresy IP VM (qemu z agentem lub lxc).
        Zwraca listÄ IP (ipv4 przed ipv6).
        """
        ips: List[str] = []
        host = self.nodes.get(node)
        if not host:
            return ips
        try:
            p = self._connect(host)
            cur = None
            if vmtype == "qemu":
                cur = p.nodes(node).qemu(vmid).status.current.get()
            elif vmtype == "lxc":
                cur = p.nodes(node).lxc(vmid).status.current.get()
            else:
                return ips

            status = (cur or {}).get("status") or (cur or {}).get("state")
            if status != "running":
                return ips

            if vmtype == "qemu":
                try:
                    res = p.nodes(node).qemu(vmid).agent("network-get-interfaces").get()
                    for iface in res.get("result", []) or []:
                        for a in iface.get("ip-addresses", []) or []:
                            ip = (a or {}).get("ip-address")
                            if ip and ip not in ips:
                                ips.append(ip)
                except Exception:
                    # agent unavailable or failed - ignore
                    pass
            else:
                try:
                    res = p.nodes(node).lxc(vmid).ips.get()
                    for nic in res or []:
                        for ipobj in nic.get("ips", []) or []:
                            ip = (ipobj or {}).get("ip")
                            if ip and ip not in ips:
                                ips.append(ip)
                except Exception:
                    try:
                        cfg = p.nodes(node).lxc(vmid).config.get()
                        for k, v in (cfg or {}).items():
                            if k.startswith("net") and isinstance(v, str) and "ip=" in v:
                                for part in v.split(","):
                                    part = part.strip()
                                    if part.startswith("ip="):
                                        ip = part.split("=", 1)[1].split("/")[0]
                                        if ip and ip not in ips:
                                            ips.append(ip)
                    except Exception:
                        pass

            ipv4 = [x for x in ips if ":" not in x]
            ipv6 = [x for x in ips if ":" in x]
            return ipv4 + ipv6
        except Exception as e:
            self.logger.exception("get_vm_ips error: %s", e)
            return ips

    def list_all_vms(self) -> List[Dict[str, Any]]:
        """
        Lista wszystkich VMs i LXC na wszystkich skonfigurowanych wÄzĹach.
        Zwraca listÄ dictĂłw z kluczami: node,type,vmid,name,status,uptime,ips
        """
        results: List[Dict[str, Any]] = []
        if not _PROXMOX_AVAILABLE:
            raise RuntimeError("proxmoxer not installed")

        for node_name, host in (self.nodes or {}).items():
            try:
                wait = self.node_fail_until.get(node_name, 0)
                if time.time() < wait:
                    # muted due to previous failures
                    continue
                p = self._connect(host)

                if self.node_state.get(node_name) == "offline":
                    if self.log_reachability and node_name not in self.nodes_quiet:
                        self.logger.info("Proxmox node %s (%s) back online", node_name, host)
                self.node_state[node_name] = "online"

                # qemu
                try:
                    qemus = p.nodes(node_name).qemu.get() or []
                except Exception:
                    qemus = []
                for vm in qemus:
                    vmid = vm.get("vmid")
                    status = vm.get("status")
                    ip_list: List[str] = []
                    if vmid is not None and status == "running":
                        try:
                            ip_list = self.get_vm_ips(node_name, "qemu", int(vmid))
                        except Exception:
                            ip_list = []
                    results.append({
                        "node": node_name,
                        "type": "qemu",
                        "vmid": vmid,
                        "name": vm.get("name") or vmid,
                        "status": status,
                        "uptime": vm.get("uptime", 0),
                        "ips": ip_list,
                    })

                # lxc
                try:
                    lxcs = p.nodes(node_name).lxc.get() or []
                except Exception:
                    lxcs = []
                for ct in lxcs:
                    vmid = ct.get("vmid")
                    status = ct.get("status")
                    ip_list: List[str] = []
                    if vmid is not None and status == "running":
                        try:
                            ip_list = self.get_vm_ips(node_name, "lxc", int(vmid))
                        except Exception:
                            ip_list = []
                    results.append({
                        "node": node_name,
                        "type": "lxc",
                        "vmid": vmid,
                        "name": ct.get("name") or vmid,
                        "status": status,
                        "uptime": ct.get("uptime", 0),
                        "ips": ip_list,
                    })
            except Exception as e:
                # transition to offline + mute for cooldown
                if self.node_state.get(node_name) != "offline":
                    if self.log_reachability and node_name not in self.nodes_quiet:
                        self.logger.info("Proxmox node %s (%s) unreachable â muting errors for %ss", node_name, host, self.cooldown)
                self.node_state[node_name] = "offline"
                self.node_fail_until[node_name] = time.time() + float(self.cooldown)
        return results

    def vm_action(self, node: str, vmtype: str, vmid: int, action: str) -> Dict[str, Any]:
        """
        Akcje na VM (start, shutdown, stop, reset for qemu)
        """
        host = self.nodes.get(node)
        if not host:
            return {"success": False, "message": f"Unknown node '{node}'."}
        try:
            p = self._connect(host)
            if vmtype == "qemu":
                obj = p.nodes(node).qemu(vmid).status
            elif vmtype == "lxc":
                obj = p.nodes(node).lxc(vmid).status
            else:
                return {"success": False, "message": "Invalid VM type 'qemu' or 'lxc' expected."}

            action = action.lower()
            if action == "start":
                res = obj.start.post()
            elif action == "shutdown":
                res = obj.shutdown.post()
            elif action == "stop":
                res = obj.stop.post()
            elif action == "reset" and vmtype == "qemu":
                res = obj.reset.post()
            else:
                return {"success": False, "message": f"Action '{action}' unsupported for type '{vmtype}'."}

            taskid = res.get("upid") if isinstance(res, dict) else None
            return {"success": True, "taskid": taskid, "message": "Command sent."}
        except Exception as e:
            self.logger.exception("vm_action error: %s", e)
            return {"success": False, "message": str(e)}

    def node_action(self, node: str, action: str) -> Dict[str, Any]:
        """
        Node-level actions: 'shutdown', 'reboot', 'wake' (WOL)
        If proxmox API doesn't implement shutdown/reboot -> fallback to SSH (if paramiko + credentials provided).
        """
        action = (action or "").lower()
        host = self.nodes.get(node)
        if not host:
            return {"success": False, "message": f"Unknown node '{node}'"}

        if action == "wake":
            mac = self.nodes_mac.get(node)
            if not mac:
                return {"success": False, "message": f"No MAC configured for node {node} (nodes_mac.{node})"}
            if not _WOL_AVAILABLE:
                return {"success": False, "message": "wakeonlan not installed on server"}
            try:
                send_magic_packet(mac)
                return {"success": True, "message": f"WOL packet sent to {node} ({mac})"}
            except Exception as e:
                self.logger.exception("WOL error for %s", node)
                return {"success": False, "message": f"WOL failed: {e}"}

        if action in ("shutdown", "reboot"):
            # try API first
            try:
                p = None
                try:
                    p = self._connect(host)
                except Exception as e:
                    self.logger.warning("Cannot connect to proxmox host %s for node %s: %s", host, node, e)
                    p = None

                if p:
                    try:
                        if action == "shutdown":
                            res = p.nodes(node).status.shutdown.post()
                        else:
                            res = p.nodes(node).status.reboot.post()
                        return {"success": True, "message": "Proxmox API invoked", "result": res}
                    except ResourceException as e:
                        # API returned not implemented / resource error -> fallback to SSH
                        self.logger.warning("Proxmox API node %s %s not implemented: %s", node, action, e)
                    except requests.exceptions.ConnectionError as e:
                        # network-level error to proxmox host => node likely unreachable
                        self.logger.warning("Proxmox API node %s %s error: %s", node, action, e)
                        return {"success": False, "message": "Proxmox API unreachable (node may be powered off or network down)"}
                    except Exception as e:
                        self.logger.warning("Proxmox API node %s %s error: %s", node, action, e, exc_info=True)
                else:
                    self.logger.info("Skipping Proxmox API for node %s (no proxmox connection)", node)
            except Exception:
                self.logger.exception("Unexpected error while trying Proxmox API for node_action")

            # SSH fallback
            creds = {}
            if isinstance(self.node_creds, dict):
                creds = self.node_creds.get(node, {}) or self.node_creds.get("default", {}) or {}
            ssh_user = creds.get("user") or creds.get("username") or "root"
            ssh_pass = creds.get("password") or creds.get("passwd") or None
            ssh_port = int(creds.get("port", 22) or 22)

            if not _PARAMIKO_AVAILABLE:
                return {"success": False, "message": "paramiko not installed and Proxmox API not available for node actions"}

            # quick TCP check
            if not _tcp_port_open(host, ssh_port, timeout=2.0):
                self.logger.warning("SSH port %s on %s not reachable; skipping SSH fallback", ssh_port, host)
                return {"success": False, "message": f"Host {host} not reachable on port {ssh_port} (node probably down or network unreachable)"}

            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                if ssh_pass:
                    client.connect(host, port=ssh_port, username=ssh_user, password=ssh_pass, timeout=10)
                else:
                    client.connect(host, port=ssh_port, username=ssh_user, timeout=10)

                if action == "shutdown":
                    cmd = (
                        "if command -v sudo >/dev/null 2>&1; then "
                        "sudo -n systemctl poweroff || sudo -n poweroff || /sbin/poweroff || shutdown -h now; "
                        "else "
                        "systemctl poweroff || poweroff || /sbin/poweroff || shutdown -h now; "
                        "fi"
                    )
                else:
                    cmd = (
                        "if command -v sudo >/dev/null 2>&1; then "
                        "sudo -n systemctl reboot || sudo -n reboot || /sbin/reboot || shutdown -r now; "
                        "else "
                        "systemctl reboot || reboot || /sbin/reboot || shutdown -r now; "
                        "fi"
                    )

                stdin, stdout, stderr = client.exec_command(cmd)
                out = stdout.read().decode(errors="ignore").strip()
                err = stderr.read().decode(errors="ignore").strip()
                client.close()

                if err:
                    self.logger.info("SSH node %s %s -> out=%s err=%s", node, action, out[:400], err[:400])
                    return {"success": True, "message": f"SSH command executed (stderr: {err[:200]})", "out": out, "err": err}
                else:
                    self.logger.info("SSH node %s %s -> out=%s err=%s", node, action, out[:400], err[:400])
                    return {"success": True, "message": "SSH command executed", "out": out}
            except Exception as e:
                self.logger.exception("SSH node %s %s failed", node, action)
                return {"success": False, "message": f"SSH fallback failed: {e}"}

        return {"success": False, "message": f"Unsupported action '{action}'"}
