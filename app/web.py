# app/web.py
# -*- coding: utf-8 -*-
"""
Enhanced PowerControl Web API with improved dependency injection,
consistent error handling, better UX support, and Relay 5 dependency logic.

IMPROVEMENTS (2025-10-17):
- Added relay field to computer config (which relay powers the host)
- Check relay state before pinging hosts
- Improved ping implementation with better timeout and error handling
- Real-time status detection in /hosts/list endpoint
- Added status reasons for better debugging
"""

import os
import json
import time
import logging
from threading import Thread, Event
from typing import Any, Optional, Dict, List
from flask import Flask, render_template, jsonify, request, Response, stream_with_context, make_response

from .relay import RelayController
from .proxmox import ProxmoxHelper
from .emailer import Emailer

logger = logging.getLogger(__name__)

# Project paths (assume package layout: app/)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

flask_app = Flask(__name__, static_folder=STATIC_DIR, template_folder=TEMPLATES_DIR)


class PowerControlWeb:
    def __init__(
        self,
        cfg: Any,
        app_logger: logging.Logger,
        emailer: Optional[Any] = None,
        relay: Optional[Any] = None,
        proxmox: Optional[Any] = None,
        monitor: Optional[Any] = None,
    ):
        """
        Enhanced PowerControl Web Service with proper dependency injection.

        Args:
            cfg: Configuration object (dataclass or dict-like)
            app_logger: Logger instance
            emailer: Optional Emailer instance (uses DI if provided)
            relay: Optional RelayController instance (uses DI if provided)
            proxmox: Optional ProxmoxHelper instance (uses DI if provided)
            monitor: Optional Monitor instance (uses DI if provided)
        """
        self.cfg = cfg
        self.logger = app_logger or logger
        self.running = False
        self._stop_event = Event()

        # Enhanced dependency injection - prefer passed instances
        self.emailer = emailer
        self.relay = relay
        self.proxmox = proxmox
        self.monitor = monitor

        # Get relay count from config instead of hardcoding
        self.relay_count = len(getattr(cfg, 'relay_pins', [])) or 8

        # Register routes after components are ready
        self._register_routes()

        # Thread handle for flask server
        self.server_thread: Optional[Thread] = None
        self._server = None  # Werkzeug server instance for proper shutdown
        self.logger.debug(f"PowerControlWeb initialized with {self.relay_count} relays")

    def get_relay_states(self) -> List[Dict[str, Any]]:
        """Get relay states with simplified, robust fallback logic.
        
        Returns:
            List[Dict]: [{'id': int, 'on': bool}, ...]
        """
        if not self.relay:
            # No relay controller - return all OFF
            return [{'id': i + 1, 'on': False} for i in range(self.relay_count)]

        try:
            # Try primary method first
            if hasattr(self.relay, 'get_status') and callable(getattr(self.relay, 'get_status')):
                states = self.relay.get_status()
                if states and isinstance(states, list):
                    return states
        except Exception as e:
            self.logger.debug(f"get_status() failed: {e}")

        try:
            # Fallback to direct relay access
            if hasattr(self.relay, 'Relays'):
                relays = getattr(self.relay, 'Relays', [])
                return [
                    {'id': i + 1, 'on': bool(getattr(relay, 'is_lit', False))}
                    for i, relay in enumerate(relays)
                ]
        except Exception as e:
            self.logger.debug(f"Direct relay access failed: {e}")

        # Final fallback - all OFF
        return [{'id': i + 1, 'on': False} for i in range(self.relay_count)]

    def _should_fetch_proxmox_vms(self) -> bool:
        """
        Sprawdź czy należy pobrać VM z Proxmox na podstawie relay rules.
        
        Config:
            proxmox.vm_fetch_relays: [2, 8]  # Lista relay IDs
        
        Returns:
            bool: True - pobierz VM, False - pomiń (zwróć pusty array)
        """
        try:
            # Pobierz konfigurację Proxmox
            proxmox_cfg = getattr(self.cfg, 'proxmox', {}) or {}
            
            # Pobierz listę wymaganych relay
            vm_fetch_relays = proxmox_cfg.get('vm_fetch_relays', [])
            
            # Jeśli brak konfiguracji → zawsze pobieraj (backward compatible)
            if not vm_fetch_relays or not isinstance(vm_fetch_relays, list):
                return True
            
            # Sprawdź czy którykolwiek z wymaganych relay jest ON (OR logic)
            for relay_id in vm_fetch_relays:
                if isinstance(relay_id, int) and 1 <= relay_id <= 8:
                    relay_on = self.get_relay_state(relay_id)
                    
                    if relay_on:
                        self.logger.debug(f"Relay {relay_id} is ON - will fetch Proxmox VMs")
                        return True  # Wystarczy jeden relay ON
            
            # Wszystkie wymagane relay są OFF
            self.logger.debug(f"All required relays {vm_fetch_relays} are OFF - skipping Proxmox VM fetch")
            return False
        
        except Exception as e:
            self.logger.debug(f"Error checking Proxmox VM fetch condition: {e}")
            # W razie błędu - bezpieczny fallback: pobierz VM
            return True

    def standardize_error_response(self, error_message: str, status_code: int = 500) -> tuple:
        """Create standardized JSON error response."""
        import time
        return jsonify({
            'success': False,
            'error': error_message,
            'timestamp': int(time.time())
        }), status_code

    def standardize_success_response(self, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create standardized JSON success response."""
        import time
        response = {
            'success': True,
            'timestamp': int(time.time())
        }
        if data:
            response.update(data)
        return response

    def find_host_config(self, host_id):
        """Znajdź konfigurację hosta po ID."""
        # Sprawdź computers
        computers = getattr(self.cfg, 'computers', {}) or {}
        if host_id in computers:
            comp = computers[host_id]
            return {
                'name': host_id,
                'ip': comp.get('IP', ''),
                'mac': comp.get('MAC', ''),
                'os': comp.get('OS', 'unknown'),
                'username': comp.get('Username', ''),
                'password': comp.get('Password', ''),
                'relay': comp.get('relay'),  # NOWE POLE
                'type': 'computer'
            }

        # Sprawdź proxmox nodes
        proxmox_cfg = getattr(self.cfg, 'proxmox', {}) or {}
        nodes = proxmox_cfg.get('nodes', {}) or {}
        nodes_mac = proxmox_cfg.get('nodes_mac', {}) or {}
        nodes_relay = proxmox_cfg.get('nodes_relay', {}) or {}

        if host_id in nodes:
            # Pobierz dane logowania z node_credentials - z bezpiecznym fallbackiem
            credentials = proxmox_cfg.get('node_credentials', {}) or {}
            default_creds = credentials.get('default', {}) or {}
            node_creds = credentials.get(host_id, {}) or {}

            username = node_creds.get('user') if node_creds else None
            if not username:
                username = default_creds.get('user', 'root')

            password = node_creds.get('password') if node_creds else None
            if not password:
                password = default_creds.get('password', '')

            port = node_creds.get('port') if node_creds else None
            if not port:
                port = default_creds.get('port', 22)

            return {
                'name': host_id,
                'ip': nodes[host_id],
                'mac': nodes_mac.get(host_id, ''),
                'os': 'linux',
                'username': username,
                'password': password,
                'port': port,
                'relay': nodes_relay.get(host_id),  # Proxmox nodes zazwyczaj bez relay
                'type': 'proxmox_node'
            }

        return None

    def execute_ssh_command(self, host, command):
        try:
            import paramiko
            
            ip = host.get('ip')
            username = host.get('username', 'root')
            password = host.get('password', '')
            port = int(host.get('port', 22))
            os_type = host.get('os', 'linux').lower()
            
            # Szczegółowa walidacja
            if not ip:
                self.logger.error(f"Missing IP address for {host.get('name')}")
                return False
            if not username:
                self.logger.error(f"Missing username for {host.get('name')}")
                return False
            if not password:
                self.logger.error(f"Missing password for {host.get('name')}")
                return False
            
            # ✅ POPRAWKA 1: Root nie używa sudo
            if username == 'root':
                if os_type == 'windows':
                    commands = {
                        'shutdown': 'shutdown /s /t 0',
                        'reboot': 'shutdown /r /t 0'
                    }
                else:
                    commands = {
                        'shutdown': 'shutdown -h now',      # BEZ sudo
                        'reboot': 'reboot'                  # BEZ sudo
                    }
            else:
                # Nie-root użytkownik potrzebuje sudo
                if os_type == 'windows':
                    commands = {
                        'shutdown': 'shutdown /s /t 0',
                        'reboot': 'shutdown /r /t 0'
                    }
                else:
                    commands = {
                        'shutdown': 'sudo shutdown -h now',  # Z sudo
                        'reboot': 'sudo reboot'              # Z sudo
                    }
            
            cmd = commands.get(command)
            if not cmd:
                self.logger.error(f"Unknown command: {command}")
                return False
            
            # ✅ POPRAWKA 2: Dodaj parametry dla lepszej kompatybilności
            self.logger.info(f"Attempting SSH to {ip}:{port} as {username} (OS: {os_type})")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                ssh.connect(
                    hostname=ip,
                    port=port,
                    username=username,
                    password=password,
                    timeout=30,                    # Zwiększony timeout
                    look_for_keys=False,          # Nie szukaj kluczy SSH
                    allow_agent=False,            # Nie używaj SSH agent
                    banner_timeout=30             # Timeout dla SSH banner
                )
            except paramiko.AuthenticationException:
                self.logger.error(f"SSH authentication failed for {host.get('name')} - check username/password")
                return False
            except Exception as e:
                self.logger.error(f"SSH connection failed for {host.get('name')}: {e}")
                return False
            
            # ✅ POPRAWKA 3: Wykonaj polecenie z get_pty dla sudo
            self.logger.info(f"Executing: {cmd}")
            if username != 'root' and os_type != 'windows':
                # Dla sudo potrzebujemy PTY
                stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
            else:
                stdin, stdout, stderr = ssh.exec_command(cmd)
            
            # Krótkie oczekiwanie na output (dla Windows)
            if os_type == 'windows':
                import time
                time.sleep(1)
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    error_msg = stderr.read().decode('utf-8', errors='ignore')
                    self.logger.error(f"Command failed (exit {exit_status}): {error_msg}")
                    ssh.close()
                    return False
            
            ssh.close()
            self.logger.info(f"SSH command '{command}' sent successfully to {ip}")
            return True
            
        except ImportError:
            self.logger.error("paramiko library not available")
            self.logger.error("Install: pip install paramiko")
            return False
        except Exception as e:
            self.logger.error(f"SSH command '{command}' failed: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return False

    # ======= SNAPSHOT HELPERS FOR SSE =======
    def _snapshot_hosts(self) -> List[Dict[str, Any]]:
        """Zwróć listę hostów ze statusem (używane w SSE)."""
        hosts: List[Dict[str, Any]] = []
        try:
            computers = getattr(self.cfg, 'computers', {}) or {}
            proxmox_cfg = getattr(self.cfg, 'proxmox', {}) or {}
            proxmox_nodes = proxmox_cfg.get('nodes', {}) or {}
            proxmox_macs = proxmox_cfg.get('nodes_mac', {}) or {}
            proxmox_relays = proxmox_cfg.get('nodes_relay', {}) or {}

            for name, info in computers.items():
                ip = info.get('IP', '')
                relay_id = info.get('relay')
                if ip:
                    status_info = self.check_host_status(ip, relay_id)
                    status = status_info['status']
                    status_reason = status_info['reason']
                else:
                    status = 'unknown'
                    status_reason = 'No IP configured'

                hosts.append({
                    'hostname': name,
                    'name': name,
                    'ip': ip,
                    'mac': info.get('MAC', ''),
                    'os': info.get('OS', 'unknown'),
                    'relay': relay_id,
                    'status': status,
                    'status_reason': status_reason,
                    'type': 'computer'
                })

            for node_name, node_ip in proxmox_nodes.items():
                relay_id = proxmox_relays.get(node_name)
                if node_ip:
                    status_info = self.check_host_status(node_ip, relay_id)
                    status = status_info['status']
                    status_reason = status_info['reason']
                else:
                    status = 'unknown'
                    status_reason = 'No IP configured'

                hosts.append({
                    'hostname': node_name,
                    'name': node_name,
                    'ip': node_ip,
                    'mac': proxmox_macs.get(node_name, ''),
                    'os': 'linux',
                    'relay': relay_id,
                    'status': status,
                    'status_reason': status_reason,
                    'type': 'proxmox_node'
                })
        except Exception as e:
            self.logger.exception("Error building hosts snapshot: %s", e)
        return hosts

    def _snapshot_vms(self) -> List[Dict[str, Any]]:
        """Zwróć listę VM (używane w SSE)."""
        if not self.proxmox or not getattr(self.proxmox, 'is_available', lambda: False)():
            return []
        try:
            # Użyj istniejącej logiki warunkowego fetchu
            if not self._should_fetch_proxmox_vms():
                return []
            return self.proxmox.list_all_vms() or []
        except Exception as e:
            self.logger.exception("Error building VMs snapshot: %s", e)
            return []

    def ping_host(self, ip: str, timeout: int = 2, count: int = 1) -> bool:
        """
        Ping hosta i zwróć czy jest dostępny.
        
        Args:
            ip: IP address to ping
            timeout: Timeout w sekundach (default: 2)
            count: Liczba pakietów (default: 1)
        
        Returns:
            bool: True jeśli host odpowiada
        """
        try:
            import subprocess
            import platform

            if not ip or ip.strip() == '':
                return False

            system = platform.system().lower()

            if system == 'windows':
                # Windows: -n count, -w timeout_ms
                cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), ip]
            else:
                # Linux/Unix: -c count, -W timeout_sec
                cmd = ['ping', '-c', str(count), '-W', str(timeout), ip]

            # Zwiększony timeout dla subprocess (timeout + 1s buffer)
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout + 1,
                check=False  # Nie rzucaj wyjątku na non-zero exit code
            )

            # return code 0 = host odpowiada
            success = result.returncode == 0

            if success:
                self.logger.debug(f"Ping successful for {ip}")
            else:
                self.logger.debug(f"Ping failed for {ip} (returncode: {result.returncode})")

            return success

        except subprocess.TimeoutExpired:
            self.logger.debug(f"Ping timeout for {ip}")
            return False
        except FileNotFoundError:
            self.logger.warning("ping command not found in system PATH")
            return False
        except Exception as e:
            self.logger.debug(f"Ping failed for {ip}: {e}")
            return False

    def get_relay_state(self, relay_id: int) -> bool:
        """
        Sprawdź czy przekaźnik jest włączony.
        
        Args:
            relay_id: Numer przekaźnika (1-8)
        
        Returns:
            bool: True jeśli włączony, False jeśli wyłączony
        """
        if not self.relay:
            return False

        try:
            idx = relay_id - 1

            # Metoda 1: Bezpośredni dostęp do Relays
            if hasattr(self.relay, 'Relays'):
                relays = getattr(self.relay, 'Relays', [])
                if 0 <= idx < len(relays):
                    relay = relays[idx]
                    if hasattr(relay, 'is_lit'):
                        return bool(relay.is_lit)

            # Metoda 2: get_status()
            if hasattr(self.relay, 'get_status'):
                states = self.relay.get_status()
                if states and isinstance(states, list) and 0 <= idx < len(states):
                    return bool(states[idx].get('on', False))

        except Exception as e:
            self.logger.debug(f"Error checking relay {relay_id} state: {e}")

        return False

    def check_host_status(self, ip: str, relay_id: int = None) -> dict:
        """
        Sprawdź status hosta z uwzględnieniem stanu przekaźnika.
        
        Args:
            ip: IP address hosta
            relay_id: Opcjonalny numer przekaźnika zasilającego host (1-8)
        
        Returns:
            dict: {
                'status': 'online'|'offline'|'powered_off'|'unknown',
                'reachable': bool,
                'relay_on': bool|None,
                'reason': str  # Wyjaśnienie statusu
            }
        """
        result = {
            'status': 'unknown',
            'reachable': False,
            'relay_on': None,
            'reason': ''
        }

        if not ip or ip.strip() == '':
            result['reason'] = 'No IP configured'
            return result

        # Sprawdź stan przekaźnika jeśli podany
        if relay_id is not None and 1 <= relay_id <= 8:
            relay_on = self.get_relay_state(relay_id)
            result['relay_on'] = relay_on

            if not relay_on:
                # Przekaźnik wyłączony = host nie ma zasilania
                result['status'] = 'powered_off'
                result['reason'] = f'Relay {relay_id} is OFF'
                return result

        # Przekaźnik włączony lub nie skonfigurowany - sprawdź ping
        reachable = self.ping_host(ip, timeout=2, count=1)
        result['reachable'] = reachable

        if reachable:
            result['status'] = 'online'
            result['reason'] = 'Host responds to ping'
        else:
            # Host nie odpowiada mimo że przekaźnik włączony
            if result['relay_on']:
                result['status'] = 'offline'
                result['reason'] = 'Relay ON but host not responding'
            else:
                result['status'] = 'offline'
                result['reason'] = 'Host not responding to ping'

        return result

    def _register_routes(self):
        app = flask_app

        @app.route('/favicon.ico')
        @app.route('/favicon.png')
        def favicon():
            fav = os.path.join(STATIC_DIR, 'favicon.png')
            if os.path.isfile(fav):
                return flask_app.send_static_file('favicon.png')
            return '', 204

        @app.route('/events')
        def events():
            """Server-Sent Events stream: relays + hosts + VMs."""
            def event_stream():
                relay_interval = 3.0
                host_interval = 15.0
                vm_interval = 20.0
                next_relay = next_hosts = next_vms = 0.0

                while not self._stop_event.is_set():
                    now = time.monotonic()

                    if now >= next_relay:
                        try:
                            payload = {"type": "relays", "relays": self.get_relay_states()}
                            yield f"data:{json.dumps(payload)}\n\n"
                        except Exception as e:
                            self.logger.debug(f"SSE relay payload error: {e}")
                        next_relay = now + relay_interval

                    if now >= next_hosts:
                        try:
                            payload = {"type": "hosts", "hosts": self._snapshot_hosts()}
                            yield f"data:{json.dumps(payload)}\n\n"
                        except Exception as e:
                            self.logger.debug(f"SSE hosts payload error: {e}")
                        next_hosts = now + host_interval

                    if now >= next_vms:
                        try:
                            payload = {"type": "vms", "vms": self._snapshot_vms()}
                            yield f"data:{json.dumps(payload)}\n\n"
                        except Exception as e:
                            self.logger.debug(f"SSE vms payload error: {e}")
                        next_vms = now + vm_interval

                    # keep-alive comment every loop to prevent idle timeouts
                    yield ": keep-alive\n\n"

                    if self._stop_event.wait(0.5):
                        break

            headers = {
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"
            }
            return Response(stream_with_context(event_stream()), mimetype='text/event-stream', headers=headers)

        @app.route('/healthz')
        def healthz():
            return jsonify({
                'ok': True,
                'components': {
                    'relay': bool(self.relay and hasattr(self.relay, 'Relays')),
                    'proxmox': bool(self.proxmox and getattr(self.proxmox, 'is_available', lambda: False)()),
                    'emailer': bool(self.emailer),
                    'monitor': bool(self.monitor)
                },
                'relay_count': self.relay_count
            })

        @app.route('/')
        def index():
            try:
                states = self.get_relay_states()
                relay_status = []
                for s in states:
                    status_txt = 'on (włączony)' if s.get('on') else 'off (wyłączony)'
                    relay_status.append({
                        'id': s.get('id'),
                        'status': status_txt,
                        'on': s.get('on')
                    })
                computers = getattr(self.cfg, 'computers', {}) or {}
                # Pobierz konfigurację quick_start_vms dla przekaźników 2 i 8
                proxmox_cfg = getattr(self.cfg, 'proxmox', {}) or {}
                quick_start_vms = proxmox_cfg.get('quick_start_vms', {}) or {}
                response = make_response(render_template('index.html', relay_status=relay_status, computers=computers, relay_count=self.relay_count, quick_start_vms=quick_start_vms))
                # Explicitly set Content-Type with charset to prevent proxy encoding issues
                response.headers['Content-Type'] = 'text/html; charset=utf-8'
                return response
            except Exception as e:
                self.logger.exception("Error rendering index page")
                # Fallback relay status
                relay_status = [{'id': i + 1, 'status': 'off (wyłączony)', 'on': False} for i in range(self.relay_count)]
                computers = {}
                quick_start_vms = {}
                response = make_response(render_template('index.html', relay_status=relay_status, computers=computers, relay_count=self.relay_count, quick_start_vms=quick_start_vms))
                # Explicitly set Content-Type with charset to prevent proxy encoding issues
                response.headers['Content-Type'] = 'text/html; charset=utf-8'
                return response

        # RELAY CONTROL ENDPOINTS
        @app.route('/relay/<int:relay_id>/<action>', methods=['POST'])
        def control_relay(relay_id, action):
            if not self.relay:
                return self.standardize_error_response("Relay controller not available", 503)

            if action not in ['on', 'off']:
                return self.standardize_error_response("Valid actions: 'on', 'off'", 400)

            if not (1 <= relay_id <= self.relay_count):
                return self.standardize_error_response(f"Relay ID must be 1-{self.relay_count}", 400)

            try:
                idx = relay_id - 1
                if action == 'on':
                    if hasattr(self.relay, 'turn_on'):
                        self.relay.turn_on(idx)
                    elif hasattr(self.relay, 'set_relay'):
                        self.relay.set_relay(idx, True)
                    else:
                        return self.standardize_error_response("Relay turn_on not supported", 501)
                else:  # action == 'off'
                    if hasattr(self.relay, 'turn_off'):
                        self.relay.turn_off(idx)
                    elif hasattr(self.relay, 'set_relay'):
                        self.relay.set_relay(idx, False)
                    else:
                        return self.standardize_error_response("Relay turn_off not supported", 501)

                # CRITICAL: Call Relay 5 dependency logic after any relay change
                # FIXED: Don't call for relay 5 itself to prevent recursion
                if relay_id != 5 and hasattr(self.relay, 'control_relay_19'):
                    try:
                        self.relay.control_relay_19()
                        self.logger.debug(f"control_relay_19() called after relay {relay_id} {action}")
                    except Exception as e:
                        self.logger.debug(f"control_relay_19() failed after relay {relay_id} {action}: {e}")

                return jsonify(self.standardize_success_response({'relay_id': relay_id, 'action': action}))

            except Exception as e:
                self.logger.exception(f"Error controlling relay {relay_id}")
                return self.standardize_error_response(str(e), 500)

        @app.route('/relay/<int:relay_id>/notify', methods=['POST'])
        def set_relay_notify(relay_id):
            if not self.relay:
                return self.standardize_error_response("Relay controller not available", 503)

            if not (1 <= relay_id <= self.relay_count):
                return self.standardize_error_response(f"Relay ID must be 1-{self.relay_count}", 400)

            try:
                data = request.get_json(silent=True) or {}
                if 'enabled' not in data:
                    return self.standardize_error_response("Missing 'enabled' field", 400)

                enabled = bool(data.get('enabled'))

                if not hasattr(self.relay, 'set_notification_enabled'):
                    return self.standardize_error_response("Relay notifications not supported", 501)

                success = self.relay.set_notification_enabled(relay_id, enabled)
                if not success:
                    return self.standardize_error_response(f"Failed to update relay {relay_id} notifications", 500)

                return jsonify(self.standardize_success_response({'relay_id': relay_id, 'enabled': enabled}))

            except Exception as e:
                self.logger.exception(f"Error setting relay {relay_id} notifications")
                return self.standardize_error_response(str(e), 500)

        @app.route('/debug/relay_notifications', methods=['GET'])
        def debug_relay_notifications():
            if not self.relay:
                return self.standardize_error_response("Relay controller not available", 503)

            try:
                if not hasattr(self.relay, 'get_notification_states'):
                    return self.standardize_error_response("Notifications not supported", 501)

                states = self.relay.get_notification_states() or {}

                # Normalize notification states
                normalized = {}
                for relay_id, state in states.items():
                    try:
                        if isinstance(state, dict):
                            normalized[str(relay_id)] = bool(state.get('enabled', False))
                        else:
                            normalized[str(relay_id)] = bool(state)
                    except Exception:
                        normalized[str(relay_id)] = False

                return jsonify(self.standardize_success_response({'notifications': normalized}))

            except Exception as e:
                self.logger.exception("Error getting relay notifications")
                return self.standardize_error_response(str(e), 500)

        @app.route('/allon', methods=['POST'])
        def all_on():
            if not self.relay:
                return self.standardize_error_response("Relay controller not available", 503)

            try:
                if hasattr(self.relay, 'turn_on_all'):
                    self.relay.turn_on_all()
                else:
                    return self.standardize_error_response("turn_on_all not supported", 501)

                # CRITICAL: Call Relay 5 dependency logic after allon
                if hasattr(self.relay, 'control_relay_19'):
                    try:
                        self.relay.control_relay_19()
                        self.logger.debug("control_relay_19() called after allon")
                    except Exception as e:
                        self.logger.debug(f"control_relay_19() failed after allon: {e}")

                return jsonify(self.standardize_success_response())

            except Exception as e:
                self.logger.exception("Error turning all relays on")
                return self.standardize_error_response(str(e), 500)

        @app.route('/alloff', methods=['POST'])
        def all_off():
            if not self.relay:
                return self.standardize_error_response("Relay controller not available", 503)

            try:
                if hasattr(self.relay, 'turn_off_all'):
                    self.relay.turn_off_all()
                else:
                    return self.standardize_error_response("turn_off_all not supported", 501)

                # CRITICAL: Call Relay 5 dependency logic after alloff
                if hasattr(self.relay, 'control_relay_19'):
                    try:
                        self.relay.control_relay_19()
                        self.logger.debug("control_relay_19() called after alloff")
                    except Exception as e:
                        self.logger.debug(f"control_relay_19() failed after alloff: {e}")

                return jsonify(self.standardize_success_response())

            except Exception as e:
                self.logger.exception("Error turning all relays off")
                return self.standardize_error_response(str(e), 500)

        @app.route('/status', methods=['GET'])
        def status():
            try:
                states = self.get_relay_states()
                status_lines = [f"Przekaźnik {s['id']}: {'on (włączony)' if s['on'] else 'off (wyłączony)'}" for s in states]
                return jsonify(self.standardize_success_response({'relay_status': status_lines}))
            except Exception as e:
                self.logger.exception("Error getting status")
                return self.standardize_error_response(str(e), 500)

        @app.route('/debug/relays', methods=['GET'])
        def debug_relays():
            try:
                states = self.get_relay_states()
                return jsonify(self.standardize_success_response({'relays': states, 'relay_count': self.relay_count}))
            except Exception as e:
                self.logger.exception("Error in debug_relays")
                return self.standardize_error_response(str(e), 500)

        # LEGACY COMPUTER ENDPOINTS (for backward compatibility)
        @app.route('/computer/<name>/wake', methods=['POST'])
        def computer_wake(name):
            try:
                computers = getattr(self.cfg, 'computers', {}) or {}
                computer = computers.get(name)
                if not computer:
                    self.logger.warning(f"WOL request for unknown computer: {name}")
                    return self.standardize_error_response("Computer not found", 404)
                
                mac = computer.get('MAC', '')
                if not mac:
                    self.logger.error(f"WOL failed for {name}: MAC address not configured")
                    return self.standardize_error_response("Computer MAC address not configured", 400)
                
                success = False
                method_used = None
                
                # ✅ LOG: Początek operacji WOL
                self.logger.info(f"Sending WOL to computer '{name}' (MAC: {mac})")
                
                # Try WOL through relay controller
                if hasattr(self.relay, 'send_wol_safe'):
                    self.logger.debug(f"Using relay.send_wol_safe() for WOL")
                    try:
                        success = bool(self.relay.send_wol_safe(mac))
                        method_used = 'relay.send_wol_safe'
                        if success:
                            self.logger.info(f"WOL magic packet sent via relay to {mac} (computer: {name})")
                        else:
                            self.logger.warning(f"relay.send_wol_safe() returned False for {mac}")
                    except Exception as e:
                        self.logger.error(f"relay.send_wol_safe() failed for {mac}: {e}")
                else:
                    # Fallback - try wakeonlan library
                    self.logger.debug(f"relay.send_wol_safe() not available, using wakeonlan library")
                    try:
                        from wakeonlan import send_magic_packet
                        send_magic_packet(mac)
                        success = True
                        method_used = 'wakeonlan.send_magic_packet'
                        # ✅ LOG: Sukces
                        self.logger.info(f"WOL magic packet sent via wakeonlan to {mac} (computer: {name})")
                    except ImportError:
                        self.logger.warning("wakeonlan library not available for WOL")
                        self.logger.warning("Install: pip install wakeonlan")
                        method_used = 'none (wakeonlan not installed)'
                    except Exception as e:
                        self.logger.error(f"WOL failed for {mac}: {e}")
                        method_used = 'wakeonlan (failed)'
                
                # ✅ LOG: Podsumowanie
                if success:
                    self.logger.info(f"WOL completed successfully for computer '{name}' using {method_used}")
                else:
                    self.logger.error(f"WOL failed for computer '{name}' - no method available")
                
                return jsonify(self.standardize_success_response({
                    'computer': name, 
                    'mac': mac, 
                    'wol_sent': success,
                    'method': method_used
                }))
                
            except Exception as e:
                self.logger.exception(f"Error waking computer {name}")
                return self.standardize_error_response(str(e), 500)

        @app.route('/computer/<name>/shutdown', methods=['POST'])
        def computer_shutdown(name):
            try:
                computers = getattr(self.cfg, 'computers', {}) or {}
                computer = computers.get(name)
                if not computer:
                    return self.standardize_error_response("Computer not found", 404)

                ip = computer.get('IP', '')
                os_type = computer.get('OS', '')
                username = computer.get('Username')
                password = computer.get('Password')

                if not ip:
                    return self.standardize_error_response("Computer IP not configured", 400)

                success = False
                if hasattr(self.relay, 'shutdown_remote_computer'):
                    success = bool(self.relay.shutdown_remote_computer(ip, os_type, username, password))

                return jsonify(self.standardize_success_response({'computer': name, 'ip': ip, 'shutdown_sent': success}))

            except Exception as e:
                self.logger.exception(f"Error shutting down computer {name}")
                return self.standardize_error_response(str(e), 500)

        # UNIFIED HOST MANAGEMENT ENDPOINTS
        @app.route('/hosts/list', methods=['GET'])
        def hosts_list():
            """Endpoint zwracający listę hostów z konfiguracji i realnym statusem."""
            try:
                computers = getattr(self.cfg, 'computers', {}) or {}
                proxmox_cfg = getattr(self.cfg, 'proxmox', {}) or {}
                proxmox_nodes = proxmox_cfg.get('nodes', {}) or {}
                proxmox_macs = proxmox_cfg.get('nodes_mac', {}) or {}
                proxmox_relays = proxmox_cfg.get('nodes_relay', {}) or {}

                hosts = []

                # Dodaj komputery z sekcji computers
                for name, info in computers.items():
                    ip = info.get('IP', '')
                    relay_id = info.get('relay')  # NOWE POLE: numer przekaźnika

                    # Sprawdź status z uwzględnieniem przekaźnika
                    if ip:
                        status_info = self.check_host_status(ip, relay_id)
                        status = status_info['status']
                        status_reason = status_info['reason']
                    else:
                        status = 'unknown'
                        status_reason = 'No IP configured'

                    host_data = {
                        'hostname': name,
                        'name': name,
                        'ip': ip,
                        'mac': info.get('MAC', ''),
                        'os': info.get('OS', 'unknown'),
                        'relay': relay_id,  # NOWE POLE
                        'status': status,
                        'status_reason': status_reason,  # NOWE POLE
                        'type': 'computer'
                    }
                    hosts.append(host_data)

                # Dodaj węzły Proxmox
                for node_name, node_ip in proxmox_nodes.items():
                    relay_id = proxmox_relays.get(node_name)
                    # Węzły Proxmox zazwyczaj nie są na przekaźnikach
                    # ale jeśli są, można dodać proxmox_relay_map w config
                    if node_ip:
                        status_info = self.check_host_status(node_ip, relay_id)
                        status = status_info['status']
                        status_reason = status_info['reason']
                    else:
                        status = 'unknown'
                        status_reason = 'No IP configured'

                    host_data = {
                        'hostname': node_name,
                        'name': node_name,
                        'ip': node_ip,
                        'mac': proxmox_macs.get(node_name, ''),
                        'os': 'linux',
                        'relay': relay_id,
                        'status': status,
                        'status_reason': status_reason,
                        'type': 'proxmox_node'
                    }
                    hosts.append(host_data)

                return jsonify(self.standardize_success_response({'hosts': hosts}))

            except Exception as e:
                self.logger.exception("Error getting hosts list")
                return self.standardize_error_response(str(e), 500)

        @app.route('/hosts/<host_id>/wake', methods=['POST'])
        def host_wake(host_id):
            """WOL dla hosta."""
            try:
                host = self.find_host_config(host_id)
                if not host:
                    self.logger.warning(f"WOL request for unknown host: {host_id}")
                    return self.standardize_error_response(f"Host {host_id} not found", 404)
                
                mac = host.get('mac', '')
                if not mac:
                    self.logger.error(f"WOL failed for {host_id}: MAC address not configured")
                    return self.standardize_error_response(f"MAC address not configured for host {host_id}", 400)
                
                success = False
                method_used = None
                
                # ✅ LOG: Początek operacji WOL
                self.logger.info(f"Sending WOL to host '{host_id}' (MAC: {mac})")
                
                # Próbuj WOL przez relay controller
                if hasattr(self.relay, 'send_wol_safe'):
                    self.logger.debug(f"Using relay.send_wol_safe() for WOL")
                    try:
                        success = bool(self.relay.send_wol_safe(mac))
                        method_used = 'relay.send_wol_safe'
                        if success:
                            self.logger.info(f"WOL magic packet sent via relay to {mac} (host: {host_id})")
                        else:
                            self.logger.warning(f"relay.send_wol_safe() returned False for {mac}")
                    except Exception as e:
                        self.logger.error(f"relay.send_wol_safe() failed for {mac}: {e}")
                        success = False
                else:
                    # Fallback - użyj biblioteki wakeonlan jeśli dostępna
                    self.logger.debug(f"relay.send_wol_safe() not available, using wakeonlan library")
                    try:
                        from wakeonlan import send_magic_packet
                        send_magic_packet(mac)
                        success = True
                        method_used = 'wakeonlan.send_magic_packet'
                        # ✅ LOG: Sukces wysłania przez wakeonlan
                        self.logger.info(f"WOL magic packet sent via wakeonlan to {mac} (host: {host_id})")
                    except ImportError:
                        self.logger.warning("wakeonlan library not available for WOL")
                        self.logger.warning("Install: pip install wakeonlan")
                        success = False
                        method_used = 'none (wakeonlan not installed)'
                    except Exception as e:
                        self.logger.error(f"WOL failed for {mac}: {e}")
                        success = False
                        method_used = 'wakeonlan (failed)'
                
                #LOG: Podsumowanie
                if success:
                    self.logger.info(f"WOL completed successfully for host '{host_id}' using {method_used}")
                else:
                    self.logger.error(f"WOL failed for host '{host_id}' - no method available or all methods failed")
                
                return jsonify(self.standardize_success_response({
                    'host': host_id, 
                    'mac': mac, 
                    'wol_sent': success,
                    'method': method_used  #NOWE: informacja o użytej metodzie
                }))
                
            except Exception as e:
                self.logger.exception(f"Error waking host {host_id}")
                return self.standardize_error_response(str(e), 500)

        @app.route('/hosts/<host_id>/shutdown', methods=['POST'])
        def host_shutdown(host_id):
            """Shutdown hosta przez SSH."""
            try:
                host = self.find_host_config(host_id)
                if not host:
                    return self.standardize_error_response(f"Host {host_id} not found", 404)

                ip = host.get('ip', '')
                if not ip:
                    return self.standardize_error_response(f"IP address not configured for host {host_id}", 400)

                # Użyj istniejącej logiki shutdownu
                success = self.execute_ssh_command(host, 'shutdown')

                return jsonify(self.standardize_success_response({'host': host_id, 'ip': ip, 'shutdown_sent': success}))

            except Exception as e:
                self.logger.exception(f"Error shutting down host {host_id}")
                return self.standardize_error_response(str(e), 500)

        @app.route('/hosts/<host_id>/reboot', methods=['POST'])
        def host_reboot(host_id):
            """Restart hosta przez SSH."""
            try:
                host = self.find_host_config(host_id)
                if not host:
                    return self.standardize_error_response(f"Host {host_id} not found", 404)

                ip = host.get('ip', '')
                if not ip:
                    return self.standardize_error_response(f"IP address not configured for host {host_id}", 400)

                # Użyj istniejącej logiki shutdownu
                success = self.execute_ssh_command(host, 'reboot')

                return jsonify(self.standardize_success_response({'host': host_id, 'ip': ip, 'reboot_sent': success}))

            except Exception as e:
                self.logger.exception(f"Error rebooting host {host_id}")
                return self.standardize_error_response(str(e), 500)

        @app.route('/hosts/<host_id>/ping', methods=['GET', 'POST'])  # DODANO GET
        def host_ping(host_id):
            """Ping hosta z uwzględnieniem stanu przekaźnika."""
            try:
                host = self.find_host_config(host_id)
                if not host:
                    return self.standardize_error_response(f"Host {host_id} not found", 404)

                ip = host.get('ip', '')
                if not ip:
                    return self.standardize_error_response(
                        f"IP address not configured for host {host_id}", 400
                    )

                # Pobierz numer przekaźnika jeśli jest
                relay_id = host.get('relay')

                # Sprawdź status
                status_info = self.check_host_status(ip, relay_id)

                return jsonify(self.standardize_success_response({
                    'host': host_id,
                    'ip': ip,
                    'relay': relay_id,
                    'reachable': status_info['reachable'],
                    'relay_on': status_info['relay_on'],
                    'status': status_info['status'],
                    'reason': status_info['reason']
                }))

            except Exception as e:
                self.logger.exception(f"Error pinging host {host_id}")
                return self.standardize_error_response(str(e), 500)

        # PROXMOX ENDPOINTS
        @app.route('/proxmox/vms', methods=['GET'])
        def proxmox_vms():
            if not self.proxmox:
                return self.standardize_error_response("Proxmox helper not available", 503)
            
            try:
                if not getattr(self.proxmox, 'is_available', lambda: False)():
                    return self.standardize_error_response("Proxmox not configured or unavailable", 503)
                
                # 🆕 SPRAWDŹ WARUNEK CONDITIONAL FETCHING
                if not self._should_fetch_proxmox_vms():
                    self.logger.debug("Skipping Proxmox VM fetch - required relays are OFF")
                    return jsonify(self.standardize_success_response({
                        'vms': [],
                        'skipped': True,
                        'reason': 'Required relays are OFF'
                    }))
                
                # Pobierz VM tylko jeśli warunek spełniony
                vms = self.proxmox.list_all_vms()
                return jsonify(self.standardize_success_response({'vms': vms}))
            
            except Exception as e:
                self.logger.exception("Error getting Proxmox VMs")
                return self.standardize_error_response(str(e), 500)

        @app.route('/proxmox/vm/ips', methods=['GET'])
        def proxmox_vm_ips():
            if not self.proxmox:
                return self.standardize_error_response("Proxmox helper not available", 503)

            try:
                if not getattr(self.proxmox, 'is_available', lambda: False)():
                    return self.standardize_error_response("Proxmox not configured or unavailable", 503)

                node = request.args.get('node', '', type=str)
                vmtype = request.args.get('type', '', type=str)
                vmid = request.args.get('vmid', type=int)

                if not all([node, vmtype, vmid is not None]):
                    return self.standardize_error_response("Required parameters: node, type, vmid", 400)

                ips = self.proxmox.get_vm_ips(node, vmtype, vmid)
                return jsonify(self.standardize_success_response({'node': node, 'type': vmtype, 'vmid': vmid, 'ips': ips}))

            except Exception as e:
                self.logger.exception("Error getting VM IPs")
                return self.standardize_error_response(str(e), 500)

        @app.route('/proxmox/vm/action', methods=['POST'])
        def proxmox_vm_action():
            if not self.proxmox:
                return self.standardize_error_response("Proxmox helper not available", 503)

            try:
                if not getattr(self.proxmox, 'is_available', lambda: False)():
                    return self.standardize_error_response("Proxmox not configured or unavailable", 503)

                data = request.get_json(silent=True) or {}
                node = data.get('node')
                vmtype = data.get('type')
                vmid = data.get('vmid')
                action = data.get('action')

                if not all([node, vmtype, vmid, action]):
                    return self.standardize_error_response("Required fields: node, type, vmid, action", 400)

                try:
                    vmid = int(vmid)
                except (ValueError, TypeError):
                    return self.standardize_error_response("vmid must be an integer", 400)

                if not hasattr(self.proxmox, 'vm_action'):
                    return self.standardize_error_response("VM actions not supported", 501)

                result = self.proxmox.vm_action(node, vmtype, vmid, action)

                if result.get('success'):
                    return jsonify(self.standardize_success_response(result))
                else:
                    return self.standardize_error_response(result.get('error', 'VM action failed'), 400)

            except Exception as e:
                self.logger.exception("Error executing VM action")
                return self.standardize_error_response(str(e), 500)

        @app.route('/proxmox/node/action', methods=['POST'])
        def proxmox_node_action():
            if not self.proxmox:
                return self.standardize_error_response("Proxmox helper not available", 503)

            try:
                if not getattr(self.proxmox, 'is_available', lambda: False)():
                    return self.standardize_error_response("Proxmox not configured or unavailable", 503)

                data = request.get_json(silent=True) or {}
                node = data.get('node')
                action = data.get('action')

                if not all([node, action]):
                    return self.standardize_error_response("Required fields: node, action", 400)

                if not hasattr(self.proxmox, 'node_action'):
                    return self.standardize_error_response("Node actions not supported", 501)

                result = self.proxmox.node_action(node, action)

                if result.get('success'):
                    return jsonify(self.standardize_success_response(result))
                else:
                    return self.standardize_error_response(result.get('error', 'Node action failed'), 400)

            except Exception as e:
                self.logger.exception("Error executing node action")
                return self.standardize_error_response(str(e), 500)

        @app.route('/relay/<int:relay_id>/quick_start', methods=['POST'])
        def relay_quick_start(relay_id):
            """
            Szybki skrót: włącza przekaźnik, czeka na Proxmox i uruchamia VM.
            """
            if not self.relay:
                return self.standardize_error_response("Relay controller not available", 503)
            
            if not (1 <= relay_id <= self.relay_count):
                return self.standardize_error_response(f"Relay ID must be 1-{self.relay_count}", 400)
            
            if relay_id not in [2, 8]:
                return self.standardize_error_response("Quick start available only for relays 2 and 8", 400)
            
            try:
                data = request.get_json(silent=True) or {}
                vmid = data.get('vmid')
                vmtype = data.get('type', 'qemu')  # domyślnie qemu
                
                if not vmid:
                    return self.standardize_error_response("Required field: vmid", 400)
                
                try:
                    vmid = int(vmid)
                except (ValueError, TypeError):
                    return self.standardize_error_response("vmid must be an integer", 400)
                
                # Pobierz konfigurację Proxmox
                proxmox_cfg = getattr(self.cfg, 'proxmox', {}) or {}
                nodes = proxmox_cfg.get('nodes', {}) or {}
                nodes_relay = proxmox_cfg.get('nodes_relay', {}) or {}
                
                # Znajdź node dla tego przekaźnika
                expected_node = None
                for node_name, relay_num in nodes_relay.items():
                    if relay_num == relay_id:
                        expected_node = node_name
                        break
                
                if not expected_node:
                    return self.standardize_error_response(f"No Proxmox node configured for relay {relay_id}", 400)
                
                node = expected_node  # Użyj automatycznie wykrytego node
                node_ip = nodes.get(node)
                if not node_ip:
                    return self.standardize_error_response(f"IP address not configured for node {node}", 400)
                
                # 1. Włącz przekaźnik
                idx = relay_id - 1
                if hasattr(self.relay, 'turn_on'):
                    self.relay.turn_on(idx)
                elif hasattr(self.relay, 'set_relay'):
                    self.relay.set_relay(idx, True)
                else:
                    return self.standardize_error_response("Relay turn_on not supported", 501)
                
                self.logger.info(f"Quick start: Relay {relay_id} turned ON, waiting for Proxmox node {node} ({node_ip})")
                
                # Import funkcji sprawdzającej port TCP
                from app.proxmox import _tcp_port_open
                
                # 2. Czekaj na Proxmox (sprawdzaj dostępność przez ping i TCP port 8006)
                max_wait_time = 120  # maksymalnie 2 minuty
                check_interval = 3  # sprawdzaj co 3 sekundy
                start_time = time.time()
                proxmox_ready = False
                
                while time.time() - start_time < max_wait_time:
                    # Sprawdź ping
                    if self.ping_host(node_ip, timeout=2, count=1):
                        # Sprawdź czy port Proxmox (8006) jest otwarty
                        if _tcp_port_open(node_ip, 8006, timeout=2.0):
                            proxmox_ready = True
                            self.logger.info(f"Proxmox node {node} is ready after {int(time.time() - start_time)} seconds")
                            break
                    time.sleep(check_interval)
                
                if not proxmox_ready:
                    return self.standardize_error_response(f"Proxmox node {node} did not become ready within {max_wait_time} seconds", 408)
                
                # 3. Uruchom VM
                if not self.proxmox:
                    return self.standardize_error_response("Proxmox helper not available", 503)
                
                if not getattr(self.proxmox, 'is_available', lambda: False)():
                    return self.standardize_error_response("Proxmox not configured or unavailable", 503)
                
                if not hasattr(self.proxmox, 'vm_action'):
                    return self.standardize_error_response("VM actions not supported", 501)
                
                result = self.proxmox.vm_action(node, vmtype, vmid, 'start')
                
                if result.get('success'):
                    taskid = result.get('taskid')
                    self.logger.info(f"Quick start: VM {vmid} on node {node} started (task: {taskid})")
                    return jsonify(self.standardize_success_response({
                        'relay_id': relay_id,
                        'node': node,
                        'vmid': vmid,
                        'taskid': taskid,
                        'message': f'Relay {relay_id} turned on, Proxmox ready, VM {vmid} started'
                    }))
                else:
                    return self.standardize_error_response(result.get('message', 'VM start failed'), 400)
                
            except Exception as e:
                self.logger.exception(f"Error in quick start for relay {relay_id}")
                return self.standardize_error_response(str(e), 500)

        @app.route('/relay/<int:relay_id>/quick_shutdown', methods=['POST'])
        def relay_quick_shutdown(relay_id):
            """
            Szybkie wyłączenie: wyłącza wszystkie VM, wyłącza Proxmox node, czeka 5 minut, wyłącza przekaźnik.
            """
            if not self.relay:
                return self.standardize_error_response("Relay controller not available", 503)
            
            if not (1 <= relay_id <= self.relay_count):
                return self.standardize_error_response(f"Relay ID must be 1-{self.relay_count}", 400)
            
            if relay_id not in [2, 8]:
                return self.standardize_error_response("Quick shutdown available only for relays 2 and 8", 400)
            
            try:
                # Pobierz konfigurację Proxmox
                proxmox_cfg = getattr(self.cfg, 'proxmox', {}) or {}
                nodes = proxmox_cfg.get('nodes', {}) or {}
                nodes_relay = proxmox_cfg.get('nodes_relay', {}) or {}
                
                # Znajdź node dla tego przekaźnika
                expected_node = None
                for node_name, relay_num in nodes_relay.items():
                    if relay_num == relay_id:
                        expected_node = node_name
                        break
                
                if not expected_node:
                    return self.standardize_error_response(f"No Proxmox node configured for relay {relay_id}", 400)
                
                node = expected_node
                
                if not self.proxmox:
                    return self.standardize_error_response("Proxmox helper not available", 503)
                
                if not getattr(self.proxmox, 'is_available', lambda: False)():
                    return self.standardize_error_response("Proxmox not configured or unavailable", 503)
                
                self.logger.info(f"Quick shutdown: Starting shutdown sequence for relay {relay_id} (node {node})")
                
                # 1. Pobierz listę wszystkich VM dla tego node
                all_vms = []
                try:
                    all_vms = self.proxmox.list_all_vms()
                except Exception as e:
                    self.logger.warning(f"Failed to list VMs for quick shutdown: {e}")
                
                # Filtruj tylko running VM dla tego node
                running_vms = [
                    vm for vm in all_vms 
                    if vm.get('node') == node and (vm.get('status') or '').lower() == 'running'
                ]
                
                self.logger.info(f"Quick shutdown: Found {len(running_vms)} running VMs on node {node}")
                
                # 2. Wyłącz wszystkie running VM
                shutdown_results = []
                for vm in running_vms:
                    vmtype = vm.get('type', 'qemu')
                    vmid = vm.get('vmid')
                    if vmid:
                        try:
                            self.logger.info(f"Quick shutdown: Shutting down VM {vmid} ({vmtype}) on node {node}")
                            result = self.proxmox.vm_action(node, vmtype, int(vmid), 'shutdown')
                            shutdown_results.append({
                                'vmid': vmid,
                                'type': vmtype,
                                'success': result.get('success', False),
                                'message': result.get('message', '')
                            })
                            # Krótkie opóźnienie między wyłączaniami
                            time.sleep(1)
                        except Exception as e:
                            self.logger.warning(f"Failed to shutdown VM {vmid}: {e}")
                            shutdown_results.append({
                                'vmid': vmid,
                                'type': vmtype,
                                'success': False,
                                'message': str(e)
                            })
                
                # 3. Wyłącz Proxmox node
                self.logger.info(f"Quick shutdown: Shutting down Proxmox node {node}")
                node_shutdown_result = None
                try:
                    if hasattr(self.proxmox, 'node_action'):
                        node_shutdown_result = self.proxmox.node_action(node, 'shutdown')
                        if not node_shutdown_result.get('success'):
                            self.logger.warning(f"Node shutdown may have failed: {node_shutdown_result.get('message')}")
                except Exception as e:
                    self.logger.warning(f"Failed to shutdown node {node}: {e}")
                    node_shutdown_result = {'success': False, 'message': str(e)}
                
                # 4. Czekaj 5 minut (300 sekund)
                wait_time = 300  # 5 minut
                self.logger.info(f"Quick shutdown: Waiting {wait_time} seconds before turning off relay {relay_id}")
                
                # Uruchom w tle, aby nie blokować requestu
                def delayed_relay_off():
                    try:
                        time.sleep(wait_time)
                        idx = relay_id - 1
                        if hasattr(self.relay, 'turn_off'):
                            self.relay.turn_off(idx)
                        elif hasattr(self.relay, 'set_relay'):
                            self.relay.set_relay(idx, False)
                        self.logger.info(f"Quick shutdown: Relay {relay_id} turned OFF after {wait_time} seconds wait")
                    except Exception as e:
                        self.logger.exception(f"Error turning off relay {relay_id} after delay: {e}")
                
                shutdown_thread = Thread(target=delayed_relay_off, daemon=True)
                shutdown_thread.start()
                
                return jsonify(self.standardize_success_response({
                    'relay_id': relay_id,
                    'node': node,
                    'vms_shutdown': len(running_vms),
                    'vm_results': shutdown_results,
                    'node_shutdown': node_shutdown_result,
                    'relay_will_off_in_seconds': wait_time,
                    'message': f'Shutdown sequence started: {len(running_vms)} VMs, node {node}, relay {relay_id} will turn off in {wait_time}s'
                }))
                
            except Exception as e:
                self.logger.exception(f"Error in quick shutdown for relay {relay_id}")
                return self.standardize_error_response(str(e), 500)

        @app.route('/quick_start/choice', methods=['GET', 'POST'])
        def quick_start_choice():
            """
            Zapisz lub odczytaj ostatni wybór VM dla szybkiego startu.
            GET: zwraca ostatnie wybory dla wszystkich przekaźników
            POST: zapisuje wybór dla przekaźnika
            """
            choice_file = os.path.join(BASE_DIR, 'quick_start_vm_choices.json')
            
            if request.method == 'GET':
                try:
                    if os.path.exists(choice_file):
                        with open(choice_file, 'r') as f:
                            choices = json.load(f)
                    else:
                        choices = {}
                    
                    return jsonify(self.standardize_success_response({'choices': choices}))
                except Exception as e:
                    self.logger.exception("Error reading quick start choices")
                    return self.standardize_error_response(str(e), 500)
            
            elif request.method == 'POST':
                try:
                    data = request.get_json(silent=True) or {}
                    relay_id = data.get('relay_id')
                    vmid = data.get('vmid')
                    
                    if not relay_id or not vmid:
                        return self.standardize_error_response("Required fields: relay_id, vmid", 400)
                    
                    try:
                        relay_id = int(relay_id)
                        vmid = int(vmid)
                    except (ValueError, TypeError):
                        return self.standardize_error_response("relay_id and vmid must be integers", 400)
                    
                    # Wczytaj istniejące wybory
                    if os.path.exists(choice_file):
                        try:
                            with open(choice_file, 'r') as f:
                                choices = json.load(f)
                        except Exception:
                            choices = {}
                    else:
                        choices = {}
                    
                    # Zaktualizuj wybór dla przekaźnika
                    choices[str(relay_id)] = vmid
                    
                    # Zapisz atomowo (użyj temp file)
                    temp_file = choice_file + '.tmp'
                    with open(temp_file, 'w') as f:
                        json.dump(choices, f, indent=2)
                    os.replace(temp_file, choice_file)
                    
                    self.logger.debug(f"Saved quick start choice: relay {relay_id} -> VM {vmid}")
                    return jsonify(self.standardize_success_response({
                        'relay_id': relay_id,
                        'vmid': vmid
                    }))
                    
                except Exception as e:
                    self.logger.exception("Error saving quick start choice")
                    return self.standardize_error_response(str(e), 500)

        @app.route('/services/list', methods=['GET'])
        def list_services():
            """Lista usług systemd z konfiguracji."""
            try:
                # Pobierz konfigurację usług
                services_cfg = getattr(self.cfg, 'services', None)
                self.logger.debug(f"Services config from cfg: {services_cfg}")
                
                # Jeśli services nie istnieje lub jest None, zwróć pustą listę
                if services_cfg is None:
                    self.logger.debug("No 'services' attribute in config")
                    return jsonify(self.standardize_success_response({'services': []}))
                
                # Jeśli services jest pustym słownikiem, zwróć pustą listę
                if not services_cfg or (isinstance(services_cfg, dict) and len(services_cfg) == 0):
                    self.logger.debug("Services config is empty")
                    return jsonify(self.standardize_success_response({'services': []}))
                
                if not isinstance(services_cfg, dict):
                    self.logger.error(f"Services config is not a dict: {type(services_cfg)}")
                    return jsonify(self.standardize_success_response({'services': []}))
                
                self.logger.debug(f"Processing {len(services_cfg)} services from config")
                services = []
                
                for name, info in services_cfg.items():
                    self.logger.debug(f"Processing service: name={name}, info={info}, info_type={type(info)}")
                    
                    # Obsłuż różne formaty konfiguracji
                    if isinstance(info, dict):
                        service_name = info.get('service', name)
                    elif isinstance(info, str):
                        service_name = info
                    else:
                        service_name = name
                    
                    if not service_name.endswith('.service'):
                        service_name = f"{service_name}.service"
                    
                    # Sprawdź status usługi
                    import subprocess
                    try:
                        status_result = subprocess.run(
                            ['sudo', 'systemctl', 'is-active', service_name],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        is_active = status_result.returncode == 0 and status_result.stdout.strip() == 'active'
                        status_text = status_result.stdout.strip() if status_result.returncode == 0 else 'inactive'
                    except Exception as e:
                        self.logger.warning(f"Failed to check status for {service_name}: {e}")
                        is_active = False
                        status_text = 'unknown'
                    
                    service_data = {
                        'name': name,
                        'service': service_name,
                        'status': 'active' if is_active else 'inactive',
                        'status_text': status_text,
                        'description': info.get('description', '') if isinstance(info, dict) else ''
                    }
                    services.append(service_data)
                
                self.logger.debug(f"Returning {len(services)} services")
                return jsonify(self.standardize_success_response({'services': services}))
            except Exception as e:
                self.logger.exception("Error listing services")
                return self.standardize_error_response(str(e), 500)

        @app.route('/services/<service_name>/<action>', methods=['POST'])
        def service_action(service_name, action):
            """Zarządzanie usługą systemd (start, stop, restart, status)."""
            self.logger.info(f"=== SERVICE ACTION REQUEST ===")
            self.logger.info(f"Service name: {service_name}, Action: {action}")
            
            try:
                import subprocess
                
                # Walidacja akcji
                if action not in ['start', 'stop', 'restart', 'reload']:
                    self.logger.warning(f"Invalid action: {action}")
                    return self.standardize_error_response(f"Nieprawidłowa akcja: {action}. Dozwolone: start, stop, restart, reload", 400)
                
                # Pobierz pełną nazwę usługi z konfiguracji
                services_cfg = getattr(self.cfg, 'services', {}) or {}
                service_info = services_cfg.get(service_name, {})
                
                # Jeśli usługa nie istnieje w konfiguracji, użyj nazwy bezpośrednio
                if not service_info:
                    self.logger.warning(f"Service '{service_name}' not found in config, using name directly")
                    full_service_name = service_name
                elif isinstance(service_info, dict):
                    full_service_name = service_info.get('service', service_name)
                else:
                    full_service_name = service_name
                
                if not full_service_name.endswith('.service'):
                    full_service_name = f"{full_service_name}.service"
                
                self.logger.debug(f"Service action: {action} on {full_service_name} (config name: {service_name})")
                
                result = subprocess.run(
                    ['sudo', 'systemctl', action, full_service_name],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    self.logger.info(f"✅ Service {full_service_name} {action} command executed successfully (returncode: 0)")
                    
                    # Sprawdź status po akcji
                    time.sleep(1)
                    status_result = subprocess.run(
                        ['sudo', 'systemctl', 'is-active', full_service_name],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    is_active = status_result.returncode == 0 and status_result.stdout.strip() == 'active'
                    status_text = status_result.stdout.strip() if status_result.returncode == 0 else 'inactive'
                    
                    self.logger.info(f"Service status after {action}: {status_text} (is_active: {is_active})")
                    self.logger.info("=== SERVICE ACTION COMPLETED ===")
                    
                    return jsonify(self.standardize_success_response({
                        'service': service_name,
                        'service_full': full_service_name,
                        'action': action,
                        'status': 'active' if is_active else 'inactive',
                        'status_text': status_text,
                        'message': f'Usługa {action} wykonana pomyślnie'
                    }))
                else:
                    error_msg = result.stderr.strip() or result.stdout.strip() or 'Unknown error'
                    self.logger.error(f"❌ Failed to {action} service {full_service_name} (returncode: {result.returncode})")
                    self.logger.error(f"Error message: {error_msg}")
                    if result.stdout:
                        self.logger.debug(f"stdout: {result.stdout[:200]}")
                    if result.stderr:
                        self.logger.debug(f"stderr: {result.stderr[:200]}")
                    self.logger.error("=== SERVICE ACTION FAILED ===")
                    return self.standardize_error_response(f"Nie udało się wykonać {action}: {error_msg}", 500)
                    
            except subprocess.TimeoutExpired:
                full_service_name_for_error = full_service_name if 'full_service_name' in locals() else service_name
                self.logger.error(f"❌ Timeout while executing {action} on {full_service_name_for_error}")
                self.logger.error("=== SERVICE ACTION TIMEOUT ===")
                return self.standardize_error_response("Timeout podczas wykonywania akcji", 500)
            except Exception as e:
                self.logger.exception(f"❌ Exception executing service action {action} on {service_name}")
                self.logger.error(f"Exception type: {type(e).__name__}, message: {str(e)}")
                self.logger.error("=== SERVICE ACTION EXCEPTION ===")
                return self.standardize_error_response(str(e), 500)

        @app.route('/services/<service_name>/status', methods=['GET'])
        def service_status(service_name):
            """Sprawdź status usługi systemd."""
            try:
                import subprocess
                
                services_cfg = getattr(self.cfg, 'services', {}) or {}
                service_info = services_cfg.get(service_name, {})
                
                if isinstance(service_info, dict):
                    full_service_name = service_info.get('service', service_name)
                else:
                    full_service_name = service_name
                
                if not full_service_name.endswith('.service'):
                    full_service_name = f"{full_service_name}.service"
                
                result = subprocess.run(
                    ['sudo', 'systemctl', 'is-active', full_service_name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                is_active = result.returncode == 0 and result.stdout.strip() == 'active'
                status_text = result.stdout.strip() if result.returncode == 0 else 'inactive'
                
                # Szczegółowy status
                detailed_result = subprocess.run(
                    ['sudo', 'systemctl', 'status', full_service_name, '--no-pager', '-l'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                detailed_status = None
                if detailed_result.returncode == 0:
                    lines = detailed_result.stdout.split('\n')[:5]
                    detailed_status = '\n'.join([line for line in lines if line.strip()])
                
                return jsonify(self.standardize_success_response({
                    'service': service_name,
                    'service_full': full_service_name,
                    'active': is_active,
                    'status': 'active' if is_active else 'inactive',
                    'status_text': status_text,
                    'detailed_status': detailed_status
                }))
                    
            except Exception as e:
                self.logger.exception(f"Error checking service status for {service_name}")
                return self.standardize_error_response(str(e), 500)

        @app.route('/docker/containers', methods=['GET'])
        def list_docker_containers():
            """Lista kontenerów Docker."""
            try:
                import subprocess
                import json
                
                # Pobierz listę kontenerów
                result = subprocess.run(
                    ['docker', 'ps', '-a', '--format', 'json'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode != 0:
                    # Spróbuj bez sudo
                    result = subprocess.run(
                        ['sudo', 'docker', 'ps', '-a', '--format', 'json'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                
                containers = []
                if result.returncode == 0:
                    if result.stdout.strip():
                        for line in result.stdout.strip().split('\n'):
                            if line.strip():
                                try:
                                    container = json.loads(line)
                                    container_id = container.get('ID', '')
                                    if not container_id:
                                        continue
                                    containers.append({
                                        'id': container_id[:12],  # Użyj pełnego ID, ale pokaż tylko 12 znaków
                                        'name': container.get('Names', ''),
                                        'image': container.get('Image', ''),
                                        'status': container.get('Status', ''),
                                        'state': 'running' if 'Up' in container.get('Status', '') else 'stopped',
                                        'ports': container.get('Ports', '')
                                    })
                                except json.JSONDecodeError as e:
                                    self.logger.warning(f"Failed to parse Docker container JSON: {line[:100]}... Error: {e}")
                                    continue
                    else:
                        self.logger.debug("Docker ps returned empty output")
                else:
                    error_msg = result.stderr.strip() or result.stdout.strip() or 'Unknown error'
                    self.logger.error(f"Docker ps failed (returncode {result.returncode}): {error_msg}")
                    # Jeśli docker nie jest dostępny, zwróć pustą listę zamiast błędu
                    if "docker: command not found" in error_msg or "Cannot connect to the Docker daemon" in error_msg:
                        return jsonify(self.standardize_success_response({
                            'containers': [],
                            'warning': 'Docker nie jest dostępny lub daemon nie działa'
                        }))
                
                return jsonify(self.standardize_success_response({'containers': containers}))
                    
            except FileNotFoundError:
                self.logger.warning("Docker command not found in PATH")
                return jsonify(self.standardize_success_response({
                    'containers': [],
                    'warning': 'Docker nie jest zainstalowany lub nie jest dostępny w PATH'
                }))
            except Exception as e:
                self.logger.exception("Error listing Docker containers")
                return self.standardize_error_response(str(e), 500)

        @app.route('/docker/containers/<container_id>/<action>', methods=['POST'])
        def docker_container_action(container_id, action):
            """Zarządzanie kontenerem Docker (start, stop, restart)."""
            try:
                import subprocess
                
                if action not in ['start', 'stop', 'restart', 'remove']:
                    return self.standardize_error_response(f"Nieprawidłowa akcja: {action}. Dozwolone: start, stop, restart, remove", 400)
                
                self.logger.info(f"Docker action: {action} on container {container_id}")
                
                # Spróbuj najpierw bez sudo
                cmd = ['docker', action, container_id]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    # Spróbuj z sudo
                    cmd = ['sudo', 'docker', action, container_id]
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                
                if result.returncode == 0:
                    # Dla akcji remove, kontener może nie istnieć już, więc nie sprawdzamy statusu
                    if action == 'remove':
                        self.logger.info(f"Container {container_id[:12]} removed successfully")
                        return jsonify(self.standardize_success_response({
                            'container_id': container_id,
                            'action': action,
                            'message': f'Kontener {container_id[:12]} usunięty pomyślnie'
                        }))
                    else:
                        self.logger.info(f"Container {container_id[:12]} {action} executed successfully")
                        return jsonify(self.standardize_success_response({
                            'container_id': container_id,
                            'action': action,
                            'message': f'Akcja {action} wykonana pomyślnie'
                        }))
                else:
                    error_msg = result.stderr.strip() or result.stdout.strip() or 'Unknown error'
                    self.logger.error(f"Failed to {action} container {container_id}: {error_msg}")
                    
                    # Sprawdź typowe błędy Docker
                    error_lower = error_msg.lower()
                    if 'no such container' in error_lower:
                        return self.standardize_error_response(f"Kontener {container_id[:12]} nie istnieje", 404)
                    elif 'container is not running' in error_lower and action in ['stop', 'restart']:
                        return self.standardize_error_response(f"Kontener {container_id[:12]} nie jest uruchomiony", 400)
                    elif 'container is running' in error_lower and action == 'start':
                        return self.standardize_error_response(f"Kontener {container_id[:12]} jest już uruchomiony", 400)
                    elif 'cannot remove a running container' in error_lower:
                        return self.standardize_error_response(f"Nie można usunąć uruchomionego kontenera. Najpierw zatrzymaj kontener.", 400)
                    
                    return self.standardize_error_response(f"Nie udało się wykonać {action}: {error_msg}", 500)
                    
            except subprocess.TimeoutExpired:
                return self.standardize_error_response("Timeout podczas wykonywania akcji", 500)
            except Exception as e:
                self.logger.exception(f"Error executing Docker action {action} on {container_id}")
                return self.standardize_error_response(str(e), 500)

        @app.route('/logs', methods=['GET'])
        def get_logs():
            """Pobierz logi z pliku logów programu."""
            try:
                # Pobierz parametry z query string
                lines = request.args.get('lines', type=int, default=200)  # Domyślnie ostatnie 200 linii
                level = request.args.get('level', type=str, default='')  # Filtr poziomu (INFO, DEBUG, WARNING, ERROR)
                max_lines = 1000  # Maksymalna liczba linii do zwrócenia
                
                if lines > max_lines:
                    lines = max_lines
                if lines < 1:
                    lines = 50
                
                # Pobierz ścieżkę do pliku logów z konfiguracji
                log_path = getattr(self.cfg, 'log_path', 'logs/power_control.log')
                
                # Jeśli ścieżka jest względna, zrób ją absolutną względem BASE_DIR
                if not os.path.isabs(log_path):
                    log_path = os.path.join(BASE_DIR, log_path)
                
                self.logger.debug(f"Reading logs from: {log_path}, lines: {lines}, level filter: {level}")
                
                if not os.path.exists(log_path):
                    return self.standardize_error_response(f"Plik logów nie istnieje: {log_path}", 404)
                
                # Przeczytaj plik logów (od końca, ostatnie N linii)
                try:
                    with open(log_path, 'r', encoding='utf-8') as f:
                        all_lines = f.readlines()
                    
                    # Pobierz ostatnie N linii
                    log_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
                    
                    # Filtruj po poziomie jeśli podano
                    if level and level.upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                        level_upper = level.upper()
                        log_lines = [
                            line for line in log_lines 
                            if f' - {level_upper} - ' in line
                        ]
                    
                    # Formatuj logi (usuń puste linie na końcu)
                    log_text = ''.join(log_lines).rstrip()
                    
                    # Policz linie przed i po filtrowaniu
                    total_lines = len(all_lines)
                    filtered_lines = len(log_lines)
                    
                    return jsonify(self.standardize_success_response({
                        'logs': log_text,
                        'total_lines': total_lines,
                        'displayed_lines': filtered_lines,
                        'requested_lines': lines,
                        'level_filter': level if level else None,
                        'log_file': log_path,
                        'file_size': os.path.getsize(log_path) if os.path.exists(log_path) else 0
                    }))
                    
                except UnicodeDecodeError:
                    self.logger.error(f"Failed to decode log file {log_path} as UTF-8")
                    return self.standardize_error_response("Błąd odczytu pliku logów (nieprawidłowe kodowanie)", 500)
                except Exception as e:
                    self.logger.exception(f"Error reading log file {log_path}")
                    return self.standardize_error_response(f"Błąd odczytu pliku logów: {str(e)}", 500)
                    
            except Exception as e:
                self.logger.exception("❌ Error in get_logs endpoint")
                return self.standardize_error_response(str(e), 500)

    def start(self):
        """Start Flask server in background thread."""
        if self.running:
            return

        host = getattr(self.cfg, 'host', '0.0.0.0')
        port = int(getattr(self.cfg, 'port', 5000))

        try:
            # FIXED: Use Werkzeug server for proper shutdown capability
            from werkzeug.serving import make_server
            self._server = make_server(host, port, flask_app, threaded=True)
            
            self.server_thread = Thread(
                target=self._server.serve_forever,
                daemon=True
            )
            self.server_thread.start()
            self.running = True
            self.logger.info(f"Flask started on {host}:{port}")
            self.logger.info("Web service started")
        except ImportError:
            # Fallback to old method if Werkzeug not available
            self.logger.warning("Werkzeug not available, using flask_app.run() (shutdown may not work properly)")
            self._server = None
            self.server_thread = Thread(
                target=flask_app.run,
                kwargs={'host': host, 'port': port, 'threaded': True, 'use_reloader': False},
                daemon=True
            )
            self.server_thread.start()
            self.running = True
            self.logger.info(f"Flask started on {host}:{port} (fallback mode)")

    def stop(self):
        """Stop web service gracefully."""
        if not self.running:
            return

        self.running = False
        self._stop_event.set()
        
        # FIXED: Properly shutdown Werkzeug server
        if hasattr(self, '_server') and self._server:
            try:
                self._server.shutdown()
                self.logger.debug("Werkzeug server shutdown called")
            except Exception as e:
                self.logger.debug("Error shutting down Werkzeug server: %s", e)
        
        if self.server_thread:
            self.server_thread.join(timeout=5.0)
            if self.server_thread.is_alive():
                self.logger.warning("Web server thread did not stop within timeout")
        
        self.logger.info("Web service stopped")
