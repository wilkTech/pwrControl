# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
from typing import Dict, Any
import os
import logging

try:
    import yaml  # type: ignore
    _YAML = True
except Exception:
    yaml = None
    _YAML = False


@dataclass
class AppConfig:
    log_path: str = './power_control.log'
    silence_logs: bool = False
    log_level: str = 'INFO'
    host: str = '0.0.0.0'
    port: int = 5000
    proxmox: Dict[str, Any] = field(default_factory=lambda: {})
    email: Dict[str, Any] = field(default_factory=lambda: {})
    computers: Dict[str, Dict[str, str]] = field(default_factory=lambda: {})
    services: Dict[str, Dict[str, str]] = field(default_factory=lambda: {})
    relay_pins: list = field(default_factory=lambda: [5, 6, 13, 16, 19, 20, 21, 26])
    switch_pins: list = field(default_factory=lambda: [24, 8, 10, 7, 22, 12, 9, 25])
    enable_email_notifications: bool = True

    # NEW: separate flags for types of notifications
    enable_relay_event_emails: bool = True      # emails about relay on/off events (batched)
    enable_startup_notifications: bool = True   # startup emails
    enable_shutdown_notifications: bool = True  # shutdown emails

    # optional files
    notification_state_file: str = 'relay_notifications.json'
    heartbeat_file: str = 'last_heartbeat.json'
    heartbeat_interval_s: int = 60


def load_config(path: str = 'config.yaml') -> AppConfig:
    cfg = AppConfig()
    logger = logging.getLogger('powercontrol.config')

    if _YAML and os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                raw = yaml.safe_load(f) or {}
                if isinstance(raw, dict):
                    for k, v in raw.items():
                        if hasattr(cfg, k):
                            setattr(cfg, k, v)
                        else:
                            if k == 'proxmox' and isinstance(v, dict):
                                cfg.proxmox.update(v)
                            elif k == 'email' and isinstance(v, dict):
                                cfg.email.update(v)
                            elif k == 'computers' and isinstance(v, dict):
                                cfg.computers.update(v)
                            elif k == 'services' and isinstance(v, dict):
                                cfg.services.update(v)
                                logger.debug(f"Loaded services config: {cfg.services}")
        except Exception as e:
            logger.warning("Nie można wczytać config.yaml: %s", e)
    else:
        ini_path = os.path.join(os.getcwd(), 'config.conf')
        if os.path.isfile(ini_path):
            try:
                import configparser
                cp = configparser.ConfigParser()
                cp.read(ini_path)
                if cp.has_section('Settings'):
                    cfg.enable_email_notifications = cp.getboolean('Settings', 'enable_email_notifications', fallback=cfg.enable_email_notifications)
                    cfg.enable_relay_event_emails = cp.getboolean('Settings', 'enable_relay_event_emails', fallback=cfg.enable_relay_event_emails)
                    cfg.enable_startup_notifications = cp.getboolean('Settings', 'enable_startup_notifications', fallback=cfg.enable_startup_notifications)
                    cfg.enable_shutdown_notifications = cp.getboolean('Settings', 'enable_shutdown_notifications', fallback=cfg.enable_shutdown_notifications)
                if cp.has_section('Proxmox'):
                    prox = dict(cp.items('Proxmox'))
                    nodes_raw = prox.get('nodes', '')
                    nodes = {}
                    for item in nodes_raw.split(','):
                        item = item.strip()
                        if not item:
                            continue
                        if ':' in item:
                            name, host = item.split(':', 1)
                            nodes[name.strip()] = host.strip()
                    prox['nodes'] = nodes
                    cfg.proxmox.update(prox)
                if cp.has_section('Email'):
                    cfg.email.update(dict(cp.items('Email')))
                if cp.has_section('Computers'):
                    comps = {}
                    for name, val in cp.items('Computers'):
                        parts = [p.strip() for p in val.split(';')]
                        while len(parts) < 5:
                            parts.append('')
                        mac, ip, os_type, user, pwd = parts[:5]
                        comps[name] = {'MAC': mac, 'IP': ip, 'OS': os_type, 'Username': user, 'Password': pwd}
                    cfg.computers.update(comps)
            except Exception as e:
                logger.warning("Nie można wczytać config.conf: %s", e)

    # environment overrides (POWERCONTROL__SECTION__KEY)
    for key, val in os.environ.items():
        if not key.startswith('POWERCONTROL__'):
            continue
        parts = key.split('__')[1:]
        if not parts:
            continue
        target = cfg
        for p in parts[:-1]:
            p = p.lower()
            cur = getattr(target, p, None)
            if cur is None:
                setattr(target, p, {})
                cur = getattr(target, p)
            target = cur
        last = parts[-1].lower()
        if isinstance(target, dict):
            target[last] = val
        else:
            try:
                # attempt to coerce booleans/ints
                if val.lower() in ('true', 'yes', '1', 'on'):
                    v = True
                elif val.lower() in ('false', 'no', '0', 'off'):
                    v = False
                else:
                    try:
                        v = int(val)
                    except Exception:
                        v = val
                setattr(target, last, v)
            except Exception:
                pass

    return cfg
