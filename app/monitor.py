# app/monitor.py
# -*- coding: utf-8 -*-

"""
Monitor service for PowerControl with graceful shutdown detection.
Enhanced to distinguish between graceful shutdown and power loss events.

Preserves all original functionality while adding graceful shutdown tracking.
"""

from __future__ import annotations
import json
import os
import time
import logging
import signal
from threading import Thread, Event, Lock
from typing import Any, Optional, Dict

logger = logging.getLogger(__name__)

def _iso(ts: Optional[float]) -> Optional[str]:
    try:
        if ts is None:
            return None
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return str(ts)

def _format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable string."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        sec = int(seconds % 60)
        return f"{minutes}m {sec}s" if sec else f"{minutes}m"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    else:
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        return f"{days}d {hours}h" if hours else f"{days}d"

def _read_uptime_seconds() -> Optional[float]:
    try:
        with open("/proc/uptime", "r") as f:
            parts = f.read().strip().split()
            return float(parts[0])
    except Exception:
        return None

class Monitor:
    def __init__(self, cfg: Any, emailer: Any, relay: Any = None, logger_obj: Optional[logging.Logger] = None):
        self.cfg = cfg
        self.emailer = emailer
        self.relay = relay
        self.logger = logger_obj or logger
        
        self.heartbeat_file = getattr(cfg, "heartbeat_file", "last_heartbeat.json")
        self.heartbeat_interval = float(getattr(cfg, "heartbeat_interval_s", 60.0))
        
        # Session tracking
        self.session_id = hex(int(time.time()))[2:][:8]
        self.process_start_time = time.time()
        
        # Threading
        self._stop_event = Event()
        self._thread: Optional[Thread] = None
        self._lock = Lock()
        
        # Previous session analysis
        self.previous_heartbeat = None
        self.previous_session_id = None
        self.offline_duration = None
        self.estimated_downtime = None
        self.heartbeat_file_status = "unknown"
        self.previous_graceful_shutdown = False
        self.previous_graceful_shutdown_time = None
        
        # Enhanced analysis
        self._detailed_session_analysis()

    def _detailed_session_analysis(self):
        """Enhanced analysis of previous session with graceful shutdown detection."""
        try:
            if not os.path.exists(self.heartbeat_file):
                self.heartbeat_file_status = "file_not_found"
                self.logger.debug("Heartbeat file not found - first startup or file was removed")
                return
                
            # Check file permissions and readability
            if not os.access(self.heartbeat_file, os.R_OK):
                self.heartbeat_file_status = "permission_denied"
                self.logger.error("Cannot read heartbeat file - permission denied")
                return
                
            with open(self.heartbeat_file, 'r') as f:
                try:
                    data = json.load(f)
                    self.heartbeat_file_status = "valid"
                except json.JSONDecodeError as e:
                    self.heartbeat_file_status = "corrupted"
                    self.logger.error("Heartbeat file corrupted: %s", e)
                    return
            
            # Extract previous session data
            self.previous_heartbeat = data.get('timestamp') or data.get('ts')
            self.previous_session_id = data.get('session_id', 'unknown')
            self.previous_process_start = data.get('process_start')
            
            # CRITICAL: Read graceful shutdown flag
            self.previous_graceful_shutdown = data.get('graceful_shutdown', False)
            self.previous_graceful_shutdown_time = data.get('graceful_shutdown_time')
            
            # DEBUG: Log what we found
            self.logger.debug(f"Previous session analysis:")
            self.logger.debug(f"  - graceful_shutdown flag: {self.previous_graceful_shutdown}")
            self.logger.debug(f"  - graceful_shutdown_time: {_iso(self.previous_graceful_shutdown_time)}")
            self.logger.debug(f"  - last heartbeat: {_iso(self.previous_heartbeat)}")
        
            if self.previous_heartbeat:
                # Calculate offline duration (time between last heartbeat and now)
                self.offline_duration = self.process_start_time - self.previous_heartbeat
                
                # Enhanced downtime estimation considering graceful shutdown
                if self.previous_graceful_shutdown:
                    # For graceful shutdown, use graceful_shutdown_time if available
                    if self.previous_graceful_shutdown_time:
                        self.offline_duration = self.process_start_time - self.previous_graceful_shutdown_time
                        
                    # Graceful shutdown - minimal estimated downtime
                    self.estimated_downtime = max(0, self.offline_duration - 5)  # Allow 5s for shutdown process
                    
                    if self.offline_duration > self.heartbeat_interval * 2:
                        self.logger.info("Graceful shutdown detected: %.1f seconds offline", self.offline_duration)
                    else:
                        self.logger.info("Quick restart after graceful shutdown: %.1f seconds", self.offline_duration)
                else:
                    # Ungraceful shutdown - calculate as before
                    self.estimated_downtime = max(0, self.offline_duration - self.heartbeat_interval)
                    
                    if self.offline_duration > self.heartbeat_interval * 2:
                        self.logger.info("Ungraceful shutdown detected: %.1f seconds offline, estimated downtime: %.1f seconds", 
                                       self.offline_duration, self.estimated_downtime)
                    else:
                        self.logger.info("Short offline period: %.1f seconds (likely quick restart)", 
                                       self.offline_duration)
            else:
                self.heartbeat_file_status = "no_timestamp"
                self.logger.warning("Heartbeat file exists but contains no valid timestamp")
                
        except Exception as e:
            self.heartbeat_file_status = "read_error"
            self.logger.error("Error analyzing previous session: %s", e)

    def mark_graceful_shutdown_immediate(self):
        """
        IMMEDIATELY mark the current session as gracefully shut down.
        Uses fsync() to ensure data is written to disk before returning.
        This should be called at the VERY BEGINNING of shutdown sequence.
        """
        try:
            if os.path.exists(self.heartbeat_file):
                with open(self.heartbeat_file, 'r') as f:
                    data = json.load(f)
            else:
                # No heartbeat file yet - create minimal one
                data = {
                    'timestamp': time.time(),
                    'session_id': self.session_id,
                    'process_start': self.process_start_time
                }
            
            # Mark as graceful shutdown
            data['graceful_shutdown'] = True
            data['graceful_shutdown_time'] = time.time()
            
            # Write with FORCED SYNC to disk
            temp_file = self.heartbeat_file + '.tmp'
            
            # Open with explicit sync mode
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
                f.flush()  # Flush Python buffers
                os.fsync(f.fileno())  # ✅ FORCE write to disk!
            
            # Atomic replace
            os.replace(temp_file, self.heartbeat_file)
            
            #EXTRA: Sync the directory entry
            try:
                dir_fd = os.open(os.path.dirname(self.heartbeat_file) or '.', os.O_RDONLY)
                os.fsync(dir_fd)
                os.close(dir_fd)
            except Exception:
                pass  # Not critical if this fails
            
            self.logger.info("Graceful shutdown flag written and synced to disk")
            return True
            
        except Exception as e:
            self.logger.error("Failed to mark graceful shutdown: %s", e)
            return False

    def _write_heartbeat(self):
        """Write heartbeat data to file with graceful shutdown tracking."""
        try:
            heartbeat_data = {
                'timestamp': time.time(),
                'session_id': self.session_id,
                'process_start': self.process_start_time,
                'heartbeat_interval': self.heartbeat_interval,
                'write_count': getattr(self, '_heartbeat_count', 0) + 1,
                'graceful_shutdown': False  # Will be set to True during graceful shutdown
            }
            
            # Atomic write
            temp_file = self.heartbeat_file + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(heartbeat_data, f, indent=2)
            os.replace(temp_file, self.heartbeat_file)
            
            self._heartbeat_count = heartbeat_data['write_count']
            
        except Exception as e:
            self.logger.error("Failed to write heartbeat: %s", e)

    def _mark_graceful_shutdown(self):
        """Mark the current session as gracefully shut down."""
        try:
            if os.path.exists(self.heartbeat_file):
                with open(self.heartbeat_file, 'r') as f:
                    data = json.load(f)
                    
                # Mark as graceful shutdown
                data['graceful_shutdown'] = True
                data['graceful_shutdown_time'] = time.time()
                
                # Atomic write
                temp_file = self.heartbeat_file + '.tmp'
                with open(temp_file, 'w') as f:
                    json.dump(data, f, indent=2)
                os.replace(temp_file, self.heartbeat_file)
                
                self.logger.debug("Marked session as gracefully shut down")
                
        except Exception as e:
            self.logger.error("Failed to mark graceful shutdown: %s", e)

    def _correlate_with_relay_data(self) -> Dict[str, Any]:
        """Correlate monitor data with relay power loss detection."""
        correlation_data = {
            'power_loss_detected': False,
            'affected_relays': [],
            'estimated_power_loss_time': None,
            'power_loss_duration': None
        }
        
        if self.relay and hasattr(self.relay, '_last_power_loss_data'):
            power_loss_events = getattr(self.relay, '_last_power_loss_data', [])
            
            if power_loss_events:
                correlation_data['power_loss_detected'] = True
                correlation_data['affected_relays'] = [event['relay_id'] for event in power_loss_events]
                
                # Estimate power loss time (earliest relay timestamp)
                if power_loss_events:
                    earliest_timestamp = min(event['last_on'] for event in power_loss_events)
                    correlation_data['estimated_power_loss_time'] = earliest_timestamp
                    
                    # Estimate power loss duration
                    if self.offline_duration:
                        estimated_power_loss_duration = self.offline_duration
                        correlation_data['power_loss_duration'] = estimated_power_loss_duration
                        
        return correlation_data

    def _detect_components(self) -> list[str]:
        """Detect and list available components."""
        components = []
        
        if self.emailer:
            components.append("✓ Emailer")
        else:
            components.append("✗ Emailer (not configured)")
            
        if self.relay:
            components.append("✓ Relay Controller")
        else:
            components.append("✗ Relay Controller (not available)")
            
        # Check for Proxmox (through relay controller or direct access)
        proxmox_available = False
        try:
            if hasattr(self.cfg, 'proxmox') and self.cfg.proxmox:
                proxmox_available = True
        except Exception:
            pass
            
        if proxmox_available:
            components.append("✓ Proxmox Helper (configured)")
        else:
            components.append("✗ Proxmox Helper (not configured)")
            
        # Monitor is always available (we're running it)
        components.append("✓ Monitor")
        
        return components

    def send_startup_notification(self):
        """Send enhanced startup notification with accurate graceful vs ungraceful detection."""
        if not self.emailer:
            self.logger.debug("No emailer available for startup notification")
            return
            
        try:
            subject = f"[Startup] PowerControl started (session {self.session_id})"
            
            body_parts = []
            body_parts.append(f"PowerControl STARTUP at {_iso(self.process_start_time)}")
            body_parts.append(f"Session ID: {self.session_id}")
            body_parts.append("")
            
            # Enhanced previous session analysis with graceful shutdown detection
            body_parts.append("=== DOWNTIME ANALYSIS ===")
            
            if self.heartbeat_file_status == "file_not_found":
                body_parts.append("Previous heartbeat: No heartbeat file found (first startup ever)")
                body_parts.append("Downtime: N/A (initial startup)")
                
            elif self.heartbeat_file_status == "permission_denied":
                body_parts.append("Previous heartbeat: Cannot read heartbeat file (permission error)")
                body_parts.append("Downtime: Unknown (check file permissions)")
                
            elif self.heartbeat_file_status == "corrupted":
                body_parts.append("Previous heartbeat: Heartbeat file corrupted")
                body_parts.append("Downtime: Unknown (file corruption detected)")
                
            elif self.heartbeat_file_status == "no_timestamp":
                body_parts.append("Previous heartbeat: File exists but no valid timestamp found")
                body_parts.append("Downtime: Unknown (invalid heartbeat data)")
                
            elif self.previous_heartbeat:
                body_parts.append(f"Previous heartbeat: {_iso(self.previous_heartbeat)}")
                body_parts.append(f"Previous session: {self.previous_session_id}")
                
                # Check if previous shutdown was graceful
                if self.previous_graceful_shutdown:
                    body_parts.append(f"Previous shutdown: GRACEFUL")
                    if self.previous_graceful_shutdown_time:
                        body_parts.append(f"Graceful shutdown time: {_iso(self.previous_graceful_shutdown_time)}")
                else:
                    body_parts.append(f"Previous shutdown: UNGRACEFUL or unknown")
                
                if self.offline_duration:
                    body_parts.append(f"Total offline time: {_format_duration(self.offline_duration)}")
                    
                    # Enhanced classification based on graceful shutdown detection
                    if self.previous_graceful_shutdown:
                        if self.offline_duration > self.heartbeat_interval * 10:  # >10 minutes
                            body_parts.append(f"🟡 Extended downtime after graceful shutdown: {_format_duration(self.offline_duration)}")
                            body_parts.append("     System was intentionally offline for extended period")
                        else:
                            body_parts.append(f"🟢 Clean graceful restart: {_format_duration(self.offline_duration)}")
                            body_parts.append("     Normal restart after graceful shutdown")
                    else:
                        # Ungraceful shutdown classification
                        if self.offline_duration > self.heartbeat_interval * 3:
                            body_parts.append(f"🔴 SIGNIFICANT OUTAGE DETECTED: {_format_duration(self.estimated_downtime)}")
                            body_parts.append("     This indicates unexpected shutdown or power loss")
                        elif self.offline_duration > self.heartbeat_interval * 2:
                            body_parts.append(f"🟡 Moderate outage detected: {_format_duration(self.estimated_downtime)}")
                            body_parts.append("     Possibly ungraceful shutdown")
                        else:
                            body_parts.append(f"🟢 Quick restart: {_format_duration(self.offline_duration)} offline")
                            body_parts.append("     Short offline period")
            else:
                body_parts.append("Previous heartbeat: Unknown error during analysis")
                
            body_parts.append("")
            
            # Power loss correlation (only for ungraceful shutdowns)
            correlation_data = self._correlate_with_relay_data()
            if correlation_data['power_loss_detected']:
                # Only report power loss if previous shutdown was NOT graceful
                if not self.previous_graceful_shutdown:
                    body_parts.append("=== POWER LOSS CORRELATION ===")
                    body_parts.append(f"⚠️ POWER LOSS DETECTED affecting {len(correlation_data['affected_relays'])} relays")
                    body_parts.append(f"Affected relays: {', '.join(correlation_data['affected_relays'])}")
                    
                    if correlation_data['estimated_power_loss_time']:
                        power_loss_time = _iso(correlation_data['estimated_power_loss_time'])
                        body_parts.append(f"Estimated power loss time: {power_loss_time}")
                        
                    if correlation_data['power_loss_duration']:
                        power_loss_duration = _format_duration(correlation_data['power_loss_duration'])
                        body_parts.append(f"Power was off for approximately: {power_loss_duration}")
                        
                    body_parts.append("All affected relays have been reset to OFF state")
                else:
                    body_parts.append("=== RELAY STATE CLEANUP ===")
                    body_parts.append(f"ℹ️ Cleaned up {len(correlation_data['affected_relays'])} relay states after graceful shutdown")
                    body_parts.append(f"Affected relays: {', '.join(correlation_data['affected_relays'])}")
                    body_parts.append("(This is normal cleanup after graceful shutdown)")
                    
                body_parts.append("")
            
            # System information
            body_parts.append("=== SYSTEM STATUS ===")
            system_uptime = _read_uptime_seconds()
            if system_uptime:
                body_parts.append(f"System uptime since boot: {_format_duration(system_uptime)}")
            
            process_uptime = time.time() - self.process_start_time
            body_parts.append(f"Process uptime: {_format_duration(process_uptime)}")
            
            # If system uptime is less than offline duration, system was rebooted
            if system_uptime and self.offline_duration and system_uptime < self.offline_duration:
                body_parts.append(f"📝 NOTE: System was rebooted during offline period")
                body_parts.append(f"       System boot time: ~{_format_duration(system_uptime)} ago")
                
            body_parts.append("")
            
            # Component status
            components = self._detect_components()
            body_parts.append("Active components:")
            for component in components:
                body_parts.append(component)
            body_parts.append("")
            
            # Enhanced notification settings snapshot (BEFORE relay status)
            if self.relay and hasattr(self.relay, 'get_notification_snapshot_details'):
                try:
                    snapshot_details = self.relay.get_notification_snapshot_details()
                    body_parts.append("=== NOTIFICATION SETTINGS SNAPSHOT ===")
                    for detail in snapshot_details:
                        body_parts.append(detail)
                    body_parts.append("")
                    
                    # Notification file timestamp
                    if hasattr(self.relay, 'notification_file'):
                        try:
                            mtime = os.path.getmtime(self.relay.notification_file)
                            body_parts.append(f"Notification snapshot last saved: {_iso(mtime)}")
                            body_parts.append("")
                        except Exception:
                            pass
                            
                except Exception as e:
                    self.logger.error("Failed to get notification snapshot details: %s", e)
                    body_parts.append("Notification snapshot: Error retrieving details")
                    body_parts.append("")
            
            # Current relay status  
            if self.relay:
                try:
                    status_lines = self.relay.get_status_lines()
                    body_parts.append("=== CURRENT RELAY STATUS ===")
                    for line in status_lines:
                        body_parts.append(line)
                    body_parts.append("")
                except Exception as e:
                    self.logger.error("Failed to get relay status: %s", e)
                    body_parts.append("Relay status: Error retrieving status")
                    body_parts.append("")
            
            body = "\n".join(body_parts)
            
            # Send notification
            self.emailer.send_sync(subject, body)
            self.logger.info("Enhanced startup notification sent (session: %s)", self.session_id)
            
        except Exception as e:
            self.logger.error("Failed to send startup notification: %s", e)

    def send_shutdown_notification(self):
        """Send enhanced shutdown notification and mark as graceful."""
        if not self.emailer:
            self.logger.debug("No emailer available for shutdown notification")
            return
            
        try:
            # CRITICAL: Mark this shutdown as graceful BEFORE sending notification
            self._mark_graceful_shutdown()
            
            session_duration = time.time() - self.process_start_time
            subject = f"[Shutdown] PowerControl stopped (session {self.session_id})"
            
            body_parts = []
            body_parts.append(f"PowerControl GRACEFUL SHUTDOWN at {_iso(time.time())}")
            body_parts.append(f"Session ID: {self.session_id}")
            body_parts.append(f"Session duration: {_format_duration(session_duration)}")
            body_parts.append("")
            
            # Heartbeat statistics
            if hasattr(self, '_heartbeat_count'):
                expected_heartbeats = max(1, int(session_duration / self.heartbeat_interval))
                body_parts.append(f"Heartbeats written: {self._heartbeat_count}/{expected_heartbeats}")
                body_parts.append("")
            
            # Final relay status
            if self.relay:
                try:
                    status_lines = self.relay.get_status_lines()
                    body_parts.append("=== FINAL RELAY STATUS ===")
                    for line in status_lines:
                        body_parts.append(line)
                    body_parts.append("")
                    
                    # Check for any relays that were ON
                    relay_status = self.relay.get_status()
                    active_relays = [r for r in relay_status if r.get('on', False)]
                    if active_relays:
                        body_parts.append("⚠️ WARNING: The following relays were ON at shutdown:")
                        for relay in active_relays:
                            body_parts.append(f"    Relay {relay['id']}: ON")
                        body_parts.append("(These will be properly cleaned up and reset to OFF)")
                        body_parts.append("")
                        
                except Exception as e:
                    body_parts.append(f"Relay status: Error retrieving status ({e})")
                    body_parts.append("")
            
            # Important notes about relay behavior
            body_parts.append("=== GRACEFUL SHUTDOWN NOTES ===")
            body_parts.append("🔌 All relays will return to OFF state after power loss/restart")
            body_parts.append("   Any currently ON relays will be automatically turned OFF when power is restored.")
            body_parts.append("")
            body_parts.append("💾 Session marked as graceful shutdown")
            body_parts.append("   Next startup will correctly identify this as intentional shutdown")
            
            body = "\n".join(body_parts)
            
            # Send notification  
            self.emailer.send_sync(subject, body)
            self.logger.info("Enhanced shutdown notification sent (session: %s)", self.session_id)
            
        except Exception as e:
            self.logger.error("Failed to send shutdown notification: %s", e)

    def _heartbeat_worker(self):
        """Heartbeat worker thread (unchanged functionality)."""
        self.logger.info("Monitor heartbeat worker started")
        
        while not self._stop_event.wait(self.heartbeat_interval):
            try:
                self._write_heartbeat()
                
            except Exception as e:
                self.logger.error("Heartbeat write failed: %s", e)
                
        self.logger.info("Monitor heartbeat worker stopped")

    def start(self):
        """Start monitor heartbeat (unchanged functionality)."""
        if self._thread and self._thread.is_alive():
            return
            
        self._stop_event.clear()
        self._thread = Thread(target=self._heartbeat_worker, name="MonitorHeartbeat", daemon=True)
        self._thread.start()
        
        self.logger.info("Monitor heartbeat started (interval: %.1fs)", self.heartbeat_interval)

    def stop(self):
        """Stop monitor with graceful shutdown marking."""
        if self._stop_event.is_set():
            return
        
        self._stop_event.set()
        
        try:
            # Mark this shutdown as graceful
            self._mark_graceful_shutdown()
            
            # ❌ USUŃ to: NIE wywołuj _write_heartbeat() tutaj!
            # _write_heartbeat() nadpisze flagę graceful_shutdown na False
            # _mark_graceful_shutdown() już zapisał wszystkie potrzebne dane
            
        except Exception:
            self.logger.exception("Final heartbeat write failed (graceful)")
        
        if self._thread:
            self._thread.join(timeout=3.0)
        
        self.logger.info("Monitor heartbeat stopped")