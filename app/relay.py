# app/relay.py
# -*- coding: utf-8 -*-

"""
Relay controller with persistent notification state + notification worker.
COMPLETE VERSION with Relay 5 dependency, email config control, and graceful shutdown detection.

Handles migration from legacy boolean file format:
{"1": true, "2": false, ...}

to the extended structure:
{"1": {"enabled": true, "last_on": 169..., "notified": false}, ...}

IMPORTANT: 
- Relays default to OFF state when power is lost/restored
- Relay 5 (pin 19) has dependency logic - auto ON when dependent relays active
- Email notifications can be disabled via enable_relay_event_emails config
- Graceful shutdown detection prevents false power loss alerts
"""

from typing import List, Optional, Dict, Any
import time
from threading import Timer, Lock, Thread, Event
from queue import Queue
import json
import os
import logging

try:
    from gpiozero import LED, Button  # real hardware
    _GPIO_AVAILABLE = True
except Exception:
    _GPIO_AVAILABLE = False
    # Mock classes for testing
    class LED:
        def __init__(self, pin, active_high=False):
            self.pin = pin
            self.is_lit = False
        def on(self): self.is_lit = True
        def off(self): self.is_lit = False
    
    class Button:
        def __init__(self, pin, pull_up=True, bounce_time=0.1):
            self.pin = pin
            self.when_pressed = None
            self.when_held = None
            self.hold_time = 3

logger = logging.getLogger(__name__)

class RelayController:
    def __init__(
        self, 
        relay_pins: List[int], 
        switch_pins: List[int], 
        logger_obj, 
        emailer: Optional[Any] = None, 
        cfg: Optional[Any] = None
    ):
        self.logger = logger_obj
        self.emailer = emailer
        self.cfg = cfg
        
        self.relay_pins = list(relay_pins)
        self.switch_pins = list(switch_pins)
        
        # Threading
        self.state_lock = Lock()
        self.stop_event = Event()
        
        # Notification settings
        self.notification_file = getattr(cfg, 'relay_notification_file', 'relay_notifications.json')
        self.notify_threshold_s = float(getattr(cfg, 'relay_notify_threshold_s', 5*3600))  # 5 hours
        
        # Event batching for ON/OFF emails
        self.event_queue = Queue()
        self.batch_timer = None
        self.batch_lock = Lock()
        
        # Initialize hardware (all relays start OFF after power loss)
        self.Relays = [LED(pin, active_high=False) for pin in self.relay_pins]
        self.Switches = [Button(pin, pull_up=True, bounce_time=0.1) for pin in self.switch_pins]
        
        # Ensure all relays are OFF at startup (power loss recovery)
        for relay in self.Relays:
            relay.off()
        
        # Load/migrate notification states
        self.notification_states = {}
        self.load_notification_states()
        
        # CRITICAL: Sync notification state with hardware reality after power loss
        self.sync_states_on_startup()
        
        # Setup switch callbacks
        self.setup_switches()
        
        # Start notification worker
        self.notification_worker_thread = Thread(
            target=self._notification_worker,
            name="RelayNotificationWorker",
            daemon=True
        )
        self.notification_worker_thread.start()
        
        self.logger.info("RelayNotificationWorker started (threshold=%ds) file=%s", 
                        self.notify_threshold_s, self.notification_file)

    def _default_state(self) -> Dict[str, Any]:
        """Default notification state for a relay."""
        return {
            "enabled": True,    # Notifications enabled by default
            "last_on": None,    # When relay was turned on (None = not currently on)
            "notified": False   # Whether long-running notification was sent
        }

    def sync_states_on_startup(self):
        """
        CRITICAL: Sync notification state with hardware reality.
        
        Since relays default to OFF after power loss, any relay that has
        last_on timestamp but is currently OFF might indicate power loss.
        However, we need to distinguish between power loss and graceful shutdown.
        """
        cleaned_relays = []
        potentially_lost_data = []
        
        # Try to determine if previous shutdown was graceful
        previous_graceful_shutdown = False
        try:
            # Check monitor's heartbeat file for graceful shutdown marker
            monitor_heartbeat_file = getattr(self.cfg, 'heartbeat_file', 'last_heartbeat.json')
            if os.path.exists(monitor_heartbeat_file):
                with open(monitor_heartbeat_file, 'r') as f:
                    heartbeat_data = json.load(f)
                    previous_graceful_shutdown = heartbeat_data.get('graceful_shutdown', False)
                    self.logger.debug("Previous shutdown was %s", 
                                     "graceful" if previous_graceful_shutdown else "ungraceful/unknown")
        except Exception as e:
            self.logger.debug("Could not determine previous shutdown type: %s", e)
        
        with self.state_lock:
            for idx, relay in enumerate(self.Relays):
                relay_id = str(idx + 1)
                
                # Hardware state after power loss/restart (always OFF at startup)
                hardware_on = getattr(relay, 'is_lit', False)  # Should be False
                
                # Get notification state
                st = self.notification_states.get(relay_id, self._default_state())
                
                # Check for inconsistency (relay OFF but notification thinks it was ON)
                had_last_on = st.get("last_on") is not None
                
                if not hardware_on and had_last_on:
                    old_timestamp = st["last_on"]
                    
                    # Determine if this is power loss or graceful shutdown cleanup
                    if previous_graceful_shutdown:
                        # Graceful shutdown - this is normal cleanup
                        self.logger.debug("Relay %s: cleaning up notification state after graceful shutdown", relay_id)
                        cleanup_reason = "graceful_shutdown_cleanup"
                    else:
                        # Ungraceful shutdown or power loss
                        self.logger.debug("Relay %s: detected stale timestamp (potential power loss)", relay_id)
                        cleanup_reason = "power_loss"
                        
                        potentially_lost_data.append({
                            'relay_id': relay_id,
                            'last_on': old_timestamp,
                            'lost_duration': int(time.time() - old_timestamp) if old_timestamp else 0,
                            'reason': cleanup_reason
                        })
                    
                    # Clean up notification state regardless of reason
                    st["last_on"] = None
                    st["notified"] = False
                    cleaned_relays.append(relay_id)
                    
                elif not hardware_on:
                    # Relay OFF and state consistent - ensure clean state
                    st["last_on"] = None
                    st["notified"] = False
                
                # Ensure enabled flag is properly set (fix the enabled=False bug)
                if "enabled" not in st:
                    st["enabled"] = True  # Default to notifications enabled
                    
                self.notification_states[relay_id] = st
            
            # Save cleaned states
            self.save_notification_states()
            
        # Store power loss data for monitor correlation (only real power loss events)
        real_power_loss_data = [item for item in potentially_lost_data if item.get('reason') == 'power_loss']
        self._last_power_loss_data = real_power_loss_data
        
        # Log startup cleanup with appropriate messages
        if cleaned_relays:
            if previous_graceful_shutdown:
                self.logger.info("Cleaned up notification states for relays %s after graceful shutdown", 
                                ', '.join(cleaned_relays))
            else:
                self.logger.info("Cleaned up notification states for relays %s after power loss/restart", 
                                ', '.join(cleaned_relays))
        
        if real_power_loss_data:
            self.logger.warning("Detected %d relays with stale timestamps (potential power loss)", 
                               len(real_power_loss_data))
            for item in real_power_loss_data:
                self.logger.debug("Relay %s: last_on timestamp %s, lost duration ~%ds", 
                                 item['relay_id'], item['last_on'], item['lost_duration'])
        elif potentially_lost_data and previous_graceful_shutdown:
            self.logger.info("Cleaned up %d relay notification states after graceful shutdown (normal operation)", 
                            len(potentially_lost_data))
                
        return real_power_loss_data  # Return only real power loss events

    def load_notification_states(self):
        """Load notification states from file with legacy migration."""
        try:
            if os.path.exists(self.notification_file):
                with open(self.notification_file, 'r') as f:
                    data = json.load(f)
                    
                # Check if legacy format {"1": true, "2": false}
                if data and isinstance(list(data.values())[0], bool):
                    self.logger.info("Migrating legacy notification file format")
                    self._migrate_legacy(data)
                else:
                    self.notification_states = data
            else:
                # Initialize default states
                self.notification_states = {
                    str(i+1): self._default_state() 
                    for i in range(len(self.relay_pins))
                }
                self.save_notification_states()
                
        except Exception as e:
            self.logger.error("Failed to load notification states: %s", e)
            # Fallback to defaults
            self.notification_states = {
                str(i+1): self._default_state() 
                for i in range(len(self.relay_pins))
            }

    def _migrate_legacy(self, legacy_data: Dict[str, bool]):
        """Migrate from legacy boolean format to extended format."""
        migrated = {}
        for relay_id, was_enabled in legacy_data.items():
            migrated[str(relay_id)] = {
                "enabled": bool(was_enabled),  # Preserve notification preference
                "last_on": None,  # Reset tracking state
                "notified": False
            }
        
        self.notification_states = migrated
        self.save_notification_states()
        self.logger.info("Notification snapshot migrated from legacy format")

    def save_notification_states(self):
        """Atomically save notification states to file."""
        try:
            temp_file = self.notification_file + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(self.notification_states, f, indent=2)
            os.replace(temp_file, self.notification_file)
            
        except Exception as e:
            self.logger.error("Failed to save notification states: %s", e)

    def get_notification_snapshot_details(self) -> List[str]:
        """Get detailed snapshot info for email notifications."""
        details = []
        
        with self.state_lock:
            for idx in range(len(self.Relays)):
                relay_id = str(idx + 1)
                st = self.notification_states.get(relay_id, {})
                relay = self.Relays[idx]
                
                enabled = st.get("enabled", True)
                last_on = st.get("last_on")
                notified = st.get("notified", False)
                hardware_on = getattr(relay, 'is_lit', False)
                
                # Build status line
                notify_status = "ON" if enabled else "OFF"
                relay_status = "ON" if hardware_on else "OFF"
                
                if last_on and hardware_on:
                    duration = int(time.time() - last_on)
                    if duration < 60:
                        duration_str = f"{duration}s"
                    elif duration < 3600:
                        duration_str = f"{duration//60}m {duration%60}s"
                    else:
                        hours = duration // 3600
                        minutes = (duration % 3600) // 60
                        duration_str = f"{hours}h {minutes}m"
                    
                    notify_sent = "YES" if notified else "NO"
                    details.append(f"Relay {relay_id}: notifications {notify_status}, "
                                 f"relay {relay_status} (since {duration_str}), notification sent: {notify_sent}")
                else:
                    last_active = "never"
                    if last_on:
                        ago = int(time.time() - last_on)
                        if ago < 3600:
                            last_active = f"{ago//60}m ago"
                        else:
                            last_active = f"{ago//3600}h {(ago%3600)//60}m ago"
                    
                    details.append(f"Relay {relay_id}: notifications {notify_status}, "
                                 f"relay {relay_status}, last active: {last_active}")
                    
        return details

    def turn_on(self, idx: int):
        """Turn on relay and update notification state."""
        if 0 <= idx < len(self.Relays):
            self.Relays[idx].on()
            
            # FIXED: Don't reset enabled to False, preserve user setting
            relay_id = str(idx + 1)
            with self.state_lock:
                st = self.notification_states.get(relay_id, self._default_state())
                st["last_on"] = int(time.time())
                st["notified"] = False  # Reset notification flag for new session
                # enabled stays as user configured it
                self.notification_states[relay_id] = st
                
            self.save_notification_states()
            self.add_relay_event(idx + 1, True)
            self.logger.debug("Relay %d turned ON, notification tracking updated", idx + 1)

    def turn_off(self, idx: int):
        """Turn off relay and update notification state."""  
        if 0 <= idx < len(self.Relays):
            self.Relays[idx].off()
            
            # FIXED: Don't reset enabled to False, preserve user setting  
            relay_id = str(idx + 1)
            with self.state_lock:
                st = self.notification_states.get(relay_id, self._default_state())
                st["last_on"] = None  # Relay is now OFF
                st["notified"] = False  # Reset notification flag
                # enabled stays as user configured it
                self.notification_states[relay_id] = st
                
            self.save_notification_states() 
            self.add_relay_event(idx + 1, False)
            self.logger.debug("Relay %d turned OFF, notification tracking updated", idx + 1)

    def control_relay_19(self, force_on: bool = False):
        """
        Special logic for relay 19 (Relay 5) dependency.
        
        Relay 5 (pin 19) should automatically turn ON when any of the dependent relays are ON:
        - Relay 1 (pin 5) 
        - Relay 2 (pin 6)
        - Relay 4 (pin 16) 
        - Relay 6 (pin 20)
        - Relay 8 (pin 26)
        
        And turn OFF when all dependent relays are OFF.
        """
        try:
            # Dependent pins that should trigger Relay 5 (pin 19)
            dependent_pins = [5, 6, 16, 20, 26]
            
            # Find indices of dependent relays
            dependent_indices = []
            for pin in dependent_pins:
                try:
                    idx = self.relay_pins.index(pin)
                    dependent_indices.append(idx)
                except ValueError:
                    # Pin not in relay_pins - skip it
                    continue
            
            # Find Relay 5 (pin 19) index
            try:
                relay5_pin = 19
                relay5_index = self.relay_pins.index(relay5_pin)
            except ValueError:
                # Pin 19 not in relay_pins - can't control it
                self.logger.debug("control_relay_19: Pin 19 not found in relay_pins")
                return
            
            # Check if any dependent relay is ON
            any_dependent_on = any(
                getattr(self.Relays[idx], 'is_lit', False) 
                for idx in dependent_indices
            )
            
            # Get current state of Relay 5 (pin 19)
            relay5_current_state = getattr(self.Relays[relay5_index], 'is_lit', False)
            
            # Apply logic
            if force_on:
                # Force Relay 5 ON regardless of dependencies
                if not relay5_current_state:
                    self.turn_on(relay5_index)
                    self.logger.info("control_relay_19: Forced Relay 5 ON")
                    
            elif any_dependent_on and not relay5_current_state:
                # Turn Relay 5 ON because dependents are active
                self.turn_on(relay5_index)
                self.logger.info("control_relay_19: Relay 5 auto-turned ON (dependents active)")
                
            elif not any_dependent_on and relay5_current_state:
                # Turn Relay 5 OFF because no dependents are active
                self.turn_off(relay5_index)
                self.logger.info("control_relay_19: Relay 5 auto-turned OFF (no dependents active)")
            
            # Log current state for debugging
            self.logger.debug("control_relay_19: dependent_pins=%s, any_on=%s, relay5_state=%s", 
                             dependent_pins, any_dependent_on, relay5_current_state)
                
        except Exception as e:
            self.logger.exception("control_relay_19 failed: %s", e)

    def cleanup_for_graceful_shutdown(self):
        """
        Clean up notification states during graceful shutdown.
        This prevents false positive power loss detection on next startup.
        """
        try:
            with self.state_lock:
                cleaned_count = 0
                for relay_id, st in self.notification_states.items():
                    if st.get("last_on") is not None:
                        st["last_on"] = None
                        st["notified"] = False
                        cleaned_count += 1
                        
                if cleaned_count > 0:
                    self.save_notification_states()
                    self.logger.info("Cleaned up %d relay notification timestamps for graceful shutdown", cleaned_count)
                    
        except Exception as e:
            self.logger.error("Error cleaning up notification states for graceful shutdown: %s", e)

    def get_status(self) -> List[Dict[str, Any]]:
        """Get relay status for web API."""
        result = []
        for idx, relay in enumerate(self.Relays):
            result.append({
                "id": idx + 1,
                "on": getattr(relay, 'is_lit', False)
            })
        return result

    def get_status_lines(self) -> List[str]:
        """Get relay status lines for monitor email."""
        status_lines = []
        for idx, relay in enumerate(self.Relays):
            is_on = getattr(relay, 'is_lit', False)
            if is_on:
                status_lines.append(f"Relay {idx + 1}: (on) włączony ⚡")
            else:
                status_lines.append(f"Relay {idx + 1}: (off) wyłączony")
        return status_lines

    def get_notification_states(self) -> Dict[str, Any]:
        """Get notification states for debug endpoint."""
        with self.state_lock:
            return dict(self.notification_states)

    def set_notification_enabled(self, relay_id: int, enabled: bool):
        """Enable/disable notifications for specific relay."""
        relay_key = str(relay_id)
        with self.state_lock:
            if relay_key in self.notification_states:
                self.notification_states[relay_key]["enabled"] = enabled
                self.save_notification_states()
                self.logger.info("Relay %d notifications %s", relay_id, 
                               "enabled" if enabled else "disabled")
                return True
        return False

    def add_relay_event(self, relay_id: int, turned_on: bool):
        """Add relay ON/OFF event to batch queue (respects config setting)."""
        
        # Check if relay event emails are enabled in config
        try:
            if self.cfg and not getattr(self.cfg, 'enable_relay_event_emails', True):
                self.logger.debug("Relay event emails disabled in config - skipping event for relay %d", relay_id)
                return
        except Exception as e:
            self.logger.debug("Error checking enable_relay_event_emails config: %s", e)
            
        try:
            self.event_queue.put({
                'relay_id': relay_id,
                'turned_on': turned_on,
                'timestamp': time.time()
            }, block=False)
            
            with self.batch_lock:
                if self.batch_timer is None:
                    # Start batch timer (send email after 30s of inactivity)
                    self.batch_timer = Timer(30.0, self._send_batched_events)
                    self.batch_timer.start()
                    
        except Exception as e:
            self.logger.error("Failed to queue relay event: %s", e)

    def _send_batched_events(self):
        """Send batched relay events email (checks config setting)."""
        
        # Check if relay event emails are enabled
        try:
            if self.cfg and not getattr(self.cfg, 'enable_relay_event_emails', True):
                # Drain the queue without sending emails
                drained_count = 0
                while not self.event_queue.empty():
                    try:
                        self.event_queue.get_nowait()
                        drained_count += 1
                    except:
                        break
                        
                if drained_count > 0:
                    self.logger.info("Relay event emails disabled in config - dropped %d queued events", drained_count)
                return
        except Exception as e:
            self.logger.debug("Error checking enable_relay_event_emails config: %s", e)
        
        if not self.emailer:
            # Drain queue if no emailer available
            drained_count = 0
            while not self.event_queue.empty():
                try:
                    self.event_queue.get_nowait()
                    drained_count += 1
                except:
                    break
            
            if drained_count > 0:
                self.logger.debug("No emailer available - dropped %d queued events", drained_count)
            return
            
        events = []
        try:
            while not self.event_queue.empty():
                events.append(self.event_queue.get_nowait())
        except:
            pass
            
        with self.batch_lock:
            self.batch_timer = None
            
        if not events:
            return
            
        # Group events and send email
        try:
            subject = f"Relay Events ({len(events)} events)"
            
            body_lines = ["Relay state changes:"]
            for event in events:
                action = "turned ON ⚡" if event['turned_on'] else "turned OFF"
                timestamp = time.strftime("%H:%M:%S", time.localtime(event['timestamp']))
                body_lines.append(f"[{timestamp}] Relay {event['relay_id']}: {action}")
                
            body = "\n".join(body_lines)
            
            self.emailer.send(subject, body)
            self.logger.debug("Sent batched relay events email (%d events)", len(events))
            
        except Exception as e:
            self.logger.error("Failed to send batched relay events: %s", e)

    def _notification_worker(self):
        """Worker thread checking for long-running relays."""
        self.logger.info("RelayNotificationWorker started")
        
        while not self.stop_event.wait(60):  # Check every 60 seconds
            try:
                with self.state_lock:
                    current_time = time.time()
                    
                    for relay_id, st in self.notification_states.items():
                        # Check if notifications enabled and relay is running
                        if not st.get("enabled", False):
                            continue
                            
                        last_on = st.get("last_on")
                        if not last_on:
                            continue
                            
                        if st.get("notified", False):
                            continue  # Already notified
                            
                        # Check if running too long
                        running_time = current_time - last_on
                        if running_time >= self.notify_threshold_s:
                            self._send_long_running_notification(relay_id, running_time)
                            st["notified"] = True
                            
                    # Save updated notification flags
                    self.save_notification_states()
                    
            except Exception as e:
                self.logger.error("Error in notification worker: %s", e)
                
        self.logger.info("RelayNotificationWorker stopped")

    def _send_long_running_notification(self, relay_id: str, running_time: float):
        """Send notification about long-running relay."""
        if not self.emailer:
            return
            
        try:
            hours = running_time / 3600
            if hours < 24:
                duration_str = f"{hours:.1f} hours"
            else:
                days = hours / 24
                duration_str = f"{days:.1f} days"
                
            subject = f"[ALERT] Relay {relay_id} running for {duration_str}"
            
            body = f"""Relay {relay_id} has been running for {duration_str}.

Please check if this is intentional or if the relay should be turned off.

Notification threshold: {self.notify_threshold_s/3600:.1f} hours
Current status: ON ⚡"""

            self.emailer.send(subject, body)
            self.logger.warning("Sent long-running notification for Relay %s (%.1f hours)", 
                               relay_id, hours)
            
        except Exception as e:
            self.logger.error("Failed to send long-running notification: %s", e)

    def setup_switches(self):
        """Setup physical switch callbacks."""
        for idx, switch in enumerate(self.Switches):
            if hasattr(switch, 'when_pressed'):
                switch.when_pressed = lambda idx=idx: self.toggle_relay(idx)
                
        self.logger.debug("Physical switches configured")

    def toggle_relay(self, idx: int):
        """Toggle relay state (for physical switches)."""
        if 0 <= idx < len(self.Relays):
            if getattr(self.Relays[idx], 'is_lit', False):
                self.turn_off(idx)
            else:
                self.turn_on(idx)

    def turn_on_all(self):
        """Turn on all relays."""
        for idx in range(len(self.Relays)):
            self.turn_on(idx)

    def turn_off_all(self):
        """Turn off all relays."""
        for idx in range(len(self.Relays)):
            self.turn_off(idx)

    def stop(self):
        """Stop notification worker and cleanup."""
        # Clean up notification states for graceful shutdown
        self.cleanup_for_graceful_shutdown()
        
        self.stop_event.set()
        
        if hasattr(self, 'notification_worker_thread'):
            self.notification_worker_thread.join(timeout=5)
            
        with self.batch_lock:
            if self.batch_timer:
                self.batch_timer.cancel()
                self.batch_timer = None
                
        # Send any remaining batched events
        self._send_batched_events()
        
        self.logger.info("RelayController stopped")
