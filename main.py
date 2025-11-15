#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import signal
import sys
import time
import threading
from threading import Event, Lock
from typing import Optional

from app.config import load_config
from app.logger import setup_root_logger
from app.web import PowerControlWeb
from app.emailer import Emailer
from app.relay import RelayController
from app.monitor import Monitor
from app.proxmox import ProxmoxHelper

class PowerControlApp:
    """Główna klasa aplikacji z bezpiecznym zarządzaniem lifecycle."""
    
    def __init__(self):
        self.cfg = None
        self.logger = None
        self.emailer = None
        self.relay = None
        self.monitor = None
        self.proxmox = None
        self.web = None
        
        self._shutdown_lock = Lock()
        self._shutdown_called = False
        self._stop_event = Event()
        
    def _validate_config(self, cfg) -> bool:
        """Walidacja podstawowej struktury konfiguracji."""
        if cfg is None:
            return False
        
        # Sprawdź czy ma podstawowe atrybuty lub jest dict-like
        if hasattr(cfg, '__dict__') or isinstance(cfg, dict):
            return True
            
        return False
    
    def _wait_for_smtp(self, timeout_total: int = 15, per_try: int = 3) -> bool:
        """Sprawdza dostępność serwera SMTP tylko jeśli emailer został utworzony."""
        if not self.emailer:
            self.logger.debug("No emailer available, skipping SMTP check")
            return True
            
        import socket
        
        try:
            email_cfg = {}
            if hasattr(self.cfg, "email"):
                email_cfg = getattr(self.cfg, "email") or {}
            elif isinstance(self.cfg, dict):
                email_cfg = self.cfg.get("email", {}) or {}
                
            server = email_cfg.get("server", "smtp.gmail.com")
            port = int(email_cfg.get("port", 465))
        except Exception:
            self.logger.debug("No valid email config for SMTP check")
            return True
            
        deadline = time.time() + float(timeout_total)
        
        while time.time() < deadline and not self._stop_event.is_set():
            try:
                with socket.create_connection((server, port), timeout=per_try):
                    self.logger.info("SMTP server %s:%s reachable", server, port)
                    return True
            except Exception:
                time.sleep(1.0)
                
        self.logger.warning("SMTP server %s:%s not reachable after %ss", server, port, timeout_total)
        return False
    
    def _initialize_components(self) -> bool:
        """Inicjalizuje wszystkie komponenty aplikacji."""
        
        # 1. Konfiguracja i logger
        try:
            self.cfg = load_config()
            if not self._validate_config(self.cfg):
                print("ERROR: Invalid or missing configuration", file=sys.stderr)
                return False
                
            self.logger = setup_root_logger(self.cfg)
            self.logger.info("Starting PowerControl - configuration loaded")
        except Exception as e:
            print(f"ERROR: Failed to load config/logger: {e}", file=sys.stderr)
            return False
        
        # 2. Emailer (opcjonalny)
        try:
            self.emailer = Emailer(self.cfg, self.logger)
            self.logger.info("Emailer initialized successfully")
        except Exception:
            self.logger.exception("Failed to initialize Emailer; continuing without email support")
            self.emailer = None
            
        # 3. RelayController (opcjonalny)
        try:
            relay_pins = getattr(self.cfg, "relay_pins", [])
            switch_pins = getattr(self.cfg, "switch_pins", [])
            self.relay = RelayController(relay_pins, switch_pins, self.logger,
                                       emailer=self.emailer, cfg=self.cfg)
            self.logger.info("RelayController initialized successfully")
        except Exception:
            self.logger.exception("Failed to initialize RelayController")
            self.relay = None
            
        # 4. ProxmoxHelper (opcjonalny)
        try:
            if hasattr(self.cfg, 'proxmox') and getattr(self.cfg, 'proxmox'):
                self.proxmox = ProxmoxHelper(self.cfg, self.logger)
                self.logger.info("ProxmoxHelper initialized successfully")
            else:
                self.logger.info("No Proxmox configuration found, skipping Proxmox integration")
        except Exception:
            self.logger.exception("Failed to initialize ProxmoxHelper")
            self.proxmox = None
            
        # 5. Monitor (opcjonalny)
        try:
            self.monitor = Monitor(self.cfg, self.emailer, self.relay, self.logger)
            self.logger.info("Monitor initialized successfully")
        except Exception:
            self.logger.exception("Failed to initialize Monitor")
            self.monitor = None
            
        # 6. Web service (wymagany) - BEZ parametru monitor w konstruktorze
        try:
            self.web = PowerControlWeb(self.cfg, self.logger, 
                                     emailer=self.emailer, 
                                     relay=self.relay, 
                                     proxmox=self.proxmox)
            
            # Dodaj monitor przez setattr jeśli jest dostępny
            if self.monitor:
                setattr(self.web, "monitor", self.monitor)
                self.logger.debug("Monitor attached to web service")
                
            self.logger.info("Web service initialized successfully")
        except Exception:
            self.logger.exception("Failed to initialize Web service")
            self.web = None
            return False  # Web service jest krytyczny
            
        return True
    
    def _graceful_shutdown(self):
        """Bezpieczny shutdown z ochroną przed wielokrotnym wywołaniem."""
        with self._shutdown_lock:
            if self._shutdown_called:
                if self.logger:
                    self.logger.debug("Shutdown already in progress, ignoring duplicate call")
                return
            
            self._shutdown_called = True
            self._stop_event.set()
            
            if self.logger:
                self.logger.info("Initiating graceful shutdown...")
            
            #POPRAWKA 1: Zapisz flagę graceful NATYCHMIAST (przed wszystkim!)
            if self.monitor:
                try:
                    self.logger.info("Marking graceful shutdown in heartbeat file...")
                    self.monitor.mark_graceful_shutdown_immediate()
                    self.logger.info("Graceful shutdown flag saved")
                except Exception:
                    if self.logger:
                        self.logger.exception("Failed to mark graceful shutdown")
            
            # Teraz dopiero reszta (email może trwać długo)
            # 1. Wyślij powiadomienie o shutdown (potrzebuje emailera)
            if self.monitor:
                try:
                    self.logger.info("Sending shutdown notification...")
                    self.monitor.send_shutdown_notification()
                except Exception:
                    if self.logger:
                        self.logger.exception("Error while sending shutdown notification")
            
            # 2. Zatrzymaj monitor (heartbeat)
            if self.monitor:
                try:
                    self.monitor.stop()
                    if self.logger:
                        self.logger.debug("Monitor stopped")
                except Exception:
                    if self.logger:
                        self.logger.exception("Error stopping monitor")
            
            # 3. Zatrzymaj web service
            if self.web:
                try:
                    if self.logger:
                        self.logger.info("Stopping web service...")
                    self.web.stop()
                except Exception:
                    if self.logger:
                        self.logger.exception("Error stopping web service")
            
            # 4. Zatrzymaj emailer jako ostatni (potrzebny do końca)
            if self.emailer:
                try:
                    if self.logger:
                        self.logger.info("Shutting down email worker...")
                    self.emailer.shutdown()
                except Exception:
                    if self.logger:
                        self.logger.exception("Error shutting down emailer")
            
            if self.logger:
                self.logger.info("Graceful shutdown completed")

    def _signal_handler(self, signum, frame):
        """Handler sygnałów - ustawia flagę stop i pozwala głównemu wątkowi zakończyć."""
        if self.logger:
            self.logger.info("Signal %s received -> initiating shutdown", signum)
        
        self._stop_event.set()
        
        # Przywróć domyślny handler i przekaż sygnał dalej po cleanup
        signal.signal(signum, signal.SIG_DFL)
    
    def _start_services(self) -> bool:
        """Uruchamia usługi w odpowiedniej kolejności."""
        
        # 1. Start monitor (heartbeat)
        if self.monitor:
            try:
                self.monitor.start()
                self.logger.info("Monitor (heartbeat) started")
            except Exception:
                self.logger.exception("Failed to start monitor")
                
        # 2. Sprawdź SMTP (jeśli jest emailer)
        try:
            smtp_ok = self._wait_for_smtp(timeout_total=15)
            if not smtp_ok and self.emailer:
                self.logger.warning("SMTP not available, email notifications may fail")
        except Exception:
            self.logger.exception("SMTP connectivity check failed")
            
        # 3. Wyślij powiadomienie o starcie
        if self.monitor:
            try:
                self.logger.info("Sending startup notification...")
                self.monitor.send_startup_notification()
            except Exception:
                self.logger.exception("Failed to send startup notification")
                
        # 4. Start web service (krytyczny)
        if self.web:
            try:
                self.web.start()
                self.logger.info("Web service started successfully")
                return True
            except Exception:
                self.logger.exception("Failed to start web service")
                return False
        else:
            self.logger.error("No web service available")
            return False
    
    def run(self) -> int:
        """Główna metoda uruchamiająca aplikację."""
        
        # Inicjalizacja komponentów
        if not self._initialize_components():
            print("ERROR: Failed to initialize critical components", file=sys.stderr)
            return 2
            
        # Ustawienie handlerów sygnałów
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Uruchomienie usług
        try:
            if not self._start_services():
                self.logger.error("Failed to start services")
                self._graceful_shutdown()
                return 2
        except Exception:
            self.logger.exception("Unhandled exception during service startup")
            self._graceful_shutdown()
            return 2
            
        # Główna pętla aplikacji
        self.logger.info("PowerControl is running. Press Ctrl+C to stop.")
        
        try:
            # Czekaj na sygnał stop lub KeyboardInterrupt
            while not self._stop_event.is_set():
                self._stop_event.wait(0.5)
                
        except KeyboardInterrupt:
            self.logger.info("KeyboardInterrupt received")
            
        except Exception:
            self.logger.exception("Unhandled exception in main loop")
            
        finally:
            self._graceful_shutdown()
            
        self.logger.info("PowerControl stopped")
        return 0


def main() -> int:
    """Punkt wejścia aplikacji."""
    app = PowerControlApp()
    return app.run()


if __name__ == "__main__":
    sys.exit(main())
