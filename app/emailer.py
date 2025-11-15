# app/emailer.py
# -*- coding: utf-8 -*-
"""
Emailer: prosty worker + send_sync/send API.

- recipients pochodzą z konfiguracji (cfg.email.recipient)
- opcjonalnie filtrujemy adres nadawcy z listy odbiorców (cfg.email.exclude_sender_from_recipients, default True)
- opcjonalny nagłówek From niezależny od konta SMTP (cfg.email.from_address)
"""
from __future__ import annotations
import threading
import time
import smtplib
import ssl
from email.mime.text import MIMEText
from typing import Any, Optional, List, Dict
from queue import Queue, Empty

import logging
import os

logger = logging.getLogger(__name__)


def _normalize_recipients(r) -> List[str]:
    if not r:
        return []
    if isinstance(r, (list, tuple)):
        return [str(x).strip() for x in r if x]
    if isinstance(r, str):
        parts = [p.strip() for p in r.split(",") if p.strip()]
        return parts
    return [str(r)]


class Emailer:
    def __init__(self, cfg: Any, logger_obj: Optional[logging.Logger] = None):
        self.logger = logger_obj or logger
        self.cfg = cfg

        # read email configuration (support dataclass or dict)
        email_cfg: Dict[str, Any] = {}
        if hasattr(cfg, "email"):
            email_cfg = getattr(cfg, "email") or {}
        elif isinstance(cfg, dict):
            email_cfg = cfg.get("email", {}) or {}

        # global enable flag
        self.enabled_global = bool(getattr(cfg, "enable_email_notifications", True))
        self.enabled = bool(email_cfg.get("enabled", True))

        # server settings
        self.server = email_cfg.get("server", "smtp.gmail.com")
        self.port = int(email_cfg.get("port", 465) or 465)
        self.username = email_cfg.get("address") or email_cfg.get("username") or ""
        self.password = email_cfg.get("password") or ""
        self.use_ssl = bool(int(email_cfg.get("use_ssl", 1))) if str(email_cfg.get("use_ssl", "1")).strip() else True
        self.use_starttls = bool(email_cfg.get("starttls", False)) or (not self.use_ssl and self.port in (587, 25))

        # recipients (authoritative)
        self.recipients = _normalize_recipients(email_cfg.get("recipient") or email_cfg.get("recipients") or [])

        # optional header-from (can be different from login username)
        self.from_address = email_cfg.get("from_address") or self.username

        # option: exclude sender (login username) from recipients list before sending
        self.exclude_sender_from_recipients = bool(email_cfg.get("exclude_sender_from_recipients", True))

        # readiness
        self._ready = bool(self.username and self.password and self.recipients and self.enabled_global and self.enabled)

        # queue + worker
        self._queue: "Queue[Dict[str,Any]]" = Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._worker_stop = threading.Event()
        self._worker_lock = threading.Lock()
        if self._ready:
            self._start_worker()
        else:
            self.logger.info("Emailer initialized not-ready (ready=%s). recipients=%s from=%s exclude_sender=%s",
                             self._ready, self.recipients, self.from_address, self.exclude_sender_from_recipients)

    # ---------- worker ----------
    def _start_worker(self):
        with self._worker_lock:
            if self._worker_thread and self._worker_thread.is_alive():
                return
            self._worker_stop.clear()
            self._worker_thread = threading.Thread(target=self._worker_loop, name="EmailerWorker", daemon=True)
            self._worker_thread.start()
            self.logger.info("Emailer worker started")

    def _worker_loop(self):
        self.logger.debug("Emailer worker loop running")
        while not self._worker_stop.is_set():
            try:
                item = self._queue.get(timeout=1.0)
            except Empty:
                continue
            try:
                subj = item.get("subject", "(no-subject)")
                body = item.get("body", "")
                ok = self._send_sync_internal(subj, body)
                if ok:
                    self.logger.info("Email sent: subj=%s to=%s", subj, ok if isinstance(ok, list) else self.recipients)
                else:
                    tries = item.get("tries", 0) + 1
                    if tries <= 3:
                        item["tries"] = tries
                        self.logger.warning("Email send failed in worker, requeueing (try %d): %s", tries, subj)
                        time.sleep(1.0 * tries)
                        self._queue.put(item)
                    else:
                        self.logger.error("Dropping email after %d failed attempts: %s", tries, subj)
            except Exception as e:
                self.logger.exception("Unhandled exception in email worker loop: %s", e)
            finally:
                try:
                    self._queue.task_done()
                except Exception:
                    pass
        self.logger.debug("Emailer worker loop exiting")

    # ---------- helper: filter recipients ----------
    def _resolve_recipients_for_send(self) -> List[str]:
        """Return actual recipients used for this send, possibly excluding sender."""
        recipients = [r.strip() for r in self.recipients if r and isinstance(r, str)]
        if self.exclude_sender_from_recipients and self.username:
            try:
                filtered = [r for r in recipients if r.lower() != self.username.lower()]
                return filtered
            except Exception:
                return recipients
        return recipients

    # ---------- internal synchronous send used by both send_sync and worker ----------
    def _send_sync_internal(self, subject: str, body: str, timeout: float = 15.0) -> Optional[List[str]]:
        """
        Internal: attempts to send and returns list of actual recipients on success,
        None on failure.
        """
        if not (self.enabled_global and self.enabled):
            self.logger.debug("Email disabled (global/local); _send_sync_internal aborted")
            return None

        actual_recipients = self._resolve_recipients_for_send()
        if not actual_recipients:
            self.logger.warning("After filtering recipients (exclude_sender=%s) no recipients remain; aborting send. configured=%s username=%s",
                                self.exclude_sender_from_recipients, self.recipients, self.username)
            return None

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.from_address
        msg["To"] = ", ".join(actual_recipients)

        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(self.server, self.port, context=context, timeout=timeout) as s:
                    s.login(self.username, self.password)
                    s.sendmail(self.from_address, list(actual_recipients), msg.as_string())
            else:
                with smtplib.SMTP(self.server, self.port, timeout=timeout) as s:
                    s.ehlo()
                    if self.use_starttls:
                        s.starttls(context=ssl.create_default_context())
                        s.ehlo()
                    if self.username and self.password:
                        s.login(self.username, self.password)
                    s.sendmail(self.from_address, list(actual_recipients), msg.as_string())
            # return recipients list to indicate success and to log
            return actual_recipients
        except Exception as e:
            self.logger.exception("Email send error to %s:%s recipients=%s: %s", self.server, self.port, actual_recipients, e)
            return None

    # ---------- public API ----------
    def send(self, subject: str, body: str) -> bool:
        if not (self.enabled_global and self.enabled):
            self.logger.debug("Email send requested but global/local email notifications disabled")
            return False
        if not self.recipients:
            self.logger.warning("Email send requested but no configured recipients; ignoring")
            return False
        if not (self._worker_thread and self._worker_thread.is_alive()):
            try:
                self._start_worker()
            except Exception:
                self.logger.exception("Failed to start email worker")
        try:
            self._queue.put_nowait({"subject": subject, "body": body, "tries": 0})
            self.logger.debug("Enqueued email: subj=%s configured_recipients=%s", subject, self.recipients)
            return True
        except Exception:
            self.logger.exception("Failed to enqueue email")
            return False

    def send_sync(self, subject: str, body: str, timeout: float = 15.0) -> bool:
        """Public synchronous send; returns True on success."""
        if not (self.enabled_global and self.enabled):
            self.logger.debug("send_sync called but global/local email notifications disabled")
            return False
        if not self.recipients:
            self.logger.warning("send_sync called but no configured recipients")
            return False
        ok = self._send_sync_internal(subject, body, timeout=timeout)
        if ok:
            self.logger.info("Email sent_sync: subj=%s to=%s", subject, ok)
            return True
        return False

    def shutdown(self, flush_timeout: float = 5.0):
        self.logger.info("Emailer shutting down; flushing queue (timeout %ss)...", flush_timeout)
        start = time.time()
        while not self._queue.empty() and (time.time() - start) < flush_timeout:
            time.sleep(0.1)
        self._worker_stop.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=2.0)
        try:
            while not self._queue.empty():
                item = self._queue.get_nowait()
                try:
                    self._send_sync_internal(item.get("subject", "(no-subject)"), item.get("body", ""))
                except Exception:
                    pass
                try:
                    self._queue.task_done()
                except Exception:
                    pass
        except Empty:
            pass
        self.logger.info("Emailer shutdown complete")
