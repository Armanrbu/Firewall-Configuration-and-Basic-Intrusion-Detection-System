"""
Notification backend.

Provides desktop notifications, email alerts, and optional Twilio SMS.
All methods are fail-safe — exceptions are logged but never propagated.
"""

from __future__ import annotations

import os
import smtplib
import threading
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

# Optional dependency — desktop notifications
try:
    from plyer import notification as _plyer_notification
    HAS_PLYER = True
except ImportError:
    HAS_PLYER = False

# Optional dependency — Twilio SMS
try:
    from twilio.rest import Client as TwilioClient
    HAS_TWILIO = True
except ImportError:
    HAS_TWILIO = False

# Rate-limiting: ip → last_email_sent_timestamp
_email_sent: dict[str, float] = {}
_EMAIL_RATE_LIMIT = 3600  # 1 email per IP per hour


class Notifier:
    """
    Central notification dispatcher.

    Reads settings from the provided *config* dict or falls back to defaults.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        self.desktop_enabled: bool = cfg.get("notifications", {}).get("desktop", True)
        self.email_enabled: bool = cfg.get("notifications", {}).get("email", False)
        self.sms_enabled: bool = cfg.get("notifications", {}).get("sms", False)

        email_cfg = cfg.get("email", {})
        self.smtp_host: str = email_cfg.get("smtp_host", "smtp.gmail.com")
        self.smtp_port: int = int(email_cfg.get("smtp_port", 465))
        self.smtp_user: str = os.environ.get("NETGUARD_SMTP_USER", "")
        self.smtp_pass: str = os.environ.get("NETGUARD_SMTP_PASSWORD", "")
        self.smtp_to: str = email_cfg.get("recipient", "")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def notify_alert(self, ip: str, alert_type: str, details: str = "", geo: dict | None = None) -> None:
        """
        Send notifications for a new alert.

        Dispatches desktop / email / SMS depending on configuration.
        """
        title = f"🚨 NetGuard Alert — {alert_type}"
        body = self._format_body(ip, alert_type, details, geo)

        if self.desktop_enabled:
            self._desktop(title, body)
        if self.email_enabled:
            threading.Thread(
                target=self._email,
                args=(ip, title, body),
                daemon=True,
            ).start()
        if self.sms_enabled and HAS_TWILIO:
            threading.Thread(
                target=self._sms,
                args=(f"{title}: {ip}",),
                daemon=True,
            ).start()

    def notify_info(self, title: str, message: str) -> None:
        """Send an informational desktop notification."""
        if self.desktop_enabled:
            self._desktop(title, message)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _format_body(
        self, ip: str, alert_type: str, details: str, geo: dict | None
    ) -> str:
        lines = [
            f"IP: {ip}",
            f"Type: {alert_type}",
        ]
        if details:
            lines.append(f"Details: {details}")
        if geo:
            lines.append(
                f"Location: {geo.get('city', '?')}, {geo.get('country', '?')} "
                f"({geo.get('countryCode', '?')})"
            )
            lines.append(f"ISP: {geo.get('isp', '?')}")
        lines.append(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        return "\n".join(lines)

    def _desktop(self, title: str, message: str) -> None:
        if not HAS_PLYER:
            logger.debug("plyer not installed; desktop notification skipped.")
            return
        try:
            _plyer_notification.notify(
                title=title,
                message=message[:255],
                app_name="NetGuard IDS",
                timeout=10,
            )
        except Exception as exc:
            logger.debug("Desktop notification failed: %s", exc)

    def _email(self, ip: str, subject: str, body: str) -> None:
        if not self.smtp_user or not self.smtp_to:
            logger.debug("Email not configured; skipping.")
            return
        now = time.time()
        if now - _email_sent.get(ip, 0) < _EMAIL_RATE_LIMIT:
            logger.debug("Email rate-limited for %s", ip)
            return
        _email_sent[ip] = now

        try:
            html = f"<pre style='font-family:monospace'>{body}</pre>"
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.smtp_user
            msg["To"] = self.smtp_to
            msg.attach(MIMEText(body, "plain"))
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port) as server:
                server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
            logger.info("Email alert sent for %s", ip)
        except Exception as exc:
            logger.warning("Email send failed: %s", exc)

    def _sms(self, message: str) -> None:
        if not HAS_TWILIO:
            return
        try:
            client = TwilioClient(
                os.environ.get("NETGUARD_TWILIO_SID"),
                os.environ.get("NETGUARD_TWILIO_TOKEN"),
            )
            client.messages.create(
                body=message[:160],
                from_=os.environ.get("NETGUARD_TWILIO_FROM", ""),
                to=os.environ.get("NETGUARD_TWILIO_TO", ""),
            )
            logger.info("SMS alert sent.")
        except Exception as exc:
            logger.warning("SMS send failed: %s", exc)


# Singleton
_notifier: Notifier | None = None


def get_notifier(config: dict | None = None) -> Notifier:
    global _notifier
    if _notifier is None:
        _notifier = Notifier(config)
    return _notifier


def reconfigure(config: dict) -> None:
    """Replace the singleton with a freshly configured instance."""
    global _notifier
    _notifier = Notifier(config)
