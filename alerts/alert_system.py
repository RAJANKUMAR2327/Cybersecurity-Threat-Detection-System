"""
alert_system.py
---------------
Multi-channel alert dispatcher:
  - Console (rich terminal output)
  - Log file (JSON structured)
  - Email (SMTP)
  - Webhook (Slack, Teams, custom)
  - In-memory alert queue for dashboard
"""

import json
import time
import logging
import smtplib
import threading
import requests
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Callable, Dict, List, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

logger = logging.getLogger(__name__)


SEVERITY_COLORS = {
    "LOW":      "cyan",
    "MEDIUM":   "yellow",
    "HIGH":     "red",
    "CRITICAL": "bold red on white",
}

SEVERITY_EMOJI = {
    "LOW":      "🔵",
    "MEDIUM":   "🟡",
    "HIGH":     "🔴",
    "CRITICAL": "🚨",
}


@dataclass
class AlertConfig:
    """Configuration for the alert system."""
    # Console
    console_enabled: bool = True
    console_min_severity: str = "LOW"

    # File logging
    log_file: str = "logs/alerts.json"
    log_enabled: bool = True

    # Email
    email_enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_from: str = ""
    email_to: List[str] = field(default_factory=list)
    email_min_severity: str = "HIGH"

    # Webhook (Slack/Teams/custom)
    webhook_enabled: bool = False
    webhook_url: str = ""
    webhook_min_severity: str = "MEDIUM"

    # Rate limiting
    max_alerts_per_minute: int = 60
    dedup_window_secs: int = 30


class RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, max_per_minute: int):
        self.max_per_minute = max_per_minute
        self._timestamps: deque = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = time.time()
            # Remove timestamps older than 60s
            while self._timestamps and now - self._timestamps[0] > 60:
                self._timestamps.popleft()
            if len(self._timestamps) < self.max_per_minute:
                self._timestamps.append(now)
                return True
            return False


class AlertSystem:
    """
    Central alert dispatcher. Receives ThreatEvent objects and
    routes them to configured channels.

    Usage:
        config = AlertConfig(console_enabled=True, log_enabled=True)
        alerts = AlertSystem(config)
        alerts.dispatch(threat_event)
    """

    SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    def __init__(self, config: Optional[AlertConfig] = None):
        self.config = config or AlertConfig()
        self._queue: deque = deque(maxlen=10000)
        self._rate_limiter = RateLimiter(self.config.max_alerts_per_minute)
        self._dedup_cache: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._callbacks: List[Callable] = []
        self._stats = {
            "total_dispatched": 0,
            "by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "rate_limited": 0,
            "deduped": 0,
        }

        if RICH_AVAILABLE:
            self._console = Console(stderr=True)
        else:
            self._console = None

        # Ensure log directory exists
        if self.config.log_enabled:
            import os
            os.makedirs("logs", exist_ok=True)

        logger.info("AlertSystem initialized")

    def add_callback(self, cb: Callable):
        """Register a callback invoked on every dispatched alert."""
        self._callbacks.append(cb)

    def dispatch(self, event) -> bool:
        """
        Main entry point. Accepts a ThreatEvent (or dict).
        Returns True if alert was dispatched, False if suppressed.
        """
        if hasattr(event, "to_dict"):
            event_dict = event.to_dict()
        else:
            event_dict = event

        severity = event_dict.get("severity", "LOW")

        # Dedup check
        dedup_key = f"{event_dict.get('category')}:{event_dict.get('src_ip')}"
        with self._lock:
            last = self._dedup_cache.get(dedup_key, 0)
            if time.time() - last < self.config.dedup_window_secs:
                self._stats["deduped"] += 1
                return False
            self._dedup_cache[dedup_key] = time.time()

        # Rate limit check
        if not self._rate_limiter.allow():
            self._stats["rate_limited"] += 1
            return False

        # Store in queue
        self._queue.append(event_dict)
        self._stats["total_dispatched"] += 1
        self._stats["by_severity"][severity] = (
            self._stats["by_severity"].get(severity, 0) + 1
        )

        # Dispatch to channels (non-blocking)
        threading.Thread(
            target=self._dispatch_all,
            args=(event_dict,),
            daemon=True,
        ).start()

        return True

    def _dispatch_all(self, event: dict):
        """Send alert to all configured channels."""
        sev = event.get("severity", "LOW")
        sev_rank = self.SEVERITY_ORDER.get(sev, 0)

        if (
            self.config.console_enabled
            and sev_rank >= self.SEVERITY_ORDER.get(self.config.console_min_severity, 0)
        ):
            self._dispatch_console(event)

        if self.config.log_enabled:
            self._dispatch_log(event)

        if (
            self.config.email_enabled
            and sev_rank >= self.SEVERITY_ORDER.get(self.config.email_min_severity, 0)
        ):
            self._dispatch_email(event)

        if (
            self.config.webhook_enabled
            and sev_rank >= self.SEVERITY_ORDER.get(self.config.webhook_min_severity, 0)
        ):
            self._dispatch_webhook(event)

        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def _dispatch_console(self, event: dict):
        """Print a formatted alert to the terminal."""
        sev = event.get("severity", "LOW")
        emoji = SEVERITY_EMOJI.get(sev, "⚠️")
        color = SEVERITY_COLORS.get(sev, "white")
        ts = event.get("datetime", datetime.now().strftime("%H:%M:%S"))

        if self._console:
            self._console.print(
                f"[dim]{ts}[/dim] {emoji} "
                f"[{color}]{sev}[/{color}] "
                f"[bold]{event.get('category', 'UNKNOWN')}[/bold] "
                f"[dim]{event.get('src_ip','?')} → {event.get('dst_ip','?')}[/dim] "
                f"— {event.get('description', '')}"
            )
        else:
            print(
                f"{ts} {emoji} [{sev}] {event.get('category','?')} "
                f"{event.get('src_ip','?')} → {event.get('dst_ip','?')} "
                f"— {event.get('description','')}"
            )

    def _dispatch_log(self, event: dict):
        """Append alert as JSON line to the log file."""
        try:
            with open(self.config.log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"Log write error: {e}")

    def _dispatch_email(self, event: dict):
        """Send alert via SMTP email."""
        try:
            sev = event.get("severity", "LOW")
            subject = (
                f"[{sev}] Threat Detected: {event.get('category','?')} "
                f"from {event.get('src_ip','?')}"
            )
            body = self._format_email_body(event)

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.config.email_from
            msg["To"] = ", ".join(self.config.email_to)
            msg.attach(MIMEText(body, "html"))

            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                server.starttls()
                server.login(self.config.smtp_user, self.config.smtp_password)
                server.sendmail(
                    self.config.email_from,
                    self.config.email_to,
                    msg.as_string(),
                )
            logger.info(f"Email alert sent for {event.get('category')}")
        except Exception as e:
            logger.error(f"Email dispatch error: {e}")

    def _format_email_body(self, event: dict) -> str:
        sev = event.get("severity", "LOW")
        color_map = {"LOW": "#00bcd4", "MEDIUM": "#ff9800", "HIGH": "#f44336", "CRITICAL": "#b71c1c"}
        color = color_map.get(sev, "#333")
        return f"""
        <html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px;">
        <div style="border-left:4px solid {color};padding-left:16px;margin-bottom:16px;">
          <h2 style="color:{color};margin:0">{SEVERITY_EMOJI.get(sev,'')} {sev} — {event.get('category','?')}</h2>
          <p style="color:#8b949e">{event.get('datetime','')}</p>
        </div>
        <table style="width:100%;border-collapse:collapse;">
          <tr><td style="color:#8b949e;padding:4px 8px">Source</td>
              <td style="padding:4px 8px">{event.get('src_ip','?')}:{event.get('src_port','?')}</td></tr>
          <tr><td style="color:#8b949e;padding:4px 8px">Destination</td>
              <td style="padding:4px 8px">{event.get('dst_ip','?')}:{event.get('dst_port','?')}</td></tr>
          <tr><td style="color:#8b949e;padding:4px 8px">Protocol</td>
              <td style="padding:4px 8px">{event.get('protocol','?')}</td></tr>
          <tr><td style="color:#8b949e;padding:4px 8px">Confidence</td>
              <td style="padding:4px 8px">{event.get('confidence',0)*100:.1f}%</td></tr>
          <tr><td style="color:#8b949e;padding:4px 8px">MITRE</td>
              <td style="padding:4px 8px">{event.get('mitre_tactic','')} / {event.get('mitre_technique','')}</td></tr>
        </table>
        <p style="margin-top:16px;color:#c9d1d9">{event.get('description','')}</p>
        <pre style="background:#161b22;padding:12px;border-radius:6px;color:#7ee787">
{json.dumps(event.get('evidence',{}), indent=2)}</pre>
        </body></html>
        """

    def _dispatch_webhook(self, event: dict):
        """POST alert to a webhook (Slack-compatible format)."""
        try:
            sev = event.get("severity", "LOW")
            emoji = SEVERITY_EMOJI.get(sev, "⚠️")
            color_map = {
                "LOW": "#36a64f", "MEDIUM": "#ffd700",
                "HIGH": "#ff4500", "CRITICAL": "#8b0000"
            }
            # Slack attachment format
            payload = {
                "attachments": [{
                    "color": color_map.get(sev, "#888"),
                    "title": f"{emoji} [{sev}] {event.get('category','?')}",
                    "text": event.get("description", ""),
                    "fields": [
                        {"title": "Source",      "value": f"{event.get('src_ip')}:{event.get('src_port')}", "short": True},
                        {"title": "Destination", "value": f"{event.get('dst_ip')}:{event.get('dst_port')}", "short": True},
                        {"title": "Protocol",    "value": event.get("protocol", "?"), "short": True},
                        {"title": "Confidence",  "value": f"{event.get('confidence',0)*100:.1f}%", "short": True},
                        {"title": "MITRE ATT&CK","value": f"{event.get('mitre_tactic','')} — {event.get('mitre_technique','')}", "short": False},
                    ],
                    "footer": f"CyberShield IDS | {event.get('datetime','')}",
                    "ts": int(event.get("timestamp", time.time())),
                }]
            }
            resp = requests.post(
                self.config.webhook_url, json=payload, timeout=5
            )
            if resp.status_code not in (200, 204):
                logger.warning(f"Webhook returned {resp.status_code}")
        except Exception as e:
            logger.error(f"Webhook dispatch error: {e}")

    def get_recent_alerts(self, n: int = 100) -> List[dict]:
        return list(self._queue)[-n:]

    def get_stats(self) -> dict:
        return dict(self._stats)

    def clear_queue(self):
        self._queue.clear()
