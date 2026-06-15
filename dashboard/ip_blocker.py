"""
ip_blocker.py
-------------
Auto-firewall rules for detected threats.
Uses Windows Firewall (netsh / PowerShell) or iptables on Linux.
Supports block, unblock, whitelist, and audit log.
"""

import os
import time
import subprocess
import logging
import platform
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SYSTEM = platform.system()  # "Windows" or "Linux" or "Darwin"


@dataclass
class BlockRule:
    ip: str
    reason: str
    timestamp: float
    severity: str
    blocked_by: str     # "manual" or "auto"
    rule_name: str = ""
    active: bool = True

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": self.severity,
            "blocked_by": self.blocked_by,
            "rule_name": self.rule_name,
            "active": self.active,
        }


class IPBlocker:
    """
    Manages firewall rules to block malicious IPs.
    
    On Windows: uses netsh advfirewall
    On Linux:   uses iptables
    Falls back to in-memory blocklist if no admin rights.
    """

    RULE_PREFIX = "CyberShield_Block_"

    # Never block these
    WHITELIST = {
        "127.0.0.1", "::1", "0.0.0.0",
        "8.8.8.8", "8.8.4.4",  # Google DNS
        "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
    }

    def __init__(self):
        self._rules: Dict[str, BlockRule] = {}
        self._lock = threading.Lock()
        self._has_admin = self._check_admin()
        self._system = SYSTEM
        logger.info(f"IPBlocker initialized | System: {self._system} | Admin: {self._has_admin}")

    def _check_admin(self) -> bool:
        try:
            if SYSTEM == "Windows":
                result = subprocess.run(
                    ["net", "session"],
                    capture_output=True, timeout=5
                )
                return result.returncode == 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    def block_ip(self, ip: str, reason: str = "", severity: str = "HIGH",
                 blocked_by: str = "auto") -> dict:
        """Block an IP address via firewall rule."""
        if ip in self.WHITELIST:
            return {"success": False, "error": f"{ip} is whitelisted", "ip": ip}

        with self._lock:
            if ip in self._rules and self._rules[ip].active:
                return {"success": True, "error": "Already blocked", "ip": ip}

        rule_name = f"{self.RULE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
        success = False
        error = ""

        if self._has_admin:
            if self._system == "Windows":
                success, error = self._block_windows(ip, rule_name)
            else:
                success, error = self._block_linux(ip, rule_name)
        else:
            # Soft block — in-memory only
            success = True
            error = "No admin rights — soft block only (in-memory)"
            logger.warning(f"Soft blocking {ip} — run as Administrator for real firewall rules")

        rule = BlockRule(
            ip=ip,
            reason=reason or f"Blocked by CyberShield ({severity})",
            timestamp=time.time(),
            severity=severity,
            blocked_by=blocked_by,
            rule_name=rule_name,
            active=True,
        )

        with self._lock:
            self._rules[ip] = rule

        logger.info(f"{'Blocked' if success else 'Soft-blocked'} IP: {ip} | Reason: {reason}")
        return {
            "success": success,
            "ip": ip,
            "rule_name": rule_name,
            "error": error,
            "admin": self._has_admin,
            "method": "firewall" if (success and self._has_admin) else "soft",
        }

    def unblock_ip(self, ip: str) -> dict:
        """Remove firewall block for an IP."""
        with self._lock:
            rule = self._rules.get(ip)
            if not rule or not rule.active:
                return {"success": False, "error": "IP not blocked", "ip": ip}

        success = False
        error = ""

        if self._has_admin:
            if self._system == "Windows":
                success, error = self._unblock_windows(rule.rule_name)
            else:
                success, error = self._unblock_linux(ip)
        else:
            success = True
            error = "Soft unblock (no admin)"

        with self._lock:
            if ip in self._rules:
                self._rules[ip].active = False

        return {"success": success, "ip": ip, "error": error}

    def _block_windows(self, ip: str, rule_name: str):
        """Add Windows Firewall inbound block rule."""
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
                "profile=any",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Also block outbound
                cmd_out = cmd.copy()
                cmd_out[cmd_out.index("dir=in")] = "dir=out"
                cmd_out[cmd_out.index(f"name={rule_name}")] = f"name={rule_name}_out"
                subprocess.run(cmd_out, capture_output=True, timeout=10)
                return True, ""
            return False, result.stderr.strip()
        except Exception as e:
            return False, str(e)

    def _unblock_windows(self, rule_name: str):
        try:
            for suffix in ["", "_out"]:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}{suffix}"
                ], capture_output=True, timeout=10)
            return True, ""
        except Exception as e:
            return False, str(e)

    def _block_linux(self, ip: str, rule_name: str):
        try:
            cmds = [
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
            ]
            for cmd in cmds:
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                if result.returncode != 0:
                    return False, result.stderr.decode()
            return True, ""
        except Exception as e:
            return False, str(e)

    def _unblock_linux(self, ip: str):
        try:
            cmds = [
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
            ]
            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, timeout=10)
            return True, ""
        except Exception as e:
            return False, str(e)

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            rule = self._rules.get(ip)
            return rule is not None and rule.active

    def get_blocked_ips(self) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in self._rules.values()]

    def get_stats(self) -> dict:
        with self._lock:
            active = sum(1 for r in self._rules.values() if r.active)
            return {
                "total_blocked": len(self._rules),
                "active_blocks": active,
                "has_admin": self._has_admin,
                "system": self._system,
                "method": "firewall" if self._has_admin else "soft-block",
            }

    def auto_block_on_threat(self, event_dict: dict, min_severity: str = "HIGH") -> Optional[dict]:
        """Automatically block IP when a high-severity threat is detected."""
        sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        event_sev = event_dict.get("severity", "LOW")
        if sev_order.get(event_sev, 0) < sev_order.get(min_severity, 2):
            return None
        src_ip = event_dict.get("src_ip", "")
        if not src_ip:
            return None
        return self.block_ip(
            ip=src_ip,
            reason=event_dict.get("description", "Auto-blocked by CyberShield"),
            severity=event_sev,
            blocked_by="auto",
        )