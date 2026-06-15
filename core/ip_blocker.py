"""
ip_blocker.py
-------------
Auto-firewall rules for detected threats.
Uses Windows Firewall (netsh) or iptables on Linux.
Falls back to soft/in-memory block without admin rights.
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
SYSTEM = platform.system()


@dataclass
class BlockRule:
    ip: str
    reason: str
    timestamp: float
    severity: str
    blocked_by: str
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

    RULE_PREFIX = "CyberShield_Block_"

    WHITELIST = {
        "127.0.0.1", "::1", "0.0.0.0",
        "8.8.8.8", "8.8.4.4",
        "1.1.1.1", "1.0.0.1",
    }

    def __init__(self):
        self._rules: Dict[str, BlockRule] = {}
        self._lock = threading.Lock()
        self._has_admin = self._check_admin()
        logger.info(f"IPBlocker | System: {SYSTEM} | Admin: {self._has_admin}")

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
        if ip in self.WHITELIST:
            return {"success": False, "error": f"{ip} is whitelisted", "ip": ip}

        with self._lock:
            if ip in self._rules and self._rules[ip].active:
                return {"success": True, "error": "Already blocked", "ip": ip}

        rule_name = f"{self.RULE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
        success = False
        error = ""

        if self._has_admin:
            if SYSTEM == "Windows":
                success, error = self._block_windows(ip, rule_name)
            else:
                success, error = self._block_linux(ip, rule_name)
        else:
            success = True
            error = "No admin rights — soft block only (in-memory)"

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

        return {
            "success": success,
            "ip": ip,
            "rule_name": rule_name,
            "error": error,
            "admin": self._has_admin,
            "method": "firewall" if (success and self._has_admin) else "soft",
        }

    def unblock_ip(self, ip: str) -> dict:
        with self._lock:
            rule = self._rules.get(ip)
            if not rule or not rule.active:
                return {"success": False, "error": "IP not blocked", "ip": ip}

        success = False
        error = ""

        if self._has_admin:
            if SYSTEM == "Windows":
                success, error = self._unblock_windows(rule.rule_name)
            else:
                success, error = self._unblock_linux(ip)
        else:
            success = True
            error = "Soft unblock"

        with self._lock:
            if ip in self._rules:
                self._rules[ip].active = False

        return {"success": success, "ip": ip, "error": error}

    def _block_windows(self, ip: str, rule_name: str):
        try:
            for direction in ["in", "out"]:
                suffix = "" if direction == "in" else "_out"
                remote = "remoteip" if direction == "in" else "remoteip"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}{suffix}",
                    f"dir={direction}",
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes",
                    "profile=any",
                ]
                subprocess.run(cmd, capture_output=True, timeout=10)
            return True, ""
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
            for cmd in [
                ["iptables", "-A", "INPUT",  "-s", ip, "-j", "DROP"],
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
            ]:
                subprocess.run(cmd, capture_output=True, timeout=10)
            return True, ""
        except Exception as e:
            return False, str(e)

    def _unblock_linux(self, ip: str):
        try:
            for cmd in [
                ["iptables", "-D", "INPUT",  "-s", ip, "-j", "DROP"],
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
            ]:
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
                "system": SYSTEM,
                "method": "firewall" if self._has_admin else "soft-block",
            }

    def auto_block_on_threat(self, event_dict: dict,
                              min_severity: str = "HIGH") -> Optional[dict]:
        sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if sev_order.get(event_dict.get("severity","LOW"), 0) < sev_order.get(min_severity, 2):
            return None
        src_ip = event_dict.get("src_ip", "")
        if not src_ip:
            return None
        return self.block_ip(
            ip=src_ip,
            reason=event_dict.get("description", "Auto-blocked"),
            severity=event_dict.get("severity", "HIGH"),
            blocked_by="auto",
        )