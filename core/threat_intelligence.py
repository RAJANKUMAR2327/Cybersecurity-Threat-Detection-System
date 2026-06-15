"""
threat_intelligence.py
----------------------
Auto-lookup IPs against VirusTotal and AbuseIPDB.
Works in demo mode without API keys using heuristics.
"""

import time
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
import requests

logger = logging.getLogger(__name__)
CACHE_TTL = 3600


@dataclass
class ThreatIntelResult:
    ip: str
    timestamp: float
    virustotal_score: Optional[str] = None
    virustotal_categories: List[str] = field(default_factory=list)
    abuseipdb_score: Optional[int] = None
    abuseipdb_country: Optional[str] = None
    abuseipdb_isp: Optional[str] = None
    abuseipdb_reports: Optional[int] = None
    is_malicious: bool = False
    risk_level: str = "UNKNOWN"
    tags: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "virustotal_score": self.virustotal_score,
            "virustotal_categories": self.virustotal_categories,
            "abuseipdb_score": self.abuseipdb_score,
            "abuseipdb_country": self.abuseipdb_country,
            "abuseipdb_isp": self.abuseipdb_isp,
            "abuseipdb_reports": self.abuseipdb_reports,
            "is_malicious": self.is_malicious,
            "risk_level": self.risk_level,
            "tags": self.tags,
            "error": self.error,
        }


class ThreatIntelligence:

    PRIVATE_RANGES = [
        "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "127.", "169.254.",
    ]

    def __init__(self, vt_api_key: str = "", abuseipdb_api_key: str = ""):
        self.vt_api_key = vt_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self._cache: Dict[str, ThreatIntelResult] = {}
        self._cache_lock = threading.Lock()
        self._results: List[dict] = []
        self._lookup_lock = threading.Lock()
        threading.Thread(target=self._cleanup_cache, daemon=True).start()

    def set_keys(self, vt_key: str = "", abuse_key: str = ""):
        self.vt_api_key = vt_key
        self.abuseipdb_api_key = abuse_key

    def is_private(self, ip: str) -> bool:
        return any(ip.startswith(r) for r in self.PRIVATE_RANGES)

    def lookup(self, ip: str) -> ThreatIntelResult:
        if self.is_private(ip):
            return ThreatIntelResult(
                ip=ip, timestamp=time.time(),
                risk_level="PRIVATE", tags=["Private/Internal IP"]
            )
        with self._cache_lock:
            cached = self._cache.get(ip)
            if cached and time.time() - cached.timestamp < CACHE_TTL:
                return cached

        result = ThreatIntelResult(ip=ip, timestamp=time.time())

        if self.vt_api_key:
            self._query_virustotal(ip, result)
        if self.abuseipdb_api_key:
            self._query_abuseipdb(ip, result)
        if not self.vt_api_key and not self.abuseipdb_api_key:
            self._apply_heuristics(ip, result)

        self._compute_risk(result)

        with self._cache_lock:
            self._cache[ip] = result
        with self._lookup_lock:
            self._results.append(result.to_dict())
            if len(self._results) > 1000:
                self._results.pop(0)

        return result

    def lookup_async(self, ip: str, callback=None):
        def _run():
            r = self.lookup(ip)
            if callback:
                callback(r)
        threading.Thread(target=_run, daemon=True).start()

    def _query_virustotal(self, ip, result):
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            resp = requests.get(url, headers={"x-apikey": self.vt_api_key}, timeout=10)
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                result.virustotal_score = f"{malicious}/{total} engines"
                result.virustotal_categories = list(set(attrs.get("categories", {}).values()))[:5]
                if malicious > 0:
                    result.is_malicious = True
                    result.tags.append(f"VT: {malicious} engines flagged")
            elif resp.status_code == 401:
                result.error = "VirusTotal: Invalid API key"
            elif resp.status_code == 429:
                result.error = "VirusTotal: Rate limit exceeded"
        except Exception as e:
            logger.debug(f"VT error: {e}")

    def _query_abuseipdb(self, ip, result):
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.abuseipdb_api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result.abuseipdb_score = data.get("abuseConfidenceScore", 0)
                result.abuseipdb_country = data.get("countryCode", "")
                result.abuseipdb_isp = data.get("isp", "")
                result.abuseipdb_reports = data.get("totalReports", 0)
                if result.abuseipdb_score and result.abuseipdb_score > 25:
                    result.is_malicious = True
                    result.tags.append(f"AbuseIPDB: {result.abuseipdb_score}% confidence")
        except Exception as e:
            logger.debug(f"AbuseIPDB error: {e}")

    def _apply_heuristics(self, ip, result):
        bad_prefixes = ["185.220.", "45.142.", "194.165.", "91.108.", "198.96.", "199.195."]
        for prefix in bad_prefixes:
            if ip.startswith(prefix):
                result.is_malicious = True
                result.abuseipdb_score = 85
                result.tags.append("Known malicious range (heuristic)")
                result.virustotal_score = "Demo mode — add API key for real data"
                return
        result.virustotal_score = "0/94 engines (demo)"
        result.abuseipdb_score = 0
        result.tags.append("No API keys — demo mode")

    def _compute_risk(self, result):
        score = 0
        if result.abuseipdb_score:
            score = max(score, result.abuseipdb_score)
        if result.virustotal_score:
            try:
                flagged = int(result.virustotal_score.split("/")[0])
                score = max(score, min(100, flagged * 10))
            except Exception:
                pass
        if score >= 75:
            result.risk_level = "CRITICAL"
        elif score >= 50:
            result.risk_level = "HIGH"
        elif score >= 25:
            result.risk_level = "MEDIUM"
        elif result.is_malicious:
            result.risk_level = "HIGH"
        else:
            result.risk_level = "LOW"

    def _cleanup_cache(self):
        while True:
            time.sleep(300)
            now = time.time()
            with self._cache_lock:
                expired = [k for k, v in self._cache.items() if now - v.timestamp > CACHE_TTL]
                for k in expired:
                    del self._cache[k]

    def get_results(self, n: int = 50) -> List[dict]:
        with self._lookup_lock:
            return list(reversed(self._results[-n:]))

    def get_cache_stats(self) -> dict:
        with self._cache_lock:
            return {"cached_ips": len(self._cache), "ttl_seconds": CACHE_TTL}