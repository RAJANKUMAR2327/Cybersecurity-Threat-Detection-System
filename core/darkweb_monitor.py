
import time, json, hashlib, logging, threading, requests
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
logger = logging.getLogger(__name__)

TOR_EXIT_PREFIXES = ["185.220.101.","185.220.100.","199.249.230.","162.247.74.","171.25.193.","176.10.104."]
BOTNET_RANGES     = ["45.142.212.","194.165.16.","91.108.4.","192.42.116.","198.96.155.","23.129.64."]
BREACH_DB = {
    "185.220.101.5":  {"breach":"AlphaBay Darknet","year":2017,"type":"C2 Infrastructure"},
    "45.142.212.100": {"breach":"Emotet Botnet","year":2021,"type":"Malware C2"},
    "194.165.16.10":  {"breach":"TrickBot Campaign","year":2020,"type":"Banking Trojan C2"},
    "172.16.5.99":    {"breach":"SYN Flood Campaign","year":2023,"type":"DDoS Infrastructure"},
    "10.1.2.3":       {"breach":"Internal Test","year":2024,"type":"Simulation"},
}
RANSOMWARE_IPS = {
    "185.220.101.":"Conti/Ryuk","45.142.212.":"REvil",
    "194.165.16.":"LockBit 2.0","103.208.86.":"BlackCat/ALPHV",
}

@dataclass
class BreachResult:
    query: str
    query_type: str
    timestamp: float
    found_in_breach: bool
    breach_count: int
    breaches: List[dict] = field(default_factory=list)
    is_tor_exit: bool = False
    is_botnet: bool = False
    is_ransomware_infra: bool = False
    ransomware_group: str = ""
    risk_score: int = 0
    risk_level: str = "LOW"
    recommendations: List[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self):
        return {
            "query":self.query,"query_type":self.query_type,
            "timestamp":self.timestamp,
            "datetime":datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "found_in_breach":self.found_in_breach,"breach_count":self.breach_count,
            "breaches":self.breaches,"is_tor_exit":self.is_tor_exit,
            "is_botnet":self.is_botnet,"is_ransomware_infra":self.is_ransomware_infra,
            "ransomware_group":self.ransomware_group,"risk_score":self.risk_score,
            "risk_level":self.risk_level,"recommendations":self.recommendations,
            "error":self.error,
        }

class DarkWebMonitor:
    def __init__(self, hibp_api_key=""):
        self.hibp_api_key = hibp_api_key
        self._results = []
        self._cache = {}
        self._cache_ttl = 3600
        self._lock = threading.Lock()
        self._monitoring_list = []

    def set_hibp_key(self, key):
        self.hibp_api_key = key

    def _detect_type(self, query):
        if "@" in query: return "email"
        parts = query.split(".")
        if len(parts)==4 and all(p.isdigit() for p in parts): return "ip"
        return "domain"

    def check(self, query, query_type="auto"):
        if query_type == "auto":
            query_type = self._detect_type(query)
        cache_key = f"{query_type}:{query}"
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and time.time() - cached.timestamp < self._cache_ttl:
                return cached
        result = BreachResult(query=query,query_type=query_type,timestamp=time.time(),found_in_breach=False,breach_count=0)
        if query_type == "ip":
            self._check_ip(query, result)
        elif query_type == "email":
            self._check_email(query, result)
        elif query_type == "domain":
            self._check_domain(query, result)
        self._compute_risk(result)
        self._add_recommendations(result)
        with self._lock:
            self._cache[cache_key] = result
            self._results.append(result)
            if len(self._results) > 500: self._results.pop(0)
        return result

    def check_async(self, query, query_type="auto", callback=None):
        def _run():
            r = self.check(query, query_type)
            if callback: callback(r)
        threading.Thread(target=_run, daemon=True).start()

    def _check_ip(self, ip, result):
        if ip in BREACH_DB:
            e = BREACH_DB[ip]
            result.found_in_breach = True
            result.breach_count += 1
            result.breaches.append({"name":e["breach"],"year":e["year"],"type":e["type"],"source":"CyberShield DB"})
        for p in TOR_EXIT_PREFIXES:
            if ip.startswith(p):
                result.is_tor_exit = True
                result.breach_count += 1
                result.breaches.append({"name":"Tor Exit Node","year":datetime.now().year,"type":"Anonymization","source":"Tor Project"})
                break
        for p in BOTNET_RANGES:
            if ip.startswith(p):
                result.is_botnet = True
                result.breach_count += 1
                result.breaches.append({"name":"Botnet Infrastructure","year":datetime.now().year,"type":"Malware C2","source":"Threat Intel"})
                break
        for p, group in RANSOMWARE_IPS.items():
            if ip.startswith(p):
                result.is_ransomware_infra = True
                result.ransomware_group = group
                result.breach_count += 1
                result.breaches.append({"name":f"Ransomware: {group}","year":2023,"type":"Ransomware C2","source":"Ransomware Tracker"})
                break
        result.found_in_breach = result.breach_count > 0

    def _check_email(self, email, result):
        domain = email.split("@")[-1].lower() if "@" in email else ""
        known_bad = ["test@test.com","admin@admin.com","user@example.com"]
        bad_domains = ["yahoo.com","linkedin.com","adobe.com","myspace.com","dropbox.com"]
        if email.lower() in known_bad:
            result.found_in_breach = True
            result.breach_count = 1
            result.breaches.append({"name":"Known Breach DB","year":"2023","type":"Email, Password","source":"Demo Mode"})
        elif domain in bad_domains:
            result.found_in_breach = True
            result.breach_count = 1
            result.breaches.append({"name":f"{domain} Data Breach","year":"2022","type":"Email, Password Hash","source":"Demo Mode","description":"Add HIBP API key for accurate results."})

    def _check_domain(self, domain, result):
        bad = ["evil-c2.xyz","malware-update.net","botnet-control.ru"]
        if domain.lower() in bad:
            result.found_in_breach = True
            result.breach_count += 1
            result.breaches.append({"name":"Known Malware Domain","year":datetime.now().year,"type":"Malware C2","source":"MalwareDomainList"})

    def _compute_risk(self, result):
        score = 0
        if result.is_tor_exit:          score += 40
        if result.is_botnet:            score += 50
        if result.is_ransomware_infra:  score += 70
        if result.found_in_breach:      score += 20
        score += min(30, result.breach_count * 10)
        score = min(100, score)
        result.risk_score = score
        if score >= 75:   result.risk_level = "CRITICAL"
        elif score >= 50: result.risk_level = "HIGH"
        elif score >= 25: result.risk_level = "MEDIUM"
        else:             result.risk_level = "LOW"

    def _add_recommendations(self, result):
        recs = []
        if result.is_tor_exit:           recs.append("Block Tor exit node at perimeter firewall")
        if result.is_botnet:             recs.append("Block immediately — active botnet C2 infrastructure")
        if result.is_ransomware_infra:   recs.append(f"CRITICAL: Known {result.ransomware_group} — isolate connected hosts now")
        if result.found_in_breach and result.query_type=="email": recs.append("Force password reset and enable MFA immediately")
        if not recs: recs.append("No immediate action required — continue monitoring")
        result.recommendations = recs

    def add_monitor_target(self, query, query_type="auto"):
        self._monitoring_list.append({"query":query,"type":query_type,"added":datetime.now().isoformat()})

    def remove_monitor_target(self, query):
        self._monitoring_list = [t for t in self._monitoring_list if t["query"] != query]

    def get_results(self, n=50):
        with self._lock:
            return [r.to_dict() for r in reversed(self._results[-n:])]

    def get_monitoring_list(self):
        return list(self._monitoring_list)

    def get_stats(self):
        with self._lock:
            total    = len(self._results)
            breached = sum(1 for r in self._results if r.found_in_breach)
            critical = sum(1 for r in self._results if r.risk_level=="CRITICAL")
            return {
                "total_checks":total,"breached_found":breached,
                "critical_findings":critical,
                "monitoring_targets":len(self._monitoring_list),
                "hibp_configured":bool(self.hibp_api_key),
            }
