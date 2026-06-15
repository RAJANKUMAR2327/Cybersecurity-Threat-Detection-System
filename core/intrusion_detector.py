"""
intrusion_detector.py
---------------------
Multi-layered intrusion detection system combining:
  1. Rule-based signature detection (port scans, SYN floods, etc.)
  2. ML anomaly detection (Isolation Forest)
  3. Behavioral heuristics (DNS tunneling, beaconing, etc.)
"""

import time
import logging
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


class ThreatSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(Enum):
    PORT_SCAN = "Port Scan"
    SYN_FLOOD = "SYN Flood"
    BRUTE_FORCE = "Brute Force"
    DNS_TUNNELING = "DNS Tunneling"
    BEACONING = "Beaconing / C2"
    DATA_EXFILTRATION = "Data Exfiltration"
    ARP_SPOOFING = "ARP Spoofing"
    MALFORMED_PACKET = "Malformed Packet"
    ANOMALOUS_TRAFFIC = "Anomalous Traffic"
    BLACKLISTED_IP = "Blacklisted IP"
    SUSPICIOUS_PAYLOAD = "Suspicious Payload"
    ICMP_FLOOD = "ICMP Flood"


@dataclass
class ThreatEvent:
    """Represents a detected threat/intrusion event."""
    id: str
    timestamp: float
    category: ThreatCategory
    severity: ThreatSeverity
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    description: str
    confidence: float  # 0.0 - 1.0
    evidence: dict = field(default_factory=dict)
    mitre_tactic: str = ""
    mitre_technique: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "category": self.category.value,
            "severity": self.severity.value,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "description": self.description,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
        }


# ---------------------------------------------------------------------------
# Signature / Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """
    Signature-based detection rules.
    Each rule inspects packet features and flow stats.
    """

    # Known malicious IPs / CIDR ranges (example blocklist)
    BLOCKLIST = {
        "185.220.101.0", "45.142.212.0", "194.165.16.0",
        "91.108.4.0", "192.42.116.0",
    }

    # Ports associated with sensitive services
    SENSITIVE_PORTS = {22, 23, 3389, 5900, 21, 25, 110, 143, 3306, 5432, 27017}

    # Suspicious payload patterns (regex-ready strings)
    SUSPICIOUS_PATTERNS = [
        b"/bin/sh", b"/etc/passwd", b"cmd.exe",
        b"powershell", b"base64", b"eval(",
        b"SELECT ", b"UNION ", b"DROP TABLE",
        b"<script>", b"javascript:",
        b"wget ", b"curl ", b"nc -",
    ]

    def __init__(self):
        # Per-IP tracking windows
        self._syn_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._port_tracker: Dict[str, set] = defaultdict(set)
        self._port_time_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._icmp_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._auth_fail_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self._dns_size_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        self.thresholds = {
            "syn_flood_rate": 100,        # SYNs per second per src
            "port_scan_unique_ports": 20,  # unique dst ports in window
            "port_scan_window_secs": 10,
            "icmp_flood_rate": 50,        # ICMP pkts/sec
            "brute_force_window_secs": 60,
            "brute_force_attempts": 10,
            "dns_payload_threshold": 200,  # bytes, suspicious large DNS
        }

    def check(self, features, flow) -> List[ThreatEvent]:
        """Run all rules against a packet+flow. Returns list of events."""
        events = []
        now = time.time()

        events.extend(self._check_blocklist(features, now))
        events.extend(self._check_syn_flood(features, now))
        events.extend(self._check_port_scan(features, now))
        events.extend(self._check_icmp_flood(features, now))
        events.extend(self._check_brute_force(features, now))
        events.extend(self._check_suspicious_payload(features, now))
        events.extend(self._check_malformed(features, now))
        events.extend(self._check_dns_tunneling(features, now))

        return events

    # --- Individual Rules ---

    def _check_blocklist(self, f, now) -> list:
        for ip in (f.src_ip, f.dst_ip):
            # Simplified: check first 3 octets
            prefix = ".".join(ip.split(".")[:3]) + ".0"
            if ip in self.BLOCKLIST or prefix in self.BLOCKLIST:
                return [self._event(
                    f, ThreatCategory.BLACKLISTED_IP, ThreatSeverity.HIGH,
                    f"Traffic to/from known malicious IP {ip}",
                    0.95,
                    evidence={"blacklisted_ip": ip},
                    mitre_tactic="Command and Control",
                    mitre_technique="T1071",
                )]
        return []

    def _check_syn_flood(self, f, now) -> list:
        if f.protocol != "TCP" or f.flags != "S":
            return []
        tracker = self._syn_tracker[f.src_ip]
        tracker.append(now)
        # Count SYNs in last second
        recent = sum(1 for t in tracker if now - t <= 1.0)
        if recent >= self.thresholds["syn_flood_rate"]:
            return [self._event(
                f, ThreatCategory.SYN_FLOOD, ThreatSeverity.CRITICAL,
                f"SYN flood: {recent} SYN packets/sec from {f.src_ip}",
                min(0.99, recent / 200),
                evidence={"syn_rate": recent, "window": "1s"},
                mitre_tactic="Impact",
                mitre_technique="T1499",
            )]
        return []

    def _check_port_scan(self, f, now) -> list:
        if f.protocol not in ("TCP", "UDP"):
            return []
        time_track = self._port_time_tracker[f.src_ip]
        time_track.append(now)
        port_track = self._port_tracker[f.src_ip]
        port_track.add(f.dst_port)

        window = self.thresholds["port_scan_window_secs"]
        if now - (time_track[0] if time_track else now) <= window:
            unique_ports = len(port_track)
            if unique_ports >= self.thresholds["port_scan_unique_ports"]:
                confidence = min(0.97, unique_ports / 100)
                sev = ThreatSeverity.HIGH if unique_ports > 50 else ThreatSeverity.MEDIUM
                self._port_tracker[f.src_ip] = set()  # reset after alert
                return [self._event(
                    f, ThreatCategory.PORT_SCAN, sev,
                    f"Port scan: {unique_ports} unique ports from {f.src_ip}",
                    confidence,
                    evidence={"unique_ports": unique_ports, "window_secs": window},
                    mitre_tactic="Discovery",
                    mitre_technique="T1046",
                )]
        else:
            # Window expired, reset
            self._port_tracker[f.src_ip] = {f.dst_port}
            while time_track and now - time_track[0] > window:
                time_track.popleft()
        return []

    def _check_icmp_flood(self, f, now) -> list:
        if f.protocol != "ICMP":
            return []
        tracker = self._icmp_tracker[f.src_ip]
        tracker.append(now)
        recent = sum(1 for t in tracker if now - t <= 1.0)
        if recent >= self.thresholds["icmp_flood_rate"]:
            return [self._event(
                f, ThreatCategory.ICMP_FLOOD, ThreatSeverity.HIGH,
                f"ICMP flood: {recent} packets/sec from {f.src_ip}",
                0.9,
                evidence={"icmp_rate": recent},
                mitre_tactic="Impact",
                mitre_technique="T1498",
            )]
        return []

    def _check_brute_force(self, f, now) -> list:
        if f.dst_port not in self.SENSITIVE_PORTS:
            return []
        tracker = self._auth_fail_tracker[f.src_ip]
        tracker.append(now)
        window = self.thresholds["brute_force_window_secs"]
        recent = sum(1 for t in tracker if now - t <= window)
        if recent >= self.thresholds["brute_force_attempts"]:
            port_name = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC",
                         21: "FTP", 25: "SMTP"}.get(f.dst_port, str(f.dst_port))
            return [self._event(
                f, ThreatCategory.BRUTE_FORCE, ThreatSeverity.HIGH,
                f"Brute force: {recent} attempts to {port_name} ({f.dst_ip})",
                0.85,
                evidence={"attempts": recent, "service": port_name, "window": window},
                mitre_tactic="Credential Access",
                mitre_technique="T1110",
            )]
        return []

    def _check_suspicious_payload(self, f, now) -> list:
        if not f.raw_payload:
            return []
        payload = f.raw_payload.lower()
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.lower() in payload:
                return [self._event(
                    f, ThreatCategory.SUSPICIOUS_PAYLOAD, ThreatSeverity.HIGH,
                    f"Suspicious payload pattern: {pattern.decode(errors='replace')}",
                    0.80,
                    evidence={"pattern": pattern.decode(errors="replace")},
                    mitre_tactic="Execution",
                    mitre_technique="T1059",
                )]
        return []

    def _check_malformed(self, f, now) -> list:
        if f.is_fragment and f.packet_size < 20:
            return [self._event(
                f, ThreatCategory.MALFORMED_PACKET, ThreatSeverity.MEDIUM,
                f"Malformed IP fragment from {f.src_ip} (size={f.packet_size})",
                0.75,
                evidence={"fragment": True, "size": f.packet_size},
                mitre_tactic="Evasion",
                mitre_technique="T1599",
            )]
        return []

    def _check_dns_tunneling(self, f, now) -> list:
        if f.dst_port != 53 and f.src_port != 53:
            return []
        if f.payload_size > self.thresholds["dns_payload_threshold"]:
            return [self._event(
                f, ThreatCategory.DNS_TUNNELING, ThreatSeverity.HIGH,
                f"Possible DNS tunneling: large DNS payload ({f.payload_size}B)",
                0.72,
                evidence={"payload_size": f.payload_size},
                mitre_tactic="Exfiltration",
                mitre_technique="T1048",
            )]
        return []

    def _event(
        self, f, category, severity, description, confidence,
        evidence=None, mitre_tactic="", mitre_technique=""
    ) -> ThreatEvent:
        import uuid
        return ThreatEvent(
            id=str(uuid.uuid4())[:8],
            timestamp=time.time(),
            category=category,
            severity=severity,
            src_ip=f.src_ip,
            dst_ip=f.dst_ip,
            src_port=f.src_port,
            dst_port=f.dst_port,
            protocol=f.protocol,
            description=description,
            confidence=confidence,
            evidence=evidence or {},
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
        )


# ---------------------------------------------------------------------------
# ML Anomaly Detector
# ---------------------------------------------------------------------------

class MLAnomalyDetector:
    """
    Isolation Forest-based anomaly detection on network flow features.
    Trains on normal traffic then flags statistical outliers.
    """

    FEATURE_NAMES = [
        "packet_count", "byte_count", "duration",
        "packets_per_second", "avg_packet_size",
        "avg_inter_arrival", "unique_flags",
        "src_port", "dst_port",
        "is_tcp", "is_udp", "is_icmp",
    ]

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model = None
        self._training_data: List[List[float]] = []
        self._min_training_samples = 200
        self._trained = False
        self._train_lock = threading.Lock()
        self._scaler_mean: Optional[np.ndarray] = None
        self._scaler_std: Optional[np.ndarray] = None

    def add_sample(self, feature_vector: List[float]):
        """Add a flow feature vector to the training buffer."""
        with self._train_lock:
            self._training_data.append(feature_vector)
            # Auto-train once we have enough samples
            if (
                len(self._training_data) >= self._min_training_samples
                and len(self._training_data) % 100 == 0
            ):
                self._train()

    def _train(self):
        """Train / retrain the Isolation Forest model."""
        try:
            from sklearn.ensemble import IsolationForest
            X = np.array(self._training_data)
            # Normalize
            self._scaler_mean = X.mean(axis=0)
            self._scaler_std = X.std(axis=0) + 1e-8
            X_norm = (X - self._scaler_mean) / self._scaler_std

            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1,
            )
            self.model.fit(X_norm)
            self._trained = True
            logger.info(f"ML model trained on {len(X)} samples")
        except Exception as e:
            logger.error(f"ML training error: {e}")

    def predict(self, feature_vector: List[float]) -> Tuple[bool, float]:
        """
        Returns (is_anomaly, anomaly_score).
        Score ranges 0.0 (normal) to 1.0 (very anomalous).
        """
        if not self._trained or self.model is None:
            return False, 0.0
        try:
            X = np.array(feature_vector).reshape(1, -1)
            X_norm = (X - self._scaler_mean) / self._scaler_std
            pred = self.model.predict(X_norm)[0]
            score = -self.model.score_samples(X_norm)[0]  # Higher = more anomalous
            # Normalize score to 0-1
            normalized = min(1.0, max(0.0, score / 0.5))
            return pred == -1, normalized
        except Exception as e:
            logger.debug(f"ML predict error: {e}")
            return False, 0.0

    def save_model(self, path: str):
        """Persist model to disk."""
        if not self._trained:
            return
        try:
            import joblib, os
            os.makedirs(os.path.dirname(path), exist_ok=True)
            joblib.dump({
                "model": self.model,
                "mean": self._scaler_mean,
                "std": self._scaler_std,
            }, path)
            logger.info(f"Model saved to {path}")
        except Exception as e:
            logger.error(f"Model save error: {e}")

    def load_model(self, path: str):
        """Load persisted model from disk."""
        try:
            import joblib
            data = joblib.load(path)
            self.model = data["model"]
            self._scaler_mean = data["mean"]
            self._scaler_std = data["std"]
            self._trained = True
            logger.info(f"Model loaded from {path}")
        except Exception as e:
            logger.error(f"Model load error: {e}")


# ---------------------------------------------------------------------------
# Main Intrusion Detector (combines both)
# ---------------------------------------------------------------------------

class IntrusionDetector:
    """
    Orchestrates rule-based and ML detection.
    Provides a single on_packet() callback for the NetworkMonitor.
    """

    def __init__(self, alert_callback=None):
        self.rule_engine = RuleEngine()
        self.ml_detector = MLAnomalyDetector()
        self._alert_callback = alert_callback
        self._events: deque = deque(maxlen=5000)
        self._event_counts: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

        # Dedup: suppress same event type from same src within cooldown
        self._dedup_cache: Dict[str, float] = {}
        self._dedup_cooldown = 5.0  # seconds

    def on_packet(self, features, flow):
        """Main entry point — called for every captured packet."""
        # 1. Rule-based detection
        events = self.rule_engine.check(features, flow)

        # 2. ML detection on completed flows
        if flow.packet_count % 20 == 0 and flow.packet_count > 0:
            vec = flow.to_feature_vector()
            self.ml_detector.add_sample(vec)
            is_anomaly, score = self.ml_detector.predict(vec)
            if is_anomaly and score > 0.6:
                import uuid
                events.append(ThreatEvent(
                    id=str(uuid.uuid4())[:8],
                    timestamp=time.time(),
                    category=ThreatCategory.ANOMALOUS_TRAFFIC,
                    severity=(
                        ThreatSeverity.CRITICAL if score > 0.9
                        else ThreatSeverity.HIGH if score > 0.75
                        else ThreatSeverity.MEDIUM
                    ),
                    src_ip=features.src_ip,
                    dst_ip=features.dst_ip,
                    src_port=features.src_port,
                    dst_port=features.dst_port,
                    protocol=features.protocol,
                    description=f"ML anomaly detected (score={score:.2f}) "
                                f"on flow {features.src_ip}→{features.dst_ip}",
                    confidence=score,
                    evidence={"anomaly_score": score, "flow_packets": flow.packet_count},
                    mitre_tactic="Unknown",
                    mitre_technique="ML-001",
                ))

        # 3. Dedup and dispatch
        for event in events:
            dedup_key = f"{event.category.value}:{event.src_ip}"
            with self._lock:
                last_seen = self._dedup_cache.get(dedup_key, 0)
                if time.time() - last_seen < self._dedup_cooldown:
                    continue
                self._dedup_cache[dedup_key] = time.time()
                self._events.append(event)
                self._event_counts[event.severity.value] += 1

            if self._alert_callback:
                try:
                    self._alert_callback(event)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")

    def get_recent_events(self, n: int = 100) -> List[dict]:
        return [e.to_dict() for e in list(self._events)[-n:]]

    def get_event_counts(self) -> dict:
        return dict(self._event_counts)

    def set_alert_callback(self, cb):
        self._alert_callback = cb
