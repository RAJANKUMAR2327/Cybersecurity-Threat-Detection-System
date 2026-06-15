"""
network_monitor.py
------------------
Real-time network packet capture and analysis using Scapy.
Captures packets, extracts features, and feeds them to the detection engine.
"""

import time
import threading
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Callable

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw,
        get_if_list, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import psutil

logger = logging.getLogger(__name__)


@dataclass
class PacketFeatures:
    """Extracted features from a network packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    flags: str
    payload_size: int
    ttl: int
    is_fragment: bool
    raw_payload: bytes = field(default_factory=bytes)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_size": self.packet_size,
            "flags": self.flags,
            "payload_size": self.payload_size,
            "ttl": self.ttl,
            "is_fragment": self.is_fragment,
        }


@dataclass
class FlowStats:
    """Statistics for a network flow (src_ip:port -> dst_ip:port)."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    flags_seen: set = field(default_factory=set)
    inter_arrival_times: list = field(default_factory=list)
    last_packet_time: float = field(default_factory=time.time)

    def update(self, pkt_features: PacketFeatures):
        now = time.time()
        self.inter_arrival_times.append(now - self.last_packet_time)
        self.last_packet_time = now
        self.packet_count += 1
        self.byte_count += pkt_features.packet_size
        self.last_seen = now
        if pkt_features.flags:
            self.flags_seen.add(pkt_features.flags)

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time

    @property
    def packets_per_second(self) -> float:
        d = self.duration
        return self.packet_count / d if d > 0 else self.packet_count

    @property
    def avg_inter_arrival(self) -> float:
        if not self.inter_arrival_times:
            return 0.0
        return sum(self.inter_arrival_times) / len(self.inter_arrival_times)

    def to_feature_vector(self) -> List[float]:
        """Convert flow stats to ML feature vector."""
        return [
            self.packet_count,
            self.byte_count,
            self.duration,
            self.packets_per_second,
            self.byte_count / max(self.packet_count, 1),
            self.avg_inter_arrival,
            len(self.flags_seen),
            self.src_port,
            self.dst_port,
            1 if self.protocol == "TCP" else 0,
            1 if self.protocol == "UDP" else 0,
            1 if self.protocol == "ICMP" else 0,
        ]


class NetworkMonitor:
    """
    Real-time network packet capture and flow tracking.

    Usage:
        monitor = NetworkMonitor(interface="eth0")
        monitor.add_packet_callback(my_handler)
        monitor.start()
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        packet_callback: Optional[Callable] = None,
        flow_timeout: int = 120,
        max_flows: int = 10000,
    ):
        self.interface = interface or self._get_default_interface()
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows

        self._flows: Dict[tuple, FlowStats] = {}
        self._packet_callbacks: List[Callable] = []
        self._flow_callbacks: List[Callable] = []
        self._recent_packets: deque = deque(maxlen=1000)

        self._running = False
        self._capture_thread: Optional[threading.Thread] = None
        self._cleanup_thread: Optional[threading.Thread] = None

        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "active_flows": 0,
            "packets_per_second": 0,
            "protocols": defaultdict(int),
            "start_time": time.time(),
        }
        self._pps_window = deque(maxlen=60)  # 1-minute rolling window

        if packet_callback:
            self._packet_callbacks.append(packet_callback)

        logger.info(f"NetworkMonitor initialized on interface: {self.interface}")

    def _get_default_interface(self) -> str:
        """Auto-detect best network interface."""
        if not SCAPY_AVAILABLE:
            return "eth0"
        try:
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            for iface in ifaces:
                name = iface.get('name', '')
                if name and 'loopback' not in name.lower():
                    return iface.get('win_index', name)
        except Exception:
            pass
        interfaces = get_if_list()
        return interfaces[0] if interfaces else "eth0"

    def add_packet_callback(self, callback: Callable):
        """Register a callback for each captured packet."""
        self._packet_callbacks.append(callback)

    def add_flow_callback(self, callback: Callable):
        """Register a callback when a flow is updated."""
        self._flow_callbacks.append(callback)

    def _extract_features(self, packet) -> Optional[PacketFeatures]:
        """Extract structured features from a raw Scapy packet."""
        try:
            if not packet.haslayer(IP):
                # Handle ARP separately
                if packet.haslayer(ARP):
                    return PacketFeatures(
                        timestamp=time.time(),
                        src_ip=packet[ARP].psrc,
                        dst_ip=packet[ARP].pdst,
                        src_port=0, dst_port=0,
                        protocol="ARP",
                        packet_size=len(packet),
                        flags="", payload_size=0,
                        ttl=0, is_fragment=False,
                    )
                return None

            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            ttl = ip.ttl
            is_fragment = bool(ip.flags & 0x1) or ip.frag > 0

            src_port = dst_port = 0
            flags = ""
            protocol = "OTHER"
            payload_size = 0

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                protocol = "TCP"
                flag_map = {
                    0x01: "F", 0x02: "S", 0x04: "R",
                    0x08: "P", 0x10: "A", 0x20: "U",
                }
                flags = "".join(v for k, v in flag_map.items() if tcp.flags & k)
                if packet.haslayer(Raw):
                    payload_size = len(packet[Raw].load)

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                protocol = "UDP"
                if packet.haslayer(Raw):
                    payload_size = len(packet[Raw].load)

            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            raw_payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""

            return PacketFeatures(
                timestamp=time.time(),
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=protocol,
                packet_size=len(packet),
                flags=flags,
                payload_size=payload_size,
                ttl=ttl,
                is_fragment=is_fragment,
                raw_payload=raw_payload,
            )
        except Exception as e:
            logger.debug(f"Feature extraction error: {e}")
            return None

    def _update_flow(self, features: PacketFeatures):
        """Update or create flow entry for the packet."""
        flow_key = (
            features.src_ip, features.dst_ip,
            features.src_port, features.dst_port,
            features.protocol
        )
        if flow_key not in self._flows:
            if len(self._flows) >= self.max_flows:
                self._evict_oldest_flow()
            self._flows[flow_key] = FlowStats(
                src_ip=features.src_ip,
                dst_ip=features.dst_ip,
                src_port=features.src_port,
                dst_port=features.dst_port,
                protocol=features.protocol,
            )
        self._flows[flow_key].update(features)
        return self._flows[flow_key]

    def _evict_oldest_flow(self):
        """Remove the least recently seen flow."""
        if not self._flows:
            return
        oldest_key = min(self._flows, key=lambda k: self._flows[k].last_seen)
        del self._flows[oldest_key]

    def _process_packet(self, packet):
        """Scapy callback for each captured packet."""
        features = self._extract_features(packet)
        if not features:
            return

        # Update global stats
        self.stats["total_packets"] += 1
        self.stats["total_bytes"] += features.packet_size
        self.stats["protocols"][features.protocol] += 1
        self._recent_packets.append(features)
        self._pps_window.append(time.time())

        # Update packets-per-second
        now = time.time()
        recent = [t for t in self._pps_window if now - t <= 1.0]
        self.stats["packets_per_second"] = len(recent)

        # Update flow tracking
        flow = self._update_flow(features)
        self.stats["active_flows"] = len(self._flows)

        # Fire callbacks
        for cb in self._packet_callbacks:
            try:
                cb(features, flow)
            except Exception as e:
                logger.error(f"Packet callback error: {e}")

    def _cleanup_expired_flows(self):
        """Background thread: remove timed-out flows."""
        while self._running:
            now = time.time()
            expired = [
                k for k, v in list(self._flows.items())
                if now - v.last_seen > self.flow_timeout
            ]
            for k in expired:
                flow = self._flows.pop(k, None)
                if flow:
                    for cb in self._flow_callbacks:
                        try:
                            cb(flow)
                        except Exception as e:
                            logger.error(f"Flow callback error: {e}")
            self.stats["active_flows"] = len(self._flows)
            time.sleep(30)

    def start(self):
        """Start packet capture in background thread."""
        if self._running:
            logger.warning("Monitor already running")
            return

        self._running = True
        logger.info(f"Starting capture on {self.interface}...")

        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available — running in simulation mode")
            self._capture_thread = threading.Thread(
                target=self._simulate_traffic, daemon=True
            )
        else:
            self._capture_thread = threading.Thread(
                target=self._capture_loop, daemon=True
            )

        self._cleanup_thread = threading.Thread(
            target=self._cleanup_expired_flows, daemon=True
        )
        self._capture_thread.start()
        self._cleanup_thread.start()
        logger.info("NetworkMonitor started.")

    def _capture_loop(self):
        """Real Scapy capture loop."""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")

    def _simulate_traffic(self):
        """
        Simulation mode when Scapy/root not available.
        Generates realistic fake packets for testing.
        """
        import random
        import ipaddress

        protocols = ["TCP", "UDP", "ICMP"]
        common_ports = [80, 443, 22, 21, 25, 53, 3306, 8080, 8443]
        local_nets = ["192.168.1.", "10.0.0.", "172.16.0."]

        while self._running:
            local_net = random.choice(local_nets)
            src_ip = local_net + str(random.randint(1, 254))
            dst_ip = f"{random.randint(1,223)}.{random.randint(0,255)}." \
                     f"{random.randint(0,255)}.{random.randint(1,254)}"

            proto = random.choices(
                protocols, weights=[60, 30, 10]
            )[0]

            src_port = random.randint(1024, 65535)
            dst_port = random.choice(common_ports)

            flags = ""
            if proto == "TCP":
                flags = random.choice(["S", "SA", "A", "PA", "FA", "R"])

            features = PacketFeatures(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                packet_size=random.randint(40, 1500),
                flags=flags,
                payload_size=random.randint(0, 1460),
                ttl=random.choice([64, 128, 255]),
                is_fragment=False,
            )

            flow = self._update_flow(features)
            self.stats["total_packets"] += 1
            self.stats["total_bytes"] += features.packet_size
            self.stats["protocols"][proto] += 1
            self._recent_packets.append(features)
            self._pps_window.append(time.time())
            now = time.time()
            recent = [t for t in self._pps_window if now - t <= 1.0]
            self.stats["packets_per_second"] = len(recent)
            self.stats["active_flows"] = len(self._flows)

            for cb in self._packet_callbacks:
                try:
                    cb(features, flow)
                except Exception as e:
                    logger.error(f"Sim callback error: {e}")

            time.sleep(random.uniform(0.05, 0.3))

    def stop(self):
        """Stop packet capture."""
        self._running = False
        logger.info("NetworkMonitor stopped.")

    def get_top_talkers(self, n: int = 10) -> List[dict]:
        """Return top N source IPs by packet count."""
        src_counts = defaultdict(int)
        for flow in self._flows.values():
            src_counts[flow.src_ip] += flow.packet_count
        sorted_ips = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "packets": cnt} for ip, cnt in sorted_ips[:n]]

    def get_recent_packets(self, n: int = 50) -> List[dict]:
        """Return N most recent packet feature dicts."""
        packets = list(self._recent_packets)[-n:]
        return [p.to_dict() for p in packets]

    def get_active_flows(self) -> List[dict]:
        """Return all active flows as dicts."""
        return [
            {
                "src": f"{f.src_ip}:{f.src_port}",
                "dst": f"{f.dst_ip}:{f.dst_port}",
                "protocol": f.protocol,
                "packets": f.packet_count,
                "bytes": f.byte_count,
                "pps": round(f.packets_per_second, 2),
                "duration": round(f.duration, 2),
            }
            for f in self._flows.values()
        ]
