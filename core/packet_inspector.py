"""
packet_inspector.py
-------------------
Deep packet inspection — full decode, hex dump,
protocol parsing (HTTP/DNS/TLS), anomaly detection.
"""

import time
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

try:
    from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class InspectedPacket:
    id: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    ttl: int
    flags: str
    layers: List[str]
    payload_hex: str
    payload_ascii: str
    decoded: Dict[str, Any]
    anomalies: List[str]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )[:-3],
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "size": self.size,
            "ttl": self.ttl,
            "flags": self.flags,
            "layers": self.layers,
            "payload_hex": self.payload_hex,
            "payload_ascii": self.payload_ascii,
            "decoded": self.decoded,
            "anomalies": self.anomalies,
        }


class PacketInspector:

    def __init__(self, max_packets: int = 500):
        self._packets: deque = deque(maxlen=max_packets)
        self._counter = 0

    def inspect_from_features(self, features) -> InspectedPacket:
        """Build an InspectedPacket from a PacketFeatures object."""
        self._counter += 1
        decoded = {}
        anomalies = []

        # Protocol hints from port
        port = features.dst_port
        if port in (80, 8080):
            decoded["protocol_hint"] = "HTTP"
            if features.raw_payload:
                txt = features.raw_payload.decode(errors="replace")
                if txt.startswith(("GET ","POST ","PUT ","DELETE ","HEAD ")):
                    parts = txt.split("\r\n")
                    words = parts[0].split()
                    decoded["http_method"] = words[0] if words else ""
                    decoded["http_path"]   = words[1] if len(words) > 1 else ""
        elif port == 443:
            decoded["protocol_hint"] = "TLS/HTTPS"
        elif port == 53 or features.src_port == 53:
            decoded["protocol_hint"] = "DNS"
        elif port == 22:
            decoded["protocol_hint"] = "SSH"
        elif port == 21:
            decoded["protocol_hint"] = "FTP"
        elif port == 3306:
            decoded["protocol_hint"] = "MySQL"
        elif port == 3389:
            decoded["protocol_hint"] = "RDP"

        # Anomaly checks
        if features.ttl < 5:
            anomalies.append(f"Very low TTL: {features.ttl}")
        if features.packet_size > 1500:
            anomalies.append(f"Oversized packet: {features.packet_size}B")
        if features.flags == "FPU":
            anomalies.append("Xmas scan — FIN+PSH+URG set")
        if features.flags == "" and features.protocol == "TCP":
            anomalies.append("NULL scan — no TCP flags")
        if features.flags == "R":
            anomalies.append("RST — connection reset")
        if features.is_fragment:
            anomalies.append("IP fragment detected")
        if features.dst_port in (23, 21) and features.protocol == "TCP":
            anomalies.append(f"Insecure protocol on port {features.dst_port}")

        # Payload
        payload = features.raw_payload or b""
        payload_hex   = payload[:64].hex() if payload else ""
        payload_ascii = "".join(
            chr(b) if 32 <= b < 127 else "." for b in payload[:64]
        )

        pkt = InspectedPacket(
            id=self._counter,
            timestamp=features.timestamp,
            src_ip=features.src_ip,
            dst_ip=features.dst_ip,
            src_port=features.src_port,
            dst_port=features.dst_port,
            protocol=features.protocol,
            size=features.packet_size,
            ttl=features.ttl,
            flags=features.flags,
            layers=self._guess_layers(features),
            payload_hex=payload_hex,
            payload_ascii=payload_ascii,
            decoded=decoded,
            anomalies=anomalies,
        )
        self._packets.append(pkt)
        return pkt

    def inspect_scapy(self, raw_pkt) -> Optional[InspectedPacket]:
        """Full Scapy packet inspection."""
        if not SCAPY_AVAILABLE or not raw_pkt.haslayer(IP):
            return None

        self._counter += 1
        ip = raw_pkt[IP]
        decoded = {}
        anomalies = []
        layers = []

        # Collect layer names
        layer = raw_pkt
        while layer:
            name = layer.__class__.__name__
            if name not in ("Padding", "NoPayload"):
                layers.append(name)
            layer = layer.payload if hasattr(layer, "payload") else None

        src_ip = ip.src
        dst_ip = ip.dst
        ttl    = ip.ttl
        proto  = "OTHER"
        src_port = dst_port = 0
        flags = ""

        if raw_pkt.haslayer(TCP):
            tcp = raw_pkt[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            proto = "TCP"
            flag_map = {
                0x01:"F", 0x02:"S", 0x04:"R",
                0x08:"P", 0x10:"A", 0x20:"U",
            }
            flags = "".join(v for k,v in flag_map.items() if tcp.flags & k)
            if not flags:
                anomalies.append("NULL scan")
            if "F" in flags and "P" in flags and "U" in flags:
                anomalies.append("Xmas scan")

            # HTTP decode
            if dst_port in (80, 8080) and raw_pkt.haslayer(Raw):
                try:
                    txt = raw_pkt[Raw].load.decode("utf-8", errors="replace")
                    if txt.startswith(("GET ","POST ","PUT ","DELETE ")):
                        lines = txt.split("\r\n")
                        words = lines[0].split()
                        decoded["http_method"] = words[0]
                        decoded["http_path"]   = words[1] if len(words)>1 else ""
                        for line in lines[1:10]:
                            if line.startswith("Host:"):
                                decoded["http_host"] = line[5:].strip()
                            if line.startswith("User-Agent:"):
                                decoded["http_ua"] = line[11:].strip()[:60]
                except Exception:
                    pass

        elif raw_pkt.haslayer(UDP):
            udp = raw_pkt[UDP]
            src_port, dst_port = udp.sport, udp.dport
            proto = "UDP"
            if raw_pkt.haslayer(DNS):
                dns = raw_pkt[DNS]
                decoded["dns_id"] = dns.id
                decoded["dns_qr"] = "response" if dns.qr else "query"
                if raw_pkt.haslayer(DNSQR):
                    decoded["dns_query"] = dns[DNSQR].qname.decode(errors="replace")

        elif raw_pkt.haslayer(ICMP):
            proto = "ICMP"
            icmp = raw_pkt[ICMP]
            type_names = {
                0: "Echo Reply", 8: "Echo Request",
                3: "Dest Unreachable", 11: "Time Exceeded",
            }
            decoded["icmp_type"] = icmp.type
            decoded["icmp_name"] = type_names.get(icmp.type, "Unknown")

        if ttl < 5:
            anomalies.append(f"Low TTL: {ttl}")

        payload = bytes(raw_pkt[Raw].load) if raw_pkt.haslayer(Raw) else b""
        payload_hex   = payload[:64].hex()
        payload_ascii = "".join(
            chr(b) if 32 <= b < 127 else "." for b in payload[:64]
        )

        pkt = InspectedPacket(
            id=self._counter,
            timestamp=time.time(),
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            protocol=proto, size=len(raw_pkt),
            ttl=ttl, flags=flags,
            layers=layers,
            payload_hex=payload_hex,
            payload_ascii=payload_ascii,
            decoded=decoded,
            anomalies=anomalies,
        )
        self._packets.append(pkt)
        return pkt

    def _guess_layers(self, features) -> List[str]:
        layers = ["Ethernet", "IP", features.protocol]
        port = features.dst_port
        if port in (80, 8080):   layers.append("HTTP")
        elif port == 443:        layers.append("TLS")
        elif port == 53:         layers.append("DNS")
        elif port == 22:         layers.append("SSH")
        if features.raw_payload: layers.append("Payload")
        return layers

    def get_packets(self, n: int = 100, protocol: str = None,
                    src_ip: str = None, dst_ip: str = None) -> List[dict]:
        pkts = list(self._packets)
        if protocol:
            pkts = [p for p in pkts if p.protocol == protocol.upper()]
        if src_ip:
            pkts = [p for p in pkts if p.src_ip == src_ip]
        if dst_ip:
            pkts = [p for p in pkts if p.dst_ip == dst_ip]
        return [p.to_dict() for p in pkts[-n:]]

    def get_packet_by_id(self, pkt_id: int) -> Optional[dict]:
        for p in self._packets:
            if p.id == pkt_id:
                return p.to_dict()
        return None

    def get_stats(self) -> dict:
        pkts = list(self._packets)
        proto_counts = {}
        anomaly_count = 0
        for p in pkts:
            proto_counts[p.protocol] = proto_counts.get(p.protocol, 0) + 1
            anomaly_count += len(p.anomalies)
        return {
            "total_inspected": self._counter,
            "buffered": len(pkts),
            "protocols": proto_counts,
            "anomalies_found": anomaly_count,
        }
