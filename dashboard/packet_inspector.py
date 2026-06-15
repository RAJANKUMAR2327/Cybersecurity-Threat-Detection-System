"""
packet_inspector.py
-------------------
Deep packet inspection and analysis:
  - Full packet decode (all layers)
  - Hex dump
  - Protocol-specific parsing (HTTP, DNS, TLS)
  - Session reconstruction
  - Payload extraction
"""

import time
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

try:
    from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, Ether, ARP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
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
    decoded: Dict[str, Any]   # Protocol-specific fields
    anomalies: List[str]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
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
    """Deep packet inspection with full decode and anomaly detection."""

    def __init__(self, max_packets: int = 500):
        self._packets: deque = deque(maxlen=max_packets)
        self._counter = 0
        self._sessions: Dict[str, List[dict]] = {}

    def inspect(self, raw_packet) -> Optional[InspectedPacket]:
        """Fully inspect a raw Scapy packet."""
        if not SCAPY_AVAILABLE:
            return None
        try:
            return self._inspect_scapy(raw_packet)
        except Exception as e:
            logger.debug(f"Inspect error: {e}")
            return None

    def inspect_from_features(self, features) -> InspectedPacket:
        """Create an inspection record from PacketFeatures (for sim mode)."""
        self._counter += 1
        decoded = {}
        anomalies = []

        # Decode based on port
        if features.dst_port == 80 or features.src_port == 80:
            decoded["protocol_hint"] = "HTTP"
            if features.raw_payload:
                txt = features.raw_payload.decode(errors="replace")
                if txt.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                    parts = txt.split("\r\n")
                    decoded["http_method"] = parts[0].split()[0] if parts else ""
                    decoded["http_path"] = parts[0].split()[1] if len(parts[0].split()) > 1 else ""

        elif features.dst_port == 53 or features.src_port == 53:
            decoded["protocol_hint"] = "DNS"

        elif features.dst_port == 443 or features.src_port == 443:
            decoded["protocol_hint"] = "TLS/HTTPS"

        # Anomaly detection
        if features.ttl < 5:
            anomalies.append(f"Very low TTL: {features.ttl}")
        if features.packet_size > 1500:
            anomalies.append(f"Oversized packet: {features.packet_size}B")
        if features.flags == "R":
            anomalies.append("RST flag — connection forcefully terminated")
        if features.flags == "FPU":
            anomalies.append("Xmas scan — FIN+PSH+URG flags set")
        if features.flags == "" and features.protocol == "TCP":
            anomalies.append("NULL scan — no TCP flags set")

        payload = features.raw_payload or b""
        payload_hex = payload[:64].hex() if payload else ""
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

    def _guess_layers(self, features) -> List[str]:
        layers = ["Ethernet", "IP"]
        layers.append(features.protocol)
        if features.dst_port in (80, 8080):
            layers.append("HTTP")
        elif features.dst_port == 443:
            layers.append("TLS")
        elif features.dst_port == 53:
            layers.append("DNS")
        elif features.dst_port == 22:
            layers.append("SSH")
        if features.raw_payload:
            layers.append("Payload")
        return layers

    def _inspect_scapy(self, pkt) -> Optional[InspectedPacket]:
        if not pkt.haslayer(IP):
            return None

        self._counter += 1
        ip = pkt[IP]
        decoded = {}
        anomalies = []
        layers = []

        # Enumerate layers
        layer = pkt
        while layer:
            layers.append(layer.__class__.__name__)
            layer = layer.payload if hasattr(layer, 'payload') and layer.payload else None

        src_ip = ip.src
        dst_ip = ip.dst
        ttl = ip.ttl
        proto = "OTHER"
        src_port = dst_port = 0
        flags = ""

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            proto = "TCP"
            flag_map = {0x01:"F",0x02:"S",0x04:"R",0x08:"P",0x10:"A",0x20:"U",0x40:"E",0x80:"C"}
            flags = "".join(v for k,v in flag_map.items() if tcp.flags & k)

            # Detect scan types
            if not flags:
                anomalies.append("NULL scan detected")
            if "F" in flags and "P" in flags and "U" in flags:
                anomalies.append("Xmas scan detected")

            # HTTP decode
            if dst_port in (80, 8080) and pkt.haslayer(Raw):
                raw = pkt[Raw].load
                try:
                    txt = raw.decode("utf-8", errors="replace")
                    if txt.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
                        lines = txt.split("\r\n")
                        decoded["http_method"] = lines[0].split()[0]
                        decoded["http_path"] = lines[0].split()[1] if len(lines[0].split()) > 1 else ""
                        for line in lines[1:10]:
                            if "Host:" in line:
                                decoded["http_host"] = line.replace("Host:", "").strip()
                            if "User-Agent:" in line:
                                decoded["http_ua"] = line.replace("User-Agent:", "").strip()[:60]
                except Exception:
                    pass

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port, dst_port = udp.sport, udp.dport
            proto = "UDP"

            # DNS decode
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                decoded["dns_id"] = dns.id
                decoded["dns_qr"] = "response" if dns.qr else "query"
                if dns.haslayer(DNSQR):
                    decoded["dns_query"] = dns[DNSQR].qname.decode(errors="replace")
                if dns.haslayer(DNSRR):
                    decoded["dns_answer"] = dns[DNSRR].rdata

        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            icmp = pkt[ICMP]
            decoded["icmp_type"] = icmp.type
            decoded["icmp_code"] = icmp.code
            type_names = {0:"Echo Reply",8:"Echo Request",3:"Destination Unreachable",
                          11:"Time Exceeded",5:"Redirect"}
            decoded["icmp_type_name"] = type_names.get(icmp.type, "Unknown")

        # Low TTL
        if ttl < 5:
            anomalies.append(f"Suspiciously low TTL: {ttl}")

        # Get payload
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        payload_hex = payload[:64].hex()
        payload_ascii = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:64])

        inspected = InspectedPacket(
            id=self._counter,
            timestamp=time.time(),
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            protocol=proto, size=len(pkt),
            ttl=ttl, flags=flags,
            layers=[l for l in layers if l not in ("Padding", "NoPayload")],
            payload_hex=payload_hex,
            payload_ascii=payload_ascii,
            decoded=decoded,
            anomalies=anomalies,
        )
        self._packets.append(inspected)
        return inspected

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