"""
network_scanner.py
------------------
LAN device discovery and port scanning.
Uses ARP sweep (Scapy) + TCP connect fallback.
"""

import time
import socket
import threading
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
import ipaddress

logger = logging.getLogger(__name__)

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443]

OUI_DB = {
    "00:50:56": "VMware",       "00:0c:29": "VMware",
    "08:00:27": "VirtualBox",   "52:54:00": "QEMU/KVM",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "44:65:0d": "Amazon Echo",  "18:b4:30": "Nest Labs",
    "1c:7e:e5": "TP-Link",      "50:c7:bf": "TP-Link",
    "00:1d:0f": "ASUS",         "00:23:ae": "Cisco",
    "fc:fb:fb": "Cisco",        "00:e0:4c": "Realtek",
    "ac:de:48": "Apple",        "fc:65:de": "Apple",
    "00:17:88": "Philips Hue",
}

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


@dataclass
class OpenPort:
    port: int
    state: str
    service: str
    banner: str = ""


@dataclass
class NetworkDevice:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    open_ports: List[OpenPort] = field(default_factory=list)
    os_guess: str = ""
    response_time_ms: float = 0.0
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "open_ports": [
                {"port": p.port, "state": p.state,
                 "service": p.service, "banner": p.banner}
                for p in self.open_ports
            ],
            "os_guess": self.os_guess,
            "response_time_ms": round(self.response_time_ms, 2),
            "last_seen": datetime.fromtimestamp(self.last_seen).strftime("%Y-%m-%d %H:%M:%S"),
            "port_count": len(self.open_ports),
            "risk": self._assess_risk(),
        }

    def _assess_risk(self) -> str:
        risky = {23, 21, 3389, 5900}
        for p in self.open_ports:
            if p.port in risky:
                return "HIGH"
        if len(self.open_ports) > 10:
            return "MEDIUM"
        return "LOW"


class NetworkScanner:

    def __init__(self):
        self._devices: Dict[str, NetworkDevice] = {}
        self._scanning = False
        self._scan_progress = 0
        self._scan_total = 0
        self._last_scan: Optional[float] = None
        self._lock = threading.Lock()

    def get_local_network(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    def scan_network(self, network=None, port_scan=True, callback=None):
        if self._scanning:
            return list(self._devices.values())

        self._scanning = True
        self._scan_progress = 0
        network = network or self.get_local_network()

        try:
            hosts = self._arp_sweep(network)
            self._scan_total = len(hosts)

            for i, (ip, mac, rtt) in enumerate(hosts):
                self._scan_progress = i + 1
                device = NetworkDevice(ip=ip, mac=mac, response_time_ms=rtt)
                device.vendor = self._lookup_vendor(mac)
                device.hostname = self._resolve_hostname(ip)

                if port_scan:
                    device.open_ports = self._scan_ports(ip, COMMON_PORTS)

                device.os_guess = self._guess_os(device)

                with self._lock:
                    self._devices[ip] = device

                if callback:
                    callback(device.to_dict())

        except Exception as e:
            logger.error(f"Scan error: {e}")
        finally:
            self._scanning = False
            self._last_scan = time.time()

        return list(self._devices.values())

    def _arp_sweep(self, network: str):
        results = []

        if SCAPY_AVAILABLE:
            try:
                conf.verb = 0
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
                answered, _ = srp(pkt, timeout=2, verbose=False)
                for sent, received in answered:
                    rtt = (received.time - sent.sent_time) * 1000
                    results.append((received.psrc, received.hwsrc, rtt))
                return results
            except Exception as e:
                logger.warning(f"ARP sweep failed: {e}")

        # TCP fallback
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = list(net.hosts())[:254]
            self._scan_total = len(hosts)
            lock = threading.Lock()

            def tcp_ping(ip_obj):
                ip = str(ip_obj)
                try:
                    start = time.time()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    r = s.connect_ex((ip, 80))
                    s.close()
                    rtt = (time.time() - start) * 1000
                    if r in (0, 111):
                        with lock:
                            results.append((ip, "00:00:00:00:00:00", rtt))
                except Exception:
                    pass

            threads = [threading.Thread(target=tcp_ping, args=(h,)) for h in hosts]
            for t in threads:
                t.daemon = True
                t.start()
            for t in threads:
                t.join(timeout=2)
        except Exception as e:
            logger.error(f"TCP sweep error: {e}")

        return results

    def _scan_ports(self, ip: str, ports: List[int]):
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(OpenPort(
                        port=port, state="open",
                        service=SERVICE_NAMES.get(port, "unknown"),
                    ))
                s.close()
            except Exception:
                pass
        return open_ports

    def _lookup_vendor(self, mac: str) -> str:
        if not mac or mac == "00:00:00:00:00:00":
            return "Unknown"
        prefix = mac[:8].lower()
        for oui, vendor in OUI_DB.items():
            if prefix == oui.lower():
                return vendor
        return "Unknown"

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def _guess_os(self, device: NetworkDevice) -> str:
        ports = {p.port for p in device.open_ports}
        if 3389 in ports:
            return "Windows (RDP)"
        if 445 in ports and 139 in ports:
            return "Windows (SMB)"
        if 22 in ports:
            return "Linux/Unix"
        if 80 in ports or 443 in ports:
            return "Web Server"
        if device.vendor == "Raspberry Pi":
            return "Linux (Pi)"
        if device.vendor == "Apple":
            return "macOS/iOS"
        return "Unknown"

    def get_devices(self) -> List[dict]:
        with self._lock:
            return [d.to_dict() for d in self._devices.values()]

    def get_status(self) -> dict:
        return {
            "scanning": self._scanning,
            "progress": self._scan_progress,
            "total": self._scan_total,
            "devices_found": len(self._devices),
            "last_scan": datetime.fromtimestamp(self._last_scan).strftime("%Y-%m-%d %H:%M:%S")
                         if self._last_scan else None,
            "local_network": self.get_local_network(),
        }