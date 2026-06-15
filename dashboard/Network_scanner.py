"""
network_scanner.py
------------------
LAN device discovery and port scanning using:
  - ARP ping sweep (Scapy)
  - TCP SYN port scanner
  - Service/OS fingerprinting
  - Vendor lookup via MAC OUI
"""

import time
import socket
import struct
import threading
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
import ipaddress

logger = logging.getLogger(__name__)

try:
    from scapy.all import ARP, Ether, srp, IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

# MAC OUI vendor prefixes (first 3 octets)
OUI_DB = {
    "00:50:56": "VMware",       "00:0c:29": "VMware",
    "08:00:27": "VirtualBox",   "52:54:00": "QEMU/KVM",
    "00:1a:11": "Google",       "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi", "00:17:88": "Philips Hue",
    "18:b4:30": "Nest Labs",    "44:65:0d": "Amazon Echo",
    "fc:65:de": "Apple",        "ac:de:48": "Apple",
    "00:1b:63": "Apple",        "3c:15:c2": "Apple",
    "00:23:12": "Apple",        "00:26:bb": "Apple",
    "28:cf:e9": "Apple",        "00:50:ba": "D-Link",
    "1c:7e:e5": "TP-Link",      "50:c7:bf": "TP-Link",
    "00:1d:0f": "ASUS",         "00:e0:4c": "Realtek",
    "00:23:ae": "Cisco",        "00:1e:13": "Cisco",
    "fc:fb:fb": "Cisco",        "00:1b:2f": "Cisco",
}


@dataclass
class OpenPort:
    port: int
    state: str          # open / closed / filtered
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
    is_gateway: bool = False

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "open_ports": [
                {"port": p.port, "state": p.state, "service": p.service, "banner": p.banner}
                for p in self.open_ports
            ],
            "os_guess": self.os_guess,
            "response_time_ms": round(self.response_time_ms, 2),
            "last_seen": datetime.fromtimestamp(self.last_seen).strftime("%Y-%m-%d %H:%M:%S"),
            "is_gateway": self.is_gateway,
            "port_count": len(self.open_ports),
            "risk": self._assess_risk(),
        }

    def _assess_risk(self) -> str:
        risky_ports = {23: "Telnet", 21: "FTP", 3389: "RDP", 5900: "VNC", 1723: "PPTP"}
        for p in self.open_ports:
            if p.port in risky_ports:
                return "HIGH"
        if len(self.open_ports) > 10:
            return "MEDIUM"
        return "LOW"


# Service name map
SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


class NetworkScanner:
    """
    Discovers and scans devices on the local network.
    Uses ARP for host discovery, TCP for port scanning.
    """

    def __init__(self):
        self._devices: Dict[str, NetworkDevice] = {}
        self._scanning = False
        self._scan_progress = 0
        self._scan_total = 0
        self._last_scan: Optional[float] = None
        self._lock = threading.Lock()

    def get_local_network(self) -> str:
        """Auto-detect local network CIDR."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Assume /24
            parts = local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    def scan_network(self, network: Optional[str] = None, port_scan: bool = True,
                     callback=None) -> List[NetworkDevice]:
        """
        Full network scan: ARP discovery + optional port scan.
        Runs in current thread — call via threading for async.
        """
        if self._scanning:
            return list(self._devices.values())

        self._scanning = True
        self._scan_progress = 0
        network = network or self.get_local_network()
        devices = []

        try:
            logger.info(f"Scanning network: {network}")
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
                devices.append(device)

                if callback:
                    callback(device.to_dict())

        except Exception as e:
            logger.error(f"Network scan error: {e}")
        finally:
            self._scanning = False
            self._last_scan = time.time()

        return devices

    def _arp_sweep(self, network: str) -> List[tuple]:
        """ARP ping sweep — returns list of (ip, mac, rtt_ms)."""
        results = []

        if SCAPY_AVAILABLE:
            try:
                conf.verb = 0
                arp = ARP(pdst=network)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp
                answered, _ = srp(packet, timeout=2, verbose=False)
                for sent, received in answered:
                    rtt = (received.time - sent.sent_time) * 1000
                    results.append((received.psrc, received.hwsrc, rtt))
                return results
            except Exception as e:
                logger.warning(f"ARP sweep failed: {e}, falling back to TCP ping")

        # Fallback: TCP connect sweep
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = list(net.hosts())[:254]
            self._scan_total = len(hosts)

            def tcp_ping(ip_obj):
                ip = str(ip_obj)
                try:
                    start = time.time()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    r = s.connect_ex((ip, 80))
                    s.close()
                    rtt = (time.time() - start) * 1000
                    if r in (0, 111):  # Connected or connection refused = host up
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
            logger.error(f"TCP ping sweep error: {e}")

        return results

    def _scan_ports(self, ip: str, ports: List[int]) -> List[OpenPort]:
        """TCP connect port scan."""
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    banner = ""
                    try:
                        if port in (80, 8080, 8443, 443):
                            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = s.recv(128).decode(errors="replace").split("\r\n")[0]
                    except Exception:
                        pass
                    open_ports.append(OpenPort(
                        port=port,
                        state="open",
                        service=SERVICE_NAMES.get(port, "unknown"),
                        banner=banner[:80],
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
            return "Windows (RDP open)"
        if 445 in ports and 139 in ports:
            return "Windows (SMB open)"
        if 22 in ports and 80 in ports:
            return "Linux/Unix"
        if 22 in ports:
            return "Linux/Unix (SSH)"
        if 80 in ports or 443 in ports:
            return "Web Server"
        if device.vendor in ("Raspberry Pi",):
            return "Linux (Raspberry Pi)"
        if device.vendor in ("Apple",):
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