import time, socket, logging, threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from collections import deque
logger = logging.getLogger(__name__)

@dataclass
class HoneypotEvent:
    timestamp: float
    service: str
    port: int
    src_ip: str
    src_port: int
    payload: str = ""
    credentials: dict = field(default_factory=dict)
    event_type: str = "connection"
    def to_dict(self):
        return {"timestamp":self.timestamp,"datetime":datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),"service":self.service,"port":self.port,"src_ip":self.src_ip,"src_port":self.src_port,"payload":self.payload[:200],"credentials":self.credentials,"event_type":self.event_type}

class BaseHoneypot:
    def __init__(self, port, name, callback=None):
        self.port = port
        self.service_name = name
        self._callback = callback
        self._running = False
        self._server = None
        self._events = deque(maxlen=1000)
        self._connections = 0
    def start(self):
        try:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind(("0.0.0.0", self.port))
            self._server.listen(10)
            self._server.settimeout(1.0)
            self._running = True
            threading.Thread(target=self._loop, daemon=True).start()
            return True
        except OSError as e:
            logger.warning(f"Cannot start {self.service_name} on {self.port}: {e}")
            return False
    def stop(self):
        self._running = False
        if self._server:
            try: self._server.close()
            except: pass
    def _loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                self._connections += 1
                threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
            except socket.timeout: continue
            except: break
    def _handle(self, conn, addr):
        self._log(HoneypotEvent(timestamp=time.time(), service=self.service_name, port=self.port, src_ip=addr[0], src_port=addr[1]))
        try: conn.close()
        except: pass
    def _log(self, event):
        self._events.append(event)
        if self._callback:
            try: self._callback(event)
            except Exception as e: logger.error(f"HP callback: {e}")
    def get_events(self): return [e.to_dict() for e in self._events]
    @property
    def is_running(self): return self._running

class SSHHoneypot(BaseHoneypot):
    def __init__(self, port=2222, callback=None): super().__init__(port, "SSH", callback)
    def _handle(self, conn, addr):
        self._log(HoneypotEvent(timestamp=time.time(), service="SSH", port=self.port, src_ip=addr[0], src_port=addr[1], event_type="connection"))
        try:
            banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" + b"\r\n"
            conn.send(banner)
            conn.settimeout(10)
            data = conn.recv(1024)
            if data:
                self._log(HoneypotEvent(timestamp=time.time(), service="SSH", port=self.port, src_ip=addr[0], src_port=addr[1], payload=data.decode(errors="replace"), event_type="auth_attempt"))
        except: pass
        finally:
            try: conn.close()
            except: pass

class FTPHoneypot(BaseHoneypot):
    def __init__(self, port=2121, callback=None): super().__init__(port, "FTP", callback)
    def _handle(self, conn, addr):
        self._log(HoneypotEvent(timestamp=time.time(), service="FTP", port=self.port, src_ip=addr[0], src_port=addr[1], event_type="connection"))
        try:
            conn.send(b"220 FTP Server Ready\r\n")
            conn.settimeout(15)
            username = ""
            while True:
                data = conn.recv(1024)
                if not data: break
                cmd = data.decode(errors="replace").strip()
                if cmd.upper().startswith("USER"):
                    username = cmd[5:].strip()
                    conn.send(b"331 Password required\r\n")
                elif cmd.upper().startswith("PASS"):
                    pwd = cmd[5:].strip()
                    self._log(HoneypotEvent(timestamp=time.time(), service="FTP", port=self.port, src_ip=addr[0], src_port=addr[1], payload=f"USER:{username} PASS:{pwd}", credentials={"username":username,"password":pwd}, event_type="auth_attempt"))
                    conn.send(b"530 Login incorrect\r\n")
                    break
                elif cmd.upper() == "QUIT":
                    conn.send(b"221 Goodbye\r\n")
                    break
                else:
                    conn.send(b"500 Unknown command\r\n")
        except: pass
        finally:
            try: conn.close()
            except: pass

class HTTPHoneypot(BaseHoneypot):
    def __init__(self, port=8888, callback=None): super().__init__(port, "HTTP", callback)
    def _handle(self, conn, addr):
        self._log(HoneypotEvent(timestamp=time.time(), service="HTTP", port=self.port, src_ip=addr[0], src_port=addr[1], event_type="connection"))
        try:
            conn.settimeout(10)
            data = conn.recv(4096)
            if data:
                lines = data.decode(errors="replace").split("\r\n")
                self._log(HoneypotEvent(timestamp=time.time(), service="HTTP", port=self.port, src_ip=addr[0], src_port=addr[1], payload=lines[0] if lines else "", event_type="data_received"))
                conn.send(b"HTTP/1.1 403 Forbidden\r\nServer: Apache/2.4.51\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><h1>403</h1></body></html>")
        except: pass
        finally:
            try: conn.close()
            except: pass

class TelnetHoneypot(BaseHoneypot):
    def __init__(self, port=2323, callback=None): super().__init__(port, "Telnet", callback)
    def _handle(self, conn, addr):
        self._log(HoneypotEvent(timestamp=time.time(), service="Telnet", port=self.port, src_ip=addr[0], src_port=addr[1], event_type="connection"))
        try:
            conn.send(b"\r\nUbuntu 22.04 LTS\r\nlogin: ")
            conn.settimeout(15)
            u = conn.recv(256)
            if u:
                conn.send(b"\r\nPassword: ")
                p = conn.recv(256)
                if p:
                    self._log(HoneypotEvent(timestamp=time.time(), service="Telnet", port=self.port, src_ip=addr[0], src_port=addr[1], credentials={"username":u.strip().decode(errors="replace"),"password":p.strip().decode(errors="replace")}, event_type="auth_attempt"))
                    conn.send(b"\r\nLogin incorrect\r\n")
        except: pass
        finally:
            try: conn.close()
            except: pass

class HoneypotManager:
    DEFAULT_PORTS = {"SSH":2222,"FTP":2121,"HTTP":8888,"Telnet":2323}
    def __init__(self, callback=None):
        self._callback = callback
        self._pots = {}
        self._all = deque(maxlen=5000)
        self._stats = {"total_connections":0,"auth_attempts":0,"unique_ips":set()}
        self._lock = threading.Lock()
    def _on_event(self, event):
        with self._lock:
            self._all.append(event)
            self._stats["total_connections"] += 1
            self._stats["unique_ips"].add(event.src_ip)
            if event.event_type == "auth_attempt":
                self._stats["auth_attempts"] += 1
        if self._callback:
            try: self._callback(event)
            except Exception as e: logger.error(f"HP mgr: {e}")
    def start_all(self):
        classes = {"SSH":(SSHHoneypot,2222),"FTP":(FTPHoneypot,2121),"HTTP":(HTTPHoneypot,8888),"Telnet":(TelnetHoneypot,2323)}
        results = {}
        for name,(cls,port) in classes.items():
            hp = cls(port=port, callback=self._on_event)
            ok = hp.start()
            self._pots[name] = hp
            results[name] = {"port":port,"running":ok}
        return results
    def start_service(self, service, port=None):
        classes = {"SSH":SSHHoneypot,"FTP":FTPHoneypot,"HTTP":HTTPHoneypot,"Telnet":TelnetHoneypot}
        cls = classes.get(service)
        if not cls: return False
        p = port or self.DEFAULT_PORTS.get(service, 9999)
        hp = cls(port=p, callback=self._on_event)
        ok = hp.start()
        if ok: self._pots[service] = hp
        return ok
    def stop_service(self, service):
        hp = self._pots.get(service)
        if hp: hp.stop(); del self._pots[service]
    def stop_all(self):
        for hp in self._pots.values(): hp.stop()
        self._pots.clear()
    def get_status(self):
        s = {}
        for name,hp in self._pots.items():
            s[name] = {"running":hp.is_running,"port":hp.port,"events":len(hp.get_events())}
        for name,port in self.DEFAULT_PORTS.items():
            if name not in s: s[name] = {"running":False,"port":port,"events":0}
        return s
    def get_events(self, n=100, service=None):
        with self._lock: events = list(self._all)
        if service: events = [e for e in events if e.service==service]
        return [e.to_dict() for e in events[-n:]]
    def get_stats(self):
        with self._lock:
            return {"total_connections":self._stats["total_connections"],"auth_attempts":self._stats["auth_attempts"],"unique_attackers":len(self._stats["unique_ips"]),"active_services":sum(1 for hp in self._pots.values() if hp.is_running)}
