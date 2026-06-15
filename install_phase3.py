import os

os.makedirs("core", exist_ok=True)

# ── ai_assistant.py ──────────────────────────────────────────
open("core/ai_assistant.py","w",encoding="utf-8").write('''
import time, json, logging, threading, requests
from collections import deque
from datetime import datetime
from typing import List, Dict, Optional
logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are CyberShield AI, an expert cybersecurity analyst embedded in a real-time network threat detection system. Analyze the network data provided and give specific, actionable security advice. Reference actual IPs and events from the context. Be concise but complete."""

class AIAssistant:
    def __init__(self):
        self._history = []
        self._context_cache = {}
        self._context_lock = threading.Lock()
        self._chat_log = deque(maxlen=200)
        self._model = "claude-sonnet-4-6"

    def set_context(self, context):
        with self._context_lock:
            self._context_cache = context

    def _build_context(self):
        with self._context_lock:
            ctx = self._context_cache or {}
        if not ctx: return "No live network data available yet."
        lines = ["## LIVE NETWORK STATUS"]
        stats = ctx.get("stats", {})
        if stats:
            lines.append(f"Packets: {stats.get(\'total_packets\',0):,} | Flows: {stats.get(\'active_flows\',0)} | PPS: {stats.get(\'packets_per_second\',0)} | Interface: {stats.get(\'interface\',\'?\')} | ML: {\'Trained\' if stats.get(\'ml_trained\') else \'Training\'}")
        events = ctx.get("events", [])
        if events:
            sev = {}
            for e in events: sev[e.get("severity","LOW")] = sev.get(e.get("severity","LOW"),0)+1
            lines.append(f"\\n## THREATS ({len(events)} total) | {sev}")
            for e in events[:10]:
                lines.append(f"- [{e.get(\'severity\')}] {e.get(\'category\')} | {e.get(\'src_ip\')}:{e.get(\'src_port\')} -> {e.get(\'dst_ip\')}:{e.get(\'dst_port\')} | {e.get(\'description\',\'\')[:80]}")
        blocked = [b for b in ctx.get("blocked_ips",[]) if b.get("active")]
        if blocked:
            lines.append(f"\\n## BLOCKED IPs ({len(blocked)})")
            for b in blocked[:5]: lines.append(f"- {b.get(\'ip\')} | {b.get(\'reason\')}")
        malware = [m for m in ctx.get("malware",[]) if m.get("is_malicious")]
        if malware:
            lines.append(f"\\n## MALWARE ({len(malware)})")
            for m in malware[:5]: lines.append(f"- {m.get(\'target\')} | {m.get(\'threat_name\')} | {m.get(\'severity\')}")
        return "\\n".join(lines)

    def chat(self, message):
        ctx_block = self._build_context()
        full_msg = f"{message}\\n\\n---\\nCURRENT NETWORK CONTEXT:\\n{ctx_block}"
        self._history.append({"role":"user","content":full_msg})
        if len(self._history) > 40: self._history = self._history[-40:]
        try:
            resp = requests.post("https://api.anthropic.com/v1/messages",
                headers={"Content-Type":"application/json"},
                json={"model":self._model,"max_tokens":1000,"system":SYSTEM_PROMPT,"messages":self._history},
                timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                reply = "".join(b.get("text","") for b in data.get("content",[]) if b.get("type")=="text")
                self._history.append({"role":"assistant","content":reply})
                self._chat_log.append({"timestamp":time.time(),"datetime":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"user":message,"assistant":reply})
                return reply
            else: return self._demo(message)
        except Exception as e:
            logger.error(f"AI error: {e}")
            return self._demo(message)

    def _demo(self, message):
        msg = message.lower()
        ctx = self._context_cache or {}
        events = ctx.get("events",[])
        critical = [e for e in events if e.get("severity")=="CRITICAL"]
        high = [e for e in events if e.get("severity")=="HIGH"]
        if any(w in msg for w in ["status","summary","overview"]):
            return f"## Security Summary\\n\\nThreats: {len(events)} total | {len(critical)} CRITICAL | {len(high)} HIGH\\n\\n" + ("\\n".join([f"- [{e.get(\'severity\')}] {e.get(\'category\')}: {e.get(\'src_ip\')} -> {e.get(\'dst_ip\')}" for e in (critical+high)[:5]]) or "No active threats") + "\\n\\n*Enable internet access for full Claude AI analysis.*"
        elif any(w in msg for w in ["critical","urgent","worst"]):
            if critical:
                e = critical[0]
                return f"## Most Critical Threat\\n\\n**{e.get(\'category\')}** from `{e.get(\'src_ip\')}`\\n- Destination: {e.get(\'dst_ip\')}:{e.get(\'dst_port\')}\\n- Confidence: {round(e.get(\'confidence\',0)*100)}%\\n- {e.get(\'description\')}\\n\\n**Action:** Block {e.get(\'src_ip\')} immediately in the IP Blocker tab."
            return "No CRITICAL threats detected. System stable."
        elif any(w in msg for w in ["block","stop","fix","prevent"]):
            return "## Recommendations\\n\\n1. Use **IP Blocker** tab to block malicious IPs\\n2. Enable **Auto-Block** for HIGH+ severity\\n3. Check **Threat Intel** to verify IPs on VirusTotal\\n4. Review **Dark Web** tab for breach matches\\n5. Download **PDF Report** for documentation"
        return "I can help analyze your network security. Try:\\n- *Give me a security summary*\\n- *What are my critical threats?*\\n- *How do I respond to a SYN flood?*\\n- *Which IPs should I block?*\\n\\n*(Connect to internet for full Claude AI responses)*"

    def get_quick_prompts(self):
        return ["Give me a security posture summary","What are my most critical threats?","Which IPs should I block immediately?","Explain the most recent attack","What patterns do you see in the threats?","Generate an executive summary","How do I respond to a SYN flood?","What does the MITRE data tell us?"]

    def clear_history(self): self._history = []

    def get_chat_log(self, n=50): return list(self._chat_log)[-n:]
''')
print("core/ai_assistant.py written")

# ── geoip_map.py ─────────────────────────────────────────────
open("core/geoip_map.py","w",encoding="utf-8").write('''
import time, logging, threading, requests
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
logger = logging.getLogger(__name__)

PRIVATE_PREFIXES = ["10.","192.168.","172.16.","172.17.","172.18.","172.19.","172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31.","127.","169.254.","0."]
COUNTRY_COORDS = {"US":(37.09,-95.71),"CN":(35.86,104.19),"RU":(61.52,105.31),"DE":(51.16,10.45),"GB":(55.37,-3.43),"FR":(46.22,2.21),"NL":(52.13,5.29),"JP":(36.20,138.25),"KR":(35.90,127.76),"BR":(-14.23,-51.92),"IN":(20.59,78.96),"CA":(56.13,-106.34),"AU":(-25.27,133.77),"UA":(48.37,31.16),"SE":(60.12,18.64),"IT":(41.87,12.56),"ES":(40.46,-3.74),"TR":(38.96,35.24),"SG":(1.35,103.82),"RO":(45.94,24.96)}
KNOWN_GEO = {"185.220.":("Germany","DE","Frankfurt",51.16,10.45),"45.142.":("Russia","RU","Moscow",55.75,37.61),"194.165.":("Netherlands","NL","Amsterdam",52.37,4.89),"91.108.":("Germany","DE","Berlin",52.52,13.40),"199.249.":("United States","US","New York",40.71,-74.00),"162.247.":("United States","US","Chicago",41.87,-87.62),"172.16.":("Private","LAN","Internal",0,0),"192.168.":("Private","LAN","Internal",0,0),"10.":("Private","LAN","Internal",0,0)}

@dataclass
class GeoLocation:
    ip: str; country: str=""; country_code: str=""; city: str=""; lat: float=0.0; lon: float=0.0; isp: str=""; is_private: bool=False; timestamp: float=field(default_factory=time.time)
    def to_dict(self): return {"ip":self.ip,"country":self.country,"country_code":self.country_code,"city":self.city,"lat":self.lat,"lon":self.lon,"isp":self.isp,"is_private":self.is_private}

@dataclass
class AttackOrigin:
    ip: str; lat: float; lon: float; country: str; country_code: str; city: str; attack_count: int; severity_counts: dict; categories: list; last_seen: float; isp: str=""
    def to_dict(self):
        sev = self.severity_counts
        rl = "CRITICAL" if sev.get("CRITICAL",0)>0 else "HIGH" if sev.get("HIGH",0)>0 else "MEDIUM" if sev.get("MEDIUM",0)>0 else "LOW"
        return {"ip":self.ip,"lat":self.lat,"lon":self.lon,"country":self.country,"country_code":self.country_code,"city":self.city,"attack_count":self.attack_count,"severity_counts":sev,"categories":list(set(self.categories))[:5],"last_seen":datetime.fromtimestamp(self.last_seen).strftime("%Y-%m-%d %H:%M:%S"),"isp":self.isp,"risk_level":rl}

class GeoIPMap:
    def __init__(self):
        self._cache: Dict[str,GeoLocation]={}; self._cache_lock=threading.Lock()
        self._origins: Dict[str,AttackOrigin]={}; self._origins_lock=threading.Lock()
        self._queue=deque(maxlen=500); self._country_stats=defaultdict(int)
        self._recent=deque(maxlen=500); self._running=True
        threading.Thread(target=self._worker,daemon=True).start()

    def _is_private(self,ip): return any(ip.startswith(p) for p in PRIVATE_PREFIXES)

    def track_event(self, event):
        src = event.get("src_ip","")
        if src and not self._is_private(src):
            self._queue.append({"ip":src,"severity":event.get("severity","LOW"),"category":event.get("category","Unknown"),"timestamp":time.time()})

    def lookup(self, ip):
        if self._is_private(ip): return GeoLocation(ip=ip,is_private=True,country="Private",country_code="LAN")
        with self._cache_lock:
            c=self._cache.get(ip)
            if c and time.time()-c.timestamp<86400: return c
        geo=self._fetch(ip)
        with self._cache_lock: self._cache[ip]=geo
        return geo

    def _fetch(self, ip):
        for prefix,(country,code,city,lat,lon) in KNOWN_GEO.items():
            if ip.startswith(prefix): return GeoLocation(ip=ip,country=country,country_code=code,city=city,lat=lat,lon=lon,isp="Demo mode")
        try:
            r=requests.get(f"http://ip-api.com/json/{ip}",params={"fields":"status,country,countryCode,city,lat,lon,isp"},timeout=5)
            if r.status_code==200:
                d=r.json()
                if d.get("status")=="success": return GeoLocation(ip=ip,country=d.get("country",""),country_code=d.get("countryCode",""),city=d.get("city",""),lat=float(d.get("lat",0)),lon=float(d.get("lon",0)),isp=d.get("isp",""))
        except Exception: pass
        parts=ip.split(".")
        try: lat,lon=(int(parts[0])%180)-90,(int(parts[1])%360)-180
        except: lat,lon=0,0
        return GeoLocation(ip=ip,country="Unknown",country_code="??",city="Unknown",lat=lat,lon=lon)

    def _worker(self):
        while self._running:
            if self._queue:
                item=self._queue.popleft(); ip=item["ip"]; geo=self.lookup(ip)
                if not geo.is_private:
                    with self._origins_lock:
                        if ip not in self._origins:
                            self._origins[ip]=AttackOrigin(ip=ip,lat=geo.lat,lon=geo.lon,country=geo.country,country_code=geo.country_code,city=geo.city,attack_count=0,severity_counts={},categories=[],last_seen=time.time(),isp=geo.isp)
                        o=self._origins[ip]; o.attack_count+=1; o.last_seen=time.time()
                        s=item.get("severity","LOW"); o.severity_counts[s]=o.severity_counts.get(s,0)+1
                        c=item.get("category","Unknown")
                        if c not in o.categories: o.categories.append(c)
                    self._country_stats[geo.country_code]+=1
                    self._recent.append({**item,"geo":geo.to_dict()})
            time.sleep(0.5)

    def get_map_data(self):
        with self._origins_lock: origins=[o.to_dict() for o in self._origins.values()]
        cc=[{"code":k,"count":v,"lat":COUNTRY_COORDS.get(k,(0,0))[0],"lon":COUNTRY_COORDS.get(k,(0,0))[1]} for k,v in sorted(self._country_stats.items(),key=lambda x:x[1],reverse=True)[:20]]
        return {"origins":origins,"country_stats":cc,"total_origins":len(origins),"total_countries":len(self._country_stats),"recent_attacks":list(self._recent)[-20:]}

    def get_top_countries(self,n=10): return sorted([{"code":k,"count":v} for k,v in self._country_stats.items()],key=lambda x:x["count"],reverse=True)[:n]
    def stop(self): self._running=False
''')
print("core/geoip_map.py written")

# ── vuln_scanner.py ──────────────────────────────────────────
open("core/vuln_scanner.py","w",encoding="utf-8").write('''
import time, logging, threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
logger = logging.getLogger(__name__)

LOCAL_CVE_DB = {
    22:[("CVE-2023-38408","CRITICAL","OpenSSH RCE via ssh-agent",9.8),("CVE-2018-15473","MEDIUM","OpenSSH username enum",5.3)],
    23:[("CVE-2020-10188","CRITICAL","Telnet remote code execution",9.8)],
    21:[("CVE-2011-2523","CRITICAL","vsftpd 2.3.4 backdoor",10.0),("CVE-2021-3618","HIGH","vsftpd ALPACA attack",7.4)],
    25:[("CVE-2023-42115","CRITICAL","Exim auth bypass RCE",9.8),("CVE-2019-10149","CRITICAL","Exim RCE via recipient",9.8)],
    80:[("CVE-2021-41773","CRITICAL","Apache path traversal RCE",9.8),("CVE-2021-44228","CRITICAL","Log4Shell RCE",10.0)],
    443:[("CVE-2021-44228","CRITICAL","Log4Shell RCE",10.0),("CVE-2014-0160","HIGH","Heartbleed info disclosure",7.5)],
    445:[("CVE-2017-0144","CRITICAL","EternalBlue SMB RCE (WannaCry)",9.8),("CVE-2020-0796","CRITICAL","SMBGhost RCE",10.0)],
    3389:[("CVE-2019-0708","CRITICAL","BlueKeep RDP RCE pre-auth",9.8),("CVE-2019-1181","CRITICAL","DejaBlue RDP RCE",9.8)],
    3306:[("CVE-2022-21824","HIGH","MySQL privilege escalation",7.1)],
    5900:[("CVE-2023-28771","CRITICAL","LibVNCServer buffer overflow",9.8)],
    8080:[("CVE-2021-44228","CRITICAL","Log4Shell RCE",10.0),("CVE-2020-1938","CRITICAL","Apache Tomcat Ghostcat",9.8)],
    6379:[("CVE-2022-0543","CRITICAL","Redis Lua sandbox escape RCE",10.0)],
    27017:[("CVE-2019-2389","MEDIUM","MongoDB unauthorized access",6.1)],
}
REMEDIATION = {22:"Update OpenSSH. Use key-based auth only.",23:"DISABLE Telnet immediately — use SSH.",21:"Disable FTP. Use SFTP instead.",25:"Update Exim/Postfix. Apply patches.",80:"Update web server. Patch Log4j.",443:"Update TLS. Patch Log4j. Enable HSTS.",445:"Apply MS17-010 patch. Disable SMBv1.",3389:"Apply BlueKeep patch. Enable NLA.",3306:"Bind MySQL to localhost. Use strong passwords.",5900:"Update VNC. Use VPN for access.",8080:"Patch Log4j. Apply WAF rules.",6379:"Bind Redis to localhost. Enable AUTH.",27017:"Enable MongoDB auth. Bind to localhost."}
SERVICE_NAMES = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",80:"HTTP",443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",5900:"VNC",6379:"Redis",8080:"HTTP-Alt",27017:"MongoDB"}
SEV_SCORE = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}

@dataclass
class CVEFinding:
    cve_id:str; severity:str; description:str; cvss_score:float; port:int; service:str; remediation:str=""
    def to_dict(self): return {"cve_id":self.cve_id,"severity":self.severity,"description":self.description,"cvss_score":self.cvss_score,"port":self.port,"service":self.service,"remediation":self.remediation}

@dataclass
class VulnScanResult:
    ip:str; hostname:str; timestamp:float; findings:list=field(default_factory=list); scan_duration:float=0.0; ports_scanned:list=field(default_factory=list); risk_score:int=0; risk_level:str="LOW"
    def to_dict(self):
        return {"ip":self.ip,"hostname":self.hostname,"timestamp":self.timestamp,"datetime":datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),"findings":[f.to_dict() for f in self.findings],"finding_count":len(self.findings),"critical_count":sum(1 for f in self.findings if f.severity=="CRITICAL"),"high_count":sum(1 for f in self.findings if f.severity=="HIGH"),"scan_duration":round(self.scan_duration,2),"ports_scanned":self.ports_scanned,"risk_score":self.risk_score,"risk_level":self.risk_level}

class VulnerabilityScanner:
    def __init__(self):
        self._results=[]; self._scanning=False; self._lock=threading.Lock()

    def scan_device(self, ip, open_ports, hostname=""):
        start=time.time(); findings=[]
        for p in open_ports:
            port=p.get("port",0); svc=SERVICE_NAMES.get(port,p.get("service","unknown"))
            for cve_id,sev,desc,score in LOCAL_CVE_DB.get(port,[]):
                findings.append(CVEFinding(cve_id=cve_id,severity=sev,description=desc,cvss_score=score,port=port,service=svc,remediation=REMEDIATION.get(port,"Update and patch.")))
        findings.sort(key=lambda f:SEV_SCORE.get(f.severity,0),reverse=True)
        score=min(100,sum({"CRITICAL":30,"HIGH":20,"MEDIUM":10,"LOW":5}.get(f.severity,0) for f in findings))
        rl="CRITICAL" if score>=75 else "HIGH" if score>=50 else "MEDIUM" if score>=25 else "LOW"
        r=VulnScanResult(ip=ip,hostname=hostname,timestamp=time.time(),findings=findings,scan_duration=time.time()-start,ports_scanned=[p.get("port",0) for p in open_ports],risk_score=score,risk_level=rl)
        with self._lock:
            self._results=[x for x in self._results if x.ip!=ip]
            self._results.append(r)
        return r

    def scan_all(self, devices, callback=None):
        self._scanning=True; results=[]
        for d in devices:
            try:
                r=self.scan_device(d.get("ip",""),d.get("open_ports",[]),d.get("hostname",""))
                results.append(r)
                if callback: callback(r.to_dict())
            except Exception as e: logger.error(f"Scan error {d.get(\'ip\')}: {e}")
        self._scanning=False; return results

    def get_results(self,n=50):
        with self._lock: return [r.to_dict() for r in self._results[-n:]]

    def get_critical(self):
        out=[]
        with self._lock:
            for r in self._results:
                for f in r.findings:
                    if f.severity=="CRITICAL": out.append({"ip":r.ip,"hostname":r.hostname,**f.to_dict()})
        return sorted(out,key=lambda x:x["cvss_score"],reverse=True)

    def get_stats(self):
        with self._lock:
            return {"hosts_scanned":len(self._results),"critical_hosts":sum(1 for r in self._results if r.risk_level=="CRITICAL"),"total_cves":sum(len(r.findings) for r in self._results),"scanning":self._scanning}
''')
print("core/vuln_scanner.py written")

# ── honeypot.py ──────────────────────────────────────────────
open("core/honeypot.py","w",encoding="utf-8").write('''
import time, socket, logging, threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from collections import deque
logger = logging.getLogger(__name__)

@dataclass
class HoneypotEvent:
    timestamp:float; service:str; port:int; src_ip:str; src_port:int; payload:str=""; credentials:dict=field(default_factory=dict); event_type:str="connection"
    def to_dict(self): return {"timestamp":self.timestamp,"datetime":datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),"service":self.service,"port":self.port,"src_ip":self.src_ip,"src_port":self.src_port,"payload":self.payload[:200],"credentials":self.credentials,"event_type":self.event_type}

class BaseHoneypot:
    def __init__(self,port,name,callback=None):
        self.port=port; self.service_name=name; self._callback=callback
        self._running=False; self._server=None; self._events=deque(maxlen=1000); self._connections=0
    def start(self):
        try:
            self._server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            self._server.bind(("0.0.0.0",self.port)); self._server.listen(10); self._server.settimeout(1.0)
            self._running=True; threading.Thread(target=self._loop,daemon=True).start(); return True
        except OSError as e: logger.warning(f"Cannot start {self.service_name} on {self.port}: {e}"); return False
    def stop(self):
        self._running=False
        if self._server:
            try: self._server.close()
            except: pass
    def _loop(self):
        while self._running:
            try:
                conn,addr=self._server.accept(); self._connections+=1
                threading.Thread(target=self._handle,args=(conn,addr),daemon=True).start()
            except socket.timeout: continue
            except: break
    def _handle(self,conn,addr):
        self._log(HoneypotEvent(timestamp=time.time(),service=self.service_name,port=self.port,src_ip=addr[0],src_port=addr[1]))
        try: conn.close()
        except: pass
    def _log(self,event):
        self._events.append(event)
        if self._callback:
            try: self._callback(event)
            except Exception as e: logger.error(f"HP callback: {e}")
    def get_events(self): return [e.to_dict() for e in self._events]
    @property
    def is_running(self): return self._running

class SSHHoneypot(BaseHoneypot):
    def __init__(self,port=2222,callback=None): super().__init__(port,"SSH",callback)
    def _handle(self,conn,addr):
        self._log(HoneypotEvent(timestamp=time.time(),service="SSH",port=self.port,src_ip=addr[0],src_port=addr[1],event_type="connection"))
        try:
            conn.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"); conn.settimeout(10)
            data=conn.recv(1024)
            if data: self._log(HoneypotEvent(timestamp=time.time(),service="SSH",port=self.port,src_ip=addr[0],src_port=addr[1],payload=data.decode(errors="replace"),event_type="auth_attempt"))
        except: pass
        finally:
            try: conn.close()
            except: pass

class FTPHoneypot(BaseHoneypot):
    def __init__(self,port=2121,callback=None): super().__init__(port,"FTP",callback)
    def _handle(self,conn,addr):
        self._log(HoneypotEvent(timestamp=time.time(),service="FTP",port=self.port,src_ip=addr[0],src_port=addr[1],event_type="connection"))
        try:
            conn.send(b"220 FTP Server Ready\r\n"); conn.settimeout(15); username=""
            while True:
                data=conn.recv(1024)
                if not data: break
                cmd=data.decode(errors="replace").strip()
                if cmd.upper().startswith("USER"): username=cmd[5:].strip(); conn.send(b"331 Password required\r\n")
                elif cmd.upper().startswith("PASS"):
                    pwd=cmd[5:].strip()
                    self._log(HoneypotEvent(timestamp=time.time(),service="FTP",port=self.port,src_ip=addr[0],src_port=addr[1],payload=f"USER:{username} PASS:{pwd}",credentials={"username":username,"password":pwd},event_type="auth_attempt"))
                    conn.send(b"530 Login incorrect\r\n"); break
                elif cmd.upper()=="QUIT": conn.send(b"221 Goodbye\r\n"); break
                else: conn.send(b"500 Unknown command\r\n")
        except: pass
        finally:
            try: conn.close()
            except: pass

class HTTPHoneypot(BaseHoneypot):
    def __init__(self,port=8888,callback=None): super().__init__(port,"HTTP",callback)
    def _handle(self,conn,addr):
        self._log(HoneypotEvent(timestamp=time.time(),service="HTTP",port=self.port,src_ip=addr[0],src_port=addr[1],event_type="connection"))
        try:
            conn.settimeout(10); data=conn.recv(4096)
            if data:
                lines=data.decode(errors="replace").split("\r\n")
                self._log(HoneypotEvent(timestamp=time.time(),service="HTTP",port=self.port,src_ip=addr[0],src_port=addr[1],payload=lines[0] if lines else "",event_type="data_received"))
                conn.send(b"HTTP/1.1 403 Forbidden\r\nServer: Apache/2.4.51\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><h1>403 Forbidden</h1></body></html>")
        except: pass
        finally:
            try: conn.close()
            except: pass

class TelnetHoneypot(BaseHoneypot):
    def __init__(self,port=2323,callback=None): super().__init__(port,"Telnet",callback)
    def _handle(self,conn,addr):
        self._log(HoneypotEvent(timestamp=time.time(),service="Telnet",port=self.port,src_ip=addr[0],src_port=addr[1],event_type="connection"))
        try:
            conn.send(b"\r\nUbuntu 22.04 LTS\r\nlogin: "); conn.settimeout(15)
            u=conn.recv(256)
            if u:
                conn.send(b"\r\nPassword: "); p=conn.recv(256)
                if p:
                    self._log(HoneypotEvent(timestamp=time.time(),service="Telnet",port=self.port,src_ip=addr[0],src_port=addr[1],credentials={"username":u.strip().decode(errors="replace"),"password":p.strip().decode(errors="replace")},event_type="auth_attempt"))
                    conn.send(b"\r\nLogin incorrect\r\n")
        except: pass
        finally:
            try: conn.close()
            except: pass

class HoneypotManager:
    DEFAULT_PORTS={"SSH":2222,"FTP":2121,"HTTP":8888,"Telnet":2323}
    def __init__(self,callback=None):
        self._callback=callback; self._pots={}; self._all=deque(maxlen=5000)
        self._stats={"total_connections":0,"auth_attempts":0,"unique_ips":set()}; self._lock=threading.Lock()
    def _on_event(self,event):
        with self._lock:
            self._all.append(event); self._stats["total_connections"]+=1; self._stats["unique_ips"].add(event.src_ip)
            if event.event_type=="auth_attempt": self._stats["auth_attempts"]+=1
        if self._callback:
            try: self._callback(event)
            except Exception as e: logger.error(f"HP mgr cb: {e}")
    def start_all(self):
        classes={"SSH":(SSHHoneypot,2222),"FTP":(FTPHoneypot,2121),"HTTP":(HTTPHoneypot,8888),"Telnet":(TelnetHoneypot,2323)}
        results={}
        for name,(cls,port) in classes.items():
            hp=cls(port=port,callback=self._on_event); ok=hp.start(); self._pots[name]=hp; results[name]={"port":port,"running":ok}
        return results
    def start_service(self,service,port=None):
        classes={"SSH":SSHHoneypot,"FTP":FTPHoneypot,"HTTP":HTTPHoneypot,"Telnet":TelnetHoneypot}
        cls=classes.get(service)
        if not cls: return False
        p=port or self.DEFAULT_PORTS.get(service,9999); hp=cls(port=p,callback=self._on_event); ok=hp.start()
        if ok: self._pots[service]=hp
        return ok
    def stop_service(self,service):
        hp=self._pots.get(service)
        if hp: hp.stop(); del self._pots[service]
    def stop_all(self):
        for hp in self._pots.values(): hp.stop()
        self._pots.clear()
    def get_status(self):
        s={}
        for name,hp in self._pots.items(): s[name]={"running":hp.is_running,"port":hp.port,"events":len(hp.get_events())}
        for name,port in self.DEFAULT_PORTS.items():
            if name not in s: s[name]={"running":False,"port":port,"events":0}
        return s
    def get_events(self,n=100,service=None):
        with self._lock: events=list(self._all)
        if service: events=[e for e in events if e.service==service]
        return [e.to_dict() for e in events[-n:]]
    def get_stats(self):
        with self._lock: return {"total_connections":self._stats["total_connections"],"auth_attempts":self._stats["auth_attempts"],"unique_attackers":len(self._stats["unique_ips"]),"active_services":sum(1 for hp in self._pots.values() if hp.is_running)}
''')
print("core/honeypot.py written")

# ── timeline.py ──────────────────────────────────────────────
open("core/timeline.py","w",encoding="utf-8").write('''
import time, logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
logger = logging.getLogger(__name__)

KILL_CHAIN = ["Reconnaissance","Resource Development","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact"]
CAT_TO_STAGE = {"Port Scan":"Reconnaissance","Network Scan":"Reconnaissance","DNS Tunneling":"Command and Control","Beaconing / C2":"Command and Control","SYN Flood":"Impact","ICMP Flood":"Impact","Brute Force":"Credential Access","Suspicious Payload":"Execution","Malformed Packet":"Defense Evasion","ARP Spoofing":"Lateral Movement","Data Exfiltration":"Exfiltration","Anomalous Traffic":"Discovery","Blacklisted IP":"Command and Control"}
SEV_SCORE={"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}

@dataclass
class TimelineEntry:
    timestamp:float; event_id:str; src_ip:str; dst_ip:str; category:str; severity:str; stage:str; campaign_id:Optional[str]; description:str
    def to_dict(self):
        return {"timestamp":self.timestamp,"datetime":datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),"event_id":self.event_id,"src_ip":self.src_ip,"dst_ip":self.dst_ip,"category":self.category,"severity":self.severity,"stage":self.stage,"stage_index":KILL_CHAIN.index(self.stage) if self.stage in KILL_CHAIN else -1,"campaign_id":self.campaign_id,"description":self.description}

@dataclass
class Campaign:
    campaign_id:str; src_ip:str; start_time:float; end_time:float; events:list=field(default_factory=list); stages_hit:list=field(default_factory=list); severity:str="LOW"; confidence:float=0.5; description:str=""
    def to_dict(self):
        return {"campaign_id":self.campaign_id,"src_ip":self.src_ip,"start_time":self.start_time,"end_time":self.end_time,"start_datetime":datetime.fromtimestamp(self.start_time).strftime("%Y-%m-%d %H:%M:%S"),"end_datetime":datetime.fromtimestamp(self.end_time).strftime("%Y-%m-%d %H:%M:%S"),"duration_secs":round(self.end_time-self.start_time,1),"event_count":len(self.events),"stages_hit":self.stages_hit,"stage_count":len(self.stages_hit),"severity":self.severity,"confidence":round(self.confidence,2),"description":self.description}

class TimelineEngine:
    def __init__(self,window=300):
        self.window=window; self._timeline=deque(maxlen=2000); self._campaigns={}
        self._ip_last={}; self._ip_camp={}; self._counter=0
        self._stage_counts=defaultdict(int); self._hourly=defaultdict(int)

    def ingest(self, event):
        src=event.get("src_ip","?"); cat=event.get("category","Unknown"); sev=event.get("severity","LOW"); ts=event.get("timestamp",time.time())
        stage=CAT_TO_STAGE.get(cat,"Discovery"); self._stage_counts[stage]+=1
        self._hourly[int(ts//3600)]+=1
        camp_id=self._correlate(src,event,stage,ts)
        entry=TimelineEntry(timestamp=ts,event_id=event.get("id",""),src_ip=src,dst_ip=event.get("dst_ip",""),category=cat,severity=sev,stage=stage,campaign_id=camp_id,description=event.get("description",""))
        self._timeline.append(entry); return entry

    def _correlate(self,src,event,stage,ts):
        last=self._ip_last.get(src,0); self._ip_last[src]=ts
        if src in self._ip_camp and ts-last<=self.window:
            cid=self._ip_camp[src]
            if cid in self._campaigns:
                c=self._campaigns[cid]; c.end_time=ts; c.events.append(event.get("id",""))
                if stage not in c.stages_hit: c.stages_hit.append(stage)
                if SEV_SCORE.get(event.get("severity"),0)>SEV_SCORE.get(c.severity,0): c.severity=event.get("severity",c.severity)
                c.confidence=min(0.99,0.5+len(c.stages_hit)*0.1)
                c.description=f"{'Advanced multi-stage' if len(c.stages_hit)>=4 else 'Multi-stage'} attack from {src} — {len(c.stages_hit)} stages"
        else:
            self._counter+=1; cid=f"CAMP-{self._counter:04d}"; self._ip_camp[src]=cid
            self._campaigns[cid]=Campaign(campaign_id=cid,src_ip=src,start_time=ts,end_time=ts,events=[event.get("id","")],stages_hit=[stage],severity=event.get("severity","LOW"),confidence=0.5,description=f"Attack from {src}")
        return self._ip_camp[src]

    def get_timeline(self,limit=200,src_ip=None,stage=None,severity=None,hours=None):
        entries=list(self._timeline)
        if hours: cutoff=time.time()-hours*3600; entries=[e for e in entries if e.timestamp>=cutoff]
        if src_ip: entries=[e for e in entries if e.src_ip==src_ip]
        if stage: entries=[e for e in entries if e.stage==stage]
        if severity: entries=[e for e in entries if e.severity==severity]
        return [e.to_dict() for e in entries[-limit:]]

    def get_campaigns(self,active_only=False):
        camps=list(self._campaigns.values())
        if active_only:
            cutoff=time.time()-self.window; camps=[c for c in camps if c.end_time>=cutoff]
        return [c.to_dict() for c in sorted(camps,key=lambda c:c.end_time,reverse=True)]

    def get_kill_chain(self):
        return [{"stage":s,"index":i,"count":self._stage_counts.get(s,0),"active":self._stage_counts.get(s,0)>0} for i,s in enumerate(KILL_CHAIN)]

    def get_heatmap(self,hours=24):
        now=int(time.time()//3600)
        return [{"hour":now-(hours-1-i),"hour_label":datetime.fromtimestamp((now-(hours-1-i))*3600).strftime("%H:00"),"count":self._hourly.get(now-(hours-1-i),0)} for i in range(hours)]

    def get_stats(self):
        active=sum(1 for c in self._campaigns.values() if time.time()-c.end_time<=self.window)
        return {"total_events":len(self._timeline),"total_campaigns":len(self._campaigns),"active_campaigns":active,"stages_hit":dict(self._stage_counts),"top_stage":max(self._stage_counts,key=self._stage_counts.get) if self._stage_counts else None}
''')
print("core/timeline.py written")

print("\nAll 5 core modules written successfully!")
print("Next: run python install_phase3_server.py to update dashboard_server.py")