
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
            except Exception as e: logger.error(f"Scan error {d.get('ip')}: {e}")
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
