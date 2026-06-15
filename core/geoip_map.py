
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
