
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
