
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
            lines.append(f"Packets: {stats.get('total_packets',0):,} | Flows: {stats.get('active_flows',0)} | PPS: {stats.get('packets_per_second',0)} | Interface: {stats.get('interface','?')} | ML: {'Trained' if stats.get('ml_trained') else 'Training'}")
        events = ctx.get("events", [])
        if events:
            sev = {}
            for e in events: sev[e.get("severity","LOW")] = sev.get(e.get("severity","LOW"),0)+1
            lines.append(f"\n## THREATS ({len(events)} total) | {sev}")
            for e in events[:10]:
                lines.append(f"- [{e.get('severity')}] {e.get('category')} | {e.get('src_ip')}:{e.get('src_port')} -> {e.get('dst_ip')}:{e.get('dst_port')} | {e.get('description','')[:80]}")
        blocked = [b for b in ctx.get("blocked_ips",[]) if b.get("active")]
        if blocked:
            lines.append(f"\n## BLOCKED IPs ({len(blocked)})")
            for b in blocked[:5]: lines.append(f"- {b.get('ip')} | {b.get('reason')}")
        malware = [m for m in ctx.get("malware",[]) if m.get("is_malicious")]
        if malware:
            lines.append(f"\n## MALWARE ({len(malware)})")
            for m in malware[:5]: lines.append(f"- {m.get('target')} | {m.get('threat_name')} | {m.get('severity')}")
        return "\n".join(lines)

    def chat(self, message):
        ctx_block = self._build_context()
        full_msg = f"{message}\n\n---\nCURRENT NETWORK CONTEXT:\n{ctx_block}"
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
            return f"## Security Summary\n\nThreats: {len(events)} total | {len(critical)} CRITICAL | {len(high)} HIGH\n\n" + ("\n".join([f"- [{e.get('severity')}] {e.get('category')}: {e.get('src_ip')} -> {e.get('dst_ip')}" for e in (critical+high)[:5]]) or "No active threats") + "\n\n*Enable internet access for full Claude AI analysis.*"
        elif any(w in msg for w in ["critical","urgent","worst"]):
            if critical:
                e = critical[0]
                return f"## Most Critical Threat\n\n**{e.get('category')}** from `{e.get('src_ip')}`\n- Destination: {e.get('dst_ip')}:{e.get('dst_port')}\n- Confidence: {round(e.get('confidence',0)*100)}%\n- {e.get('description')}\n\n**Action:** Block {e.get('src_ip')} immediately in the IP Blocker tab."
            return "No CRITICAL threats detected. System stable."
        elif any(w in msg for w in ["block","stop","fix","prevent"]):
            return "## Recommendations\n\n1. Use **IP Blocker** tab to block malicious IPs\n2. Enable **Auto-Block** for HIGH+ severity\n3. Check **Threat Intel** to verify IPs on VirusTotal\n4. Review **Dark Web** tab for breach matches\n5. Download **PDF Report** for documentation"
        return "I can help analyze your network security. Try:\n- *Give me a security summary*\n- *What are my critical threats?*\n- *How do I respond to a SYN flood?*\n- *Which IPs should I block?*\n\n*(Connect to internet for full Claude AI responses)*"

    def get_quick_prompts(self):
        return ["Give me a security posture summary","What are my most critical threats?","Which IPs should I block immediately?","Explain the most recent attack","What patterns do you see in the threats?","Generate an executive summary","How do I respond to a SYN flood?","What does the MITRE data tell us?"]

    def clear_history(self): self._history = []

    def get_chat_log(self, n=50): return list(self._chat_log)[-n:]
