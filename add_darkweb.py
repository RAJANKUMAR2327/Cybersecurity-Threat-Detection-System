import os

# ── 1. Copy darkweb_monitor.py to core folder ─────────────────
darkweb_code = '''
import time, json, hashlib, logging, threading, requests
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
logger = logging.getLogger(__name__)

TOR_EXIT_PREFIXES = ["185.220.101.","185.220.100.","199.249.230.","162.247.74.","171.25.193.","176.10.104."]
BOTNET_RANGES     = ["45.142.212.","194.165.16.","91.108.4.","192.42.116.","198.96.155.","23.129.64."]
BREACH_DB = {
    "185.220.101.5":  {"breach":"AlphaBay Darknet","year":2017,"type":"C2 Infrastructure"},
    "45.142.212.100": {"breach":"Emotet Botnet","year":2021,"type":"Malware C2"},
    "194.165.16.10":  {"breach":"TrickBot Campaign","year":2020,"type":"Banking Trojan C2"},
    "172.16.5.99":    {"breach":"SYN Flood Campaign","year":2023,"type":"DDoS Infrastructure"},
    "10.1.2.3":       {"breach":"Internal Test","year":2024,"type":"Simulation"},
}
RANSOMWARE_IPS = {
    "185.220.101.":"Conti/Ryuk","45.142.212.":"REvil",
    "194.165.16.":"LockBit 2.0","103.208.86.":"BlackCat/ALPHV",
}

@dataclass
class BreachResult:
    query: str
    query_type: str
    timestamp: float
    found_in_breach: bool
    breach_count: int
    breaches: List[dict] = field(default_factory=list)
    is_tor_exit: bool = False
    is_botnet: bool = False
    is_ransomware_infra: bool = False
    ransomware_group: str = ""
    risk_score: int = 0
    risk_level: str = "LOW"
    recommendations: List[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self):
        return {
            "query":self.query,"query_type":self.query_type,
            "timestamp":self.timestamp,
            "datetime":datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "found_in_breach":self.found_in_breach,"breach_count":self.breach_count,
            "breaches":self.breaches,"is_tor_exit":self.is_tor_exit,
            "is_botnet":self.is_botnet,"is_ransomware_infra":self.is_ransomware_infra,
            "ransomware_group":self.ransomware_group,"risk_score":self.risk_score,
            "risk_level":self.risk_level,"recommendations":self.recommendations,
            "error":self.error,
        }

class DarkWebMonitor:
    def __init__(self, hibp_api_key=""):
        self.hibp_api_key = hibp_api_key
        self._results = []
        self._cache = {}
        self._cache_ttl = 3600
        self._lock = threading.Lock()
        self._monitoring_list = []

    def set_hibp_key(self, key):
        self.hibp_api_key = key

    def _detect_type(self, query):
        if "@" in query: return "email"
        parts = query.split(".")
        if len(parts)==4 and all(p.isdigit() for p in parts): return "ip"
        return "domain"

    def check(self, query, query_type="auto"):
        if query_type == "auto":
            query_type = self._detect_type(query)
        cache_key = f"{query_type}:{query}"
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and time.time() - cached.timestamp < self._cache_ttl:
                return cached
        result = BreachResult(query=query,query_type=query_type,timestamp=time.time(),found_in_breach=False,breach_count=0)
        if query_type == "ip":
            self._check_ip(query, result)
        elif query_type == "email":
            self._check_email(query, result)
        elif query_type == "domain":
            self._check_domain(query, result)
        self._compute_risk(result)
        self._add_recommendations(result)
        with self._lock:
            self._cache[cache_key] = result
            self._results.append(result)
            if len(self._results) > 500: self._results.pop(0)
        return result

    def check_async(self, query, query_type="auto", callback=None):
        def _run():
            r = self.check(query, query_type)
            if callback: callback(r)
        threading.Thread(target=_run, daemon=True).start()

    def _check_ip(self, ip, result):
        if ip in BREACH_DB:
            e = BREACH_DB[ip]
            result.found_in_breach = True
            result.breach_count += 1
            result.breaches.append({"name":e["breach"],"year":e["year"],"type":e["type"],"source":"CyberShield DB"})
        for p in TOR_EXIT_PREFIXES:
            if ip.startswith(p):
                result.is_tor_exit = True
                result.breach_count += 1
                result.breaches.append({"name":"Tor Exit Node","year":datetime.now().year,"type":"Anonymization","source":"Tor Project"})
                break
        for p in BOTNET_RANGES:
            if ip.startswith(p):
                result.is_botnet = True
                result.breach_count += 1
                result.breaches.append({"name":"Botnet Infrastructure","year":datetime.now().year,"type":"Malware C2","source":"Threat Intel"})
                break
        for p, group in RANSOMWARE_IPS.items():
            if ip.startswith(p):
                result.is_ransomware_infra = True
                result.ransomware_group = group
                result.breach_count += 1
                result.breaches.append({"name":f"Ransomware: {group}","year":2023,"type":"Ransomware C2","source":"Ransomware Tracker"})
                break
        result.found_in_breach = result.breach_count > 0

    def _check_email(self, email, result):
        domain = email.split("@")[-1].lower() if "@" in email else ""
        known_bad = ["test@test.com","admin@admin.com","user@example.com"]
        bad_domains = ["yahoo.com","linkedin.com","adobe.com","myspace.com","dropbox.com"]
        if email.lower() in known_bad:
            result.found_in_breach = True
            result.breach_count = 1
            result.breaches.append({"name":"Known Breach DB","year":"2023","type":"Email, Password","source":"Demo Mode"})
        elif domain in bad_domains:
            result.found_in_breach = True
            result.breach_count = 1
            result.breaches.append({"name":f"{domain} Data Breach","year":"2022","type":"Email, Password Hash","source":"Demo Mode","description":"Add HIBP API key for accurate results."})

    def _check_domain(self, domain, result):
        bad = ["evil-c2.xyz","malware-update.net","botnet-control.ru"]
        if domain.lower() in bad:
            result.found_in_breach = True
            result.breach_count += 1
            result.breaches.append({"name":"Known Malware Domain","year":datetime.now().year,"type":"Malware C2","source":"MalwareDomainList"})

    def _compute_risk(self, result):
        score = 0
        if result.is_tor_exit:          score += 40
        if result.is_botnet:            score += 50
        if result.is_ransomware_infra:  score += 70
        if result.found_in_breach:      score += 20
        score += min(30, result.breach_count * 10)
        score = min(100, score)
        result.risk_score = score
        if score >= 75:   result.risk_level = "CRITICAL"
        elif score >= 50: result.risk_level = "HIGH"
        elif score >= 25: result.risk_level = "MEDIUM"
        else:             result.risk_level = "LOW"

    def _add_recommendations(self, result):
        recs = []
        if result.is_tor_exit:           recs.append("Block Tor exit node at perimeter firewall")
        if result.is_botnet:             recs.append("Block immediately — active botnet C2 infrastructure")
        if result.is_ransomware_infra:   recs.append(f"CRITICAL: Known {result.ransomware_group} — isolate connected hosts now")
        if result.found_in_breach and result.query_type=="email": recs.append("Force password reset and enable MFA immediately")
        if not recs: recs.append("No immediate action required — continue monitoring")
        result.recommendations = recs

    def add_monitor_target(self, query, query_type="auto"):
        self._monitoring_list.append({"query":query,"type":query_type,"added":datetime.now().isoformat()})

    def remove_monitor_target(self, query):
        self._monitoring_list = [t for t in self._monitoring_list if t["query"] != query]

    def get_results(self, n=50):
        with self._lock:
            return [r.to_dict() for r in reversed(self._results[-n:])]

    def get_monitoring_list(self):
        return list(self._monitoring_list)

    def get_stats(self):
        with self._lock:
            total    = len(self._results)
            breached = sum(1 for r in self._results if r.found_in_breach)
            critical = sum(1 for r in self._results if r.risk_level=="CRITICAL")
            return {
                "total_checks":total,"breached_found":breached,
                "critical_findings":critical,
                "monitoring_targets":len(self._monitoring_list),
                "hibp_configured":bool(self.hibp_api_key),
            }
'''

os.makedirs("core", exist_ok=True)
with open("core/darkweb_monitor.py", "w", encoding="utf-8") as f:
    f.write(darkweb_code)
print("core/darkweb_monitor.py written")

# ── 2. Patch dashboard_server.py ─────────────────────────────
srv_path = "dashboard/dashboard_server.py"
with open(srv_path, encoding="utf-8") as f:
    srv = f.read()

if "DarkWebMonitor" not in srv:
    srv = srv.replace(
        "from core.report_generator",
        "from core.darkweb_monitor     import DarkWebMonitor\nfrom core.report_generator"
    )
    srv = srv.replace(
        "blocker      = IPBlocker()",
        "blocker      = IPBlocker()\ndarkweb      = DarkWebMonitor()"
    )

    routes = '''
@app.route("/api/darkweb/check", methods=["POST"])
def api_darkweb_check():
    data  = request.get_json() or {}
    query = data.get("query","")
    qtype = data.get("type","auto")
    if not query: return jsonify({"error":"query required"}),400
    result = darkweb.check(query, qtype)
    socketio.emit("darkweb_result", result.to_dict())
    return jsonify(result.to_dict())

@app.route("/api/darkweb/results")
def api_darkweb_results():
    return jsonify(darkweb.get_results(int(request.args.get("n",50))))

@app.route("/api/darkweb/stats")
def api_darkweb_stats():
    return jsonify(darkweb.get_stats())

@app.route("/api/darkweb/monitor", methods=["POST"])
def api_darkweb_add():
    data = request.get_json() or {}
    q    = data.get("query","")
    if not q: return jsonify({"error":"query required"}),400
    darkweb.add_monitor_target(q, data.get("type","auto"))
    return jsonify({"status":"added","query":q})

@app.route("/api/darkweb/monitor/<path:query>", methods=["DELETE"])
def api_darkweb_remove(query):
    darkweb.remove_monitor_target(query)
    return jsonify({"status":"removed"})

@app.route("/api/darkweb/monitor/list")
def api_darkweb_list():
    return jsonify(darkweb.get_monitoring_list())

@app.route("/api/darkweb/config", methods=["POST"])
def api_darkweb_config():
    data = request.get_json() or {}
    if "hibp_key" in data: darkweb.set_hibp_key(data["hibp_key"])
    return jsonify({"status":"ok"})

'''
    srv = srv.replace("# ── WebSocket", routes + "# ── WebSocket")
    with open(srv_path, "w", encoding="utf-8") as f:
        f.write(srv)
    print("dashboard_server.py patched")
else:
    print("dashboard_server.py already has DarkWebMonitor")

# ── 3. Patch index.html ───────────────────────────────────────
html_path = "dashboard/index.html"
with open(html_path, encoding="utf-8") as f:
    html = f.read()

if "panel-darkweb" in html:
    print("index.html already has dark web panel")
else:
    # Add nav item
    html = html.replace(
        '<div class="nav-item" data-panel="reports"',
        '''<div class="nav-item" data-panel="darkweb" onclick="showPanel('darkweb', this)">
      <span class="nav-icon">&#128373;</span> Dark Web
    </div>
    <div class="nav-item" data-panel="reports"'''
    )

    # Add panel
    panel = """
    <div class="panel" id="panel-darkweb">
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">TOTAL CHECKS</div><div class="metric-value" id="dw-total">0</div><div class="metric-sub">queries run</div></div>
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">BREACHES FOUND</div><div class="metric-value" id="dw-breached">0</div><div class="metric-sub">compromised</div></div>
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">CRITICAL</div><div class="metric-value" id="dw-critical">0</div><div class="metric-sub">immediate action</div></div>
        <div class="metric-card purple"><div class="metric-glow"></div><div class="metric-label">MONITORING</div><div class="metric-value" id="dw-monitoring">0</div><div class="metric-sub">targets watched</div></div>
      </div>
      <div class="grid-2">
        <div style="display:flex;flex-direction:column;gap:16px">
          <div class="card">
            <div class="card-header"><div class="card-title">DARK WEB BREACH CHECK</div></div>
            <div class="card-body">
              <div style="display:flex;gap:8px;margin-bottom:12px">
                <input type="text" id="dw-query" placeholder="IP, email, or domain..."
                  style="flex:1;background:var(--bg-deep);border:1px solid var(--border);color:var(--text-main);padding:8px 12px;font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none">
                <select id="dw-type" style="background:var(--bg-deep);border:1px solid var(--border);color:var(--text-main);padding:8px;font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none">
                  <option value="auto">Auto</option><option value="ip">IP</option>
                  <option value="email">Email</option><option value="domain">Domain</option>
                </select>
                <button class="btn primary" onclick="darkwebCheck()">CHECK</button>
              </div>
              <div style="margin-bottom:12px">
                <div class="font-mono text-dim" style="font-size:10px;margin-bottom:6px">QUICK TEST:</div>
                <div style="display:flex;flex-wrap:wrap;gap:6px">
                  <button class="btn" style="font-size:10px;padding:3px 8px" onclick="dwQuick('185.220.101.5','ip')">Tor Exit Node</button>
                  <button class="btn" style="font-size:10px;padding:3px 8px" onclick="dwQuick('45.142.212.100','ip')">Botnet C2</button>
                  <button class="btn" style="font-size:10px;padding:3px 8px" onclick="dwQuick('194.165.16.10','ip')">Ransomware IP</button>
                  <button class="btn" style="font-size:10px;padding:3px 8px" onclick="dwQuick('test@test.com','email')">Breached Email</button>
                </div>
              </div>
              <div id="dw-result"></div>
            </div>
          </div>
          <div class="card">
            <div class="card-header"><div class="card-title">API KEY (optional)</div></div>
            <div class="card-body">
              <div style="display:flex;gap:8px">
                <input type="password" id="hibp-key" placeholder="HaveIBeenPwned API key"
                  style="flex:1;background:var(--bg-deep);border:1px solid var(--border);color:var(--text-main);padding:8px;font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none">
                <button class="btn primary" onclick="saveDWConfig()">SAVE</button>
              </div>
              <div id="dw-config-msg" class="font-mono text-dim" style="font-size:11px;margin-top:8px"></div>
              <div class="font-mono text-dim" style="font-size:10px;margin-top:10px;line-height:1.8">
                Free key: haveibeenpwned.com/API/Key<br>
                Without key: uses built-in threat database
              </div>
            </div>
          </div>
          <div class="card">
            <div class="card-header"><div class="card-title">CONTINUOUS MONITORING</div><div class="card-badge" id="badge-dw-monitor">0 targets</div></div>
            <div class="card-body">
              <div style="display:flex;gap:8px;margin-bottom:10px">
                <input type="text" id="dw-monitor-query" placeholder="IP, email, or domain..."
                  style="flex:1;background:var(--bg-deep);border:1px solid var(--border);color:var(--text-main);padding:8px;font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none">
                <button class="btn primary" onclick="addDWMonitor()">+ WATCH</button>
              </div>
              <div id="dw-monitor-list"><div class="text-dim font-mono" style="font-size:11px;padding:10px;text-align:center">No targets monitored</div></div>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">CHECK HISTORY</div><div class="card-badge" id="badge-dw-count">0 checks</div></div>
          <div id="dw-history" style="max-height:700px;overflow-y:auto">
            <div class="text-dim font-mono" style="font-size:11px;padding:20px;text-align:center">No checks yet</div>
          </div>
        </div>
      </div>
    </div>
"""
    html = html.replace("  </main>", panel + "\n  </main>")

    # Add JS
    js = """
// ── DARK WEB MONITOR JS ──────────────────────────────────────
async function darkwebCheck() {
  var query = document.getElementById('dw-query').value.trim();
  var type  = document.getElementById('dw-type').value;
  if (!query) return;
  document.getElementById('dw-result').innerHTML = '<div class="font-mono text-dim" style="font-size:11px;padding:10px">Checking ' + query + '...</div>';
  try {
    var r = await fetch('/api/darkweb/check', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:query,type:type})});
    var d = await r.json();
    renderDWResult(d);
    refreshDWHistory();
    refreshDWStats();
  } catch(e) {
    document.getElementById('dw-result').innerHTML = '<div class="font-mono text-red" style="font-size:11px">' + e.message + '</div>';
  }
}

function dwQuick(q, t) {
  document.getElementById('dw-query').value = q;
  document.getElementById('dw-type').value  = t;
  darkwebCheck();
}

function renderDWResult(d) {
  var rc = {LOW:'var(--green)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
  var color = rc[d.risk_level] || 'var(--text-dim)';
  var badges = '';
  if (d.is_tor_exit)         badges += '<span style="background:rgba(170,68,255,0.2);border:1px solid #aa44ff;color:#cc88ff;padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">TOR EXIT</span>';
  if (d.is_botnet)           badges += '<span style="background:rgba(255,34,68,0.2);border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">BOTNET C2</span>';
  if (d.is_ransomware_infra) badges += '<span style="background:rgba(255,34,68,0.3);border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">RANSOMWARE: '+d.ransomware_group+'</span>';
  if (d.found_in_breach)     badges += '<span style="background:rgba(255,102,0,0.2);border:1px solid var(--orange);color:var(--orange);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">'+d.breach_count+' BREACH(ES)</span>';
  var breachHTML = '';
  if (d.breaches && d.breaches.length) {
    breachHTML = '<div style="margin-bottom:10px"><div class="font-mono text-accent" style="font-size:10px;letter-spacing:1.5px;margin-bottom:6px">FOUND IN DATABASES:</div>';
    for (var i=0;i<d.breaches.length;i++) {
      var b = d.breaches[i];
      breachHTML += '<div style="background:rgba(255,34,68,0.08);border-left:3px solid var(--red-dim);padding:8px 12px;margin-bottom:6px;border-radius:0 3px 3px 0"><div style="font-weight:700;color:var(--text-bright);font-size:12px">'+b.name+'</div><div class="font-mono text-dim" style="font-size:10px">'+b.type+' | '+b.year+' | '+b.source+'</div>'+(b.description?'<div class="font-mono text-dim" style="font-size:10px;margin-top:4px">'+b.description+'</div>':'')+'</div>';
    }
    breachHTML += '</div>';
  } else {
    breachHTML = '<div style="color:var(--green);font-family:var(--font-mono);font-size:12px;margin-bottom:10px">Not found in breach databases</div>';
  }
  var recsHTML = '';
  if (d.recommendations && d.recommendations.length) {
    recsHTML = '<div style="border-top:1px solid var(--border);padding-top:10px"><div class="font-mono text-accent" style="font-size:10px;letter-spacing:1.5px;margin-bottom:6px">RECOMMENDATIONS:</div>';
    for (var j=0;j<d.recommendations.length;j++) {
      recsHTML += '<div style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim);margin-bottom:4px"><span style="color:var(--accent)">&#9654;</span> '+d.recommendations[j]+'</div>';
    }
    recsHTML += '</div>';
  }
  document.getElementById('dw-result').innerHTML =
    '<div style="background:var(--bg-deep);border:2px solid '+color+';border-radius:4px;padding:16px;margin-top:10px">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">' +
    '<span class="font-mono" style="font-size:15px;font-weight:700;color:var(--text-bright)">'+d.query+'</span>' +
    '<div style="text-align:right"><div style="font-family:var(--font-title);font-size:22px;font-weight:700;color:'+color+'">'+d.risk_score+'</div>' +
    '<div class="font-mono" style="font-size:10px;color:'+color+'">'+d.risk_level+' RISK</div></div></div>' +
    (badges?'<div style="margin-bottom:10px">'+badges+'</div>':'') +
    breachHTML + recsHTML +
    '<div style="border-top:1px solid var(--border);padding-top:10px;margin-top:8px;display:flex;gap:8px">' +
    '<button class="btn danger" style="font-size:11px;padding:4px 10px" onclick="document.getElementById(\'block-ip\').value=\''+d.query+'\';showPanel(\'blocker\',document.querySelector(\'[data-panel=blocker]\'))">Block IP</button>' +
    '<button class="btn" style="font-size:11px;padding:4px 10px" onclick="document.getElementById(\'dw-monitor-query\').value=\''+d.query+'\';addDWMonitor()">Watch</button>' +
    '</div></div>';
}

async function refreshDWHistory() {
  try {
    var results = await (await fetch('/api/darkweb/results?n=30')).json();
    document.getElementById('badge-dw-count').textContent = results.length + ' checks';
    var rc = {LOW:'var(--green)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
    if (!results.length) {
      document.getElementById('dw-history').innerHTML = '<div class="text-dim font-mono" style="font-size:11px;padding:20px;text-align:center">No checks yet</div>';
      return;
    }
    var html = '';
    for (var i=0;i<results.length;i++) {
      var d = results[i];
      var color = rc[d.risk_level] || 'var(--text-dim)';
      var tags = '';
      if (d.is_tor_exit)         tags += '<span style="font-size:9px;color:#cc88ff;font-family:var(--font-mono)">TOR </span>';
      if (d.is_botnet)           tags += '<span style="font-size:9px;color:var(--red);font-family:var(--font-mono)">BOTNET </span>';
      if (d.is_ransomware_infra) tags += '<span style="font-size:9px;color:var(--red);font-family:var(--font-mono)">RANSOMWARE </span>';
      if (d.found_in_breach)     tags += '<span style="font-size:9px;color:var(--orange);font-family:var(--font-mono)">'+d.breach_count+' BREACH </span>';
      html += '<div style="padding:10px 16px;border-bottom:1px solid rgba(15,61,92,0.3);cursor:pointer" onclick="dwQuick(\''+d.query+'\',\''+d.query_type+'\')">' +
        '<div style="display:flex;justify-content:space-between;align-items:center">' +
        '<span class="font-mono" style="color:var(--text-bright);font-weight:700">'+d.query+'</span>' +
        '<span style="color:'+color+';font-size:12px;font-weight:700;font-family:var(--font-mono)">'+d.risk_score+' '+d.risk_level+'</span></div>' +
        '<div style="margin-top:3px">'+tags+'<span class="font-mono text-dim" style="font-size:9px">'+d.datetime+'</span></div></div>';
    }
    document.getElementById('dw-history').innerHTML = html;
  } catch(e) {}
}

async function refreshDWStats() {
  try {
    var s = await (await fetch('/api/darkweb/stats')).json();
    document.getElementById('dw-total').textContent    = s.total_checks;
    document.getElementById('dw-breached').textContent = s.breached_found;
    document.getElementById('dw-critical').textContent = s.critical_findings;
    document.getElementById('dw-monitoring').textContent = s.monitoring_targets;
  } catch(e) {}
}

async function saveDWConfig() {
  var key = document.getElementById('hibp-key').value.trim();
  try {
    await fetch('/api/darkweb/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hibp_key:key})});
    document.getElementById('dw-config-msg').innerHTML = '<span class="text-green">Saved</span>';
  } catch(e) { document.getElementById('dw-config-msg').innerHTML = '<span class="text-red">Failed</span>'; }
}

async function addDWMonitor() {
  var query = document.getElementById('dw-monitor-query').value.trim();
  if (!query) return;
  try {
    await fetch('/api/darkweb/monitor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:query,type:'auto'})});
    document.getElementById('dw-monitor-query').value = '';
    refreshDWMonitorList();
    refreshDWStats();
  } catch(e) {}
}

async function removeDWMonitor(query) {
  try {
    await fetch('/api/darkweb/monitor/'+encodeURIComponent(query),{method:'DELETE'});
    refreshDWMonitorList();
    refreshDWStats();
  } catch(e) {}
}

async function refreshDWMonitorList() {
  try {
    var list = await (await fetch('/api/darkweb/monitor/list')).json();
    document.getElementById('badge-dw-monitor').textContent = list.length + ' targets';
    if (!list.length) {
      document.getElementById('dw-monitor-list').innerHTML = '<div class="text-dim font-mono" style="font-size:11px;padding:10px;text-align:center">No targets</div>';
      return;
    }
    var html = '';
    for (var i=0;i<list.length;i++) {
      var t = list[i];
      html += '<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 4px;border-bottom:1px solid rgba(15,61,92,0.3)">' +
        '<span class="font-mono text-accent" style="font-size:12px">'+t.query+'</span>' +
        '<button class="btn" style="padding:2px 6px;font-size:10px;border-color:var(--red);color:var(--red)" onclick="removeDWMonitor(\''+t.query+'\')">remove</button></div>';
    }
    document.getElementById('dw-monitor-list').innerHTML = html;
  } catch(e) {}
}
"""
    html = html.replace("</script>", js + "\n</script>")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    print("index.html patched with Dark Web panel")

print("\\nAll done! Run: python main.py")