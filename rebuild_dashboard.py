# This script writes a completely fresh index.html
path = "dashboard/index.html"

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberShield — Threat Detection</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&family=Orbitron:wght@700;900&display=swap');
:root{
  --bg-void:#020408;--bg-deep:#060c12;--bg-panel:#0a1520;--bg-card:#0d1e2e;--bg-hover:#112233;
  --border:#0f3d5c;--border-glow:#1a6a9a;
  --accent:#00d4ff;--accent-dim:#0088aa;
  --red:#ff2244;--red-dim:#aa1133;--orange:#ff6600;--yellow:#ffcc00;
  --green:#00ff88;--green-dim:#00aa55;--purple:#aa44ff;
  --text-bright:#e8f4ff;--text-main:#8eb8d4;--text-dim:#3a6a8a;
  --font-mono:'Share Tech Mono',monospace;--font-ui:'Rajdhani',sans-serif;--font-title:'Orbitron',monospace;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg-void);color:var(--text-main);font-family:var(--font-ui);font-size:14px;overflow-x:hidden;min-height:100vh;}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,0.015) 2px,rgba(0,212,255,0.015) 4px);pointer-events:none;z-index:1000;}
header{position:sticky;top:0;background:rgba(2,4,8,0.95);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);padding:0 24px;height:56px;display:flex;align-items:center;justify-content:space-between;z-index:100;}
.brand-name{font-family:var(--font-title);font-size:18px;font-weight:900;color:var(--accent);letter-spacing:3px;text-shadow:0 0 20px rgba(0,212,255,0.5);}
.brand-sub{font-family:var(--font-mono);font-size:10px;color:var(--text-dim);letter-spacing:2px;}
.logo-wrap{width:32px;height:32px;position:relative;margin-right:14px;}
.logo-ring{width:32px;height:32px;border:2px solid var(--accent);border-radius:50%;position:absolute;animation:spin 8s linear infinite;box-shadow:0 0 10px var(--accent);}
.logo-core{width:14px;height:14px;background:var(--accent);border-radius:50%;position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);box-shadow:0 0 16px var(--accent);}
@keyframes spin{to{transform:rotate(360deg);}}
.hdr-status{display:flex;align-items:center;gap:20px;}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:blink 2s infinite;}
.status-dot.off{background:var(--red);box-shadow:0 0 8px var(--red);}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:0.3;}}
.hdr-time{font-family:var(--font-mono);font-size:12px;color:var(--accent);}
.si{font-family:var(--font-mono);font-size:11px;color:var(--text-dim);display:flex;align-items:center;gap:6px;}
.layout{display:grid;grid-template-columns:210px 1fr;min-height:calc(100vh - 56px);position:relative;z-index:1;}
nav{background:var(--bg-deep);border-right:1px solid var(--border);padding:12px 0;display:flex;flex-direction:column;gap:2px;}
.nav-sec{padding:12px 16px 4px;font-size:10px;letter-spacing:2px;color:var(--text-dim);font-family:var(--font-mono);}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 20px;cursor:pointer;color:var(--text-dim);font-weight:600;letter-spacing:0.5px;transition:all 0.2s;border-left:3px solid transparent;font-size:13px;}
.nav-item:hover{background:var(--bg-hover);color:var(--text-bright);border-left-color:var(--accent-dim);}
.nav-item.active{background:rgba(0,212,255,0.06);color:var(--accent);border-left-color:var(--accent);}
.nav-icon{font-size:16px;width:20px;text-align:center;}
.nav-badge{margin-left:auto;background:var(--red);color:white;font-size:10px;font-family:var(--font-mono);padding:1px 6px;border-radius:10px;}
main{background:var(--bg-void);overflow-y:auto;padding:20px;display:flex;flex-direction:column;gap:16px;}
.panel{display:none;}
.panel.active{display:contents;}
.metrics-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;}
.metric-card{background:var(--bg-panel);border:1px solid var(--border);border-radius:4px;padding:16px 20px;position:relative;overflow:hidden;}
.metric-card::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--accent);}
.metric-card.danger::before{background:var(--red);}
.metric-card.warn::before{background:var(--orange);}
.metric-card.success::before{background:var(--green);}
.metric-card.purple::before{background:var(--purple);}
.metric-glow{position:absolute;top:-20px;right:-20px;width:80px;height:80px;border-radius:50%;opacity:0.08;background:var(--accent);filter:blur(20px);}
.metric-card.danger .metric-glow{background:var(--red);}
.metric-card.warn .metric-glow{background:var(--orange);}
.metric-card.success .metric-glow{background:var(--green);}
.metric-card.purple .metric-glow{background:var(--purple);}
.metric-label{font-family:var(--font-mono);font-size:10px;letter-spacing:2px;color:var(--text-dim);margin-bottom:8px;}
.metric-value{font-family:var(--font-title);font-size:28px;font-weight:700;color:var(--text-bright);line-height:1;margin-bottom:4px;}
.metric-sub{font-family:var(--font-mono);font-size:11px;color:var(--text-dim);}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;}
.g60{display:grid;grid-template-columns:60fr 40fr;gap:16px;}
.card{background:var(--bg-panel);border:1px solid var(--border);border-radius:4px;overflow:hidden;}
.card-header{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);background:rgba(0,212,255,0.02);}
.card-title{font-family:var(--font-mono);font-size:11px;letter-spacing:2px;color:var(--accent);text-transform:uppercase;}
.card-badge{font-family:var(--font-mono);font-size:10px;color:var(--text-dim);background:var(--bg-deep);padding:2px 8px;border-radius:3px;border:1px solid var(--border);}
.card-body{padding:16px;}
.ttable{width:100%;border-collapse:collapse;}
.ttable th{font-family:var(--font-mono);font-size:10px;letter-spacing:1.5px;color:var(--text-dim);text-transform:uppercase;padding:8px 12px;border-bottom:1px solid var(--border);text-align:left;background:var(--bg-deep);}
.ttable td{padding:10px 12px;border-bottom:1px solid rgba(15,61,92,0.5);font-family:var(--font-mono);font-size:12px;vertical-align:middle;}
.ttable tr:hover td{background:var(--bg-hover);}
.sev-badge{display:inline-block;padding:2px 8px;border-radius:2px;font-size:10px;font-weight:700;letter-spacing:1px;}
.sev-CRITICAL{background:rgba(255,34,68,0.2);color:var(--red);border:1px solid var(--red-dim);}
.sev-HIGH{background:rgba(255,102,0,0.2);color:var(--orange);border:1px solid #883300;}
.sev-MEDIUM{background:rgba(255,204,0,0.15);color:var(--yellow);border:1px solid #886600;}
.sev-LOW{background:rgba(0,212,255,0.1);color:var(--accent);border:1px solid var(--border);}
.proto-badge{display:inline-block;padding:1px 6px;border-radius:2px;font-size:10px;background:var(--bg-deep);border:1px solid var(--border);color:var(--text-dim);}
.proto-TCP{border-color:var(--accent-dim);color:var(--accent);}
.proto-UDP{border-color:#558800;color:#88cc00;}
.proto-ICMP{border-color:#885500;color:var(--orange);}
.live-feed{height:280px;overflow-y:auto;font-family:var(--font-mono);font-size:11px;line-height:1.8;padding:12px;background:var(--bg-deep);}
.live-feed::-webkit-scrollbar{width:4px;}
.live-feed::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px;}
.feed-line{display:flex;gap:10px;padding:2px 0;}
.feed-ts{color:var(--text-dim);flex-shrink:0;}
.feed-proto{color:var(--accent-dim);width:36px;flex-shrink:0;}
.alert-item{display:flex;align-items:flex-start;gap:12px;padding:10px 16px;border-bottom:1px solid rgba(15,61,92,0.3);}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border:1px solid var(--border);border-radius:3px;background:var(--bg-card);color:var(--text-main);font-family:var(--font-ui);font-size:13px;font-weight:600;cursor:pointer;transition:all 0.2s;}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(0,212,255,0.05);}
.btn.primary{border-color:var(--accent);color:var(--accent);background:rgba(0,212,255,0.08);}
.btn.danger{border-color:var(--red);color:var(--red);background:rgba(255,34,68,0.05);}
.inp{width:100%;background:var(--bg-deep);border:1px solid var(--border);color:var(--text-main);padding:8px 12px;font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none;}
.inp:focus{border-color:var(--accent);}
.sel{background:var(--bg-deep);border:1px solid var(--border);color:var(--text-main);padding:8px 12px;font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none;}
.lbl{display:block;font-family:var(--font-mono);font-size:10px;letter-spacing:1.5px;color:var(--text-dim);margin-bottom:5px;}
.fg{margin-bottom:12px;}
.flex{display:flex;align-items:center;gap:8px;}
.chart-wrap{position:relative;height:200px;}
::-webkit-scrollbar{width:6px;}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px;}
.text-accent{color:var(--accent);}
.text-red{color:var(--red);}
.text-orange{color:var(--orange);}
.text-yellow{color:var(--yellow);}
.text-green{color:var(--green);}
.text-dim{color:var(--text-dim);}
.fm{font-family:var(--font-mono);}
</style>
</head>
<body>
<header>
  <div style="display:flex;align-items:center">
    <div class="logo-wrap"><div class="logo-ring"></div><div class="logo-core"></div></div>
    <div><div class="brand-name">CYBERSHIELD</div><div class="brand-sub">THREAT DETECTION SYSTEM v2.0</div></div>
  </div>
  <div class="hdr-status">
    <div class="si"><div class="status-dot" id="conn-dot"></div><span id="conn-label">CONNECTING</span></div>
    <div class="si">IFACE: <span id="hdr-iface" class="text-accent">—</span></div>
    <div class="si">ML: <span id="hdr-ml" class="text-dim">TRAINING</span></div>
    <div class="hdr-time" id="clock">00:00:00</div>
  </div>
</header>
<div class="layout">
<nav>
  <div class="nav-sec">MONITOR</div>
  <div class="nav-item active" onclick="showPanel('overview',this)" data-panel="overview"><span class="nav-icon">⬡</span> Overview</div>
  <div class="nav-item" onclick="showPanel('threats',this)" data-panel="threats"><span class="nav-icon">⚡</span> Threat Events <span class="nav-badge" id="nb-threats">0</span></div>
  <div class="nav-item" onclick="showPanel('packets',this)" data-panel="packets"><span class="nav-icon">◈</span> Live Traffic</div>
  <div class="nav-item" onclick="showPanel('flows',this)" data-panel="flows"><span class="nav-icon">⟶</span> Active Flows</div>
  <div class="nav-sec">ANALYSIS</div>
  <div class="nav-item" onclick="showPanel('malware',this)" data-panel="malware"><span class="nav-icon">☣</span> Malware Scanner</div>
  <div class="nav-item" onclick="showPanel('simulate',this)" data-panel="simulate"><span class="nav-icon">◉</span> Attack Simulator</div>
  <div class="nav-item" onclick="showPanel('mitre',this)" data-panel="mitre"><span class="nav-icon">⬙</span> MITRE ATT&CK</div>
  <div class="nav-sec">FEATURES</div>
  <div class="nav-item" onclick="showPanel('intel',this)" data-panel="intel"><span class="nav-icon">🔍</span> Threat Intel</div>
  <div class="nav-item" onclick="showPanel('scanner',this)" data-panel="scanner"><span class="nav-icon">📡</span> Network Scanner</div>
  <div class="nav-item" onclick="showPanel('inspector',this)" data-panel="inspector"><span class="nav-icon">🔬</span> Packet Inspector</div>
  <div class="nav-item" onclick="showPanel('blocker',this)" data-panel="blocker"><span class="nav-icon">🚫</span> IP Blocker</div>
  <div class="nav-item" onclick="showPanel('darkweb',this)" data-panel="darkweb"><span class="nav-icon">🕵️</span> Dark Web</div>
  <div class="nav-item" onclick="showPanel('alertcfg',this)" data-panel="alertcfg"><span class="nav-icon">🔔</span> Alert Config</div>
  <div class="nav-item" onclick="showPanel('reports',this)" data-panel="reports"><span class="nav-icon">📄</span> Reports</div>
</nav>
<main>

<!-- OVERVIEW -->
<div class="panel active" id="panel-overview">
  <div class="metrics-row">
    <div class="metric-card"><div class="metric-glow"></div><div class="metric-label">TOTAL PACKETS</div><div class="metric-value" id="m-packets">0</div><div class="metric-sub"><span id="m-pps">0</span> pkt/s</div></div>
    <div class="metric-card success"><div class="metric-glow"></div><div class="metric-label">DATA CAPTURED</div><div class="metric-value" id="m-bytes">0</div><div class="metric-sub">bytes</div></div>
    <div class="metric-card warn"><div class="metric-glow"></div><div class="metric-label">ACTIVE FLOWS</div><div class="metric-value" id="m-flows">0</div><div class="metric-sub">connections</div></div>
    <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">THREATS</div><div class="metric-value" id="m-threats">0</div><div class="metric-sub"><span id="m-crit" class="text-red">0</span> critical</div></div>
  </div>
  <div class="g60">
    <div class="card">
      <div class="card-header"><div class="card-title">◈ TRAFFIC RATE (PPS)</div><div class="card-badge" id="b-pps">0 pps</div></div>
      <div class="card-body"><div class="chart-wrap"><canvas id="chart-traffic"></canvas></div></div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title">◉ PROTOCOLS</div></div>
      <div class="card-body" style="display:flex;gap:16px;align-items:center">
        <div style="width:130px;height:130px;flex-shrink:0"><canvas id="chart-proto"></canvas></div>
        <div id="proto-legend" style="display:flex;flex-direction:column;gap:6px;font-family:var(--font-mono);font-size:11px"></div>
      </div>
    </div>
  </div>
  <div class="grid-2">
    <div class="card">
      <div class="card-header"><div class="card-title">⚡ SEVERITY BREAKDOWN</div></div>
      <div class="card-body"><div class="chart-wrap" style="height:160px"><canvas id="chart-sev"></canvas></div></div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title">◈ TOP SOURCE IPs</div><div class="card-badge" id="b-talkers">0</div></div>
      <div class="card-body" id="top-talkers"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">Waiting for traffic...</div></div>
    </div>
  </div>
  <div class="card">
    <div class="card-header"><div class="card-title">🚨 RECENT ALERTS</div><div class="flex"><div class="card-badge" id="b-alerts">0</div><button class="btn" onclick="clearAlerts()" style="padding:3px 10px;font-size:11px;margin-left:8px">CLEAR</button></div></div>
    <div id="alert-list" style="max-height:240px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No alerts yet</div></div>
  </div>
</div>

<!-- THREATS -->
<div class="panel" id="panel-threats">
  <div class="card">
    <div class="card-header"><div class="card-title">⚡ THREAT EVENT LOG</div>
      <div class="flex">
        <select class="sel" id="fil-sev" onchange="filterThreats()" style="padding:3px 8px;font-size:11px">
          <option value="">ALL</option><option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option>
        </select>
        <button class="btn primary" onclick="loadThreats()" style="padding:4px 12px;font-size:11px;margin-left:8px">↻ REFRESH</button>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table class="ttable"><thead><tr><th>TIME</th><th>SEV</th><th>CATEGORY</th><th>SOURCE</th><th>DESTINATION</th><th>PROTO</th><th>CONF</th><th>MITRE</th></tr></thead>
      <tbody id="threats-body"><tr><td colspan="8" style="text-align:center;color:var(--text-dim);padding:40px">No threats yet</td></tr></tbody></table>
    </div>
  </div>
</div>

<!-- LIVE TRAFFIC -->
<div class="panel" id="panel-packets">
  <div class="card">
    <div class="card-header"><div class="card-title">◈ LIVE PACKET CAPTURE</div><div class="flex"><div class="status-dot" style="animation-duration:0.8s"></div><span class="fm text-green" style="font-size:11px">LIVE</span><div class="card-badge" id="b-pkts" style="margin-left:8px">0</div></div></div>
    <div class="live-feed" id="pkt-feed"></div>
  </div>
  <div class="grid-2">
    <div class="card"><div class="card-header"><div class="card-title">PROTOCOL STATS</div></div><div class="card-body" id="proto-stats" style="font-family:var(--font-mono);font-size:12px;line-height:2"></div></div>
    <div class="card"><div class="card-header"><div class="card-title">TOTAL BYTES</div></div><div class="card-body"><div class="fm text-accent" style="font-size:20px" id="total-bytes-disp">0 B</div></div></div>
  </div>
</div>

<!-- FLOWS -->
<div class="panel" id="panel-flows">
  <div class="card">
    <div class="card-header"><div class="card-title">⟶ ACTIVE FLOWS</div><div class="card-badge" id="b-flows">0</div></div>
    <div style="overflow-x:auto">
      <table class="ttable"><thead><tr><th>SOURCE</th><th>DESTINATION</th><th>PROTO</th><th>PACKETS</th><th>BYTES</th><th>PPS</th><th>DURATION</th></tr></thead>
      <tbody id="flows-body"><tr><td colspan="7" style="text-align:center;color:var(--text-dim);padding:40px">No active flows</td></tr></tbody></table>
    </div>
  </div>
</div>

<!-- MALWARE -->
<div class="panel" id="panel-malware">
  <div class="grid-2">
    <div class="card">
      <div class="card-header"><div class="card-title">☣ FILE SCANNER</div></div>
      <div class="card-body">
        <div class="fg"><label class="lbl">FILE PATH</label><div class="flex"><input type="text" class="inp" id="scan-path" placeholder="C:\path\to\file.exe" style="flex:1"><button class="btn primary" onclick="scanFile()" style="margin-left:8px">SCAN</button></div></div>
        <div id="scan-result"></div>
      </div>
    </div>
    <div class="card"><div class="card-header"><div class="card-title">SCAN HISTORY</div></div><div id="malware-list" style="max-height:400px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No scans yet</div></div></div>
  </div>
</div>

<!-- SIMULATE -->
<div class="panel" id="panel-simulate">
  <div class="grid-2">
    <div class="card">
      <div class="card-header"><div class="card-title">◉ INJECT ATTACK</div></div>
      <div class="card-body">
        <div class="grid-2">
          <div class="fg"><label class="lbl">ATTACK TYPE</label><select class="sel" id="sim-type" style="width:100%"><option value="port_scan">Port Scan</option><option value="syn_flood">SYN Flood</option><option value="brute_force">Brute Force</option><option value="dns_tunnel">DNS Tunneling</option><option value="malware">Malware Payload</option><option value="anomaly">ML Anomaly</option></select></div>
          <div class="fg"><label class="lbl">SEVERITY</label><select class="sel" id="sim-sev" style="width:100%"><option value="critical">CRITICAL</option><option value="high" selected>HIGH</option><option value="medium">MEDIUM</option><option value="low">LOW</option></select></div>
          <div class="fg"><label class="lbl">SOURCE IP</label><input type="text" class="inp" id="sim-src" value="192.168.1.42"></div>
          <div class="fg"><label class="lbl">DEST IP</label><input type="text" class="inp" id="sim-dst" value="10.0.0.1"></div>
        </div>
        <div class="flex" style="margin-top:8px">
          <button class="btn primary" onclick="simAttack()">▶ INJECT</button>
          <button class="btn" onclick="simBurst()" style="margin-left:8px">⚡ BURST x5</button>
        </div>
        <div id="sim-msg" class="fm text-dim" style="font-size:11px;margin-top:10px"></div>
      </div>
    </div>
    <div class="card"><div class="card-header"><div class="card-title">SIM LOG</div></div><div class="live-feed" id="sim-log" style="height:300px"><div class="text-dim" style="text-align:center;padding:40px;font-size:11px">No simulations yet</div></div></div>
  </div>
</div>

<!-- MITRE -->
<div class="panel" id="panel-mitre">
  <div class="card">
    <div class="card-header"><div class="card-title">⬙ MITRE ATT&CK MAP</div></div>
    <div class="card-body" id="mitre-grid" style="display:grid;grid-template-columns:repeat(6,1fr);gap:4px"></div>
  </div>
</div>

<!-- THREAT INTEL -->
<div class="panel" id="panel-intel">
  <div class="grid-2">
    <div class="card">
      <div class="card-header"><div class="card-title">🔍 IP LOOKUP</div></div>
      <div class="card-body">
        <div class="fg"><label class="lbl">IP ADDRESS</label><div class="flex"><input type="text" class="inp" id="intel-ip" placeholder="e.g. 185.220.101.5" style="flex:1"><button class="btn primary" onclick="intelLookup()" style="margin-left:8px">LOOKUP</button></div></div>
        <div id="intel-result"></div>
        <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px">
          <div class="lbl">VIRUSTOTAL API KEY</div>
          <input type="password" class="inp" id="vt-key" placeholder="virustotal.com — free key" style="margin-bottom:8px">
          <div class="lbl">ABUSEIPDB API KEY</div>
          <input type="password" class="inp" id="abuse-key" placeholder="abuseipdb.com — free key" style="margin-bottom:8px">
          <button class="btn primary" onclick="saveIntelKeys()">SAVE KEYS</button>
          <div id="intel-key-msg" class="fm text-dim" style="font-size:11px;margin-top:6px"></div>
        </div>
      </div>
    </div>
    <div class="card"><div class="card-header"><div class="card-title">RECENT LOOKUPS</div><div class="card-badge" id="b-intel">0</div></div><div id="intel-history" style="max-height:500px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No lookups yet</div></div></div>
  </div>
</div>

<!-- NETWORK SCANNER -->
<div class="panel" id="panel-scanner">
  <div class="card" style="margin-bottom:16px">
    <div class="card-header"><div class="card-title">📡 LAN SCANNER</div><div class="flex"><div class="status-dot off" id="scan-dot" style="animation:none"></div><span id="scan-lbl" class="fm text-dim" style="font-size:11px">IDLE</span></div></div>
    <div class="card-body" style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap">
      <div style="flex:1;min-width:180px"><label class="lbl">NETWORK CIDR (blank=auto)</label><input type="text" class="inp" id="scan-net" placeholder="192.168.1.0/24"></div>
      <button class="btn primary" onclick="startScan(true)">🔍 FULL SCAN</button>
      <button class="btn" onclick="startScan(false)">⚡ QUICK</button>
    </div>
    <div style="padding:8px 16px"><div style="height:5px;background:var(--bg-deep);border-radius:3px;overflow:hidden"><div id="scan-bar" style="height:100%;width:0%;background:linear-gradient(90deg,var(--accent-dim),var(--accent));border-radius:3px;transition:width 0.5s"></div></div><div class="fm text-dim" style="font-size:10px;margin-top:3px" id="scan-txt">Ready</div></div>
  </div>
  <div class="card">
    <div class="card-header"><div class="card-title">DISCOVERED DEVICES</div><div class="card-badge" id="b-devices">0</div></div>
    <div style="overflow-x:auto"><table class="ttable"><thead><tr><th>IP</th><th>HOSTNAME</th><th>VENDOR</th><th>OPEN PORTS</th><th>OS</th><th>RISK</th><th>RTT</th><th>ACTION</th></tr></thead><tbody id="devices-body"><tr><td colspan="8" style="text-align:center;color:var(--text-dim);padding:40px;font-family:var(--font-mono);font-size:11px">Run a scan first</td></tr></tbody></table></div>
  </div>
</div>

<!-- PACKET INSPECTOR -->
<div class="panel" id="panel-inspector">
  <div class="card" style="margin-bottom:16px">
    <div class="card-header"><div class="card-title">🔬 PACKET INSPECTOR</div>
      <div class="flex">
        <select class="sel" id="ins-proto" onchange="loadInspector()" style="padding:3px 8px;font-size:11px"><option value="">ALL</option><option value="TCP">TCP</option><option value="UDP">UDP</option><option value="ICMP">ICMP</option></select>
        <button class="btn primary" onclick="loadInspector()" style="padding:4px 12px;font-size:11px;margin-left:8px">↻</button>
      </div>
    </div>
    <div style="overflow-x:auto"><table class="ttable"><thead><tr><th>#</th><th>TIME</th><th>PROTO</th><th>SRC</th><th>DST</th><th>SIZE</th><th>FLAGS</th><th>ANOMALIES</th><th>ACTION</th></tr></thead><tbody id="ins-body"><tr><td colspan="9" style="text-align:center;color:var(--text-dim);padding:30px;font-family:var(--font-mono);font-size:11px">Waiting...</td></tr></tbody></table></div>
  </div>
  <div class="card" id="ins-detail" style="display:none">
    <div class="card-header"><div class="card-title">PACKET DETAIL</div><button class="btn" onclick="document.getElementById('ins-detail').style.display='none'" style="padding:3px 10px;font-size:11px">✕</button></div>
    <div class="card-body" id="ins-detail-body"></div>
  </div>
</div>

<!-- IP BLOCKER -->
<div class="panel" id="panel-blocker">
  <div class="grid-2">
    <div class="card">
      <div class="card-header"><div class="card-title">🚫 BLOCK IP</div></div>
      <div class="card-body">
        <div class="fg"><label class="lbl">IP ADDRESS</label><input type="text" class="inp" id="blk-ip" placeholder="e.g. 192.168.1.42"></div>
        <div class="grid-2">
          <div class="fg"><label class="lbl">SEVERITY</label><select class="sel" id="blk-sev" style="width:100%"><option value="CRITICAL">CRITICAL</option><option value="HIGH" selected>HIGH</option><option value="MEDIUM">MEDIUM</option></select></div>
          <div class="fg"><label class="lbl">REASON</label><input type="text" class="inp" id="blk-reason" placeholder="reason..."></div>
        </div>
        <button class="btn danger" onclick="blockIP()">🚫 BLOCK</button>
        <div id="blk-msg" class="fm text-dim" style="font-size:11px;margin-top:8px"></div>
        <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
          <div class="lbl">AUTO-BLOCK SETTINGS</div>
          <div class="flex" style="margin-bottom:8px"><input type="checkbox" id="auto-blk" style="width:16px;height:16px"><label class="fm text-dim" style="font-size:11px;margin-left:8px">Auto-block above:</label><select class="sel" id="auto-sev" style="padding:3px 8px;font-size:11px;margin-left:8px"><option value="CRITICAL">CRITICAL</option><option value="HIGH" selected>HIGH+</option><option value="MEDIUM">MEDIUM+</option></select></div>
          <button class="btn primary" onclick="saveAutoBlock()" style="font-size:11px;padding:6px 12px">SAVE</button>
        </div>
        <div id="blk-stats" class="fm text-dim" style="font-size:11px;line-height:2;margin-top:14px;border-top:1px solid var(--border);padding-top:10px">Loading...</div>
      </div>
    </div>
    <div class="card"><div class="card-header"><div class="card-title">BLOCKED IPs</div><div class="card-badge" id="b-blocked">0</div></div><div id="blocked-list" style="max-height:500px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">None blocked</div></div></div>
  </div>
</div>

<!-- DARK WEB -->
<div class="panel" id="panel-darkweb">
  <div class="metrics-row" style="margin-bottom:16px">
    <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">TOTAL CHECKS</div><div class="metric-value" id="dw-total">0</div><div class="metric-sub">queries run</div></div>
    <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">BREACHES FOUND</div><div class="metric-value" id="dw-breached">0</div><div class="metric-sub">compromised</div></div>
    <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">CRITICAL</div><div class="metric-value" id="dw-critical">0</div><div class="metric-sub">immediate action</div></div>
    <div class="metric-card purple"><div class="metric-glow"></div><div class="metric-label">MONITORING</div><div class="metric-value" id="dw-watching">0</div><div class="metric-sub">targets watched</div></div>
  </div>
  <div class="grid-2">
    <div style="display:flex;flex-direction:column;gap:16px">
      <div class="card">
        <div class="card-header"><div class="card-title">🕵️ BREACH CHECK</div></div>
        <div class="card-body">
          <div class="fg"><label class="lbl">IP / EMAIL / DOMAIN</label>
            <div class="flex"><input type="text" class="inp" id="dw-q" placeholder="185.220.101.5 or user@domain.com" style="flex:1">
            <select class="sel" id="dw-t" style="margin-left:8px"><option value="auto">Auto</option><option value="ip">IP</option><option value="email">Email</option><option value="domain">Domain</option></select>
            <button class="btn primary" onclick="dwCheck()" style="margin-left:8px">CHECK</button></div>
          </div>
          <div class="lbl" style="margin-bottom:6px">QUICK TESTS:</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px">
            <button class="btn" style="font-size:10px;padding:3px 8px" onclick="dwQuick('185.220.101.5','ip')">Tor Exit</button>
            <button class="btn" style="font-size:10px;padding:3px 8px" onclick="dwQuick('45.142.212.100','ip')">Botnet C2</button>
            <button class="btn" style="font-size:10px;padding:3px 8px" onclick="dwQuick('194.165.16.10','ip')">Ransomware</button>
            <button class="btn" style="font-size:10px;padding:3px 8px" onclick="dwQuick('test@test.com','email')">Breached Email</button>
          </div>
          <div id="dw-result"></div>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><div class="card-title">API KEY</div></div>
        <div class="card-body">
          <div class="fg"><label class="lbl">HAVEIBEENPWNED KEY (optional)</label><div class="flex"><input type="password" class="inp" id="hibp-key" placeholder="haveibeenpwned.com/API/Key" style="flex:1"><button class="btn primary" onclick="saveDWKey()" style="margin-left:8px">SAVE</button></div></div>
          <div id="dw-key-msg" class="fm text-dim" style="font-size:11px"></div>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><div class="card-title">WATCH LIST</div><div class="card-badge" id="b-watching">0</div></div>
        <div class="card-body">
          <div class="flex" style="margin-bottom:10px"><input type="text" class="inp" id="dw-watch-q" placeholder="IP, email, or domain..." style="flex:1"><button class="btn primary" onclick="addDWWatch()" style="margin-left:8px">+ WATCH</button></div>
          <div id="dw-watch-list"><div class="text-dim fm" style="font-size:11px;padding:10px;text-align:center">No targets</div></div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title">CHECK HISTORY</div><div class="card-badge" id="b-dw-hist">0</div></div>
      <div id="dw-history" style="max-height:700px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No checks yet</div></div>
    </div>
  </div>
</div>

<!-- ALERT CONFIG -->
<div class="panel" id="panel-alertcfg">
  <div class="grid-2">
    <div class="card">
      <div class="card-header"><div class="card-title">📧 EMAIL ALERTS</div></div>
      <div class="card-body">
        <div class="grid-2">
          <div class="fg"><label class="lbl">SMTP HOST</label><input type="text" class="inp" id="smtp-host" value="smtp.gmail.com"></div>
          <div class="fg"><label class="lbl">SMTP PORT</label><input type="number" class="inp" id="smtp-port" value="587"></div>
          <div class="fg"><label class="lbl">FROM EMAIL</label><input type="email" class="inp" id="email-from" placeholder="your@gmail.com"></div>
          <div class="fg"><label class="lbl">APP PASSWORD</label><input type="password" class="inp" id="email-pass" placeholder="Gmail app password"></div>
        </div>
        <div class="fg"><label class="lbl">SEND TO (comma separated)</label><input type="text" class="inp" id="email-to" placeholder="alert@example.com"></div>
        <div class="fg"><label class="lbl">MIN SEVERITY</label><select class="sel" id="email-sev" style="width:100%"><option value="CRITICAL">CRITICAL only</option><option value="HIGH" selected>HIGH+</option><option value="MEDIUM">MEDIUM+</option><option value="LOW">All</option></select></div>
        <div class="flex" style="margin-bottom:12px"><input type="checkbox" id="email-on" style="width:16px;height:16px"><label class="fm text-dim" style="font-size:11px;margin-left:8px">Enable email alerts</label></div>
        <button class="btn primary" onclick="saveEmailCfg()">SAVE</button>
        <div id="email-msg" class="fm text-dim" style="font-size:11px;margin-top:8px"></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title">🔗 WEBHOOK (SLACK/TEAMS)</div></div>
      <div class="card-body">
        <div class="fg"><label class="lbl">WEBHOOK URL</label><input type="text" class="inp" id="wh-url" placeholder="https://hooks.slack.com/..."></div>
        <div class="fg"><label class="lbl">MIN SEVERITY</label><select class="sel" id="wh-sev" style="width:100%"><option value="CRITICAL">CRITICAL</option><option value="HIGH" selected>HIGH+</option><option value="MEDIUM">MEDIUM+</option></select></div>
        <div class="flex" style="margin-bottom:12px"><input type="checkbox" id="wh-on" style="width:16px;height:16px"><label class="fm text-dim" style="font-size:11px;margin-left:8px">Enable webhook</label></div>
        <button class="btn primary" onclick="saveWebhook()">SAVE</button>
        <div id="wh-msg" class="fm text-dim" style="font-size:11px;margin-top:8px"></div>
        <div class="fm text-dim" style="font-size:11px;margin-top:14px;border-top:1px solid var(--border);padding-top:10px;line-height:1.8">
          Slack: api.slack.com/apps → Create App → Incoming Webhooks → Add Webhook
        </div>
      </div>
    </div>
  </div>
</div>

<!-- REPORTS -->
<div class="panel" id="panel-reports">
  <div class="grid-2">
    <div class="card">
      <div class="card-header"><div class="card-title">📄 EXPORT</div></div>
      <div class="card-body" style="display:flex;flex-direction:column;gap:14px">
        <div style="background:var(--bg-deep);border:1px solid var(--border);border-radius:4px;padding:14px">
          <div style="font-weight:700;color:var(--text-bright);margin-bottom:6px">📊 CSV Report</div>
          <div class="fm text-dim" style="font-size:11px;margin-bottom:10px">All threat events — Excel/Sheets compatible</div>
          <a href="/api/report/csv" class="btn primary" style="text-decoration:none;display:inline-flex">⬇ DOWNLOAD CSV</a>
        </div>
        <div style="background:var(--bg-deep);border:1px solid var(--border);border-radius:4px;padding:14px">
          <div style="font-weight:700;color:var(--text-bright);margin-bottom:6px">📑 PDF Report</div>
          <div class="fm text-dim" style="font-size:11px;margin-bottom:10px">Incident report with summary + threat table</div>
          <a href="/api/report/pdf" class="btn primary" style="text-decoration:none;display:inline-flex">⬇ DOWNLOAD PDF</a>
        </div>
      </div>
    </div>
    <div class="card"><div class="card-header"><div class="card-title">SESSION SUMMARY</div></div><div class="card-body" id="rpt-summary"><div class="text-dim fm" style="font-size:11px">Loading...</div></div></div>
  </div>
</div>

</main>
</div>

<script>
// ================================================================
// NAVIGATION
// ================================================================
function showPanel(name, el) {
  document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
  document.querySelectorAll('.nav-item').forEach(function(n){ n.classList.remove('active'); });
  var t = document.getElementById('panel-' + name);
  if (t) t.classList.add('active');
  if (el) el.classList.add('active');
  if (name==='threats')   loadThreats();
  if (name==='flows')     loadFlows();
  if (name==='malware')   loadMalware();
  if (name==='intel')     loadIntelHistory();
  if (name==='scanner')   loadDevices();
  if (name==='inspector') loadInspector();
  if (name==='blocker')   loadBlockList();
  if (name==='darkweb')   { loadDWHistory(); loadDWStats(); loadDWWatchList(); }
  if (name==='reports')   loadRptSummary();
  if (name==='mitre')     renderMitre();
}

// ================================================================
// CLOCK
// ================================================================
setInterval(function(){ document.getElementById('clock').textContent = new Date().toTimeString().slice(0,8); }, 1000);

// ================================================================
// CHARTS
// ================================================================
var trafficData = { labels: Array(60).fill(''), datasets:[{ data:Array(60).fill(0), borderColor:'#00d4ff', backgroundColor:'rgba(0,212,255,0.06)', fill:true, borderWidth:2, tension:0.4, pointRadius:0 }] };
var trafficChart = new Chart(document.getElementById('chart-traffic').getContext('2d'), { type:'line', data:trafficData, options:{ responsive:true, maintainAspectRatio:false, animation:{duration:200}, scales:{ x:{display:false}, y:{grid:{color:'rgba(15,61,92,0.5)'}, ticks:{color:'#3a6a8a',font:{family:'Share Tech Mono',size:10}}, beginAtZero:true } }, plugins:{legend:{display:false}} } });
var protoChart = new Chart(document.getElementById('chart-proto').getContext('2d'), { type:'doughnut', data:{ labels:['TCP','UDP','ICMP','OTHER'], datasets:[{ data:[0,0,0,0], backgroundColor:['rgba(0,212,255,0.7)','rgba(0,255,136,0.7)','rgba(255,102,0,0.7)','rgba(170,68,255,0.7)'], borderColor:['#00d4ff','#00ff88','#ff6600','#aa44ff'], borderWidth:1 }] }, options:{ responsive:true, maintainAspectRatio:false, animation:{duration:200}, plugins:{legend:{display:false}}, cutout:'65%' } });
var sevChart = new Chart(document.getElementById('chart-sev').getContext('2d'), { type:'bar', data:{ labels:['CRITICAL','HIGH','MEDIUM','LOW'], datasets:[{ data:[0,0,0,0], backgroundColor:['rgba(255,34,68,0.7)','rgba(255,102,0,0.6)','rgba(255,204,0,0.5)','rgba(0,212,255,0.4)'], borderColor:['#ff2244','#ff6600','#ffcc00','#00d4ff'], borderWidth:1, borderRadius:2 }] }, options:{ responsive:true, maintainAspectRatio:false, animation:{duration:200}, scales:{ x:{grid:{display:false},ticks:{color:'#3a6a8a',font:{family:'Share Tech Mono',size:10}}}, y:{grid:{color:'rgba(15,61,92,0.5)'},ticks:{color:'#3a6a8a',font:{family:'Share Tech Mono',size:10}},beginAtZero:true} }, plugins:{legend:{display:false}} } });

// ================================================================
// WEBSOCKET
// ================================================================
var socket = io(window.location.origin, {transports:['websocket','polling']});
socket.on('connect', function(){ setConn(true); socket.emit('request_events',{n:100}); });
socket.on('disconnect', function(){ setConn(false); });
socket.on('stats_update', onStats);
socket.on('threat_event', function(e){ allEvents.unshift(e); if(allEvents.length>500)allEvents.pop(); renderThreats(); var tot=Object.values(e.event_counts||{}).reduce(function(a,b){return a+b;},0); document.getElementById('nb-threats').textContent=allEvents.length; });
socket.on('alert', onAlert);
socket.on('events_batch', function(ev){ allEvents=ev; renderThreats(); });
socket.on('darkweb_result', function(){ loadDWHistory(); loadDWStats(); });
socket.on('ip_blocked', function(){ loadBlockList(); });
socket.on('device_found', function(){ loadDevices(); });

function setConn(ok){
  document.getElementById('conn-dot').className = 'status-dot' + (ok?'':' off');
  document.getElementById('conn-label').textContent = ok ? 'CONNECTED' : 'DISCONNECTED';
}

// ================================================================
// STATS
// ================================================================
var allEvents = [];
var mitreData = {};
var pktCount = 0;
var alertCount = 0;

function onStats(s) {
  document.getElementById('m-packets').textContent = fmt(s.packets);
  document.getElementById('m-pps').textContent = s.pps;
  document.getElementById('m-bytes').textContent = fmtB(s.bytes);
  document.getElementById('m-flows').textContent = fmt(s.flows);
  document.getElementById('b-pps').textContent = s.pps + ' pps';
  document.getElementById('total-bytes-disp').textContent = fmtB(s.bytes);
  document.getElementById('hdr-iface').textContent = s.interface || 'eth0';
  var ml = document.getElementById('hdr-ml');
  ml.textContent = s.ml_trained ? 'ACTIVE' : 'TRAINING';
  ml.className = s.ml_trained ? 'text-green' : 'text-dim';
  var ec = s.event_counts || {};
  var tot = (ec.CRITICAL||0)+(ec.HIGH||0)+(ec.MEDIUM||0)+(ec.LOW||0);
  document.getElementById('m-threats').textContent = tot;
  document.getElementById('m-crit').textContent = ec.CRITICAL||0;
  document.getElementById('nb-threats').textContent = tot;
  trafficData.datasets[0].data.push(s.pps); trafficData.datasets[0].data.shift(); trafficChart.update('none');
  var pr = s.protocols||{};
  protoChart.data.datasets[0].data=[pr.TCP||0,pr.UDP||0,pr.ICMP||0,pr.OTHER||0]; protoChart.update('none');
  sevChart.data.datasets[0].data=[ec.CRITICAL||0,ec.HIGH||0,ec.MEDIUM||0,ec.LOW||0]; sevChart.update('none');
  renderProtoLegend(pr);
  renderProtoStats(pr);
  loadTopTalkers();
}

setInterval(function(){
  fetch('/api/status').then(function(r){return r.json();}).then(function(s){
    onStats({packets:s.total_packets,bytes:s.total_bytes,flows:s.active_flows,pps:s.packets_per_second,protocols:s.protocols,event_counts:s.event_counts,ml_trained:s.ml_trained,interface:s.interface});
  }).catch(function(){});
}, 2000);

// ================================================================
// THREATS
// ================================================================
function loadThreats() {
  fetch('/api/events?n=200').then(function(r){return r.json();}).then(function(ev){ allEvents=ev; renderThreats(); });
}
function filterThreats(){ renderThreats(); }
function renderThreats() {
  var sev = document.getElementById('fil-sev').value;
  var ev = sev ? allEvents.filter(function(e){return e.severity===sev;}) : allEvents;
  var body = document.getElementById('threats-body');
  if (!ev.length){ body.innerHTML='<tr><td colspan="8" style="text-align:center;color:var(--text-dim);padding:40px;font-family:var(--font-mono);font-size:11px">No threats</td></tr>'; return; }
  var html='';
  ev.slice(0,200).forEach(function(e){
    html+='<tr><td class="fm text-dim" style="font-size:10px">'+(e.datetime||'').slice(11)+'</td>'+
    '<td><span class="sev-badge sev-'+e.severity+'">'+e.severity+'</span></td>'+
    '<td style="color:var(--text-bright);font-weight:600">'+e.category+'</td>'+
    '<td class="fm" style="font-size:11px">'+e.src_ip+':'+e.src_port+'</td>'+
    '<td class="fm text-dim" style="font-size:11px">'+e.dst_ip+':'+e.dst_port+'</td>'+
    '<td><span class="proto-badge proto-'+e.protocol+'">'+e.protocol+'</span></td>'+
    '<td class="fm" style="font-size:11px">'+(Math.round((e.confidence||0)*100))+'%</td>'+
    '<td class="fm text-dim" style="font-size:10px">'+(e.mitre_technique||'—')+'</td></tr>';
    if (e.mitre_tactic) mitreData[e.mitre_tactic]=(mitreData[e.mitre_tactic]||0)+1;
  });
  body.innerHTML=html;
}

// ================================================================
// ALERTS
// ================================================================
function onAlert(a) {
  alertCount++;
  document.getElementById('b-alerts').textContent = alertCount;
  var list = document.getElementById('alert-list');
  var first = list.querySelector('.text-dim');
  if (first) first.remove();
  var icons={CRITICAL:'🚨',HIGH:'🔴',MEDIUM:'🟡',LOW:'🔵'};
  var div=document.createElement('div'); div.className='alert-item';
  div.innerHTML='<div style="font-size:16px;flex-shrink:0">'+(icons[a.severity]||'⚠️')+'</div>'+
    '<div style="flex:1"><div style="font-weight:700;color:var(--text-bright);font-size:13px">'+a.category+'</div>'+
    '<div style="font-size:12px;color:var(--text-dim)">'+a.description+'</div>'+
    '<div class="fm text-dim" style="font-size:10px;margin-top:3px">'+a.src_ip+' → '+a.dst_ip+' | '+(a.confidence?Math.round(a.confidence*100)+'%':'')+'</div></div>'+
    '<div class="fm text-dim" style="font-size:10px;flex-shrink:0">'+((a.datetime||'').slice(11))+'</div>';
  list.insertBefore(div, list.firstChild);
  while(list.children.length>50) list.removeChild(list.lastChild);
}
function clearAlerts(){ document.getElementById('alert-list').innerHTML='<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">Cleared</div>'; alertCount=0; document.getElementById('b-alerts').textContent='0'; }

// ================================================================
// LIVE PACKETS
// ================================================================
setInterval(function(){
  if (!document.getElementById('panel-packets').classList.contains('active')) return;
  fetch('/api/packets?n=10').then(function(r){return r.json();}).then(function(pkts){
    var feed=document.getElementById('pkt-feed');
    pkts.slice(-5).forEach(function(p){
      var d=document.createElement('div'); d.className='feed-line';
      var ts=new Date(p.timestamp*1000).toTimeString().slice(0,8);
      d.innerHTML='<span class="feed-ts">'+ts+'</span><span class="feed-proto">'+p.protocol+'</span>'+
        '<span style="color:var(--text-main)">'+p.src_ip+':'+p.src_port+'</span>'+
        '<span class="text-dim" style="padding:0 4px">→</span>'+
        '<span class="text-dim">'+p.dst_ip+':'+p.dst_port+'</span>'+
        '<span style="color:var(--green-dim);margin-left:auto">'+p.packet_size+'B</span>';
      feed.appendChild(d); pktCount++;
      while(feed.children.length>100) feed.removeChild(feed.firstChild);
    });
    feed.scrollTop=feed.scrollHeight;
    document.getElementById('b-pkts').textContent=fmt(pktCount)+' pkts';
  }).catch(function(){});
}, 500);

// ================================================================
// FLOWS
// ================================================================
function loadFlows(){
  fetch('/api/flows').then(function(r){return r.json();}).then(function(fl){
    document.getElementById('b-flows').textContent=fl.length+' flows';
    var body=document.getElementById('flows-body');
    if(!fl.length){body.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--text-dim);padding:30px;font-family:var(--font-mono);font-size:11px">No active flows</td></tr>';return;}
    var html=''; fl.slice(0,100).forEach(function(f){
      html+='<tr><td class="fm" style="font-size:11px">'+f.src+'</td><td class="fm text-dim" style="font-size:11px">'+f.dst+'</td>'+
        '<td><span class="proto-badge proto-'+f.protocol+'">'+f.protocol+'</span></td>'+
        '<td class="fm">'+fmt(f.packets)+'</td><td class="fm">'+fmtB(f.bytes)+'</td>'+
        '<td class="fm text-accent">'+f.pps+'</td><td class="fm text-dim">'+f.duration+'s</td></tr>';
    }); body.innerHTML=html;
  });
}
setInterval(function(){ if(document.getElementById('panel-flows').classList.contains('active')) loadFlows(); },3000);

// ================================================================
// TOP TALKERS
// ================================================================
function loadTopTalkers(){
  fetch('/api/top-talkers?n=8').then(function(r){return r.json();}).then(function(tl){
    document.getElementById('b-talkers').textContent=tl.length;
    if(!tl.length) return;
    var max=tl[0].packets||1;
    var html=''; tl.forEach(function(t,i){
      html+='<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(15,61,92,0.3)">'+
        '<span class="fm text-dim" style="font-size:10px;width:16px">'+(i+1)+'</span>'+
        '<span class="fm" style="font-size:12px;flex:1;color:var(--text-main)">'+t.ip+'</span>'+
        '<div style="flex:1;height:5px;background:var(--bg-deep);border-radius:2px"><div style="height:100%;background:linear-gradient(90deg,var(--accent-dim),var(--accent));border-radius:2px;width:'+Math.round(t.packets/max*100)+'%"></div></div>'+
        '<span class="fm text-dim" style="font-size:10px;width:45px;text-align:right">'+fmt(t.packets)+'</span></div>';
    }); document.getElementById('top-talkers').innerHTML=html;
  });
}

// ================================================================
// MALWARE SCANNER
// ================================================================
function scanFile(){
  var fp=document.getElementById('scan-path').value.trim(); if(!fp)return;
  document.getElementById('scan-result').innerHTML='<div class="fm text-dim" style="font-size:11px;margin-top:10px">Scanning...</div>';
  fetch('/api/scan-file',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filepath:fp})})
    .then(function(r){return r.json();}).then(function(r){
      var c=r.is_malicious?'var(--red)':'var(--green)';
      document.getElementById('scan-result').innerHTML='<div style="background:var(--bg-deep);border:1px solid var(--border);border-radius:4px;padding:12px;margin-top:10px">'+
        '<div style="font-family:var(--font-title);font-size:18px;font-weight:700;color:'+c+';margin-bottom:8px">'+(r.is_malicious?'✗ THREAT: '+r.threat_name:'✓ CLEAN')+'</div>'+
        '<div class="fm text-dim" style="font-size:11px;line-height:2">Severity: '+r.severity+' | Confidence: '+Math.round((r.confidence||0)*100)+'%<br>'+
        'MD5: '+(r.details&&r.details.hashes?r.details.hashes.md5||'N/A':'N/A')+'<br>'+
        'Entropy: '+(r.details?r.details.entropy||'N/A':'N/A')+'</div>'+
        (r.indicators&&r.indicators.length?'<div class="fm text-red" style="font-size:11px;margin-top:8px">'+r.indicators.map(function(i){return '• '+i;}).join('<br>')+'</div>':'')+'</div>';
      loadMalware();
    }).catch(function(e){ document.getElementById('scan-result').innerHTML='<div class="fm text-red" style="font-size:11px;margin-top:8px">'+e.message+'</div>'; });
}
function loadMalware(){
  fetch('/api/malware?n=20').then(function(r){return r.json();}).then(function(res){
    if(!res.length)return;
    var html=''; res.reverse().forEach(function(r){
      html+='<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3)">'+
        '<div style="display:flex;justify-content:space-between"><span style="font-weight:600;color:var(--text-bright)">'+r.target+'</span><span class="sev-badge sev-'+r.severity+'">'+r.severity+'</span></div>'+
        '<div class="fm text-dim" style="font-size:10px">'+r.threat_name+' | '+Math.round((r.confidence||0)*100)+'% | '+r.datetime+'</div></div>';
    }); document.getElementById('malware-list').innerHTML=html;
  });
}

// ================================================================
// SIMULATE
// ================================================================
function simAttack(){
  var p={type:document.getElementById('sim-type').value,severity:document.getElementById('sim-sev').value,src_ip:document.getElementById('sim-src').value,dst_ip:document.getElementById('sim-dst').value};
  fetch('/api/simulate-attack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)})
    .then(function(r){return r.json();}).then(function(d){
      document.getElementById('sim-msg').innerHTML='<span class="text-green">✓ Injected: '+d.event.id+'</span>';
      var log=document.getElementById('sim-log');
      var first=log.querySelector('.text-dim'); if(first)first.remove();
      var ln=document.createElement('div'); ln.className='feed-line';
      ln.innerHTML='<span class="feed-ts">'+new Date().toTimeString().slice(0,8)+'</span><span style="color:var(--orange)">'+p.type+'</span><span class="text-dim">'+p.src_ip+'</span>';
      log.appendChild(ln); log.scrollTop=log.scrollHeight;
    }).catch(function(e){ document.getElementById('sim-msg').innerHTML='<span class="text-red">✗ '+e.message+'</span>'; });
}
function sleep(ms){return new Promise(function(r){setTimeout(r,ms);});}
async function simBurst(){
  var types=['port_scan','syn_flood','brute_force','dns_tunnel','malware'];
  document.getElementById('sim-msg').innerHTML='<span class="text-yellow">⚡ Burst sending...</span>';
  for(var i=0;i<types.length;i++){
    document.getElementById('sim-type').value=types[i];
    simAttack(); await sleep(400);
  }
  document.getElementById('sim-msg').innerHTML='<span class="text-green">✓ Burst complete</span>';
}

// ================================================================
// MITRE
// ================================================================
var MITRE_TACTICS=['Reconnaissance','Resource Dev','Initial Access','Execution','Persistence','Privilege Esc.','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','C2','Exfiltration','Impact','Evasion','Simulation','T1046','T1499','T1110','T1048','T1059','T1498','Unknown','ML-001'];
function renderMitre(){
  var g=document.getElementById('mitre-grid'); g.innerHTML='';
  MITRE_TACTICS.forEach(function(t){
    var cnt=Math.min(4,mitreData[t]||0);
    var colors=['background:var(--bg-deep);border:1px solid var(--border);color:var(--text-dim)','background:rgba(0,212,255,0.15);border:1px solid var(--accent-dim);color:var(--accent)','background:rgba(255,204,0,0.2);border:1px solid #886600;color:var(--yellow)','background:rgba(255,102,0,0.25);border:1px solid #883300;color:var(--orange)','background:rgba(255,34,68,0.3);border:1px solid var(--red-dim);color:var(--red)'];
    var d=document.createElement('div');
    d.style.cssText='aspect-ratio:1;border-radius:3px;display:flex;align-items:center;justify-content:center;cursor:pointer;'+colors[cnt];
    d.title=t+': '+(mitreData[t]||0)+' events';
    d.innerHTML='<div style="text-align:center;line-height:1.3"><div style="font-size:7px;font-family:var(--font-mono)">'+t.slice(0,8)+'</div><div style="font-size:10px;font-weight:700;font-family:var(--font-mono)">'+(mitreData[t]||0)+'</div></div>';
    g.appendChild(d);
  });
}

// ================================================================
// THREAT INTEL
// ================================================================
function intelLookup(){
  var ip=document.getElementById('intel-ip').value.trim(); if(!ip)return;
  document.getElementById('intel-result').innerHTML='<div class="fm text-dim" style="font-size:11px;padding:8px">Looking up '+ip+'...</div>';
  fetch('/api/intel/lookup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})})
    .then(function(r){return r.json();}).then(function(d){
      var rc={LOW:'var(--green)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)',PRIVATE:'var(--green)',UNKNOWN:'var(--text-dim)'};
      var c=rc[d.risk_level]||'var(--text-dim)';
      document.getElementById('intel-result').innerHTML='<div style="background:var(--bg-deep);border:1px solid var(--border);border-radius:4px;padding:12px;margin-top:8px">'+
        '<div style="display:flex;justify-content:space-between;margin-bottom:8px"><span class="fm" style="font-size:14px;font-weight:700;color:var(--text-bright)">'+d.ip+'</span><span class="sev-badge" style="color:'+c+';border-color:'+c+'">'+d.risk_level+'</span></div>'+
        '<div class="fm" style="font-size:11px;display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:8px">'+
        '<div><span class="text-dim">VirusTotal:</span> <span class="text-accent">'+(d.virustotal_score||'N/A')+'</span></div>'+
        '<div><span class="text-dim">AbuseIPDB:</span> <span style="color:'+(d.abuseipdb_score>50?'var(--red)':'var(--green)')+'">'+((d.abuseipdb_score!=null)?d.abuseipdb_score+'%':'N/A')+'</span></div>'+
        '<div><span class="text-dim">Country:</span> '+(d.abuseipdb_country||'Unknown')+'</div>'+
        '<div><span class="text-dim">ISP:</span> '+(d.abuseipdb_isp||'Unknown')+'</div></div>'+
        (d.tags&&d.tags.length?'<div>'+d.tags.map(function(t){return '<span style="background:var(--bg-panel);border:1px solid var(--border);padding:2px 6px;border-radius:2px;margin:2px;display:inline-block;font-size:10px;font-family:var(--font-mono)">'+t+'</span>';}).join('')+'</div>':'')+'</div>';
      loadIntelHistory();
    }).catch(function(e){ document.getElementById('intel-result').innerHTML='<div class="fm text-red" style="font-size:11px">'+e.message+'</div>'; });
}
function loadIntelHistory(){
  fetch('/api/intel/results?n=20').then(function(r){return r.json();}).then(function(res){
    document.getElementById('b-intel').textContent=res.length;
    var rc={LOW:'var(--green)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)',PRIVATE:'var(--green)',UNKNOWN:'var(--text-dim)'};
    document.getElementById('intel-history').innerHTML=res.length?res.map(function(d){
      return '<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3);cursor:pointer" onclick="document.getElementById(\'intel-ip\').value=\''+d.ip+'\'">'+
        '<div style="display:flex;justify-content:space-between"><span class="fm" style="color:var(--text-bright);font-weight:700">'+d.ip+'</span><span style="color:'+(rc[d.risk_level]||'var(--text-dim)')+';font-size:11px;font-weight:700">'+d.risk_level+'</span></div>'+
        '<div class="fm text-dim" style="font-size:10px">'+d.datetime+'</div></div>';
    }).join(''):'<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No lookups yet</div>';
  });
}
function saveIntelKeys(){
  fetch('/api/intel/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({virustotal_key:document.getElementById('vt-key').value,abuseipdb_key:document.getElementById('abuse-key').value})})
    .then(function(){ document.getElementById('intel-key-msg').innerHTML='<span class="text-green">✓ Saved</span>'; })
    .catch(function(){ document.getElementById('intel-key-msg').innerHTML='<span class="text-red">✗ Failed</span>'; });
}

// ================================================================
// NETWORK SCANNER
// ================================================================
function startScan(ports){
  var net=document.getElementById('scan-net').value.trim()||null;
  document.getElementById('scan-dot').style.background='var(--green)';
  document.getElementById('scan-dot').style.animation='blink 1s infinite';
  document.getElementById('scan-lbl').textContent='SCANNING...';
  document.getElementById('scan-bar').style.width='5%';
  fetch('/api/scan/network',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({network:net,port_scan:ports})})
    .then(function(){ pollScan(); }).catch(function(){ document.getElementById('scan-lbl').textContent='ERROR'; });
}
function pollScan(){
  var iv=setInterval(function(){
    fetch('/api/scan/status').then(function(r){return r.json();}).then(function(s){
      var pct=s.total>0?Math.round(s.progress/s.total*100):10;
      document.getElementById('scan-bar').style.width=pct+'%';
      document.getElementById('scan-txt').textContent='Scanned '+s.progress+'/'+s.total+' — '+s.devices_found+' found';
      if(!s.scanning){ clearInterval(iv); document.getElementById('scan-dot').style.animation='none'; document.getElementById('scan-lbl').textContent='COMPLETE'; document.getElementById('scan-bar').style.width='100%'; loadDevices(); }
    }).catch(function(){ clearInterval(iv); });
  },1000);
}
function loadDevices(){
  fetch('/api/scan/devices').then(function(r){return r.json();}).then(function(devs){
    document.getElementById('b-devices').textContent=devs.length+' devices';
    if(!devs.length)return;
    var rc={LOW:'var(--accent)',MEDIUM:'var(--yellow)',HIGH:'var(--red)'};
    var html=''; devs.forEach(function(d){
      html+='<tr><td class="fm text-accent">'+d.ip+'</td><td class="fm text-dim" style="font-size:11px">'+(d.hostname||'—')+'</td><td style="font-size:11px">'+(d.vendor||'Unknown')+'</td>'+
        '<td class="fm" style="font-size:10px">'+d.open_ports.map(function(p){return '<span style="color:var(--accent)">'+p.port+'/'+p.service+'</span>';}).join(' ')+'</td>'+
        '<td style="font-size:11px;color:var(--text-dim)">'+d.os_guess+'</td>'+
        '<td style="color:'+(rc[d.risk]||'var(--text-dim)')+';font-weight:700;font-size:11px">'+d.risk+'</td>'+
        '<td class="fm text-dim" style="font-size:11px">'+d.response_time_ms+'ms</td>'+
        '<td><button class="btn" style="padding:2px 6px;font-size:10px" onclick="document.getElementById(\'blk-ip\').value=\''+d.ip+'\';showPanel(\'blocker\',document.querySelector(\'[data-panel=blocker]\'))">🚫</button></td></tr>';
    }); document.getElementById('devices-body').innerHTML=html;
  });
}

// ================================================================
// PACKET INSPECTOR
// ================================================================
function loadInspector(){
  var proto=document.getElementById('ins-proto').value;
  var url='/api/inspect/packets?n=100'+(proto?'&protocol='+proto:'');
  fetch(url).then(function(r){return r.json();}).then(function(pkts){
    var body=document.getElementById('ins-body');
    if(!pkts.length){body.innerHTML='<tr><td colspan="9" style="text-align:center;color:var(--text-dim);padding:30px;font-family:var(--font-mono);font-size:11px">No packets yet</td></tr>';return;}
    var html=''; pkts.slice().reverse().slice(0,100).forEach(function(p){
      html+='<tr><td class="fm text-dim" style="font-size:10px">'+p.id+'</td>'+
        '<td class="fm text-dim" style="font-size:10px">'+((p.datetime||'').slice(11))+'</td>'+
        '<td><span class="proto-badge proto-'+p.protocol+'">'+p.protocol+'</span></td>'+
        '<td class="fm" style="font-size:11px">'+p.src_ip+':'+p.src_port+'</td>'+
        '<td class="fm text-dim" style="font-size:11px">'+p.dst_ip+':'+p.dst_port+'</td>'+
        '<td class="fm text-dim" style="font-size:11px">'+p.size+'B</td>'+
        '<td class="fm text-accent" style="font-size:10px">'+(p.flags||'—')+'</td>'+
        '<td>'+(p.anomalies&&p.anomalies.length?'<span class="text-red" style="font-size:10px">⚠ '+p.anomalies.length+'</span>':'<span class="text-dim" style="font-size:10px">—</span>')+'</td>'+
        '<td><button class="btn" style="padding:2px 6px;font-size:10px" onclick="showPktDetail('+p.id+')">VIEW</button></td></tr>';
    }); body.innerHTML=html;
  });
}
function showPktDetail(id){
  fetch('/api/inspect/packet/'+id).then(function(r){return r.json();}).then(function(p){
    var card=document.getElementById('ins-detail'); card.style.display='block';
    document.getElementById('ins-detail-body').innerHTML=
      '<div class="fm" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;font-size:11px;margin-bottom:12px">'+
      '<div><span class="text-dim">Proto:</span> <span class="text-accent">'+p.protocol+'</span></div>'+
      '<div><span class="text-dim">Src:</span> '+p.src_ip+':'+p.src_port+'</div>'+
      '<div><span class="text-dim">Dst:</span> '+p.dst_ip+':'+p.dst_port+'</div>'+
      '<div><span class="text-dim">Size:</span> '+p.size+'B</div>'+
      '<div><span class="text-dim">TTL:</span> '+p.ttl+'</div>'+
      '<div><span class="text-dim">Flags:</span> <span class="text-accent">'+(p.flags||'—')+'</span></div></div>'+
      (p.anomalies&&p.anomalies.length?'<div class="fm text-red" style="font-size:11px;margin-bottom:8px">⚠ '+p.anomalies.join(' | ')+'</div>':'')+
      (p.payload_hex?'<div style="background:var(--bg-void);padding:10px;border-radius:3px;font-family:var(--font-mono);font-size:11px"><div class="text-dim">HEX: <span class="text-green">'+(p.payload_hex.match(/.{1,2}/g)||[]).join(' ')+'</span></div><div class="text-dim" style="margin-top:4px">ASCII: <span class="text-accent">'+p.payload_ascii+'</span></div></div>':'');
    card.scrollIntoView({behavior:'smooth'});
  });
}
setInterval(function(){ if(document.getElementById('panel-inspector').classList.contains('active')) loadInspector(); },2000);

// ================================================================
// IP BLOCKER
// ================================================================
function blockIP(){
  var ip=document.getElementById('blk-ip').value.trim(); if(!ip)return;
  fetch('/api/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip,severity:document.getElementById('blk-sev').value,reason:document.getElementById('blk-reason').value})})
    .then(function(r){return r.json();}).then(function(d){
      document.getElementById('blk-msg').innerHTML=d.success?'<span class="text-green">✓ '+ip+' blocked via '+d.method+'</span>':'<span class="text-orange">⚠ '+d.error+'</span>';
      loadBlockList();
    }).catch(function(e){ document.getElementById('blk-msg').innerHTML='<span class="text-red">✗ '+e.message+'</span>'; });
}
function unblockIP(ip){
  fetch('/api/block/'+encodeURIComponent(ip),{method:'DELETE'}).then(function(){ loadBlockList(); });
}
function loadBlockList(){
  fetch('/api/block/list').then(function(r){return r.json();}).then(function(list){
    document.getElementById('b-blocked').textContent=list.filter(function(b){return b.active;}).length;
    document.getElementById('blocked-list').innerHTML=list.length?list.map(function(b){
      return '<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3);display:flex;justify-content:space-between;align-items:center">'+
        '<div><div class="fm" style="color:'+(b.active?'var(--red)':'var(--text-dim)')+';font-weight:700">'+b.ip+' '+(b.active?'🚫':'')+'</div>'+
        '<div class="fm text-dim" style="font-size:10px">'+b.reason+' | '+b.datetime+'</div></div>'+
        (b.active?'<button class="btn" style="padding:3px 8px;font-size:10px;border-color:var(--green);color:var(--green)" onclick="unblockIP(\''+b.ip+'\')">UNBLOCK</button>':'<span class="fm text-dim" style="font-size:10px">inactive</span>')+'</div>';
    }).join(''):'<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">None blocked</div>';
    fetch('/api/block/stats').then(function(r){return r.json();}).then(function(s){
      document.getElementById('blk-stats').innerHTML='Active: <span class="text-red">'+s.active_blocks+'</span><br>Total: <span class="text-accent">'+s.total_blocked+'</span><br>Method: <span class="text-green">'+s.method+'</span><br>Admin: <span class="'+(s.has_admin?'text-green':'text-orange')+'">'+(s.has_admin?'YES':'NO — soft block')+'</span>';
    });
  });
}
function saveAutoBlock(){
  fetch('/api/block/auto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:document.getElementById('auto-blk').checked,min_severity:document.getElementById('auto-sev').value})})
    .then(function(){ document.getElementById('blk-msg').innerHTML='<span class="text-green">✓ Auto-block saved</span>'; });
}

// ================================================================
// DARK WEB MONITOR
// ================================================================
function dwCheck(){
  var q=document.getElementById('dw-q').value.trim(); var t=document.getElementById('dw-t').value; if(!q)return;
  document.getElementById('dw-result').innerHTML='<div class="fm text-dim" style="font-size:11px;padding:8px">Checking '+q+'...</div>';
  fetch('/api/darkweb/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:q,type:t})})
    .then(function(r){return r.json();}).then(function(d){ renderDWResult(d); loadDWHistory(); loadDWStats(); })
    .catch(function(e){ document.getElementById('dw-result').innerHTML='<div class="fm text-red" style="font-size:11px">'+e.message+'</div>'; });
}
function dwQuick(q,t){ document.getElementById('dw-q').value=q; document.getElementById('dw-t').value=t; dwCheck(); }
function renderDWResult(d){
  var rc={LOW:'var(--green)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
  var color=rc[d.risk_level]||'var(--text-dim)';
  var badges='';
  if(d.is_tor_exit) badges+='<span style="background:rgba(170,68,255,0.2);border:1px solid #aa44ff;color:#cc88ff;padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">TOR EXIT</span>';
  if(d.is_botnet) badges+='<span style="background:rgba(255,34,68,0.2);border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">BOTNET C2</span>';
  if(d.is_ransomware_infra) badges+='<span style="background:rgba(255,34,68,0.3);border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">RANSOMWARE: '+d.ransomware_group+'</span>';
  if(d.found_in_breach) badges+='<span style="background:rgba(255,102,0,0.2);border:1px solid var(--orange);color:var(--orange);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">'+d.breach_count+' BREACH(ES)</span>';
  var bHTML='';
  if(d.breaches&&d.breaches.length){ d.breaches.forEach(function(b){ bHTML+='<div style="background:rgba(255,34,68,0.08);border-left:3px solid var(--red-dim);padding:8px 12px;margin-bottom:6px;border-radius:0 3px 3px 0"><div style="font-weight:700;color:var(--text-bright);font-size:12px">'+b.name+'</div><div class="fm text-dim" style="font-size:10px">'+b.type+' | '+b.year+' | '+b.source+'</div></div>'; }); }
  else bHTML='<div style="color:var(--green);font-family:var(--font-mono);font-size:12px;margin-bottom:8px">Not found in breach databases</div>';
  var rHTML='';
  if(d.recommendations&&d.recommendations.length){ d.recommendations.forEach(function(r){ rHTML+='<div class="fm text-dim" style="font-size:11px;margin-bottom:4px"><span style="color:var(--accent)">▶</span> '+r+'</div>'; }); }
  document.getElementById('dw-result').innerHTML='<div style="background:var(--bg-deep);border:2px solid '+color+';border-radius:4px;padding:14px;margin-top:8px">'+
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><span class="fm" style="font-size:14px;font-weight:700;color:var(--text-bright)">'+d.query+'</span>'+
    '<div style="text-align:right"><div style="font-family:var(--font-title);font-size:20px;font-weight:700;color:'+color+'">'+d.risk_score+'</div><div class="fm" style="font-size:10px;color:'+color+'">'+d.risk_level+' RISK</div></div></div>'+
    (badges?'<div style="margin-bottom:10px">'+badges+'</div>':'')+bHTML+
    (rHTML?'<div style="border-top:1px solid var(--border);padding-top:8px;margin-top:8px">'+rHTML+'</div>':'')+
    '<div style="border-top:1px solid var(--border);padding-top:8px;margin-top:8px;display:flex;gap:8px">'+
    '<button class="btn danger" style="font-size:11px;padding:4px 10px" onclick="document.getElementById(\'blk-ip\').value=\''+d.query+'\';showPanel(\'blocker\',document.querySelector(\'[data-panel=blocker]\'))">🚫 Block</button>'+
    '<button class="btn" style="font-size:11px;padding:4px 10px" onclick="document.getElementById(\'dw-watch-q\').value=\''+d.query+'\';addDWWatch()">👁 Watch</button></div></div>';
}
function loadDWHistory(){
  fetch('/api/darkweb/results?n=30').then(function(r){return r.json();}).then(function(res){
    document.getElementById('b-dw-hist').textContent=res.length;
    var rc={LOW:'var(--green)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
    document.getElementById('dw-history').innerHTML=res.length?res.map(function(d){
      var tags='';
      if(d.is_tor_exit) tags+='<span style="font-size:9px;color:#cc88ff;font-family:var(--font-mono)">TOR </span>';
      if(d.is_botnet) tags+='<span style="font-size:9px;color:var(--red);font-family:var(--font-mono)">BOTNET </span>';
      if(d.is_ransomware_infra) tags+='<span style="font-size:9px;color:var(--red);font-family:var(--font-mono)">RANSOMWARE </span>';
      if(d.found_in_breach) tags+='<span style="font-size:9px;color:var(--orange);font-family:var(--font-mono)">'+d.breach_count+' BREACH </span>';
      return '<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3);cursor:pointer" onclick="dwQuick(\''+d.query+'\',\''+d.query_type+'\')">'+
        '<div style="display:flex;justify-content:space-between"><span class="fm" style="color:var(--text-bright);font-weight:700">'+d.query+'</span>'+
        '<span style="color:'+(rc[d.risk_level]||'var(--text-dim)')+';font-size:12px;font-weight:700;font-family:var(--font-mono)">'+d.risk_score+' '+d.risk_level+'</span></div>'+
        '<div style="margin-top:3px">'+tags+'<span class="fm text-dim" style="font-size:9px">'+d.datetime+'</span></div></div>';
    }).join(''):'<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No checks yet</div>';
  });
}
function loadDWStats(){
  fetch('/api/darkweb/stats').then(function(r){return r.json();}).then(function(s){
    var t=document.getElementById('dw-total'); if(t)t.textContent=s.total_checks;
    var b=document.getElementById('dw-breached'); if(b)b.textContent=s.breached_found;
    var c=document.getElementById('dw-critical'); if(c)c.textContent=s.critical_findings;
    var w=document.getElementById('dw-watching'); if(w)w.textContent=s.monitoring_targets;
  });
}
function saveDWKey(){
  fetch('/api/darkweb/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hibp_key:document.getElementById('hibp-key').value})})
    .then(function(){ document.getElementById('dw-key-msg').innerHTML='<span class="text-green">✓ Saved</span>'; })
    .catch(function(){ document.getElementById('dw-key-msg').innerHTML='<span class="text-red">✗ Failed</span>'; });
}
function addDWWatch(){
  var q=document.getElementById('dw-watch-q').value.trim(); if(!q)return;
  fetch('/api/darkweb/monitor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:q,type:'auto'})})
    .then(function(){ document.getElementById('dw-watch-q').value=''; loadDWWatchList(); loadDWStats(); });
}
function removeDWWatch(q){
  fetch('/api/darkweb/monitor/'+encodeURIComponent(q),{method:'DELETE'}).then(function(){ loadDWWatchList(); loadDWStats(); });
}
function loadDWWatchList(){
  fetch('/api/darkweb/monitor/list').then(function(r){return r.json();}).then(function(list){
    document.getElementById('b-watching').textContent=list.length;
    document.getElementById('dw-watch-list').innerHTML=list.length?list.map(function(t){
      return '<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 2px;border-bottom:1px solid rgba(15,61,92,0.3)">'+
        '<span class="fm text-accent" style="font-size:12px">'+t.query+'</span>'+
        '<button class="btn" style="padding:2px 6px;font-size:10px;border-color:var(--red);color:var(--red)" onclick="removeDWWatch(\''+t.query+'\')">✕</button></div>';
    }).join(''):'<div class="text-dim fm" style="font-size:11px;padding:10px;text-align:center">No targets</div>';
  });
}

// ================================================================
// ALERT CONFIG
// ================================================================
function saveEmailCfg(){
  fetch('/api/config/alert',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email_enabled:document.getElementById('email-on').checked,smtp_host:document.getElementById('smtp-host').value,smtp_port:parseInt(document.getElementById('smtp-port').value),smtp_user:document.getElementById('email-from').value,smtp_password:document.getElementById('email-pass').value,email_from:document.getElementById('email-from').value,email_to:document.getElementById('email-to').value.split(',').map(function(s){return s.trim();}),email_min_severity:document.getElementById('email-sev').value})})
    .then(function(){ document.getElementById('email-msg').innerHTML='<span class="text-green">✓ Saved</span>'; })
    .catch(function(){ document.getElementById('email-msg').innerHTML='<span class="text-red">✗ Failed</span>'; });
}
function saveWebhook(){
  fetch('/api/config/alert',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({webhook_enabled:document.getElementById('wh-on').checked,webhook_url:document.getElementById('wh-url').value,webhook_min_severity:document.getElementById('wh-sev').value})})
    .then(function(){ document.getElementById('wh-msg').innerHTML='<span class="text-green">✓ Saved</span>'; })
    .catch(function(){ document.getElementById('wh-msg').innerHTML='<span class="text-red">✗ Failed</span>'; });
}

// ================================================================
// REPORTS
// ================================================================
function loadRptSummary(){
  fetch('/api/status').then(function(r){return r.json();}).then(function(s){
    var ec=s.event_counts||{};
    document.getElementById('rpt-summary').innerHTML='<div class="fm" style="font-size:12px;line-height:2.2">'+
      '<div><span class="text-dim">Packets:</span> <span class="text-accent">'+fmt(s.total_packets||0)+'</span></div>'+
      '<div><span class="text-dim">Bytes:</span> <span class="text-accent">'+fmtB(s.total_bytes||0)+'</span></div>'+
      '<div><span class="text-dim">Uptime:</span> <span class="text-accent">'+Math.floor((s.uptime_secs||0)/60)+'m '+((s.uptime_secs||0)%60|0)+'s</span></div>'+
      '<div><span class="text-dim">CRITICAL:</span> <span class="text-red">'+(ec.CRITICAL||0)+'</span></div>'+
      '<div><span class="text-dim">HIGH:</span> <span class="text-orange">'+(ec.HIGH||0)+'</span></div>'+
      '<div><span class="text-dim">MEDIUM:</span> <span class="text-yellow">'+(ec.MEDIUM||0)+'</span></div>'+
      '<div><span class="text-dim">Alerts:</span> <span class="text-accent">'+(s.alert_stats&&s.alert_stats.total_dispatched?s.alert_stats.total_dispatched:0)+'</span></div>'+
      '<div><span class="text-dim">ML:</span> <span class="'+(s.ml_trained?'text-green':'text-dim')+'">'+(s.ml_trained?'TRAINED':'TRAINING')+'</span></div></div>';
  });
}

// ================================================================
// HELPERS
// ================================================================
function fmt(n){ if(n>=1e9)return (n/1e9).toFixed(1)+'B'; if(n>=1e6)return (n/1e6).toFixed(1)+'M'; if(n>=1e3)return (n/1e3).toFixed(1)+'K'; return String(n||0); }
function fmtB(b){ if(b>=1e9)return (b/1e9).toFixed(2)+' GB'; if(b>=1e6)return (b/1e6).toFixed(2)+' MB'; if(b>=1e3)return (b/1e3).toFixed(1)+' KB'; return (b||0)+' B'; }
function renderProtoLegend(pr){ var cols={TCP:'#00d4ff',UDP:'#00ff88',ICMP:'#ff6600',OTHER:'#aa44ff'}; var tot=Object.values(pr).reduce(function(a,b){return a+b;},0)||1; document.getElementById('proto-legend').innerHTML=Object.entries(pr).map(function(e){return '<div style="display:flex;align-items:center;gap:6px"><div style="width:10px;height:10px;border-radius:50%;background:'+(cols[e[0]]||'#888')+'"></div><span>'+e[0]+'</span><span class="text-dim" style="margin-left:auto">'+Math.round(e[1]/tot*100)+'%</span></div>';}).join(''); }
function renderProtoStats(pr){ var cols={TCP:'var(--accent)',UDP:'var(--green)',ICMP:'var(--orange)',OTHER:'var(--purple)'}; document.getElementById('proto-stats').innerHTML=Object.entries(pr).map(function(e){return '<div style="color:'+(cols[e[0]]||'var(--text-dim)')+'">'+e[0]+': <strong>'+fmt(e[1])+'</strong> packets</div>';}).join(''); }
</script>
</body>
</html>"""

with open(path, "w", encoding="utf-8") as f:
    f.write(HTML)

print("Done! Clean index.html written (" + str(len(HTML)) + " chars)")
