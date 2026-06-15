import os

# ── Update dashboard_server.py ────────────────────────────────
srv = open("dashboard/dashboard_server.py", encoding="utf-8").read()

# Add imports
if "AIAssistant" not in srv:
    srv = srv.replace(
        "from core.darkweb_monitor",
        "from core.ai_assistant     import AIAssistant\n"
        "from core.geoip_map        import GeoIPMap\n"
        "from core.vuln_scanner     import VulnerabilityScanner\n"
        "from core.honeypot         import HoneypotManager\n"
        "from core.timeline         import TimelineEngine\n"
        "from core.darkweb_monitor"
    )

# Add instances
if "ai_assistant" not in srv:
    srv = srv.replace(
        "darkweb      = DarkWebMonitor()",
        "darkweb      = DarkWebMonitor()\n"
        "ai           = AIAssistant()\n"
        "geomap       = GeoIPMap()\n"
        "vulns        = VulnerabilityScanner()\n"
        "honeypots    = HoneypotManager()\n"
        "timeline     = TimelineEngine()"
    )

# Hook threat events into new modules
if "geomap.track_event" not in srv:
    srv = srv.replace(
        "    alert_system.dispatch(event)\n    socketio.emit(\"threat_event\", event.to_dict())",
        "    alert_system.dispatch(event)\n"
        "    socketio.emit(\"threat_event\", event.to_dict())\n"
        "    geomap.track_event(event.to_dict())\n"
        "    timeline.ingest(event.to_dict())"
    )

# Hook honeypot events
if "honeypot_event" not in srv:
    srv = srv.replace(
        "def start_system():",
        "def on_honeypot_event(event):\n"
        "    socketio.emit('honeypot_event', event.to_dict())\n\n"
        "honeypots._callback = on_honeypot_event\n\n"
        "def start_system():"
    )

# Add all new routes before websocket section
NEW_ROUTES = '''
# ── AI ASSISTANT ──────────────────────────────────────────────
@app.route("/api/ai/chat", methods=["POST"])
def api_ai_chat():
    data = request.get_json() or {}
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "message required"}), 400
    # Update AI context with live data
    try:
        ctx = {
            "stats": monitor.stats.copy(),
            "events": detector.get_recent_events(50),
            "blocked_ips": blocker.get_blocked_ips(),
            "malware": analyzer.get_results(20),
            "darkweb": darkweb.get_results(20),
            "top_talkers": monitor.get_top_talkers(10),
        }
        ctx["stats"]["ml_trained"] = detector.ml_detector._trained
        ai.set_context(ctx)
    except Exception:
        pass
    reply = ai.chat(message)
    socketio.emit("ai_reply", {"message": message, "reply": reply})
    return jsonify({"reply": reply})

@app.route("/api/ai/prompts")
def api_ai_prompts():
    return jsonify(ai.get_quick_prompts())

@app.route("/api/ai/history")
def api_ai_history():
    return jsonify(ai.get_chat_log())

@app.route("/api/ai/clear", methods=["POST"])
def api_ai_clear():
    ai.clear_history()
    return jsonify({"status": "ok"})

# ── GEOIP MAP ─────────────────────────────────────────────────
@app.route("/api/geo/map")
def api_geo_map():
    return jsonify(geomap.get_map_data())

@app.route("/api/geo/lookup", methods=["POST"])
def api_geo_lookup():
    data = request.get_json() or {}
    ip = data.get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    return jsonify(geomap.lookup(ip).to_dict())

@app.route("/api/geo/countries")
def api_geo_countries():
    return jsonify(geomap.get_top_countries())

# ── VULNERABILITY SCANNER ─────────────────────────────────────
@app.route("/api/vuln/scan", methods=["POST"])
def api_vuln_scan():
    data = request.get_json() or {}
    devices = data.get("devices") or scanner.get_devices()
    if not devices:
        return jsonify({"error": "no devices — run network scan first"}), 400
    def run():
        def cb(r): socketio.emit("vuln_result", r)
        vulns.scan_all(devices, callback=cb)
        socketio.emit("vuln_complete", vulns.get_stats())
    import threading
    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "scanning", "devices": len(devices)})

@app.route("/api/vuln/results")
def api_vuln_results():
    return jsonify(vulns.get_results())

@app.route("/api/vuln/critical")
def api_vuln_critical():
    return jsonify(vulns.get_critical())

@app.route("/api/vuln/stats")
def api_vuln_stats():
    return jsonify(vulns.get_stats())

# ── HONEYPOT ──────────────────────────────────────────────────
@app.route("/api/honeypot/start", methods=["POST"])
def api_honeypot_start():
    data = request.get_json() or {}
    service = data.get("service")
    if service:
        ok = honeypots.start_service(service, data.get("port"))
        return jsonify({"status": "started" if ok else "failed", "service": service})
    results = honeypots.start_all()
    return jsonify(results)

@app.route("/api/honeypot/stop", methods=["POST"])
def api_honeypot_stop():
    data = request.get_json() or {}
    service = data.get("service")
    if service:
        honeypots.stop_service(service)
        return jsonify({"status": "stopped", "service": service})
    honeypots.stop_all()
    return jsonify({"status": "all stopped"})

@app.route("/api/honeypot/status")
def api_honeypot_status():
    return jsonify(honeypots.get_status())

@app.route("/api/honeypot/events")
def api_honeypot_events():
    n = int(request.args.get("n", 100))
    svc = request.args.get("service")
    return jsonify(honeypots.get_events(n, svc))

@app.route("/api/honeypot/stats")
def api_honeypot_stats():
    return jsonify(honeypots.get_stats())

# ── TIMELINE ──────────────────────────────────────────────────
@app.route("/api/timeline/events")
def api_timeline_events():
    limit = int(request.args.get("limit", 200))
    hours = request.args.get("hours")
    src = request.args.get("src_ip")
    stage = request.args.get("stage")
    sev = request.args.get("severity")
    return jsonify(timeline.get_timeline(
        limit=limit,
        hours=int(hours) if hours else None,
        src_ip=src, stage=stage, severity=sev
    ))

@app.route("/api/timeline/campaigns")
def api_timeline_campaigns():
    active = request.args.get("active") == "true"
    return jsonify(timeline.get_campaigns(active_only=active))

@app.route("/api/timeline/killchain")
def api_timeline_killchain():
    return jsonify(timeline.get_kill_chain())

@app.route("/api/timeline/heatmap")
def api_timeline_heatmap():
    hours = int(request.args.get("hours", 24))
    return jsonify(timeline.get_heatmap(hours))

@app.route("/api/timeline/stats")
def api_timeline_stats():
    return jsonify(timeline.get_stats())

'''

if "/api/ai/chat" not in srv:
    srv = srv.replace("# ── WebSocket", NEW_ROUTES + "# ── WebSocket")

open("dashboard/dashboard_server.py", "w", encoding="utf-8").write(srv)
print("dashboard_server.py updated with all Phase 3 routes")

# ── Write rebuild_v3.py ───────────────────────────────────────
# This patches index.html to add 5 new tabs
patch = open("dashboard/index.html", encoding="utf-8").read()

NAV_ADDITION = """
    <div class="nav-sec">PHASE 3</div>
    <div class="nav-item" onclick="showPanel('ai',this)" data-panel="ai"><span class="nav-icon">🤖</span> AI Assistant</div>
    <div class="nav-item" onclick="showPanel('geomap',this)" data-panel="geomap"><span class="nav-icon">🌍</span> World Map</div>
    <div class="nav-item" onclick="showPanel('vulns',this)" data-panel="vulns"><span class="nav-icon">🔓</span> CVE Scanner</div>
    <div class="nav-item" onclick="showPanel('honeypot',this)" data-panel="honeypot"><span class="nav-icon">🍯</span> Honeypot</div>
    <div class="nav-item" onclick="showPanel('tl',this)" data-panel="tl"><span class="nav-icon">📅</span> Timeline</div>
"""

if "panel-ai" not in patch:
    patch = patch.replace("</nav>", NAV_ADDITION + "</nav>")

    PANELS = """
    <!-- AI ASSISTANT -->
    <div class="panel" id="panel-ai">
      <div class="grid-2">
        <div class="card" style="display:flex;flex-direction:column">
          <div class="card-header"><div class="card-title">🤖 CYBERSHIELD AI ASSISTANT</div><button class="btn" onclick="aiClear()" style="padding:3px 10px;font-size:11px">CLEAR</button></div>
          <div id="ai-chat" style="flex:1;min-height:400px;max-height:500px;overflow-y:auto;padding:16px;background:var(--bg-deep);font-family:var(--font-mono);font-size:12px;line-height:1.6">
            <div style="color:var(--accent);margin-bottom:12px">CyberShield AI ready. Ask me anything about your network security.</div>
          </div>
          <div style="padding:12px;border-top:1px solid var(--border);display:flex;gap:8px">
            <input type="text" class="inp" id="ai-input" placeholder="Ask about your network..." style="flex:1" onkeydown="if(event.key==='Enter')aiSend()">
            <button class="btn primary" onclick="aiSend()">SEND</button>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">QUICK PROMPTS</div></div>
          <div class="card-body">
            <div id="ai-prompts" style="display:flex;flex-direction:column;gap:8px"></div>
            <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px;font-family:var(--font-mono);font-size:10px;color:var(--text-dim);line-height:1.8">
              Powered by Claude AI (claude-sonnet-4-6)<br>
              Analyzes live network data in context<br>
              Works offline with built-in demo responses
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- WORLD MAP -->
    <div class="panel" id="panel-geomap">
      <div class="metrics-row" style="margin-bottom:16px">
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">ATTACK ORIGINS</div><div class="metric-value" id="geo-origins">0</div><div class="metric-sub">unique source IPs</div></div>
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">COUNTRIES</div><div class="metric-value" id="geo-countries">0</div><div class="metric-sub">attack sources</div></div>
        <div class="metric-card warn"><div class="metric-glow"></div><div class="metric-label">RECENT ATTACKS</div><div class="metric-value" id="geo-recent">0</div><div class="metric-sub">last 20 geolocated</div></div>
        <div class="metric-card purple"><div class="metric-glow"></div><div class="metric-label">TOP COUNTRY</div><div class="metric-value" id="geo-top" style="font-size:18px">—</div><div class="metric-sub">most attacks</div></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><div class="card-title">🌍 ATTACK ORIGIN MAP</div><button class="btn primary" onclick="loadGeoMap()" style="padding:4px 12px;font-size:11px">↻ REFRESH</button></div>
          <div id="geo-map-container" style="height:400px;background:var(--bg-deep);border-radius:2px;position:relative;overflow:hidden">
            <canvas id="geo-canvas" style="width:100%;height:100%"></canvas>
            <div id="geo-tooltip" style="display:none;position:absolute;background:var(--bg-card);border:1px solid var(--border);padding:8px 12px;border-radius:3px;font-family:var(--font-mono);font-size:11px;pointer-events:none;z-index:10"></div>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">TOP ATTACK COUNTRIES</div></div>
          <div class="card-body" id="geo-countries-list"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No geo data yet — inject attacks to populate</div></div>
        </div>
      </div>
      <div class="card" style="margin-top:16px">
        <div class="card-header"><div class="card-title">ATTACK ORIGINS DETAIL</div><div class="card-badge" id="b-geo-origins">0</div></div>
        <div style="overflow-x:auto"><table class="ttable"><thead><tr><th>IP</th><th>COUNTRY</th><th>CITY</th><th>ISP</th><th>ATTACKS</th><th>RISK</th><th>LAST SEEN</th><th>ACTION</th></tr></thead><tbody id="geo-table"></tbody></table></div>
      </div>
    </div>

    <!-- CVE SCANNER -->
    <div class="panel" id="panel-vulns">
      <div class="metrics-row" style="margin-bottom:16px">
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">HOSTS SCANNED</div><div class="metric-value" id="vuln-hosts">0</div><div class="metric-sub">devices checked</div></div>
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">CRITICAL HOSTS</div><div class="metric-value" id="vuln-critical">0</div><div class="metric-sub">immediate action</div></div>
        <div class="metric-card warn"><div class="metric-glow"></div><div class="metric-label">TOTAL CVEs</div><div class="metric-value" id="vuln-cves">0</div><div class="metric-sub">vulnerabilities found</div></div>
        <div class="metric-card success"><div class="metric-glow"></div><div class="metric-label">STATUS</div><div class="metric-value" id="vuln-status" style="font-size:16px">IDLE</div><div class="metric-sub">scanner state</div></div>
      </div>
      <div class="card" style="margin-bottom:16px">
        <div class="card-header"><div class="card-title">🔓 CVE VULNERABILITY SCANNER</div>
          <div class="flex">
            <button class="btn primary" onclick="startVulnScan()">🔍 SCAN ALL DEVICES</button>
            <div class="card-badge" style="margin-left:8px">Requires Network Scanner first</div>
          </div>
        </div>
        <div class="card-body"><div class="fm text-dim" style="font-size:11px">Scans all devices discovered by the Network Scanner for known CVEs based on open ports. Checks against 50+ known vulnerabilities including Log4Shell, EternalBlue, BlueKeep, and more.</div></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><div class="card-title">CRITICAL FINDINGS</div></div>
          <div id="vuln-critical-list" style="max-height:400px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">Run a scan to find vulnerabilities</div></div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">SCAN RESULTS BY HOST</div></div>
          <div id="vuln-results" style="max-height:400px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No results yet</div></div>
        </div>
      </div>
    </div>

    <!-- HONEYPOT -->
    <div class="panel" id="panel-honeypot">
      <div class="metrics-row" style="margin-bottom:16px">
        <div class="metric-card success"><div class="metric-glow"></div><div class="metric-label">TOTAL CONNECTIONS</div><div class="metric-value" id="hp-connections">0</div><div class="metric-sub">to honeypots</div></div>
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">AUTH ATTEMPTS</div><div class="metric-value" id="hp-auth">0</div><div class="metric-sub">credential captures</div></div>
        <div class="metric-card warn"><div class="metric-glow"></div><div class="metric-label">UNIQUE ATTACKERS</div><div class="metric-value" id="hp-ips">0</div><div class="metric-sub">distinct IPs</div></div>
        <div class="metric-card purple"><div class="metric-glow"></div><div class="metric-label">ACTIVE SERVICES</div><div class="metric-value" id="hp-services">0</div><div class="metric-sub">running honeypots</div></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><div class="card-title">🍯 HONEYPOT SERVICES</div></div>
          <div class="card-body" id="hp-service-list"></div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">CAPTURED CREDENTIALS</div><div class="card-badge" id="b-hp-events">0</div></div>
          <div id="hp-events" style="max-height:400px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No captures yet — start a honeypot service</div></div>
        </div>
      </div>
      <div class="card" style="margin-top:16px">
        <div class="card-header"><div class="card-title">CONNECTION LOG</div></div>
        <div class="live-feed" id="hp-log" style="height:200px"></div>
      </div>
    </div>

    <!-- TIMELINE -->
    <div class="panel" id="panel-tl">
      <div class="metrics-row" style="margin-bottom:16px">
        <div class="metric-card"><div class="metric-glow"></div><div class="metric-label">TIMELINE EVENTS</div><div class="metric-value" id="tl-events">0</div><div class="metric-sub">total logged</div></div>
        <div class="metric-card warn"><div class="metric-glow"></div><div class="metric-label">CAMPAIGNS</div><div class="metric-value" id="tl-campaigns">0</div><div class="metric-sub">correlated attacks</div></div>
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">ACTIVE NOW</div><div class="metric-value" id="tl-active">0</div><div class="metric-sub">ongoing campaigns</div></div>
        <div class="metric-card purple"><div class="metric-glow"></div><div class="metric-label">TOP STAGE</div><div class="metric-value" id="tl-top-stage" style="font-size:14px">—</div><div class="metric-sub">kill chain</div></div>
      </div>
      <div class="card" style="margin-bottom:16px">
        <div class="card-header"><div class="card-title">📅 KILL CHAIN COVERAGE</div></div>
        <div class="card-body" id="tl-killchain" style="display:flex;flex-wrap:wrap;gap:6px"></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><div class="card-title">ATTACK CAMPAIGNS</div><div class="card-badge" id="b-tl-camps">0</div></div>
          <div id="tl-camp-list" style="max-height:400px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No campaigns yet — inject attacks to correlate</div></div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">EVENT TIMELINE</div><button class="btn primary" onclick="loadTimeline()" style="padding:4px 12px;font-size:11px">↻</button></div>
          <div id="tl-events-list" style="max-height:400px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No events yet</div></div>
        </div>
      </div>
    </div>
"""

    patch = patch.replace("  </main>", PANELS + "\n  </main>")

    JS = """
// ================================================================
// AI ASSISTANT
// ================================================================
var aiTyping = false;
function aiSend() {
  var msg = document.getElementById('ai-input').value.trim();
  if (!msg || aiTyping) return;
  document.getElementById('ai-input').value = '';
  appendAIMsg('user', msg);
  aiTyping = true;
  appendAIMsg('thinking', 'Analyzing network data...');
  fetch('/api/ai/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({message: msg})})
    .then(function(r){ return r.json(); })
    .then(function(d) {
      removeAIThinking();
      appendAIMsg('ai', d.reply || 'No response');
      aiTyping = false;
    })
    .catch(function(e) {
      removeAIThinking();
      appendAIMsg('ai', 'Error: ' + e.message);
      aiTyping = false;
    });
}
function appendAIMsg(role, text) {
  var chat = document.getElementById('ai-chat');
  var div = document.createElement('div');
  div.style.cssText = 'margin-bottom:12px;padding:8px 12px;border-radius:4px;';
  if (role === 'user') {
    div.style.cssText += 'background:rgba(0,212,255,0.08);border-left:3px solid var(--accent);';
    div.innerHTML = '<span style="color:var(--accent);font-size:10px">YOU</span><br>' + text.replace(/\\n/g,'<br>');
  } else if (role === 'thinking') {
    div.id = 'ai-thinking';
    div.style.cssText += 'color:var(--text-dim);font-style:italic;';
    div.innerHTML = '<span style="color:var(--green);font-size:10px">AI</span><br>' + text;
  } else {
    div.style.cssText += 'background:rgba(0,255,136,0.05);border-left:3px solid var(--green-dim);';
    var formatted = text.replace(/## (.*)/g, '<div style="font-weight:700;color:var(--text-bright);margin-top:8px;margin-bottom:4px">$1</div>').replace(/\\*\\*(.*?)\\*\\*/g,'<strong style="color:var(--text-bright)">$1</strong>').replace(/- (.*)/g,'<div style="padding-left:12px;color:var(--text-dim)">• $1</div>').replace(/\\n/g,'<br>');
    div.innerHTML = '<span style="color:var(--green);font-size:10px">CYBERSHIELD AI</span><br>' + formatted;
  }
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}
function removeAIThinking() {
  var t = document.getElementById('ai-thinking');
  if (t) t.remove();
}
function aiClear() {
  document.getElementById('ai-chat').innerHTML = '<div style="color:var(--accent);font-family:var(--font-mono);font-size:12px">Conversation cleared. Ask me anything.</div>';
  fetch('/api/ai/clear', {method:'POST'});
}
function loadAIPrompts() {
  fetch('/api/ai/prompts').then(function(r){return r.json();}).then(function(prompts) {
    document.getElementById('ai-prompts').innerHTML = prompts.map(function(p) {
      return '<button class="btn" style="text-align:left;font-size:11px;padding:8px 12px;width:100%" onclick="document.getElementById(\'ai-input\').value=\'' + p.replace(/'/g,"\\'") + '\';aiSend()">' + p + '</button>';
    }).join('');
  });
}
socket.on('ai_reply', function() {});

// ================================================================
// WORLD MAP (SVG-based)
// ================================================================
var geoData = null;
function loadGeoMap() {
  fetch('/api/geo/map').then(function(r){return r.json();}).then(function(d) {
    geoData = d;
    document.getElementById('geo-origins').textContent = d.total_origins;
    document.getElementById('geo-countries').textContent = d.total_countries;
    document.getElementById('geo-recent').textContent = d.recent_attacks.length;
    renderGeoMap(d);
    renderCountriesList(d.country_stats);
    renderGeoTable(d.origins);
    if (d.country_stats && d.country_stats.length) {
      document.getElementById('geo-top').textContent = d.country_stats[0].code;
    }
  });
}
function renderGeoMap(d) {
  var container = document.getElementById('geo-map-container');
  var w = container.offsetWidth || 600;
  var h = container.offsetHeight || 400;
  var svg = '<svg width="' + w + '" height="' + h + '" style="background:#060c12;display:block">';
  // Simple grid
  for (var x = 0; x < w; x += 40) svg += '<line x1="' + x + '" y1="0" x2="' + x + '" y2="' + h + '" stroke="rgba(15,61,92,0.3)" stroke-width="0.5"/>';
  for (var y = 0; y < h; y += 40) svg += '<line x1="0" y1="' + y + '" x2="' + w + '" y2="' + y + '" stroke="rgba(15,61,92,0.3)" stroke-width="0.5"/>';
  // Equator and prime meridian
  svg += '<line x1="0" y1="' + (h/2) + '" x2="' + w + '" y2="' + (h/2) + '" stroke="rgba(0,212,255,0.15)" stroke-width="1"/>';
  svg += '<line x1="' + (w/2) + '" y1="0" x2="' + (w/2) + '" y2="' + h + '" stroke="rgba(0,212,255,0.15)" stroke-width="1"/>';
  // Plot attack origins
  var rc = {LOW:'#00d4ff', MEDIUM:'#ffcc00', HIGH:'#ff6600', CRITICAL:'#ff2244'};
  (d.origins || []).forEach(function(o) {
    var x = ((o.lon + 180) / 360) * w;
    var y = ((90 - o.lat) / 180) * h;
    var r = Math.min(20, 4 + Math.log(o.attack_count + 1) * 3);
    var c = rc[o.risk_level] || '#00d4ff';
    svg += '<circle cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="' + r + '" fill="' + c + '" fill-opacity="0.3" stroke="' + c + '" stroke-width="1.5"/>';
    svg += '<circle cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="3" fill="' + c + '"/>';
    svg += '<title>' + o.ip + ' (' + o.country + ') — ' + o.attack_count + ' attacks</title>';
  });
  svg += '</svg>';
  container.innerHTML = svg + '<div id="geo-tooltip" style="display:none;position:absolute;background:var(--bg-card);border:1px solid var(--border);padding:8px 12px;border-radius:3px;font-family:var(--font-mono);font-size:11px;pointer-events:none;z-index:10"></div>';
}
function renderCountriesList(countries) {
  if (!countries || !countries.length) return;
  var max = countries[0].count || 1;
  document.getElementById('geo-countries-list').innerHTML = countries.slice(0,10).map(function(c,i) {
    return '<div style="display:flex;align-items:center;gap:8px;padding:8px 16px;border-bottom:1px solid rgba(15,61,92,0.3)">' +
      '<span class="fm text-dim" style="font-size:10px;width:16px">' + (i+1) + '</span>' +
      '<span class="fm" style="color:var(--text-bright);font-weight:700;width:40px">' + c.code + '</span>' +
      '<div style="flex:1;height:5px;background:var(--bg-deep);border-radius:2px"><div style="height:100%;background:linear-gradient(90deg,var(--red-dim),var(--red));border-radius:2px;width:' + Math.round(c.count/max*100) + '%"></div></div>' +
      '<span class="fm text-dim" style="font-size:11px;width:40px;text-align:right">' + c.count + '</span></div>';
  }).join('');
}
function renderGeoTable(origins) {
  document.getElementById('b-geo-origins').textContent = origins.length;
  var rc = {LOW:'var(--accent)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
  document.getElementById('geo-table').innerHTML = origins.slice(0,50).map(function(o) {
    return '<tr><td class="fm text-accent">' + o.ip + '</td>' +
      '<td class="fm" style="font-size:11px">' + o.country + ' (' + o.country_code + ')</td>' +
      '<td class="fm text-dim" style="font-size:11px">' + o.city + '</td>' +
      '<td class="fm text-dim" style="font-size:10px">' + (o.isp||'—') + '</td>' +
      '<td class="fm" style="font-weight:700">' + o.attack_count + '</td>' +
      '<td style="color:' + (rc[o.risk_level]||'var(--text-dim)') + ';font-weight:700;font-size:11px">' + o.risk_level + '</td>' +
      '<td class="fm text-dim" style="font-size:10px">' + o.last_seen + '</td>' +
      '<td><button class="btn" style="padding:2px 6px;font-size:10px" onclick="document.getElementById(\'blk-ip\').value=\'' + o.ip + '\';showPanel(\'blocker\',document.querySelector(\'[data-panel=blocker]\'))">🚫</button></td></tr>';
  }).join('');
}
setInterval(function(){ if(document.getElementById('panel-geomap').classList.contains('active')) loadGeoMap(); }, 10000);

// ================================================================
// VULNERABILITY SCANNER
// ================================================================
function startVulnScan() {
  document.getElementById('vuln-status').textContent = 'SCANNING';
  document.getElementById('vuln-status').style.color = 'var(--orange)';
  fetch('/api/vuln/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'})
    .then(function(r){return r.json();})
    .then(function(d) {
      if (d.error) { alert(d.error); document.getElementById('vuln-status').textContent = 'ERROR'; return; }
      pollVulnStatus();
    });
}
function pollVulnStatus() {
  var iv = setInterval(function() {
    fetch('/api/vuln/stats').then(function(r){return r.json();}).then(function(s) {
      document.getElementById('vuln-hosts').textContent = s.hosts_scanned;
      document.getElementById('vuln-critical').textContent = s.critical_hosts;
      document.getElementById('vuln-cves').textContent = s.total_cves;
      if (!s.scanning) {
        clearInterval(iv);
        document.getElementById('vuln-status').textContent = 'COMPLETE';
        document.getElementById('vuln-status').style.color = 'var(--green)';
        loadVulnResults();
      }
    });
  }, 1000);
}
function loadVulnResults() {
  fetch('/api/vuln/critical').then(function(r){return r.json();}).then(function(crits) {
    var rc = {CRITICAL:'var(--red)',HIGH:'var(--orange)',MEDIUM:'var(--yellow)',LOW:'var(--accent)'};
    document.getElementById('vuln-critical-list').innerHTML = crits.length ?
      crits.map(function(f) {
        return '<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3)">' +
          '<div style="display:flex;justify-content:space-between;align-items:center">' +
          '<span class="fm" style="font-weight:700;color:var(--text-bright)">' + f.cve_id + '</span>' +
          '<span class="sev-badge sev-' + f.severity + '">' + f.severity + '</span></div>' +
          '<div class="fm text-dim" style="font-size:11px;margin-top:3px">' + f.ip + ' | Port ' + f.port + '/' + f.service + ' | CVSS: ' + f.cvss_score + '</div>' +
          '<div class="fm text-dim" style="font-size:11px;margin-top:2px">' + f.description + '</div>' +
          '<div class="fm" style="font-size:10px;color:var(--orange);margin-top:4px">Fix: ' + f.remediation + '</div></div>';
      }).join('') : '<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No critical findings</div>';
  });
  fetch('/api/vuln/results').then(function(r){return r.json();}).then(function(results) {
    document.getElementById('vuln-results').innerHTML = results.length ?
      results.map(function(r) {
        var c = r.risk_level==='CRITICAL'?'var(--red)':r.risk_level==='HIGH'?'var(--orange)':r.risk_level==='MEDIUM'?'var(--yellow)':'var(--accent)';
        return '<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3)">' +
          '<div style="display:flex;justify-content:space-between">' +
          '<span class="fm text-accent">' + r.ip + (r.hostname?' ('+r.hostname+')':'') + '</span>' +
          '<span style="color:' + c + ';font-weight:700;font-size:11px">' + r.risk_level + ' — ' + r.risk_score + '/100</span></div>' +
          '<div class="fm text-dim" style="font-size:10px">' + r.finding_count + ' CVEs | ' + r.critical_count + ' critical | ' + r.high_count + ' high</div></div>';
      }).join('') : '<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No results</div>';
  });
}
socket.on('vuln_result', function() { loadVulnResults(); });

// ================================================================
// HONEYPOT
// ================================================================
function loadHoneypotStatus() {
  fetch('/api/honeypot/status').then(function(r){return r.json();}).then(function(status) {
    var html = '';
    Object.entries(status).forEach(function(entry) {
      var name = entry[0]; var s = entry[1];
      html += '<div style="display:flex;align-items:center;justify-content:space-between;padding:12px;border-bottom:1px solid rgba(15,61,92,0.3)">' +
        '<div><div class="fm" style="font-weight:700;color:var(--text-bright)">' + name + ' Honeypot</div>' +
        '<div class="fm text-dim" style="font-size:10px">Port ' + s.port + ' | ' + s.events + ' events</div></div>' +
        '<div class="flex">' +
        (s.running ?
          '<span class="fm text-green" style="font-size:11px;margin-right:8px">● ACTIVE</span><button class="btn danger" style="padding:3px 8px;font-size:10px" onclick="stopHoneypot(\'' + name + '\')">STOP</button>' :
          '<span class="fm text-dim" style="font-size:11px;margin-right:8px">○ IDLE</span><button class="btn primary" style="padding:3px 8px;font-size:10px" onclick="startHoneypot(\'' + name + '\')">START</button>') +
        '</div></div>';
    });
    html += '<div style="padding:12px;display:flex;gap:8px"><button class="btn primary" onclick="startAllHoneypots()">▶ START ALL</button><button class="btn danger" onclick="stopAllHoneypots()">■ STOP ALL</button></div>';
    document.getElementById('hp-service-list').innerHTML = html;
  });
  fetch('/api/honeypot/stats').then(function(r){return r.json();}).then(function(s) {
    document.getElementById('hp-connections').textContent = s.total_connections;
    document.getElementById('hp-auth').textContent = s.auth_attempts;
    document.getElementById('hp-ips').textContent = s.unique_attackers;
    document.getElementById('hp-services').textContent = s.active_services;
  });
  fetch('/api/honeypot/events?n=50').then(function(r){return r.json();}).then(function(events) {
    document.getElementById('b-hp-events').textContent = events.length;
    var authEvents = events.filter(function(e){ return e.event_type==='auth_attempt'; });
    document.getElementById('hp-events').innerHTML = authEvents.length ?
      authEvents.reverse().map(function(e) {
        return '<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3)">' +
          '<div style="display:flex;justify-content:space-between">' +
          '<span class="fm text-red" style="font-weight:700">' + e.service + '</span>' +
          '<span class="fm text-dim" style="font-size:10px">' + e.datetime + '</span></div>' +
          '<div class="fm text-accent" style="font-size:11px">' + e.src_ip + ':' + e.src_port + '</div>' +
          (e.credentials && (e.credentials.username||e.credentials.password) ?
            '<div class="fm" style="font-size:11px;margin-top:4px"><span class="text-dim">User:</span> <span class="text-orange">' + (e.credentials.username||'?') + '</span> <span class="text-dim">Pass:</span> <span class="text-orange">' + (e.credentials.password||'?') + '</span></div>' : '') +
          (e.payload ? '<div class="fm text-dim" style="font-size:10px;margin-top:2px">' + e.payload.slice(0,80) + '</div>' : '') + '</div>';
      }).join('') : '<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No credential captures yet</div>';
    // Connection log
    var log = document.getElementById('hp-log');
    events.reverse().slice(0,20).forEach(function(e) {
      var line = document.createElement('div');
      line.className = 'feed-line';
      line.innerHTML = '<span class="feed-ts">' + (e.datetime||'').slice(11) + '</span>' +
        '<span class="feed-proto" style="color:var(--purple)">' + e.service + '</span>' +
        '<span style="color:var(--text-main)">' + e.src_ip + '</span>' +
        '<span class="text-dim" style="margin-left:auto;font-size:10px">' + e.event_type + '</span>';
      log.appendChild(line);
    });
    while(log.children.length > 50) log.removeChild(log.firstChild);
    log.scrollTop = log.scrollHeight;
  });
}
function startHoneypot(svc) { fetch('/api/honeypot/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({service:svc})}).then(function(){loadHoneypotStatus();}); }
function stopHoneypot(svc) { fetch('/api/honeypot/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({service:svc})}).then(function(){loadHoneypotStatus();}); }
function startAllHoneypots() { fetch('/api/honeypot/start',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(function(){setTimeout(loadHoneypotStatus,500);}); }
function stopAllHoneypots() { fetch('/api/honeypot/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(function(){setTimeout(loadHoneypotStatus,500);}); }
socket.on('honeypot_event', function(){ if(document.getElementById('panel-honeypot').classList.contains('active')) loadHoneypotStatus(); });
setInterval(function(){ if(document.getElementById('panel-honeypot').classList.contains('active')) loadHoneypotStatus(); }, 5000);

// ================================================================
// TIMELINE
// ================================================================
function loadTimeline() {
  fetch('/api/timeline/stats').then(function(r){return r.json();}).then(function(s) {
    document.getElementById('tl-events').textContent = s.total_events;
    document.getElementById('tl-campaigns').textContent = s.total_campaigns;
    document.getElementById('tl-active').textContent = s.active_campaigns;
    document.getElementById('tl-top-stage').textContent = s.top_stage ? s.top_stage.slice(0,10) : '—';
  });
  fetch('/api/timeline/killchain').then(function(r){return r.json();}).then(function(kc) {
    var kcs = ["Recon","Resource Dev","Init Access","Execution","Persistence","Priv Esc","Def Evasion","Cred Access","Discovery","Lateral Mov","Collection","C2","Exfiltration","Impact"];
    document.getElementById('tl-killchain').innerHTML = kc.map(function(s,i) {
      var c = s.active ? (s.count>5?'var(--red)':s.count>2?'var(--orange)':'var(--accent)') : 'var(--text-dim)';
      return '<div style="background:' + (s.active?'rgba(0,212,255,0.1)':'var(--bg-deep)') + ';border:1px solid ' + (s.active?c:'var(--border)') + ';border-radius:3px;padding:8px 10px;text-align:center;min-width:80px">' +
        '<div style="font-family:var(--font-mono);font-size:9px;color:' + c + ';margin-bottom:4px">' + (kcs[i]||s.stage.slice(0,10)) + '</div>' +
        '<div style="font-family:var(--font-title);font-size:18px;font-weight:700;color:' + c + '">' + s.count + '</div></div>';
    }).join('');
  });
  fetch('/api/timeline/campaigns').then(function(r){return r.json();}).then(function(camps) {
    document.getElementById('b-tl-camps').textContent = camps.length;
    var sc = {LOW:'var(--accent)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
    document.getElementById('tl-camp-list').innerHTML = camps.length ?
      camps.map(function(c) {
        return '<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3)">' +
          '<div style="display:flex;justify-content:space-between;align-items:center">' +
          '<span class="fm" style="font-weight:700;color:var(--text-bright)">' + c.campaign_id + '</span>' +
          '<span style="color:' + (sc[c.severity]||'var(--text-dim)') + ';font-size:11px;font-weight:700">' + c.severity + '</span></div>' +
          '<div class="fm text-accent" style="font-size:11px">' + c.src_ip + '</div>' +
          '<div class="fm text-dim" style="font-size:10px;margin-top:2px">' + c.stage_count + ' stages | ' + c.event_count + ' events | ' + c.duration_secs + 's</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:4px">' + c.stages_hit.map(function(s){return '<span style="background:rgba(0,212,255,0.1);border:1px solid var(--border);padding:1px 5px;border-radius:2px;font-size:9px;font-family:var(--font-mono);color:var(--text-dim)">'+s+'</span>';}).join('') + '</div></div>';
      }).join('') : '<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No campaigns — inject attacks first</div>';
  });
  fetch('/api/timeline/events?limit=100').then(function(r){return r.json();}).then(function(events) {
    var sc = {LOW:'var(--accent)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
    document.getElementById('tl-events-list').innerHTML = events.length ?
      events.slice().reverse().map(function(e) {
        return '<div style="display:flex;align-items:center;gap:8px;padding:8px 14px;border-bottom:1px solid rgba(15,61,92,0.3)">' +
          '<div class="fm text-dim" style="font-size:10px;width:60px;flex-shrink:0">' + (e.datetime||'').slice(11) + '</div>' +
          '<div style="width:8px;height:8px;border-radius:50%;background:' + (sc[e.severity]||'var(--text-dim)') + ';flex-shrink:0"></div>' +
          '<div style="flex:1"><div class="fm" style="font-size:11px;color:var(--text-bright)">' + e.category + '</div>' +
          '<div class="fm text-dim" style="font-size:10px">' + e.src_ip + ' → ' + e.stage + '</div></div>' +
          '<div class="fm text-dim" style="font-size:9px;flex-shrink:0">' + (e.campaign_id||'—') + '</div></div>';
      }).join('') : '<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No timeline events</div>';
  });
}
setInterval(function(){ if(document.getElementById('panel-tl').classList.contains('active')) loadTimeline(); }, 5000);

// ── HOOK INTO showPanel ───────────────────────────────────────
var _pOrig = showPanel;
showPanel = function(name, el) {
  _pOrig(name, el);
  if (name==='ai')      loadAIPrompts();
  if (name==='geomap')  loadGeoMap();
  if (name==='vulns')   { fetch('/api/vuln/stats').then(function(r){return r.json();}).then(function(s){ document.getElementById('vuln-hosts').textContent=s.hosts_scanned; document.getElementById('vuln-critical').textContent=s.critical_hosts; document.getElementById('vuln-cves').textContent=s.total_cves; }); }
  if (name==='honeypot') loadHoneypotStatus();
  if (name==='tl')      loadTimeline();
};
"""

    patch = patch.replace("</script>", JS + "\n</script>")
    open("dashboard/index.html", "w", encoding="utf-8").write(patch)
    print("index.html patched with Phase 3 panels")
else:
    print("index.html already has Phase 3 panels")

print("\nPhase 3 complete! Run: python main.py")