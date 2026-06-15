import os

path = "dashboard/index.html"
with open(path, encoding="utf-8") as f:
    html = f.read()

# Verify it's clean
count = html.count("function showPanel")
print(f"showPanel count before: {count}")
assert count == 1, "Run rebuild_dashboard.py first!"

# Add Phase 3 nav (once only)
NAV = """
    <div class="nav-sec">PHASE 3</div>
    <div class="nav-item" onclick="showPanel('ai',this)" data-panel="ai"><span class="nav-icon">🤖</span> AI Assistant</div>
    <div class="nav-item" onclick="showPanel('geomap',this)" data-panel="geomap"><span class="nav-icon">🌍</span> World Map</div>
    <div class="nav-item" onclick="showPanel('vulns',this)" data-panel="vulns"><span class="nav-icon">🔓</span> CVE Scanner</div>
    <div class="nav-item" onclick="showPanel('honeypot',this)" data-panel="honeypot"><span class="nav-icon">🍯</span> Honeypot</div>
    <div class="nav-item" onclick="showPanel('tl',this)" data-panel="tl"><span class="nav-icon">📅</span> Timeline</div>
"""
html = html.replace("</nav>", NAV + "</nav>")

# Add Phase 3 panels
PANELS = """
    <div class="panel" id="panel-ai">
      <div class="grid-2">
        <div class="card" style="display:flex;flex-direction:column">
          <div class="card-header"><div class="card-title">🤖 AI SECURITY ASSISTANT</div><button class="btn" onclick="aiClear()" style="padding:3px 10px;font-size:11px">CLEAR</button></div>
          <div id="ai-chat" style="flex:1;min-height:420px;max-height:520px;overflow-y:auto;padding:16px;background:var(--bg-deep);font-family:var(--font-mono);font-size:12px;line-height:1.7">
            <div style="color:var(--accent)">CyberShield AI ready. Ask me about your network security.</div>
          </div>
          <div style="padding:12px;border-top:1px solid var(--border);display:flex;gap:8px">
            <input type="text" class="inp" id="ai-input" placeholder="Ask anything about your network..." style="flex:1" onkeydown="if(event.key==='Enter')aiSend()">
            <button class="btn primary" onclick="aiSend()">SEND</button>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">QUICK PROMPTS</div></div>
          <div class="card-body"><div id="ai-prompts" style="display:flex;flex-direction:column;gap:8px"></div></div>
        </div>
      </div>
    </div>

    <div class="panel" id="panel-geomap">
      <div class="metrics-row" style="margin-bottom:16px">
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">ORIGINS</div><div class="metric-value" id="geo-origins">0</div><div class="metric-sub">unique IPs</div></div>
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">COUNTRIES</div><div class="metric-value" id="geo-countries">0</div><div class="metric-sub">attack sources</div></div>
        <div class="metric-card warn"><div class="metric-glow"></div><div class="metric-label">RECENT</div><div class="metric-value" id="geo-recent">0</div><div class="metric-sub">geolocated</div></div>
        <div class="metric-card purple"><div class="metric-glow"></div><div class="metric-label">TOP COUNTRY</div><div class="metric-value" id="geo-top" style="font-size:18px">—</div><div class="metric-sub">most attacks</div></div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><div class="card-title">🌍 ATTACK MAP</div><button class="btn primary" onclick="loadGeoMap()" style="padding:4px 12px;font-size:11px">↻ REFRESH</button></div>
          <div id="geo-map-container" style="height:380px;background:var(--bg-deep);position:relative;overflow:hidden"></div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">TOP COUNTRIES</div></div>
          <div class="card-body" id="geo-countries-list"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">Inject attacks to populate</div></div>
        </div>
      </div>
      <div class="card" style="margin-top:16px">
        <div class="card-header"><div class="card-title">ORIGIN DETAILS</div><div class="card-badge" id="b-geo-origins">0</div></div>
        <div style="overflow-x:auto"><table class="ttable"><thead><tr><th>IP</th><th>COUNTRY</th><th>CITY</th><th>ISP</th><th>ATTACKS</th><th>RISK</th><th>LAST SEEN</th><th>ACTION</th></tr></thead><tbody id="geo-table"><tr><td colspan="8" style="text-align:center;color:var(--text-dim);padding:30px;font-family:var(--font-mono);font-size:11px">No data yet</td></tr></tbody></table></div>
      </div>
    </div>

    <div class="panel" id="panel-vulns">
      <div class="metrics-row" style="margin-bottom:16px">
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">HOSTS SCANNED</div><div class="metric-value" id="vuln-hosts">0</div><div class="metric-sub">devices</div></div>
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">CRITICAL HOSTS</div><div class="metric-value" id="vuln-critical">0</div><div class="metric-sub">action needed</div></div>
        <div class="metric-card warn"><div class="metric-glow"></div><div class="metric-label">TOTAL CVEs</div><div class="metric-value" id="vuln-cves">0</div><div class="metric-sub">found</div></div>
        <div class="metric-card success"><div class="metric-glow"></div><div class="metric-label">STATUS</div><div class="metric-value" id="vuln-status" style="font-size:16px">IDLE</div><div class="metric-sub">scanner</div></div>
      </div>
      <div class="card" style="margin-bottom:16px">
        <div class="card-header"><div class="card-title">🔓 CVE SCANNER</div><div class="flex"><button class="btn primary" onclick="startVulnScan()">🔍 SCAN ALL DEVICES</button><div class="card-badge" style="margin-left:8px">Run Network Scanner first</div></div></div>
        <div class="card-body fm text-dim" style="font-size:11px">Checks all discovered LAN devices for 50+ known CVEs including Log4Shell, EternalBlue, BlueKeep, and more.</div>
      </div>
      <div class="grid-2">
        <div class="card"><div class="card-header"><div class="card-title">CRITICAL CVEs</div></div><div id="vuln-critical-list" style="max-height:400px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">Run scan first</div></div></div>
        <div class="card"><div class="card-header"><div class="card-title">BY HOST</div></div><div id="vuln-results" style="max-height:400px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No results</div></div></div>
      </div>
    </div>

    <div class="panel" id="panel-honeypot">
      <div class="metrics-row" style="margin-bottom:16px">
        <div class="metric-card success"><div class="metric-glow"></div><div class="metric-label">CONNECTIONS</div><div class="metric-value" id="hp-connections">0</div><div class="metric-sub">total</div></div>
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">CREDENTIALS</div><div class="metric-value" id="hp-auth">0</div><div class="metric-sub">captured</div></div>
        <div class="metric-card warn"><div class="metric-glow"></div><div class="metric-label">ATTACKERS</div><div class="metric-value" id="hp-ips">0</div><div class="metric-sub">unique IPs</div></div>
        <div class="metric-card purple"><div class="metric-glow"></div><div class="metric-label">ACTIVE</div><div class="metric-value" id="hp-services">0</div><div class="metric-sub">services</div></div>
      </div>
      <div class="grid-2">
        <div class="card"><div class="card-header"><div class="card-title">🍯 SERVICES</div></div><div class="card-body" id="hp-service-list"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">Loading...</div></div></div>
        <div class="card"><div class="card-header"><div class="card-title">CAPTURED CREDENTIALS</div><div class="card-badge" id="b-hp-events">0</div></div><div id="hp-events" style="max-height:400px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">Start a honeypot to capture credentials</div></div></div>
      </div>
      <div class="card" style="margin-top:16px"><div class="card-header"><div class="card-title">CONNECTION LOG</div></div><div class="live-feed" id="hp-log" style="height:180px"></div></div>
    </div>

    <div class="panel" id="panel-tl">
      <div class="metrics-row" style="margin-bottom:16px">
        <div class="metric-card"><div class="metric-glow"></div><div class="metric-label">EVENTS</div><div class="metric-value" id="tl-events">0</div><div class="metric-sub">logged</div></div>
        <div class="metric-card warn"><div class="metric-glow"></div><div class="metric-label">CAMPAIGNS</div><div class="metric-value" id="tl-campaigns">0</div><div class="metric-sub">correlated</div></div>
        <div class="metric-card danger"><div class="metric-glow"></div><div class="metric-label">ACTIVE</div><div class="metric-value" id="tl-active">0</div><div class="metric-sub">ongoing</div></div>
        <div class="metric-card purple"><div class="metric-glow"></div><div class="metric-label">TOP STAGE</div><div class="metric-value" id="tl-top-stage" style="font-size:14px">—</div><div class="metric-sub">kill chain</div></div>
      </div>
      <div class="card" style="margin-bottom:16px"><div class="card-header"><div class="card-title">KILL CHAIN COVERAGE</div></div><div class="card-body" id="tl-killchain" style="display:flex;flex-wrap:wrap;gap:6px"></div></div>
      <div class="grid-2">
        <div class="card"><div class="card-header"><div class="card-title">CAMPAIGNS</div><div class="card-badge" id="b-tl-camps">0</div></div><div id="tl-camp-list" style="max-height:400px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">Inject attacks to see campaigns</div></div></div>
        <div class="card"><div class="card-header"><div class="card-title">EVENT TIMELINE</div><button class="btn primary" onclick="loadTimeline()" style="padding:4px 12px;font-size:11px">↻</button></div><div id="tl-events-list" style="max-height:400px;overflow-y:auto"><div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No events yet</div></div></div>
      </div>
    </div>
"""
html = html.replace("  </main>", PANELS + "\n  </main>")

# Add Phase 3 JS - clean, no overwrites
P3_JS = """
// ================================================================
// PHASE 3 - AI ASSISTANT
// ================================================================
var aiTyping = false;

function aiSend() {
  var msg = document.getElementById('ai-input').value.trim();
  if (!msg || aiTyping) return;
  document.getElementById('ai-input').value = '';
  appendAIMsg('user', msg);
  aiTyping = true;
  appendAIMsg('thinking', 'Analyzing...');
  fetch('/api/ai/chat', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg})})
    .then(function(r){return r.json();})
    .then(function(d){ removeAIThinking(); appendAIMsg('ai', d.reply||'No response'); aiTyping=false; })
    .catch(function(e){ removeAIThinking(); appendAIMsg('ai','Error: '+e.message); aiTyping=false; });
}

function appendAIMsg(role, text) {
  var chat = document.getElementById('ai-chat');
  var div = document.createElement('div');
  div.style.cssText = 'margin-bottom:12px;padding:8px 12px;border-radius:4px;';
  if (role === 'user') {
    div.style.cssText += 'background:rgba(0,212,255,0.08);border-left:3px solid var(--accent)';
    div.innerHTML = '<div style="color:var(--accent);font-size:10px;margin-bottom:4px">YOU</div>' + text.replace(/\n/g,'<br>');
  } else if (role === 'thinking') {
    div.id = 'ai-thinking';
    div.style.cssText += 'color:var(--text-dim);font-style:italic';
    div.innerHTML = '<div style="color:var(--green);font-size:10px;margin-bottom:4px">AI</div>' + text;
  } else {
    div.style.cssText += 'background:rgba(0,255,136,0.05);border-left:3px solid var(--green-dim)';
    var fmt = text
      .replace(/## (.*)/g,'<div style="font-weight:700;color:var(--text-bright);margin:8px 0 4px">$1</div>')
      .replace(/\*\*(.*?)\*\*/g,'<strong style="color:var(--text-bright)">$1</strong>')
      .replace(/^- (.*)/gm,'<div style="padding-left:12px;color:var(--text-dim)">• $1</div>')
      .replace(/\n/g,'<br>');
    div.innerHTML = '<div style="color:var(--green);font-size:10px;margin-bottom:4px">CYBERSHIELD AI</div>' + fmt;
  }
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

function removeAIThinking() {
  var t = document.getElementById('ai-thinking');
  if (t) t.remove();
}

function aiClear() {
  document.getElementById('ai-chat').innerHTML = '<div style="color:var(--accent);font-family:var(--font-mono);font-size:12px">Cleared. Ask me anything.</div>';
  fetch('/api/ai/clear',{method:'POST'}).catch(function(){});
}

function loadAIPrompts() {
  fetch('/api/ai/prompts')
    .then(function(r){return r.json();})
    .then(function(prompts){
      document.getElementById('ai-prompts').innerHTML = prompts.map(function(p){
        return '<button class="btn" style="text-align:left;font-size:11px;padding:8px 12px;width:100%" onclick="document.getElementById(\'ai-input\').value=\'' + p.replace(/'/g,"\\'") + '\';aiSend()">' + p + '</button>';
      }).join('');
    }).catch(function(){});
}

// ================================================================
// PHASE 3 - WORLD MAP
// ================================================================
function loadGeoMap() {
  fetch('/api/geo/map')
    .then(function(r){return r.json();})
    .then(function(d){
      document.getElementById('geo-origins').textContent = d.total_origins||0;
      document.getElementById('geo-countries').textContent = d.total_countries||0;
      document.getElementById('geo-recent').textContent = (d.recent_attacks||[]).length;
      if (d.country_stats && d.country_stats.length) {
        document.getElementById('geo-top').textContent = d.country_stats[0].code;
      }
      renderGeoSVG(d);
      renderCountriesList(d.country_stats||[]);
      renderGeoTable(d.origins||[]);
    }).catch(function(){});
}

function renderGeoSVG(d) {
  var container = document.getElementById('geo-map-container');
  var w = container.offsetWidth||600;
  var h = container.offsetHeight||380;
  var rc = {LOW:'#00d4ff',MEDIUM:'#ffcc00',HIGH:'#ff6600',CRITICAL:'#ff2244'};
  var svg = '<svg width="'+w+'" height="'+h+'" style="background:#060c12;display:block">';
  for (var x=0;x<w;x+=50) svg += '<line x1="'+x+'" y1="0" x2="'+x+'" y2="'+h+'" stroke="rgba(15,61,92,0.25)" stroke-width="0.5"/>';
  for (var y=0;y<h;y+=50) svg += '<line x1="0" y1="'+y+'" x2="'+w+'" y2="'+y+'" stroke="rgba(15,61,92,0.25)" stroke-width="0.5"/>';
  svg += '<line x1="0" y1="'+(h/2)+'" x2="'+w+'" y2="'+(h/2)+'" stroke="rgba(0,212,255,0.2)" stroke-width="1"/>';
  svg += '<line x1="'+(w/2)+'" y1="0" x2="'+(w/2)+'" y2="'+h+'" stroke="rgba(0,212,255,0.2)" stroke-width="1"/>';
  svg += '<text x="'+(w/2+4)+'" y="'+(h/2-4)+'" fill="rgba(0,212,255,0.3)" font-size="9" font-family="monospace">0°</text>';
  (d.origins||[]).forEach(function(o){
    var x = ((o.lon+180)/360)*w;
    var y = ((90-o.lat)/180)*h;
    var r = Math.min(22, 5+Math.log(o.attack_count+1)*3);
    var c = rc[o.risk_level]||'#00d4ff';
    svg += '<circle cx="'+x.toFixed(1)+'" cy="'+y.toFixed(1)+'" r="'+(r+4)+'" fill="'+c+'" fill-opacity="0.1"/>';
    svg += '<circle cx="'+x.toFixed(1)+'" cy="'+y.toFixed(1)+'" r="'+r+'" fill="'+c+'" fill-opacity="0.25" stroke="'+c+'" stroke-width="1.5"/>';
    svg += '<circle cx="'+x.toFixed(1)+'" cy="'+y.toFixed(1)+'" r="3" fill="'+c+'"/>';
    svg += '<text x="'+(x+r+3).toFixed(1)+'" y="'+(y+4).toFixed(1)+'" fill="'+c+'" font-size="9" font-family="monospace">'+o.ip+'</text>';
  });
  svg += '</svg>';
  container.innerHTML = svg;
}

function renderCountriesList(countries) {
  if (!countries.length) return;
  var max = countries[0].count||1;
  document.getElementById('geo-countries-list').innerHTML = countries.slice(0,10).map(function(c,i){
    return '<div style="display:flex;align-items:center;gap:8px;padding:8px 16px;border-bottom:1px solid rgba(15,61,92,0.3)">'+
      '<span class="fm text-dim" style="font-size:10px;width:16px">'+(i+1)+'</span>'+
      '<span class="fm" style="color:var(--text-bright);font-weight:700;width:40px">'+c.code+'</span>'+
      '<div style="flex:1;height:5px;background:var(--bg-deep);border-radius:2px"><div style="height:100%;background:linear-gradient(90deg,var(--red-dim),var(--red));border-radius:2px;width:'+Math.round(c.count/max*100)+'%"></div></div>'+
      '<span class="fm text-dim" style="font-size:11px;width:40px;text-align:right">'+c.count+'</span></div>';
  }).join('');
}

function renderGeoTable(origins) {
  document.getElementById('b-geo-origins').textContent = origins.length;
  var rc = {LOW:'var(--accent)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
  document.getElementById('geo-table').innerHTML = origins.length ? origins.slice(0,50).map(function(o){
    return '<tr><td class="fm text-accent">'+o.ip+'</td>'+
      '<td class="fm" style="font-size:11px">'+o.country+' ('+o.country_code+')</td>'+
      '<td class="fm text-dim" style="font-size:11px">'+o.city+'</td>'+
      '<td class="fm text-dim" style="font-size:10px">'+(o.isp||'—')+'</td>'+
      '<td class="fm" style="font-weight:700">'+o.attack_count+'</td>'+
      '<td style="color:'+(rc[o.risk_level]||'var(--text-dim)')+';font-weight:700;font-size:11px">'+o.risk_level+'</td>'+
      '<td class="fm text-dim" style="font-size:10px">'+o.last_seen+'</td>'+
      '<td><button class="btn" style="padding:2px 6px;font-size:10px" onclick="document.getElementById(\'blk-ip\').value=\''+o.ip+'\';showPanel(\'blocker\',document.querySelector(\'[data-panel=blocker]\'))">🚫</button></td></tr>';
  }).join('') : '<tr><td colspan="8" style="text-align:center;color:var(--text-dim);padding:20px;font-family:var(--font-mono);font-size:11px">No data — inject attacks first</td></tr>';
}

setInterval(function(){
  if (document.getElementById('panel-geomap').classList.contains('active')) loadGeoMap();
}, 15000);

// ================================================================
// PHASE 3 - CVE SCANNER
// ================================================================
function startVulnScan() {
  document.getElementById('vuln-status').textContent = 'SCANNING';
  document.getElementById('vuln-status').style.color = 'var(--orange)';
  fetch('/api/vuln/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(function(r){return r.json();})
    .then(function(d){
      if (d.error) { alert(d.error); document.getElementById('vuln-status').textContent='ERROR'; return; }
      pollVulnStatus();
    }).catch(function(e){ alert('Error: '+e.message); });
}

function pollVulnStatus() {
  var iv = setInterval(function(){
    fetch('/api/vuln/stats').then(function(r){return r.json();}).then(function(s){
      document.getElementById('vuln-hosts').textContent = s.hosts_scanned;
      document.getElementById('vuln-critical').textContent = s.critical_hosts;
      document.getElementById('vuln-cves').textContent = s.total_cves;
      if (!s.scanning) {
        clearInterval(iv);
        document.getElementById('vuln-status').textContent = 'DONE';
        document.getElementById('vuln-status').style.color = 'var(--green)';
        loadVulnResults();
      }
    });
  }, 1000);
}

function loadVulnResults() {
  fetch('/api/vuln/critical').then(function(r){return r.json();}).then(function(crits){
    document.getElementById('vuln-critical-list').innerHTML = crits.length ? crits.map(function(f){
      return '<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3)">'+
        '<div style="display:flex;justify-content:space-between"><span class="fm" style="font-weight:700;color:var(--text-bright)">'+f.cve_id+'</span><span class="sev-badge sev-'+f.severity+'">'+f.severity+'</span></div>'+
        '<div class="fm text-dim" style="font-size:11px;margin-top:3px">'+f.ip+' | Port '+f.port+'/'+f.service+' | CVSS: '+f.cvss_score+'</div>'+
        '<div class="fm text-dim" style="font-size:11px;margin-top:2px">'+f.description+'</div>'+
        '<div class="fm" style="font-size:10px;color:var(--orange);margin-top:4px">Fix: '+f.remediation+'</div></div>';
    }).join('') : '<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No critical findings</div>';
  });
  fetch('/api/vuln/results').then(function(r){return r.json();}).then(function(results){
    document.getElementById('vuln-results').innerHTML = results.length ? results.map(function(r){
      var c = r.risk_level==='CRITICAL'?'var(--red)':r.risk_level==='HIGH'?'var(--orange)':r.risk_level==='MEDIUM'?'var(--yellow)':'var(--accent)';
      return '<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3)">'+
        '<div style="display:flex;justify-content:space-between"><span class="fm text-accent">'+r.ip+(r.hostname?' ('+r.hostname+')':'')+'</span><span style="color:'+c+';font-weight:700;font-size:11px">'+r.risk_level+' — '+r.risk_score+'/100</span></div>'+
        '<div class="fm text-dim" style="font-size:10px">'+r.finding_count+' CVEs | '+r.critical_count+' critical</div></div>';
    }).join('') : '<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No results</div>';
  });
}

// ================================================================
// PHASE 3 - HONEYPOT
// ================================================================
function loadHoneypotStatus() {
  fetch('/api/honeypot/status').then(function(r){return r.json();}).then(function(status){
    var html = '';
    Object.keys(status).forEach(function(name){
      var s = status[name];
      html += '<div style="display:flex;align-items:center;justify-content:space-between;padding:12px;border-bottom:1px solid rgba(15,61,92,0.3)">'+
        '<div><div class="fm" style="font-weight:700;color:var(--text-bright)">'+name+' Honeypot</div>'+
        '<div class="fm text-dim" style="font-size:10px">Port '+s.port+' | '+s.events+' events</div></div>'+
        '<div style="display:flex;align-items:center;gap:8px">'+
        (s.running ?
          '<span class="fm text-green" style="font-size:11px">● ACTIVE</span><button class="btn danger" style="padding:3px 8px;font-size:10px" onclick="stopHP(\''+name+'\')">STOP</button>' :
          '<span class="fm text-dim" style="font-size:11px">○ IDLE</span><button class="btn primary" style="padding:3px 8px;font-size:10px" onclick="startHP(\''+name+'\')">START</button>')+
        '</div></div>';
    });
    html += '<div style="padding:12px;display:flex;gap:8px">'+
      '<button class="btn primary" onclick="startAllHP()">▶ START ALL</button>'+
      '<button class="btn danger" onclick="stopAllHP()">■ STOP ALL</button></div>';
    document.getElementById('hp-service-list').innerHTML = html;
  });
  fetch('/api/honeypot/stats').then(function(r){return r.json();}).then(function(s){
    document.getElementById('hp-connections').textContent = s.total_connections;
    document.getElementById('hp-auth').textContent = s.auth_attempts;
    document.getElementById('hp-ips').textContent = s.unique_attackers;
    document.getElementById('hp-services').textContent = s.active_services;
  });
  fetch('/api/honeypot/events?n=50').then(function(r){return r.json();}).then(function(events){
    document.getElementById('b-hp-events').textContent = events.length;
    var auths = events.filter(function(e){ return e.event_type==='auth_attempt'; });
    document.getElementById('hp-events').innerHTML = auths.length ? auths.reverse().map(function(e){
      return '<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3)">'+
        '<div style="display:flex;justify-content:space-between"><span class="fm text-red" style="font-weight:700">'+e.service+'</span><span class="fm text-dim" style="font-size:10px">'+e.datetime+'</span></div>'+
        '<div class="fm text-accent" style="font-size:11px">'+e.src_ip+':'+e.src_port+'</div>'+
        (e.credentials&&(e.credentials.username||e.credentials.password)?
          '<div class="fm" style="font-size:11px;margin-top:4px"><span class="text-dim">User:</span> <span class="text-orange">'+(e.credentials.username||'?')+'</span> <span class="text-dim">Pass:</span> <span class="text-orange">'+(e.credentials.password||'?')+'</span></div>':'')+
        '</div>';
    }).join('') : '<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No credentials captured yet</div>';
    var log = document.getElementById('hp-log');
    events.slice(-10).forEach(function(e){
      var line = document.createElement('div');
      line.className = 'feed-line';
      line.innerHTML = '<span class="feed-ts">'+(e.datetime||'').slice(11)+'</span><span class="feed-proto" style="color:var(--purple)">'+e.service+'</span><span style="color:var(--text-main)">'+e.src_ip+'</span><span class="text-dim" style="margin-left:auto;font-size:10px">'+e.event_type+'</span>';
      log.appendChild(line);
    });
    while(log.children.length>50) log.removeChild(log.firstChild);
    log.scrollTop = log.scrollHeight;
  });
}

function startHP(svc){ fetch('/api/honeypot/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({service:svc})}).then(function(){setTimeout(loadHoneypotStatus,500);}); }
function stopHP(svc){ fetch('/api/honeypot/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({service:svc})}).then(function(){setTimeout(loadHoneypotStatus,500);}); }
function startAllHP(){ fetch('/api/honeypot/start',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(function(){setTimeout(loadHoneypotStatus,800);}); }
function stopAllHP(){ fetch('/api/honeypot/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(function(){setTimeout(loadHoneypotStatus,800);}); }

setInterval(function(){
  if (document.getElementById('panel-honeypot').classList.contains('active')) loadHoneypotStatus();
}, 5000);

// ================================================================
// PHASE 3 - TIMELINE
// ================================================================
function loadTimeline() {
  fetch('/api/timeline/stats').then(function(r){return r.json();}).then(function(s){
    document.getElementById('tl-events').textContent = s.total_events||0;
    document.getElementById('tl-campaigns').textContent = s.total_campaigns||0;
    document.getElementById('tl-active').textContent = s.active_campaigns||0;
    document.getElementById('tl-top-stage').textContent = s.top_stage ? s.top_stage.slice(0,10) : '—';
  });
  fetch('/api/timeline/killchain').then(function(r){return r.json();}).then(function(kc){
    var short = ['Recon','Res Dev','Init Access','Execution','Persistence','Priv Esc','Def Evasion','Cred Access','Discovery','Lateral Mov','Collection','C2','Exfiltration','Impact'];
    document.getElementById('tl-killchain').innerHTML = kc.map(function(s,i){
      var c = s.active ? (s.count>5?'var(--red)':s.count>2?'var(--orange)':'var(--accent)') : 'var(--text-dim)';
      return '<div style="background:'+(s.active?'rgba(0,212,255,0.08)':'var(--bg-deep)')+';border:1px solid '+(s.active?c:'var(--border)')+';border-radius:3px;padding:8px;text-align:center;min-width:75px">'+
        '<div style="font-family:var(--font-mono);font-size:9px;color:'+c+';margin-bottom:4px">'+(short[i]||s.stage.slice(0,8))+'</div>'+
        '<div style="font-family:var(--font-title);font-size:18px;font-weight:700;color:'+c+'">'+s.count+'</div></div>';
    }).join('');
  });
  fetch('/api/timeline/campaigns').then(function(r){return r.json();}).then(function(camps){
    document.getElementById('b-tl-camps').textContent = camps.length;
    var sc = {LOW:'var(--accent)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
    document.getElementById('tl-camp-list').innerHTML = camps.length ? camps.map(function(c){
      return '<div style="padding:10px 14px;border-bottom:1px solid rgba(15,61,92,0.3)">'+
        '<div style="display:flex;justify-content:space-between"><span class="fm" style="font-weight:700;color:var(--text-bright)">'+c.campaign_id+'</span><span style="color:'+(sc[c.severity]||'var(--text-dim)')+';font-size:11px;font-weight:700">'+c.severity+'</span></div>'+
        '<div class="fm text-accent" style="font-size:11px">'+c.src_ip+'</div>'+
        '<div class="fm text-dim" style="font-size:10px;margin-top:2px">'+c.stage_count+' stages | '+c.event_count+' events | '+c.duration_secs+'s</div>'+
        '<div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:4px">'+c.stages_hit.map(function(s){return '<span style="background:rgba(0,212,255,0.1);border:1px solid var(--border);padding:1px 5px;border-radius:2px;font-size:9px;font-family:var(--font-mono);color:var(--text-dim)">'+s+'</span>';}).join('')+'</div></div>';
    }).join('') : '<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">Inject attacks to see campaigns</div>';
  });
  fetch('/api/timeline/events?limit=100').then(function(r){return r.json();}).then(function(events){
    var sc = {LOW:'var(--accent)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
    document.getElementById('tl-events-list').innerHTML = events.length ? events.slice().reverse().map(function(e){
      return '<div style="display:flex;align-items:center;gap:8px;padding:8px 14px;border-bottom:1px solid rgba(15,61,92,0.3)">'+
        '<div class="fm text-dim" style="font-size:10px;width:60px;flex-shrink:0">'+(e.datetime||'').slice(11)+'</div>'+
        '<div style="width:8px;height:8px;border-radius:50%;background:'+(sc[e.severity]||'var(--text-dim)')+';flex-shrink:0"></div>'+
        '<div style="flex:1"><div class="fm" style="font-size:11px;color:var(--text-bright)">'+e.category+'</div><div class="fm text-dim" style="font-size:10px">'+e.src_ip+' → '+e.stage+'</div></div>'+
        '<div class="fm text-dim" style="font-size:9px;flex-shrink:0">'+(e.campaign_id||'—')+'</div></div>';
    }).join('') : '<div class="text-dim fm" style="font-size:11px;padding:20px;text-align:center">No events yet</div>';
  });
}

setInterval(function(){
  if (document.getElementById('panel-tl').classList.contains('active')) loadTimeline();
}, 5000);

// Update showPanel to include Phase 3 panels
var _sp = showPanel;
showPanel = function(name, el) {
  _sp(name, el);
  if (name==='ai')       { try{loadAIPrompts();}catch(e){} }
  if (name==='geomap')   { try{loadGeoMap();}catch(e){} }
  if (name==='honeypot') { try{loadHoneypotStatus();}catch(e){} }
  if (name==='tl')       { try{loadTimeline();}catch(e){} }
  if (name==='vulns')    { try{fetch('/api/vuln/stats').then(function(r){return r.json();}).then(function(s){document.getElementById('vuln-hosts').textContent=s.hosts_scanned;document.getElementById('vuln-critical').textContent=s.critical_hosts;document.getElementById('vuln-cves').textContent=s.total_cves;});}catch(e){} }
};
"""

html = html.replace("</script>", P3_JS + "\n</script>")

with open(path, "w", encoding="utf-8") as f:
    f.write(html)

# Verify
with open(path, encoding="utf-8") as f:
    final = f.read()

sp_count = final.count("function showPanel")
ai_count = final.count("PHASE 3")
nav_count = final.count("nav-sec")
print(f"showPanel definitions: {sp_count}")
print(f"Phase 3 sections: {ai_count}")
print(f"Nav sections: {nav_count}")
print(f"File size: {len(final):,} chars")
if sp_count == 1 and nav_count <= 3:
    print("SUCCESS!")
else:
    print("WARNING: check for duplicates")