import os, re

path = "dashboard/index.html"
with open(path, encoding="utf-8") as f:
    html = f.read()

# Remove ALL showPanel overrides that stack on top of each other
# These break navigation when there are multiple patches
html = re.sub(
    r'// ── UNIFIED PANEL HANDLER.*?socket\.on\(\'darkweb_result\'.*?\}\);\s*',
    '', html, flags=re.DOTALL
)
html = re.sub(
    r'const _orig\w+ = showPanel;.*?showPanel = function.*?\};\s*',
    '', html, flags=re.DOTALL
)
html = re.sub(
    r'// Hook into panel switches.*?socket\.on\(\'ip_blocked\'.*?\}\);\s*',
    '', html, flags=re.DOTALL
)
html = re.sub(
    r'// ── PANEL HOOK.*?socket\.on\(\'ip_blocked\'.*?\}\);\s*',
    '', html, flags=re.DOTALL
)

# Also remove duplicate DW JS if any
html = re.sub(
    r'// ── DARK WEB MONITOR JS ──.*?(?=// ──|</script>)',
    '', html, flags=re.DOTALL
)

# Now add ONE clean unified showPanel before </script>
FIXED_JS = """
// ================================================================
// UNIFIED NAVIGATION — single showPanel, no stacking
// ================================================================
function showPanel(name, el) {
  // Hide all panels
  document.querySelectorAll('.panel').forEach(function(p) {
    p.classList.remove('active');
  });
  // Deactivate all nav items
  document.querySelectorAll('.nav-item').forEach(function(n) {
    n.classList.remove('active');
  });
  // Show target panel
  var target = document.getElementById('panel-' + name);
  if (target) target.classList.add('active');
  if (el) el.classList.add('active');

  // Panel-specific refresh
  if (name === 'threats')      { refreshThreats(); }
  if (name === 'flows')        { refreshFlows(); }
  if (name === 'malware')      { refreshMalware(); }
  if (name === 'intel')        { refreshIntelHistory(); }
  if (name === 'netscanner')   { refreshDevices(); }
  if (name === 'inspector')    { refreshInspector(); }
  if (name === 'blocker')      { refreshBlockList(); }
  if (name === 'reports')      { loadReportSummary(); }
  if (name === 'darkweb')      { refreshDWHistory(); refreshDWStats(); refreshDWMonitorList(); }
}

// WebSocket panel events
if (typeof socket !== 'undefined') {
  socket.on('intel_result',  function() { refreshIntelHistory(); });
  socket.on('ip_blocked',    function() { refreshBlockList(); });
  socket.on('darkweb_result',function() { refreshDWHistory(); refreshDWStats(); });
  socket.on('device_found',  function() {
    if (document.querySelector('.nav-item.active') &&
        document.querySelector('.nav-item.active').dataset.panel === 'netscanner') {
      refreshDevices();
    }
  });
}

// ── DARK WEB MONITOR JS ──────────────────────────────────────
async function darkwebCheck() {
  var query = document.getElementById('dw-query').value.trim();
  var type  = document.getElementById('dw-type').value;
  if (!query) return;
  document.getElementById('dw-result').innerHTML =
    '<div class="font-mono text-dim" style="font-size:11px;padding:10px">Checking ' + query + '...</div>';
  try {
    var r = await fetch('/api/darkweb/check', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({query:query, type:type})
    });
    var d = await r.json();
    renderDWResult(d);
    refreshDWHistory();
    refreshDWStats();
  } catch(e) {
    document.getElementById('dw-result').innerHTML =
      '<div class="font-mono text-red" style="font-size:11px">' + e.message + '</div>';
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
  if (d.is_tor_exit)
    badges += '<span style="background:rgba(170,68,255,0.2);border:1px solid #aa44ff;color:#cc88ff;padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">TOR EXIT</span>';
  if (d.is_botnet)
    badges += '<span style="background:rgba(255,34,68,0.2);border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">BOTNET C2</span>';
  if (d.is_ransomware_infra)
    badges += '<span style="background:rgba(255,34,68,0.3);border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">RANSOMWARE: ' + d.ransomware_group + '</span>';
  if (d.found_in_breach)
    badges += '<span style="background:rgba(255,102,0,0.2);border:1px solid var(--orange);color:var(--orange);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px;font-family:var(--font-mono)">' + d.breach_count + ' BREACH(ES)</span>';

  var breachHTML = '';
  if (d.breaches && d.breaches.length) {
    breachHTML = '<div style="margin-bottom:10px"><div class="font-mono text-accent" style="font-size:10px;letter-spacing:1.5px;margin-bottom:6px">FOUND IN DATABASES:</div>';
    for (var i = 0; i < d.breaches.length; i++) {
      var b = d.breaches[i];
      breachHTML += '<div style="background:rgba(255,34,68,0.08);border-left:3px solid var(--red-dim);padding:8px 12px;margin-bottom:6px;border-radius:0 3px 3px 0">' +
        '<div style="font-weight:700;color:var(--text-bright);font-size:12px">' + b.name + '</div>' +
        '<div class="font-mono text-dim" style="font-size:10px">' + b.type + ' | ' + b.year + ' | ' + b.source + '</div>' +
        (b.description ? '<div class="font-mono text-dim" style="font-size:10px;margin-top:4px">' + b.description + '</div>' : '') +
        '</div>';
    }
    breachHTML += '</div>';
  } else {
    breachHTML = '<div style="color:var(--green);font-family:var(--font-mono);font-size:12px;margin-bottom:10px">Not found in breach databases</div>';
  }

  var recsHTML = '';
  if (d.recommendations && d.recommendations.length) {
    recsHTML = '<div style="border-top:1px solid var(--border);padding-top:10px"><div class="font-mono text-accent" style="font-size:10px;margin-bottom:6px">RECOMMENDATIONS:</div>';
    for (var j = 0; j < d.recommendations.length; j++) {
      recsHTML += '<div style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim);margin-bottom:4px">' +
        '<span style="color:var(--accent)">&#9654;</span> ' + d.recommendations[j] + '</div>';
    }
    recsHTML += '</div>';
  }

  document.getElementById('dw-result').innerHTML =
    '<div style="background:var(--bg-deep);border:2px solid ' + color + ';border-radius:4px;padding:16px;margin-top:10px">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">' +
    '<span class="font-mono" style="font-size:15px;font-weight:700;color:var(--text-bright)">' + d.query + '</span>' +
    '<div style="text-align:right">' +
    '<div style="font-family:var(--font-title);font-size:22px;font-weight:700;color:' + color + '">' + d.risk_score + '</div>' +
    '<div class="font-mono" style="font-size:10px;color:' + color + '">' + d.risk_level + ' RISK</div>' +
    '</div></div>' +
    (badges ? '<div style="margin-bottom:10px">' + badges + '</div>' : '') +
    breachHTML + recsHTML +
    '</div>';
}

async function refreshDWHistory() {
  try {
    var results = await (await fetch('/api/darkweb/results?n=30')).json();
    var el = document.getElementById('badge-dw-count');
    if (el) el.textContent = results.length + ' checks';
    var rc = {LOW:'var(--green)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
    var histEl = document.getElementById('dw-history');
    if (!histEl) return;
    if (!results.length) {
      histEl.innerHTML = '<div class="text-dim font-mono" style="font-size:11px;padding:20px;text-align:center">No checks yet</div>';
      return;
    }
    var out = '';
    for (var i = 0; i < results.length; i++) {
      var d = results[i];
      var color = rc[d.risk_level] || 'var(--text-dim)';
      var tags = '';
      if (d.is_tor_exit)         tags += '<span style="font-size:9px;color:#cc88ff;font-family:var(--font-mono)">TOR </span>';
      if (d.is_botnet)           tags += '<span style="font-size:9px;color:var(--red);font-family:var(--font-mono)">BOTNET </span>';
      if (d.is_ransomware_infra) tags += '<span style="font-size:9px;color:var(--red);font-family:var(--font-mono)">RANSOMWARE </span>';
      if (d.found_in_breach)     tags += '<span style="font-size:9px;color:var(--orange);font-family:var(--font-mono)">' + d.breach_count + ' BREACH </span>';
      out += '<div style="padding:10px 16px;border-bottom:1px solid rgba(15,61,92,0.3);cursor:pointer" ' +
        'onclick="dwQuick(\'' + d.query + '\',\'' + d.query_type + '\')">' +
        '<div style="display:flex;justify-content:space-between;align-items:center">' +
        '<span class="font-mono" style="color:var(--text-bright);font-weight:700">' + d.query + '</span>' +
        '<span style="color:' + color + ';font-size:12px;font-weight:700;font-family:var(--font-mono)">' + d.risk_score + ' ' + d.risk_level + '</span>' +
        '</div><div style="margin-top:3px">' + tags +
        '<span class="font-mono text-dim" style="font-size:9px">' + d.datetime + '</span></div></div>';
    }
    histEl.innerHTML = out;
  } catch(e) {}
}

async function refreshDWStats() {
  try {
    var s = await (await fetch('/api/darkweb/stats')).json();
    var t = document.getElementById('dw-total');     if(t) t.textContent = s.total_checks;
    var b = document.getElementById('dw-breached');  if(b) b.textContent = s.breached_found;
    var c = document.getElementById('dw-critical');  if(c) c.textContent = s.critical_findings;
    var m = document.getElementById('dw-monitoring');if(m) m.textContent = s.monitoring_targets;
  } catch(e) {}
}

async function saveDWConfig() {
  var key = document.getElementById('hibp-key').value.trim();
  try {
    await fetch('/api/darkweb/config', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({hibp_key: key})
    });
    document.getElementById('dw-config-msg').innerHTML = '<span class="text-green">Saved</span>';
  } catch(e) {
    document.getElementById('dw-config-msg').innerHTML = '<span class="text-red">Failed</span>';
  }
}

async function addDWMonitor() {
  var query = document.getElementById('dw-monitor-query').value.trim();
  if (!query) return;
  try {
    await fetch('/api/darkweb/monitor', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({query:query, type:'auto'})
    });
    document.getElementById('dw-monitor-query').value = '';
    refreshDWMonitorList();
    refreshDWStats();
  } catch(e) {}
}

async function removeDWMonitor(query) {
  try {
    await fetch('/api/darkweb/monitor/' + encodeURIComponent(query), {method:'DELETE'});
    refreshDWMonitorList();
    refreshDWStats();
  } catch(e) {}
}

async function refreshDWMonitorList() {
  try {
    var list = await (await fetch('/api/darkweb/monitor/list')).json();
    var el = document.getElementById('badge-dw-monitor');
    if (el) el.textContent = list.length + ' targets';
    var listEl = document.getElementById('dw-monitor-list');
    if (!listEl) return;
    if (!list.length) {
      listEl.innerHTML = '<div class="text-dim font-mono" style="font-size:11px;padding:10px;text-align:center">No targets</div>';
      return;
    }
    var out = '';
    for (var i = 0; i < list.length; i++) {
      var t = list[i];
      out += '<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 4px;border-bottom:1px solid rgba(15,61,92,0.3)">' +
        '<span class="font-mono text-accent" style="font-size:12px">' + t.query + '</span>' +
        '<button class="btn" style="padding:2px 6px;font-size:10px;border-color:var(--red);color:var(--red)" ' +
        'onclick="removeDWMonitor(\'' + t.query + '\')">remove</button></div>';
    }
    listEl.innerHTML = out;
  } catch(e) {}
}
"""

html = html.replace("</script>", FIXED_JS + "\n</script>")

with open(path, "w", encoding="utf-8") as f:
    f.write(html)

print("Fixed! All navigation + Dark Web JS rewritten cleanly.")
print("Run: python main.py")