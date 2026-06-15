import os

path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "dashboard", "index.html"
)

with open(path, "r", encoding="utf-8") as f:
    html = f.read()

# ── 1. New nav items ─────────────────────────────────────────
NEW_NAV = """
    <div class="nav-section">NEW FEATURES</div>
    <div class="nav-item" data-panel="intel" onclick="showPanel('intel', this)">
      <span class="nav-icon">🔍</span> Threat Intel
    </div>
    <div class="nav-item" data-panel="netscanner" onclick="showPanel('netscanner', this)">
      <span class="nav-icon">📡</span> Network Scanner
    </div>
    <div class="nav-item" data-panel="inspector" onclick="showPanel('inspector', this)">
      <span class="nav-icon">🔬</span> Packet Inspector
    </div>
    <div class="nav-item" data-panel="blocker" onclick="showPanel('blocker', this)">
      <span class="nav-icon">🚫</span> IP Blocker
    </div>
    <div class="nav-item" data-panel="alerts-config" onclick="showPanel('alerts-config', this)">
      <span class="nav-icon">🔔</span> Alert Config
    </div>
    <div class="nav-item" data-panel="reports" onclick="showPanel('reports', this)">
      <span class="nav-icon">📄</span> Reports
    </div>
"""
html = html.replace("</nav>", NEW_NAV + "</nav>")

# ── 2. New panel HTML ────────────────────────────────────────
NEW_PANELS = """
    <!-- THREAT INTEL -->
    <div class="panel" id="panel-intel">
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><div class="card-title">🔍 IP THREAT LOOKUP</div></div>
          <div class="card-body">
            <div class="form-group" style="margin-bottom:12px">
              <label>IP ADDRESS</label>
              <div style="display:flex;gap:8px;margin-top:6px">
                <input type="text" id="intel-ip" placeholder="e.g. 185.220.101.5"
                  style="flex:1;background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px 12px;font-family:var(--font-mono);
                  font-size:12px;border-radius:3px;outline:none">
                <button class="btn primary" onclick="lookupIP()">LOOKUP</button>
              </div>
            </div>
            <div id="intel-result"></div>
            <div style="margin-top:20px;border-top:1px solid var(--border);padding-top:16px">
              <div class="card-title" style="margin-bottom:10px">🔑 API KEYS (optional)</div>
              <div class="form-group" style="margin-bottom:8px">
                <label>VIRUSTOTAL KEY</label>
                <input type="password" id="vt-key" placeholder="virustotal.com — free key"
                  style="width:100%;background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px;font-family:var(--font-mono);
                  font-size:12px;border-radius:3px;outline:none;margin-top:4px">
              </div>
              <div class="form-group" style="margin-bottom:10px">
                <label>ABUSEIPDB KEY</label>
                <input type="password" id="abuse-key" placeholder="abuseipdb.com — free key"
                  style="width:100%;background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px;font-family:var(--font-mono);
                  font-size:12px;border-radius:3px;outline:none;margin-top:4px">
              </div>
              <button class="btn primary" onclick="saveIntelKeys()">SAVE KEYS</button>
              <div id="intel-key-msg" class="font-mono text-dim" style="font-size:11px;margin-top:8px"></div>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-header">
            <div class="card-title">RECENT LOOKUPS</div>
            <div class="card-badge" id="badge-intel-count">0 lookups</div>
          </div>
          <div id="intel-history" style="max-height:500px;overflow-y:auto">
            <div class="text-dim font-mono" style="font-size:11px;padding:20px;text-align:center">No lookups yet</div>
          </div>
        </div>
      </div>
    </div>

    <!-- NETWORK SCANNER -->
    <div class="panel" id="panel-netscanner">
      <div class="card" style="margin-bottom:16px">
        <div class="card-header">
          <div class="card-title">📡 LAN DEVICE SCANNER</div>
          <div class="flex-gap">
            <div id="scan-status-dot" class="status-dot" style="background:var(--text-dim);animation:none"></div>
            <span id="scan-status-label" class="font-mono text-dim" style="font-size:11px">IDLE</span>
          </div>
        </div>
        <div class="card-body" style="display:flex;gap:16px;align-items:flex-end;flex-wrap:wrap">
          <div class="form-group" style="flex:1;min-width:200px">
            <label>NETWORK CIDR (blank = auto-detect)</label>
            <input type="text" id="scan-network" placeholder="e.g. 192.168.1.0/24"
              style="width:100%;background:var(--bg-deep);border:1px solid var(--border);
              color:var(--text-main);padding:8px 12px;font-family:var(--font-mono);
              font-size:12px;border-radius:3px;outline:none;margin-top:4px">
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn primary" onclick="startNetScan(true)">🔍 FULL SCAN</button>
            <button class="btn" onclick="startNetScan(false)">⚡ QUICK SCAN</button>
          </div>
        </div>
        <div style="padding:8px 16px">
          <div style="height:6px;background:var(--bg-deep);border-radius:3px;overflow:hidden">
            <div id="scan-progress-bar" style="height:100%;width:0%;background:linear-gradient(90deg,var(--accent-dim),var(--accent));border-radius:3px;transition:width 0.5s ease"></div>
          </div>
          <div class="font-mono text-dim" style="font-size:10px;margin-top:4px" id="scan-progress-text">Ready</div>
        </div>
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title">DISCOVERED DEVICES</div>
          <div class="card-badge" id="badge-device-count">0 devices</div>
        </div>
        <div style="overflow-x:auto">
          <table class="threat-table">
            <thead><tr>
              <th>IP</th><th>HOSTNAME</th><th>MAC</th><th>VENDOR</th>
              <th>OPEN PORTS</th><th>OS</th><th>RISK</th><th>RTT</th><th>ACTION</th>
            </tr></thead>
            <tbody id="devices-tbody">
              <tr><td colspan="9" style="text-align:center;color:var(--text-dim);padding:40px;font-family:var(--font-mono);font-size:11px">Run a scan to discover devices</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- PACKET INSPECTOR -->
    <div class="panel" id="panel-inspector">
      <div class="card" style="margin-bottom:16px">
        <div class="card-header">
          <div class="card-title">🔬 PACKET INSPECTOR</div>
          <div class="flex-gap">
            <select id="filter-proto" onchange="refreshInspector()"
              style="background:var(--bg-deep);border:1px solid var(--border);
              color:var(--text-main);padding:3px 8px;font-size:11px;
              font-family:var(--font-mono);border-radius:2px">
              <option value="">ALL</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
            <input type="text" id="filter-src" placeholder="src IP"
              style="background:var(--bg-deep);border:1px solid var(--border);
              color:var(--text-main);padding:3px 8px;font-size:11px;
              font-family:var(--font-mono);border-radius:2px;width:120px">
            <button class="btn primary" onclick="refreshInspector()" style="padding:4px 12px;font-size:11px">↻ REFRESH</button>
          </div>
        </div>
        <div style="overflow-x:auto">
          <table class="threat-table">
            <thead><tr>
              <th>#</th><th>TIME</th><th>PROTO</th><th>SOURCE</th>
              <th>DESTINATION</th><th>SIZE</th><th>FLAGS</th><th>LAYERS</th><th>ANOMALIES</th><th>ACTION</th>
            </tr></thead>
            <tbody id="inspector-tbody">
              <tr><td colspan="10" style="text-align:center;color:var(--text-dim);padding:40px;font-family:var(--font-mono);font-size:11px">Waiting for packets...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
      <div class="card" id="pkt-detail-card" style="display:none">
        <div class="card-header">
          <div class="card-title">PACKET DETAIL</div>
          <button class="btn" onclick="document.getElementById('pkt-detail-card').style.display='none'" style="padding:3px 10px;font-size:11px">✕ CLOSE</button>
        </div>
        <div class="card-body" id="pkt-detail-body"></div>
      </div>
    </div>

    <!-- IP BLOCKER -->
    <div class="panel" id="panel-blocker">
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><div class="card-title">🚫 BLOCK AN IP</div></div>
          <div class="card-body">
            <div class="sim-form">
              <div class="form-group">
                <label>IP ADDRESS</label>
                <input type="text" id="block-ip" placeholder="e.g. 192.168.1.42"
                  style="width:100%;background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px;font-family:var(--font-mono);
                  font-size:12px;border-radius:3px;outline:none">
              </div>
              <div class="form-group">
                <label>SEVERITY</label>
                <select id="block-sev" style="width:100%;background:var(--bg-deep);
                  border:1px solid var(--border);color:var(--text-main);padding:8px;
                  font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none">
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH" selected>HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                </select>
              </div>
            </div>
            <div class="form-group" style="margin-top:10px">
              <label>REASON</label>
              <input type="text" id="block-reason" placeholder="e.g. Port scan detected"
                style="width:100%;background:var(--bg-deep);border:1px solid var(--border);
                color:var(--text-main);padding:8px;font-family:var(--font-mono);
                font-size:12px;border-radius:3px;outline:none;margin-top:4px">
            </div>
            <button class="btn danger" onclick="blockIP()" style="margin-top:12px">🚫 BLOCK IP</button>
            <div id="block-feedback" class="font-mono text-dim" style="font-size:11px;margin-top:10px"></div>
            <div style="margin-top:20px;border-top:1px solid var(--border);padding-top:16px">
              <div class="card-title" style="margin-bottom:10px">⚙️ AUTO-BLOCK</div>
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
                <input type="checkbox" id="auto-block-enabled" style="width:16px;height:16px">
                <label class="font-mono text-dim" style="font-size:11px">Auto-block severity:</label>
                <select id="auto-block-sev" style="background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:4px 8px;font-family:var(--font-mono);
                  font-size:11px;border-radius:3px">
                  <option value="CRITICAL">CRITICAL only</option>
                  <option value="HIGH" selected>HIGH+</option>
                  <option value="MEDIUM">MEDIUM+</option>
                </select>
              </div>
              <button class="btn primary" onclick="saveAutoBlock()" style="font-size:11px;padding:6px 12px">SAVE</button>
            </div>
            <div id="blocker-stats" class="font-mono text-dim" style="font-size:11px;line-height:2;margin-top:16px;border-top:1px solid var(--border);padding-top:12px">Loading...</div>
          </div>
        </div>
        <div class="card">
          <div class="card-header">
            <div class="card-title">BLOCKED IPs</div>
            <div class="card-badge" id="badge-blocked-count">0 blocked</div>
          </div>
          <div id="blocked-list" style="max-height:500px;overflow-y:auto">
            <div class="text-dim font-mono" style="font-size:11px;padding:20px;text-align:center">No IPs blocked</div>
          </div>
        </div>
      </div>
    </div>

    <!-- ALERT CONFIG -->
    <div class="panel" id="panel-alerts-config">
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><div class="card-title">📧 EMAIL ALERTS</div></div>
          <div class="card-body">
            <div class="sim-form">
              <div class="form-group">
                <label>SMTP HOST</label>
                <input type="text" id="smtp-host" value="smtp.gmail.com"
                  style="width:100%;background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px;font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none">
              </div>
              <div class="form-group">
                <label>SMTP PORT</label>
                <input type="number" id="smtp-port" value="587"
                  style="width:100%;background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px;font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none">
              </div>
              <div class="form-group">
                <label>FROM EMAIL</label>
                <input type="email" id="email-from" placeholder="your@gmail.com"
                  style="width:100%;background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px;font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none">
              </div>
              <div class="form-group">
                <label>APP PASSWORD</label>
                <input type="password" id="smtp-pass" placeholder="Gmail app password"
                  style="width:100%;background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px;font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none">
              </div>
              <div class="form-group" style="grid-column:1/-1">
                <label>SEND TO</label>
                <input type="text" id="email-to" placeholder="alert@example.com"
                  style="width:100%;background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px;font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none">
              </div>
              <div class="form-group">
                <label>MIN SEVERITY</label>
                <select id="email-min-sev" style="width:100%;background:var(--bg-deep);
                  border:1px solid var(--border);color:var(--text-main);padding:8px;
                  font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none">
                  <option value="CRITICAL">CRITICAL only</option>
                  <option value="HIGH" selected>HIGH+</option>
                  <option value="MEDIUM">MEDIUM+</option>
                  <option value="LOW">All</option>
                </select>
              </div>
              <div class="form-group" style="display:flex;align-items:center;gap:8px">
                <input type="checkbox" id="email-enabled" style="width:16px;height:16px">
                <label class="font-mono text-dim" style="font-size:11px">Enable email alerts</label>
              </div>
            </div>
            <button class="btn primary" onclick="saveEmailConfig()" style="margin-top:12px">SAVE EMAIL CONFIG</button>
            <div id="email-msg" class="font-mono text-dim" style="font-size:11px;margin-top:8px"></div>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">🔗 WEBHOOK (SLACK/TEAMS)</div></div>
          <div class="card-body">
            <div class="form-group" style="margin-bottom:12px">
              <label>WEBHOOK URL</label>
              <input type="text" id="webhook-url" placeholder="https://hooks.slack.com/..."
                style="width:100%;background:var(--bg-deep);border:1px solid var(--border);
                color:var(--text-main);padding:8px;font-family:var(--font-mono);
                font-size:12px;border-radius:3px;outline:none;margin-top:4px">
            </div>
            <div class="form-group" style="margin-bottom:12px">
              <label>MIN SEVERITY</label>
              <select id="webhook-min-sev" style="width:100%;background:var(--bg-deep);
                border:1px solid var(--border);color:var(--text-main);padding:8px;
                font-family:var(--font-mono);font-size:12px;border-radius:3px;outline:none;margin-top:4px">
                <option value="CRITICAL">CRITICAL only</option>
                <option value="HIGH" selected>HIGH+</option>
                <option value="MEDIUM">MEDIUM+</option>
              </select>
            </div>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
              <input type="checkbox" id="webhook-enabled" style="width:16px;height:16px">
              <label class="font-mono text-dim" style="font-size:11px">Enable webhook</label>
            </div>
            <button class="btn primary" onclick="saveWebhookConfig()">SAVE WEBHOOK</button>
            <div id="webhook-msg" class="font-mono text-dim" style="font-size:11px;margin-top:8px"></div>
            <div style="margin-top:20px;border-top:1px solid var(--border);padding-top:12px;font-family:var(--font-mono);font-size:11px;color:var(--text-dim);line-height:1.8">
              <strong style="color:var(--accent)">Slack setup:</strong><br>
              1. api.slack.com/apps → Create App<br>
              2. Incoming Webhooks → Activate<br>
              3. Add Webhook → Copy URL above
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- REPORTS -->
    <div class="panel" id="panel-reports">
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><div class="card-title">📄 EXPORT REPORTS</div></div>
          <div class="card-body">
            <div style="display:flex;flex-direction:column;gap:16px">
              <div style="background:var(--bg-deep);border:1px solid var(--border);border-radius:4px;padding:16px">
                <div style="font-weight:700;color:var(--text-bright);margin-bottom:6px">📊 CSV Report</div>
                <div class="font-mono text-dim" style="font-size:11px;margin-bottom:12px">All threat events — Excel/Sheets compatible</div>
                <a href="/api/report/csv" class="btn primary" style="text-decoration:none;display:inline-flex">⬇ DOWNLOAD CSV</a>
              </div>
              <div style="background:var(--bg-deep);border:1px solid var(--border);border-radius:4px;padding:16px">
                <div style="font-weight:700;color:var(--text-bright);margin-bottom:6px">📑 PDF Report</div>
                <div class="font-mono text-dim" style="font-size:11px;margin-bottom:12px">Professional incident report with summary + tables</div>
                <a href="/api/report/pdf" class="btn primary" style="text-decoration:none;display:inline-flex">⬇ DOWNLOAD PDF</a>
              </div>
              <div style="background:var(--bg-deep);border:1px solid var(--border);border-radius:4px;padding:12px">
                <div class="font-mono text-accent" style="font-size:11px;margin-bottom:6px">Enable PDF (better formatting):</div>
                <div class="font-mono" style="background:var(--bg-void);padding:8px;border-radius:3px;font-size:11px;color:var(--green)">pip install reportlab</div>
              </div>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">📈 SESSION SUMMARY</div></div>
          <div class="card-body" id="report-summary">
            <div class="text-dim font-mono" style="font-size:11px">Loading...</div>
          </div>
        </div>
      </div>
    </div>
"""
html = html.replace("  </main>", NEW_PANELS + "\n  </main>")

# ── 3. New JavaScript ────────────────────────────────────────
NEW_JS = """
// ── THREAT INTEL ─────────────────────────────────────────────
async function lookupIP() {
  const ip = document.getElementById('intel-ip').value.trim();
  if (!ip) return;
  document.getElementById('intel-result').innerHTML =
    '<div class="font-mono text-dim" style="font-size:11px;padding:10px">Looking up ' + ip + '...</div>';
  try {
    const r = await fetch('/api/intel/lookup', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ip})
    });
    renderIntelResult(await r.json());
    refreshIntelHistory();
  } catch(e) {
    document.getElementById('intel-result').innerHTML =
      '<div class="font-mono text-red" style="font-size:11px">' + e.message + '</div>';
  }
}

function renderIntelResult(d) {
  const rc = {LOW:'var(--accent)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)',PRIVATE:'var(--green)',UNKNOWN:'var(--text-dim)'};
  const c  = rc[d.risk_level] || 'var(--text-dim)';
  document.getElementById('intel-result').innerHTML = `
    <div style="background:var(--bg-deep);border:1px solid var(--border);border-radius:4px;padding:14px;margin-top:10px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
        <span class="font-mono" style="font-size:16px;font-weight:700;color:var(--text-bright)">${d.ip}</span>
        <span class="sev-badge" style="color:${c};border-color:${c}">${d.risk_level}</span>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-family:var(--font-mono);font-size:11px;margin-bottom:10px">
        <div><span class="text-dim">VirusTotal:</span> <span class="text-accent">${d.virustotal_score||'N/A'}</span></div>
        <div><span class="text-dim">AbuseIPDB:</span> <span style="color:${(d.abuseipdb_score||0)>50?'var(--red)':'var(--green)'}">${d.abuseipdb_score!=null?d.abuseipdb_score+'%':'N/A'}</span></div>
        <div><span class="text-dim">Country:</span> ${d.abuseipdb_country||'Unknown'}</div>
        <div><span class="text-dim">ISP:</span> ${d.abuseipdb_isp||'Unknown'}</div>
        <div><span class="text-dim">Reports:</span> ${d.abuseipdb_reports??'N/A'}</div>
        <div><span class="text-dim">Malicious:</span> <span style="color:${d.is_malicious?'var(--red)':'var(--green)'}">${d.is_malicious?'YES':'NO'}</span></div>
      </div>
      ${d.tags.length?`<div>${d.tags.map(t=>`<span style="background:var(--bg-panel);border:1px solid var(--border);padding:2px 6px;border-radius:2px;margin:2px;display:inline-block;font-size:10px;font-family:var(--font-mono)">${t}</span>`).join('')}</div>`:''}
      ${d.error?`<div class="font-mono text-orange" style="font-size:11px;margin-top:8px">⚠ ${d.error}</div>`:''}
    </div>`;
}

async function refreshIntelHistory() {
  try {
    const r = await fetch('/api/intel/results?n=20');
    const results = await r.json();
    document.getElementById('badge-intel-count').textContent = results.length + ' lookups';
    const rc = {LOW:'var(--accent)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)',PRIVATE:'var(--green)',UNKNOWN:'var(--text-dim)'};
    document.getElementById('intel-history').innerHTML = results.length ?
      results.map(d=>`
        <div style="padding:10px 16px;border-bottom:1px solid rgba(15,61,92,0.3);cursor:pointer"
          onclick="document.getElementById('intel-ip').value='${d.ip}';renderIntelResult(${JSON.stringify(d).replace(/'/g,"\\'")})">
          <div style="display:flex;justify-content:space-between">
            <span class="font-mono" style="color:var(--text-bright)">${d.ip}</span>
            <span style="color:${rc[d.risk_level]||'var(--text-dim)'};font-size:11px;font-weight:700">${d.risk_level}</span>
          </div>
          <div class="font-mono text-dim" style="font-size:10px">${d.datetime} | ${d.abuseipdb_country||''} ${d.abuseipdb_isp||''}</div>
        </div>`).join('') :
      '<div class="text-dim font-mono" style="font-size:11px;padding:20px;text-align:center">No lookups yet</div>';
  } catch(e) {}
}

async function saveIntelKeys() {
  try {
    await fetch('/api/intel/config', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        virustotal_key: document.getElementById('vt-key').value,
        abuseipdb_key:  document.getElementById('abuse-key').value
      })
    });
    document.getElementById('intel-key-msg').innerHTML = '<span class="text-green">✓ Keys saved</span>';
  } catch(e) {
    document.getElementById('intel-key-msg').innerHTML = '<span class="text-red">✗ Failed</span>';
  }
}

// ── NETWORK SCANNER ──────────────────────────────────────────
async function startNetScan(withPorts) {
  const network = document.getElementById('scan-network').value.trim() || null;
  document.getElementById('scan-status-dot').style.background = 'var(--green)';
  document.getElementById('scan-status-dot').style.animation  = 'blink 1s infinite';
  document.getElementById('scan-status-label').textContent = 'SCANNING...';
  document.getElementById('scan-progress-bar').style.width = '5%';
  try {
    await fetch('/api/scan/network', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({network, port_scan: withPorts})
    });
    pollScanStatus();
  } catch(e) {
    document.getElementById('scan-status-label').textContent = 'ERROR';
  }
}

function pollScanStatus() {
  const iv = setInterval(async () => {
    try {
      const s = await (await fetch('/api/scan/status')).json();
      const pct = s.total > 0 ? Math.round(s.progress/s.total*100) : 10;
      document.getElementById('scan-progress-bar').style.width = pct + '%';
      document.getElementById('scan-progress-text').textContent =
        `Scanned ${s.progress}/${s.total} hosts — ${s.devices_found} found`;
      if (!s.scanning) {
        clearInterval(iv);
        document.getElementById('scan-status-dot').style.animation = 'none';
        document.getElementById('scan-status-dot').style.background = 'var(--accent)';
        document.getElementById('scan-status-label').textContent = 'COMPLETE';
        document.getElementById('scan-progress-bar').style.width = '100%';
        refreshDevices();
      }
    } catch(e) { clearInterval(iv); }
  }, 1000);
}

async function refreshDevices() {
  try {
    const devices = await (await fetch('/api/scan/devices')).json();
    document.getElementById('badge-device-count').textContent = devices.length + ' devices';
    if (!devices.length) return;
    const rc = {LOW:'var(--accent)',MEDIUM:'var(--yellow)',HIGH:'var(--red)'};
    document.getElementById('devices-tbody').innerHTML = devices.map(d=>`
      <tr>
        <td class="font-mono text-accent">${d.ip}</td>
        <td class="font-mono text-dim" style="font-size:11px">${d.hostname||'—'}</td>
        <td class="font-mono text-dim" style="font-size:10px">${d.mac||'—'}</td>
        <td style="font-size:11px">${d.vendor||'Unknown'}</td>
        <td class="font-mono" style="font-size:10px">${d.open_ports.map(p=>`<span style="color:var(--accent)">${p.port}/${p.service}</span>`).join(' ')||'—'}</td>
        <td style="font-size:11px;color:var(--text-dim)">${d.os_guess}</td>
        <td><span style="color:${rc[d.risk]||'var(--text-dim)'};font-weight:700;font-size:11px">${d.risk}</span></td>
        <td class="font-mono text-dim" style="font-size:11px">${d.response_time_ms}ms</td>
        <td style="display:flex;gap:4px">
          <button class="btn" style="padding:2px 6px;font-size:10px"
            onclick="document.getElementById('block-ip').value='${d.ip}';showPanel('blocker',document.querySelector('[data-panel=blocker]'))">🚫</button>
          <button class="btn" style="padding:2px 6px;font-size:10px"
            onclick="document.getElementById('intel-ip').value='${d.ip}';showPanel('intel',document.querySelector('[data-panel=intel]'));lookupIP()">🔍</button>
        </td>
      </tr>`).join('');
  } catch(e) {}
}

// ── PACKET INSPECTOR ─────────────────────────────────────────
async function refreshInspector() {
  const proto = document.getElementById('filter-proto').value;
  const src   = document.getElementById('filter-src').value;
  try {
    const params = new URLSearchParams({n:100});
    if (proto) params.append('protocol', proto);
    if (src)   params.append('src_ip', src);
    const pkts = await (await fetch('/api/inspect/packets?' + params)).json();
    const tbody = document.getElementById('inspector-tbody');
    if (!pkts.length) {
      tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--text-dim);padding:30px;font-family:var(--font-mono);font-size:11px">No packets yet</td></tr>';
      return;
    }
    tbody.innerHTML = [...pkts].reverse().slice(0,100).map(p=>`
      <tr>
        <td class="font-mono text-dim" style="font-size:10px">${p.id}</td>
        <td class="font-mono text-dim" style="font-size:10px">${(p.datetime||'').slice(11)}</td>
        <td><span class="proto-badge proto-${p.protocol}">${p.protocol}</span></td>
        <td class="font-mono" style="font-size:11px">${p.src_ip}:${p.src_port}</td>
        <td class="font-mono text-dim" style="font-size:11px">${p.dst_ip}:${p.dst_port}</td>
        <td class="font-mono text-dim" style="font-size:11px">${p.size}B</td>
        <td class="font-mono text-accent" style="font-size:10px">${p.flags||'—'}</td>
        <td style="font-size:10px;color:var(--text-dim)">${(p.layers||[]).join(' › ')}</td>
        <td>${p.anomalies?.length?`<span class="text-red" style="font-size:10px">⚠ ${p.anomalies.length}</span>`:'<span class="text-dim" style="font-size:10px">—</span>'}</td>
        <td><button class="btn" style="padding:2px 8px;font-size:10px" onclick="showPacketDetail(${p.id})">INSPECT</button></td>
      </tr>`).join('');
  } catch(e) {}
}
setInterval(()=>{ if(document.querySelector('.nav-item.active')?.dataset.panel==='inspector') refreshInspector(); }, 2000);

async function showPacketDetail(id) {
  try {
    const p = await (await fetch('/api/inspect/packet/'+id)).json();
    document.getElementById('pkt-detail-card').style.display = 'block';
    document.getElementById('pkt-detail-body').innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;font-family:var(--font-mono);font-size:11px;margin-bottom:12px">
        <div><span class="text-dim">ID:</span> ${p.id}</div>
        <div><span class="text-dim">Proto:</span> <span class="text-accent">${p.protocol}</span></div>
        <div><span class="text-dim">Size:</span> ${p.size}B</div>
        <div><span class="text-dim">Src:</span> ${p.src_ip}:${p.src_port}</div>
        <div><span class="text-dim">Dst:</span> ${p.dst_ip}:${p.dst_port}</div>
        <div><span class="text-dim">TTL:</span> ${p.ttl}</div>
        <div><span class="text-dim">Flags:</span> <span class="text-accent">${p.flags||'—'}</span></div>
        <div><span class="text-dim">Time:</span> ${p.datetime}</div>
        <div><span class="text-dim">Layers:</span> ${(p.layers||[]).join(' › ')}</div>
      </div>
      ${Object.keys(p.decoded||{}).length?`
        <div style="border-top:1px solid var(--border);padding-top:10px;margin-bottom:10px">
          <div class="font-mono text-accent" style="font-size:10px;letter-spacing:1.5px;margin-bottom:6px">DECODED</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-family:var(--font-mono);font-size:11px">
            ${Object.entries(p.decoded).map(([k,v])=>`<div><span class="text-dim">${k}:</span> ${v}</div>`).join('')}
          </div>
        </div>`:''}
      ${p.anomalies?.length?`
        <div style="border-top:1px solid var(--border);padding-top:10px;margin-bottom:10px">
          <div class="font-mono text-red" style="font-size:10px;margin-bottom:6px">⚠ ANOMALIES</div>
          ${p.anomalies.map(a=>`<div class="font-mono text-orange" style="font-size:11px">• ${a}</div>`).join('')}
        </div>`:''}
      ${p.payload_hex?`
        <div style="border-top:1px solid var(--border);padding-top:10px">
          <div class="font-mono text-accent" style="font-size:10px;margin-bottom:6px">PAYLOAD (first 64B)</div>
          <div style="background:var(--bg-void);padding:10px;border-radius:3px;font-family:var(--font-mono);font-size:11px">
            <div class="text-dim">HEX:   <span class="text-green">${p.payload_hex.match(/.{1,2}/g)?.join(' ')||''}</span></div>
            <div class="text-dim" style="margin-top:4px">ASCII: <span class="text-accent">${p.payload_ascii}</span></div>
          </div>
        </div>`:''}`;
    document.getElementById('pkt-detail-card').scrollIntoView({behavior:'smooth'});
  } catch(e) {}
}

// ── IP BLOCKER ───────────────────────────────────────────────
async function blockIP() {
  const ip     = document.getElementById('block-ip').value.trim();
  const sev    = document.getElementById('block-sev').value;
  const reason = document.getElementById('block-reason').value;
  if (!ip) return;
  try {
    const data = await (await fetch('/api/block', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ip, severity:sev, reason})
    })).json();
    document.getElementById('block-feedback').innerHTML =
      data.success ?
      `<span class="text-green">✓ ${ip} blocked via ${data.method}</span>` :
      `<span class="text-orange">⚠ ${data.error}</span>`;
    refreshBlockList();
  } catch(e) {
    document.getElementById('block-feedback').innerHTML = `<span class="text-red">✗ ${e.message}</span>`;
  }
}

async function unblockIP(ip) {
  try {
    await fetch('/api/block/' + encodeURIComponent(ip), {method:'DELETE'});
    refreshBlockList();
  } catch(e) {}
}

async function refreshBlockList() {
  try {
    const list = await (await fetch('/api/block/list')).json();
    document.getElementById('badge-blocked-count').textContent =
      list.filter(b=>b.active).length + ' blocked';
    document.getElementById('blocked-list').innerHTML = list.length ?
      list.map(b=>`
        <div style="padding:10px 16px;border-bottom:1px solid rgba(15,61,92,0.3);display:flex;justify-content:space-between;align-items:center">
          <div>
            <div class="font-mono" style="color:${b.active?'var(--red)':'var(--text-dim)'};font-weight:700">${b.ip} ${b.active?'🚫':''}</div>
            <div class="font-mono text-dim" style="font-size:10px">${b.reason} | ${b.datetime} | ${b.blocked_by}</div>
          </div>
          ${b.active?`<button class="btn" style="padding:3px 8px;font-size:10px;border-color:var(--green);color:var(--green)" onclick="unblockIP('${b.ip}')">UNBLOCK</button>`:'<span class="font-mono text-dim" style="font-size:10px">INACTIVE</span>'}
        </div>`).join('') :
      '<div class="text-dim font-mono" style="font-size:11px;padding:20px;text-align:center">No IPs blocked</div>';

    const stats = await (await fetch('/api/block/stats')).json();
    document.getElementById('blocker-stats').innerHTML = `
      Active blocks: <span class="text-red">${stats.active_blocks}</span><br>
      Total blocked: <span class="text-accent">${stats.total_blocked}</span><br>
      Method: <span class="text-green">${stats.method}</span><br>
      Admin: <span class="${stats.has_admin?'text-green':'text-orange'}">${stats.has_admin?'YES — real firewall':'NO — soft block'}</span>`;
  } catch(e) {}
}

async function saveAutoBlock() {
  try {
    await fetch('/api/block/auto', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        enabled:      document.getElementById('auto-block-enabled').checked,
        min_severity: document.getElementById('auto-block-sev').value
      })
    });
    document.getElementById('block-feedback').innerHTML =
      '<span class="text-green">✓ Auto-block saved</span>';
  } catch(e) {}
}

// ── ALERT CONFIG ─────────────────────────────────────────────
async function saveEmailConfig() {
  try {
    await fetch('/api/config/alert', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        email_enabled:     document.getElementById('email-enabled').checked,
        smtp_host:         document.getElementById('smtp-host').value,
        smtp_port:         parseInt(document.getElementById('smtp-port').value),
        smtp_user:         document.getElementById('email-from').value,
        smtp_password:     document.getElementById('smtp-pass').value,
        email_from:        document.getElementById('email-from').value,
        email_to:          document.getElementById('email-to').value.split(',').map(s=>s.trim()),
        email_min_severity: document.getElementById('email-min-sev').value,
      })
    });
    document.getElementById('email-msg').innerHTML = '<span class="text-green">✓ Saved</span>';
  } catch(e) {
    document.getElementById('email-msg').innerHTML = '<span class="text-red">✗ Failed</span>';
  }
}

async function saveWebhookConfig() {
  try {
    await fetch('/api/config/alert', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        webhook_enabled:      document.getElementById('webhook-enabled').checked,
        webhook_url:          document.getElementById('webhook-url').value,
        webhook_min_severity: document.getElementById('webhook-min-sev').value,
      })
    });
    document.getElementById('webhook-msg').innerHTML = '<span class="text-green">✓ Saved</span>';
  } catch(e) {
    document.getElementById('webhook-msg').innerHTML = '<span class="text-red">✗ Failed</span>';
  }
}

// ── REPORTS ──────────────────────────────────────────────────
async function loadReportSummary() {
  try {
    const s  = await (await fetch('/api/status')).json();
    const ec = s.event_counts || {};
    document.getElementById('report-summary').innerHTML = `
      <div style="font-family:var(--font-mono);font-size:12px;line-height:2.2">
        <div><span class="text-dim">Packets:</span> <span class="text-accent">${(s.total_packets||0).toLocaleString()}</span></div>
        <div><span class="text-dim">Bytes:</span>   <span class="text-accent">${fmtBytes(s.total_bytes||0)}</span></div>
        <div><span class="text-dim">Uptime:</span>  <span class="text-accent">${Math.floor((s.uptime_secs||0)/60)}m ${(s.uptime_secs||0)%60|0}s</span></div>
        <div><span class="text-dim">CRITICAL:</span> <span class="text-red">${ec.CRITICAL||0}</span></div>
        <div><span class="text-dim">HIGH:</span>     <span class="text-orange">${ec.HIGH||0}</span></div>
        <div><span class="text-dim">MEDIUM:</span>   <span class="text-yellow">${ec.MEDIUM||0}</span></div>
        <div><span class="text-dim">LOW:</span>      <span class="text-accent">${ec.LOW||0}</span></div>
        <div><span class="text-dim">Alerts:</span>   <span class="text-accent">${s.alert_stats?.total_dispatched||0}</span></div>
        <div><span class="text-dim">ML Model:</span> <span class="${s.ml_trained?'text-green':'text-dim'}">${s.ml_trained?'TRAINED':'TRAINING'}</span></div>
      </div>`;
  } catch(e) {}
}

// ── PANEL HOOK ───────────────────────────────────────────────
const _orig = showPanel;
showPanel = function(name, el) {
  _orig(name, el);
  if (name==='intel')        refreshIntelHistory();
  if (name==='netscanner')   refreshDevices();
  if (name==='inspector')    refreshInspector();
  if (name==='blocker')      refreshBlockList();
  if (name==='reports')      loadReportSummary();
};

socket.on('intel_result',  () => refreshIntelHistory());
socket.on('device_found',  () => { if(document.querySelector('.nav-item.active')?.dataset.panel==='netscanner') refreshDevices(); });
socket.on('ip_blocked',    () => { if(document.querySelector('.nav-item.active')?.dataset.panel==='blocker') refreshBlockList(); });
"""

html = html.replace("</script>", NEW_JS + "\n</script>")

with open(path, "w", encoding="utf-8") as f:
    f.write(html)

print(f"Done! File size: {len(html):,} chars")