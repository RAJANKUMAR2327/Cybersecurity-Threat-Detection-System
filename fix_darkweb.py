import os, re

path = os.path.join("dashboard", "index.html")
with open(path, "r", encoding="utf-8") as f:
    html = f.read()

# Remove any broken darkweb patches first
if "panel-darkweb" in html:
    print("Removing broken patch...")
    # Remove broken nav item
    html = re.sub(
        r'\s*<div class="nav-item" data-panel="darkweb".*?</div>\s*',
        '\n    ',
        html, flags=re.DOTALL
    )
    # Remove broken panel
    html = re.sub(
        r'\s*<!-- DARK WEB MONITOR -->.*?</div>\s*(?=\s*</main>)',
        '\n  ',
        html, flags=re.DOTALL
    )
    # Remove broken JS
    html = re.sub(
        r'// ── DARK WEB MONITOR.*?socket\.on\(\'darkweb_result\'.*?\}\);',
        '',
        html, flags=re.DOTALL
    )
    print("Broken patch removed.")

# Fix the showPanel override stacking issue
# Replace ALL showPanel overrides with a single clean version
html = re.sub(
    r'(const _orig\w+ = showPanel;[\s\S]*?showPanel = function.*?\};)',
    '',
    html
)

# Add single clean showPanel override before </script>
CLEAN_OVERRIDE = """
// ── UNIFIED PANEL HANDLER ────────────────────────────────────
const _origShowPanel = window._origShowPanel || showPanel;
window._origShowPanel = _origShowPanel;
showPanel = function(name, el) {
  _origShowPanel(name, el);
  if (name === 'threats')      refreshThreats();
  if (name === 'flows')        refreshFlows();
  if (name === 'malware')      refreshMalware();
  if (name === 'intel')        refreshIntelHistory();
  if (name === 'netscanner')   refreshDevices();
  if (name === 'inspector')    refreshInspector();
  if (name === 'blocker')      refreshBlockList();
  if (name === 'reports')      loadReportSummary();
  if (name === 'darkweb') {
    refreshDWHistory();
    refreshDWStats();
    refreshMonitorList();
  }
};
"""

html = html.replace("</script>", CLEAN_OVERRIDE + "\n</script>")

with open(path, "w", encoding="utf-8") as f:
    f.write(html)
print("Fixed! Run python main.py")