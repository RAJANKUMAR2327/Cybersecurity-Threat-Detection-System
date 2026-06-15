path = "dashboard/dashboard_server.py"
with open(path, encoding="utf-8") as f:
    content = f.read()

# Check what instances exist
print("Has honeypots:", "honeypots" in content)
print("Has HoneypotManager:", "HoneypotManager" in content)
print("Has ai =", "ai           =" in content)
print("Has geomap =", "geomap       =" in content)

# Fix 1: Remove broken honeypot callback from start_system
content = content.replace(
    "def start_system():\n    def on_honeypot_event(event):\n        socketio.emit('honeypot_event', event.to_dict())\n    honeypots._callback = on_honeypot_event\n    monitor.start()",
    "def start_system():\n    monitor.start()"
)

# Fix 2: Make sure all instances are defined
# Find where darkweb is defined and add missing ones after it
if "honeypots    = HoneypotManager()" not in content:
    content = content.replace(
        "darkweb      = DarkWebMonitor()",
        "darkweb      = DarkWebMonitor()\n"
        "ai           = AIAssistant()\n"
        "geomap       = GeoIPMap()\n"
        "vulns        = VulnerabilityScanner()\n"
        "honeypots    = HoneypotManager()\n"
        "timeline     = TimelineEngine()"
    )
    print("Added missing instances")

# Fix 3: Add honeypot callback cleanly in start_system
if "on_honeypot_event" not in content:
    content = content.replace(
        "def start_system():\n    monitor.start()",
        "def start_system():\n"
        "    def on_honeypot_event(event):\n"
        "        socketio.emit('honeypot_event', event.to_dict())\n"
        "    honeypots._callback = on_honeypot_event\n"
        "    monitor.start()"
    )
    print("Added honeypot callback")

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("Done!")