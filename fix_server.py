path = "dashboard/dashboard_server.py"
with open(path, encoding="utf-8") as f:
    content = f.read()

# Remove the misplaced honeypot callback that got added before instances
content = content.replace(
    "def on_honeypot_event(event):\n    socketio.emit('honeypot_event', event.to_dict())\n\nhoneypots._callback = on_honeypot_event\n\n",
    ""
)

# Add it correctly inside start_system function
if "on_honeypot_event" not in content:
    content = content.replace(
        "def start_system():\n    monitor.start()",
        "def start_system():\n    def on_honeypot_event(event):\n        socketio.emit('honeypot_event', event.to_dict())\n    honeypots._callback = on_honeypot_event\n    monitor.start()"
    )

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("Fixed!")