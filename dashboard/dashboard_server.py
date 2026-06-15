"""
dashboard_server.py - v2.0
All 7 new features integrated.
"""

import os, sys, time, logging, threading
from datetime import datetime

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(THIS_DIR)
sys.path.insert(0, ROOT_DIR)
from core.report_generator    import generate_csv, generate_pdf
from core.ai_assistant     import AIAssistant
from core.geoip_map        import GeoIPMap
from core.vuln_scanner     import VulnerabilityScanner
from core.honeypot         import HoneypotManager
from core.timeline         import TimelineEngine
from core.darkweb_monitor     import DarkWebMonitor
from flask import Flask, jsonify, request, send_file, Response
from flask_socketio import SocketIO, emit

from core.network_monitor     import NetworkMonitor
from core.intrusion_detector  import IntrusionDetector
from core.malware_analyzer    import MalwareAnalyzer
from core.threat_intelligence import ThreatIntelligence
from core.network_scanner     import NetworkScanner
from core.ip_blocker          import IPBlocker
from core.packet_inspector    import PacketInspector
from core.report_generator    import generate_csv, generate_pdf
from alerts.alert_system      import AlertSystem, AlertConfig

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = "cybershield-2024"
app.config["AUTO_BLOCK_ENABLED"] = False
app.config["AUTO_BLOCK_MIN_SEV"] = "HIGH"

socketio = SocketIO(app, cors_allowed_origins="*",
                    async_mode="threading",
                    logger=False, engineio_logger=False)

# ── Components ───────────────────────────────────────────────
monitor      = NetworkMonitor()
detector     = IntrusionDetector()
analyzer     = MalwareAnalyzer()
intel        = ThreatIntelligence()
scanner      = NetworkScanner()
blocker      = IPBlocker()
darkweb      = DarkWebMonitor()
ai           = AIAssistant()
geomap       = GeoIPMap()
vulns        = VulnerabilityScanner()
honeypots    = HoneypotManager()
timeline     = TimelineEngine()
inspector    = PacketInspector()
alert_system = AlertSystem(AlertConfig(
    console_enabled=True, log_enabled=True
))

# ── Callbacks ────────────────────────────────────────────────
def on_threat_detected(event):
    alert_system.dispatch(event)
    socketio.emit("threat_event", event.to_dict())
    geomap.track_event(event.to_dict())
    timeline.ingest(event.to_dict())
    ed = event.to_dict()
    if ed.get("severity") in ("HIGH", "CRITICAL"):
        src = ed.get("src_ip", "")
        if src:
            intel.lookup_async(
                src,
                callback=lambda r: socketio.emit("intel_result", r.to_dict())
            )
        if app.config.get("AUTO_BLOCK_ENABLED"):
            blocker.auto_block_on_threat(
                ed, app.config.get("AUTO_BLOCK_MIN_SEV", "HIGH")
            )

def on_alert_dispatched(a):
    socketio.emit("alert", a)

def on_packet(features, flow):
    detector.on_packet(features, flow)
    inspector.inspect_from_features(features)

detector.set_alert_callback(on_threat_detected)
alert_system.add_callback(on_alert_dispatched)
monitor.add_packet_callback(on_packet)

# ── Core routes ──────────────────────────────────────────────
@app.route("/")
def index():
    return send_file(os.path.join(THIS_DIR, "index.html"))

@app.route("/api/status")
def api_status():
    s = monitor.stats.copy()
    s["uptime_secs"]     = round(time.time() - s.get("start_time", time.time()), 1)
    s["protocols"]       = dict(s.get("protocols", {}))
    s["event_counts"]    = detector.get_event_counts()
    s["alert_stats"]     = alert_system.get_stats()
    s["ml_trained"]      = detector.ml_detector._trained
    s["interface"]       = monitor.interface
    s["timestamp"]       = datetime.now().isoformat()
    s["blocker_stats"]   = blocker.get_stats()
    s["inspector_stats"] = inspector.get_stats()
    return jsonify(s)

@app.route("/api/events")
def api_events():
    n   = int(request.args.get("n", 100))
    sev = request.args.get("severity")
    ev  = detector.get_recent_events(n)
    if sev:
        ev = [e for e in ev if e["severity"] == sev.upper()]
    return jsonify(ev)

@app.route("/api/alerts")
def api_alerts():
    return jsonify(alert_system.get_recent_alerts(
        int(request.args.get("n", 100))
    ))

@app.route("/api/flows")
def api_flows():
    return jsonify(monitor.get_active_flows())

@app.route("/api/packets")
def api_packets():
    return jsonify(monitor.get_recent_packets(
        int(request.args.get("n", 50))
    ))

@app.route("/api/malware")
def api_malware():
    return jsonify(analyzer.get_results(
        int(request.args.get("n", 50))
    ))

@app.route("/api/top-talkers")
def api_top_talkers():
    return jsonify(monitor.get_top_talkers(
        int(request.args.get("n", 10))
    ))

@app.route("/api/scan-file", methods=["POST"])
def api_scan_file():
    data = request.get_json() or {}
    fp   = data.get("filepath", "")
    if not fp:
        return jsonify({"error": "filepath required"}), 400
    return jsonify(analyzer.analyze_file(fp).to_dict())

# ── Threat Intelligence ──────────────────────────────────────
@app.route("/api/intel/lookup", methods=["POST"])
def api_intel_lookup():
    data = request.get_json() or {}
    ip   = data.get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    return jsonify(intel.lookup(ip).to_dict())

@app.route("/api/intel/results")
def api_intel_results():
    return jsonify(intel.get_results(
        int(request.args.get("n", 50))
    ))

@app.route("/api/intel/config", methods=["POST"])
def api_intel_config():
    data = request.get_json() or {}
    intel.set_keys(
        vt_key    = data.get("virustotal_key", ""),
        abuse_key = data.get("abuseipdb_key", ""),
    )
    return jsonify({"status": "ok"})

@app.route("/api/intel/cache")
def api_intel_cache():
    return jsonify(intel.get_cache_stats())

# ── Network Scanner ──────────────────────────────────────────
@app.route("/api/scan/network", methods=["POST"])
def api_scan_network():
    data      = request.get_json() or {}
    network   = data.get("network")
    port_scan = data.get("port_scan", True)

    def run():
        def on_device(d):
            socketio.emit("device_found", d)
        scanner.scan_network(
            network=network, port_scan=port_scan, callback=on_device
        )
        socketio.emit("scan_complete", {"devices": scanner.get_devices()})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({
        "status": "scanning",
        "network": network or scanner.get_local_network()
    })

@app.route("/api/scan/devices")
def api_scan_devices():
    return jsonify(scanner.get_devices())

@app.route("/api/scan/status")
def api_scan_status():
    return jsonify(scanner.get_status())

# ── IP Blocker ───────────────────────────────────────────────
@app.route("/api/block", methods=["POST"])
def api_block_ip():
    data = request.get_json() or {}
    ip   = data.get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    result = blocker.block_ip(
        ip         = ip,
        reason     = data.get("reason", "Manually blocked"),
        severity   = data.get("severity", "HIGH"),
        blocked_by = "manual",
    )
    socketio.emit("ip_blocked", result)
    return jsonify(result)

@app.route("/api/block/<ip>", methods=["DELETE"])
def api_unblock_ip(ip):
    result = blocker.unblock_ip(ip)
    socketio.emit("ip_unblocked", result)
    return jsonify(result)

@app.route("/api/block/list")
def api_block_list():
    return jsonify(blocker.get_blocked_ips())

@app.route("/api/block/stats")
def api_block_stats():
    return jsonify(blocker.get_stats())

@app.route("/api/block/auto", methods=["POST"])
def api_auto_block():
    data = request.get_json() or {}
    app.config["AUTO_BLOCK_ENABLED"] = data.get("enabled", True)
    app.config["AUTO_BLOCK_MIN_SEV"] = data.get("min_severity", "HIGH")
    return jsonify({
        "status": "ok",
        "enabled": app.config["AUTO_BLOCK_ENABLED"],
        "min_severity": app.config["AUTO_BLOCK_MIN_SEV"],
    })

# ── Packet Inspector ─────────────────────────────────────────
@app.route("/api/inspect/packets")
def api_inspect_packets():
    n        = int(request.args.get("n", 100))
    protocol = request.args.get("protocol")
    src_ip   = request.args.get("src_ip")
    dst_ip   = request.args.get("dst_ip")
    return jsonify(inspector.get_packets(n, protocol, src_ip, dst_ip))

@app.route("/api/inspect/packet/<int:pkt_id>")
def api_inspect_packet(pkt_id):
    pkt = inspector.get_packet_by_id(pkt_id)
    if not pkt:
        return jsonify({"error": "not found"}), 404
    return jsonify(pkt)

@app.route("/api/inspect/stats")
def api_inspect_stats():
    return jsonify(inspector.get_stats())

# ── Reports ──────────────────────────────────────────────────
@app.route("/api/report/csv")
def api_report_csv():
    events  = detector.get_recent_events(1000)
    alerts  = alert_system.get_recent_alerts(1000)
    content = generate_csv(events, alerts)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        content,
        mimetype="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename=cybershield_{ts}.csv"},
    )

@app.route("/api/report/pdf")
def api_report_pdf():
    events  = detector.get_recent_events(1000)
    alerts  = alert_system.get_recent_alerts(1000)
    stats   = monitor.stats.copy()
    malware = analyzer.get_results(100)
    content = generate_pdf(events, alerts, stats, malware)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext  = "pdf" if content[:4] == b"%PDF" else "txt"
    mime = "application/pdf" if ext == "pdf" else "text/plain"
    return Response(
        content,
        mimetype=mime,
        headers={"Content-Disposition":
                 f"attachment; filename=cybershield_{ts}.{ext}"},
    )

# ── Alert Config ─────────────────────────────────────────────
@app.route("/api/config/alert", methods=["POST"])
def api_config_alert():
    data = request.get_json() or {}
    cfg  = alert_system.config
    for k in ("console_enabled", "email_enabled", "webhook_enabled",
              "webhook_url", "smtp_host", "smtp_port", "smtp_user",
              "smtp_password", "email_from", "email_to",
              "email_min_severity", "webhook_min_severity"):
        if k in data:
            setattr(cfg, k, data[k])
    return jsonify({"status": "ok"})

# ── Simulate ─────────────────────────────────────────────────
@app.route("/api/simulate-attack", methods=["POST"])
def api_simulate_attack():
    import uuid
    from core.intrusion_detector import (
        ThreatEvent, ThreatCategory, ThreatSeverity
    )
    data = request.get_json() or {}
    cat_map = {
        "port_scan":   ThreatCategory.PORT_SCAN,
        "syn_flood":   ThreatCategory.SYN_FLOOD,
        "brute_force": ThreatCategory.BRUTE_FORCE,
        "dns_tunnel":  ThreatCategory.DNS_TUNNELING,
        "malware":     ThreatCategory.SUSPICIOUS_PAYLOAD,
        "anomaly":     ThreatCategory.ANOMALOUS_TRAFFIC,
    }
    sev_map = {
        "low":      ThreatSeverity.LOW,
        "medium":   ThreatSeverity.MEDIUM,
        "high":     ThreatSeverity.HIGH,
        "critical": ThreatSeverity.CRITICAL,
    }
    cat = cat_map.get(data.get("type", "port_scan"), ThreatCategory.PORT_SCAN)
    sev = sev_map.get(data.get("severity", "high"), ThreatSeverity.HIGH)
    ev  = ThreatEvent(
        id=str(uuid.uuid4())[:8],
        timestamp=time.time(),
        category=cat, severity=sev,
        src_ip=data.get("src_ip", "192.168.1.42"),
        dst_ip=data.get("dst_ip", "10.0.0.1"),
        src_port=data.get("src_port", 54321),
        dst_port=data.get("dst_port", 22),
        protocol=data.get("protocol", "TCP"),
        description=f"Simulated {cat.value} attack",
        confidence=data.get("confidence", 0.92),
        evidence={"simulated": True},
        mitre_tactic="Simulated",
        mitre_technique="T0000",
    )
    on_threat_detected(ev)
    return jsonify({"status": "injected", "event": ev.to_dict()})


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

# ── WebSocket ─────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    emit("stats_update", {
        "packets": monitor.stats["total_packets"],
        "bytes":   monitor.stats["total_bytes"],
        "flows":   monitor.stats["active_flows"],
        "pps":     monitor.stats["packets_per_second"],
    })

@socketio.on("request_events")
def on_request_events(data):
    n = data.get("n", 50) if data else 50
    emit("events_batch", detector.get_recent_events(n))

# ── Broadcaster ───────────────────────────────────────────────
def stats_broadcaster():
    while True:
        time.sleep(1)
        try:
            socketio.emit("stats_update", {
                "packets":      monitor.stats["total_packets"],
                "bytes":        monitor.stats["total_bytes"],
                "flows":        monitor.stats["active_flows"],
                "pps":          monitor.stats["packets_per_second"],
                "protocols":    dict(monitor.stats.get("protocols", {})),
                "event_counts": detector.get_event_counts(),
                "timestamp":    time.time(),
            })
        except Exception:
            pass

def start_system():
    def on_honeypot_event(event):
        socketio.emit('honeypot_event', event.to_dict())
    honeypots._callback = on_honeypot_event
    monitor.start()
    threading.Thread(target=stats_broadcaster, daemon=True).start()

if __name__ == "__main__":
    start_system()
    socketio.run(app, host="0.0.0.0", port=5000,
                 debug=False, allow_unsafe_werkzeug=True)