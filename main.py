"""
main.py
-------
CyberShield — Cybersecurity Threat Detection System
Entry point with CLI interface.

Usage:
    python main.py                    # Start full system (monitor + dashboard)
    python main.py --no-dashboard     # Monitor + console only
    python main.py --scan FILE        # Scan a single file for malware
    python main.py --demo             # Inject demo attacks for testing
"""

import argparse
import sys
import os
import time
import logging
import threading

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich import box

console = Console()

BANNER = """
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗███████║██║█████╗  ██║     ██║  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
"""


def print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print(
        Panel(
            "[bold cyan]Network Threat Detection & Intrusion Prevention System[/bold cyan]\n"
            "[dim]v1.0.0 | Python + Scapy + ML | Real-time Analysis[/dim]",
            border_style="red",
        )
    )


def run_full_system(args):
    """Start network monitor + dashboard server."""
    print_banner()
    console.print("[bold green]▶ Starting CyberShield...[/bold green]\n")

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from dashboard.dashboard_server import start_system, app, socketio

    start_system()

    host = args.host if hasattr(args, "host") else "0.0.0.0"
    port = args.port if hasattr(args, "port") else 5000

    console.print(f"\n[bold green]✓ Dashboard:[/bold green] http://localhost:{port}")
    console.print(f"[bold green]✓ API:[/bold green]       http://localhost:{port}/api/status")
    console.print("\n[dim]Press Ctrl+C to stop[/dim]\n")

    try:
        socketio.run(
            app, host=host, port=port,
            debug=False, allow_unsafe_werkzeug=True,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow]")


def run_monitor_only(args):
    """Monitor + console alerts, no web dashboard."""
    print_banner()
    console.print("[bold green]▶ Starting in monitor-only mode...[/bold green]\n")

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from core.network_monitor import NetworkMonitor
    from core.intrusion_detector import IntrusionDetector
    from alerts.alert_system import AlertSystem, AlertConfig

    alert_sys = AlertSystem(AlertConfig(console_enabled=True))
    detector = IntrusionDetector(
        alert_callback=lambda e: alert_sys.dispatch(e)
    )
    monitor = NetworkMonitor()
    monitor.add_packet_callback(detector.on_packet)
    monitor.start()

    console.print(f"[bold green]✓ Monitoring interface:[/bold green] {monitor.interface}")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    try:
        while True:
            time.sleep(5)
            s = monitor.stats
            console.print(
                f"[dim]Packets: {s['total_packets']:,} | "
                f"Flows: {s['active_flows']} | "
                f"PPS: {s['packets_per_second']} | "
                f"Events: {sum(detector.get_event_counts().values())}[/dim]"
            )
    except KeyboardInterrupt:
        monitor.stop()
        console.print("\n[yellow]Stopped.[/yellow]")


def run_file_scan(filepath: str):
    """Scan a single file for malware."""
    print_banner()
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from core.malware_analyzer import MalwareAnalyzer

    analyzer = MalwareAnalyzer()
    console.print(f"[bold cyan]Scanning:[/bold cyan] {filepath}\n")

    result = analyzer.analyze_file(filepath)
    r = result.to_dict()

    color = "green" if not r["is_malicious"] else (
        "red" if r["severity"] in ("HIGH", "CRITICAL") else "yellow"
    )
    verdict = "CLEAN ✓" if not r["is_malicious"] else f"THREAT DETECTED ✗ ({r['threat_name']})"

    table = Table(title=f"Scan Result: {r['target']}", box=box.ROUNDED, border_style=color)
    table.add_column("Field", style="dim", width=20)
    table.add_column("Value")

    table.add_row("Verdict", f"[{color}]{verdict}[/{color}]")
    table.add_row("Severity", r["severity"])
    table.add_row("Confidence", f"{r['confidence']*100:.1f}%")
    table.add_row("MD5", r["details"].get("hashes", {}).get("md5", "N/A"))
    table.add_row("SHA256", r["details"].get("hashes", {}).get("sha256", "N/A"))
    table.add_row("Entropy", str(r["details"].get("entropy", "N/A")))

    console.print(table)

    if r["indicators"]:
        console.print("\n[bold red]Indicators:[/bold red]")
        for ind in r["indicators"]:
            console.print(f"  [red]•[/red] {ind}")

    analyzer.stop()


def run_demo(args):
    """Start system and auto-inject demo attacks."""
    import requests as req_lib
    import time

    # Start server in background thread
    t = threading.Thread(target=run_full_system, args=(args,), daemon=True)
    t.start()
    time.sleep(3)  # Wait for server

    attacks = [
        {"type": "port_scan",  "severity": "high",     "src_ip": "10.1.2.3"},
        {"type": "syn_flood",  "severity": "critical",  "src_ip": "172.16.5.99"},
        {"type": "brute_force","severity": "high",      "src_ip": "185.220.101.5"},
        {"type": "dns_tunnel", "severity": "high",      "src_ip": "192.168.1.201"},
        {"type": "malware",    "severity": "critical",  "src_ip": "45.142.212.100"},
        {"type": "anomaly",    "severity": "medium",    "src_ip": "10.0.0.77"},
    ]

    console.print("\n[bold yellow]Demo mode: injecting simulated attacks...[/bold yellow]\n")
    for attack in attacks:
        try:
            resp = req_lib.post(
                "http://localhost:5000/api/simulate-attack",
                json=attack, timeout=3
            )
            console.print(f"[green]✓[/green] Injected: {attack['type']} from {attack['src_ip']}")
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to inject {attack['type']}: {e}")
        time.sleep(1.5)

    console.print("\n[bold green]Demo attacks sent! Check the dashboard.[/bold green]")
    t.join()


def main():
    parser = argparse.ArgumentParser(
        description="CyberShield — Network Threat Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                        Start full system with dashboard
  python main.py --no-dashboard         Monitor + console alerts only
  python main.py --scan /path/to/file   Scan a file for malware
  python main.py --demo                 Start with demo attack simulation
  python main.py --port 8080            Use custom port
        """,
    )
    parser.add_argument("--no-dashboard", action="store_true",
                        help="Run without web dashboard")
    parser.add_argument("--scan", metavar="FILE",
                        help="Scan a file for malware and exit")
    parser.add_argument("--demo", action="store_true",
                        help="Auto-inject demo attacks for testing")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Dashboard host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000,
                        help="Dashboard port (default: 5000)")
    parser.add_argument("--interface", default=None,
                        help="Network interface to capture on")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    if args.scan:
        run_file_scan(args.scan)
    elif args.demo:
        run_demo(args)
    elif args.no_dashboard:
        run_monitor_only(args)
    else:
        run_full_system(args)


if __name__ == "__main__":
    main()
