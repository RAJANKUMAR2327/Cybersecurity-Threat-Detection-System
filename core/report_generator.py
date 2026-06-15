import csv
import io
import logging
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def generate_csv(events: List[dict], alerts: List[dict] = None) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "DateTime", "Severity", "Category",
        "Source IP", "Source Port", "Destination IP", "Destination Port",
        "Protocol", "Confidence %", "MITRE Tactic", "MITRE Technique",
        "Description"
    ])
    for e in events:
        writer.writerow([
            e.get("id", ""),
            e.get("datetime", ""),
            e.get("severity", ""),
            e.get("category", ""),
            e.get("src_ip", ""),
            e.get("src_port", ""),
            e.get("dst_ip", ""),
            e.get("dst_port", ""),
            e.get("protocol", ""),
            f"{round(e.get('confidence', 0) * 100, 1)}%",
            e.get("mitre_tactic", ""),
            e.get("mitre_technique", ""),
            e.get("description", ""),
        ])
    return output.getvalue().encode("utf-8")


def generate_pdf(
    events: List[dict],
    alerts: List[dict] = None,
    stats: Dict[str, Any] = None,
    malware_results: List[dict] = None,
) -> bytes:
    return _text_report(events, stats)


def _text_report(events, stats) -> bytes:
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append("=" * 60)
    lines.append("  CYBERSHIELD SECURITY INCIDENT REPORT")
    lines.append(f"  Generated: {now}")
    lines.append("=" * 60)
    sev = {}
    for e in events:
        s = e.get("severity", "LOW")
        sev[s] = sev.get(s, 0) + 1
    lines.append(f"\nTotal Events : {len(events)}")
    lines.append(f"CRITICAL     : {sev.get('CRITICAL', 0)}")
    lines.append(f"HIGH         : {sev.get('HIGH', 0)}")
    lines.append(f"MEDIUM       : {sev.get('MEDIUM', 0)}")
    lines.append(f"LOW          : {sev.get('LOW', 0)}")
    lines.append("\nTHREAT EVENTS\n" + "-" * 40)
    for e in events[:50]:
        lines.append(
            f"[{e.get('severity', '?'):8}] "
            f"{e.get('datetime', '')[-8:]} "
            f"{e.get('category', '?'):25} "
            f"{e.get('src_ip', '?')} -> {e.get('dst_ip', '?')}"
        )
    lines.append("\n" + "=" * 60)
    lines.append("END OF REPORT — CyberShield")
    return "\n".join(lines).encode("utf-8")