"""
report_generator.py
-------------------
Generates PDF and CSV incident reports from threat data.
PDF uses reportlab. CSV uses built-in csv module.
"""

import csv
import io
import time
import logging
import os
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def generate_csv(events: List[dict], alerts: List[dict] = None) -> bytes:
    """Generate a CSV report of threat events."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
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
    """Generate a professional PDF incident report."""
    try:
        from reportlab.lib.pagesizes import A4, letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch, cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
        return _generate_pdf_reportlab(events, alerts, stats, malware_results)
    except ImportError:
        logger.warning("reportlab not installed — generating text-based PDF substitute")
        return _generate_text_report(events, alerts, stats, malware_results)


def _generate_pdf_reportlab(events, alerts, stats, malware_results) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    # Colors
    DARK_BG   = colors.HexColor("#0a1520")
    ACCENT    = colors.HexColor("#00d4ff")
    RED       = colors.HexColor("#ff2244")
    ORANGE    = colors.HexColor("#ff6600")
    YELLOW    = colors.HexColor("#ffcc00")
    LIGHT_BG  = colors.HexColor("#f0f4f8")
    MID_GRAY  = colors.HexColor("#4a6080")
    DARK_GRAY = colors.HexColor("#1a2a3a")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Title"],
                                  textColor=DARK_GRAY, fontSize=24, spaceAfter=6)
    h1_style = ParagraphStyle("H1", parent=styles["Heading1"],
                               textColor=DARK_GRAY, fontSize=14, spaceAfter=4, spaceBefore=16)
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"],
                               textColor=MID_GRAY, fontSize=11, spaceAfter=4, spaceBefore=10)
    body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9, leading=14)
    meta_style = ParagraphStyle("Meta", parent=styles["Normal"],
                                 fontSize=8, textColor=MID_GRAY)

    story = []
    now = datetime.now()

    # ── Cover ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("🛡️ CyberShield", title_style))
    story.append(Paragraph("Security Incident Report", ParagraphStyle(
        "Sub", parent=styles["Normal"], fontSize=16, textColor=MID_GRAY, spaceAfter=4
    )))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT, spaceAfter=12))
    story.append(Paragraph(f"Generated: {now.strftime('%B %d, %Y at %H:%M:%S')}", meta_style))
    story.append(Paragraph(f"Report Period: Last session", meta_style))
    story.append(Spacer(1, 0.3*inch))

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h1_style))

    sev_counts = {}
    for e in events:
        s = e.get("severity", "LOW")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    summary_data = [
        ["Metric", "Value"],
        ["Total Threat Events", str(len(events))],
        ["Critical Events", str(sev_counts.get("CRITICAL", 0))],
        ["High Severity Events", str(sev_counts.get("HIGH", 0))],
        ["Medium Severity Events", str(sev_counts.get("MEDIUM", 0))],
        ["Low Severity Events", str(sev_counts.get("LOW", 0))],
        ["Total Alerts Dispatched", str(len(alerts or []))],
        ["Malware Scans", str(len(malware_results or []))],
    ]
    if stats:
        summary_data += [
            ["Total Packets Captured", f"{stats.get('total_packets', 0):,}"],
            ["Total Bytes Analyzed", f"{stats.get('total_bytes', 0):,}"],
            ["Active Flows", str(stats.get('active_flows', 0))],
        ]

    summary_table = Table(summary_data, colWidths=[4*inch, 2.5*inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_GRAY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 1), (-1, -1), LIGHT_BG),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ccddee")),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))

    # ── Threat Events Table ───────────────────────────────────────────────────
    if events:
        story.append(Paragraph("Threat Events", h1_style))
        sev_colors = {
            "CRITICAL": RED, "HIGH": ORANGE,
            "MEDIUM": YELLOW, "LOW": ACCENT,
        }

        headers = ["Time", "Severity", "Category", "Source", "Destination", "Conf%", "MITRE"]
        table_data = [headers]
        for e in events[:100]:  # Cap at 100 rows
            table_data.append([
                e.get("datetime", "")[-8:] or "--:--:--",
                e.get("severity", ""),
                e.get("category", "")[:20],
                f"{e.get('src_ip', '')}:{e.get('src_port', '')}",
                f"{e.get('dst_ip', '')}:{e.get('dst_port', '')}",
                f"{round(e.get('confidence', 0)*100)}%",
                e.get("mitre_technique", "") or "--",
            ])

        col_widths = [0.8*inch, 0.7*inch, 1.5*inch, 1.4*inch, 1.4*inch, 0.5*inch, 0.7*inch]
        events_table = Table(table_data, colWidths=col_widths)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), DARK_GRAY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#ccddee")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        for i, e in enumerate(events[:100], 1):
            sev = e.get("severity", "LOW")
            bg = sev_colors.get(sev, ACCENT)
            style.append(("TEXTCOLOR", (1, i), (1, i), bg))
            style.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
            style.append(("BACKGROUND", (0, i), (-1, i),
                           colors.white if i % 2 == 0 else LIGHT_BG))
        events_table.setStyle(TableStyle(style))
        story.append(events_table)

    # ── Malware Results ───────────────────────────────────────────────────────
    if malware_results:
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("Malware Scan Results", h1_style))
        mal_data = [["Target", "Verdict", "Severity", "Confidence", "Threat Name"]]
        for r in malware_results:
            mal_data.append([
                r.get("target", "")[:30],
                "THREAT" if r.get("is_malicious") else "CLEAN",
                r.get("severity", ""),
                f"{round(r.get('confidence', 0)*100)}%",
                r.get("threat_name", "")[:25],
            ])
        mal_table = Table(mal_data, colWidths=[2*inch, 0.8*inch, 0.8*inch, 0.8*inch, 2*inch])
        mal_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK_GRAY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#ccddee")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(mal_table)

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5*inch))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY))
    story.append(Paragraph(
        f"CyberShield Threat Detection System — Confidential — {now.strftime('%Y-%m-%d')}",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7,
                        textColor=MID_GRAY, alignment=TA_CENTER)
    ))

    doc.build(story)
    return buffer.getvalue()


def _generate_text_report(events, alerts, stats, malware_results) -> bytes:
    """Fallback plain-text report when reportlab is not installed."""
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append("=" * 70)
    lines.append("  CYBERSHIELD SECURITY INCIDENT REPORT")
    lines.append(f"  Generated: {now}")
    lines.append("=" * 70)
    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    sev_counts = {}
    for e in events:
        s = e.get("severity", "LOW")
        sev_counts[s] = sev_counts.get(s, 0) + 1
    lines.append(f"Total Events:    {len(events)}")
    lines.append(f"CRITICAL:        {sev_counts.get('CRITICAL', 0)}")
    lines.append(f"HIGH:            {sev_counts.get('HIGH', 0)}")
    lines.append(f"MEDIUM:          {sev_counts.get('MEDIUM', 0)}")
    lines.append(f"LOW:             {sev_counts.get('LOW', 0)}")
    lines.append("")
    lines.append("THREAT EVENTS")
    lines.append("-" * 40)
    for e in events[:50]:
        lines.append(
            f"[{e.get('severity','?'):8}] {e.get('datetime','')[-8:]} "
            f"{e.get('category','?'):25} "
            f"{e.get('src_ip','?')} -> {e.get('dst_ip','?')} "
            f"({e.get('protocol','?')})"
        )
    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT — CyberShield")
    return "\n".join(lines).encode("utf-8")