"""
Export utilities — CSV and PDF report generation.
"""

from __future__ import annotations

import csv
import io
import time
from pathlib import Path
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    logger.warning("reportlab not installed; PDF export disabled.")


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def export_csv(
    data: list[dict[str, Any]],
    path: str,
    columns: list[str] | None = None,
) -> bool:
    """
    Write *data* (list of dicts) to a CSV file at *path*.

    If *columns* is given, only those keys are included in that order.
    Returns True on success.
    """
    if not data:
        logger.warning("export_csv: no data to export.")
        return False
    try:
        cols = columns or list(data[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)
        logger.info("CSV exported: %s (%d rows)", path, len(data))
        return True
    except Exception as exc:
        logger.error("CSV export failed: %s", exc)
        return False


def export_blocklist_txt(ips: list[str], path: str) -> bool:
    """Write a plain-text blocklist (one IP per line) to *path*."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(ips) + "\n")
        logger.info("Blocklist TXT exported: %s", path)
        return True
    except Exception as exc:
        logger.error("Blocklist TXT export failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# PDF export
# ---------------------------------------------------------------------------

def export_pdf_report(
    path: str,
    title: str = "NetGuard IDS Report",
    summary: dict[str, Any] | None = None,
    tables: list[tuple[str, list[list[str]]]] | None = None,
) -> bool:
    """
    Generate a PDF report at *path*.

    *summary* — dict of key/value pairs for the summary section.
    *tables*  — list of (table_title, rows) where rows[0] is the header row.

    Returns True on success.
    """
    if not HAS_REPORTLAB:
        logger.warning("reportlab not installed; cannot export PDF.")
        return False

    try:
        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph(title, styles["Title"]))
        story.append(Paragraph(
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"],
        ))
        story.append(Spacer(1, 0.5 * cm))

        # Summary section
        if summary:
            story.append(Paragraph("Summary", styles["Heading2"]))
            for k, v in summary.items():
                story.append(Paragraph(f"<b>{k}:</b> {v}", styles["Normal"]))
            story.append(Spacer(1, 0.3 * cm))

        # Tables
        for table_title, rows in (tables or []):
            if not rows:
                continue
            story.append(Paragraph(table_title, styles["Heading2"]))
            t = Table(rows, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7c3aed")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f3ff")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.5 * cm))

        doc.build(story)
        logger.info("PDF report exported: %s", path)
        return True
    except Exception as exc:
        logger.error("PDF export failed: %s", exc)
        return False


def alerts_to_pdf(alerts: list[dict[str, Any]], path: str) -> bool:
    """Export the alerts list to a formatted PDF report."""
    summary = {
        "Total alerts": len(alerts),
        "Unresolved": sum(1 for a in alerts if not a.get("resolved")),
        "Unique IPs": len({a.get("ip") for a in alerts}),
    }
    header = ["#", "Timestamp", "IP", "Type", "Details", "Resolved"]
    rows = [header] + [
        [
            str(i + 1),
            time.strftime("%Y-%m-%d %H:%M", time.localtime(a.get("timestamp", 0))),
            str(a.get("ip", "")),
            str(a.get("type", "")),
            str(a.get("details", ""))[:60],
            "Yes" if a.get("resolved") else "No",
        ]
        for i, a in enumerate(alerts)
    ]
    return export_pdf_report(
        path,
        title="NetGuard IDS — Alert Report",
        summary=summary,
        tables=[("Alert Log", rows)],
    )


def blocklist_to_pdf(blocked: list[dict[str, Any]], path: str) -> bool:
    """Export the blocklist to a formatted PDF report."""
    summary = {
        "Total blocked IPs": len(blocked),
        "Auto-blocked": sum(1 for b in blocked if b.get("auto_blocked")),
    }
    header = ["IP", "Reason", "Blocked At", "Auto"]
    rows = [header] + [
        [
            str(b.get("ip", "")),
            str(b.get("reason", ""))[:60],
            time.strftime("%Y-%m-%d %H:%M", time.localtime(b.get("blocked_at", 0))),
            "Yes" if b.get("auto_blocked") else "No",
        ]
        for b in blocked
    ]
    return export_pdf_report(
        path,
        title="NetGuard IDS — Blocklist Report",
        summary=summary,
        tables=[("Blocked IPs", rows)],
    )
