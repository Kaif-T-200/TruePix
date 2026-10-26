"""PDF forensic report renderer for TruePix (Phase 2).

Renders the same evidence as ``json_report.build_report`` into a single
PDF via reportlab (pure Python, no native deps). The disclaimer is always
included verbatim; verdict colors match the UI palette but meaning is
never conveyed by color alone (icon + text labels are present).
"""

from __future__ import annotations

import base64
import binascii
import html
import io

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Palette mirrors src/ui/styles.py.
_COLOR = {
    "LOW": "#2ea043",
    "MODERATE": "#3a7ca5",
    "ELEVATED": "#e0a32e",
    "HIGH": "#e5534b",
    "INSUFFICIENT_EVIDENCE": "#5b6b7f",
    "INCONCLUSIVE": "#8b98a9",
}
_ICON = {
    "LOW": "[ OK ]",
    "MODERATE": "[ ~ ]",
    "ELEVATED": "[ ! ]",
    "HIGH": "[ X ]",
    "INSUFFICIENT_EVIDENCE": "[ . ]",
    "INCONCLUSIVE": "[ ? ]",
}

_Muted = None  # populated in _styles() after stylesheet creation


def _styles():
    ss = getSampleStyleSheet()
    base = ss["Normal"].fontName = "Helvetica"
    return {
        "title": ParagraphStyle(
            "tpTitle", parent=ss["Title"], fontName="Helvetica-Bold",
            fontSize=20, textColor=colors.HexColor("#0a0d12"),
            spaceAfter=2 * mm,
        ),
        "subtitle": ParagraphStyle(
            "tpSub", parent=ss["Normal"], fontName="Helvetica",
            fontSize=9.5, textColor=colors.HexColor("#5b6b7f"),
            spaceAfter=6 * mm,
        ),
        "h2": ParagraphStyle(
            "tpH2", parent=ss["Heading2"], fontName="Helvetica-Bold",
            fontSize=13, textColor=colors.HexColor("#121722"),
            spaceBefore=6 * mm, spaceAfter=2 * mm,
        ),
        "body": ParagraphStyle(
            "tpBody", parent=ss["Normal"], fontName="Helvetica",
            fontSize=9.5, leading=13, textColor=colors.HexColor("#222c3a"),
        ),
        "muted": ParagraphStyle(
            "tpMuted", parent=ss["Normal"], fontName="Helvetica-Oblique",
            fontSize=8.5, leading=11.5, textColor=colors.HexColor("#5b6b7f"),
        ),
        "finding_title": ParagraphStyle(
            "tpFTitle", parent=ss["Normal"], fontName="Helvetica-Bold",
            fontSize=10, leading=13, textColor=colors.HexColor("#121722"),
            spaceAfter=1 * mm,
        ),
        "verdict": ParagraphStyle(
            "tpVerdict", parent=ss["Normal"], fontName="Helvetica-Bold",
            fontSize=16, alignment=TA_CENTER, textColor=colors.white,
        ),
        "verdict_sub": ParagraphStyle(
            "tpVerdictSub", parent=ss["Normal"], fontName="Helvetica",
            fontSize=9, alignment=TA_CENTER, textColor=colors.white,
        ),
        "_base": base,
    }


def _esc(v) -> str:
    return html.escape(str(v if v is not None else "—"))


def _kv_table(rows: list[tuple[str, str]], styles) -> Table:
    data = [[Paragraph(f"<b>{_esc(k)}</b>", styles["body"]), _esc(v)]
            for k, v in rows]
    t = Table(data, colWidths=[52 * mm, 110 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, colors.HexColor("#d8dee6")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("FONTNAME", (1, 0), (1, -1), "Courier"),
        ("FONTSIZE", (1, 0), (1, -1), 8.5),
    ]))
    return t


def _verdict_banner(rep: dict, styles) -> list:
    assessment = ((rep.get("assessment") or {}).get("verdict")) or \
        "INSUFFICIENT_EVIDENCE"
    origin = ((rep.get("assessment") or {}).get("origin_verdict")) or ""
    color = _COLOR.get(assessment, "#5b6b7f")
    icon = _ICON.get(assessment, "[ . ]")
    label = str(origin).replace("_", " ") or assessment.replace("_", " ")

    inner = [
        Paragraph(f"{icon} {html.escape(label)}", styles["verdict"]),
        Paragraph(
            f"Assessment band: {html.escape(assessment)} · "
            f"Strength: {html.escape(str((rep['assessment'] or {}).get('verdict_strength') or 'UNKNOWN'))}",
            styles["verdict_sub"],
        ),
    ]
    t = Table([[inner]], colWidths=[162 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(color)),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor(color)),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _finding_block(f: dict, styles) -> list:
    out = [
        Paragraph(
            f"{_esc(f.get('id'))} · {_esc(f.get('category'))} — "
            f"{_esc(f.get('title'))} ({_esc(f.get('severity'))}/"
            f"{_esc(f.get('confidence'))})",
            styles["finding_title"],
        ),
        Paragraph(f"Evidence: {_esc(f.get('evidence'))}", styles["body"]),
        Paragraph(f"Interpretation: {_esc(f.get('interpretation'))}", styles["muted"]),
        Spacer(1, 3 * mm),
    ]
    return out


def build_pdf(rep: dict, ela_preview_b64: str | None = None) -> bytes:
    """Render a report dict (from json_report.build_report) to PDF bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=24 * mm, rightMargin=24 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"TruePix Forensic Report — {rep.get('filename', '')}",
        author="TruePix",
    )
    st = _styles()
    story = []

    # Header.
    story.append(Paragraph("TRUEPIX — Forensic Analysis Report", st["title"]))
    story.append(Paragraph(
        f"Generated {html.escape(rep.get('generated_utc', ''))} · "
        f"schema {html.escape(rep.get('schema_version', ''))} · "
        f"TruePix {html.escape(rep.get('version', ''))} · local CPU analysis",
        st["subtitle"],
    ))

    story.append(_verdict_banner(rep, st))
    story.append(Spacer(1, 4 * mm))

    a = rep.get("assessment") or {}
    score = a.get("evidence_score")
    score_txt = f"{int(round(score * 100))}% of maximum family weight" \
        if isinstance(score, (int, float)) else "not available"
    story.extend([
        Paragraph("Assessment", st["h2"]),
        _kv_table([
            ("Evidence score", f"{score_txt} (not a probability)"),
            ("AI assessment", a.get("ai_assessment")),
            ("Confidence", a.get("confidence")),
            ("Definitive", "YES" if a.get("definitive") else "NO"),
            ("Proof basis", a.get("proof_basis")),
        ], st),
        Spacer(1, 3 * mm),
        Paragraph(html.escape(a.get("summary_text") or ""), st["body"])
        if a.get("summary_text") else Spacer(1, 0),
    ])

    # Image facts.
    img = rep.get("image") or {}
    story.append(Paragraph("Image", st["h2"]))
    story.append(_kv_table([
        ("Filename", rep.get("filename")),
        ("SHA-256", rep.get("sha256")),
        ("Format / size", f"{img.get('format')} · {img.get('width')}×{img.get('height')}"
                          f" · {img.get('file_size_bytes'):,} bytes"
         if isinstance(img.get("file_size_bytes"), int)
         else f"{img.get('format')} · {img.get('width')}×{img.get('height')}"),
        ("Color mode / MIME", f"{img.get('color_mode')} · {img.get('mime_type')}"),
        ("Aspect ratio", img.get("aspect_ratio")),
    ], st))

    # Optional ELA preview.
    if ela_preview_b64:
        try:
            raw = base64.b64decode(ela_preview_b64)
            img_obj = Image(io.BytesIO(raw), width=80 * mm, height=80 * mm)
            story.append(Spacer(1, 3 * mm))
            story.append(img_obj)
            story.append(Paragraph("ELA preview (recompression residual)",
                                   st["muted"]))
        except (binascii.Error, ValueError, OSError):
            pass  # a corrupt preview must not fail the whole report

    # Per-module sections.
    modules = rep.get("modules") or {}
    findings = rep.get("findings") or {}
    titles = {
        "metadata": "Metadata Forensics",
        "c2pa": "Content Credentials (C2PA)",
        "forensics": "Image Forensics",
        "artifacts": "Visual Artifacts",
        "ai_detector": "AI Detector",
        "watermark": "Provenance Watermarks",
        "jpeg_history": "JPEG Compression History",
        "cfa": "Demosaicing (CFA) Signature",
    }
    for key, title in titles.items():
        m = modules.get(key)
        fs = findings.get(key) or []
        if m is None and not fs:
            continue
        story.append(Paragraph(title, st["h2"]))
        status = (m or {}).get("status", "unavailable")
        lines = [Paragraph(f"Status: <b>{_esc(status)}</b>", st["body"])]
        for k, v in sorted((m or {}).items()):
            if k == "status":
                continue
            lines.append(Paragraph(
                f"<b>{_esc(k)}</b>: {_esc(v)}", st["body"]))
        story.extend(lines)
        for f in fs:
            story.extend(_finding_block(f, st))
        if not fs:
            story.append(Paragraph("No findings recorded.", st["muted"]))

    # Evidence weighting table.
    ev = rep.get("evidence") or []
    if ev:
        story.append(Paragraph("Evidence Weighting", st["h2"]))
        rows = [["Source", "Finding", "Impact", "Weight"]]
        for e in ev[:60]:
            rows.append([_esc(e.get("source")), _esc(e.get("finding_id")),
                         _esc(e.get("impact")), f"{e.get('weight', 0):.2f}"])
        t = Table(rows, colWidths=[40 * mm, 30 * mm, 32 * mm, 20 * mm])
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d8dee6")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f2f5f8")]),
        ]))
        story.append(t)

    # Limitations + disclaimer. Always last, never omitted.
    story.append(PageBreak())
    story.append(Paragraph("Limitations", st["h2"]))
    for lim in rep.get("limitations") or []:
        story.append(Paragraph(f"• {html.escape(lim)}", st["body"]))
    errs = rep.get("module_errors") or []
    if errs:
        story.append(Paragraph("Module errors (results excluded)", st["h2"]))
        for e in errs:
            story.append(Paragraph(f"• {html.escape(e)}", st["muted"]))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Disclaimer", st["h2"]))
    story.append(Paragraph(html.escape(rep.get("disclaimer", "")), st["body"]))

    doc.build(story)
    return buf.getvalue()
