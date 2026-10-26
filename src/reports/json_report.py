"""JSON forensic report builder for TruePix (Phase 2).

Produces a self-contained, JSON-serializable dict from an
``AnalysisContext``. The report contains only discovered evidence — no
fabricated probabilities or provenance — and carries the same disclaimer
text the UI shows.

Binary payloads (ELA previews, artifact overlays) are stripped: they are
presentation artifacts, not evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone

# Bump when the report shape changes in a way consumers must notice.
SCHEMA_VERSION = "1.1.0"

# Keys that hold binary previews or bulky per-metric blocks that the UI
# renders itself; they are not part of the portable evidence record.
_DROP_KEYS = {
    "findings", "checks", "ela", "noise", "compression", "edges", "frequency",
    "dct", "color_banding", "texture_uniformity", "saturation",
    "noise_correlation", "channel_correlation", "transformation_history",
    "screen_capture", "content_style", "provenance", "hints",
    "preview_b64", "artifact_overlay_b64", "technical",
    # Phase-3 modules carry their metrics nested; keep summary + status only.
    "jpeg_history", "cfa_analysis",
}


def _safe_summary(d: dict | None) -> dict | None:
    if d is None:
        return None
    return {k: v for k, v in d.items() if k not in _DROP_KEYS}


def build_report(ctx) -> dict:
    """Build the JSON-serializable report dict from an AnalysisContext."""
    info = ctx.image_info
    risk = ctx.risk or {}
    from src.ui.styles import DISCLAIMER, VERSION

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "application": "TruePix",
        "version": VERSION,
        "filename": info["filename"],
        "sha256": info["sha256"],
        "image": {
            "format": info["image_format"],
            "width": info["width"],
            "height": info["height"],
            "color_mode": info["color_mode"],
            "mime_type": info["mime_type"],
            "aspect_ratio": info["aspect_ratio"],
            "file_size_bytes": info["file_size_bytes"],
        },
        "assessment": {
            "verdict": risk.get("assessment"),
            "origin_verdict": risk.get("verdict"),
            "verdict_strength": risk.get("verdict_strength"),
            "definitive": risk.get("definitive", False),
            "proof_basis": risk.get("proof_basis"),
            "ai_assessment": risk.get("ai_assessment"),
            "evidence_score": risk.get("evidence_score"),
            "confidence": risk.get("confidence"),
            "summary_text": risk.get("summary"),
            "not_a_probability": True,
            "authenticity_established": risk.get("authenticity_established", False),
            "origin_unknown": risk.get("origin_unknown", True),
            "context_flags": risk.get("context_flags", []),
            "ensemble_consensus": risk.get("ensemble_consensus", {}),
        },
        "modules": {
            "metadata": _safe_summary(ctx.metadata),
            "c2pa": _safe_summary(ctx.c2pa),
            "forensics": _safe_summary(ctx.forensics),
            "artifacts": _safe_summary(ctx.artifacts),
            "ai_detector": _safe_summary(ctx.ai_detector),
            "watermark": _safe_summary(ctx.synthid),
            "jpeg_history": _safe_summary(ctx.jpeg_ghost),
            "cfa": _safe_summary(ctx.cfa),
        },
        # Findings are kept per-module at full fidelity here (unlike the UI
        # summary) so the exported report is auditable on its own.
        "findings": {
            name: (ctx_result or {}).get("findings", [])
            for name, ctx_result in (
                ("metadata", ctx.metadata),
                ("c2pa", ctx.c2pa),
                ("forensics", ctx.forensics),
                ("artifacts", ctx.artifacts),
                ("ai_detector", ctx.ai_detector),
                ("watermark", ctx.synthid),
                ("jpeg_history", ctx.jpeg_ghost),
                ("cfa", ctx.cfa),
            )
        },
        "module_errors": list(ctx.errors),
        "evidence": risk.get("evidence", []),
        "limitations": risk.get("limitations", []),
        "disclaimer": DISCLAIMER,
    }


def report_filename(sha256: str) -> str:
    """Deterministic download filename for a report."""
    return f"truepix_report_{sha256[:12]}.json"
