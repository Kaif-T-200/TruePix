"""Batch analysis runner for TruePix (Phase 2).

Runs ``analysis.run_all`` sequentially over multiple uploaded files.
CPU-only by design: NumPy/OpenCV work already saturates cores, and a
single-threaded loop keeps memory bounded on low-end machines.

The caller (Streamlit UI or CLI) supplies validated, sanitized paths;
this module never touches Streamlit state so it stays testable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from src.analysis import AnalysisContext, run_all
from src.image_info import analyze as _analyze_image_info

logger = logging.getLogger("truepix")


@dataclass
class BatchRow:
    """One row of the batch summary table."""

    filename: str
    sha256: str
    ok: bool
    error: str
    verdict: str | None
    assessment: str | None
    evidence_score: float | None
    confidence: str | None
    ctx: AnalysisContext | None  # full context; excluded from CSV export


def run_one(path: str, original_name: str) -> BatchRow:
    """Analyze one file and return its summary row."""
    result = _analyze_image_info_from_path(path, original_name)
    if not result["ok"]:
        return BatchRow(
            filename=result.get("filename", original_name),
            sha256="",
            ok=False,
            error=result["error"],
            verdict=None,
            assessment=None,
            evidence_score=None,
            confidence=None,
            ctx=None,
        )
    info = result["info"]
    ctx = run_all(path, info)
    risk = ctx.risk or {}
    return BatchRow(
        filename=info["filename"],
        sha256=info["sha256"],
        ok=True,
        error="",
        verdict=risk.get("verdict"),
        assessment=risk.get("assessment"),
        evidence_score=risk.get("evidence_score"),
        confidence=risk.get("confidence"),
        ctx=ctx,
    )


def _analyze_image_info_from_path(path: str, original_name: str) -> dict:
    """Validate + decode a file already on disk.

    Mirrors ``image_info.analyze`` but takes a path instead of an
    ``UploadedFile`` so batch mode can reuse the same validation chain.
    """
    from src.image_info import (
        extract_image_info,
        validate_image_dimensions,
    )
    from src.utils import safe_open_image, sanitize_filename

    try:
        size = __import__("os").path.getsize(path)
    except OSError as exc:
        return {"ok": False, "error": f"Cannot read file: {exc}",
                "filename": sanitize_filename(original_name), "info": None}
    if size == 0:
        return {"ok": False, "error": "Empty file.",
                "filename": sanitize_filename(original_name), "info": None}

    try:
        img = safe_open_image(path)
    except ValueError as exc:
        return {"ok": False, "error": str(exc),
                "filename": sanitize_filename(original_name), "info": None}

    ok, reason = validate_image_dimensions(*img.size)
    if not ok:
        return {"ok": False, "error": reason,
                "filename": sanitize_filename(original_name), "info": None}

    try:
        info = extract_image_info(path, original_name)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"Could not read image information: {exc}",
                "filename": sanitize_filename(original_name), "info": None}

    return {"ok": True, "error": "", "filename": info["filename"], "info": info}


def run_batch(paths: list[tuple[str, str]], progress_cb=None):
    """Analyze many files. Returns ``(rows, done)``.

    ``paths`` is a list of ``(path, original_name)`` tuples.
    ``progress_cb(i, total, filename)`` is invoked before each file so the
    UI can update a progress bar; it may raise to cancel the batch.
    """
    rows: list[BatchRow] = []
    total = len(paths)
    for i, (path, name) in enumerate(paths):
        if progress_cb is not None:
            progress_cb(i, total, name)
        try:
            row = run_one(path, name)
        except Exception as exc:  # noqa: BLE001 — one bad file never kills the batch
            logger.warning("batch: %s failed hard: %s", name, exc)
            row = BatchRow(
                filename=name, sha256="", ok=False,
                error=f"Unexpected failure: {exc}",
                verdict=None, assessment=None,
                evidence_score=None, confidence=None, ctx=None,
            )
        rows.append(row)
    return rows


def to_csv(rows: list[BatchRow]) -> str:
    """Render summary rows as CSV text (pandas is already a dependency)."""
    import io as _io

    import pandas as pd

    data = [{
        "filename": r.filename,
        "sha256": r.sha256,
        "ok": r.ok,
        "error": r.error,
        "verdict": r.verdict or "",
        "assessment": r.assessment or "",
        "evidence_score": "" if r.evidence_score is None else f"{r.evidence_score:.3f}",
        "confidence": r.confidence or "",
    } for r in rows]
    buf = _io.StringIO()
    pd.DataFrame(data).to_csv(buf, index=False)
    return buf.getvalue()
