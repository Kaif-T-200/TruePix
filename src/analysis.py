"""Pure analysis pipeline for TruePix (Phase 1).

Wraps every analyzer module so a single failure cannot abort the rest of the
run. A failed module produces ``None`` for its result and a string entry in
``AnalysisContext.errors``; the UI surfaces both.

The pipeline is a pure function of an on-disk image path. The Streamlit
upload widget (``UploadedFile``) is handled in the UI layer; once a file has
been validated and written to ``tmp_path``, this module takes over.

This module deliberately performs no I/O outside the supplied path. It
imports analyzer modules lazily inside the try/except so that a missing
optional dependency (e.g. ``transformers`` for the local AI detector) does
not break the rest of the run.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("truepix")

# Per-analyzer timeout / failure budget. A module that raises or returns
# None still appears in errors so the user knows what was skipped.
_MODULE_NAMES = (
    "metadata", "c2pa", "forensics", "artifacts",
    "ai_detector", "synthid",
)


@dataclass
class AnalysisContext:
    """All results from a single forensic run, in a stable shape.

    Each field is either the analyzer's dict (with its own status / findings
    schema) or ``None`` when the module failed. ``errors`` lists the
    human-readable reason for each ``None`` so the UI can show them in
    Settings without a separate log.
    """

    image_path: str
    image_info: dict | None
    metadata: dict | None = None
    c2pa: dict | None = None
    forensics: dict | None = None
    artifacts: dict | None = None
    ai_detector: dict | None = None
    synthid: dict | None = None
    jpeg_ghost: dict | None = None
    cfa: dict | None = None
    risk: dict | None = None
    errors: list[str] = field(default_factory=list)

    def module_statuses(self) -> dict[str, str]:
        """Return a ``{module: status}`` mapping the UI uses for tiles.

        ``status`` is one of: ``COMPLETE``, ``FINDINGS``, ``NO DATA``,
        ``UNAVAILABLE``, ``NOT CONFIGURED``, ``ERROR``. The strings match
        the StatusCard colors already defined in the Streamlit UI.
        """
        statuses: dict[str, str] = {}

        meta = self.metadata
        if meta is None:
            statuses["metadata"] = "UNAVAILABLE"
        else:
            statuses["metadata"] = "COMPLETE" if meta.get("available") else "NO DATA"
            if any("AI-generation" in f.get("title", "")
                   for f in meta.get("findings", [])):
                statuses["metadata"] = "FINDINGS"

        c2pa = self.c2pa
        if c2pa is None:
            statuses["c2pa"] = "UNAVAILABLE"
        else:
            statuses["c2pa"] = {
                "VERIFIED": "COMPLETE",
                "PRESENT_UNVERIFIED": "FINDINGS",
                "NOT_FOUND": "NO DATA",
                "UNSUPPORTED": "UNAVAILABLE",
                "ERROR": "UNAVAILABLE",
            }.get(c2pa.get("status"), "UNAVAILABLE")

        forensics = self.forensics
        if forensics is None:
            statuses["forensics"] = "UNAVAILABLE"
        elif forensics.get("findings"):
            statuses["forensics"] = "FINDINGS"
        elif any(
            forensics.get(k, {}).get("available")
            for k in ("ela", "noise", "compression", "edges", "frequency", "dct",
                      "color_banding", "texture_uniformity", "saturation",
                      "noise_correlation", "channel_correlation",
                      "transformation_history", "screen_capture", "content_style")
        ):
            statuses["forensics"] = "COMPLETE"
        else:
            statuses["forensics"] = "NO DATA"

        artifacts = self.artifacts
        if artifacts is None:
            statuses["artifacts"] = "UNAVAILABLE"
        elif artifacts.get("findings"):
            statuses["artifacts"] = "FINDINGS"
        elif artifacts.get("checks"):
            statuses["artifacts"] = "COMPLETE"
        else:
            statuses["artifacts"] = "NO DATA"

        ai = self.ai_detector
        if ai is None:
            statuses["ai_detector"] = "UNAVAILABLE"
        else:
            statuses["ai_detector"] = {
                "AVAILABLE": "CONFIGURED",
                "NOT_CONFIGURED": "NOT CONFIGURED",
                "ERROR": "ERROR",
            }.get(ai.get("status"), "UNAVAILABLE")

        synth = self.synthid
        if synth is None:
            statuses["synthid"] = "UNAVAILABLE"
        else:
            statuses["synthid"] = {
                "DETECTED": "FINDINGS",
                "NOT_DETECTED": "COMPLETE",
                "UNAVAILABLE": "UNAVAILABLE",
                "ERROR": "ERROR",
            }.get(synth.get("status"), "UNAVAILABLE")

        jg = self.jpeg_ghost
        if jg is None:
            statuses["jpeg_ghost"] = "UNAVAILABLE"
        elif jg.get("findings"):
            statuses["jpeg_ghost"] = "FINDINGS"
        else:
            statuses["jpeg_ghost"] = ("COMPLETE" if jg.get("available")
                                      else "NO DATA")

        cfa = self.cfa
        if cfa is None:
            statuses["cfa"] = "UNAVAILABLE"
        elif cfa.get("findings"):
            statuses["cfa"] = "FINDINGS"
        else:
            statuses["cfa"] = ("COMPLETE" if cfa.get("available")
                               else "NO DATA")

        return statuses


def _safe(name: str, fn) -> tuple[Any, str | None]:
    """Run ``fn()`` and return ``(result, error)``.

    ``result`` is the analyzer's return value on success and ``None`` on
    failure. ``error`` is a human-readable string on failure and ``None``
    on success. Never propagates exceptions.
    """
    try:
        return fn(), None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Analyzer %s failed: %s", name, exc, exc_info=False)
        return None, f"{name}: {exc}"


def run_all(image_path: str, info: dict | None) -> AnalysisContext:
    """Run every analyzer and the risk engine on ``image_path``.

    ``info`` is the pre-validated image info dict from
    ``image_info.analyze``. The function never raises; a per-module
    failure becomes ``None`` plus an ``errors`` entry.
    """
    # Imported lazily so a missing optional dependency (torch, transformers)
    # only breaks its own module, not the rest of the run.
    from src import (metadata_analyzer, c2pa_analyzer, image_forensics,
                     artifact_analyzer, ai_detector, provenance_detector,
                     risk_engine, jpeg_ghost, cfa_analyzer)

    ctx = AnalysisContext(image_path=image_path, image_info=info)

    ctx.metadata, err = _safe("metadata",
                              lambda: metadata_analyzer.analyze(image_path))
    if err:
        ctx.errors.append(err)

    ctx.c2pa, err = _safe("c2pa",
                          lambda: c2pa_analyzer.analyze(image_path))
    if err:
        ctx.errors.append(err)

    ctx.forensics, err = _safe("forensics",
                               lambda: image_forensics.analyze(image_path))
    if err:
        ctx.errors.append(err)

    ctx.artifacts, err = _safe("artifacts",
                               lambda: artifact_analyzer.analyze(image_path))
    if err:
        ctx.errors.append(err)

    ctx.ai_detector, err = _safe("ai_detector",
                                 lambda: ai_detector.analyze(image_path))
    if err:
        ctx.errors.append(err)

    ctx.synthid, err = _safe("synthid",
                             lambda: provenance_detector.analyze(image_path))
    if err:
        ctx.errors.append(err)

    ctx.jpeg_ghost, err = _safe("jpeg_ghost",
                                lambda: jpeg_ghost.analyze(image_path))
    if err:
        ctx.errors.append(err)

    ctx.cfa, err = _safe("cfa",
                         lambda: cfa_analyzer.analyze(image_path))
    if err:
        ctx.errors.append(err)

    # Risk engine is non-critical and depends on all of the above. It
    # should never fail except for an internal bug; if it does, we still
    # hand the user the raw evidence.
    try:
        ctx.risk = risk_engine.assess({
            "metadata": ctx.metadata,
            "c2pa": ctx.c2pa,
            "forensics": ctx.forensics,
            "artifacts": ctx.artifacts,
            "ai_detector": ctx.ai_detector,
            "synthid": ctx.synthid,
            "jpeg_ghost": ctx.jpeg_ghost,
            "cfa": ctx.cfa,
        })
    except Exception as exc:  # noqa: BLE001
        logger.warning("Risk engine failed: %s", exc, exc_info=False)
        ctx.errors.append(f"risk_engine: {exc}")
        ctx.risk = None

    return ctx
