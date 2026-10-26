"""TruePix — AI Image Authenticity & Forensic Analysis System.

Phase 1 entry point. The presentation layer has been moved into
``src/ui/``; this file is now a thin shell that:

1. Boots session state.
2. Reads uploaded files (sidebar or landing).
3. Validates + decodes the image (delegated to ``src.image_info``).
4. Runs the pure analysis pipeline (``src.analysis.run_all``).
5. Dispatches to the right page renderer based on the sidebar radio.

It is intentionally small (< 200 lines) so future features (batch mode,
image diff, case history) can extend the dispatcher without touching
forensic logic.
"""

from __future__ import annotations

import logging
import os
import tempfile

import streamlit as st

from src import ai_detector, image_info, utils
from src.analysis import AnalysisContext, run_all
from src.ui import (
    landing,
    page_export,
    page_settings,
    render_css,
    render_header,
    render_overview,
    sidebar,
)
from src.ui.pages import (
    page_batch,
    page_compare,
    render_artifacts,
    render_c2pa,
    render_forensics,
    render_image_info,
    render_metadata,
)

# Configure a package-level logger. NullHandler by default so that
# importing TruePix from a script or test never emits a record.
logger = logging.getLogger("truepix")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


def _resolve_uploaded():
    """Return the most recent ``UploadedFile`` from sidebar or landing."""
    sb = st.session_state.get("sidebar_uploader")
    lm = st.session_state.get("landing_uploader")
    return lm or sb


def _dispatch(ctx: AnalysisContext) -> None:
    """Route to the page the user selected in the sidebar."""
    nav = st.session_state.get("nav", "Overview")
    if nav == "Overview":
        render_overview(ctx)
    elif nav == "Image Info":
        render_image_info(ctx)
    elif nav == "Metadata":
        render_metadata(ctx.metadata)
    elif nav == "C2PA / Content Credentials":
        render_c2pa(ctx.c2pa)
    elif nav == "Image Forensics":
        render_forensics(ctx.forensics, ctx.jpeg_ghost, ctx.cfa)
    elif nav == "Visual Artifacts":
        render_artifacts(ctx.artifacts)
    elif nav == "Compare":
        page_compare()
    elif nav == "Batch":
        page_batch()
    elif nav == "Evidence Report":
        page_export(ctx)
    elif nav == "Settings":
        page_settings(ctx.errors)


def _record_history(ctx: AnalysisContext) -> None:
    """Append a lightweight history entry (session-only, never on disk)."""
    risk = ctx.risk or {}
    verdict = risk.get("verdict") or "ORIGIN_UNKNOWN"
    entry = {
        "filename": ctx.image_info["filename"],
        "sha256": ctx.image_info["sha256"],
        "verdict": verdict,
        "verdict_short": verdict.replace("_", " ")[:14],
        "assessment": risk.get("assessment"),
        "evidence_score": risk.get("evidence_score"),
        "confidence": risk.get("confidence"),
        # Small thumbnail keeps memory bounded; full images stay temp files.
        "thumbnail_b64": _thumbnail_b64(ctx.image_path),
    }
    history: list = st.session_state.setdefault("history", [])
    max_size = int(st.session_state.get("opt_history_size", 20))
    history.append(entry)
    del history[:-max_size]


def _thumbnail_b64(path: str, max_side: int = 96) -> str | None:
    try:
        import base64
        import io

        from PIL import Image

        with Image.open(path) as img:
            img.thumbnail((max_side, max_side))
            buf = io.BytesIO()
            img.convert("RGB").save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:  # noqa: BLE001 — a failed thumbnail never breaks analysis
        return None


def main_entry() -> None:
    """Streamlit entry point invoked by ``Start_TruePix.bat``."""
    ai_detector._read_dotenv()  # optional .env support, no external dep
    st.session_state.setdefault("nav", "Overview")
    st.session_state.setdefault("session_errors", [])

    render_css()
    uploaded = _resolve_uploaded()
    sidebar(uploaded is not None)

    if uploaded is None:
        landing()
        return

    # Validate + decode first; bail out cleanly on a bad upload.
    tmp_dir = tempfile.mkdtemp(prefix="truepix_")
    tmp_path = os.path.join(tmp_dir, utils.sanitize_filename(uploaded.name))
    try:
        result = image_info.analyze(uploaded, tmp_path)
        if not result["ok"]:
            st.error(f"Upload rejected: {result['error']}")
            from src.ui.styles import DISCLAIMER, VERSION
            st.caption(DISCLAIMER)
            st.markdown(
                f'<div class="tp-footer">TruePix {VERSION}</div>',
                unsafe_allow_html=True,
            )
            return

        with st.spinner("Running local forensic analysis…"):
            ctx = run_all(tmp_path, result["info"])
        st.session_state["session_errors"] = list(ctx.errors)
        _record_history(ctx)

        render_header(ctx)
        _dispatch(ctx)

        from src.ui.styles import DISCLAIMER, VERSION
        st.caption(DISCLAIMER)
        st.markdown(
            f'<div class="tp-footer">TruePix {VERSION}</div>',
            unsafe_allow_html=True,
        )
    finally:
        try:
            os.remove(tmp_path)
            os.rmdir(tmp_dir)
        except OSError:
            pass


if __name__ == "__main__":
    main_entry()
