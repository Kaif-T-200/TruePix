"""Streamlit UI package for TruePix (Phase 1).

The actual entry point is still ``app.py`` at the repo root. This package
owns the presentation: CSS, layout, components, and per-page renderers.
"""

from __future__ import annotations

from src.ui.layout import landing, render_css, render_header, sidebar
from src.ui.pages import (
    build_report,
    page_batch,
    page_compare,
    page_export,
    page_settings,
    render_artifacts,
    render_c2pa,
    render_forensics,
    render_image_info,
    render_metadata,
    render_overview,
    render_risk,
)

__all__ = [
    "landing",
    "render_css",
    "render_header",
    "sidebar",
    "build_report",
    "page_batch",
    "page_compare",
    "page_export",
    "page_settings",
    "render_artifacts",
    "render_c2pa",
    "render_forensics",
    "render_image_info",
    "render_metadata",
    "render_overview",
    "render_risk",
]
