"""Sidebar, landing page, and workspace header for TruePix.

Pure presentation: no analyzer code lives here. The sidebar owns the
upload widget, navigation radio, and a compact case list (Phase 2+ will
expand it). The landing page is shown when no file is uploaded.
"""

from __future__ import annotations

import streamlit as st

from src.ui.styles import (
    DARK_CSS,
    DISCLAIMER,
    SUBTITLE,
    TAGLINE,
    TITLE,
    VERSION,
)


def render_css() -> None:
    """Inject the global dark forensic CSS once per page."""
    st.markdown(DARK_CSS, unsafe_allow_html=True)


def sidebar(uploaded_present: bool) -> None:
    """Render the fixed-width sidebar."""
    st.sidebar.markdown(
        f'<div class="tp-brand">{TITLE}<span class="dot">.</span></div>',
        unsafe_allow_html=True,
    )
    st.sidebar.markdown(
        '<div class="tp-sub">Forensic Analysis</div>', unsafe_allow_html=True
    )
    st.sidebar.markdown('<div class="tp-sep"></div>', unsafe_allow_html=True)

    st.sidebar.markdown(
        '<div class="tp-section-label">Upload</div>', unsafe_allow_html=True
    )
    st.sidebar.file_uploader(
        "Upload Image",
        type=["jpg", "jpeg", "png", "bmp", "gif", "tiff", "webp"],
        help="Max 25 MB. Processed locally on CPU.",
        key="sidebar_uploader",
    )

    if uploaded_present:
        st.sidebar.markdown('<div class="tp-sep"></div>', unsafe_allow_html=True)
        st.sidebar.markdown(
            '<div class="tp-section-label">Case</div>', unsafe_allow_html=True
        )
        st.sidebar.radio(
            "Navigate",
            [
                "Overview",
                "Image Info",
                "Metadata",
                "C2PA / Content Credentials",
                "Image Forensics",
                "Visual Artifacts",
                "Compare",
                "Batch",
                "Evidence Report",
                "Settings",
            ],
            key="nav",
            label_visibility="collapsed",
        )

    _sidebar_history()


def _sidebar_history() -> None:
    """Compact list of cases analyzed this session (click to re-open)."""
    history = st.session_state.get("history") or []
    if not history:
        return
    st.sidebar.markdown('<div class="tp-sep"></div>', unsafe_allow_html=True)
    st.sidebar.markdown(
        '<div class="tp-section-label">History</div>', unsafe_allow_html=True
    )
    for i, entry in enumerate(reversed(history[:10])):
        label = f"{entry['filename'][:18]} · {entry['verdict_short']}"
        if st.sidebar.button(label, key=f"hist_{i}",
                             use_container_width=True):
            # Selecting a historical case re-displays its cached context.
            st.session_state["active_case"] = len(history) - 1 - i
            st.session_state["nav"] = "Overview"
            st.rerun()

    st.sidebar.markdown('<div class="tp-sep"></div>', unsafe_allow_html=True)
    st.sidebar.markdown(
        '<div class="tp-section-label">System</div>', unsafe_allow_html=True
    )
    st.sidebar.markdown(
        '<div class="tp-muted">CPU Mode<br>Local Processing</div>',
        unsafe_allow_html=True,
    )

    st.sidebar.markdown('<div class="tp-sep"></div>', unsafe_allow_html=True)
    st.sidebar.markdown(
        f'<div class="tp-muted">Version {VERSION}</div>', unsafe_allow_html=True
    )
    st.sidebar.caption(DISCLAIMER)


def landing() -> None:
    """Render the pre-upload landing page."""
    st.markdown(
        f'<div class="tp-hero">'
        f'<div class="tp-brand" style="font-size:48px">{TITLE}<span class="dot">.</span></div>'
        f'<div style="color:var(--accent);font-size:17px;letter-spacing:1px;'
        f'margin-top:6px">{SUBTITLE}</div>'
        f'<div class="tp-muted" style="font-size:15px;margin-top:8px">{TAGLINE}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.markdown("<hr class='tp'>", unsafe_allow_html=True)

    col = st.columns([1, 2, 1])[1]
    with col:
        st.markdown("### Upload an image to begin")
        st.markdown(
            "Drop an image into the **Upload** control in the sidebar (or use "
            "the one below) to run a complete on-device forensic analysis.",
            unsafe_allow_html=True,
        )
        st.file_uploader(
            "Upload Image",
            type=["jpg", "jpeg", "png", "bmp", "gif", "tiff", "webp"],
            key="landing_uploader",
            help="Max 25 MB. Processed locally on CPU.",
        )
        st.markdown("<br>", unsafe_allow_html=True)

        features = [
            ("LOCAL FORENSICS", "Metadata, EXIF, ELA, noise, compression"),
            ("CONTENT CREDENTIALS", "C2PA provenance detection (not verification)"),
            ("EVIDENCE-BASED ASSESSMENT", "Weighted, probability-free scoring"),
        ]
        st.markdown('<div class="tp-card">', unsafe_allow_html=True)
        for name, desc in features:
            st.markdown(
                f'<div style="display:flex;justify-content:space-between;'
                f'align-items:center;padding:6px 0;'
                f'border-bottom:1px dashed var(--border)">'
                f'<b style="font-size:12px;letter-spacing:.5px;color:var(--accent)">'
                f'{name}</b>'
                f'<span class="tp-muted" style="font-size:11.5px">{desc}</span></div>',
                unsafe_allow_html=True,
            )
        st.markdown('</div>', unsafe_allow_html=True)
        st.caption(DISCLAIMER)

    st.markdown(
        f'<div class="tp-footer">TruePix {VERSION} · Local CPU forensic engine</div>',
        unsafe_allow_html=True,
    )


def render_header(ctx) -> None:
    """Render the top-of-workspace header bar."""
    info = ctx.image_info
    st.markdown(
        f'<div class="tp-header">'
        f'<div><div class="title">Analysis Overview</div>'
        f'<div class="desc">Forensic analysis of {info["filename"]}</div></div>'
        f'<div class="controls"></div></div>',
        unsafe_allow_html=True,
    )
    hc = st.columns([2.6, 2.5, 1.2, 0.5])
    with hc[0]:
        st.markdown(
            f'<div class="tp-muted" style="padding-top:6px">'
            f'{TITLE} · Forensic Workspace</div>',
            unsafe_allow_html=True,
        )
    with hc[1]:
        st.markdown(
            '<span class="tp-badge" style="background:#444c56">● LOCAL ONLY</span>',
            unsafe_allow_html=True,
        )
    with hc[2]:
        if st.button(
            "⬇ Export Report", key="header_export", use_container_width=True
        ):
            st.session_state["nav"] = "Evidence Report"
    with hc[3]:
        if st.button(
            "⋮", key="header_menu", use_container_width=True,
            help="Settings and configuration",
        ):
            st.session_state["nav"] = "Settings"
