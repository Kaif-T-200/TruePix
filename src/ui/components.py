"""Reusable Streamlit UI components for TruePix.

These helpers are intentionally tiny and stateless; they are rendered with
``st.markdown(..., unsafe_allow_html=True)`` to fit the dark forensic
theme. The components never return values -- they are presentational.
"""

from __future__ import annotations

import uuid

import streamlit as st
import streamlit.components.v1 as components

from src.ui.styles import SEVERITY_STYLE, STATUS_STYLE


def status_badge(status: str) -> str:
    """Return HTML for a status badge (color + icon + label)."""
    color, icon, label = STATUS_STYLE.get(status, STATUS_STYLE["PENDING"])
    return f'<span class="tp-badge" style="background:{color}">{icon} {label}</span>'


def status_color(status: str) -> str:
    return STATUS_STYLE.get(status, STATUS_STYLE["PENDING"])[0]


def status_icon_label(status: str) -> tuple[str, str]:
    return STATUS_STYLE.get(status, STATUS_STYLE["PENDING"])[1:]


def severity_badge(sev: str) -> str:
    color = SEVERITY_STYLE.get(sev, SEVERITY_STYLE["Informational"])
    return f'<span class="tp-badge" style="background:{color}">{sev.upper()}</span>'


def stat_line(name: str, value) -> None:
    """Render a single ``name: value`` row in a card."""
    st.markdown(
        f'<div class="tp-stat"><span class="tp-key">{name}</span>'
        f'<b>{value}</b></div>',
        unsafe_allow_html=True,
    )


def render_findings(findings: list[dict] | None) -> None:
    """Render a list of findings in the dark-theme card style."""
    if not findings:
        st.info("No findings.")
        return
    for f in findings:
        accent = SEVERITY_STYLE.get(
            f.get("severity"), SEVERITY_STYLE["Informational"]
        )
        st.markdown(
            f'<div class="tp-finding" style="border-left-color:{accent}">'
            f'<div style="display:flex;justify-content:space-between;align-items:center">'
            f'<b>{f.get("id", "F-?")} · {f.get("category", "")}</b> '
            f'{severity_badge(f.get("severity", "Informational"))}</div>'
            f'<div style="margin:6px 0;font-size:15px"><b>{f.get("title", "")}</b></div>'
            f'<div class="tp-muted">Confidence: {f.get("confidence", "")}</div>'
            f'<div style="margin-top:6px"><span class="tp-key">Evidence:</span> '
            f'{f.get("evidence", "")}</div>'
            f'<div><span class="tp-key">Interpretation:</span> '
            f'{f.get("interpretation", "")}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


def copy_button(text: str, label: str = "Copy") -> None:
    """Render a small JS-driven copy-to-clipboard button.

    Uses ``st.components.html`` for a single self-contained button so the
    parent page is not rerun on click.
    """
    cid = "cp_" + uuid.uuid4().hex[:8]
    safe = text.replace("'", "")
    html = (
        f'<button id="{cid}" onclick="navigator.clipboard.writeText(\'{safe}\').then('
        f'function(){{var e=document.getElementById(\'{cid}\');e.innerText=\'Copied\';'
        f'setTimeout(function(){{e.innerText=\'{label}\';}},1500);}})" '
        f'style="background:#2b333d;color:#e6edf3;border:1px solid #30363d;'
        f'border-radius:6px;padding:3px 10px;font-size:11px;cursor:pointer">{label}</button>'
    )
    components.html(html, height=30)
