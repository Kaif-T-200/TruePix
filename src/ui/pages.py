"""Per-nav-target renderers for the TruePix workspace.

Each public function in this module corresponds to one entry in the
sidebar radio (Image Info, Metadata, C2PA, Forensics, Artifacts, Risk
Report, Settings). The dispatcher in ``app.py`` calls the right
function based on ``st.session_state["nav"]``.

Renderers are pure presentation: they take an ``AnalysisContext`` (or a
field of one) and call Streamlit. They never invoke analyzers.
"""

from __future__ import annotations

import json

import streamlit as st

from src.reports.json_report import report_filename
from src.ui.components import (
    copy_button,
    render_findings,
    severity_badge,
    stat_line,
    status_badge,
    status_color,
    status_icon_label,
)
from src.ui.styles import (
    DISCLAIMER,
    ORIGIN_VERDICT_LABEL,
    OVERVIEW_VERDICT_LABEL,
    VERDICT_BANNER_COLOR,
    VERDICT_BANNER_ICON,
    VERDICT_BANNER_LABEL,
)


# --------------------------------------------------------------------------- #
# Image Info
# --------------------------------------------------------------------------- #
def render_image_info(ctx) -> None:
    info = ctx.image_info
    st.markdown("### Image Information")
    st.markdown('<div class="tp-card flush">', unsafe_allow_html=True)
    st.image(ctx.image_path, width=420)
    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
    for k, v in [
        ("Filename", info["filename"]),
        ("Format", info["image_format"]),
        ("Resolution", f'{info["width"]} × {info["height"]}'),
        ("Color mode", info["color_mode"]),
        ("MIME type", info["mime_type"]),
        ("Aspect ratio", info["aspect_ratio"]),
        ("File size", f'{info["file_size_bytes"]:,} bytes'),
        ("SHA-256", info["sha256"]),
    ]:
        stat_line(k, v)
    st.markdown('</div>', unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #
def render_metadata(meta: dict | None) -> None:
    st.markdown("### Metadata Forensics")
    if meta is None:
        st.warning("Metadata analysis unavailable.")
        return
    st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
    status_txt = "AVAILABLE" if meta["available"] else "NONE FOUND"
    gps_txt = "PRESENT" if meta["fields"].get("GPS Metadata") == "Present" else "NONE"
    sw = meta["fields"].get("Software", "—")
    stat_line("Metadata Status", status_txt)
    stat_line("Fields Found", meta["field_count"])
    stat_line("GPS Data", gps_txt)
    stat_line("Software", sw)
    st.markdown('</div>', unsafe_allow_html=True)
    for k, v in meta["fields"].items():
        if k in ("Software", "GPS Metadata"):
            continue
        st.markdown(f"<b>{k}</b>: {v}", unsafe_allow_html=True)
    if meta.get("findings"):
        render_findings(meta["findings"])
    with st.expander("Technical Metadata"):
        if meta.get("technical"):
            for k, v in meta["technical"].items():
                st.markdown(f"<b>{k}</b>: {v}", unsafe_allow_html=True)
        else:
            st.markdown("No additional technical metadata.")


# --------------------------------------------------------------------------- #
# C2PA
# --------------------------------------------------------------------------- #
def render_c2pa(c2pa: dict | None) -> None:
    st.markdown("### Content Credentials")
    if c2pa is None:
        st.warning("Content Credentials analysis unavailable.")
        return

    status = c2pa.get("status")
    color = {
        "VERIFIED": "#2ea043", "PRESENT_UNVERIFIED": "#e0a32e",
        "NOT_FOUND": "#5b6b7f", "UNSUPPORTED": "#444c56", "ERROR": "#444c56",
    }.get(status, "#444c56")
    icon = {"VERIFIED": "✓", "PRESENT_UNVERIFIED": "⚠", "NOT_FOUND": "○",
            "UNSUPPORTED": "○", "ERROR": "○"}.get(status, "○")
    label = {
        "VERIFIED": "VERIFIED CONTENT CREDENTIALS",
        "PRESENT_UNVERIFIED": "CONTENT CREDENTIALS",
        "NOT_FOUND": "NO CONTENT CREDENTIALS FOUND",
        "UNSUPPORTED": "UNSUPPORTED",
        "ERROR": "ERROR",
    }.get(status, str(status))
    st.markdown(
        f'<div class="tp-card sm">'
        f'<span class="tp-badge" style="background:{color}">{icon} {label}</span>'
        f'<div class="tp-muted" style="margin-top:8px">{c2pa.get("summary", "")}</div></div>',
        unsafe_allow_html=True,
    )

    prov = c2pa.get("provenance") or {}
    if prov:
        st.markdown("**Provenance information**")
        field_map = [
            ("Source / History", "source_history"),
            ("App / Device Used", "application"),
            ("Issued By", "issued_by"),
            ("Issued On", "issued_on"),
            ("Actions", "actions"),
            ("Digital Source Type", "digital_source_type"),
            ("Claim Generator", "claim_generator"),
            ("Manifest ID", "manifest_id"),
        ]
        for name, key in field_map:
            if prov.get(key):
                stat_line(name, prov[key])
        dst = (prov.get("digital_source_type") or "").lower()
        if "ai" in dst or "generated" in dst:
            st.info("Digital Source Type indicates AI-generated content. This is "
                    "strong provenance evidence, not a generic visual prediction.")
        elif "edit" in dst or "composite" in dst or "compositing" in dst:
            st.info("Digital Source Type indicates editing/compositing. This does "
                    "NOT by itself mean the image is AI-generated.")

    if status == "PRESENT_UNVERIFIED":
        stat_line("Verification",
                  '<b style="color:#e0a32e">⚠ PRESENT — UNVERIFIED</b>')
        st.markdown(
            "A C2PA / content-credentials structure was detected, but TruePix "
            "cannot cryptographically verify its authenticity in this "
            "lightweight scanner.",
            help="Detection is not verification.",
        )
        st.caption("**Detection ≠ Verification** — the presence of provenance "
                   "metadata does not by itself establish that the embedded "
                   "claims are authentic.")
    elif status == "VERIFIED":
        stat_line("Verification", '<b style="color:#2ea043">✓ VALID</b>')
    elif status == "NOT_FOUND":
        st.caption("The absence of Content Credentials does not prove that an "
                   "image is authentic or AI-generated.")

    if c2pa.get("hints"):
        st.markdown(
            f'<div class="tp-muted"><b>Unverified manifest hints:</b> '
            f'{", ".join(c2pa["hints"])}</div>',
            unsafe_allow_html=True,
        )
    if c2pa.get("findings"):
        render_findings(c2pa["findings"])
    with st.expander("Technical C2PA details"):
        st.markdown(f"Raw status: `{status}`")
        st.markdown("Manifest content is not fetched or executed. Verification "
                    "requires a cryptographic C2PA verifier, which TruePix does "
                    "not run by design.")


# --------------------------------------------------------------------------- #
# Image Forensics
# --------------------------------------------------------------------------- #
def _render_jpeg_ghost_card(jg: dict | None) -> None:
    """Phase-3: JPEG compression-history card."""
    st.markdown("#### JPEG Compression History")
    if not jg or not jg.get("available"):
        st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
        st.markdown("Unavailable" if jg is None else
                    (jg.get("summary") or "Unavailable"))
        st.markdown('</div>', unsafe_allow_html=True)
        return
    hist = jg.get("jpeg_history") or {}
    st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
    dip = hist.get("dip_found")
    stat_line("Prior JPEG compression detected", "YES" if dip else "NO")
    stat_line("Estimated original quality",
              f"q≈{hist.get('estimated_quality')}" if dip else "—")
    stat_line("Dip depth", hist.get("dip_depth", "—"))
    stat_line("8×8 grid strength", hist.get("grid_strength", "—"))
    st.markdown('</div>', unsafe_allow_html=True)
    st.caption("Compression history describes the file's storage path — "
               "screenshots, messaging apps, and edits all re-compress. It "
               "is never evidence about AI generation.")


def _render_cfa_card(cfa: dict | None) -> None:
    """Phase-3: demosaicing / camera-pipeline card."""
    st.markdown("#### Demosaicing (CFA) Signature")
    if not cfa or not cfa.get("available"):
        st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
        st.markdown("Unavailable" if cfa is None else
                    (cfa.get("summary") or "Unavailable"))
        st.markdown('</div>', unsafe_allow_html=True)
        return
    res = cfa.get("cfa_analysis") or {}
    st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
    stat_line("Camera-style CFA signature",
              "DETECTED" if res.get("cfa_detected") else "NOT DETECTED")
    stat_line("2px periodicity score",
              res.get("cfa_periodicity_score", "—"))
    st.markdown('</div>', unsafe_allow_html=True)
    if res.get("cfa_detected"):
        st.caption("Weakly consistent with a Bayer-sensor camera capture. "
                   "The signature does not survive resizing or recompression, "
                   "so its presence is a hint — never proof.")
    else:
        st.caption("No 2px periodicity found. Expected for AI images but "
                   "equally expected for screenshots, resized photos, and "
                   "rendered graphics — absence is NOT evidence of AI "
                   "generation.")


def render_forensics(forensics: dict | None,
                     jpeg_ghost: dict | None = None,
                     cfa: dict | None = None) -> None:
    st.markdown("### Image Forensics")
    if forensics is None:
        st.warning("Forensic analysis unavailable.")
        return

    st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)

    ela = forensics.get("ela", {})
    st.markdown("**ELA** — " + ("Available" if ela.get("available") else "Unavailable"))
    if ela.get("available"):
        stat_line("Mean residual", ela["mean"])
        stat_line("Std residual", ela["std"])
        stat_line("Max residual", ela["max"])

    noise = forensics.get("noise", {})
    st.markdown("**Noise** — " + ("Available" if noise.get("available") else "Unavailable"))
    if noise.get("available"):
        stat_line("Global level", noise["global_level"])
        stat_line("Regional consistency (CV)", noise["regional_consistency_cv"])

    comp = forensics.get("compression", {})
    st.markdown("**Compression** — " + ("Available" if comp.get("available") else "Unavailable"))
    if comp.get("available"):
        stat_line("Bytes / pixel", comp["bytes_per_pixel"])
        stat_line("Blockiness", comp["blockiness"])

    edges = forensics.get("edges", {})
    st.markdown("**Edges** — " + ("Available" if edges.get("available") else "Unavailable"))
    if edges.get("available"):
        stat_line("Edge density", edges["edge_density"])

    freq = forensics.get("frequency", {})
    st.markdown("**Frequency** — " + ("Available" if freq.get("available") else "Unavailable"))
    if freq.get("available"):
        stat_line("High-frequency ratio", freq["high_frequency_ratio"])

    dct = forensics.get("dct", {})
    st.markdown("**DCT Analysis** — " + ("Available" if dct.get("available") else "Unavailable"))
    if dct.get("available"):
        stat_line("DC uniformity (CV)", dct["dc_uniformity_cv"])
        stat_line("AC energy", dct["ac_energy"])

    banding = forensics.get("color_banding", {})
    st.markdown("**Color Banding** — " + ("Available" if banding.get("available") else "Unavailable"))
    if banding.get("available"):
        stat_line("Empty histogram bins", banding["zero_bins"])
        stat_line("Gradient smoothness", banding["smoothness"])

    texture = forensics.get("texture_uniformity", {})
    st.markdown("**Texture** — " + ("Available" if texture.get("available") else "Unavailable"))
    if texture.get("available"):
        stat_line("Mean variance", texture["mean_variance"])
        stat_line("Uniformity ratio", texture["uniformity_ratio"])

    sat = forensics.get("saturation", {})
    st.markdown("**Saturation** — " + ("Available" if sat.get("available") else "Unavailable"))
    if sat.get("available"):
        stat_line("Mean saturation", sat["mean_saturation"])
        stat_line("Std saturation", sat["std_saturation"])

    noise_corr = forensics.get("noise_correlation", {})
    st.markdown("**Residual Noise Correlation** — " +
                ("Available" if noise_corr.get("available") else "Unavailable"))
    if noise_corr.get("available"):
        stat_line("Selected 8×8 blocks", noise_corr.get("selected_blocks", "—"))
        stat_line("Inter-block |correlation|", noise_corr.get("inter_block_abs_corr", "—"))
        stat_line("Residual channel |correlation|",
                  noise_corr.get("residual_channel_abs_corr", "—"))

    channel_corr = forensics.get("channel_correlation", {})
    st.markdown("**Color-Channel Residuals** — " +
                ("Available" if channel_corr.get("available") else "Unavailable"))
    if channel_corr.get("available"):
        stat_line("Raw RGB |correlation|", channel_corr.get("raw_mean_abs_corr", "—"))
        stat_line("High-pass RGB |correlation|", channel_corr.get("high_pass_mean_abs_corr", "—"))

    transform = forensics.get("transformation_history", {})
    st.markdown("**Transformation Context** — " +
                ("Available" if transform.get("available") else "Unavailable"))
    if transform.get("available"):
        stat_line("Neighbor residual correlation", transform.get("neighbor_residual_corr", "—"))
        stat_line("Very smooth pixel fraction", transform.get("very_smooth_pixel_fraction", "—"))

    capture = forensics.get("screen_capture", {})
    st.markdown("**Screen-Capture Context** — " +
                ("Available" if capture.get("available") else "Unavailable"))
    if capture.get("available"):
        stat_line("Capture-context score", capture.get("screen_capture_score", "—"))
        stat_line("Likely display capture",
                  "YES" if capture.get("likely_screen_capture") else "NO")

    style = forensics.get("content_style", {})
    st.markdown("**Content Style Context** — " +
                ("Available" if style.get("available") else "Unavailable"))
    if style.get("available"):
        stat_line("Stylized-context score", style.get("stylized_score", "—"))
        stat_line("Stylized / illustrated",
                  "YES" if style.get("stylized_or_illustrated") else "NO")
    st.markdown('</div>', unsafe_allow_html=True)

    # Phase-3 modules rendered as their own cards.
    _render_jpeg_ghost_card(jpeg_ghost)
    _render_cfa_card(cfa)

    st.caption("All metrics are heuristic observations. Capture/style context "
               "is not AI evidence and no visual-only method can recover the "
               "origin of a tightly cropped screenshot.")

    if forensics.get("findings"):
        render_findings(forensics["findings"])

    with st.expander("Technical forensic details"):
        ela = forensics.get("ela", {})
        if ela.get("available") and ela.get("preview_b64"):
            st.markdown("**ELA preview** (recompression residual)")
            st.image(f"data:image/png;base64,{ela['preview_b64']}", width=256)
        st.markdown(forensics.get("summary", ""))


# --------------------------------------------------------------------------- #
# Visual Artifacts
# --------------------------------------------------------------------------- #
def render_artifacts(artifacts: dict | None) -> None:
    st.markdown("### Visual Artifact Analysis")
    if artifacts is None:
        st.warning("Artifact analysis unavailable.")
        return
    checks = artifacts.get("checks", {})
    st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
    st.markdown("**Checks performed**")
    labels = {
        "texture": "Local texture consistency",
        "repetition": "Repeated-pattern / copy-move",
        "illumination": "Illumination consistency",
        "color_consistency": "Color / skin-region consistency",
        "anatomical": "Anatomical / landmark analysis",
    }
    for key, label in labels.items():
        c = checks.get(key, {})
        if key == "anatomical":
            status = "UNAVAILABLE" if not c.get("available") else "COMPLETE"
            detail = c.get("reason", "")
            stat_line(label, status)
            if detail:
                st.caption(detail)
        else:
            stat_line(label, "Available" if c.get("available") else "Unavailable")
    st.markdown('</div>', unsafe_allow_html=True)
    st.caption("Observations only — no conclusion about authenticity or AI "
               "generation is drawn.")

    if artifacts.get("findings"):
        render_findings(artifacts["findings"])
    else:
        st.info("No visual artifact observations were flagged.")

    with st.expander("Technical artifact details"):
        if artifacts.get("artifact_overlay_b64"):
            st.markdown("**Highlighted repeated-pattern regions**")
            st.image(
                f"data:image/png;base64,{artifacts['artifact_overlay_b64']}",
                width=256,
            )
        st.markdown(artifacts.get("summary", ""))


# --------------------------------------------------------------------------- #
# Risk / Evidence Report (render-only; the export page is separate)
# --------------------------------------------------------------------------- #
def render_risk(risk: dict | None) -> None:
    if risk is None:
        st.warning("Assessment unavailable.")
        return
    assessment = risk.get("assessment", "INSUFFICIENT_EVIDENCE")
    verdict = risk.get("verdict", "ORIGIN_UNKNOWN")
    color = VERDICT_BANNER_COLOR.get(assessment, "#5b6b7f")
    label = VERDICT_BANNER_LABEL.get(assessment, assessment)
    verdict_label = ORIGIN_VERDICT_LABEL.get(
        verdict, verdict.replace("_", " ")
    )
    icon = VERDICT_BANNER_ICON.get(assessment, "○")
    score = risk.get("evidence_score", 0)
    supporting = sum(
        1 for e in risk.get("evidence", []) if e["impact"] == "SUPPORTING"
    )
    opposing = sum(
        1 for e in risk.get("evidence", []) if e["impact"] == "OPPOSING"
    )
    neutral = max(
        0, len(risk.get("evidence", [])) - supporting - opposing
    )
    total = max(1, supporting + opposing + neutral)
    w_sup = supporting / total * 100
    w_opp = opposing / total * 100
    w_neu = neutral / total * 100
    pct = int(score * 100)

    # Big visual verdict banner.
    st.markdown(
        f'<div style="background:{color};border-radius:14px;padding:24px 20px;'
        f'text-align:center;margin-bottom:16px;'
        f'box-shadow:0 4px 20px {color}44">'
        f'<div style="font-size:52px;line-height:1">{icon}</div>'
        f'<div style="font-size:28px;font-weight:800;letter-spacing:1px;color:#fff;'
        f'margin-top:6px">{verdict_label}</div>'
        f'<div style="font-size:13px;color:rgba(255,255,255,.85);margin-top:4px">'
        f'{label} · {risk.get("verdict_strength", "UNKNOWN")}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Gauge + stats row.
    c_gauge, c_stats = st.columns([1.2, 1])
    with c_gauge:
        gauge_deg = int(pct * 1.8)  # 0-100% -> 0-180deg
        st.markdown(
            f'<div class="tp-card" style="text-align:center">'
            f'<div style="width:180px;height:90px;margin:0 auto;position:relative;'
            f'overflow:hidden">'
            f'<div style="width:180px;height:180px;border-radius:50%;'
            f'background:conic-gradient({color} 0deg, {color} {gauge_deg}deg, '
            f'#1a2230 {gauge_deg}deg, #1a2230 180deg);'
            f'position:absolute;top:0;left:0"></div>'
            f'<div style="width:140px;height:140px;border-radius:50%;'
            f'background:#121722;position:absolute;top:20px;left:20px"></div>'
            f'<div style="position:absolute;bottom:8px;width:100%;text-align:center">'
            f'<span style="font-size:32px;font-weight:800;color:{color}">{pct}%</span>'
            f'<div style="font-size:10px;color:var(--muted);letter-spacing:1px">'
            f'EVIDENCE SCORE</div></div>'
            f'</div>'
            f'<div class="tp-muted" style="margin-top:8px">Not a probability — '
            f'weighted evidence strength</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    with c_stats:
        st.markdown(
            f'<div class="tp-card sm">'
            f'<div class="tp-muted" style="margin-bottom:8px">EVIDENCE SIGNALS</div>'
            f'<div class="tp-evstats">'
            f'<div><span class="num" style="color:#e5534b">{supporting}</span>'
            f'<span class="lbl">AI</span></div>'
            f'<div><span class="num" style="color:#2ea043">{opposing}</span>'
            f'<span class="lbl">Real</span></div>'
            f'<div><span class="num" style="color:#5b6b7f">{neutral}</span>'
            f'<span class="lbl">Neutral</span></div>'
            f'</div>'
            f'<div style="margin-top:10px">'
            f'<div class="tp-stat"><span class="tp-key">Confidence</span>'
            f'<b>{risk.get("confidence", "")}</b></div>'
            f'<div class="tp-stat"><span class="tp-key">AI Assessment</span>'
            f'<b style="font-size:11px">{risk.get("ai_assessment", "")}</b></div>'
            f'<div class="tp-stat"><span class="tp-key">Definitive</span>'
            f'<b>{"YES" if risk.get("definitive") else "NO"}</b></div>'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # Evidence balance bar.
    st.markdown(
        f'<div class="tp-card sm">'
        f'<div style="display:flex;justify-content:space-between;margin-bottom:4px">'
        f'<span class="tp-muted">AI-leaning</span>'
        f'<span class="tp-muted">Authenticity</span></div>'
        f'<div class="tp-evbar" style="height:14px">'
        f'<span style="width:{w_sup:.1f}%;background:#e5534b"></span>'
        f'<span style="width:{w_neu:.1f}%;background:#5b6b7f"></span>'
        f'<span style="width:{w_opp:.1f}%;background:#2ea043"></span>'
        f'</div>'
        f'<div style="display:flex;justify-content:space-between;margin-top:4px">'
        f'<span style="color:#e5534b;font-size:12px">■ {supporting} signals</span>'
        f'<span style="color:#5b6b7f;font-size:12px">■ {neutral} neutral</span>'
        f'<span style="color:#2ea043;font-size:12px">■ {opposing} signals</span>'
        f'</div></div>',
        unsafe_allow_html=True,
    )

    # Short verdict summary.
    short_summary = {
        "LOW": "No significant AI indicators found.",
        "MODERATE": "Some AI indicators present — review carefully.",
        "ELEVATED": "AI-leaning indicators detected, but origin is not proven.",
        "HIGH": "A strong result is available; inspect the verdict strength below.",
        "INSUFFICIENT_EVIDENCE": "Not enough evidence to conclude.",
        "INCONCLUSIVE": "Conflicting evidence — inconclusive.",
    }.get(assessment, "")
    st.markdown(
        f'<div class="tp-card sm" style="border-left:4px solid {color}">'
        f'<div style="font-size:15px;font-weight:600">{short_summary}</div>'
        f'<div class="tp-muted" style="margin-top:4px">{risk.get("summary", "")}</div>'
        f'<div class="tp-muted" style="margin-top:6px"><b>Basis:</b> '
        f'{risk.get("proof_basis", "")}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Evidence source chips.
    if risk.get("evidence"):
        st.markdown("#### Evidence Sources")
        ev_cols = st.columns(3)
        for i, e in enumerate(risk["evidence"]):
            if e["impact"] == "CONTEXT":
                continue
            c = "#e5534b" if e["impact"] == "SUPPORTING" else "#2ea043"
            lbl = "AI" if e["impact"] == "SUPPORTING" else "REAL"
            with ev_cols[i % 3]:
                st.markdown(
                    f'<div class="tp-card sm" style="padding:8px 10px;text-align:center">'
                    f'<span class="tp-badge" style="background:{c}">{lbl}</span>'
                    f'<div style="font-size:11px;color:var(--muted);margin-top:4px">'
                    f'{e["source"]}</div>'
                    f'<div style="font-size:13px;font-weight:700">{e["weight"]:.2f}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

    if risk.get("contradictions"):
        st.warning("⚠ Conflicting evidence detected — results are inconclusive.")

    with st.expander("Technical details"):
        for lim in risk.get("limitations", []):
            st.markdown(f"• {lim}")
        st.markdown(
            f"Modules used: {', '.join(risk.get('modules_used', [])) or 'none'}"
        )
        st.markdown(
            f"Modules unavailable: "
            f"{', '.join(risk.get('modules_unavailable', [])) or 'none'}"
        )
        st.markdown(
            "Evidence Score is an internal weighted assessment (0–1), not a "
            "calibrated probability of AI generation."
        )


# --------------------------------------------------------------------------- #
# Overview page (composes the per-module renderers + the verdict banner)
# --------------------------------------------------------------------------- #
def _render_module_tiles(ctx) -> None:
    statuses = ctx.module_statuses()
    # Image Info is always complete once the file is decoded.
    statuses["image_info"] = "COMPLETE"
    tiles = [
        ("IMAGE INFO", "▣", statuses.get("image_info", "COMPLETE")),
        ("METADATA", "❖", statuses.get("metadata", "PENDING")),
        ("C2PA", "⊞", statuses.get("c2pa", "PENDING")),
        ("FORENSICS", "◈", statuses.get("forensics", "PENDING")),
        ("ARTIFACTS", "◉", statuses.get("artifacts", "PENDING")),
    ]
    cols = st.columns(5)
    for col, (name, ico, sts) in zip(cols, tiles):
        color = status_color(sts)
        icon, label = status_icon_label(sts)
        with col:
            st.markdown(
                f'<div class="tp-modtile" style="border-top:3px solid {color}">'
                f'<div class="name">{name}</div>'
                f'<div class="ico" style="color:{color}">{ico}</div>'
                f'<span class="tp-badge" style="background:{color}">{icon} {label}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )


def _ov_technical(info) -> None:
    st.markdown("### Technical Information")
    st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
    tech = [
        ("File size", f'{info["file_size_bytes"]:,} bytes'),
        ("MIME type", info["mime_type"]),
        ("Dimensions", f'{info["width"]} × {info["height"]}'),
        ("Aspect ratio", info["aspect_ratio"]),
        ("Color mode", info["color_mode"]),
        ("Format", info["image_format"]),
    ]
    tcols = st.columns(2)
    for i, (k, v) in enumerate(tech):
        with tcols[i % 2]:
            stat_line(k, v)
    st.markdown('</div>', unsafe_allow_html=True)


def _ai_detection_card(ai: dict | None) -> None:
    st.markdown("### AI Detection")
    st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
    if ai is None:
        st.markdown(
            '<span class="tp-badge" style="background:#5b6b7f">○ AI DETECTOR '
            'NOT CONFIGURED</span>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="tp-muted" style="margin-top:8px">No trained AI '
            'detector is enabled. TruePix does not fabricate a model score.</div>',
            unsafe_allow_html=True,
        )
    else:
        ai_status = ai.get("status")
        if ai_status == "AVAILABLE":
            is_local = str(ai.get("detector", "")).startswith("local")
            badge_color = "#2ea043" if is_local else "#e0a32e"
            badge_label = "LOCAL AI ANALYSIS" if is_local else "EXTERNAL AI ANALYSIS"
            st.markdown(
                f'<span class="tp-badge" style="background:{badge_color}">'
                f'✓ {badge_label}</span>',
                unsafe_allow_html=True,
            )
            st.markdown(
                f'<div class="tp-muted" style="margin-top:8px">Detector: '
                f'<b>{ai.get("detector") or "configured backend"}</b><br>'
                f'Prediction: <b>{ai.get("prediction") or "UNCERTAIN"}</b><br>'
                f'Confidence: <b>{ai.get("confidence") or "Unknown"}</b></div>',
                unsafe_allow_html=True,
            )
            ensemble = ai.get("ensemble") or {}
            if ensemble.get("model_count", 0) > 1:
                st.caption(
                    f"Ensemble agreement: {ensemble.get('ai_votes', 0)} AI / "
                    f"{ensemble.get('authentic_votes', 0)} authentic votes. "
                    "Agreement is not proof."
                )
        elif ai_status == "NOT_CONFIGURED":
            st.markdown(
                '<span class="tp-badge" style="background:#5b6b7f">○ AI '
                'DETECTOR NOT CONFIGURED</span>',
                unsafe_allow_html=True,
            )
            st.markdown(
                '<div class="tp-muted" style="margin-top:8px">No trained AI '
                'detector is enabled. TruePix does not fabricate a model score.</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<span class="tp-badge" style="background:#e5534b">✕ AI '
                'DETECTOR ERROR</span>',
                unsafe_allow_html=True,
            )
            st.markdown(
                '<div class="tp-muted" style="margin-top:8px">The configured '
                'detector could not complete. Its result was excluded from the verdict.</div>',
                unsafe_allow_html=True,
            )
    st.markdown('</div>', unsafe_allow_html=True)
    ai_status = (ai or {}).get("status")
    if ai_status == "AVAILABLE" and not str((ai or {}).get("detector", "")).startswith("local"):
        st.caption("An external detector was explicitly configured; image "
                   "privacy depends on that provider.")
    else:
        st.caption("All enabled processing is on-device; no image leaves your device.")


def render_overview(ctx) -> None:
    info = ctx.image_info
    risk = ctx.risk or {}
    assessment = risk.get("assessment", "INSUFFICIENT_EVIDENCE")
    v_color = VERDICT_BANNER_COLOR.get(assessment, "#5b6b7f")
    v_label = VERDICT_BANNER_LABEL.get(assessment, assessment)
    origin_verdict = risk.get("verdict", "ORIGIN_UNKNOWN")
    v_label = OVERVIEW_VERDICT_LABEL.get(origin_verdict, v_label)
    v_icon = VERDICT_BANNER_ICON.get(assessment, "○")

    # Verdict banner.
    st.markdown(
        f'<div style="background:linear-gradient(135deg, {v_color}22, {v_color}11);'
        f'border:2px solid {v_color};border-radius:16px;padding:20px 24px;'
        f'display:flex;align-items:center;gap:20px;margin-bottom:16px">'
        f'<div style="font-size:48px;color:{v_color}">{v_icon}</div>'
        f'<div>'
        f'<div style="font-size:11px;color:var(--muted);letter-spacing:2px;'
        f'text-transform:uppercase">Verdict</div>'
        f'<div style="font-size:26px;font-weight:800;color:{v_color}">{v_label}</div>'
        f'<div style="font-size:12px;color:var(--muted)">'
        f'Evidence score: {int((risk.get("evidence_score") or 0) * 100)}% · '
        f'Confidence: {risk.get("confidence", "—")}</div>'
        f'</div></div>',
        unsafe_allow_html=True,
    )

    # Image + facts + hash row.
    c1, c2, c3 = st.columns([1.1, 1.5, 1])
    with c1:
        st.markdown('<div class="tp-card flush">', unsafe_allow_html=True)
        st.image(ctx.image_path, width=320)
        st.markdown('</div>', unsafe_allow_html=True)
    with c2:
        st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
        stat_line("Filename", info["filename"])
        stat_line("Resolution", f'{info["width"]} × {info["height"]}')
        stat_line("Format", info["image_format"])
        stat_line("File size", f'{info["file_size_bytes"]:,} bytes')
        st.markdown('</div>', unsafe_allow_html=True)
    with c3:
        st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
        st.markdown(
            '<div class="tp-muted" style="margin-bottom:4px">SHA-256</div>',
            unsafe_allow_html=True,
        )
        st.code(info["sha256"], language="text")
        copy_button(info["sha256"], "Copy hash")
        st.markdown('</div>', unsafe_allow_html=True)

    context_flags = risk.get("context_flags") or []
    if context_flags:
        readable = {
            "possible_screen_capture": "possible screen-capture/display context",
            "stylized_or_illustrated": "stylized or illustrated content",
            "possible_resampling_or_smoothing":
                "possible resizing/smoothing history",
        }
        st.info(
            "Context signals (not AI proof): " +
            ", ".join(readable.get(f, f.replace("_", " "))
                      for f in context_flags) +
            ". A screenshot can contain either AI-generated or non-AI artwork."
        )

    # Module status tiles.
    st.markdown("### Module Status")
    _render_module_tiles(ctx)

    # Overall assessment.
    st.markdown("### Overall Assessment")
    render_risk(ctx.risk)

    # Forensic evidence grid.
    st.markdown("### Forensic Evidence Grid")
    g1, g2 = st.columns(2)
    with g1:
        render_c2pa(ctx.c2pa)
    with g2:
        render_metadata(ctx.metadata)
    g3, g4 = st.columns(2)
    with g3:
        render_forensics(ctx.forensics, ctx.jpeg_ghost, ctx.cfa)
    with g4:
        render_artifacts(ctx.artifacts)
    g5, g6 = st.columns(2)
    with g5:
        _ov_technical(info)
    with g6:
        _ai_detection_card(ctx.ai_detector)

    st.caption("Detailed per-module forensics are available from the sidebar navigation.")


# --------------------------------------------------------------------------- #
# Report export (delegates to src/reports)
# --------------------------------------------------------------------------- #
def build_report(ctx) -> dict:
    """Backwards-compatible wrapper around ``json_report.build_report``."""
    from src.reports.json_report import build_report as _build
    return _build(ctx)


def _ela_preview_b64(ctx) -> str | None:
    ela = (ctx.forensics or {}).get("ela") or {}
    return ela.get("preview_b64")


def page_export(ctx) -> None:
    st.markdown("### Export Report")
    st.markdown(
        "Download a forensic report. The report contains only discovered "
        "evidence — no fabricated probabilities or provenance.",
        unsafe_allow_html=True,
    )
    include_previews = st.session_state.get("opt_include_previews", True)

    rep = build_report(ctx)
    st.download_button(
        "⬇ Download JSON Report",
        json.dumps(rep, indent=2),
        file_name=report_filename(ctx.image_info["sha256"]),
        mime="application/json",
        key="export_json",
    )
    try:
        from src.reports.pdf_report import build_pdf
        pdf_bytes = build_pdf(
            rep,
            ela_preview_b64=_ela_preview_b64(ctx) if include_previews else None,
        )
        st.download_button(
            "⬇ Download PDF Report",
            pdf_bytes,
            file_name=f"truepix_report_{ctx.image_info['sha256'][:12]}.pdf",
            mime="application/pdf",
            key="export_pdf",
        )
    except Exception as exc:  # noqa: BLE001 — PDF is optional; JSON always works
        st.warning("PDF export is unavailable this session "
                   f"({exc}). The JSON report remains fully functional.")
    st.caption("Both formats carry the full limitations list and disclaimer. "
               "The report describes the evidence in the uploaded file; it "
               "never asserts that an image is authentic.")

    with st.expander("Preview report"):
        st.json(rep)


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
def page_settings(errors: list[str] | None = None) -> None:
    st.markdown("### Settings")

    st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
    stat_line("Theme", "Dark Forensic (default)")
    stat_line("Processing", "Local CPU")
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("**Report options**")
    st.toggle("Include ELA preview image in PDF export",
              key="opt_include_previews",
              value=st.session_state.get("opt_include_previews", True),
              help="The preview is a small recompression-residual PNG embedded "
                   "in the PDF. Turn off for minimal reports.")
    st.toggle("Include case history in JSON export",
              key="opt_include_history",
              help="Adds prior cases from this session to the exported JSON. "
                   "History never touches disk.")

    st.markdown("**History**")
    st.slider("Cases kept this session", 5, 50, 20, key="opt_history_size",
              help="Session-only. Closing the browser tab clears it.")

    st.markdown("**Privacy**")
    st.markdown(
        "TruePix runs all forensic modules on your device. No image data is "
        "ever uploaded to a remote service; all analysis is performed locally.",
        unsafe_allow_html=True,
    )

    _settings_env_status()

    if errors:
        st.markdown("**Session errors**")
        for e in errors:
            st.markdown(f"• {e}")
    else:
        st.markdown("**Session errors**: none")

    st.caption(DISCLAIMER)


def _settings_env_status() -> None:
    """Show detected detector configuration (never secrets)."""
    import os
    from src.ui.styles import VERSION

    st.markdown("**Detector configuration**")
    local_model = os.environ.get("TRUEPIX_LOCAL_MODEL_PATH")
    local_models = os.environ.get("TRUEPIX_LOCAL_MODEL_PATHS")
    external_url = os.environ.get("TRUEPIX_AI_API_URL")
    clip_enabled = os.environ.get("TRUEPIX_ENABLE_CLIP") == "1"

    rows = [
        ("App version", VERSION),
        ("Local model path",
         local_model or local_models or "not configured"),
        ("External API detector",
         "configured (opt-in network)" if external_url
         else "not configured (local-only)"),
        ("CLIP zero-shot probe",
         "enabled" if clip_enabled else "disabled (default)"),
    ]
    st.markdown('<div class="tp-card sm">', unsafe_allow_html=True)
    for k, v in rows:
        stat_line(k, v)
    st.markdown('</div>', unsafe_allow_html=True)
    st.caption("Paths are shown as configured via environment variables or "
               ".env; no secrets are displayed.")


# --------------------------------------------------------------------------- #
# Batch analysis (Phase 2)
# --------------------------------------------------------------------------- #
def page_batch() -> None:
    """Batch mode: analyze many files in one pass, export CSV."""
    import os
    import tempfile

    import pandas as pd

    from src.batch import run_batch, to_csv
    from src.utils import sanitize_filename

    st.markdown("### Batch Analysis")
    st.markdown(
        "Queue multiple images for sequential on-device analysis. Each file is "
        "assessed independently; batch mode never merges verdicts.",
        unsafe_allow_html=True,
    )

    uploads = st.file_uploader(
        "Upload Images",
        type=["jpg", "jpeg", "png", "bmp", "gif", "tiff", "webp"],
        accept_multiple_files=True,
        key="batch_uploader",
        help="Max 25 MB each. Processed locally, one at a time.",
    )
    if not uploads:
        st.info("No files queued. Upload images above to begin.")
        return

    if not st.button(f"▶ Run batch ({len(uploads)} files)",
                     key="batch_run", type="primary"):
        st.markdown("**Queued files**")
        for u in uploads:
            st.markdown(f"• {u.name} ({u.size:,} bytes)")
        return

    rows = []
    progress = st.progress(0.0, text="Starting batch…")
    status = st.empty()
    tmp_dir = tempfile.mkdtemp(prefix="truepix_batch_")
    paths: list[tuple[str, str]] = []
    try:
        for u in uploads:
            p = os.path.join(tmp_dir, sanitize_filename(u.name))
            with open(p, "wb") as fh:
                fh.write(u.getbuffer())
            paths.append((p, u.name))

        def _cb(i, total, name):
            progress.progress(i / max(total, 1),
                              text=f"Analyzing {i + 1}/{total}: {name}")

        rows = run_batch(paths, progress_cb=_cb)
        progress.progress(1.0, text="Batch complete.")
    finally:
        for p, _ in paths:
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(tmp_dir)
        except OSError:
            pass

    ok_rows = [r for r in rows if r.ok]
    err_rows = [r for r in rows if not r.ok]
    status.markdown(
        f"**{len(ok_rows)} analyzed · {len(err_rows)} rejected**"
    )

    # Summary table (no per-file expanders — the CSV carries full detail).
    data = [{
        "File": r.filename,
        "Verdict": r.verdict or ("REJECTED" if not r.ok else "—"),
        "Assessment": r.assessment or r.error or "",
        "Score": "—" if r.evidence_score is None else f"{r.evidence_score:.2f}",
        "Confidence": r.confidence or "—",
        "SHA-256": r.sha256[:12] if r.sha256 else "—",
    } for r in rows]
    st.dataframe(pd.DataFrame(data), use_container_width=True, hide_index=True)

    csv_bytes = to_csv(rows).encode("utf-8")
    st.download_button(
        "⬇ Download Batch CSV",
        csv_bytes,
        file_name="truepix_batch.csv",
        mime="text/csv",
        key="batch_csv",
    )
    st.caption("The CSV contains one row per uploaded file with its verdict, "
               "assessment band, and evidence score. Scores are weighted "
               "evidence strength — never probabilities.")


# --------------------------------------------------------------------------- #
# Compare (Phase 2) — side-by-side metrics, no combined verdict
# --------------------------------------------------------------------------- #
_COMPARE_METRICS = [
    ("ELA mean residual", "ela", "mean", "lower = flatter recompression error"),
    ("ELA max residual", "ela", "max", None),
    ("Noise global level", "noise", "global_level", None),
    ("Noise regional CV", "noise", "regional_consistency_cv",
     "higher = more inconsistent noise regions"),
    ("Edge density", "edges", "edge_density", None),
    ("High-frequency ratio", "frequency", "high_frequency_ratio", None),
    ("DCT AC energy", "dct", "ac_energy", None),
    ("Inter-block residual |corr|", "noise_correlation",
     "inter_block_abs_corr", "higher can indicate resampling/smoothing"),
    ("Screen-capture score", "screen_capture", "screen_capture_score", None),
    ("Stylized-context score", "content_style", "stylized_score", None),
]


def _metric_value(forensics: dict | None, section: str, key: str):
    if not forensics:
        return None
    sec = forensics.get(section) or {}
    if not sec.get("available"):
        return None
    return sec.get(key)


def page_compare() -> None:
    """Side-by-side metric comparison of two images. Human aid only."""
    import os
    import tempfile

    import pandas as pd

    from src.utils import sanitize_filename

    st.markdown("### Compare Images")
    st.warning(
        "Comparison is a visual aid for a human reviewer. It produces **no "
        "verdict** — the evidence engine assesses one image at a time.",
        icon="⚠",
    )

    c1, c2 = st.columns(2)
    with c1:
        up_a = st.file_uploader("Image A", key="cmp_uploader_a",
                                type=["jpg", "jpeg", "png", "bmp", "gif",
                                      "tiff", "webp"])
    with c2:
        up_b = st.file_uploader("Image B", key="cmp_uploader_b",
                                type=["jpg", "jpeg", "png", "bmp", "gif",
                                      "tiff", "webp"])

    if not (up_a and up_b):
        st.info("Upload two images to compare their forensic metrics.")
        return

    tmp_dir = tempfile.mkdtemp(prefix="truepix_cmp_")
    pa = os.path.join(tmp_dir, "a_" + sanitize_filename(up_a.name))
    pb = os.path.join(tmp_dir, "b_" + sanitize_filename(up_b.name))
    try:
        for u, p in ((up_a, pa), (up_b, pb)):
            with open(p, "wb") as fh:
                fh.write(u.getbuffer())

        from src.analysis import run_all
        from src.image_info import extract_image_info

        ctxs = []
        for label, path, up in (("A", pa, up_a), ("B", pb, up_b)):
            info = extract_image_info(path, up.name)
            ctxs.append(run_all(path, info))

        # Thumbnails.
        t1, t2 = st.columns(2)
        for col, ctx, up in ((t1, ctxs[0], up_a), (t2, ctxs[1], up_b)):
            with col:
                st.image(ctx.image_path,
                         caption=f"{up.name} · {ctx.image_info['width']}×"
                                 f"{ctx.image_info['height']} · "
                                 f"{ctx.image_info['image_format']}",
                         use_container_width=True)

        # Metric table.
        rows = []
        for title, section, key, note in _COMPARE_METRICS:
            va = _metric_value(ctxs[0].forensics, section, key)
            vb = _metric_value(ctxs[1].forensics, section, key)
            if isinstance(va, float):
                va_s = f"{va:.4f}"
            else:
                va_s = "—" if va is None else str(va)
            if isinstance(vb, float):
                vb_s = f"{vb:.4f}"
            else:
                vb_s = "—" if vb is None else str(vb)
            rows.append({
                "Metric": title + (f" ({note})" if note else ""),
                "Image A": va_s,
                "Image B": vb_s,
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True,
                     hide_index=True)

        # Per-image verdicts remain independent and clearly separated.
        v1, v2 = st.columns(2)
        for col, ctx, name in ((v1, ctxs[0], "A"), (v2, ctxs[1], "B")):
            risk = ctx.risk or {}
            with col:
                verdict = risk.get("verdict") or "ORIGIN_UNKNOWN"
                band = risk.get("assessment") or "INSUFFICIENT_EVIDENCE"
                color = VERDICT_BANNER_COLOR.get(band, "#5b6b7f")
                st.markdown(
                    f'<div class="tp-card sm" style="border-left:4px solid {color}">'
                    f'<div class="tp-sublabel">Image {name} verdict '
                    f'(independent)</div>'
                    f'<div style="font-weight:700;font-size:14px">'
                    f'{ORIGIN_VERDICT_LABEL.get(verdict, verdict)}</div>'
                    f'<div class="tp-muted">Band: {band} · Score: '
                    f'{int((risk.get("evidence_score") or 0) * 100)}%</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        st.caption("Two verdicts side by side are still two separate "
                   "assessments. TruePix never computes a combined "
                   "'which is more real' conclusion.")
    finally:
        try:
            os.remove(pa)
            os.remove(pb)
            os.rmdir(tmp_dir)
        except OSError:
            pass
