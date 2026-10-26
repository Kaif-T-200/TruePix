"""UI styling and shared presentation constants for TruePix.

Extracted from ``app.py`` in Phase 1. No behavior change: the dark
forensic dashboard CSS is byte-for-byte the same.
"""

from __future__ import annotations

# Branding / config
TITLE = "TRUEPIX"
SUBTITLE = "AI Image Authenticity & Forensic Analysis"
TAGLINE = "See the truth behind every pixel."
VERSION = "1.0.0"

DISCLAIMER = (
    "TruePix can provide definitive AI-origin evidence only when cryptographically "
    "verified provenance explicitly declares AI generation. Pixel analysis and model "
    "scores are probabilistic indicators, not proof; screenshots, edits, metadata "
    "removal, and unseen generators can defeat detection."
)

# Status color / icon / label table. Status text is conveyed both by
# color and by an icon + label, never by color alone (accessibility).
STATUS_STYLE = {
    "COMPLETE": ("#2ea043", "✓", "COMPLETE"),
    "FINDINGS": ("#e0a32e", "⚠", "FINDINGS"),
    "NO DATA": ("#5b6b7f", "○", "NO DATA"),
    "PENDING": ("#3a3f47", "○", "PENDING"),
    "UNAVAILABLE": ("#444c56", "—", "UNAVAILABLE"),
    "NOT CONFIGURED": ("#5b6b7f", "○", "NOT CONFIGURED"),
    "CONFIGURED": ("#19c2a0", "○", "CONFIGURED"),
    "ANALYZING": ("#19c2a0", "⟳", "ANALYZING"),
    "ERROR": ("#e5534b", "✕", "ERROR"),
}

# Per-finding severity color. Same accessibility rule: text + icon.
SEVERITY_STYLE = {
    "Critical": "#e5534b",
    "High": "#e5534b",
    "Medium": "#e0a32e",
    "Low": "#3a7ca5",
    "Informational": "#5b6b7f",
}

# Verdict color (used by the big banner and gauge). Maps verdict_strength
# to the accent color for the gauge and the verdict banner.
VERDICT_BANNER_COLOR = {
    "LOW": "#2ea043",
    "MODERATE": "#3a7ca5",
    "ELEVATED": "#e0a32e",
    "HIGH": "#e5534b",
    "INSUFFICIENT_EVIDENCE": "#5b6b7f",
    "INCONCLUSIVE": "#8b98a9",
}
VERDICT_BANNER_LABEL = {
    "LOW": "LOW CONCERN",
    "MODERATE": "MODERATE CONCERN",
    "ELEVATED": "ELEVATED CONCERN",
    "HIGH": "HIGH CONCERN",
    "INSUFFICIENT_EVIDENCE": "INSUFFICIENT EVIDENCE",
    "INCONCLUSIVE": "INCONCLUSIVE",
}
VERDICT_BANNER_ICON = {
    "LOW": "✓",
    "MODERATE": "◐",
    "ELEVATED": "⚠",
    "HIGH": "✕",
    "INSUFFICIENT_EVIDENCE": "○",
    "INCONCLUSIVE": "?",
}
ORIGIN_VERDICT_LABEL = {
    "PROVEN_AI_GENERATION": "PROVEN AI GENERATION",
    "HIGH_CONFIDENCE_AI_LIKELY": "HIGH-CONFIDENCE AI LIKELY",
    "POSSIBLE_AI_GENERATION": "POSSIBLE AI GENERATION",
    "ORIGIN_UNKNOWN": "ORIGIN UNKNOWN",
    "INCONCLUSIVE": "INCONCLUSIVE",
}
OVERVIEW_VERDICT_LABEL = {
    "PROVEN_AI_GENERATION": "PROVEN AI GENERATION",
    "HIGH_CONFIDENCE_AI_LIKELY": "HIGH-CONFIDENCE AI LIKELY",
    "POSSIBLE_AI_GENERATION": "POSSIBLE AI GENERATION",
    "ORIGIN_UNKNOWN": "ORIGIN UNKNOWN",
    "INCONCLUSIVE": "INCONCLUSIVE",
}
DARK_CSS = """
<style>
:root { --bg:#0a0d12; --panel:#121722; --panel-2:#0e131c; --panel-3:#161d2b;
        --border:#222c3a; --border-2:#2b3850; --accent:#19c2a0; --accent-2:#0f8f78;
        --text:#e6edf3; --muted:#8b98a9; --good:#2ea043; --warn:#e0a32e;
        --bad:#e5534b; --neutral:#5b6b7f; }
* { font-family: "Segoe UI", system-ui, -apple-system, sans-serif; }
html, body, .stApp { background: var(--bg); color: var(--text); }
h1,h2,h3 { color: var(--text); font-weight:700; letter-spacing:.3px; margin:10px 0 6px; }
.stApp h2, .stApp h3, .stApp .stMarkdown h2, .stApp .stMarkdown h3 { font-size:16px; }
.stApp h1 { font-size:22px; }
.stApp header { background: var(--bg); }

/* Sidebar: fixed, compact, professional */
[data-testid="stSidebar"] { border-right:1px solid var(--border);
                            background: var(--panel-2); }
[data-testid="stSidebar"] > div:first-child { width: 232px; }
[data-testid="stSidebar"] { width: 232px; }
[data-testid="stSidebar"] .block-container { padding: 0 14px 24px; }
[data-testid="stSidebar"] section[data-testid="stVerticalBlock"] { gap: 2px; }

/* Main workspace: balanced, never ultra-wide */
[data-testid="stAppViewContainer"] .main .block-container {
    max-width: 1200px; margin: 0 auto; padding: 1rem 1.5rem 3rem; }

.tp-brand { font-size:24px; font-weight:800; letter-spacing:2px; color:var(--text); }
.tp-brand .dot { color: var(--accent); }
.tp-sub { color: var(--muted); font-size:12px; margin-top:-4px; }
.tp-sep { height:1px; background:var(--border); margin:12px 0; }
.tp-section-label { color:var(--accent); font-size:10.5px; letter-spacing:1.6px;
                    text-transform:uppercase; font-weight:700; margin:10px 0 4px; }
.tp-sublabel { color: var(--muted); font-size:11px; letter-spacing:.8px;
               text-transform:uppercase; font-weight:700; margin:8px 0 3px; }
.tp-card { background:var(--panel); border:1px solid var(--border); border-radius:10px;
           padding:14px 16px; margin-bottom:12px; }
.tp-card.sm { padding:10px 12px; }
.tp-card.flush { padding:0; overflow:hidden; }
.tp-evstats { display:flex; gap:8px; margin-top:6px; }
.tp-evstats > div { flex:1; background:var(--panel-2); border:1px solid var(--border);
                    border-radius:8px; padding:8px 4px; text-align:center; }
.tp-evstats .num { display:block; font-size:20px; font-weight:700; line-height:1; }
.tp-evstats .lbl { display:block; font-size:10px; color: var(--muted); margin-top:3px;
                   text-transform:uppercase; letter-spacing:.4px; }
.tp-muted { color: var(--muted); font-size:12.5px; line-height:1.4; }
.tp-badge { display:inline-block; padding:3px 9px; border-radius:6px; font-weight:700;
            font-size:10.5px; letter-spacing:.5px; color:#fff; white-space:nowrap; }
.tp-badge.outline { background:transparent; border:1px solid var(--border-2); color:var(--muted); }
.tp-stat { font-size:12.5px; display:flex; justify-content:space-between; gap:10px;
           padding:5px 0; border-bottom:1px dashed var(--border); }
.tp-stat:last-child { border-bottom:none; }
.tp-stat b { color:var(--text); font-weight:600; text-align:right; }
.tp-key { color: var(--muted); white-space:nowrap; }
.tp-finding { background:var(--panel-2); border:1px solid var(--border);
              border-left:3px solid var(--accent); border-radius:8px;
              padding:10px 12px; margin-bottom:8px; }
.tp-hero { text-align:center; padding:40px 20px 10px; }
.tp-hero h1 { font-size:42px; letter-spacing:4px; }
.tp-li { color: var(--muted); font-size:14px; padding:5px 0; }
.tp-footer { color: var(--muted); font-size:11px; text-align:center; margin-top:20px; }
hr.tp { border:none; border-top:1px solid var(--border); margin:14px 0; }

/* Top header bar */
.tp-header { display:flex; align-items:flex-end; justify-content:space-between;
             gap:16px; padding:6px 2px 14px; border-bottom:1px solid var(--border);
             margin-bottom:16px; flex-wrap:wrap; }
.tp-header .title { font-size:22px; font-weight:800; letter-spacing:.5px; }
.tp-header .desc { color: var(--muted); font-size:12.5px; margin-top:2px; }
.tp-header .controls { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }

/* Module status tile */
.tp-modtile { background:var(--panel); border:1px solid var(--border); border-radius:10px;
              padding:12px 10px; text-align:center; }
.tp-modtile .name { color: var(--muted); font-size:10.5px; letter-spacing:.6px;
                    text-transform:uppercase; font-weight:700; }
.tp-modtile .ico { font-size:18px; margin:6px 0 4px; }

/* Evidence bar */
.tp-evbar { display:flex; height:10px; border-radius:5px; overflow:hidden; margin:8px 0; }
.tp-evbar > span { display:block; height:100%; }

/* Nav radio cleanup */
[data-testid="stSidebar"] .stRadio > label { font-size:12px; }
div[data-testid="stRadio"] > div { gap:2px; }
</style>
"""
