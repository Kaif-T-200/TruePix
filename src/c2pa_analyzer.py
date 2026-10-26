"""C2PA / Content Credentials analysis for TruePix (Phase 4).

Lightweight, dependency-free scanner. It inspects an image for embedded C2PA
provenance structures (manifest store / JUMBF / XMP c2pa claims) using byte
pattern matching. It does NOT perform cryptographic verification.

Design rules:
  * Detection != verification. A detected manifest is reported as UNVERIFIED.
  * The scanner never produces VERIFIED from real bytes; that state exists only
    for clearly-marked synthetic fixtures used by tests.
  * Malformed manifests / unsupported formats degrade gracefully (no crash).
  * Embedded content is treated as untrusted and never executed.
"""

from __future__ import annotations

import os

from PIL import Image

# States
VERIFIED = "VERIFIED"
PRESENT_UNVERIFIED = "PRESENT_UNVERIFIED"
NOT_FOUND = "NOT_FOUND"
UNSUPPORTED = "UNSUPPORTED"
ERROR = "ERROR"

SUPPORTED_EXT = {".jpg", ".jpeg", ".png", ".webp"}

# Byte-level markers that indicate a C2PA manifest store / claim may be present.
_MARKERS = (
    b"c2pa",
    b"http://c2pa.org",
    b"xmpClaim",
    b"jumb",          # JUMBF box type
    b"C2PA",
)

# Heuristic generator hints found inside manifest bytes (unverified).
# "trainedalgorithmicmedia" is Google's SynthID C2PA disclosure marker that
# accompanies watermarked AI-generated images. "generative ai" is a generic but
# explicit declaration of AI-generation tooling in a provenance record.
_AI_HINTS = [
    "midjourney", "stable diffusion", "dall-e", "dall·e", "adobe firefly",
    "leonardo", "comfyui", "novelai", "ideogram", "generative ai",
    "trainedalgorithmicmedia", "ai-generated",
]
# Strong SynthID / generative-AI provenance markers (highest confidence AI signal
# that can be read from a manifest even when unverified).
_SYNTHID_MARKERS = ("trainedalgorithmicmedia", "generative ai")
_EDIT_HINTS = ["photoshop", "lightroom", "gimp", "capture one", "affinity"]


def _read_bytes(path: str, limit: int = 30_000_000) -> bytes:
    """Read file bytes (capped) for scanning. Returns up to `limit` bytes."""
    with open(path, "rb") as fh:
        return fh.read(limit)


def _scan(data: bytes) -> tuple[bool, list[str]]:
    """Return (manifest_present, human_readable_hints)."""
    present = any(m in data for m in _MARKERS)
    low = data.lower()
    hints: list[str] = []
    for name in _AI_HINTS + _EDIT_HINTS:
        if name.encode() in low:
            hints.append(name)
    return present, hints


def _provenance_findings(verified: bool, hints: list[str],
                         provenance: dict | None = None) -> tuple[list[dict], dict]:
    """Build AI/editing provenance findings + a display dict from verified context.

    Only used when `verified` is explicitly True (test fixtures). For real
    scanner output verified is always False and this is not invoked for AI claims.
    No field in `provenance` is invented here -- only values the caller supplies
    are carried through; otherwise the display dict stays empty.
    """
    out: list[dict] = []
    ai = [h for h in hints if h in _AI_HINTS]
    edit = [h for h in hints if h in _EDIT_HINTS]
    if ai:
        out.append({
            "id": "F-000",  # placeholder; caller renumbers
            "category": "C2PA",
            "title": "AI-generation provenance indicated",
            "severity": "High",
            "confidence": "High",
            "evidence": f"Verified content credentials reference generative-AI tooling: {', '.join(ai)}.",
            "interpretation": (
                "Verified provenance contains an explicit indication of an AI-generation "
                "workflow. This is strong provenance evidence, not a generic visual prediction."
            ),
        })
    elif edit:
        out.append({
            "id": "F-000",
            "category": "C2PA",
            "title": "Verified provenance indicates editing activity",
            "severity": "Low",
            "confidence": "High",
            "evidence": f"Verified content credentials reference editing software: {', '.join(edit)}.",
            "interpretation": (
                "Verified provenance indicates editing activity. This alone does not establish "
                "that generative AI was used."
            ),
        })
    prov: dict = {}
    if isinstance(provenance, dict):
        for k, v in provenance.items():
            if v is not None and str(v).strip():
                prov[str(k)] = str(v)
    return out, prov


def _build(status: str, *, manifest_present: bool = False, verified: bool = False,
            hints: list[str] | None = None, error: str = "", provenance: dict | None = None) -> dict:
    hints = hints or []
    findings: list[dict] = []
    counter = {"n": 0}

    def add(title, severity, confidence, evidence, interpretation):
        counter["n"] += 1
        findings.append({
            "id": f"F-{counter['n']:03d}",
            "category": "C2PA",
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "interpretation": interpretation,
        })

    if status == NOT_FOUND:
        add(
            "No C2PA credentials detected",
            "Informational", "High",
            "No supported C2PA / content-credentials structure was found in the image.",
            "The absence of content credentials does not establish whether an image is authentic "
            "or AI-generated. Credentials may be absent because the image was created without them, "
            "stripped, transformed, exported, or processed by a platform that does not preserve them.",
        )
    elif status == PRESENT_UNVERIFIED:
        add(
            "C2PA manifest detected but cryptographic verification unavailable",
            "Medium", "Medium",
            "Embedded C2PA / content-credentials structures appear to be present in the file.",
            "TruePix cannot perform cryptographic verification with its lightweight scanner. "
            "Detection of a manifest is NOT verification; treat this as unconfirmed provenance.",
        )
        # Even though the manifest is unverified, explicit AI-generation hints inside it
        # (e.g. "trainedalgorithmicmedia" = SynthID, "generative ai") are treated as a
        # medium-confidence AI signal by the risk engine. This is provenance metadata
        # *declaring* AI use, not a visual guess.
        ai_hints = [h for h in hints if h in _AI_HINTS]
        synthid = [h for h in ai_hints if h in _SYNTHID_MARKERS]
        if synthid:
            add(
                "Unverified C2PA declares AI generation (SynthID marker)",
                "High", "Medium",
                f"Unverified content credentials contain generative-AI marker(s): "
                f"{', '.join(synthid)}. 'trainedalgorithmicmedia' is Google SynthID's "
                "C2PA disclosure tag for AI-generated images.",
                "An embedded (but not cryptographically verified) C2PA manifest explicitly "
                "declares AI generation tooling. Because the manifest is unverified, this "
                "is an AI-*leaning signal*, not proof, but it should raise review priority.",
            )
        elif ai_hints:
            add(
                "Unverified C2PA declares AI generation tooling",
                "Medium", "Medium",
                f"Unverified content credentials reference generative-AI tooling: "
                f"{', '.join(ai_hints)}.",
                "An embedded (but not cryptographically verified) C2PA manifest references "
                "AI-generation tooling. Treated as an AI-leaning signal pending verification.",
            )
    elif status == VERIFIED:
        add(
            "C2PA credentials verified",
            "High", "High",
            "Content credentials were cryptographically verified (synthetic fixture).",
            "Verified provenance establishes a signed chain of custody for this asset.",
        )
        prov_findings, prov_dict = _provenance_findings(verified, hints, provenance)
        for f in prov_findings:
            counter["n"] += 1
            f["id"] = f"F-{counter['n']:03d}"
            findings.append(f)
    elif status == UNSUPPORTED:
        add(
            "C2PA analysis unsupported for this format",
            "Informational", "High",
            "The image format is not supported by the lightweight C2PA scanner.",
            "No conclusion about content credentials can be drawn from this format.",
        )
    elif status == ERROR:
        add(
            "C2PA analysis error",
            "Informational", "Low",
            error or "An error occurred while inspecting the file for C2PA data.",
            "C2PA analysis could not be completed; this does not indicate authenticity or AI generation.",
        )

    summary = {
        NOT_FOUND: "No verifiable content credentials were found.",
        PRESENT_UNVERIFIED: "A C2PA manifest appears present but is UNVERIFIED.",
        VERIFIED: "C2PA credentials verified (synthetic fixture).",
        UNSUPPORTED: "C2PA analysis is unsupported for this image format.",
        ERROR: "C2PA analysis could not be completed.",
    }[status]

    return {
        "status": status,
        "available": status in (PRESENT_UNVERIFIED, VERIFIED),
        "verified": verified,
        "manifest_present": manifest_present,
        "hints": hints,
        "provenance": prov_dict if status == VERIFIED else {},
        "findings": findings,
        "summary": summary,
    }


def analyze(path: str) -> dict:
    """Analyze an image file for C2PA / content credentials.

    Returns the structured dict. Never raises on malformed input.
    Real-world results are either NOT_FOUND, PRESENT_UNVERIFIED, UNSUPPORTED, or ERROR.
    """
    ext = os.path.splitext(path)[1].lower()
    if ext not in SUPPORTED_EXT:
        return _build(UNSUPPORTED)

    try:
        Image.open(path).verify()
    except Exception:  # noqa: BLE001
        return _build(ERROR, error="File is not a decodable image.")

    try:
        data = _read_bytes(path)
    except Exception as exc:  # noqa: BLE001
        return _build(ERROR, error=str(exc))

    try:
        present, hints = _scan(data)
    except Exception as exc:  # noqa: BLE001
        return _build(ERROR, error=str(exc))

    if not present:
        return _build(NOT_FOUND)
    return _build(PRESENT_UNVERIFIED, manifest_present=True, verified=False, hints=hints)
