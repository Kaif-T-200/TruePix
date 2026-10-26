"""Metadata forensics for TruePix.

Phase 3: safe EXIF / PNG / textual metadata extraction, structured findings,
and AI-generation / editing-software indicators. No ML, no network, CPU-only.

Design rules honoured:
  * Missing metadata is NOT treated as an AI signal.
  * Editing software is a distinct, weaker signal than AI-generation software.
  * GPS presence is reported without leaking precise coordinates in the summary.
  * All metadata is treated as untrusted and never executed.
"""

from __future__ import annotations

from PIL import Image, ExifTags

SEVERITY = ["Informational", "Low", "Medium", "High", "Critical"]

# --- Configurable indicator lists (easy to extend, lowercased for matching) ---
AI_GENERATION_SOFTWARE = [
    "midjourney", "dall-e", "dalle", "dall·e", "stable diffusion", "stability ai",
    "leonardo.ai", "leonardo", "adobe firefly", "firefly", "bing image creator",
    "imagen", "novelai", "comfyui", "automatic1111", "sd webui", "generative ai",
    "ai generated", "mage space", "playground ai", "ideogram", "seedream",
]

EDITING_SOFTWARE = [
    "photoshop", "adobe photoshop", "lightroom", "gimp", "paint.net", "capture one",
    "affinity", "canva", "corel", "inkscape", "pixelmator", "snapseed", "figma",
    "acdsee", "darktable", "luminar", "sketch",
]

# EXIF tag ids we care about, with human-readable labels.
_TAG_IDS = {
    0x010F: "Camera Make",
    0x0110: "Camera Model",
    0x0112: "Orientation",
    0x011A: "X Resolution",
    0x011B: "Y Resolution",
    0x0128: "Resolution Unit",
    0x010E: "Image Description",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x8769: "Exif SubIFD",
    0x8825: "GPS Info",
    0x9003: "DateTime Original",
    0x9004: "DateTime Digitized",
    0xA002: "Exif Image Width",
    0xA003: "Exif Image Height",
    0xA401: "Color Space",
    0xA434: "Lens",
}
_GPS_ID = 0x8825
_EXIF_IFD_ID = 0x8769


def _human_tag(tag_id: int) -> str:
    return _TAG_IDS.get(tag_id, ExifTags.TAGS.get(tag_id, f"EXIF:{tag_id}"))


def _clean(value) -> str:
    """Render an EXIF value as a safe, printable string."""
    try:
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace").strip("\x00")
        if isinstance(value, (list, tuple)):
            return ", ".join(str(v) for v in value)
        return str(value)
    except Exception:  # noqa: BLE001
        return "<unreadable>"


def _gps_decimal(dms, ref) -> float | None:
    """Convert EXIF GPS (degrees/minutes/seconds rationals) to decimal degrees.

    `dms` may be a 6-element sequence of (deg_num, deg_den, min_num, min_den,
    sec_num, sec_den) or a 3-element sequence of (deg, min, sec) floats.
    """
    try:
        if dms and len(dms) == 6:
            d = float(dms[0]) / float(dms[1])
            m = float(dms[2]) / float(dms[3])
            s = float(dms[4]) / float(dms[5])
        else:
            d, m, s = (float(x) for x in dms)
        dec = d + m / 60.0 + s / 3600.0
        if ref in ("S", "W"):
            dec = -dec
        return dec
    except Exception:  # noqa: BLE001
        return None


def _extract_exif(img: Image.Image) -> tuple[dict, dict]:
    """Return (visible_fields, technical_detail) from EXIF, GPS-safe."""
    fields: dict[str, str] = {}
    technical: dict[str, object] = {}
    try:
        exif = img.getexif()
    except Exception:  # noqa: BLE001
        return fields, technical

    gps_present = False
    for tag_id, value in exif.items():
        if tag_id in (_GPS_ID, _EXIF_IFD_ID):
            continue
        fields[_human_tag(tag_id)] = _clean(value)

    # Exif SubIFD
    try:
        for tag_id, value in exif.get_ifd(_EXIF_IFD_ID).items():
            fields[_human_tag(tag_id)] = _clean(value)
    except Exception:  # noqa: BLE001
        pass

    # GPS sub-IFD (coordinates kept only in technical detail)
    try:
        gps = exif.get_ifd(_GPS_ID)
        if gps:
            gps_present = True
            lat = _gps_decimal(gps.get(2), gps.get(1))
            lon = _gps_decimal(gps.get(4), gps.get(3))
            technical["GPS Latitude"] = lat
            technical["GPS Longitude"] = lon
    except Exception:  # noqa: BLE001
        pass

    return fields, technical


def _extract_png_info(img: Image.Image) -> dict:
    """Pull common textual PNG/text metadata from img.info."""
    out: dict[str, str] = {}
    keys = ["Software", "Description", "Title", "Author", "Copyright",
            "Creation Time", "Disclaimer", "Warning", "Source", "Comment"]
    for k in keys:
        v = img.info.get(k)
        if v:
            out[k] = _clean(v)
    return out


def _new_finding(counter, category, title, severity, confidence, evidence, interpretation):
    counter["n"] += 1
    return {
        "id": f"F-{counter['n']:03d}",
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "interpretation": interpretation,
    }


def _detect_software(findings, counter, text_fields: dict):
    """Emit findings for AI-generation and editing software (distinct signals)."""
    combined = " ".join(str(v).lower() for v in text_fields.values())
    software = text_fields.get("Software", "").lower()

    for name in AI_GENERATION_SOFTWARE:
        if name in combined:
            findings.append(_new_finding(
                counter, "Metadata",
                "Possible AI-generation software metadata",
                "High", "High",
                f"Metadata references '{name}', associated with AI-image generation workflows.",
                "This is a potentially strong provenance indicator, but metadata can be "
                "modified, added, or removed. It does not by itself prove the image is AI-generated.",
            ))
            break

    for name in EDITING_SOFTWARE:
        if name in software:
            findings.append(_new_finding(
                counter, "Metadata",
                "Image-editing software detected",
                "Low", "Medium",
                f"Software field references '{name}', a known image-editing application.",
                "Editing software alone does NOT indicate AI generation; many authentic photos "
                "are edited. Treat as contextual, not as an AI signal.",
            ))
            break


def analyze(path: str) -> dict:
    """Analyze image metadata at `path`.

    Returns a structured, Streamlit-agnostic dict:
        {
          "available": bool,
          "field_count": int,
          "fields": {...visible...},
          "technical": {...gps etc, for expandable view...},
          "findings": [...],
          "summary": str,
        }
    Never raises on malformed metadata -- failures degrade gracefully.
    """
    counter = {"n": 0}
    findings: list[dict] = []
    result = {
        "available": False,
        "field_count": 0,
        "fields": {},
        "technical": {},
        "findings": findings,
        "summary": "",
    }

    try:
        img = Image.open(path)
        img.load()
    except Exception as exc:  # noqa: BLE001
        result["summary"] = f"Could not open image for metadata analysis: {exc}"
        return result

    try:
        exif_fields, technical = _extract_exif(img)
        png_fields = _extract_png_info(img)
        fields = {**exif_fields, **png_fields}
    except Exception:  # noqa: BLE001
        fields, technical = {}, {}

    gps_present = technical.get("GPS Latitude") is not None or technical.get("GPS Longitude") is not None
    if gps_present:
        fields["GPS Metadata"] = "Present"

    # Drop noisy internal fields from the visible set.
    visible = {k: v for k, v in fields.items() if k not in ("Exif SubIFD", "GPS Info")}

    result["fields"] = visible
    result["technical"] = technical
    result["field_count"] = len(visible)
    result["available"] = len(visible) > 0

    if not result["available"]:
        result["summary"] = "No useful metadata found."
        findings.append(_new_finding(
            counter, "Metadata",
            "No metadata available",
            "Informational", "High",
            "The image contains no readable EXIF, PNG, or textual metadata.",
            "The absence of metadata does not establish whether the image is authentic or "
            "AI-generated, because metadata can be removed during export, compression, "
            "screenshots, or platform processing.",
        ))
        return result

    _detect_software(findings, counter, visible)

    if gps_present:
        findings.append(_new_finding(
            counter, "Metadata",
            "Location metadata present",
            "Informational", "High",
            "GPS/location information is embedded in the image metadata.",
            "Location metadata is a privacy indicator, not an authenticity signal. "
            "Precise coordinates are shown only in the technical details panel.",
        ))

    ai_hits = [f for f in findings if "AI-generation" in f["title"]]
    edit_hits = [f for f in findings if "editing software" in f["title"]]
    if ai_hits:
        result["summary"] = "Metadata contains a possible AI-generation software indicator."
    elif edit_hits:
        result["summary"] = "Metadata indicates image editing; no AI-generation indicator found."
    else:
        result["summary"] = f"Metadata read successfully ({len(visible)} fields). No AI-generation indicator found."

    return result
