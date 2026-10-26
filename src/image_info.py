"""Image information extraction and hardened upload validation for TruePix.

Phase 2: pure metadata/format facts about an already-validated image file.
No content provenance, AI detection, or forensic heuristics live here.
"""

from __future__ import annotations

import math
import os

from PIL import Image

from src import utils

# Guard against absurd dimensions that would exhaust RAM on a low-end CPU.
MAX_DIMENSION = 200_000


def _aspect_ratio(width: int, height: int) -> str:
    """Return a reduced 'W:H' fraction (e.g. '16:9'), or 'n/a' if degenerate."""
    if not width or not height:
        return "n/a"
    g = math.gcd(width, height)
    return f"{width // g}:{height // g}"


def extract_image_info(path: str, original_name: str) -> dict:
    """Extract factual image information from a decoded image file.

    `path` is the on-disk temporary file; `original_name` is the user-supplied
    filename (sanitized for display only). Returns a flat dict. Missing values
    are reported as 'unknown' rather than guessed.
    """
    img = utils.safe_open_image(path)
    width, height = img.size
    fmt = img.format or "unknown"
    try:
        mime = img.get_format_mimetype() or utils.ALLOWED_MIME.get(
            os.path.splitext(original_name)[1].lower(), {""}
        ).pop() or "unknown"
    except Exception:  # noqa: BLE001
        mime = "unknown"

    return {
        "filename": utils.sanitize_filename(original_name),
        "file_size_bytes": os.path.getsize(path),
        "image_format": fmt,
        "mime_type": mime,
        "width": width,
        "height": height,
        "aspect_ratio": _aspect_ratio(width, height),
        "color_mode": img.mode,
        "sha256": utils.compute_sha256(path),
    }


def validate_image_dimensions(width: int, height: int) -> tuple[bool, str]:
    """Reject images whose dimensions are unreasonably large or invalid.

    This protects the (low-end) host from decompression-bomb style inputs.
    """
    if width <= 0 or height <= 0:
        return False, "Image has invalid (non-positive) dimensions."
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        return False, (
            f"Image dimensions too large ({width}x{height}). "
            f"Limit is {MAX_DIMENSION} px per side."
        )
    return True, ""


def analyze(uploaded, tmp_path: str) -> dict:
    """Full Phase-2 analysis: validate, decode safely, extract info.

    Returns {"ok": bool, "error": str, "info": dict|None}. Never raises on
    malformed input -- failures are reported so the UI can show a clean message.
    """
    ok, reason = utils.validate_upload(
        uploaded.name, getattr(uploaded, "size", 0), getattr(uploaded, "type", None)
    )
    if not ok:
        return {"ok": False, "error": reason, "info": None}

    try:
        with open(tmp_path, "wb") as fh:
            fh.write(uploaded.getbuffer())
        img = utils.safe_open_image(tmp_path)
    except ValueError as exc:
        return {"ok": False, "error": str(exc), "info": None}

    ok, reason = validate_image_dimensions(*img.size)
    if not ok:
        return {"ok": False, "error": reason, "info": None}

    try:
        info = extract_image_info(tmp_path, uploaded.name)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"Could not read image information: {exc}", "info": None}

    return {"ok": True, "error": "", "info": info}
