"""Shared utilities for TruePix: safe upload validation, hashing, filename sanitization."""

from __future__ import annotations

import hashlib
import os
import re

from PIL import Image

# ponytail: keep limits conservative for a low-end CPU machine
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".webp"}
ALLOWED_MIME = {
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".png": {"image/png"},
    ".bmp": {"image/bmp", "image/x-ms-bmp"},
    ".gif": {"image/gif"},
    ".tiff": {"image/tiff"},
    ".webp": {"image/webp"},
}


def sanitize_filename(name: str) -> str:
    """Return a safe basename: strip path, keep only harmless characters."""
    base = os.path.basename(name or "uploaded_image")
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    if not base:
        base = "uploaded_image"
    return base[:120]


def validate_upload(raw_name: str, size: int, mime: str | None) -> tuple[bool, str]:
    """Validate an uploaded file before it is processed.

    Returns (ok, reason). Rejects on size, extension, or MIME mismatch.
    Does NOT open the image -- decoding happens separately in safe_open_image.
    """
    if size <= 0:
        return False, "Empty file."
    if size > MAX_FILE_SIZE:
        return False, f"File too large ({size // 1024 // 1024} MB). Limit is {MAX_FILE_SIZE // 1024 // 1024} MB."

    ext = os.path.splitext(raw_name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Unsupported file type '{ext or 'none'}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}."

    allowed_mimes = ALLOWED_MIME.get(ext, set())
    if mime and allowed_mimes and mime.lower() not in allowed_mimes:
        return False, f"MIME type '{mime}' does not match extension '{ext}'."

    return True, ""


def safe_open_image(path: str) -> Image.Image:
    """Open an image with PIL in a safe mode (no executable content is run).

    Raises ValueError on decode failure so callers can surface a clean error.
    """
    try:
        img = Image.open(path)
        img.verify()  # validates integrity without loading pixel data
        img = Image.open(path)  # re-open after verify() which leaves the file closed
        img.load()
        return img
    except Exception as exc:  # noqa: BLE001 - surface any decode error uniformly
        raise ValueError(f"Could not decode image: {exc}") from exc


def compute_sha256(path: str) -> str:
    """Return the SHA-256 hex digest of a file without loading it fully into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
