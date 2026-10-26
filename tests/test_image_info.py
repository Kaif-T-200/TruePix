"""Tests for src/image_info.py (plus the upload helpers it delegates to in src/utils.py).

Everything here locks in the *current* behaviour of Phase 2: pure factual
metadata about an already-validated image file, and hardened upload validation.
No content provenance, AI detection or forensic heuristics belong to this module.
"""

from __future__ import annotations

import hashlib
import os
import re

import numpy as np
import pytest
from PIL import Image

from src import image_info, utils
from tests.conftest import FakeUpload


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _write_bytes(path, data: bytes) -> str:
    with open(path, "wb") as fh:
        fh.write(data)
    return str(path)


def _make_png(path, height, width, mode="RGB", seed=42) -> str:
    """Deterministic PNG with exactly (width, height) pixels."""
    rng = np.random.default_rng(seed)
    shape = (height, width) if mode == "L" else (height, width, {"RGB": 3, "RGBA": 4}[mode])
    arr = (rng.random(shape) * 255).astype("uint8")
    Image.fromarray(arr, mode=mode).save(str(path))
    return str(path)


def _make_square_png(path, side=128, seed=9) -> str:
    return _make_png(path, side, side, mode="RGB", seed=seed)


# --------------------------------------------------------------------------
# analyze()
# --------------------------------------------------------------------------

def test_analyze_rejects_bad_extension(tmp_path):
    """A non-image extension is refused before any decoding happens."""
    dest = str(tmp_path / "dest.bin")
    for name in ("bad.exe", "bad.txt"):
        path = _write_bytes(tmp_path / name, b"MZ\x90\x00this is definitely not an image")

        result = image_info.analyze(FakeUpload(path, name), dest)

        assert result["ok"] is False
        assert isinstance(result["error"], str) and result["error"].strip() != ""
        assert result["info"] is None
    # Nothing was ever written because validation failed first.
    assert not os.path.exists(dest)


def test_analyze_rejects_corrupt(tmp_path):
    """Undecodable bytes carrying a *valid* extension must not raise; ok is False."""
    path = _write_bytes(
        tmp_path / "corrupt.png", b"\x89PNG\r\n\x1a\nNOT-REALLY-AN-IMAGE-BYTES" * 8
    )
    dest = str(tmp_path / "corrupt_out.png")

    result = image_info.analyze(FakeUpload(path, "corrupt.png"), dest)

    assert result["ok"] is False
    assert isinstance(result["error"], str) and result["error"].strip() != ""
    assert result["info"] is None


def test_analyze_success(rgb_image):
    """A valid PNG round-trips through analyze() into a populated info dict."""
    dest = os.path.join(os.path.dirname(rgb_image), "analyzed.png")

    result = image_info.analyze(FakeUpload(rgb_image), dest)

    assert result["ok"] is True
    assert result["error"] == ""
    assert isinstance(result["info"], dict)
    info = result["info"]

    assert info["filename"] == "rgb.png"
    assert info["width"] == 256
    assert info["height"] == 256
    assert info["image_format"] == "PNG"
    assert info["color_mode"] == "RGB"
    assert info["mime_type"] == "image/png"
    assert info["aspect_ratio"] == "1:1"
    assert info["file_size_bytes"] == os.path.getsize(rgb_image)
    assert info["file_size_bytes"] > 0

    digest = info["sha256"]
    assert isinstance(digest, str)
    assert len(digest) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    # The destination file it decoded is byte-identical to the upload.
    assert digest == utils.compute_sha256(dest)


def _upload(path, name=None):
    """FakeUpload wrapper kept local so the shared fixture stays untouched."""
    return FakeUpload(path, name)


# --------------------------------------------------------------------------
# aspect ratio
# --------------------------------------------------------------------------

def test_aspect_ratio_square(tmp_path):
    """A square image reports width == height and a reduced '1:1' ratio."""
    path = _make_square_png(tmp_path / "square.png", side=128)

    info = image_info.extract_image_info(path, "square.png")

    assert info["width"] == info["height"] == 128
    assert info["aspect_ratio"] == "1:1"

    # Direct check of the reducer for square and degenerate inputs.
    assert image_info._aspect_ratio(100, 100) == "1:1"
    assert image_info._aspect_ratio(3, 3) == "1:1"
    assert image_info._aspect_ratio(1920, 1080) == "16:9"
    assert image_info._aspect_ratio(0, 10) == "n/a"
    assert image_info._aspect_ratio(10, 0) == "n/a"


# --------------------------------------------------------------------------
# extract_image_info()
# --------------------------------------------------------------------------

def test_extract_image_info_basic(tmp_path):
    """A known 64x48 RGB PNG is reported faithfully."""
    path = _make_png(tmp_path / "known.png", height=48, width=64, mode="RGB", seed=42)

    info = image_info.extract_image_info(path, "known.png")

    assert info["filename"] == "known.png"
    assert info["width"] == 64
    assert info["height"] == 48
    assert info["image_format"] == "PNG"
    assert info["color_mode"] == "RGB"
    assert info["mime_type"] == "image/png"
    assert info["aspect_ratio"] == "4:3"
    assert info["file_size_bytes"] == os.path.getsize(path)
    assert info["sha256"] == hashlib.sha256(open(path, "rb").read()).hexdigest()
    assert set(info) == {
        "filename",
        "file_size_bytes",
        "image_format",
        "mime_type",
        "width",
        "height",
        "aspect_ratio",
        "color_mode",
        "sha256",
    }


# --------------------------------------------------------------------------
# utils.sanitize_filename()
# --------------------------------------------------------------------------

def test_sanitize_filename_strips_path():
    """Path components and traversal sequences collapse to a bare filename."""
    cases = (
        ("..\\..\\evil\\x.png", "x.png"),
        ("C:\\x\\y.png", "y.png"),
        ("../../evil/x.png", "x.png"),
        ("/var/tmp/photo.JPG", "photo.JPG"),
        ("..\\..\\etc\\passwd", "passwd"),
        ("..\\..\\..\\boot.ini", "boot.ini"),
    )
    for raw, expected in cases:
        out = utils.sanitize_filename(raw)
        assert out == expected, raw
        assert "\\" not in out
        assert "/" not in out
        assert ".." not in out
        assert ":" not in out

    # Hostile characters are neutralised, not preserved.
    assert utils.sanitize_filename("a b*c?.png") == "a_b_c_.png"

    # Empty / None still yields a usable name.
    assert utils.sanitize_filename("") == "uploaded_image"
    assert utils.sanitize_filename(None) == "uploaded_image"


# --------------------------------------------------------------------------
# utils.compute_sha256()
# --------------------------------------------------------------------------

def test_sha256_is_deterministic(rgb_image):
    """compute_sha256 is stable and matches an independent hashlib digest."""
    first = utils.compute_sha256(rgb_image)
    second = utils.compute_sha256(rgb_image)

    assert first == second
    assert len(first) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", first)

    with open(rgb_image, "rb") as fh:
        expected = hashlib.sha256(fh.read()).hexdigest()
    assert first == expected


# --------------------------------------------------------------------------
# validate_image_dimensions()
# --------------------------------------------------------------------------

def test_validate_image_dimensions():
    """Sanity bounds: sane dims pass, absurd or non-positive dims fail."""
    for width, height in ((1, 1), (64, 48), (1920, 1080), (200_000, 1), (1, 200_000)):
        ok, reason = image_info.validate_image_dimensions(width, height)
        assert ok is True, (width, height, reason)
        assert reason == ""

    for width, height in ((0, 100), (100, 0), (-5, 10), (200_001, 10), (10, 200_001)):
        ok, reason = image_info.validate_image_dimensions(width, height)
        assert ok is False, (width, height)
        assert isinstance(reason, str) and reason.strip() != ""

    ok, reason = image_info.validate_image_dimensions(300_000, 300_000)
    assert ok is False
    assert "too large" in reason
    assert "300000x300000" in reason
    assert str(image_info.MAX_DIMENSION) in reason


# --------------------------------------------------------------------------
# utils.validate_upload()
# --------------------------------------------------------------------------

def test_validate_upload_rules():
    """Size, extension and MIME rules are all enforced."""
    limit = utils.MAX_FILE_SIZE

    # Good name + size + matching MIME is accepted.
    ok, reason = utils.validate_upload("photo.png", 2048, "image/png")
    assert ok is True
    assert reason == ""

    # MIME is optional (browser may not report one).
    ok, reason = utils.validate_upload("photo.png", 2048, None)
    assert ok is True

    # Exactly at the size limit is still accepted.
    ok, reason = utils.validate_upload("photo.png", limit, "image/png")
    assert ok is True

    # Oversize is rejected.
    ok, reason = utils.validate_upload("photo.png", limit + 1, "image/png")
    assert ok is False
    assert reason.strip() != ""

    # Unsupported extension is rejected.
    ok, reason = utils.validate_upload("photo.svg", 2048, None)
    assert ok is False
    assert reason.strip() != ""

    # No extension at all is rejected.
    ok, reason = utils.validate_upload("photo", 2048, None)
    assert ok is False

    # Empty file is rejected first, even with a good name.
    ok, reason = utils.validate_upload("photo.png", 0, "image/png")
    assert ok is False
    assert reason.strip() != ""

    # Negative size is rejected too.
    ok, reason = utils.validate_upload("photo.png", -1, "image/png")
    assert ok is False

    # MIME that contradicts the extension is rejected.
    ok, reason = utils.validate_upload("photo.png", 2048, "image/jpeg")
    assert ok is False
    assert reason.strip() != ""

    # Every allowed extension is accepted with its canonical MIME.
    for ext, mimes in utils.ALLOWED_MIME.items():
        ok, reason = utils.validate_upload(f"photo{ext}", 1024, sorted(mimes)[0])
        assert ok is True, (ext, reason)
        assert utils.sanitize_filename(f"photo{ext}") == f"photo{ext}"
