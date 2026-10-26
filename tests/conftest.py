"""Shared fixtures for the TruePix test suite.

Every fixture is synthetic and deterministic (fixed seeds), so the suite runs
offline on CPU with no external model downloads and no network access.
"""

from __future__ import annotations

import os

import numpy as np
import pytest
from PIL import Image

TRUEPIX_ENV_VARS = (
    "TRUEPIX_LOCAL_MODEL_PATH",
    "TRUEPIX_LOCAL_MODEL_PATHS",
    "TRUEPIX_LOCAL_AI_LABEL",
    "TRUEPIX_LOCAL_AUTHENTIC_LABEL",
    "TRUEPIX_ENABLE_CLIP",
    "TRUEPIX_CLIP_MODEL_PATH",
    "TRUEPIX_AI_API_URL",
    "TRUEPIX_AI_API_KEY",
    "TRUEPIX_AI_PROVIDER",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Guarantee no detector config leaks between tests."""
    for var in TRUEPIX_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _save(path, arr: np.ndarray, **kwargs):
    Image.fromarray(arr).save(path, **kwargs)
    return str(path)


def make_rgb(tmp_path, size=(256, 256), seed=7, name="rgb.png"):
    rng = np.random.default_rng(seed)
    arr = (rng.random((*size, 3)) * 255).astype("uint8")
    return _save(str(tmp_path / name), arr)


def make_jpeg(tmp_path, size=(256, 256), seed=7, quality=88, name="rgb.jpg"):
    rng = np.random.default_rng(seed)
    arr = (rng.random((*size, 3)) * 255).astype("uint8")
    return _save(str(tmp_path / name), arr, quality=quality)


def make_grayscale(tmp_path, size=(64, 64), seed=3, name="gray.png"):
    rng = np.random.default_rng(seed)
    arr = (rng.random(size) * 255).astype("uint8")
    return _save(str(tmp_path / name), arr)


def make_rgba(tmp_path, size=(64, 64), seed=4, name="rgba.png"):
    rng = np.random.default_rng(seed)
    arr = (rng.random((*size, 4)) * 255).astype("uint8")
    return _save(str(tmp_path / name), arr)


def make_tiny(tmp_path, size=(8, 8), seed=5, name="tiny.png"):
    rng = np.random.default_rng(seed)
    arr = (rng.random((*size, 3)) * 255).astype("uint8")
    return _save(str(tmp_path / name), arr)


def make_uniform(tmp_path, size=(64, 64), value=128, name="uniform.png"):
    arr = np.full((*size, 3), value, dtype="uint8")
    return _save(str(tmp_path / name), arr)


def make_copymove(tmp_path, size=(256, 256), seed=11, name="copy.png"):
    """A high-entropy region duplicated at a constant offset (copy-move)."""
    rng = np.random.default_rng(seed)
    arr = np.zeros((*size, 3), dtype=np.uint8)
    seed_region = (rng.random((size[0] // 2, size[1] // 2, 3)) * 255).astype("uint8")
    arr[: size[0] // 2, : size[1] // 2] = seed_region
    arr[100 : 100 + size[0] // 2, 100 : 100 + size[1] // 2] = seed_region
    return _save(str(tmp_path / name), arr)


def make_camera_like(tmp_path, size=(256, 256), seed=13, name="cam.png"):
    """Smooth natural base + a Bayer-lattice residual in the green channel.

    Demosaicing leaves the green residual strongly aligned at exactly two
    pixels while lag-1/lag-3 stay low, which is what the CFA detector
    measures.
    """
    h, w = size
    yy, xx = np.mgrid[0:h, 0:w]
    rng = np.random.default_rng(seed)

    lum = 110.0 + 45.0 * np.sin(0.03 * xx + 0.05 * yy) + rng.random(size) * 0
    red = lum + 8.0 * np.sin(0.02 * yy)
    blue = lum + 6.0 * np.cos(0.02 * xx)

    # Green sampled on a Bayer lattice: alternating residual every 2 px.
    delta = 2.5
    green = lum + delta * np.where((np.tile(np.arange(w), (h, 1)) % 2) == 0, 1.0, -1.0)

    arr = np.stack([red, green, blue], axis=-1).clip(0, 255).astype("uint8")
    return _save(str(tmp_path / name), arr)


def make_smooth_rgb(tmp_path, size=(256, 256), seed=17, name="smooth.png"):
    """Smooth, gradation-only RGB with no lattice structure (CFA control)."""
    h, w = size
    yy, xx = np.mgrid[0:h, 0:w]
    lum = 110.0 + 45.0 * np.sin(0.03 * xx + 0.05 * yy)
    arr = np.stack([lum, lum + 4.0, lum + 2.0], axis=-1).clip(0, 255).astype("uint8")
    return _save(str(tmp_path / name), arr)


class FakeUpload:
    """Minimal stand-in for Streamlit's UploadedFile."""

    def __init__(self, path, name=None):
        self.name = name or os.path.basename(path)
        with open(path, "rb") as fh:
            self._b = fh.read()
        self._pos = 0
        self.size = len(self._b)
        self.type = None

    def read(self, *args):
        if args:
            n = args[0]
            chunk = self._b[self._pos : self._pos + n]
            self._pos += n
            return chunk
        chunk = self._b[self._pos :]
        self._pos = len(self._b)
        return chunk

    def seek(self, *a):
        self._pos = a[0] if a else 0
        return self._pos

    def tell(self):
        return self._pos

    def getbuffer(self):
        return self._b

    def getvalue(self):
        return self._b


@pytest.fixture
def rgb_image(tmp_path):
    return make_rgb(tmp_path)


@pytest.fixture
def jpg_image(tmp_path):
    return make_jpeg(tmp_path)


@pytest.fixture
def gray_image(tmp_path):
    return make_grayscale(tmp_path)


@pytest.fixture
def rgba_image(tmp_path):
    return make_rgba(tmp_path)


@pytest.fixture
def tiny_image(tmp_path):
    return make_tiny(tmp_path)


@pytest.fixture
def uniform_image(tmp_path):
    return make_uniform(tmp_path)


@pytest.fixture
def copymove_image(tmp_path):
    return make_copymove(tmp_path)


@pytest.fixture
def camera_image(tmp_path):
    return make_camera_like(tmp_path)


@pytest.fixture
def smooth_image(tmp_path):
    return make_smooth_rgb(tmp_path)
