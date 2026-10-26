"""Regression tests for src.cfa_analyzer (CFA / demosaicing periodicity).

Policy under test: CFA presence only weakly SUPPORTS a camera pipeline
(AUTHENTICITY_SUPPORT). Absence is NEUTRAL and must never be treated as
evidence of AI generation.
"""

from __future__ import annotations

import numpy as np
import pytest
from PIL import Image

from src.cfa_analyzer import analyze, cfa_score


AI_DIRECTION = "AI_INDICATOR"
AUTHENTICITY_SUPPORT = "AUTHENTICITY_SUPPORT"
NEUTRAL = "NEUTRAL"
SMALL_REASON = "image too small for CFA analysis"

CAMERA_SCORE = 0.33645
CAMERA_H_LAGS = {"1": 0.31918, "2": 0.99194, "3": 0.31839, "4": 0.99216}
CAMERA_V_LAGS = {"1": 0.99339, "2": 0.99236, "3": 0.99185, "4": 0.9922}
SMOOTH_SCORE = 0.0
SMOOTH_H_LAGS = {"1": 0.0, "2": 0.0, "3": 0.0, "4": 0.0}
SMOOTH_V_LAGS = {"1": 0.0, "2": 0.0, "3": 0.0, "4": 0.0}


def _save_png(path, arr: np.ndarray) -> str:
    Image.fromarray(arr).save(str(path))
    return str(path)


def _bayer_lattice(h: int = 256, w: int = 256) -> np.ndarray:
    """Float64 Bayer-lattice RGB: green residual aligned at exactly 2px."""
    yy, xx = np.mgrid[0:h, 0:w]
    lum = 110.0 + 45.0 * np.sin(0.03 * xx + 0.05 * yy)
    red = lum + 8.0 * np.sin(0.02 * yy)
    blue = lum + 6.0 * np.cos(0.02 * xx)
    green = lum + 2.5 * np.where((xx % 2) == 0, 1.0, -1.0)
    return np.stack([red, green, blue], axis=-1).astype(np.float64)


def _offscreen_camera_image(tmp_path) -> str:
    """Camera-like image created in-process (no fixture / no Bayer import)."""
    return _save_png(tmp_path / "bayer.png", _bayer_lattice().astype(np.uint8))


def _noise_image(tmp_path, seed: int, size=(256, 256)) -> str:
    rng = np.random.default_rng(seed)
    arr = (rng.random((*size, 3)) * 255).astype("uint8")
    return _save_png(tmp_path / f"noise_{seed}.png", arr)


def test_camera_pipeline_detected(camera_image):
    res = analyze(camera_image)

    assert res["status"] == "COMPLETE"
    assert res["provider"] == "cfa"
    assert bool(res["available"])

    cfa = res["cfa_analysis"]
    assert cfa == {
        "available": True,
        "cfa_periodicity_score": CAMERA_SCORE,
        "h_lag_correlations": CAMERA_H_LAGS,
        "v_lag_correlations": CAMERA_V_LAGS,
        "cfa_detected": True,
    }

    assert cfa["cfa_detected"] is True
    assert cfa["cfa_periodicity_score"] > 0.010

    h_lags = cfa["h_lag_correlations"]
    assert h_lags["2"] > h_lags["1"]
    assert h_lags["2"] > h_lags["3"]

    v_lags = cfa["v_lag_correlations"]
    assert v_lags["2"] > v_lags["1"]
    assert v_lags["2"] > v_lags["3"]

    findings = res["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["id"] == "F-C001"
    assert finding["category"] == "CFA"
    assert finding["title"] == "Demosaicing (CFA) signature detected"
    assert finding["severity"] == "Low"
    assert finding["confidence"] == "Low"
    assert finding["evidence_direction"] == AUTHENTICITY_SUPPORT
    assert AI_DIRECTION not in [f["evidence_direction"] for f in findings]
    assert "2-pixel periodicity score 0.3364" in finding["evidence"]
    assert "weakly supports a camera origin" in finding["interpretation"]

    assert "Camera-style demosaicing signature detected." in res["summary"]


def test_camera_pipeline_detected_direct_array():
    direct = cfa_score(_bayer_lattice())

    assert direct == {
        "available": True,
        "cfa_periodicity_score": CAMERA_SCORE,
        "h_lag_correlations": CAMERA_H_LAGS,
        "v_lag_correlations": CAMERA_V_LAGS,
        "cfa_detected": True,
    }
    assert direct["cfa_detected"] is True
    assert direct["cfa_periodicity_score"] > 0.010


def test_camera_pipeline_detected_offscreen(tmp_path):
    res = analyze(_offscreen_camera_image(tmp_path))

    cfa = res["cfa_analysis"]
    assert cfa == {
        "available": True,
        "cfa_periodicity_score": CAMERA_SCORE,
        "h_lag_correlations": CAMERA_H_LAGS,
        "v_lag_correlations": CAMERA_V_LAGS,
        "cfa_detected": True,
    }
    assert res["findings"][0]["evidence_direction"] == AUTHENTICITY_SUPPORT


def test_non_camera_control_not_detected(smooth_image):
    res = analyze(smooth_image)

    assert res["status"] == "COMPLETE"
    assert bool(res["available"])

    cfa = res["cfa_analysis"]
    assert cfa == {
        "available": True,
        "cfa_periodicity_score": SMOOTH_SCORE,
        "h_lag_correlations": SMOOTH_H_LAGS,
        "v_lag_correlations": SMOOTH_V_LAGS,
        "cfa_detected": False,
    }

    h_lags = cfa["h_lag_correlations"]
    assert h_lags["1"] == 0.0
    assert h_lags["2"] == 0.0
    assert h_lags["3"] == 0.0
    assert not (h_lags["2"] > h_lags["1"])
    assert not (h_lags["2"] > h_lags["3"])

    findings = res["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["id"] == "F-C001"
    assert finding["title"] == "No demosaicing (CFA) signature"
    assert finding["severity"] == "Informational"
    assert finding["confidence"] == "Low"
    assert finding["evidence_direction"] == NEUTRAL
    assert AI_DIRECTION not in [f["evidence_direction"] for f in findings]
    assert "2-pixel periodicity score 0.0000" in finding["evidence"]
    assert "absence of this signature is NOT evidence of AI generation" in finding["interpretation"]

    assert "No demosaicing signature found (absence is not AI evidence)." in res["summary"]


def test_non_camera_control_not_detected_direct_array(tmp_path):
    """Pure noise and a flat field carry no 2px lattice over their lags."""
    rng = np.random.default_rng(21)
    noise = cfa_score((rng.random((256, 256, 3)) * 255).astype("uint8"))
    assert bool(noise["available"])
    assert noise["cfa_periodicity_score"] < 0.010
    assert noise["cfa_detected"] is False
    assert not (noise["h_lag_correlations"]["2"] > noise["h_lag_correlations"]["1"])

    flat = cfa_score(np.full((64, 64, 3), 128, dtype=np.uint8))
    assert bool(flat["available"])
    assert flat["cfa_periodicity_score"] == 0.0
    assert flat["cfa_detected"] is False
    for lag, value in flat["h_lag_correlations"].items():
        assert value == 0.0, f"h lag {lag} should be 0.0 on a flat field"

    res = analyze(_noise_image(tmp_path, 21))
    assert res["status"] == "COMPLETE"
    assert res["cfa_analysis"]["cfa_detected"] is False
    assert AI_DIRECTION not in [f["evidence_direction"] for f in res["findings"]]


def test_absence_is_neutral_never_ai(tmp_path):
    """Every non-CFA image must yield zero AI-direction findings."""
    rng = np.random.default_rng(42)
    paths = [
        tmp_path / "smooth_gradient.png",
        tmp_path / "noise.png",
        tmp_path / "flat.png",
    ]
    _save_png(paths[0], np.zeros((128, 128, 3), dtype=np.uint8))
    _save_png(paths[1], (rng.random((128, 128, 3)) * 255).astype("uint8"))
    _save_png(paths[2], np.full((128, 128, 3), 200, dtype="uint8"))

    checked = 0
    for path in paths:
        res = analyze(str(path))
        if res["cfa_analysis"]["available"] is False:
            assert res["cfa_analysis"]["reason"] != ""
        else:
            checked += 1
            assert res["cfa_analysis"]["cfa_detected"] is False

        directions = [f["evidence_direction"] for f in res["findings"]]
        assert AI_DIRECTION not in directions, (
            f"{path.name} leaked an AI_INDICATOR finding: {res['findings']}"
        )
        assert NEUTRAL in directions, f"{path.name} should record a NEUTRAL finding"
        assert NEUTRAL in directions
        assert len(set(directions)) <= 1
        assert AUTHENTICITY_SUPPORT not in directions

    assert checked >= 2, "expected at least two analyzable control images"


def test_summary_states_absence_is_not_ai_evidence(tmp_path):
    """Absence must be worded explicitly as not-AI, never as AI suspicion."""
    rng = np.random.default_rng(7)
    controls = [
        tmp_path / "noise.png",
        tmp_path / "flat.png",
    ]
    _save_png(controls[0], (rng.random((128, 128, 3)) * 255).astype("uint8"))
    _save_png(controls[1], np.full((128, 128, 3), 90, dtype="uint8"))

    seen = 0
    for path in controls:
        res = analyze(str(path))
        assert res["status"] == "COMPLETE"
        assert res["cfa_analysis"]["cfa_detected"] is False

        summary = res["summary"]
        assert "CFA analysis complete." in summary
        assert "No demosaicing signature found" in summary
        assert "absence is not AI evidence" in summary
        assert "ai evidence" not in summary.lower().replace("not ai evidence", "")
        assert "indicates ai" not in summary.lower()
        assert "likely ai" not in summary.lower()
        assert "ai-generated" not in summary.lower()

        finding = res["findings"][0]
        assert finding["evidence_direction"] == NEUTRAL
        assert "absence of this signature is NOT evidence of AI generation" in finding["interpretation"]
        assert "expected for AI-generated images" in finding["interpretation"]
        seen += 1

    assert seen == len(controls)


def test_small_image_graceful(tiny_image, tmp_path):
    rng = np.random.default_rng(5)
    small = np.zeros((16, 16, 3), dtype=np.uint8")
    ...