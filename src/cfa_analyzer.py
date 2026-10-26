"""Color Filter Array (CFA) / demosaicing artifact detector for TruePix (Phase 3).

Real camera pipelines capture one color sample per pixel through a Bayer
filter (RGGB/GRBG/BGGR/GBRG), then interpolate (demosaic) the missing
channels. Demosaicing leaves a subtle 2-pixel periodic correlation between
the green channel and the red/blue residuals. Diffusion-model output —
trained on fully-RGB web imagery — typically shows no such periodicity.

What this can and cannot say:

  * A **strong, clean 2px CFA signature** is weak positive evidence of a
    camera pipeline (direction AUTHENTICITY_SUPPORT, Low severity and
    confidence). Upscaling, aggressive compression, screenshots, and heavy
    editing can destroy it; its *absence* proves nothing.
  * Absence is therefore reported as a NEUTRAL observation only. It is
    never an AI indicator: a screenshot of a photo or a resized camera
    image would also lack the signature.

Method: green minus (R+B)/2 residual → horizontal/vertical autocorrelation
at lag ±2 versus neighboring lags. Pure NumPy; deterministic; CPU-only.
"""

from __future__ import annotations

import numpy as np

PROVIDER = "cfa"
MAX_SIDE = 512


def _prepare(path: str) -> np.ndarray:
    from PIL import Image

    img = Image.open(path)
    img.load()
    rgb = np.array(img.convert("RGB"), dtype=np.float64)
    h, w = rgb.shape[:2]
    long = max(h, w)
    if long > MAX_SIDE:
        scale = MAX_SIDE / long
        pil = Image.fromarray(rgb.astype(np.uint8)).resize(
            (max(1, int(w * scale)), max(1, int(h * scale))), Image.BILINEAR)
        rgb = np.array(pil, dtype=np.float64)
    return rgb


def _lag_autocorr(x: np.ndarray, axis: int, lag: int) -> float:
    """Normalized autocorrelation of ``x`` along ``axis`` at ``lag``."""
    if axis == 0:
        a, b = x[:-lag, :], x[lag:, :]
    else:
        a, b = x[:, :-lag], x[:, lag:]
    a_f = a - a.mean()
    b_f = b - b.mean()
    denom = (np.sqrt((a_f ** 2).mean()) * np.sqrt((b_f ** 2).mean())) + 1e-12
    return float((a_f * b_f).mean() / denom)


def cfa_score(rgb: np.ndarray) -> dict:
    """Measure 2px demosaicing periodicity in the G-(R+B)/2 residual."""
    out = {"available": False}
    try:
        h, w = rgb.shape[:2]
        if h < 32 or w < 32:
            out["reason"] = "image too small for CFA analysis"
            return out

        r = rgb[:, :, 0]
        g = rgb[:, :, 1]
        b = rgb[:, :, 2]
        residual = g - (r + b) / 2.0
        residual = residual - residual.mean()

        # Autocorrelation at the CFA-relevant lags vs control lags.
        lags = [1, 2, 3, 4]
        h_corr = {L: _lag_autocorr(residual, axis=1, lag=L) for L in lags}
        v_corr = {L: _lag_autocorr(residual, axis=0, lag=L) for L in lags}

        # CFA strength: SIGNED excess of lag-2 alignment over its
        # neighbors. Demosaicing makes the residual positively aligned at
        # exactly 2px; using absolute values would cancel out because
        # checkerboard-style residuals are strongly NEGATIVE at lag 1.
        h_peak = h_corr[2] - (h_corr[1] + h_corr[3]) / 2.0
        v_peak = v_corr[2] - (v_corr[1] + v_corr[3]) / 2.0
        score = max(0.0, (h_peak + v_peak) / 2.0)

        out.update({
            "available": True,
            "cfa_periodicity_score": round(float(score), 5),
            "h_lag_correlations": {str(k): round(v, 5) for k, v in h_corr.items()},
            "v_lag_correlations": {str(k): round(v, 5) for k, v in v_corr.items()},
            # Conservative threshold: real demosaicing usually exceeds 0.01;
            # noise and smooth gradients stay below.
            "cfa_detected": bool(score > 0.010),
        })
    except Exception as exc:  # noqa: BLE001
        out["available"] = False
        out["reason"] = f"CFA analysis failed: {exc}"
    return out


def analyze(path: str) -> dict:
    """Module entry point matching the other analyzers."""
    rgb = _prepare(path)
    res = cfa_score(rgb)
    findings: list[dict] = []
    counter = {"n": 0}

    def _finding(title, severity, confidence, evidence, interpretation,
                 direction):
        counter["n"] += 1
        return {
            "id": f"F-C{counter['n']:03d}",
            "category": "CFA",
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "interpretation": interpretation,
            "evidence_direction": direction,
        }

    if res.get("available") and res.get("cfa_detected"):
        findings.append(_finding(
            "Demosaicing (CFA) signature detected",
            "Low", "Low",
            f"2-pixel periodicity score {res['cfa_periodicity_score']:.4f} "
            f"(H lag-2 {res['h_lag_correlations']['2']:.4f}, "
            f"V lag-2 {res['v_lag_correlations']['2']:.4f}).",
            "The green-minus-average-red-blue residual aligns at exactly two "
            "pixels, consistent with a Bayer-sensor capture followed by "
            "demosaicing. This weakly supports a camera origin but survives "
            "neither resizing nor recompression, so it can never be used to "
            "reject other origins.",
            "AUTHENTICITY_SUPPORT"))
    elif res.get("available"):
        findings.append(_finding(
            "No demosaicing (CFA) signature",
            "Informational", "Low",
            f"2-pixel periodicity score {res.get('cfa_periodicity_score', 0):.4f} "
            "below detection threshold.",
            "No Bayer-style 2px periodicity was found. This is expected for "
            "AI-generated images, but equally expected for screenshots, "
            "resized photos, rendered graphics, and heavily compressed "
            "camera files. The absence of this signature is NOT evidence of "
            "AI generation.",
            "NEUTRAL"))

    status = "COMPLETE" if res.get("available") else "UNAVAILABLE"
    return {
        "status": status,
        "provider": PROVIDER,
        "available": bool(res.get("available")),
        "cfa_analysis": res,
        "findings": findings,
        "summary": (
            "CFA analysis complete. "
            + ("Camera-style demosaicing signature detected."
               if res.get("cfa_detected")
               else "No demosaicing signature found (absence is not AI evidence).")
        ),
    }
