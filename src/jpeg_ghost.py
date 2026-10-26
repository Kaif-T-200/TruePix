"""JPEG double-compression ("ghost") analysis for TruePix (Phase 3).

Estimates whether an image was saved as JPEG more than once and at which
quality, using the classic recompression-dip technique (Lin et al.,
"Detection of double-compression in JPEG images", 2009): re-encoding an
already-JPEG-compressed image at its *original* quality produces a
measurable minimum in the difference between original and re-encoded
DCT coefficients. A single-compressed image shows no such dip.

What this can and cannot say:

  * A detected JPEG history is **transformation context**, not AI evidence.
    Screenshots, messenger forwards, and manual edits all re-compress.
  * PNG-native output from most diffusion generators will show *no* JPEG
    history — the absence of a dip proves nothing either way.
  * The estimated quality is approximate (±2) and unreliable below ~64
    or above ~96.

All computation is local, CPU-only, deterministic. Findings default to
``CONTEXT`` direction; the risk engine decides how much they matter.
"""

from __future__ import annotations

import io

import numpy as np
from PIL import Image

PROVIDER = "jpeg-ghost"
MAX_SIDE = 512

# Quality sweep bounds. Below 60 quantization is so coarse that dip
# detection is unstable; above 96 the quantization tables barely change.
Q_MIN = 60
Q_MAX = 96


def _prepare(path: str) -> np.ndarray:
    img = Image.open(path)
    img.load()
    rgb = np.array(img.convert("RGB"), dtype=np.uint8)
    h, w = rgb.shape[:2]
    long = max(h, w)
    if long > MAX_SIDE:
        scale = MAX_SIDE / long
        rgb = _resize(rgb, w, h, scale)
    return rgb


def _resize(rgb: np.ndarray, w: int, h: int, scale: float) -> np.ndarray:
    # PIL is already imported; avoid cv2 here to keep this module usable
    # without OpenCV (tests may run it standalone).
    pil = Image.fromarray(rgb).resize(
        (max(1, int(w * scale)), max(1, int(h * scale))), Image.BILINEAR)
    return np.array(pil, dtype=np.uint8)


def _blockiness(gray: np.ndarray) -> float:
    """8x8 JPEG grid strength: mean gradient across block boundaries minus
    mean gradient within blocks, normalized by image contrast."""
    g = gray.astype(np.float64)
    h, w = g.shape
    if h < 16 or w < 16:
        return 0.0
    # Gradients across columns x=8,16,... vs other columns.
    col_diff = np.abs(np.diff(g, axis=1)).mean(axis=0)  # length w-1
    row_diff = np.abs(np.diff(g, axis=0)).mean(axis=1)  # length h-1

    def _grid_score(diffs):
        n = len(diffs)
        idx = np.arange(1, n + 1)
        on_grid = diffs[(idx % 8) == 0]
        off_grid = diffs[(idx % 8) != 0]
        if on_grid.size == 0 or off_grid.size == 0:
            return 0.0
        return float(on_grid.mean() - off_grid.mean())

    overall = max(g.std(), 1e-9)
    return (_grid_score(col_diff) + _grid_score(row_diff)) / (2.0 * overall)


def estimate_jpeg_history(rgb: np.ndarray) -> dict:
    """Recompression-dip estimation over a quality sweep.

    Returns a dict with:
      ``available``       — analysis ran
      ``dip_found``       — a clear single-quality dip was found
      ``estimated_quality`` — argmin quality when ``dip_found``
      ``dip_depth``         — how pronounced the minimum is (relative)
      ``grid_strength``     — 8px blockiness of the luminance channel
    """
    out = {"available": False}
    try:
        gray = np.array(Image.fromarray(rgb).convert("L"), dtype=np.uint8)
        out["available"] = True
        out["grid_strength"] = round(_blockiness(gray), 5)

        # Sweep qualities, measuring per-8x8-block DCT disagreement via a
        # cheap proxy: mean absolute pixel difference after recompression.
        # NOTE: this proxy decreases monotonically with quality for ANY
        # image, so the global minimum is meaningless. The double-
        # compression signal is a LOCAL dip below the smooth trend —
        # re-encoding at the original quality aligns quantization grids
        # and briefly drops the error below its neighbors.
        base = rgb.astype(np.float64)
        diffs = []
        for q in range(Q_MIN, Q_MAX + 1, 2):
            buf = io.BytesIO()
            Image.fromarray(rgb).save(buf, format="JPEG", quality=q)
            buf.seek(0)
            rec = np.array(Image.open(buf).convert("RGB"), dtype=np.float64)
            diffs.append(float(np.abs(base - rec).mean()))
        diffs_arr = np.array(diffs)

        # Detrend: subtract a centered moving average (window 5) so the
        # monotonic slope cancels and only the local dip remains.
        kernel = np.ones(5) / 5.0
        trend = np.convolve(diffs_arr, kernel, mode="same")
        # Edges: shrink the window instead of wrapping zeros.
        trend[0] = diffs_arr[:3].mean()
        trend[1] = diffs_arr[:4].mean()
        trend[-1] = diffs_arr[-3:].mean()
        trend[-2] = diffs_arr[-4:].mean()
        residual_curve = diffs_arr - trend

        i_min = int(residual_curve.argmin())
        depth = float(-residual_curve[i_min])  # positive = below trend

        # Dip depth normalized by local error scale so noisy-but-flat
        # images don't produce large relative dips from tiny absolutes.
        scale = float(trend.mean()) + 1e-9
        depth_rel = depth / scale
        out["estimated_quality"] = Q_MIN + i_min * 2
        out["dip_depth"] = round(depth_rel, 5)
        out["sweep_min_diff"] = round(float(diffs_arr[i_min]), 4)
        # Conservative: real double-compression produces pronounced dips;
        # single-compressed images stay near zero after detrending.
        out["dip_found"] = bool(depth_rel > 0.01)
        out["sweep_min_diff"] = round(float(diffs_arr[i_min]), 4)
    except Exception as exc:  # noqa: BLE001
        out["available"] = False
        out["reason"] = f"JPEG history estimation failed: {exc}"
    return out


def analyze(path: str) -> dict:
    """Full module entry point matching the other analyzer modules."""
    rgb = _prepare(path)
    hist = estimate_jpeg_history(rgb)
    findings: list[dict] = []
    counter = {"n": 0}

    def _finding(title, severity, confidence, evidence, interpretation,
                 direction="CONTEXT"):
        counter["n"] += 1
        return {
            "id": f"F-J{counter['n']:03d}",
            "category": "JPEG History",
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "interpretation": interpretation,
            "evidence_direction": direction,
        }

    if hist.get("available"):
        q = hist.get("estimated_quality")
        if hist.get("dip_found"):
            findings.append(_finding(
                "Prior JPEG compression detected",
                "Informational", "Medium",
                f"Recompression sweep shows a quality dip near q={q} "
                f"(depth {hist['dip_depth']:.3f}); 8×8 grid strength "
                f"{hist['grid_strength']:.4f}.",
                "The file (or an ancestor of it) passed through JPEG "
                "compression. This describes the file's storage history — it "
                "is consistent with screenshots, messaging apps, and edits, "
                "and is not evidence about AI generation.",
            ))
        elif hist.get("grid_strength", 0) > 0.01:
            findings.append(_finding(
                "Weak 8×8 grid alignment",
                "Informational", "Low",
                f"No clear recompression dip, but block-grid strength is "
                f"{hist['grid_strength']:.4f}.",
                "A faint JPEG-style grid exists without a detectable original "
                "quality. Could reflect heavy smoothing, upscaling after "
                "compression, or a very high-quality save.",
            ))
        # No finding at all when neither dip nor grid appears — silence here
        # means nothing, and the summary says so explicitly.
    status = "COMPLETE" if hist.get("available") else "UNAVAILABLE"
    return {
        "status": status,
        "provider": PROVIDER,
        "available": bool(hist.get("available")),
        "jpeg_history": hist,
        "findings": findings,
        "summary": (
            f"JPEG-history analysis complete. Dip found: "
            f"{hist.get('dip_found', 'n/a')}; estimated quality {hist.get('estimated_quality', '—')}. "
            "Compression history is transformation context, never proof of AI generation."
        ),
    }
