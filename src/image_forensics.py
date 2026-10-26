"""Lightweight image-forensics module for TruePix (Phase 5).

CPU-only techniques built on Pillow + OpenCV + NumPy. Produces observable
forensic signals (ELA, noise, compression, edges, frequency, DCT, color,
texture). These are *observations*, never proof of AI generation or
manipulation. The evidence/risk engine combines them.

All metrics are computed on a downsampled copy (longest side <= 512) to bound
memory/CPU. The original uploaded file is never modified.
"""

from __future__ import annotations

import base64
import io
import os

import cv2
import numpy as np
from PIL import Image

MAX_SIDE = 512


def _prepare(path: str) -> tuple[np.ndarray, tuple[int, int]]:
    """Load image safely, return (RGB uint8 array, original dimensions)."""
    img = Image.open(path)
    img.load()
    orig_dims = img.size
    rgb = img.convert("RGB")
    arr = np.array(rgb, dtype=np.uint8)
    h, w = arr.shape[:2]
    long = max(h, w)
    if long > MAX_SIDE:
        scale = MAX_SIDE / long
        arr = cv2.resize(arr, (max(1, int(w * scale)), max(1, int(h * scale))))
    return arr, orig_dims


def _ela(rgb: np.ndarray) -> dict:
    """Error Level Analysis via single recompression at quality 90."""
    try:
        buf = io.BytesIO()
        Image.fromarray(rgb).save(buf, format="JPEG", quality=90)
        buf.seek(0)
        recomp = np.array(Image.open(buf).convert("RGB"), dtype=np.int32)
        orig = rgb.astype(np.int32)
        diff = np.abs(orig - recomp).mean(axis=2)  # grayscale residual
        diff_f = diff.astype(np.float64)
        stat = {
            "available": True,
            "mean": round(float(diff_f.mean()), 4),
            "std": round(float(diff_f.std()), 4),
            "max": round(float(diff_f.max()), 4),
        }
        # Lightweight preview (normalized residual, small).
        preview = _ela_preview(diff)
        stat["preview_b64"] = preview
        return stat
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "ELA computation failed"}


def _ela_preview(diff: np.ndarray, max_side: int = 256) -> str:
    d = diff.astype(np.float64)
    d = (d - d.min()) / (d.max() - d.min() + 1e-9)
    d = (d * 255).astype(np.uint8)
    small = cv2.resize(d, (max(1, min(max_side, d.shape[1])),
                           max(1, min(max_side, d.shape[0]))))
    img = Image.fromarray(small, mode="L").convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _noise(rgb: np.ndarray) -> dict:
    """Noise proxy via Laplacian variance, plus regional consistency."""
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    lap = cv2.Laplacian(gray, cv2.CV_64F)
    global_level = float(lap.var())
    # Regional consistency: split into quadrants, measure per-region noise.
    h, w = gray.shape
    q_vars = []
    for y0 in (0, h // 2):
        for x0 in (0, w // 2):
            region = gray[y0: y0 + h // 2, x0: x0 + w // 2]
            if region.size:
                q_vars.append(cv2.Laplacian(region, cv2.CV_64F).var())
    q_vars = np.array(q_vars)
    mean_q = q_vars.mean()
    regional_variance = float(q_vars.std() / (mean_q + 1e-9)) if mean_q > 1e-9 else 0.0
    return {
        "available": True,
        "global_level": round(global_level, 4),
        "regional_consistency_cv": round(regional_variance, 4),
    }


def _compression(path: str, rgb: np.ndarray, orig_dims: tuple[int, int]) -> dict:
    """Compression proxy: bytes-per-pixel and 8x8 block-edge blockiness."""
    try:
        size = os.path.getsize(path)
        w, h = orig_dims
        bpp = size / max(1, (w * h * 3))
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
        bh, bw = 8, 8
        if gray.shape[0] >= 2 * bh and gray.shape[1] >= 2 * bw:
            h_edges = np.abs(np.diff(gray[:, ::bw].astype(np.float64), axis=1)).mean()
            v_edges = np.abs(np.diff(gray[::bh, :].astype(np.float64), axis=0)).mean()
            blockiness = float((h_edges + v_edges) / 2.0)
        else:
            blockiness = 0.0
        return {
            "available": True,
            "bytes_per_pixel": round(float(bpp), 5),
            "blockiness": round(blockiness, 4),
        }
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "Compression analysis failed"}


def _edges(rgb: np.ndarray) -> dict:
    """Edge density via Canny."""
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    edges = cv2.Canny(gray, 100, 200)
    density = float(edges.mean()) / 255.0
    return {"available": True, "edge_density": round(density, 5)}


def _frequency(gray_or_rgb) -> dict:
    """Spectral analysis via 2D FFT on grayscale.

    Beyond the plain high-frequency ratio, computes a radial energy
    profile (power per frequency band) and an azimuthal uniformity score.
    Diffusion-model output tends to suppress mid/high frequencies and to
    be unusually isotropic; real photographs carry slight directional
    energy from lens/CFA structure. Both are observations with known
    confounds (smoothing, upscaling, screenshots), never proof.
    """
    gray = cv2.cvtColor(gray_or_rgb, cv2.COLOR_RGB2GRAY) if gray_or_rgb.ndim == 3 else gray_or_rgb
    small = cv2.resize(gray, (256, 256))
    f = np.fft.fft2(small.astype(np.float64))
    mag = np.abs(np.fft.fftshift(f))
    power = mag ** 2
    total = power.sum() + 1e-12
    cy, cx = np.array(power.shape) // 2
    y, x = np.mgrid[0:power.shape[0], 0:power.shape[1]]
    r = np.sqrt((y - cy) ** 2 + (x - cx) ** 2)
    max_r = r.max()
    hf = power[r > 0.5 * max_r].sum()
    ratio = float(hf / total)

    # Radial profile: mean power in 8 equal-width radial bands.
    n_bands = 8
    band_edges = np.linspace(0, max_r + 1e-9, n_bands + 1)
    band_power = []
    for b in range(n_bands):
        mask = (r >= band_edges[b]) & (r < band_edges[b + 1])
        band_power.append(round(float(power[mask].mean()), 4))

    # Mid-band ratio: energy in the middle half of the spectrum relative
    # to the outer bands — low values indicate mid-frequency suppression.
    mid_mask = (r >= 0.25 * max_r) & (r <= 0.75 * max_r)
    outer_mask = (r > 0.75 * max_r)
    mid_ratio = float(power[mid_mask].sum() / (power[outer_mask].sum() + 1e-12))

    # Azimuthal uniformity: split into 16 angular sectors; a perfectly
    # isotropic spectrum has equal sector energy. Natural images rarely do.
    theta = np.arctan2(y - cy, x - cx)
    sector_energy = []
    for s in range(16):
        smask = (theta >= -np.pi + s * np.pi / 8) & \
                (theta < -np.pi + (s + 1) * np.pi / 8)
        sector_energy.append(float(power[smask].sum()))
    se = np.array(sector_energy)
    azimuthal_cv = float(se.std() / (se.mean() + 1e-12))

    return {
        "available": True,
        "high_frequency_ratio": round(ratio, 5),
        "radial_profile": band_power,
        "mid_band_ratio": round(mid_ratio, 5),
        "azimuthal_uniformity": round(azimuthal_cv, 4),
    }


def _dct_analysis(rgb: np.ndarray) -> dict:
    """DCT coefficient analysis — AI images often have unusual DCT patterns.

    Computes the DCT of 8x8 blocks and measures:
    - DC coefficient uniformity (AI images often have very uniform DC)
    - High-frequency coefficient energy (AI images often have suppressed HF)
    - Block-to-block coefficient variance (AI images often have low variance)
    """
    try:
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY).astype(np.float64)
        h, w = gray.shape
        bh, bw = 8, 8
        blocks = []
        for y in range(0, h - bh, bh):
            for x in range(0, w - bw, bw):
                blocks.append(cv2.dct(gray[y:y + bh, x:x + bw]))
        if not blocks:
            return {"available": False, "reason": "image too small for DCT"}
        blocks = np.array(blocks)
        dc = blocks[:, 0, 0]
        ac = blocks[:, 1:, 1:]
        dc_cv = float(dc.std() / (abs(dc.mean()) + 1e-9))
        ac_energy = float(np.abs(ac).mean())
        ac_std = float(ac.std())
        return {
            "available": True,
            "dc_uniformity_cv": round(dc_cv, 4),
            "ac_energy": round(ac_energy, 4),
            "ac_std": round(ac_std, 4),
        }
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "DCT analysis failed"}


def _color_banding(rgb: np.ndarray) -> dict:
    """Detect color banding / gradient smoothness — common in AI-generated images.

    AI images often have overly smooth gradients with visible banding in
    sky/skin/background regions. Measures the histogram smoothness.
    """
    try:
        hsv = cv2.cvtColor(rgb, cv2.COLOR_RGB2HSV)
        # Analyze the V (value) channel for banding
        v = hsv[:, :, 2]
        hist = cv2.calcHist([v], [0], None, [256], [0, 256]).flatten()
        hist = hist / (hist.sum() + 1e-9)
        # Count zero bins (gaps in the histogram = banding)
        zero_bins = int((hist < 1e-6).sum())
        # Smoothness: how many adjacent bins have similar values
        diff = np.abs(np.diff(hist))
        smoothness = float(1.0 - (diff > 0.0005).mean())
        return {
            "available": True,
            "zero_bins": zero_bins,
            "smoothness": round(smoothness, 4),
        }
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "Color banding analysis failed"}


def _texture_uniformity(rgb: np.ndarray) -> dict:
    """Detect overly uniform texture — AI images often have unnaturally smooth regions.

    Computes local variance across the image. AI-generated images often have
    regions with very low variance (too smooth) or unnaturally uniform texture.
    """
    try:
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY).astype(np.float64)
        h, w = gray.shape
        bs = max(16, min(h, w) // 8)
        variances = []
        for y in range(0, h - bs, bs):
            for x in range(0, w - bs, bs):
                block = gray[y:y + bs, x:x + bs]
                variances.append(block.var())
        variances = np.array(variances)
        if variances.size < 2:
            return {"available": False, "reason": "image too small"}
        mean_var = float(variances.mean())
        std_var = float(variances.std())
        # Very low mean variance = overly smooth image
        # Low std = unnaturally uniform texture
        return {
            "available": True,
            "mean_variance": round(mean_var, 4),
            "std_variance": round(std_var, 4),
            "uniformity_ratio": round(float((variances < mean_var * 0.3).mean()), 4),
        }
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "Texture uniformity analysis failed"}


def _saturation_analysis(rgb: np.ndarray) -> dict:
    """Analyze color saturation — AI images often have unnaturally saturated colors."""
    try:
        hsv = cv2.cvtColor(rgb, cv2.COLOR_RGB2HSV)
        s = hsv[:, :, 1].astype(np.float64)
        mean_sat = float(s.mean())
        std_sat = float(s.std())
        # High saturation with low variance = unnaturally uniform vivid colors
        return {
            "available": True,
            "mean_saturation": round(mean_sat, 4),
            "std_saturation": round(std_sat, 4),
        }
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "Saturation analysis failed"}


def _noise_correlation(rgb: np.ndarray) -> dict:
    """Measure spatial and cross-channel correlation in high-pass residuals.

    Camera noise, JPEG processing, resizing, and generated-image pipelines leave
    different *statistical* traces in residual pixels.  This is an observation
    inspired by published noise-correlation detectors; it is not a classifier and
    must not be interpreted as a universal AI test.  We select low-content 8x8
    blocks so scene edges do not dominate the measurement.
    """
    try:
        arr = rgb.astype(np.float64)
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY).astype(np.float64)
        kernel = np.array([[0.0, 1.0, 0.0],
                           [1.0, -4.0, 1.0],
                           [0.0, 1.0, 0.0]], dtype=np.float64)
        residual = np.stack([
            cv2.filter2D(arr[:, :, c], cv2.CV_64F, kernel,
                         borderType=cv2.BORDER_REFLECT101)
            for c in range(3)
        ], axis=2)

        h, w = gray.shape
        block_size = 8
        candidates = []
        for y in range(0, h - block_size + 1, block_size):
            for x in range(0, w - block_size + 1, block_size):
                content = gray[y:y + block_size, x:x + block_size]
                res = residual[y:y + block_size, x:x + block_size]
                res_std = float(res.std())
                if res_std > 1e-6:
                    # Low-content blocks are less contaminated by semantic edges.
                    candidates.append((float(content.var()), y, x, res))

        candidates.sort(key=lambda item: item[0])
        selected = candidates[:64]
        if len(selected) < 4:
            return {
                "available": True,
                "selected_blocks": len(selected),
                "inter_block_abs_corr": 0.0,
                "residual_channel_abs_corr": 0.0,
                "residual_std": round(float(residual.std()), 5),
                "detail": "Too few non-flat 8x8 blocks for a stable correlation estimate",
            }

        block_corr = []
        channel_samples = [[] for _ in range(3)]
        for _, _, _, block in selected:
            for c in range(3):
                channel_samples[c].extend(block[:, :, c].ravel().tolist())
            # One row per block; channel-average reduces color-specific scale.
            block_corr.append(block.mean(axis=2).ravel())

        block_corr = np.asarray(block_corr, dtype=np.float64)
        corr = np.corrcoef(block_corr)
        off_diag = corr[~np.eye(corr.shape[0], dtype=bool)]
        inter_block = float(np.nanmean(np.abs(off_diag))) if off_diag.size else 0.0

        channel_corr = np.corrcoef(np.asarray(channel_samples, dtype=np.float64))
        channel_off = channel_corr[~np.eye(3, dtype=bool)]
        residual_channel = float(np.nanmean(np.abs(channel_off))) if channel_off.size else 0.0

        return {
            "available": True,
            "selected_blocks": len(selected),
            "inter_block_abs_corr": round(float(np.nan_to_num(inter_block)), 5),
            "residual_channel_abs_corr": round(float(np.nan_to_num(residual_channel)), 5),
            "residual_std": round(float(residual.std()), 5),
            "detail": (
                f"8x8 low-content blocks={len(selected)}, "
                f"inter-block |r|={inter_block:.3f}, "
                f"channel |r|={residual_channel:.3f}"
            ),
        }
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "Noise-correlation analysis failed"}


def _channel_correlation(rgb: np.ndarray) -> dict:
    """Compare raw and high-pass RGB channel correlation.

    Raw RGB channels are normally correlated because of scene luminance, so the
    useful quantity here is correlation after removing low-frequency content.
    The metric is reported for corroboration only; it is not provider-specific.
    """
    try:
        arr = rgb.astype(np.float64)
        low = np.stack([cv2.GaussianBlur(arr[:, :, c], (0, 0), 1.2)
                        for c in range(3)], axis=2)
        hp = arr - low
        def mean_abs_offdiag(values):
            values = np.asarray(values, dtype=np.float64)
            if values.shape[0] < 2 or any(np.std(row) < 1e-9 for row in values):
                return 0.0
            with np.errstate(divide="ignore", invalid="ignore"):
                corr = np.corrcoef(values)
            off_diag = corr[~np.eye(corr.shape[0], dtype=bool)]
            finite = off_diag[np.isfinite(off_diag)]
            return float(np.mean(np.abs(finite))) if finite.size else 0.0

        raw_mean_abs = mean_abs_offdiag([arr[:, :, c].ravel() for c in range(3)])
        hp_mean_abs = mean_abs_offdiag([hp[:, :, c].ravel() for c in range(3)])
        return {
            "available": True,
            "raw_mean_abs_corr": round(raw_mean_abs, 5),
            "high_pass_mean_abs_corr": round(hp_mean_abs, 5),
            "detail": "RGB correlation measured before and after low-frequency removal",
        }
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "Channel-correlation analysis failed"}


def _transformation_history(rgb: np.ndarray) -> dict:
    """Look for resampling/smoothing characteristics common after sharing.

    A screenshot, social-media export, or resize can create correlated residuals
    and unusually smooth gradients.  This cannot identify *why* the transform
    happened, so the output is deliberately a transformation context signal.
    """
    try:
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY).astype(np.float64)
        smooth = cv2.GaussianBlur(gray, (3, 3), 0)
        residual = gray - smooth
        lap = cv2.Laplacian(gray, cv2.CV_64F)
        flat = np.abs(lap) < np.percentile(np.abs(lap), 55)

        def corr_at(a, b, mask):
            valid = mask & np.isfinite(a) & np.isfinite(b)
            if valid.sum() < 20 or np.std(a[valid]) < 1e-9 or np.std(b[valid]) < 1e-9:
                return 0.0
            return float(np.corrcoef(a[valid], b[valid])[0, 1])

        horizontal = corr_at(residual[:, :-1], residual[:, 1:], flat[:, :-1] & flat[:, 1:])
        vertical = corr_at(residual[:-1, :], residual[1:, :], flat[:-1, :] & flat[1:, :])
        smooth_fraction = float((np.abs(lap) < 2.0).mean())
        return {
            "available": True,
            "neighbor_residual_corr": round(float((horizontal + vertical) / 2.0), 5),
            "horizontal_residual_corr": round(horizontal, 5),
            "vertical_residual_corr": round(vertical, 5),
            "very_smooth_pixel_fraction": round(smooth_fraction, 5),
            "detail": "Neighbor residual correlation and smooth-pixel fraction measured",
        }
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "Transformation-history analysis failed"}


def _screen_capture_context(rgb: np.ndarray, original_dims: tuple[int, int] | None = None) -> dict:
    """Estimate whether the file retains display/screen-capture characteristics.

    This is intentionally separate from AI evidence.  A screenshot of an AI
    image is still a screenshot, but a tightly cropped screenshot may leave no
    recoverable capture trace at all.
    """
    try:
        h, w = rgb.shape[:2]
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
        gx = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
        gy = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
        mag = np.hypot(gx, gy)
        edge = mag > np.percentile(mag, 82)
        axis_aligned = ((np.abs(gx) > 2.0 * (np.abs(gy) + 1e-6)) |
                        (np.abs(gy) > 2.0 * (np.abs(gx) + 1e-6)))
        axis_ratio = float(axis_aligned[edge].mean()) if edge.any() else 0.0

        band = max(2, min(h, w) // 50)
        border = np.concatenate([
            gray[:band, :].ravel(), gray[-band:, :].ravel(),
            gray[:, :band].ravel(), gray[:, -band:].ravel(),
        ])
        interior = gray[band:-band, band:-band] if h > 2 * band and w > 2 * band else gray
        border_std = float(border.std())
        interior_std = float(interior.std())
        border_uniformity = float(np.clip(1.0 - border_std / (interior_std + 1e-6), 0.0, 1.0))
        border_contrast = float(abs(border.mean() - interior.mean()))

        common_display = {
            (1920, 1080), (1366, 768), (1440, 900), (1536, 864), (1280, 720),
            (1080, 1920), (1170, 2532), (828, 1792), (1284, 2778),
        }
        source_w, source_h = original_dims or (w, h)
        common_size = int(
            (source_w, source_h) in common_display or
            (source_h, source_w) in common_display
        )
        # A display-like score needs more than a common resolution: axis-aligned
        # edges and a coherent border are required to avoid labelling exports.
        score = 0.45 * axis_ratio + 0.35 * border_uniformity + 0.20 * common_size
        likely = bool(score >= 0.68 and border_contrast >= 8.0)
        return {
            "available": True,
            "axis_aligned_edge_ratio": round(axis_ratio, 5),
            "border_uniformity": round(border_uniformity, 5),
            "border_contrast": round(border_contrast, 5),
            "common_display_dimensions": bool(common_size),
            "screen_capture_score": round(float(score), 5),
            "likely_screen_capture": likely,
            "detail": (
                f"axis-aligned edges={axis_ratio:.3f}, border uniformity={border_uniformity:.3f}, "
                f"display-size match={bool(common_size)}"
            ),
        }
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "Screen-capture context analysis failed"}


def _content_style(rgb: np.ndarray) -> dict:
    """Separate stylized/illustrated appearance from camera authenticity.

    Ghibli-like art, paintings, cartoons, and heavily graded photographs can all
    be stylized.  This signal prevents the UI from calling such an image
    "authentic" merely because no watermark was found; it does not call it AI.
    """
    try:
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY).astype(np.float64)
        hsv = cv2.cvtColor(rgb, cv2.COLOR_RGB2HSV).astype(np.float64)
        lap = np.abs(cv2.Laplacian(gray, cv2.CV_64F))
        flat_fraction = float((lap < 2.0).mean())
        saturation = float(hsv[:, :, 1].mean() / 255.0)
        # Quantized palette occupancy approximates broad, posterized regions.
        quantized = (rgb // 32).reshape(-1, 3)
        _, counts = np.unique(quantized, axis=0, return_counts=True)
        palette_concentration = float(counts.max() / max(1, quantized.shape[0]))
        style_score = float(np.clip(
            0.55 * flat_fraction + 0.25 * saturation + 0.20 * palette_concentration,
            0.0, 1.0))
        stylized = bool(style_score >= 0.62)
        return {
            "available": True,
            "flat_region_fraction": round(flat_fraction, 5),
            "mean_saturation_normalized": round(saturation, 5),
            "palette_concentration": round(palette_concentration, 5),
            "stylized_score": round(style_score, 5),
            "stylized_or_illustrated": stylized,
            "detail": "Flat-region, saturation, and quantized-palette context features measured",
        }
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "Content-style analysis failed"}


def _finding(counter, title, severity, confidence, evidence, interpretation,
             evidence_direction="CONTEXT", evidence_family="forensics") -> dict:
    counter["n"] += 1
    return {
        "id": f"F-{counter['n']:03d}",
        "category": "Forensics",
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "interpretation": interpretation,
        "evidence_direction": evidence_direction,
        "evidence_family": evidence_family,
    }


def analyze(path: str) -> dict:
    counter = {"n": 0}
    out = {
        "ela": {"available": False},
        "noise": {"available": False},
        "compression": {"available": False},
        "edges": {"available": False},
        "frequency": {"available": False},
        "dct": {"available": False},
        "color_banding": {"available": False},
        "texture_uniformity": {"available": False},
        "saturation": {"available": False},
        "noise_correlation": {"available": False},
        "channel_correlation": {"available": False},
        "transformation_history": {"available": False},
        "screen_capture": {"available": False},
        "content_style": {"available": False},
        "findings": [],
        "summary": "",
    }
    try:
        rgb, dims = _prepare(path)
    except Exception as exc:  # noqa: BLE001
        out["summary"] = f"Forensic analysis could not read the image: {exc}"
        out["findings"].append(_finding(
            counter, "Forensic analysis unavailable", "Informational", "Low",
            "Image could not be decoded for forensic processing.",
            "Forensic signals could not be computed; this does not indicate authenticity or AI generation."))
        return out

    ela = _ela(rgb)
    noise = _noise(rgb)
    comp = _compression(path, rgb, dims)
    edges = _edges(rgb)
    freq = _frequency(rgb)
    dct = _dct_analysis(rgb)
    banding = _color_banding(rgb)
    texture = _texture_uniformity(rgb)
    sat = _saturation_analysis(rgb)
    noise_corr = _noise_correlation(rgb)
    channel_corr = _channel_correlation(rgb)
    transform = _transformation_history(rgb)
    capture = _screen_capture_context(rgb, dims)
    style = _content_style(rgb)
    out.update(ela=ela, noise=noise, compression=comp, edges=edges, frequency=freq,
               dct=dct, color_banding=banding, texture_uniformity=texture, saturation=sat,
               noise_correlation=noise_corr, channel_correlation=channel_corr,
               transformation_history=transform, screen_capture=capture,
               content_style=style)

    # --- Threshold-gated, clearly-caveated findings ---
    if ela.get("available") and ela["mean"] > 15:
        out["findings"].append(_finding(
            counter, "Potential JPEG recompression anomaly", "Low", "Low",
            f"ELA residual mean {ela['mean']} exceeds the expected single-recompression range.",
            "ELA detects recompression differences. This may indicate prior saving/editing history, "
            "but ELA is heavily influenced by JPEG compression and cannot prove manipulation or AI generation."))

    if noise.get("available") and noise["regional_consistency_cv"] > 0.6:
        out["findings"].append(_finding(
            counter, "Potential regional noise inconsistency", "Low", "Low",
            f"Noise variance differs across regions (CV={noise['regional_consistency_cv']}).",
            "This may indicate different processing histories or local modifications. The cause cannot be "
            "determined from this signal alone and it does not establish AI generation."))

    if noise.get("available") and noise["global_level"] < 50:
        out["findings"].append(_finding(
            counter, "Unusually low noise level", "Low", "Low",
            f"Global noise level {noise['global_level']} is very low, suggesting heavy smoothing.",
            "AI-generated images often have unnaturally low noise due to denoising in the generation "
            "pipeline. However, low noise can also result from compression or post-processing."))

    if edges.get("available") and (edges["edge_density"] < 0.005 or edges["edge_density"] > 0.30):
        out["findings"].append(_finding(
            counter, "Unusual edge distribution", "Low", "Low",
            f"Edge density {edges['edge_density']} is outside the typical photographic range.",
            "Unusual edge density can reflect stylization, illustration, or heavy processing. It is not proof "
            "of AI generation."))

    if freq.get("available") and (freq["high_frequency_ratio"] < 0.02 or freq["high_frequency_ratio"] > 0.50):
        out["findings"].append(_finding(
            counter, "Unusual frequency characteristics", "Low", "Low",
            f"High-frequency energy ratio {freq['high_frequency_ratio']} is atypical.",
            "Atypical frequency content may relate to synthetic generation, smoothing, or compression. "
            "This single signal cannot establish whether the image is AI-generated."))

    if dct.get("available") and dct["dc_uniformity_cv"] < 0.15:
        out["findings"].append(_finding(
            counter, "Unusually uniform DCT coefficients", "Low", "Low",
            f"DCT DC coefficient uniformity (CV={dct['dc_uniformity_cv']}) is very low.",
            "AI-generated images often have unnaturally uniform DCT coefficients due to the "
            "generation process. This is a heuristic signal, not proof of AI generation."))

    if dct.get("available") and dct["ac_energy"] < 0.5:
        out["findings"].append(_finding(
            counter, "Suppressed high-frequency DCT energy", "Low", "Low",
            f"DCT AC energy {dct['ac_energy']} is very low, suggesting heavy smoothing.",
            "AI-generated images often have suppressed high-frequency DCT energy. This can also "
            "result from compression or blur."))

    if banding.get("available") and banding["zero_bins"] > 30:
        out["findings"].append(_finding(
            counter, "Color banding detected", "Low", "Low",
            f"Histogram has {banding['zero_bins']} empty bins, indicating gradient banding.",
            "Color banding in smooth gradients (sky, skin, backgrounds) is common in AI-generated "
            "images. It can also occur from heavy JPEG compression."))

    if texture.get("available") and texture["mean_variance"] < 100:
        out["findings"].append(_finding(
            counter, "Overly smooth texture", "Low", "Low",
            f"Mean local variance {texture['mean_variance']} is very low, indicating unnaturally smooth regions.",
            "AI-generated images often have overly smooth, unnaturally uniform texture. This can "
            "also result from heavy blur or denoising."))

    if texture.get("available") and texture["uniformity_ratio"] > 0.5:
        out["findings"].append(_finding(
            counter, "Unnaturally uniform texture", "Low", "Low",
            f"{texture['uniformity_ratio'] * 100:.0f}% of regions have very low variance.",
            "A high proportion of very low-variance regions suggests unnaturally uniform texture, "
            "common in AI-generated images. Natural photos typically have more texture variation."))

    if sat.get("available") and sat["mean_saturation"] > 150 and sat["std_saturation"] < 40:
        out["findings"].append(_finding(
            counter, "Unnaturally saturated colors", "Low", "Low",
            f"Mean saturation {sat['mean_saturation']} is high with low variance ({sat['std_saturation']}).",
            "AI-generated images often have unnaturally vivid, uniform color saturation. This can "
            "also result from aggressive color grading."))

    # Published noise-correlation-style observation.  A single threshold is
    # intentionally not enough to label an image AI: these statistics also
    # change after screenshots, resizing, JPEG export, and denoising.
    if noise_corr.get("available") and noise_corr.get("selected_blocks", 0) >= 16:
        inter = noise_corr.get("inter_block_abs_corr", 0.0)
        channel = noise_corr.get("residual_channel_abs_corr", 0.0)
        if inter >= 0.55 or channel >= 0.55:
            out["findings"].append(_finding(
                counter, "Structured residual-noise correlation", "Low", "Low",
                noise_corr["detail"],
                "High-pass residuals show stronger-than-expected correlation in selected "
                "low-content blocks. This can be associated with synthetic pipelines, but "
                "also occurs after display capture, resizing, denoising, and compression; "
                "it is not a provider or AI proof."))

    if channel_corr.get("available") and channel_corr.get("high_pass_mean_abs_corr", 0.0) >= 0.55:
        out["findings"].append(_finding(
            counter, "Correlated high-pass color channels", "Low", "Low",
            f"High-pass RGB mean absolute correlation is "
            f"{channel_corr['high_pass_mean_abs_corr']:.3f}.",
            "Color-channel residual correlation is a useful forensic feature, not a "
            "universal AI signature. Camera processing, screenshots, and image editing "
            "can produce the same observation."))

    if transform.get("available"):
        neighbor = transform.get("neighbor_residual_corr", 0.0)
        smooth = transform.get("very_smooth_pixel_fraction", 0.0)
        if neighbor >= 0.55 or smooth >= 0.72:
            out["findings"].append(_finding(
                counter, "Possible resampling or smoothing history", "Low", "Low",
                f"Neighbor residual correlation={neighbor:.3f}; very-smooth pixel "
                f"fraction={smooth:.3f}.",
                "The image has characteristics consistent with resizing, display capture, "
                "denoising, or other transformation. This is context—not evidence that the "
                "underlying artwork is AI-generated.",
                evidence_direction="CONTEXT", evidence_family="transformation"))

    if capture.get("available") and capture.get("likely_screen_capture"):
        out["findings"].append(_finding(
            counter, "Possible screen-capture or display-export context", "Informational", "Low",
            capture["detail"],
            "The file retains display-like characteristics. A screenshot may contain an "
            "AI-generated image, an authentic image, or neither; this signal cannot recover "
            "the source artwork's origin. A tightly cropped screenshot may leave no detectable "
            "capture trace.", evidence_direction="CONTEXT", evidence_family="transformation"))

    if style.get("available") and style.get("stylized_or_illustrated"):
        out["findings"].append(_finding(
            counter, "Stylized or illustrated visual characteristics", "Informational", "Low",
            f"Stylized-context score={style['stylized_score']:.3f}; "
            f"flat-region fraction={style['flat_region_fraction']:.3f}.",
            "The image appears stylized or illustrated rather than behaving like a typical "
            "camera photograph. This is not an AI finding: hand-drawn art, paintings, anime, "
            "filters, and AI-generated art can all produce this result.",
            evidence_direction="CONTEXT", evidence_family="content_style"))

    n = len(out["findings"])
    out["summary"] = (
        f"Forensic analysis complete. {n} observation(s) flagged for review; "
        "all are heuristic observations, not conclusions."
    )
    return out