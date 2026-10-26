"""Visual artifact analysis for TruePix (Phase 6).

Lightweight, CPU-only, OpenCV/NumPy/Pillow only. Produces *observations* about
potential visual inconsistencies (texture, repetition, illumination, color/skin
consistency). Findings are deliberately low-severity and never conclude AI
generation -- combination of signals is deferred to the Phase 8 risk engine.

Anatomical/landmark detection is intentionally marked UNAVAILABLE: reliable hand
or body-part analysis needs a dedicated vision model, which is out of scope for a
lightweight CPU-only tool. Faking it would be worse than honest non-support.
"""

from __future__ import annotations

import base64
import io

import cv2
import numpy as np
from PIL import Image

MAX_SIDE = 512


def _prepare(path: str) -> np.ndarray:
    img = Image.open(path)
    img.load()
    rgb = np.array(img.convert("RGB"), dtype=np.uint8)
    h, w = rgb.shape[:2]
    long = max(h, w)
    if long > MAX_SIDE:
        scale = MAX_SIDE / long
        rgb = cv2.resize(rgb, (max(1, int(w * scale)), max(1, int(h * scale))))
    return rgb


def _texture(rgb: str) -> dict:
    """Local texture consistency via per-block Laplacian variance."""
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    h, w = gray.shape
    bs = max(16, min(h, w) // 8)
    vals = []
    for y in range(0, h - bs, bs):
        for x in range(0, w - bs, bs):
            vals.append(cv2.Laplacian(gray[y:y + bs, x:x + bs], cv2.CV_64F).var())
    vals = np.array(vals, dtype=np.float64)
    if vals.size < 2:
        return {"available": False, "reason": "image too small for texture grid"}
    cv = float(vals.std() / (vals.mean() + 1e-9))
    return {
        "available": True,
        "block_texture_cv": round(cv, 4),
        "min_block": round(float(vals.min()), 4),
        "max_block": round(float(vals.max()), 4),
    }


def _repetition(rgb: str):
    """Block-based copy-move detection via quantized DCT signatures.

    Method (Popescu & Farid style, simplified for CPU):
      1. Tile the luminance channel into overlapping 8×8 blocks.
      2. Sign each block by its 8 lowest-frequency DCT coefficients,
         quantized to suppress noise.
      3. Group identical signatures; keep groups with ≥2 blocks that are
         spatially separated (offset distance above a minimum) so natural
         smooth areas don't match themselves.
      4. Cluster matches by shared offset vector — true copy-move pairs
         share one dominant offset.

    Returns metrics plus overlay context for visualization.
    """
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    h, w = gray.shape
    bs = 8

    # Cap total blocks so worst-case cost stays bounded on large images.
    stride = 4 if max(h, w) <= 512 else 8
    ys = list(range(0, h - bs + 1, stride))
    xs = list(range(0, w - bs + 1, stride))
    if len(ys) * len(xs) > 12000:
        # Subsample grid positions deterministically.
        keep_y = np.linspace(0, len(ys) - 1, min(len(ys), 110)).astype(int)
        keep_x = np.linspace(0, len(xs) - 1, min(len(xs), 110)).astype(int)
        ys = [ys[i] for i in sorted(set(keep_y.tolist()))]
        xs = [xs[i] for i in sorted(set(keep_x.tolist()))]

    f = np.fft.fftn  # noqa: F841  (kept local; real work is cv2.dct below)
    coords: list[tuple[int, int]] = []
    sigs: list[np.ndarray] = []
    for y in ys:
        for x in xs:
            blk = gray[y:y + bs, x:x + bs].astype(np.float64)
            dct = cv2.dct(blk)
            # Keep the 8 lowest-frequency coefficients (zig-zag start of
            # the row-major matrix), quantize with a step that tolerates
            # re-noise but preserves structure.
            low = dct.flatten()[:8] / 16.0
            sigs.append(np.round(low).astype(np.int16))
            coords.append((x, y))

    n = len(coords)
    if n < 8:
        return {
            "available": True, "blocks_compared": n,
            "duplicate_found": False, "match_groups": 0,
            "dominant_offset": None,
        }, None

    # Group by identical signature.
    from collections import defaultdict
    groups: dict[bytes, list[int]] = defaultdict(list)
    for i, s in enumerate(sigs):
        groups[s.tobytes()].append(i)

    # Candidate pairs within same-signature groups, separated in space.
    min_sep = bs * 2  # ignore trivially adjacent overlaps
    offset_votes: dict[tuple[int, int], list[tuple[int, int]]] = defaultdict(list)
    for members in groups.values():
        if len(members) < 2 or len(members) > 40:
            continue  # huge groups are flat sky/walls, not copies
        for a in range(len(members)):
            for b in range(a + 1, len(members)):
                i, j = members[a], members[b]
                dx = coords[j][0] - coords[i][0]
                dy = coords[j][1] - coords[i][1]
                if (dx * dx + dy * dy) ** 0.5 < min_sep:
                    continue
                # Normalize offset direction so (i→j) and (j→i) vote together.
                if (dx, dy) < (0, 0):
                    dx, dy = -dx, -dy
                    i, j = j, i
                offset_votes[(dx, dy)].append((i, j))

    if not offset_votes:
        return {
            "available": True, "blocks_compared": n,
            "duplicate_found": False, "match_groups": 0,
            "dominant_offset": None,
        }, None

    # Dominant offset = most-voted vector. A single spurious match has few
    # votes; a real copy-move region votes consistently along one offset.
    (dom_off, pairs) = max(offset_votes.items(), key=lambda kv: len(kv[1]))
    dup = len(pairs) >= 3  # need several consistent block pairs to be meaningful

    rep = {
        "available": True,
        "blocks_compared": n,
        "duplicate_found": bool(dup),
        "match_groups": len(offset_votes),
        "dominant_offset": [int(dom_off[0]), int(dom_off[1])] if dup else None,
        "consistent_pairs": len(pairs) if dup else 0,
    }
    ctx = (rgb, pairs[:40], coords, dup, bs)
    return rep, ctx


def _illumination(rgb: str) -> dict:
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    h, w = gray.shape
    bs = max(16, min(h, w) // 8)
    means = []
    for y in range(0, h - bs, bs):
        for x in range(0, w - bs, bs):
            means.append(gray[y:y + bs, x:x + bs].mean())
    means = np.array(means, dtype=np.float64)
    if means.size < 2:
        return {"available": False, "reason": "image too small for illumination grid"}
    cv = float(means.std() / (means.mean() + 1e-9))
    return {"available": True, "local_brightness_cv": round(cv, 4)}


def _color_consistency(rgb: str) -> dict:
    """Conservative skin-pixel ratio (informational only, no conclusion)."""
    ycrcb = cv2.cvtColor(rgb, cv2.COLOR_RGB2YCR_CB)
    cr, cb = ycrcb[:, :, 1], ycrcb[:, :, 2]
    skin = ((cr >= 133) & (cr <= 173) & (cb >= 77) & (cb <= 127)).mean()
    return {"available": True, "skin_pixel_ratio": round(float(skin), 4)}


def _anatomical() -> dict:
    return {
        "available": False,
        "status": "UNAVAILABLE",
        "reason": (
            "Reliable anatomical landmark detection requires a dedicated vision "
            "model and is intentionally not enabled in the lightweight CPU-only "
            "configuration."
        ),
    }


def _overlay(rgb, pairs, coords, dup, bs) -> str | None:
    if not dup or not pairs:
        return None
    vis = rgb.copy()
    for i, j in pairs:
        for idx in (i, j):
            x, y = coords[idx]
            cv2.rectangle(vis, (x, y), (x + bs, y + bs), (255, 0, 0), 1)
    buf = io.BytesIO()
    Image.fromarray(vis).save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _finding(counter, title, severity, confidence, evidence, interpretation,
             evidence_direction="CONTEXT") -> dict:
    counter["n"] += 1
    return {
        "id": f"F-{counter['n']:03d}",
        "category": "Visual Artifacts",
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "interpretation": interpretation,
        "evidence_direction": evidence_direction,
    }


def analyze(path: str) -> dict:
    counter = {"n": 0}
    out = {
        "available": True,
        "checks": {},
        "findings": [],
        "summary": "",
        "artifact_overlay_b64": None,
    }
    try:
        rgb = _prepare(path)
    except Exception as exc:  # noqa: BLE001
        out["available"] = False
        out["summary"] = f"Artifact analysis could not read the image: {exc}"
        return out

    texture = _texture(rgb)
    rep, rep_ctx = _repetition(rgb)
    illum = _illumination(rgb)
    color = _color_consistency(rgb)
    anat = _anatomical()
    out["checks"] = {
        "texture": texture,
        "repetition": rep,
        "illumination": illum,
        "color_consistency": color,
        "anatomical": anat,
    }

    # Conservative, low-severity findings. High thresholds to limit false positives.
    if texture.get("available") and texture["block_texture_cv"] > 2.0:
        out["findings"].append(_finding(
            counter, "Potential local texture inconsistency", "Low", "Low",
            f"Texture variance varies strongly across regions (CV={texture['block_texture_cv']}).",
            "An abrupt texture change may indicate different processing histories or local "
            "modification. This single signal cannot establish AI generation."))

    if rep.get("duplicate_found"):
        off = rep.get("dominant_offset") or [0, 0]
        out["findings"].append(_finding(
            counter, "Copy-move pattern candidate detected", "Medium", "Low",
            f"{rep['consistent_pairs']} block pairs share identical quantized DCT "
            f"signatures along one offset vector ({off[0]}, {off[1]}) across "
            f"{rep['blocks_compared']} blocks examined.",
            "Multiple spatially separated regions matching along a single "
            "offset is the classic signature of copy-move editing, but it can "
            "also occur in naturally repeating architecture or foliage. This "
            "is not evidence of AI generation by itself."))
        out["artifact_overlay_b64"] = _overlay(*rep_ctx)

    if illum.get("available") and illum["local_brightness_cv"] > 1.2:
        out["findings"].append(_finding(
            counter, "Potential illumination inconsistency", "Low", "Low",
            f"Local brightness varies strongly across the image (CV={illum['local_brightness_cv']}).",
            "Lighting differences can arise naturally from complex scenes or multiple light "
            "sources. This observation does not prove manipulation or AI generation."))

    n = len(out["findings"])
    out["summary"] = (
        f"Visual artifact analysis complete. {n} observation(s) flagged for review; "
        "all are heuristic signals, not conclusions."
    )
    return out
