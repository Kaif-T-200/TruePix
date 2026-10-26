# TruePix

**AI Image Authenticity & Forensic Analysis** — *See the truth behind every pixel.*

A lightweight, CPU-only digital-forensics tool that combines content provenance,
metadata, and computer-vision heuristics into an evidence-based assessment of
image authenticity.

## Quick Start — Windows

1. Install Python 3.11+ and the dependencies once:
   ```bat
   pip install -r requirements.txt
   ```
2. Double-click **`Start_TruePix.bat`**. It installs requirements if needed,
   starts Streamlit, and opens your browser at `http://localhost:8501`.

To stop: close the launcher terminal, or run **`Stop_TruePix.bat`**.

> The launcher keeps Streamlit as a child of its console window, so closing the
> window terminates the server and releases the port. `Stop_TruePix.bat` stops
> only the TruePix Streamlit process (never unrelated Python processes).

## Privacy & Processing Model

- **Default mode is local-first.** No images leave the machine by default. All
  upload handling, metadata, C2PA scanning, image forensics, visual-artifact
  analysis, and the evidence/risk engine run locally on CPU.
- The tool never makes network calls. All analysis is performed on-device.

### Optional trained local detector

The default installation does not load a model and does not download anything.
For higher recall on some newer diffusion images, you may explicitly download a
compatible Hugging Face image-classification model (for example
`Organika/sdxl-detector`, which is trained primarily on SDXL-vs-Wikimedia pairs):

```bat
hf download Organika/sdxl-detector --local-dir models\sdxl-detector
```

Then set `TRUEPIX_LOCAL_MODEL_PATH` in `.env` to that directory. TruePix loads it
with `local_files_only=True`, so a configured run remains offline. If the model
uses opaque labels, set `TRUEPIX_LOCAL_AI_LABEL` and
`TRUEPIX_LOCAL_AUTHENTIC_LABEL` explicitly; TruePix will otherwise return an
uncertain detector result instead of guessing which class means AI.

For stronger *non-definitive* model evidence, configure two or more downloaded
models with `TRUEPIX_LOCAL_MODEL_PATHS`, separated by commas. TruePix reports
`HIGH_CONFIDENCE_AI_LIKELY` only when at least two completed models agree with
high confidence. Model agreement is not proof because models can share training
data and blind spots.

### Optional CLIP zero-shot probe (opt-in)

Behind `TRUEPIX_ENABLE_CLIP=1`, TruePix can additionally score the image against
paired prompts (`"a real photograph"` vs `"an AI-generated image"`) using a
locally downloaded `openai/clip-vit-base-patch32` (`TRUEPIX_CLIP_MODEL_PATH`,
default `models/clip-vit-base-patch32`, loaded with `local_files_only=True`).
The raw softmax mass share ("AI share") is normalized into low/medium/high
bands and joined into the local-detector ensemble. **CLIP is not a forensic
tool** — it measures prompt-image similarity, not generation origin, and its
contribution is non-definitive by construction. When the flag is unset the
probe never loads and contributes nothing.

### Verdict policy

- `PROVEN_AI_GENERATION` — only an explicitly AI-generative claim in
  cryptographically verified C2PA provenance. This is the sole definitive
  verdict, and it applies to the signed provenance claim—not necessarily every
  later-edited pixel.
- `HIGH_CONFIDENCE_AI_LIKELY` — independent configured local classifiers agree;
  still not proof and not a calibrated probability.
- `POSSIBLE_AI_GENERATION` — suggestive metadata, detector, or forensic evidence
  without trusted provenance or model consensus.
- `ORIGIN_UNKNOWN` / `INCONCLUSIVE` — TruePix abstains when evidence is weak or
  conflicting. A missing watermark, C2PA record, or metadata never proves that an
  image is authentic.

This detector is an additional, non-calibrated evidence source. Its published
training scope is SDXL versus Wikimedia imagery, so it can misclassify other
generators, screenshots, edits, and stylized artwork. It cannot identify a
specific provider and cannot establish the origin of a tightly cropped image.

## Content Credentials (C2PA)

TruePix distinguishes three states clearly:

- **Verified** — provenance was detected *and* cryptographically verified. Strong
  evidence (e.g., a verified AI-generation claim is strong provenance evidence,
  but a verified *editing* claim does **not** by itself mean AI-generated).
- **Present — Unverified** — provenance structures were found, but verification
  was not performed. Not the same as verified truth.
- **Not found** — no C2PA data detected. The absence of credentials does **not**
  prove an image is authentic or AI-generated.

TruePix never performs cryptographic C2PA verification itself and never reports
`VERIFIED` from real scanned bytes; that state exists only for clearly-marked
test fixtures.

## Analysis signals and their limits

Every signal family has a documented maximum contribution ("cap") in
`src/risk_engine.py`. Weak, confound-heavy families get deliberately low caps so
a single heuristic can never move a verdict on its own.

| Signal | What it observes | Direction | Key confounds |
| --- | --- | --- | --- |
| Metadata forensics | Generator/editor software strings, history chains | AI indicator (only explicit software evidence) | stripped or forged metadata |
| C2PA / Content Credentials | Signed provenance claims | Definitive **only** when cryptographically verified | unverified manifests are context |
| Image forensics (ELA, noise, edges) | Recompression residuals, noise consistency | Context / weak indicators | edits, screenshots, re-encodes |
| Spectral profile | Radial energy falloff, mid-band suppression, azimuthal uniformity | Context only | smoothing, upscaling, heavy JPEG |
| Copy-move detection | Duplicate 8×8 DCT-signature block regions with a consistent offset | Neutral (suspicious for AI *and* manual edits) | genuine repeats (textures, tiled UI) |
| JPEG compression history | Prior-JPEG quality estimate via recompression sweep + detrended dip; 8×8 grid strength | Context only — **never** an AI sign | any screenshot, messenger app, or re-save |
| CFA / demosaicing signature | 2-pixel-period correlation in G−(R+B)/2 residuals | Detection weakly supports a camera pipeline; absence is recorded as explicitly **not** evidence of AI | resizes, crops, heavy processing erase it; some phones too |
| Visual artifacts | Diffusion-style textures, structural repetition | Context | stylized art, compression |
| Local classifier ensemble | Trained-model opinion(s), optional CLIP probe | Non-definitive model evidence | training-distribution blind spots |

Two policy rules these tables enforce:

- **Absence is never evidence.** A missing watermark, missing C2PA record,
  missing metadata, *or* a missing CFA/JPEG signature is recorded as neutral
  context with an explicit statement that it does not indicate AI generation.
- **Compression history proves nothing about origin.** A detected JPEG past
  describes the file's transformation chain (screenshot, messenger, edit), not
  whether the depicted content was machine-generated.

## Features

- **Single-image workspace** with per-module cards: image facts, metadata,
  Content Credentials, forensics, visual artifacts, detector ensemble,
  compression history, CFA signature, and the consolidated evidence report.
- **JSON + PDF export** (`reports/json_report.py`, `src/reports/pdf_report.py`)
  carrying the schema version, SHA-256, per-module findings kept at full
  fidelity for auditability, the limitations list, and the exact disclaimer
  shown in the UI.
- **Batch mode** — drop many files, analyze sequentially on CPU, review the
  summary table, download it as CSV. One failing file never aborts the batch.
- **Compare view** — side-by-side metric table for two images with independent
  verdicts. Comparison is for human eyes; there is deliberately no combined
  verdict.
- **Session case history** in the sidebar (click to reopen a case; size
  configurable in Settings, session-only by design).
- **Settings page** — export toggles, history size, and a live view of module /
  environment status (never secrets).

## Status

- Phase 1: upload, preview, validation — done
- Phase 2: image information + hashing — done
- Phase 3: metadata forensics — done
- Phase 4: C2PA / Content Credentials — done
- Phase 5: image forensics — done
- Phase 6: visual artifact analysis — done
- Phase 7: AI detector abstraction — done
- Phase 8: evidence / risk engine — done
- Phase 10: improved Content Credentials UI — done
- UI/UX + Windows launcher — done
- Improvement phase A: modular UI (`src/ui/`), extracted analysis pipeline — done
- Improvement phase B: JSON/PDF reports, batch mode, compare view,
  case history, real Settings — done
- Improvement phase C: JPEG compression history, copy-move detection,
  spectral profile, CFA detector, opt-in CLIP probe — done

## Running the tests

```bat
python -m pytest tests/
```

The suite (115 tests) includes synthetic fixtures for every detector: JPEG
files saved at known qualities to verify the compression-history estimate, a
mosaicked-and-demosaiced image that must trip the CFA detector while a
direct-RGB control does not, and risk-engine assertions that no single weak
signal can move the verdict past `POSSIBLE_AI_GENERATION`.