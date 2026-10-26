"""AI-detector abstraction layer for TruePix (Phase 7).

Defines a backend-agnostic interface so future detectors (local model, external
API, future pretrained model) can be plugged in without touching the rest of the
app. The default build has NO AI detector enabled and never fabricates a score.

Privacy: by default all analysis is local. An external detector is opt-in only,
enabled via environment variables, and never contacted unless explicitly
configured. No image is uploaded without that configuration.
"""

from __future__ import annotations

import os
import urllib.request
import urllib.error
from abc import ABC, abstractmethod

# Canonical prediction states.
AI_GENERATED = "AI_GENERATED"
LIKELY_AI = "LIKELY_AI"
LIKELY_AUTHENTIC = "LIKELY_AUTHENTIC"
UNCERTAIN = "UNCERTAIN"
UNAVAILABLE = "UNAVAILABLE"

# Status values for the detector itself.
NOT_CONFIGURED = "NOT_CONFIGURED"
AVAILABLE = "AVAILABLE"
ERROR = "ERROR"

# Environment configuration (opt-in, never hard-coded).
ENV_URL = "TRUEPIX_AI_API_URL"
ENV_KEY = "TRUEPIX_AI_API_KEY"
ENV_PROVIDER = "TRUEPIX_AI_PROVIDER"
ENV_LOCAL_MODEL = "TRUEPIX_LOCAL_MODEL_PATH"
ENV_LOCAL_MODELS = "TRUEPIX_LOCAL_MODEL_PATHS"
ENV_LOCAL_AI_LABEL = "TRUEPIX_LOCAL_AI_LABEL"
ENV_LOCAL_AUTH_LABEL = "TRUEPIX_LOCAL_AUTHENTIC_LABEL"
TIMEOUT_SECONDS = 8

# Local detector directions are intentionally strings rather than an import
# from risk_engine: this abstraction must remain usable independently.
_AI_INDICATOR = "AI_INDICATOR"
_AUTHENTICITY_SUPPORT = "AUTHENTICITY_SUPPORT"
_NEUTRAL = "NEUTRAL"


def _schema(*, available=False, status=NOT_CONFIGURED, detector=None, version=None,
            prediction=None, probability=None, confidence=None, findings=None,
            limitations=None, ensemble=None) -> dict:
    return {
        "available": available,
        "status": status,
        "detector": detector,
        "version": version,
        "prediction": prediction,
        "probability": probability,   # genuine model score only; never invented
        "confidence": confidence,      # reliability of the detector result
        "findings": findings or [],
        "limitations": limitations or [],
        "ensemble": ensemble or {},
    }


# Canonical prediction states the system itself emits (preserve these verbatim).
_CANON_PREDICTIONS = (AI_GENERATED, LIKELY_AI, LIKELY_AUTHENTIC, UNCERTAIN)


def normalize_prediction(raw) -> str:
    """Map an arbitrary detector label to a canonical prediction state."""
    s = raw or ""
    # Preserve our own canonical labels exactly.
    if s in _CANON_PREDICTIONS:
        return s
    if s == "INSUFFICIENT_EVIDENCE":  # graded verdict; treat as uncertain, not AI
        return UNCERTAIN
    sl = s.lower()
    if any(k in sl for k in ("uncertain", "unknown", "inconclusive", "insufficient",
                             "no conclusion", "inconclusive evidence")):
        return UNCERTAIN
    if any(k in sl for k in ("ai-generated", "ai generated", "generated", "fake", "synthetic")):
        return AI_GENERATED
    if any(k in sl for k in ("authentic", "real", "genuine", "photograph")):
        return LIKELY_AUTHENTIC
    return UNCERTAIN


def normalize_confidence(raw) -> str:
    """Map an arbitrary confidence label to a canonical state."""
    s = (raw or "").lower()
    if "high" in s:
        return "High"
    if "medium" in s or "moderate" in s:
        return "Medium"
    if "low" in s:
        return "Low"
    return "Unknown"


def normalize_probability(raw):
    """Return a bounded 0..1 detector score, or None when invalid."""
    if not isinstance(raw, (int, float)) or isinstance(raw, bool):
        return None
    value = float(raw)
    if value > 1:
        value /= 100.0
    return value if 0.0 <= value <= 1.0 else None


class BaseAIDetector(ABC):
    name = "abstract"
    version = None

    @abstractmethod
    def analyze(self, path: str) -> dict:
        """Return a structured AI-detector result for the image at `path`."""

    def _finding(self, prediction, probability, confidence) -> dict:
        score = f"{probability * 100:.0f}%" if isinstance(probability, (int, float)) else "not provided"
        return {
            "id": "F-AI",  # single source; risk engine will renumber/merge later
            "category": "AI Detection",
            "title": "AI detector result",
            "severity": "Low",
            "confidence": confidence or "Unknown",
            "evidence": (
                f"Configured detector '{self.name}' predicted '{prediction}' "
                f"(score: {score})."
            ),
            "interpretation": (
                "This is one optional evidence source. AI-image detectors can produce "
                "false positives and false negatives, especially for edited, compressed, "
                "resized, or novel-model images. It is not a definitive conclusion."
            ),
        }


class UnavailableDetector(BaseAIDetector):
    name = "none"
    version = None

    def analyze(self, path: str) -> dict:  # noqa: ARG002
        return _schema(
            available=False,
            status=NOT_CONFIGURED,
            limitations=["No AI detector is configured."],
        )


class ExternalApiDetector(BaseAIDetector):
    """Optional, opt-in external detector. Disabled unless URL + key are set.

    Uses only the standard library (urllib) so no networking dependency is added.
    Never logs or stores the API key beyond the outbound request header.
    """

    def __init__(self, url: str, api_key: str, provider: str | None = None):
        self.url = url
        self.api_key = api_key
        self.provider = provider or "external-api"
        self.name = f"external:{self.provider}"

    def analyze(self, path: str) -> dict:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            req = urllib.request.Request(self.url, data=data, method="POST")
            req.add_header("Content-Type", "application/octet-stream")
            req.add_header("Authorization", f"Bearer {self.api_key}")
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                import json
                payload = json.loads(resp.read().decode("utf-8"))
            return self._parse(payload)
        except urllib.error.URLError as exc:
            return _schema(
                available=False, status=ERROR, detector=self.name,
                limitations=[f"AI detector could not be reached: {exc.reason}."],
            )
        except Exception as exc:  # noqa: BLE001
            return _schema(
                available=False, status=ERROR, detector=self.name,
                limitations=[f"AI detector error: {exc}."],
            )

    def _parse(self, payload: dict) -> dict:
        raw = payload.get("prediction") or payload.get("label") or payload.get("result") or ""
        prob = next((payload[key] for key in ("probability", "score", "ai_score")
                     if key in payload and payload[key] is not None), None)
        prob = normalize_probability(prob)
        conf = payload.get("confidence")
        prediction = normalize_prediction(raw)
        finding = self._finding(prediction, prob, conf)
        return _schema(
            available=True, status=AVAILABLE, detector=self.name,
            version=self.version, prediction=prediction, probability=prob,
            confidence=conf, findings=[finding],
            limitations=["External processing was used. AI detectors may misclassify."],
        )


class LocalModelDetector(BaseAIDetector):
    """Optional local Transformers image classifier.

    The model is loaded lazily and with ``local_files_only=True``. This keeps
    the default application offline and prevents a configured detector from
    silently downloading weights during an image upload. To use it, download a
    compatible model explicitly (for example with ``hf download``), then set
    ``TRUEPIX_LOCAL_MODEL_PATH`` to that directory.

    The bundled integration is intentionally model-agnostic. It trusts semantic
    labels such as ``AI-generated``/``fake`` and ``real``/``authentic``. If a
    model exposes only opaque labels (``LABEL_0``), set the corresponding label
    environment variable rather than guessing which class means AI.
    """

    name = "local-transformers"
    version = None

    def __init__(self, model_path: str, ai_label: str | None = None,
                 authentic_label: str | None = None):
        self.model_path = os.path.abspath(os.path.expanduser(model_path))
        self.ai_label = ai_label
        self.authentic_label = authentic_label
        self._processor = None
        self._model = None
        self._torch = None
        self._load_error = None

    def _load(self):
        if self._model is not None:
            return
        if self._load_error is not None:
            raise RuntimeError(self._load_error)
        if not os.path.isdir(self.model_path):
            self._load_error = f"Local detector model path does not exist: {self.model_path}"
            raise RuntimeError(self._load_error)
        try:
            import torch
            from transformers import AutoImageProcessor, AutoModelForImageClassification

            self._torch = torch
            self._processor = AutoImageProcessor.from_pretrained(
                self.model_path, local_files_only=True)
            self._model = AutoModelForImageClassification.from_pretrained(
                self.model_path, local_files_only=True)
            self._model.eval()
            self.version = getattr(self._model.config, "_name_or_path", None) or "local"
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"Local detector could not be loaded: {exc}"
            raise RuntimeError(self._load_error) from exc

    @staticmethod
    def _canonical_label(label) -> str:
        return str(label or "").strip()

    def _label_direction(self, label: str) -> str:
        normalized = normalize_prediction(label)
        if normalized in (AI_GENERATED, LIKELY_AI):
            return _AI_INDICATOR
        if normalized == LIKELY_AUTHENTIC:
            return _AUTHENTICITY_SUPPORT
        if self.ai_label and label.lower() == self.ai_label.lower():
            return _AI_INDICATOR
        if self.authentic_label and label.lower() == self.authentic_label.lower():
            return _AUTHENTICITY_SUPPORT
        return _NEUTRAL

    def analyze(self, path: str) -> dict:
        try:
            self._load()
            from PIL import Image

            with Image.open(path) as image:
                image = image.convert("RGB")
                inputs = self._processor(images=image, return_tensors="pt")
            with self._torch.no_grad():
                logits = self._model(**inputs).logits[0]
                probabilities = self._torch.softmax(logits, dim=-1).detach().cpu().tolist()

            id2label = getattr(self._model.config, "id2label", {}) or {}
            labels = [id2label.get(i, id2label.get(str(i), f"LABEL_{i}"))
                      for i in range(len(probabilities))]
            best_index = max(range(len(probabilities)), key=probabilities.__getitem__)
            best_label = self._canonical_label(labels[best_index])
            best_score = float(probabilities[best_index])
            direction = self._label_direction(best_label)

            # Do not translate an opaque class into AI/authentic. A model with
            # opaque labels must be explicitly mapped through the environment.
            if direction == _AI_INDICATOR:
                prediction = AI_GENERATED if best_score >= 0.85 else LIKELY_AI
            elif direction == _AUTHENTICITY_SUPPORT:
                prediction = LIKELY_AUTHENTIC if best_score >= 0.65 else UNCERTAIN
            else:
                prediction = UNCERTAIN

            confidence = "High" if best_score >= 0.85 else "Medium" if best_score >= 0.65 else "Low"
            finding = self._finding(prediction, best_score, confidence)
            return _schema(
                available=True, status=AVAILABLE, detector=self.name,
                version=self.version, prediction=prediction, probability=best_score,
                confidence=confidence, findings=[finding],
                limitations=[
                    "This local classifier was trained primarily on SDXL-vs-Wikimedia pairs "
                    "and may underperform on other generators, screenshots, edits, or artwork.",
                    "Its score is model confidence, not a calibrated probability of origin.",
                ],
                ensemble={
                    "model_count": 1,
                    "ai_votes": int(direction == _AI_INDICATOR),
                    "authentic_votes": int(direction == _AUTHENTICITY_SUPPORT),
                    "agreement": 1.0,
                    "strong_consensus": False,
                    "calibration": "NOT_CALIBRATED",
                },
            )
        except Exception as exc:  # noqa: BLE001
            return _schema(
                available=False, status=ERROR, detector=self.name,
                version=self.version,
                limitations=[f"{exc}"],
            )


class ClipZeroShotDetector(BaseAIDetector):
    """Optional zero-shot probe using a locally downloaded CLIP model.

    Enabled only via ``TRUEPIX_ENABLE_CLIP=1`` plus a downloaded model
    directory at ``TRUEPIX_CLIP_MODEL_PATH`` (default
    ``models/clip-vit-base-patch32``). Loaded with ``local_files_only=True``
    so a configured run never downloads weights mid-analysis.

    The image is scored against paired prompts ("a real photograph taken
    by a camera" vs "an AI-generated synthetic image"). CLIP is NOT a
    forensic tool — it measures caption-image similarity, and its
    zero-shot judgement is heavily influenced by image style and content.
    Its vote joins the detector ensemble as one more non-calibrated,
    non-independent signal, never as proof.
    """

    name = "local-clip-zeroshot"
    version = None

    ENV_ENABLE = "TRUEPIX_ENABLE_CLIP"
    ENV_MODEL_PATH = "TRUEPIX_CLIP_MODEL_PATH"

    AI_PROMPTS = (
        "an ai-generated synthetic image",
        "a computer-generated artificial image",
    )
    AUTHENTIC_PROMPTS = (
        "a real photograph taken with a camera",
        "an authentic unedited photo of a real scene",
    )

    def __init__(self, model_path: str | None = None):
        self.model_path = os.path.abspath(os.path.expanduser(
            model_path or os.environ.get(self.ENV_MODEL_PATH)
            or os.path.join("models", "clip-vit-base-patch32")))
        self._model = None
        self._processor = None
        self._torch = None
        self._load_error = None

    @classmethod
    def is_enabled(cls) -> bool:
        return os.environ.get(cls.ENV_ENABLE, "") == "1"

    def _load(self):
        if self._model is not None:
            return
        if self._load_error is not None:
            raise RuntimeError(self._load_error)
        if not os.path.isdir(self.model_path):
            self._load_error = (f"CLIP model path does not exist: "
                                f"{self.model_path}. Download the model first.")
            raise RuntimeError(self._load_error)
        try:
            import torch
            from transformers import CLIPModel, CLIPProcessor

            self._torch = torch
            self._processor = CLIPProcessor.from_pretrained(
                self.model_path, local_files_only=True)
            self._model = CLIPModel.from_pretrained(
                self.model_path, local_files_only=True)
            self._model.eval()
            self.version = "clip-vit-base-patch32"
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"CLIP model could not be loaded: {exc}"
            raise RuntimeError(self._load_error) from exc

    def analyze(self, path: str) -> dict:
        try:
            self._load()
            from PIL import Image

            prompts = list(self.AUTHENTIC_PROMPTS) + list(self.AI_PROMPTS)
            with Image.open(path) as image:
                image = image.convert("RGB")
                inputs = self._processor(text=prompts, images=image,
                                         return_tensors="pt", padding=True)
            with self._torch.no_grad():
                outputs = self._model(**inputs)
                probs = outputs.logits_per_image.softmax(dim=1)[0].tolist()

            n_auth = len(self.AUTHENTIC_PROMPTS)
            auth_p = sum(probs[:n_auth])
            ai_p = sum(probs[n_auth:])
            total = auth_p + ai_p + 1e-12
            ai_share = ai_p / total  # 0..1 share of mass on AI prompts

            if ai_share >= 0.85:
                prediction = AI_GENERATED
            elif ai_share >= 0.65:
                prediction = LIKELY_AI
            elif ai_share <= 0.15:
                prediction = LIKELY_AUTHENTIC
            else:
                prediction = UNCERTAIN

            confidence = ("High" if (ai_share >= 0.85 or ai_share <= 0.15)
                          else "Medium" if (ai_share >= 0.65 or ai_share <= 0.35)
                          else "Low")
            finding = self._finding(prediction, round(ai_share, 4), confidence)
            return _schema(
                available=True, status=AVAILABLE, detector=self.name,
                version=self.version, prediction=prediction,
                probability=round(ai_share, 4), confidence=confidence,
                findings=[finding],
                limitations=[
                    "CLIP measures caption-image similarity; it is not trained "
                    "to distinguish real from generated content.",
                    "Style and subject strongly influence its zero-shot vote; "
                    "illustrations and unusual photos can mislead it either way.",
                    "Its score is a prompt-normalized similarity share, not a "
                    "calibrated probability of origin.",
                ],
                ensemble={
                    "model_count": 1,
                    "ai_votes": int(prediction in (AI_GENERATED, LIKELY_AI)),
                    "authentic_votes": int(prediction == LIKELY_AUTHENTIC),
                    "agreement": 1.0,
                    "strong_consensus": False,
                    "calibration": "NOT_CALIBRATED",
                },
            )
        except Exception as exc:  # noqa: BLE001
            return _schema(
                available=False, status=ERROR, detector=self.name,
                version=self.version,
                limitations=[f"{exc}"],
            )


class LocalEnsembleDetector(BaseAIDetector):
    """Run multiple explicitly downloaded local classifiers and abstain safely.

    Agreement between models is useful only as a *confidence signal*. The
    models may share training data or fail on the same distribution shift, so
    this class never calls consensus proof and never reports a calibrated
    probability. At least two independent model directories and a high score
    from every agreeing model are required for ``strong_consensus``.
    """

    name = "local-ensemble"
    version = None

    def __init__(self, model_paths: list[str], ai_label: str | None = None,
                 authentic_label: str | None = None):
        unique_paths = []
        for path in model_paths:
            normalized = os.path.abspath(os.path.expanduser(path.strip()))
            if normalized and normalized not in unique_paths:
                unique_paths.append(normalized)
        self.detectors = [LocalModelDetector(path, ai_label=ai_label,
                                             authentic_label=authentic_label)
                          for path in unique_paths]

    def analyze(self, path: str) -> dict:
        results = [detector.analyze(path) for detector in self.detectors]
        available = [result for result in results if result.get("status") == AVAILABLE]
        if not available:
            limitations = []
            for result in results:
                limitations.extend(result.get("limitations", []))
            return _schema(
                available=False, status=ERROR, detector=self.name,
                limitations=limitations or ["No local detector completed successfully."],
                ensemble={"model_count": len(results), "calibration": "NOT_CALIBRATED"},
            )

        ai_results = [result for result in available
                      if result.get("prediction") in (AI_GENERATED, LIKELY_AI)]
        authentic_results = [result for result in available
                             if result.get("prediction") == LIKELY_AUTHENTIC]
        scores = [result.get("probability") for result in ai_results
                  if isinstance(result.get("probability"), (int, float))]
        ai_high = len(ai_results) >= 2 and len(scores) == len(ai_results) and min(scores) >= 0.85
        auth_scores = [result.get("probability") for result in authentic_results
                       if isinstance(result.get("probability"), (int, float))]
        authentic_high = (len(authentic_results) >= 2 and
                          len(auth_scores) == len(authentic_results) and
                          min(auth_scores) >= 0.65)

        if ai_high and not authentic_results:
            prediction = AI_GENERATED
        elif authentic_high and not ai_results:
            prediction = LIKELY_AUTHENTIC
        elif ai_results and not authentic_results:
            # Preserve a single-model result as weak evidence, but do not call
            # it consensus. Mixed votes deliberately abstain.
            prediction = ai_results[0].get("prediction") if len(ai_results) == len(available) else UNCERTAIN
        elif authentic_results and not ai_results:
            prediction = (authentic_results[0].get("prediction")
                          if len(authentic_results) == len(available) else UNCERTAIN)
        else:
            prediction = UNCERTAIN

        model_count = len(available)
        agreement_votes = max(len(ai_results), len(authentic_results))
        agreement = agreement_votes / max(1, model_count)
        strong = bool(ai_high or authentic_high)
        confidence = "High" if strong else "Medium" if agreement >= 0.5 else "Low"
        finding = self._finding(prediction, None, confidence)
        limitations = [
            "Model agreement is not proof: classifiers can share blind spots and training bias.",
            "Scores are model confidence, not calibrated probabilities of image origin.",
            "The configured models may not cover the generator, screenshot, edit, or style in this file.",
        ]
        return _schema(
            available=True, status=AVAILABLE, detector=self.name,
            version="ensemble", prediction=prediction, probability=None,
            confidence=confidence, findings=[finding], limitations=limitations,
            ensemble={
                "model_count": model_count,
                "completed_model_count": model_count,
                "ai_votes": len(ai_results),
                "authentic_votes": len(authentic_results),
                "agreement": round(agreement, 4),
                "strong_consensus": strong,
                "consensus": prediction,
                "model_results": [
                    {
                        "detector": result.get("detector"),
                        "prediction": result.get("prediction"),
                        "confidence": result.get("confidence"),
                        "probability": result.get("probability"),
                    }
                    for result in available
                ],
                "calibration": "NOT_CALIBRATED",
            },
        )


def get_detector() -> BaseAIDetector:
    """Return the configured detector. Defaults to no detector.

    External API configuration remains backwards-compatible. Local model
    configuration is opt-in and offline-only; absent configuration never loads
    optional ML packages and never fabricates a result. When the optional CLIP
    probe is enabled (TRUEPIX_ENABLE_CLIP=1), its vote is appended to whatever
    primary detector is configured — or used alone if nothing else is.
    """
    url = os.environ.get(ENV_URL)
    key = os.environ.get(ENV_KEY)
    provider = os.environ.get(ENV_PROVIDER)
    clip_on = ClipZeroShotDetector.is_enabled()

    if url and key:
        return ExternalApiDetector(url=url, api_key=key, provider=provider)
    local_path = os.environ.get(ENV_LOCAL_MODEL)
    local_paths = [value.strip() for value in
                   os.environ.get(ENV_LOCAL_MODELS, "").split(",") if value.strip()]
    if local_paths:
        return LocalEnsembleDetector(
            local_paths,
            ai_label=os.environ.get(ENV_LOCAL_AI_LABEL),
            authentic_label=os.environ.get(ENV_LOCAL_AUTH_LABEL),
        )
    if local_path:
        return LocalModelDetector(
            local_path,
            ai_label=os.environ.get(ENV_LOCAL_AI_LABEL),
            authentic_label=os.environ.get(ENV_LOCAL_AUTH_LABEL),
        )
    if clip_on:
        return ClipZeroShotDetector()
    return UnavailableDetector()


def _read_dotenv(path: str = ".env") -> None:
    """Best-effort load of .env into os.environ (no external dependency).

    Only sets variables that are not already present. Never raises; missing
    or malformed files are ignored. Secrets stay in the process environment.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except OSError:
        pass


def analyze(path: str) -> dict:
    """Convenience: run the active detector on an image path."""
    return get_detector().analyze(path)