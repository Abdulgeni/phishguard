"""Model loading and single-URL inference.

The model is loaded once at process startup via the FastAPI lifespan and stored
on ``app.state.predictor``. Every request reads it from there. Missing model or
sklearn version mismatch fails startup loudly (design decision 15 / flaw 8).
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Protocol

import joblib
import numpy as np
import pandas as pd
import sklearn

from app.features.host import HostFeatureExtractor
from app.features.normalize import normalize_url
from app.features.pipeline import FEATURE_NAMES, Budget, extract_features
from app.services.clock import Clock

UNKNOWN = -1
PHISHING: Final = 1
BENIGN: Final = 0

Label = Literal["phishing", "benign"]


class PredictorError(RuntimeError):
    """A fail-loudly inference condition."""


class _Probabilistic(Protocol):
    def predict_proba(self, x: pd.DataFrame) -> np.ndarray: ...


@dataclass(frozen=True, slots=True)
class Verdict:
    label: Label
    confidence: float
    model_version: str
    features: dict[str, int]
    explanation: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class _Bundle:
    model: _Probabilistic
    feature_names: tuple[str, ...]
    model_version: str
    sklearn_version: str


def _load_bundle(path: Path) -> _Bundle:
    if not path.is_file():
        raise PredictorError(f"model not found at {path}; run `make train-fixture` or `make train`")
    raw = joblib.load(path)
    if not isinstance(raw, dict):
        raise PredictorError(f"model artifact at {path} is not a dict")
    for key in ("pipeline", "feature_names", "model_version", "sklearn_version"):
        if key not in raw:
            raise PredictorError(f"model artifact at {path} is missing key {key!r}")
    model = raw["pipeline"]
    if not hasattr(model, "predict_proba"):
        raise PredictorError(f"model artifact at {path} has no predict_proba")
    names = tuple(str(n) for n in raw["feature_names"])
    if names != FEATURE_NAMES:
        raise PredictorError(
            f"model feature contract mismatch: artifact has {names}, code expects {FEATURE_NAMES}"
        )
    artifact_sklearn = str(raw["sklearn_version"])
    if artifact_sklearn != sklearn.__version__:
        raise PredictorError(
            f"sklearn version mismatch: artifact {artifact_sklearn}, runtime {sklearn.__version__}"
        )
    return _Bundle(
        model=model,
        feature_names=names,
        model_version=str(raw["model_version"]),
        sklearn_version=artifact_sklearn,
    )


class Predictor:
    """Loads the model once, extracts features, and returns a verdict."""

    def __init__(
        self,
        *,
        model_path: Path,
        clock: Clock,
        host_extractor: HostFeatureExtractor,
        request_budget_seconds: float,
        enable_explanations: bool,
    ) -> None:
        self._bundle = _load_bundle(model_path)
        self._clock = clock
        self._host = host_extractor
        self._budget_seconds = request_budget_seconds
        self._enable_explanations = enable_explanations

    @property
    def model_version(self) -> str:
        return self._bundle.model_version

    def predict(self, url: str) -> Verdict:
        """Classify ``url``. Raises ``InvalidUrlError`` on unparseable input."""
        normalized = normalize_url(url)
        budget = Budget.start(self._clock, self._budget_seconds)
        features = extract_features(normalized, budget=budget, host_extractor=self._host)
        frame = pd.DataFrame([features], columns=list(FEATURE_NAMES))
        proba = self._bundle.model.predict_proba(frame)[0]
        phishing_p = float(proba[PHISHING])
        label: Label = "phishing" if phishing_p >= 0.5 else "benign"
        confidence = phishing_p if label == "phishing" else 1.0 - phishing_p
        explanation = self._explanation() if self._enable_explanations else None
        return Verdict(
            label=label,
            confidence=confidence,
            model_version=self._bundle.model_version,
            features=features,
            explanation=explanation,
        )

    def _explanation(self) -> dict[str, object] | None:
        """Global feature importances from the underlying tree, if available.

        The model may be stored in three shapes:

        * a raw estimator (e.g. ``RandomForestClassifier``),
        * a ``Pipeline([("clf", estimator)])``,
        * a ``Pipeline([("clf", CalibratedClassifierCV(...))])``.

        We walk those shapes looking for a fitted estimator that exposes
        ``feature_importances_``. If none is found, we return ``None`` — the
        explanation is best-effort.
        """
        importances = self._find_importances(self._bundle.model)
        if importances is None:
            return None
        pairs = zip(FEATURE_NAMES, importances, strict=True)
        top = sorted(pairs, key=lambda kv: kv[1], reverse=True)[:10]
        return {"global_importance": dict(top)}

    @staticmethod
    def _coerce_importances(value: object) -> tuple[float, ...] | None:
        """Convert ``feature_importances_`` to a tuple of floats, or None if unusable."""
        if value is None or not hasattr(value, "__iter__"):
            return None
        try:
            return tuple(float(v) for v in value)  # type: ignore[union-attr]
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _find_importances(model: object) -> tuple[float, ...] | None:
        """Best-effort search for ``feature_importances_`` in a saved model."""
        direct = Predictor._coerce_importances(getattr(model, "feature_importances_", None))
        if direct is not None:
            return direct
        named_steps = getattr(model, "named_steps", None)
        if isinstance(named_steps, dict):
            for step in named_steps.values():
                found = Predictor._find_importances(step)
                if found is not None:
                    return found
        calibrated = getattr(model, "calibrated_classifiers_", None)
        if isinstance(calibrated, list):
            for wrapper in calibrated:
                found = Predictor._find_importances(wrapper)
                if found is not None:
                    return found
        inner = getattr(model, "estimator", None)
        if inner is not None and inner is not model:
            return Predictor._find_importances(inner)
        return None
