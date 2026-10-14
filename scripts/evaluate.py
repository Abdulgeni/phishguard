"""Evaluate a saved model against a held-out normalized dataset.

    python -m scripts.evaluate --input data/normalized.parquet --model artifacts/model.joblib

Exits 0 if F1 >= MIN_F1, else 1.
"""

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final, Protocol

os.environ.setdefault("PYTHONHASHSEED", "0")

import joblib
import numpy as np
import pandas as pd

from app.config import get_settings
from app.data.loader import DEFAULT_NORMALIZED_PATH, load_normalized
from app.features.host import HostFeatureExtractor
from app.features.normalize import InvalidUrlError, normalize_url
from app.features.pipeline import FEATURE_NAMES, Budget, extract_features
from app.services.clock import SystemClock
from app.training.metrics import compute_metrics, confusion

DEFAULT_MIN_F1: Final = 0.90


class EvaluateError(ValueError):
    """A fail-loudly evaluation condition."""


class Probabilistic(Protocol):
    """Minimal interface for the model we load from disk."""

    def predict_proba(self, x: pd.DataFrame) -> np.ndarray: ...


def _load_bundle(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise EvaluateError(f"model not found: {path} (run scripts/train.py first)")
    bundle = joblib.load(path)
    if not isinstance(bundle, dict) or "pipeline" not in bundle or "feature_names" not in bundle:
        raise EvaluateError(f"model artifact at {path} is malformed")
    return bundle


def _featurize(frame: pd.DataFrame, feature_names: list[str]) -> tuple[pd.DataFrame, pd.Series]:
    clock = SystemClock()
    host = HostFeatureExtractor(clock=clock, whois_disabled=True)
    rows: list[dict[str, int]] = []
    keep: list[int] = []
    for idx, raw in enumerate(frame["url"].tolist()):
        try:
            url = normalize_url(raw)
        except InvalidUrlError:
            continue
        feats = extract_features(url, budget=Budget.start(clock, 3.0), host_extractor=host)
        rows.append(feats)
        keep.append(idx)
    if not rows:
        raise EvaluateError("no rows survived normalization")
    features = pd.DataFrame(rows, columns=feature_names)
    return features, frame.iloc[keep]["label"].reset_index(drop=True)


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate a saved phishing URL classifier.")
    parser.add_argument(
        "--input",
        type=Path,
        help="normalized parquet (default: $EVAL_DATASET_PATH)",
    )
    parser.add_argument("--model", type=Path, default=Path("artifacts/model.joblib"))
    parser.add_argument("--min-f1", type=float, default=DEFAULT_MIN_F1)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        settings = get_settings()
        min_f1 = args.min_f1 if args.min_f1 != DEFAULT_MIN_F1 else settings.min_f1
        source = args.input if args.input is not None else settings.eval_dataset_path
        if source is None:
            raise EvaluateError("no input: pass --input or set EVAL_DATASET_PATH")
        path = source if source.is_file() else DEFAULT_NORMALIZED_PATH
        frame = load_normalized(path)
        bundle = _load_bundle(args.model)

        raw_names = bundle["feature_names"]
        if not isinstance(raw_names, list):
            raise EvaluateError("model artifact has non-list feature_names")
        feature_names = [str(name) for name in raw_names]
        if feature_names != list(FEATURE_NAMES):
            raise EvaluateError(
                f"model feature contract mismatch: artifact has {feature_names}, "
                f"code expects {list(FEATURE_NAMES)}"
            )

        x, y = _featurize(frame, feature_names)
        model = bundle["pipeline"]
        if not hasattr(model, "predict_proba"):
            raise EvaluateError("model artifact pipeline has no predict_proba")
        proba = model.predict_proba(x)[:, 1]
        metrics = compute_metrics(y.to_numpy(), proba)
        cm = confusion(y.to_numpy(), proba)
    except (EvaluateError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"rows: {len(y)}  benign: {int((y == 0).sum())}  phishing: {int((y == 1).sum())}")
    print(
        f"precision: {metrics['precision']:.4f}"
        f"  recall: {metrics['recall']:.4f}"
        f"  f1: {metrics['f1']:.4f}"
        f"  roc_auc: {metrics['roc_auc']:.4f}"
        f"  brier: {metrics['brier']:.4f}"
    )
    print(f"confusion: {cm}")

    if metrics["f1"] < min_f1:
        print(
            f"FAIL: F1 {metrics['f1']:.4f} < MIN_F1 {min_f1:.4f}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
