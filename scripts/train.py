"""Train a phishing URL classifier and write a model artifact + model card.

    python -m scripts.train --input data/normalized.parquet --output-dir artifacts

Falls back to ``DATASET_PATH`` when ``--input`` is omitted. The WHOIS features
are disabled at train time by design (see app/features/README.md): dataset URLs
are largely dead, so WHOIS would only distinguish "dead" from "live", not
"phishing" from "benign". The model card records this limitation explicitly.
"""

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Protocol

# Enforce determinism before anything else imports the RNGs.
os.environ.setdefault("PYTHONHASHSEED", "0")

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.pipeline import Pipeline

from app.config import get_settings
from app.data.loader import DEFAULT_NORMALIZED_PATH, load_normalized
from app.features.host import HostFeatureExtractor
from app.features.normalize import InvalidUrlError, normalize_url
from app.features.pipeline import FEATURE_NAMES, Budget, extract_features
from app.services.clock import SystemClock
from app.training.metrics import compute_metrics, confusion
from app.training.split import split_dataset

RANDOM_STATE: Final = 42
TARGET_F1: Final = 0.95
CALIBRATION_BRIER_THRESHOLD: Final = 0.10
MIN_PER_CLASS: Final = 2


class TrainError(ValueError):
    """A fail-loudly training condition."""


class Probabilistic(Protocol):
    """Minimal interface every classifier we save must satisfy."""

    def fit(self, x: pd.DataFrame, y: pd.Series) -> "Probabilistic": ...

    def predict_proba(self, x: pd.DataFrame) -> np.ndarray: ...


@dataclass(frozen=True)
class Candidate:
    name: str
    estimator: Probabilistic
    val_f1: float
    val_metrics: dict[str, float | int]


def _build_host_extractor() -> HostFeatureExtractor:
    """Train-time host extractor: WHOIS disabled, shortener list still active."""
    return HostFeatureExtractor(clock=SystemClock(), whois_disabled=True)


def featurize(frame: pd.DataFrame, *, host_extractor: HostFeatureExtractor) -> pd.DataFrame:
    """Return a DataFrame of features for every row. Rows that fail to normalize are dropped."""
    clock = SystemClock()
    rows: list[dict[str, int]] = []
    keep: list[int] = []
    for idx, raw in enumerate(frame["url"].tolist()):
        try:
            url = normalize_url(raw)
        except InvalidUrlError:
            continue
        budget = Budget.start(clock, 3.0)
        feats = extract_features(url, budget=budget, host_extractor=host_extractor)
        rows.append(feats)
        keep.append(idx)
    if not rows:
        raise TrainError("no rows survived normalization")
    features = pd.DataFrame(rows, columns=list(FEATURE_NAMES))
    labels = frame.iloc[keep]["label"].reset_index(drop=True)
    return pd.concat([features, labels.rename("label")], axis=1)


def _class_balance(labels: pd.Series) -> float:
    counts = labels.value_counts()
    majority = int(counts.max())
    minority = int(counts.min())
    return majority / max(1, minority)


def _make_rf(*, balanced: bool) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        n_jobs=-1,
        random_state=RANDOM_STATE,
        class_weight="balanced" if balanced else None,
    )


def _fit_and_score(
    name: str,
    estimator: Probabilistic,
    x_train: pd.DataFrame,
    y_train: pd.Series,
    x_val: pd.DataFrame,
    y_val: pd.Series,
) -> Candidate:
    pipeline: Probabilistic = Pipeline([("clf", estimator)])
    pipeline.fit(x_train, y_train)
    proba = pipeline.predict_proba(x_val)[:, 1]
    metrics = compute_metrics(y_val.to_numpy(), proba)
    return Candidate(
        name=name,
        estimator=pipeline,
        val_f1=float(metrics["f1"]),
        val_metrics=metrics,
    )


def _choose_and_calibrate(
    candidates: list[Candidate],
    x_val: pd.DataFrame,
    y_val: pd.Series,
) -> tuple[Probabilistic, dict[str, object]]:
    winner = max(candidates, key=lambda c: c.val_f1)
    brier = float(winner.val_metrics["brier"])
    calibrated = False
    if brier > CALIBRATION_BRIER_THRESHOLD:
        frozen = FrozenEstimator(winner.estimator)
        calibrated_est = CalibratedClassifierCV(frozen, method="isotonic")
        calibrated_est.fit(x_val, y_val)
        final: Probabilistic = Pipeline([("clf", calibrated_est)])
        calibrated = True
    else:
        final = winner.estimator
    info = {
        "winner": winner.name,
        "winner_val_f1": winner.val_f1,
        "winner_val_metrics": winner.val_metrics,
        "calibrated": calibrated,
        "brier_before_calibration": brier,
        "calibration_threshold": CALIBRATION_BRIER_THRESHOLD,
    }
    return final, info


def _version() -> str:
    sha = os.environ.get("GIT_SHA", "unknown")
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{sha}-{ts}"


def _write_artifact(
    *,
    output_dir: Path,
    model: Probabilistic,
    info: dict[str, object],
    metrics: dict[str, float | int],
    confusion_matrix_: dict[str, int],
    splits_info: dict[str, object],
    dataset_name: str,
    row_counts: dict[str, int],
    class_balance: float,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    version = _version()
    trained_at = datetime.now(UTC).isoformat(timespec="seconds")
    whois_skew = (
        "WHOIS features (domain_age_days, registrar_known) are set to sentinels "
        "at train time because dataset URLs are largely dead. They carry no "
        "learned signal in this version."
    )
    bundle = {
        "pipeline": model,
        "feature_names": list(FEATURE_NAMES),
        "model_version": version,
        "trained_at": trained_at,
        "sklearn_version": sklearn.__version__,
    }
    joblib.dump(bundle, output_dir / "model.joblib")

    card = {
        "model_version": version,
        "trained_at": trained_at,
        "sklearn_version": sklearn.__version__,
        "dataset": dataset_name,
        "row_counts": row_counts,
        "class_balance_majority_over_minority": class_balance,
        "feature_names": list(FEATURE_NAMES),
        "feature_sentinels": {"numeric_unknown": -1, "boolean_unknown": 0},
        "split": splits_info,
        "model": info,
        "metrics": metrics,
        "confusion_matrix": confusion_matrix_,
        "target_f1": TARGET_F1,
        "whois_skew": whois_skew,
    }
    (output_dir / "model_card.json").write_text(
        json.dumps(card, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the phishing URL classifier.")
    parser.add_argument("--input", type=Path, help="normalized parquet (default: $DATASET_PATH)")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--random-state", type=int, default=RANDOM_STATE)
    parser.add_argument("--target-f1", type=float, default=TARGET_F1)
    parser.add_argument("--min-per-class", type=int, default=MIN_PER_CLASS)
    return parser.parse_args(argv)


def _resolve_input(cli: Path | None, env: Path | None) -> Path:
    path = cli if cli is not None else env
    if path is None:
        raise TrainError("no input: pass --input or set DATASET_PATH")
    return path


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        settings = get_settings()
        path = _resolve_input(args.input, settings.dataset_path)
        if path.is_file():
            frame = load_normalized(path)
        else:
            frame = load_normalized(DEFAULT_NORMALIZED_PATH)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        splits = split_dataset(
            frame,
            random_state=args.random_state,
            min_per_class=args.min_per_class,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    balance = _class_balance(frame["label"])
    balanced = balance > 2.0
    host = _build_host_extractor()

    try:
        train = featurize(splits.train, host_extractor=host)
        val = featurize(splits.val, host_extractor=host)
        test = featurize(splits.test, host_extractor=host)
    except TrainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    x_train, y_train = train.drop(columns="label"), train["label"]
    x_val, y_val = val.drop(columns="label"), val["label"]
    x_test, y_test = test.drop(columns="label"), test["label"]

    rf_estimator = _make_rf(balanced=balanced)
    gb_estimator = GradientBoostingClassifier(random_state=args.random_state)
    candidates = [
        _fit_and_score("random_forest", rf_estimator, x_train, y_train, x_val, y_val),
        _fit_and_score("gradient_boosting", gb_estimator, x_train, y_train, x_val, y_val),
    ]

    final_model, info = _choose_and_calibrate(candidates, x_val, y_val)

    test_proba = final_model.predict_proba(x_test)[:, 1]
    test_metrics = compute_metrics(y_test.to_numpy(), test_proba)
    test_confusion = confusion(y_test.to_numpy(), test_proba)

    _write_artifact(
        output_dir=args.output_dir,
        model=final_model,
        info=info,
        metrics=test_metrics,
        confusion_matrix_=test_confusion,
        splits_info={
            "kind": splits.kind,
            "requested_ratios": list(splits.requested_ratios),
            "rows": {"train": len(train), "val": len(val), "test": len(test)},
            "distinct_domains": splits.distinct_domains,
        },
        dataset_name=Path(path).name,
        row_counts={"total": len(frame), "train": len(train), "val": len(val), "test": len(test)},
        class_balance=balance,
    )

    print(f"winner: {info['winner']}  calibrated={info['calibrated']}")
    print(
        f"test F1: {test_metrics['f1']:.4f}"
        f"  precision: {test_metrics['precision']:.4f}"
        f"  recall: {test_metrics['recall']:.4f}"
        f"  roc_auc: {test_metrics['roc_auc']:.4f}"
        f"  brier: {test_metrics['brier']:.4f}"
    )
    print(f"confusion: {test_confusion}")
    print(f"artifacts written to {args.output_dir}/ (model.joblib, model_card.json)")

    if test_metrics["f1"] < args.target_f1:
        print(
            f"WARNING: F1 {test_metrics['f1']:.4f} < target {args.target_f1:.4f} "
            "(expected on tiny fixtures; investigate on real data)",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
