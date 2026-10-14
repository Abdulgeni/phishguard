"""Metric bundle and the model-card shape."""

from typing import Final

import numpy as np
from sklearn.metrics import (
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

METRIC_NAMES: Final[tuple[str, ...]] = (
    "precision",
    "recall",
    "f1",
    "roc_auc",
    "brier",
    "support_benign",
    "support_phishing",
)


def compute_metrics(
    y_true: np.ndarray, y_proba: np.ndarray, *, threshold: float = 0.5
) -> dict[str, float | int]:
    """Return the standard metric bundle. ``y_proba`` is P(phishing)."""
    y_pred = (y_proba >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    out: dict[str, float | int] = {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "brier": float(brier_score_loss(y_true, y_proba)),
        "support_benign": int(tn + fp),
        "support_phishing": int(fn + tp),
    }
    # ROC-AUC is undefined when only one class is present; the caller guarantees both.
    out["roc_auc"] = float(roc_auc_score(y_true, y_proba))
    return out


def confusion(y_true: np.ndarray, y_proba: np.ndarray, *, threshold: float = 0.5) -> dict[str, int]:
    y_pred = (y_proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
