"""Train/val/test splitting, group-aware by default.

A random stratified split leaks URLs from the same registered domain across
splits, which inflates F1 (Step 1, flaw 3). We default to a group split on the
registered domain. When the dataset is too small for a group split to yield
non-empty splits (the fixture dataset, for example), we fall back to a plain
stratified split and record that fact for the model card.
"""

from dataclasses import dataclass
from typing import Final

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from app.features.suffix import registered_domain

SplitKind = str  # "group" | "stratified_fallback"

DEFAULT_RANDOM_STATE: Final = 42


@dataclass(frozen=True, slots=True)
class Splits:
    train: pd.DataFrame
    val: pd.DataFrame
    test: pd.DataFrame
    kind: SplitKind
    distinct_domains: dict[str, int]  # per-split distinct registered domains
    requested_ratios: tuple[float, float, float]  # (train, val, test)


def _domains(urls: pd.Series) -> pd.Series:
    """Best-effort registered domain for each URL; empty string when unknowable."""

    def one(url: str) -> str:
        try:
            from urllib.parse import urlsplit

            host = urlsplit(url).hostname or ""
            return registered_domain(host) or ""
        except Exception:
            return ""

    return urls.map(one)


def _group_split(
    frame: pd.DataFrame, *, random_state: int, val_ratio: float, test_ratio: float
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame] | None:
    groups = _domains(frame["url"])
    if (groups == "").any():
        # Suffix-less URLs get their own singleton groups so we still get a split.
        groups = groups.where(groups != "", other=frame["url"])
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_ratio, random_state=random_state)
    try:
        train_idx, test_idx = next(splitter.split(frame, groups=groups))
    except (StopIteration, ValueError):
        return None
    train = frame.iloc[train_idx]
    test = frame.iloc[test_idx]
    # Now split train into train/val by group.
    inner_test = val_ratio / (1.0 - test_ratio)
    inner = GroupShuffleSplit(n_splits=1, test_size=inner_test, random_state=random_state)
    inner_groups = groups.iloc[train_idx]
    try:
        tr_idx, val_idx = next(inner.split(train, groups=inner_groups))
    except (StopIteration, ValueError):
        return None
    return train.iloc[tr_idx], train.iloc[val_idx], test


def _stratified_split(
    frame: pd.DataFrame, *, random_state: int, val_ratio: float, test_ratio: float
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    labels = frame["label"]
    train_val, test = train_test_split(
        frame, test_size=test_ratio, random_state=random_state, stratify=labels
    )
    val_share = val_ratio / (1.0 - test_ratio)
    train, val = train_test_split(
        train_val,
        test_size=val_share,
        random_state=random_state,
        stratify=train_val["label"],
    )
    return train, val, test


def split_dataset(
    frame: pd.DataFrame,
    *,
    random_state: int = DEFAULT_RANDOM_STATE,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    min_per_class: int = 2,
) -> Splits:
    """Return 70/15/15 splits, group-aware when possible.

    Raises ValueError when the dataset is too small to produce splits with at
    least ``min_per_class`` of each class in every split.
    """
    if not (0 < train_ratio < 1 and 0 < val_ratio < 1 and 0 < test_ratio < 1):
        raise ValueError("split ratios must be in (0, 1)")
    if abs(train_ratio + val_ratio + test_ratio - 1.0) > 1e-9:
        raise ValueError("split ratios must sum to 1")
    if frame.empty:
        raise ValueError("cannot split an empty dataset")

    result = _group_split(
        frame, random_state=random_state, val_ratio=val_ratio, test_ratio=test_ratio
    )
    if result is not None and all(_ok(s, min_per_class) for s in result):
        kind = "group"
        train, val, test = result
    else:
        train, val, test = _stratified_split(
            frame, random_state=random_state, val_ratio=val_ratio, test_ratio=test_ratio
        )
        kind = "stratified_fallback"
        if not all(_ok(s, min_per_class) for s in (train, val, test)):
            raise ValueError(
                "dataset is too small to produce splits with "
                f"{min_per_class} of each class in train/val/test"
            )

    return Splits(
        train=train.reset_index(drop=True),
        val=val.reset_index(drop=True),
        test=test.reset_index(drop=True),
        kind=kind,
        distinct_domains={
            "train": int(_domains(train["url"]).nunique()),
            "val": int(_domains(val["url"]).nunique()),
            "test": int(_domains(test["url"]).nunique()),
        },
        requested_ratios=(train_ratio, val_ratio, test_ratio),
    )


def _ok(frame: pd.DataFrame, min_per_class: int) -> bool:
    if frame.empty:
        return False
    counts = frame["label"].value_counts()
    return bool(counts.get(0, 0) >= min_per_class and counts.get(1, 0) >= min_per_class)
