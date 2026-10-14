"""Normalize a raw phishing-URL CSV into data/normalized.parquet.

    python scripts/fetch_dataset.py --input raw.csv --label-map phishing=1,benign=0

``--input`` falls back to the DATASET_PATH env var. ``--label-map`` is always required:
label polarity differs between datasets, so it is never guessed.
"""

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

import pandas as pd

from app.config import get_settings
from app.data.loader import DEFAULT_NORMALIZED_PATH, write_normalized
from app.data.schema import (
    BENIGN,
    LABEL_COLUMN,
    PHISHING,
    URL_COLUMN,
    SchemaError,
    validate_normalized,
)
from app.features.normalize import InvalidUrlError, normalize_url


class DatasetError(ValueError):
    """A fail-loudly dataset condition (bad mapping, missing column, nothing left...)."""


@dataclass(frozen=True)
class NormalizeReport:
    rows_in: int
    invalid_dropped: int
    invalid_reasons: dict[str, int]
    scheme_inferred: int  # valid rows (before dedup) that had no scheme and got http://
    duplicates_dropped: int
    conflicting_rows_dropped: int
    rows_out: int
    benign: int
    phishing: int


def parse_label_map(spec: str) -> dict[str, int]:
    """Parse 'phishing=1,benign=0' (keys case-insensitive; 1 = phishing, 0 = benign)."""
    mapping: dict[str, int] = {}
    for item in spec.split(","):
        key, sep, value = item.partition("=")
        key = key.strip().lower()
        if not sep or not key or value.strip() not in {"0", "1"}:
            raise DatasetError(f"bad --label-map item {item!r}; expected raw=0 or raw=1")
        if key in mapping:
            raise DatasetError(f"duplicate label {key!r} in --label-map")
        mapping[key] = int(value)
    if set(mapping.values()) != {BENIGN, PHISHING}:
        raise DatasetError("--label-map must map something to 0 (benign) and something to 1")
    return mapping


def read_raw_csv(path: Path, url_column: str, label_column: str) -> pd.DataFrame:
    if not path.is_file():
        raise DatasetError(f"input file not found: {path}")
    try:
        frame = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8")
    except (UnicodeDecodeError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        raise DatasetError(f"cannot read {path}: {exc}") from exc
    missing = [c for c in (url_column, label_column) if c not in frame.columns]
    if missing:
        raise DatasetError(f"missing column(s) {missing}; available: {list(frame.columns)}")
    return frame[[url_column, label_column]]


def map_labels(raw: list[str], label_map: dict[str, int]) -> list[int]:
    unmapped = sorted({v for v in raw if v.strip().lower() not in label_map})
    if unmapped:
        raise DatasetError(f"unmapped label values {unmapped[:10]}; extend --label-map")
    return [label_map[v.strip().lower()] for v in raw]


def normalize_rows(
    urls: list[str], labels: list[int], max_url_length: int
) -> tuple[pd.DataFrame, Counter[str], int]:
    """Normalize every row; return (frame, invalid-reason counts, scheme-inferred count)."""
    kept_urls: list[str] = []
    kept_labels: list[int] = []
    invalid: Counter[str] = Counter()
    inferred = 0
    for url, label in zip(urls, labels, strict=True):
        try:
            normalized = normalize_url(url, max_length=max_url_length)
        except InvalidUrlError as exc:
            invalid[exc.reason] += 1
            continue
        inferred += int(normalized.scheme_inferred)
        kept_urls.append(normalized.url)
        kept_labels.append(label)
    frame = pd.DataFrame({URL_COLUMN: kept_urls, LABEL_COLUMN: kept_labels})
    return frame, invalid, inferred


def dedupe(frame: pd.DataFrame) -> tuple[pd.DataFrame, int, int]:
    """Drop URLs with conflicting labels entirely, then exact duplicates (keep first)."""
    conflicts = frame.groupby(URL_COLUMN)[LABEL_COLUMN].transform("nunique") > 1
    conflicting_rows = int(conflicts.sum())
    frame = frame[~conflicts]
    before = len(frame)
    frame = frame.drop_duplicates(subset=URL_COLUMN, keep="first").reset_index(drop=True)
    return frame, before - len(frame), conflicting_rows


def build_normalized(
    raw_df: pd.DataFrame,
    *,
    url_column: str,
    label_column: str,
    label_map: dict[str, int],
    max_url_length: int,
) -> tuple[pd.DataFrame, NormalizeReport]:
    labels = map_labels(raw_df[label_column].tolist(), label_map)
    frame, invalid, inferred = normalize_rows(raw_df[url_column].tolist(), labels, max_url_length)
    frame, duplicates, conflicts = dedupe(frame)
    if frame.empty:
        raise DatasetError("no rows left after cleaning")
    frame = validate_normalized(frame)
    report = NormalizeReport(
        rows_in=len(raw_df),
        invalid_dropped=sum(invalid.values()),
        invalid_reasons=dict(sorted(invalid.items())),
        scheme_inferred=inferred,
        duplicates_dropped=duplicates,
        conflicting_rows_dropped=conflicts,
        rows_out=len(frame),
        benign=int((frame[LABEL_COLUMN] == BENIGN).sum()),
        phishing=int((frame[LABEL_COLUMN] == PHISHING).sum()),
    )
    return frame, report


def format_report(report: NormalizeReport, source: Path, output: Path) -> str:
    ratio = max(report.benign, report.phishing) / max(1, min(report.benign, report.phishing))
    return "\n".join(
        [
            f"source:              {source}",
            f"rows in:             {report.rows_in}",
            f"invalid dropped:     {report.invalid_dropped}  {report.invalid_reasons}",
            f"scheme inferred:     {report.scheme_inferred} (no scheme; http:// assumed)",
            f"duplicates dropped:  {report.duplicates_dropped}",
            f"conflicting dropped: {report.conflicting_rows_dropped} rows (same URL, both labels)",
            f"rows out:            {report.rows_out}  -> {output}",
            f"class balance:       benign={report.benign} phishing={report.phishing}"
            f" (majority:minority = {ratio:.2f}:1)",
        ]
    )


def write_report(path: Path, source: Path, report: NormalizeReport) -> None:
    payload = {"source": source.name, **asdict(report)}
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def resolve_input(cli_path: Path | None, env_path: Path | None) -> Path:
    path = cli_path if cli_path is not None else env_path
    if path is None:
        raise DatasetError("no input: pass --input or set DATASET_PATH")
    return path


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize a raw phishing-URL CSV.")
    parser.add_argument("--input", type=Path, help="raw CSV (default: $DATASET_PATH)")
    parser.add_argument("--output", type=Path, default=DEFAULT_NORMALIZED_PATH)
    parser.add_argument("--url-column", default="url")
    parser.add_argument("--label-column", default="label")
    parser.add_argument(
        "--label-map", required=True, help="e.g. phishing=1,benign=0 (1 = phishing)"
    )
    parser.add_argument("--max-url-length", type=int, default=None)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        label_map = parse_label_map(args.label_map)
        settings = get_settings()
        source = resolve_input(args.input, settings.dataset_path)
        raw = read_raw_csv(source, args.url_column, args.label_column)
        frame, report = build_normalized(
            raw,
            url_column=args.url_column,
            label_column=args.label_column,
            label_map=label_map,
            max_url_length=args.max_url_length or settings.max_url_length,
        )
        write_normalized(frame, args.output)
        write_report(args.output.with_suffix(".report.json"), source, report)
    except (DatasetError, SchemaError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(format_report(report, source, args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
