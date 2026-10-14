import json
from pathlib import Path

import pandas as pd
import pytest

from app.config import get_settings
from app.data.loader import load_normalized
from scripts.fetch_dataset import (
    DatasetError,
    build_normalized,
    main,
    parse_label_map,
    read_raw_csv,
)

FIXTURES = Path(__file__).parent / "fixtures"
TINY = FIXTURES / "tiny.csv"
MESSY = FIXTURES / "tiny_messy.csv"
MAP = "phishing=1,benign=0"


@pytest.fixture(autouse=True)
def _no_stray_dotenv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()


def test_parse_label_map_normalizes_case_and_whitespace() -> None:
    assert parse_label_map(" Phishing = 1, BENIGN=0") == {"phishing": 1, "benign": 0}


@pytest.mark.parametrize(
    "spec",
    ["", "phishing", "phishing=2,benign=0", "a=1,a=0", "phishing=1,malware=1", "x=y"],
)
def test_parse_label_map_fails_loudly(spec: str) -> None:
    with pytest.raises(DatasetError):
        parse_label_map(spec)


def test_messy_fixture_cleaning_report() -> None:
    raw = read_raw_csv(MESSY, "URL", "Status")
    frame, report = build_normalized(
        raw,
        url_column="URL",
        label_column="Status",
        label_map={"good": 0, "bad": 1},
        max_url_length=2048,
    )
    assert report.rows_in == 11
    assert report.invalid_dropped == 3
    assert report.invalid_reasons == {"empty": 1, "illegal_char": 1, "unsupported_scheme": 1}
    assert report.scheme_inferred == 1
    assert report.duplicates_dropped == 1
    assert report.conflicting_rows_dropped == 2
    assert (report.rows_out, report.benign, report.phishing) == (5, 3, 2)
    assert set(frame["url"]) == {
        "https://www.example-shop.com/Cart",
        "http://news-site.org/world",
        "http://xn--bcher-kva.example.com/shop",
        "http://[2001:db8::1]/login",
        "http://evil.com/a",
    }


def test_unmapped_label_values_fail() -> None:
    raw = read_raw_csv(MESSY, "URL", "Status")
    with pytest.raises(DatasetError, match="unmapped"):
        build_normalized(
            raw,
            url_column="URL",
            label_column="Status",
            label_map={"good": 0, "evil": 1},
            max_url_length=2048,
        )


def test_missing_column_fails() -> None:
    with pytest.raises(DatasetError, match="nope"):
        read_raw_csv(TINY, "nope", "label")


def _run(out: Path, *extra: str) -> int:
    return main(["--input", str(TINY), "--output", str(out), "--label-map", MAP, *extra])


def test_main_end_to_end_on_tiny_fixture(tmp_path: Path) -> None:
    out = tmp_path / "data" / "normalized.parquet"
    assert _run(out) == 0
    frame = load_normalized(out)
    assert len(frame) == 56
    assert int(frame["label"].sum()) == 28
    report = json.loads((tmp_path / "data" / "normalized.report.json").read_text())
    assert report["source"] == "tiny.csv"
    assert report["rows_out"] == 56
    assert report["invalid_dropped"] == 0


def test_main_is_idempotent(tmp_path: Path) -> None:
    out = tmp_path / "normalized.parquet"
    assert _run(out) == 0
    first = load_normalized(out)
    assert _run(out) == 0
    pd.testing.assert_frame_equal(first, load_normalized(out))


def test_main_requires_label_map(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--input", str(TINY), "--output", str(tmp_path / "o.parquet")])
    assert exc.value.code == 2


def test_main_reports_errors_and_returns_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(tmp_path / "o.parquet", "--url-column", "nope") == 1
    assert "nope" in capsys.readouterr().err
    assert not (tmp_path / "o.parquet").exists()


def test_main_falls_back_to_dataset_path_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATASET_PATH", str(TINY))
    out = tmp_path / "o.parquet"
    assert main(["--output", str(out), "--label-map", MAP]) == 0
    assert len(load_normalized(out)) == 56


def test_main_fails_without_any_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--output", str(tmp_path / "o.parquet"), "--label-map", MAP]) == 1
    assert "DATASET_PATH" in capsys.readouterr().err
