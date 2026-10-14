import json
from pathlib import Path

import joblib
import pandas as pd
import pytest

from app.data.loader import write_normalized
from app.features.host import HostFeatureExtractor
from app.features.pipeline import FEATURE_NAMES
from app.services.clock import SystemClock
from scripts.train import TrainError, featurize, main

FIXTURES = Path(__file__).parent / "fixtures"


def _load_tiny() -> pd.DataFrame:
    csv = pd.read_csv(FIXTURES / "tiny.csv", dtype=str)
    csv["label"] = (csv["label"] == "phishing").astype("int8")
    return csv.rename(columns={"url": "url"})[["url", "label"]]


@pytest.fixture
def tiny_parquet(tmp_path: Path) -> Path:
    frame = _load_tiny()
    out = tmp_path / "normalized.parquet"
    write_normalized(frame, out)
    return out


def test_featurize_produces_all_features_for_every_row() -> None:
    frame = _load_tiny()
    host = HostFeatureExtractor(clock=SystemClock(), whois_disabled=True)
    feats = featurize(frame, host_extractor=host)
    assert list(feats.columns) == [*FEATURE_NAMES, "label"]
    assert len(feats) == len(frame)
    assert feats["is_shortener"].sum() == 0  # tiny.csv has no shorteners


def test_featurize_drops_unparseable_rows() -> None:
    frame = pd.DataFrame(
        {"url": ["http://a.com/x", "http://", "http://b.com/y"], "label": [0, 1, 1]}
    ).astype({"label": "int8"})
    host = HostFeatureExtractor(clock=SystemClock(), whois_disabled=True)
    feats = featurize(frame, host_extractor=host)
    assert len(feats) == 2  # the "http://" row is dropped


def test_main_writes_model_and_card(
    tiny_parquet: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_dir = tmp_path / "artifacts"
    rc = main(["--input", str(tiny_parquet), "--output-dir", str(out_dir), "--min-per-class", "1"])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert (out_dir / "model.joblib").is_file()
    assert (out_dir / "model_card.json").is_file()
    card = json.loads((out_dir / "model_card.json").read_text())
    assert card["feature_names"] == list(FEATURE_NAMES)
    assert "whois_skew" in card
    assert card["model"]["winner"] in {"random_forest", "gradient_boosting"}
    bundle = joblib.load(out_dir / "model.joblib")
    assert set(bundle) >= {
        "pipeline",
        "feature_names",
        "model_version",
        "trained_at",
        "sklearn_version",
    }


def test_main_fails_without_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DATASET_PATH", raising=False)
    rc = main(["--output-dir", str(tmp_path / "out")])
    assert rc == 1
    assert "DATASET_PATH" in capsys.readouterr().err


def test_featurize_raises_when_nothing_parses() -> None:
    frame = pd.DataFrame({"url": ["http://", "http://"], "label": [0, 1]}).astype({"label": "int8"})
    host = HostFeatureExtractor(clock=SystemClock(), whois_disabled=True)
    with pytest.raises(TrainError, match="no rows"):
        featurize(frame, host_extractor=host)


def test_model_version_contains_timestamp() -> None:
    from scripts.train import _version

    v = _version()
    assert "-" in v
    assert len(v.split("-", 1)[1]) >= 15  # YYYYMMDDTHHMMSSZ
