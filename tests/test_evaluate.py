from pathlib import Path

import pytest

from scripts.evaluate import EvaluateError, _load_bundle, main
from scripts.train import main as train_main

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def trained(tmp_path: Path) -> tuple[Path, Path]:
    import pandas as pd

    from app.data.loader import write_normalized

    csv = pd.read_csv(FIXTURES / "tiny.csv", dtype=str)
    csv["label"] = (csv["label"] == "phishing").astype("int8")
    parquet = tmp_path / "normalized.parquet"
    write_normalized(csv[["url", "label"]], parquet)

    model_dir = tmp_path / "artifacts"
    rc = train_main(
        ["--input", str(parquet), "--output-dir", str(model_dir), "--min-per-class", "1"]
    )
    assert rc == 0
    return parquet, model_dir / "model.joblib"


def test_evaluate_on_training_data(
    trained: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    parquet, model = trained
    rc = main(["--input", str(parquet), "--model", str(model), "--min-f1", "0.1"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "f1:" in out


def test_evaluate_fails_on_high_threshold(
    trained: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    parquet, model = trained
    rc = main(["--input", str(parquet), "--model", str(model), "--min-f1", "0.999"])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().err


def test_evaluate_missing_model(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--input", str(FIXTURES / "tiny.csv"), "--model", str(tmp_path / "nope.joblib")])
    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_load_bundle_rejects_malformed(tmp_path: Path) -> None:
    import joblib

    bad = tmp_path / "bad.joblib"
    joblib.dump({"not_a_bundle": True}, bad)
    with pytest.raises(EvaluateError, match="malformed"):
        _load_bundle(bad)
