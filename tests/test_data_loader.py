from pathlib import Path

import pandas as pd
import pytest

from app.data.loader import load_normalized, write_normalized
from app.data.schema import COLUMNS, SchemaError, validate_normalized


def _frame(urls: list[str], labels: list[int | None]) -> pd.DataFrame:
    return pd.DataFrame({"url": urls, "label": labels})


def test_validate_accepts_and_casts_to_int8() -> None:
    out = validate_normalized(_frame(["http://a.com/", "http://b.com/"], [0, 1]))
    assert str(out["label"].dtype) == "int8"
    assert list(out.columns) == list(COLUMNS)


@pytest.mark.parametrize(
    ("frame", "message"),
    [
        (pd.DataFrame({"url": ["http://a.com/"]}), "columns must be exactly"),
        (_frame([], []), "empty"),
        (_frame(["http://a.com/", ""], [0, 1]), "empty or non-string"),
        (_frame(["http://a.com/", "http://b.com/"], [0, None]), "nulls"),
        (_frame(["http://a.com/", "http://b.com/"], [0, 2]), "must be 0 or 1"),
        (_frame(["http://a.com/", "http://a.com/"], [0, 1]), "duplicate"),
        (_frame(["http://a.com/", "http://b.com/"], [1, 1]), "both classes"),
    ],
)
def test_validate_rejects(frame: pd.DataFrame, message: str) -> None:
    with pytest.raises(SchemaError, match=message):
        validate_normalized(frame)


def test_round_trip_creates_parent_dir(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "normalized.parquet"
    frame = _frame(["http://a.com/", "http://b.com/x"], [0, 1])
    write_normalized(frame, path)
    loaded = load_normalized(path)
    pd.testing.assert_frame_equal(loaded, validate_normalized(frame), check_dtype=False)
    assert str(loaded["label"].dtype) == "int8"
    assert not list(path.parent.glob("*.tmp"))


def test_write_rejects_invalid_frame_without_creating_file(tmp_path: Path) -> None:
    path = tmp_path / "normalized.parquet"
    with pytest.raises(SchemaError):
        write_normalized(_frame(["http://a.com/"], [1]), path)
    assert not path.exists()


def test_load_missing_file_points_at_fetch_script(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="fetch_dataset"):
        load_normalized(tmp_path / "nope.parquet")
