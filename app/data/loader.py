"""Load and write normalized phishing URL parquet datasets."""

from pathlib import Path
from typing import Final

import pandas as pd

from app.data.schema import validate_normalized

DEFAULT_NORMALIZED_PATH: Final = Path("data/normalized.parquet")


def write_normalized(frame: pd.DataFrame, path: Path) -> None:
    """Validate and write normalized data atomically as parquet."""

    validated = validate_normalized(frame)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    validated.to_parquet(tmp, index=False)
    tmp.replace(path)


def load_normalized(path: Path) -> pd.DataFrame:
    """Load and validate normalized parquet data."""

    if not path.is_file():
        raise FileNotFoundError(
            f"normalized dataset not found at {path}; run scripts/fetch_dataset.py"
        )
    frame = pd.read_parquet(path)
    return validate_normalized(frame)
