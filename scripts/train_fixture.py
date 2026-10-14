"""Train a fixture model from tests/fixtures/tiny.csv into artifacts/.

Used by ``make train-fixture`` and by CI. Deterministic and fast: no WHOIS,
no real dataset, no network.
"""

from pathlib import Path

import pandas as pd

from app.data.loader import write_normalized
from scripts.train import main as train_main

FIXTURE_CSV = Path("tests/fixtures/tiny.csv")
TMP_PARQUET = Path("artifacts/.fixture_normalized.parquet")


def main() -> int:
    csv = pd.read_csv(FIXTURE_CSV, dtype=str)
    csv["label"] = (csv["label"] == "phishing").astype("int8")
    Path("artifacts").mkdir(exist_ok=True)
    write_normalized(csv[["url", "label"]], TMP_PARQUET)
    return train_main(
        [
            "--input",
            str(TMP_PARQUET),
            "--output-dir",
            "artifacts",
            "--min-per-class",
            "1",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
