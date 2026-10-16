"""Schema contract for normalized phishing URL datasets."""

from typing import Final

import pandas as pd

URL_COLUMN: Final = "url"
LABEL_COLUMN: Final = "label"
COLUMNS: Final = (URL_COLUMN, LABEL_COLUMN)
BENIGN: Final = 0
PHISHING: Final = 1


class SchemaError(ValueError):
    """Raised when a normalized dataset violates the schema contract."""


def validate_normalized(frame: pd.DataFrame) -> pd.DataFrame:
    """Validate and normalize a URL/label DataFrame.

    Contract:
    - columns are exactly ["url", "label"]
    - non-empty frame
    - url values are non-empty strings
    - label values are non-null and in {0, 1}
    - url values are unique
    - both classes are present
    """

    if list(frame.columns) != list(COLUMNS):
        raise SchemaError(f"columns must be exactly {list(COLUMNS)}")
    if frame.empty:
        raise SchemaError("empty normalized dataset")

    out = frame.copy()

    urls = out[URL_COLUMN]
    if urls.isnull().any():
        raise SchemaError("url contains empty or non-string values")
    if not urls.map(lambda value: isinstance(value, str) and value.strip() != "").all():
        raise SchemaError("url contains empty or non-string values")

    labels = out[LABEL_COLUMN]
    if labels.isnull().any():
        raise SchemaError("label column contains nulls")

    numeric = pd.to_numeric(labels, errors="coerce")
    if numeric.isnull().any() or not numeric.isin([BENIGN, PHISHING]).all():
        raise SchemaError("label values must be 0 or 1")

    out[LABEL_COLUMN] = numeric.astype("int8")

    duplicates = out[URL_COLUMN].duplicated(keep=False)
    if duplicates.any():
        raise SchemaError("duplicate url rows found")

    if out[LABEL_COLUMN].nunique() != 2:
        raise SchemaError("dataset must include both classes")

    return out.reset_index(drop=True)
