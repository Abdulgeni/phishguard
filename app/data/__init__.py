"""Normalized dataset I/O and schema validation."""

from app.data.loader import DEFAULT_NORMALIZED_PATH, load_normalized, write_normalized
from app.data.schema import (
    BENIGN,
    COLUMNS,
    LABEL_COLUMN,
    PHISHING,
    URL_COLUMN,
    SchemaError,
    validate_normalized,
)

__all__ = [
    "BENIGN",
    "COLUMNS",
    "DEFAULT_NORMALIZED_PATH",
    "LABEL_COLUMN",
    "PHISHING",
    "URL_COLUMN",
    "SchemaError",
    "load_normalized",
    "validate_normalized",
    "write_normalized",
]
