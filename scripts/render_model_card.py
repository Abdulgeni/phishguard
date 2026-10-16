"""Render artifacts/model_card.json as Markdown on stdout.

    python -m scripts.render_model_card > /tmp/card.md

Used by `make model-card` and by the README's model-card section.
"""

import json
import sys
from pathlib import Path
from typing import Any

CARD_PATH = Path("artifacts/model_card.json")


def _fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    if isinstance(value, (dict, list)):
        return f"`{json.dumps(value, sort_keys=True)}`"
    return str(value)


def render(card: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("## Model card")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    for key in (
        "model_version",
        "trained_at",
        "sklearn_version",
        "dataset",
        "target_f1",
    ):
        lines.append(f"| `{key}` | {_fmt(card.get(key))} |")
    lines.append("")

    lines.append("### Dataset split")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    split = card.get("split", {})
    lines.append(f"| `kind` | {_fmt(split.get('kind'))} |")
    lines.append(f"| `rows` | {_fmt(split.get('rows'))} |")
    lines.append(f"| `distinct_domains` | {_fmt(split.get('distinct_domains'))} |")
    lines.append(f"| `requested_ratios` | {_fmt(split.get('requested_ratios'))} |")
    lines.append("")

    lines.append("### Test metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    for key, value in (card.get("metrics") or {}).items():
        lines.append(f"| `{key}` | {_fmt(value)} |")
    lines.append("")

    lines.append("### Confusion matrix")
    lines.append("")
    cm = card.get("confusion_matrix", {})
    lines.append("| | Pred benign | Pred phishing |")
    lines.append("|---|---|---|")
    lines.append(f"| **True benign** | {cm.get('tn', '?')} | {cm.get('fp', '?')} |")
    lines.append(f"| **True phishing** | {cm.get('fn', '?')} | {cm.get('tp', '?')} |")
    lines.append("")

    lines.append("### Model selection")
    lines.append("")
    model = card.get("model", {})
    lines.append(f"- Winner: **{model.get('winner', '?')}**")
    lines.append(f"- Validation F1: {_fmt(model.get('winner_val_f1'))}")
    lines.append(
        f"- Calibrated: {model.get('calibrated')} "
        f"(Brier before: {_fmt(model.get('brier_before_calibration'))}, "
        f"threshold: {_fmt(model.get('calibration_threshold'))})"
    )
    lines.append("")

    lines.append("### Features")
    lines.append("")
    features = card.get("feature_names") or []
    lines.append(f"`{len(features)}` features:")
    lines.append("")
    lines.append("```")
    for name in features:
        lines.append(name)
    lines.append("```")
    lines.append("")

    lines.append("### Known limitations")
    lines.append("")
    lines.append(f"> {card.get('whois_skew', '')}")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    if not CARD_PATH.is_file():
        print(
            f"error: {CARD_PATH} not found; run `make train-fixture` or `make train` first",
            file=sys.stderr,
        )
        return 1
    card = json.loads(CARD_PATH.read_text(encoding="utf-8"))
    sys.stdout.write(render(card))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
