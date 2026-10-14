from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import joblib
import pytest
from httpx import ASGITransport, AsyncClient
from sklearn.ensemble import RandomForestClassifier

from app.features.pipeline import FEATURE_NAMES
from app.main import create_app


def _write_fixture_model(path: Path) -> None:
    """A tiny deterministic RF that predicts P(phishing)=0.9 for everything with a hyphen."""
    import numpy as np
    import pandas as pd

    rows = []
    labels = []
    for i in range(50):
        row = dict.fromkeys(FEATURE_NAMES, 0)
        row["url_length"] = 10 + i
        row["num_hyphens"] = i % 2
        rows.append(row)
        labels.append(i % 2)
    frame = pd.DataFrame(rows, columns=list(FEATURE_NAMES))
    model = RandomForestClassifier(n_estimators=20, random_state=42).fit(frame, labels)
    import sklearn

    joblib.dump(
        {
            "pipeline": model,
            "feature_names": list(FEATURE_NAMES),
            "model_version": "test-20260101T000000Z",
            "trained_at": datetime.now(UTC).isoformat(),
            "sklearn_version": sklearn.__version__,
        },
        path,
    )
    assert np is not None
    assert pd is not None


@pytest.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[AsyncClient]:
    model_path = tmp_path / "model.joblib"
    _write_fixture_model(model_path)
    monkeypatch.setenv("MODEL_PATH", str(model_path))
    monkeypatch.setenv("WHOIS_DISABLED", "true")
    from app.config import get_settings

    get_settings.cache_clear()

    app = create_app()
    transport = ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=transport, base_url="http://test") as c,
    ):
        yield c

    get_settings.cache_clear()


async def test_health_ok(client: AsyncClient) -> None:
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True
    assert body["model_version"] == "test-20260101T000000Z"


async def test_predict_returns_the_contract(client: AsyncClient) -> None:
    r = await client.post("/predict", json={"url": "http://example.com/login"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"label", "confidence", "model_version", "features", "explanation"}
    assert body["label"] in {"phishing", "benign"}
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["model_version"] == "test-20260101T000000Z"
    assert set(body["features"]) == set(FEATURE_NAMES)
    assert all(isinstance(v, int) for v in body["features"].values())


async def test_predict_rejects_malformed_url(client: AsyncClient) -> None:
    r = await client.post("/predict", json={"url": "http://"})
    assert r.status_code == 422
    body = r.json()
    assert body["error"].startswith("invalid_url:")
    assert "detail" in body


async def test_predict_rejects_empty_url(client: AsyncClient) -> None:
    r = await client.post("/predict", json={"url": ""})
    assert r.status_code == 422


async def test_predict_rejects_overlong_url(client: AsyncClient) -> None:
    r = await client.post("/predict", json={"url": "http://a.com/" + "x" * 5000})
    assert r.status_code == 422


async def test_predict_rejects_unknown_field(client: AsyncClient) -> None:
    r = await client.post("/predict", json={"url": "http://example.com/", "extra": 1})
    assert r.status_code == 422


async def test_predict_rejects_missing_url(client: AsyncClient) -> None:
    r = await client.post("/predict", json={})
    assert r.status_code == 422


async def test_predict_works_for_ip_host_and_punycode(client: AsyncClient) -> None:
    for raw in ("http://192.0.2.1/login", "http://xn--pypal-4ve.com/x", "http://localhost/"):
        r = await client.post("/predict", json={"url": raw})
        assert r.status_code == 200, (raw, r.text)


async def test_openapi_docs_available(client: AsyncClient) -> None:
    r = await client.get("/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    assert "/predict" in paths
    assert "/health" in paths
