"""End-to-end tests against the real fixture model (artifacts/model.joblib).

These exercise the full request path: HTTP -> schema validation -> predictor ->
normalizer -> feature pipeline -> sklearn -> response shaping.

Requirements:

* ``artifacts/model.joblib`` must exist. It is produced by ``make train-fixture``.
* If it does not exist, the module is **skipped** with a clear reason rather
  than failed, so a fresh clone does not break ``make test``.

WHOIS is disabled: CI must not hit WHOIS servers, and the point of these tests
is the model + lexical feature chain, not the network.
"""

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import get_settings
from app.features.pipeline import FEATURE_NAMES
from app.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = REPO_ROOT / "artifacts" / "model.joblib"
URLS_PATH = Path(__file__).parent / "fixtures" / "e2e_urls.json"

pytestmark = pytest.mark.skipif(
    not MODEL_PATH.is_file(),
    reason="artifacts/model.joblib not found; run `make train-fixture` first",
)


@pytest.fixture
def labeled_urls() -> dict[str, list[str]]:
    return json.loads(URLS_PATH.read_text(encoding="utf-8"))


@pytest.fixture
async def client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[AsyncClient]:
    monkeypatch.setenv("MODEL_PATH", str(MODEL_PATH))
    monkeypatch.setenv("WHOIS_DISABLED", "true")
    monkeypatch.setenv("ENABLE_EXPLANATIONS", "false")
    get_settings.cache_clear()

    app = create_app()
    transport = ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=transport, base_url="http://e2e") as c,
    ):
        yield c

    get_settings.cache_clear()


async def test_health_reports_the_real_model(client: AsyncClient) -> None:
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True
    assert body["model_version"]


async def test_predict_on_labeled_set_returns_full_contract(
    client: AsyncClient, labeled_urls: dict[str, list[str]]
) -> None:
    for label, urls in labeled_urls.items():
        for url in urls:
            r = await client.post("/predict", json={"url": url})
            assert r.status_code == 200, (label, url, r.text)
            body = r.json()
            assert body["label"] in {"phishing", "benign"}, (label, url, body)
            assert 0.0 <= body["confidence"] <= 1.0, (label, url, body)
            assert body["model_version"], (label, url, body)
            assert set(body["features"]) == set(FEATURE_NAMES), (label, url)
            assert all(isinstance(v, int) for v in body["features"].values())
            assert body["explanation"] is None


async def test_predict_survives_concurrent_requests(
    client: AsyncClient, labeled_urls: dict[str, list[str]]
) -> None:
    urls = labeled_urls["benign"] + labeled_urls["phishing"]
    responses = await asyncio.gather(*(client.post("/predict", json={"url": u}) for u in urls))
    for url, r in zip(urls, responses, strict=True):
        assert r.status_code == 200, (url, r.text)
        assert r.json()["label"] in {"phishing", "benign"}


async def test_phishing_urls_score_higher_than_benign_on_average(
    client: AsyncClient, labeled_urls: dict[str, list[str]]
) -> None:
    """The fixture model has ~80% F1, so we assert an average, not each label."""

    async def score(url: str) -> float:
        r = await client.post("/predict", json={"url": url})
        assert r.status_code == 200, (url, r.text)
        body = r.json()
        return body["confidence"] if body["label"] == "phishing" else 1.0 - body["confidence"]

    benign_scores = await asyncio.gather(*(score(u) for u in labeled_urls["benign"]))
    phishing_scores = await asyncio.gather(*(score(u) for u in labeled_urls["phishing"]))
    benign_avg = sum(benign_scores) / len(benign_scores)
    phishing_avg = sum(phishing_scores) / len(phishing_scores)
    assert phishing_avg > benign_avg, (benign_avg, phishing_avg)


async def test_malformed_url_returns_structured_422(client: AsyncClient) -> None:
    for bad in ("http://", "", "http://a b.com/", "ftp://files.example.org/x"):
        r = await client.post("/predict", json={"url": bad})
        assert r.status_code == 422, (bad, r.text)
        body = r.json()
        assert set(body) == {"error", "detail"}, (bad, body)


async def test_unknown_field_is_rejected(client: AsyncClient) -> None:
    r = await client.post(
        "/predict",
        json={"url": "http://example.com/", "unexpected": True},
    )
    assert r.status_code == 422
