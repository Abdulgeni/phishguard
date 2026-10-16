# PhishGuard

Phishing URL/email classifier served as a containerized FastAPI microservice.
Twenty features (17 lexical + 3 host-based), a tree-ensemble model, defensive
input handling, and graceful degradation when WHOIS is slow or unavailable.

## What this is

A production-shaped ML inference service, not a notebook:

- **`POST /predict`** — classify one URL. Returns label, confidence, feature map, model version.
- **`POST /predict_email`** — scan an email body: extract URLs, score each, return per-URL
  verdicts and an aggregate.
- **`GET /health`** — liveness + readiness, surfaces the loaded model version.
- **`GET /docs`** — auto-generated OpenAPI UI.

Runs locally with one command, ships in a multi-stage Docker image, and has four
runnable demos that prove distinct properties (see below).

## Quickstart

```bash
# install (needs uv, Docker Desktop, make)
uv sync --all-extras

# run the test suite (uses a fixture model, no network required)
make test

# build a fixture model from a tiny synthetic dataset
make train-fixture

# run the API locally
make run
# in another shell:
curl -s http://127.0.0.1:8000/health
curl -s -X POST http://127.0.0.1:8000/predict \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://paypa1-secure-login.xyz/verify"}'

# run the API in Docker, run a demo, tear down
make demo
```

## Demos

Each demo is self-contained: it starts the stack, runs a scenario, prints a
pass/fail table, exits non-zero if any expectation fails, and tears down.

| Target | Proves |
|---|---|
| `make demo` | 6 labeled URLs are classified correctly end-to-end. |
| `make demo-degraded` | The service answers correctly with WHOIS disabled; `domain_age_days` is the sentinel `-1`. |
| `make demo-budget` | A 5-second fake WHOIS delay still returns within `REQUEST_BUDGET_SECONDS=1`; the request is cut short and audited as `whois_skipped`. |
| `make demo-email` | An email body with 2 phishing URLs + 1 benign URL yields per-URL verdicts and an aggregate `verdict=phishing`. |

## Architecture

```
client ──► FastAPI (app/main.py)
             │  middleware: request-ID, per-IP rate limit
             │  schema validation, structured errors
             ▼
        predictor (app/services/predictor.py)
             │  loaded once at startup via lifespan
             ▼
        feature pipeline (app/features/pipeline.py)
             ├── lexical (pure, no I/O)
             └── host (WHOIS, bounded executor, LRU+TTL cache)
             ▼
        sklearn Pipeline.predict_proba
             ▼
        response {label, confidence, model_version, features, explanation?}
```

### Feature contract (20 features, frozen)

17 lexical: `url_length, host_length, path_length, num_dots, num_hyphens,
num_digits, num_slashes, num_query_params, num_subdomains, has_ip_host,
has_at_symbol, has_punycode, tld_length, path_depth, suspicious_keyword_hits,
has_double_slash_in_path, has_hex_encoding`

3 host: `domain_age_days, is_shortener, registrar_known`

The order and names are frozen at `app/features/pipeline.py:FEATURE_NAMES`.
Extra features require an explicit decision and a retrain.

### Feature sentinels

Unknown numeric values are `-1`; unknown booleans are `0`. Documented per
feature in `app/features/README.md`.

### Train/serve skew (important)

`domain_age_days` and `registrar_known` are set to sentinels at **train** time
because dataset URLs are largely dead: running WHOIS on them would teach the
model "WHOIS failed = phishing", which breaks the moment a live phishing site
is scored. The trees therefore do not split on these two features in v1. They
are computed and echoed at serving time, but they do not change the verdict.
`is_shortener` **is** computed at both train and serve time (it is offline) and
does carry learned signal. The model card restates this; see below.

## Training

```bash
# 1. download a public phishing-URL CSV (Kaggle: e.g. "Malicious URLs" or
#    "Phishing Site URLs"). You supply the path.
export DATASET_PATH=/path/to/raw.csv

# 2. normalize it
uv run python -m scripts.fetch_dataset \
  --url-column url --label-column type \
  --label-map phishing=1,benign=0

# 3. train, evaluate, write artifacts/model.joblib + artifacts/model_card.json
make train

# 4. render the model card
make model-card
```

The trainer:

- Splits 70/15/15 **by registered domain** (`GroupShuffleSplit`) to avoid
  train/test leakage between pages on the same site.
- Falls back to a plain stratified split when the dataset is too small for a
  group split to yield non-empty train/val/test.
- Compares `RandomForestClassifier` and `GradientBoostingClassifier` on
  validation F1.
- Checks the Brier score and, if > 0.10, wraps the winner in isotonic
  calibration via `CalibratedClassifierCV(FrozenEstimator(...))`.
- Evaluates the winner on the held-out test set and records precision, recall,
  F1, ROC-AUC, Brier, and the confusion matrix in the model card.

## Model card

<!-- BEGIN MODEL CARD -->
<!-- Run `make model-card` to render the current card here. -->
<!-- END MODEL CARD -->

## Project layout

```
app/
  main.py                    FastAPI app, lifespan, routes
  config.py                  pydantic-settings, typed env vars
  logging_setup.py           structlog JSON lines
  errors.py                  structured error handlers
  middleware.py              request-ID + rate limit
  schemas.py                 request/response models
  services/
    predictor.py             model load + single-URL inference
    email_extractor.py       URL extraction from an email body
    clock.py                 injectable time source
    cache.py                 thread-safe LRU with TTL
  features/
    normalize.py             shared URL normalization (train + serve)
    lexical.py               17 pure lexical features
    host.py                  3 host features (WHOIS + shortener list)
    suffix.py                offline public-suffix extractor
    pipeline.py              Budget + extract_features + FEATURE_NAMES
    README.md                per-feature rationale
  data/
    loader.py                read/write normalized parquet
    schema.py                typed DataFrame contract
  training/
    split.py                 group-aware train/val/test split
    metrics.py               metric bundle + confusion matrix
scripts/
  fetch_dataset.py           CSV -> normalized parquet
  train.py                   train + evaluate + save artifacts
  train_fixture.py           train on tests/fixtures/tiny.csv
  evaluate.py                evaluate a saved model
  render_model_card.py       model_card.json -> Markdown
demos/                       one shell script per demo
tests/                       pytest suite (~270 tests)
artifacts/                   model.joblib, model_card.json (gitignored)
data/                        normalized.parquet (gitignored)
```

## Configuration

Every setting is an environment variable; see `.env.example`. No secrets ship
in the repo. Notable knobs:

| Variable | Default | Purpose |
|---|---|---|
| `MODEL_PATH` | `artifacts/model.joblib` | Where the model loads from at startup. |
| `REQUEST_BUDGET_SECONDS` | `3` | Whole-request wall-clock budget for `/predict`. |
| `WHOIS_TIMEOUT_SECONDS` | `2` | WHOIS lookup cap; further capped by the request budget. |
| `WHOIS_DISABLED` | `false` | Short-circuit all WHOIS to sentinels. |
| `ENABLE_EXPLANATIONS` | `false` | Include global feature importances in responses. |
| `RATE_LIMIT_CAPACITY` | `30` | Burst size per client IP, per process. |
| `RATE_LIMIT_REFILL_PER_SECOND` | `0.5` | Steady-state refill rate. |
| `EMAIL_MAX_URLS` | `20` | Max unique URLs extracted from an email body. |

## Known limitations

- **WHOIS features carry no learned signal in v1** (see the train/serve skew
  note above). They are served but inert.
- **Rate limiting is per process.** Horizontal scaling requires a shared store
  (Redis or similar); documented, not implemented.
- **`X-Forwarded-For` is trusted as-is** for the client IP. Only safe behind a
  proxy that overwrites the header.
- **`python-whois` can hang.** A timed-out thread cannot be killed; it keeps its
  executor slot until it returns. We cap concurrency at 8 and skip when full.
- **Email extraction is plain regex + tldextract.** No HTML parsing, no
  attachment handling, no obfuscation resistance beyond what normalization does.

## License

MIT.