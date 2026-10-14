UV ?= uv
PKGS := app scripts tests

define not_yet
	@echo "make $(1): not implemented until Step $(2)." >&2; exit 1
endef

.DEFAULT_GOAL := help
.PHONY: help install lint format typecheck test run run-dev train train-fixture evaluate build \
	demo demo-degraded demo-budget demo-email clean

help:  ## List targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/' | sort

install:  ## Sync the uv-managed venv with all extras
	$(UV) sync --all-extras

lint:  ## ruff lint + format check
	$(UV) run ruff check $(PKGS)
	$(UV) run ruff format --check $(PKGS)

format:  ## ruff autofix + format
	$(UV) run ruff check --fix $(PKGS)
	$(UV) run ruff format $(PKGS)

typecheck:  ## mypy --strict on app/ and scripts/
	$(UV) run mypy app scripts

test:  ## pytest
	$(UV) run pytest

run:  ## uvicorn locally, no Docker
	$(UV) run uvicorn app.main:app --host 0.0.0.0 --port 8000

run-dev:  ## uvicorn with autoreload (for local iteration only)
	$(UV) run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

train:  ## train on data/normalized.parquet or $DATASET_PATH -> artifacts/
	$(UV) run python -m scripts.train

train-fixture:  ## train a fixture model from tests/fixtures/tiny.csv -> artifacts/
	$(UV) run python -m scripts.train_fixture

evaluate:  ## evaluate saved model, non-zero if F1 < MIN_F1
	$(UV) run python -m scripts.evaluate

build:  ## docker compose build (bakes the model into the image)
	$(UV) run python -m scripts.train_fixture
	docker compose build

demo:  ## start the container, classify the fixture set, print a pass/fail table
	$(UV) run python -m scripts.train_fixture
	docker compose up -d --build app
	bash demos/_wait_for_health.sh
	bash demos/demo.sh
	status=$$? ; docker compose down -v ; exit $$status

demo-degraded:  ## same fixture set with WHOIS_DISABLED=true
	$(UV) run python -m scripts.train_fixture
	WHOIS_DISABLED=true docker compose up -d --build app
	bash demos/_wait_for_health.sh
	bash demos/demo-degraded.sh
	status=$$? ; docker compose down -v ; exit $$status

demo-budget:  ## slow-WHOIS scenario against the request budget
	$(UV) run python -m scripts.train_fixture
	APP_ENV=test WHOIS_FAKE_DELAY_SECONDS=5 REQUEST_BUDGET_SECONDS=1 docker compose up -d --build app
	bash demos/_wait_for_health.sh
	bash demos/demo-budget.sh
	status=$$? ; docker compose down -v ; exit $$status

demo-email:  ## email body with 2 phishing + 1 benign URL (Step 14)
	$(call not_yet,demo-email,14)

clean:  ## remove caches and build output (keeps artifacts/ and data/)
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -not -path "./.git/*" -prune -exec rm -rf {} +
