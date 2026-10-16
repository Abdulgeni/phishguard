# syntax=docker/dockerfile:1.6

# ---- builder --------------------------------------------------------------
# Wheel-only runtime: every dependency ships manylinux wheels for CPython 3.11.
# We install from pyproject.toml BEFORE copying app/, so code changes do not
# invalidate the expensive dependency layer.
FROM python:3.11-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ONLY_BINARY=:all: \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src
COPY pyproject.toml ./
# Minimal package stub so `pip install .` can resolve metadata without app/.
RUN mkdir -p app \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install .

# Now copy the real code. Changes here invalidate only this layer and below.
COPY app ./app
COPY scripts ./scripts

# ---- runtime --------------------------------------------------------------
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    MODEL_PATH=/app/artifacts/model.joblib

RUN groupadd --system --gid 1000 app \
 && useradd --system --uid 1000 --gid app --create-home app

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY app ./app
COPY scripts ./scripts
COPY pyproject.toml ./
COPY artifacts ./artifacts

USER app
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
