#!/usr/bin/env bash
# Poll /health until it returns 200 or we give up.

set -u

PHISHGUARD_URL="${PHISHGUARD_URL:-http://localhost:8000}"
tries="${HEALTH_TRIES:-30}"

for i in $(seq 1 "$tries"); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$PHISHGUARD_URL/health" || echo "000")
  if [ "$code" = "200" ]; then
    echo "server up after ${i} tries"
    exit 0
  fi
  sleep 1
done

echo "server never became healthy; last code=$code" >&2
exit 1
