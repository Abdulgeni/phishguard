#!/usr/bin/env bash
# Demo: prove the request budget caps latency even when WHOIS is slow.
#
# Preconditions (set by `make demo-budget`):
#   * Container runs with APP_ENV=test, WHOIS_FAKE_DELAY_SECONDS=5, REQUEST_BUDGET_SECONDS=1
#   * Server is reachable at $PHISHGUARD_URL

set -u

PHISHGUARD_URL="${PHISHGUARD_URL:-http://localhost:8000}"
URL="${URL:-https://www.python.org/}"
BUDGET="${REQUEST_BUDGET_SECONDS:-1}"

echo "── budget scenario ──"
echo "WHOIS fake delay: 5s   request budget: ${BUDGET}s"
echo "URL: ${URL}"
echo

start=$(date +%s)
response=$(curl -s -w '\n%{http_code}\n%{time_total}' -X POST "$PHISHGUARD_URL/predict" \
  -H 'Content-Type: application/json' \
  -d "{\"url\":\"$URL\"}")
end=$(date +%s)

http_code=$(echo "$response" | tail -n2 | head -n1)
time_total=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n -2)

echo "http:     $http_code"
echo "latency:  ${time_total}s"
echo "response: $(echo "$body" | head -c 200)"
echo

status="PASS"
python -c "import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) + 0.5 else 1)" "$time_total" "$BUDGET" \
  || status="FAIL"
[ "$http_code" = "200" ] || status="FAIL"

# Also assert the response has domain_age_days = -1 (WHOIS was skipped, not completed)
age=$(echo "$body" | python -c "import sys,json; print(json.load(sys.stdin)['features']['domain_age_days'])" 2>/dev/null || echo "?")
[ "$age" = "-1" ] || status="FAIL"

echo "checks: latency <= budget, http 200, domain_age_days == -1"
echo "result: $status"
[ "$status" = "PASS" ]
