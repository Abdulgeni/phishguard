#!/usr/bin/env bash
# Demo: send a labeled URL set to /predict and print a pass/fail table.
# Assumes the service is already running and reachable at $PHISHGUARD_URL.

set -u

PHISHGUARD_URL="${PHISHGUARD_URL:-http://localhost:8000}"
FIXTURES="${FIXTURES:-demos/fixtures.txt}"

pass=0
fail=0

printf '%-58s %-9s %-9s %-7s %-6s %s\n' "URL" "EXPECTED" "ACTUAL" "CONF" "LAT" "STATUS"
printf -- '%.0s-' {1..110}; echo

while IFS=$'\t' read -r url expected min_conf; do
  case "$url" in ''|\#*) continue ;; esac

  response=$(curl -s -w '\n%{http_code}\n%{time_total}' -X POST "$PHISHGUARD_URL/predict" \
    -H 'Content-Type: application/json' \
    -d "{\"url\":\"$url\"}") || {
      printf '%-58s %-9s %-9s %-7s %-6s %s\n' "$url" "$expected" "-" "-" "-" "CURL_FAIL"
      fail=$((fail+1)); continue
    }

  http_code=$(echo "$response" | tail -n2 | head -n1)
  time_total=$(echo "$response" | tail -n1)
  body=$(echo "$response" | head -n -2)

  if [ "$http_code" != "200" ]; then
    printf '%-58s %-9s %-9s %-7s %-6s %s\n' "$url" "$expected" "-" "-" "${time_total}s" "HTTP_$http_code"
    fail=$((fail+1)); continue
  fi

  actual=$(echo "$body" | python -c "import sys,json; print(json.load(sys.stdin)['label'])")
  conf=$(echo "$body" | python -c "import sys,json; print(f\"{json.load(sys.stdin)['confidence']:.3f}\")")

  status="PASS"
  python -c "
import sys
actual, expected, conf, min_conf = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
sys.exit(0 if actual == expected and conf >= min_conf else 1)
" "$actual" "$expected" "$conf" "$min_conf" || status="FAIL"

  if [ "$status" = "PASS" ]; then pass=$((pass+1)); else fail=$((fail+1)); fi

  printf '%-58s %-9s %-9s %-7s %-6s %s\n' "$url" "$expected" "$actual" "$conf" "${time_total}s" "$status"
done < "$FIXTURES"

echo
echo "result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
