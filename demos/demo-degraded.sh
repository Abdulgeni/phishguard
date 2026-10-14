#!/usr/bin/env bash
# Demo: same URL set as demo.sh, but the service is running with WHOIS disabled.
# Proves the service still answers correctly with WHOIS off (sentinel features).

set -u

PHISHGUARD_URL="${PHISHGUARD_URL:-http://localhost:8000}"
FIXTURES="${FIXTURES:-demos/fixtures.txt}"

echo "── degraded mode: WHOIS_DISABLED=true ──"
echo "expected: every response has domain_age_days = -1 and registrar_known = 0"
echo

pass=0
fail=0

printf '%-58s %-9s %-9s %-7s %s\n' "URL" "EXPECTED" "ACTUAL" "AGE" "STATUS"
printf -- '%.0s-' {1..100}; echo

while IFS=$'\t' read -r url expected min_conf; do
  case "$url" in ''|\#*) continue ;; esac

  body=$(curl -s -X POST "$PHISHGUARD_URL/predict" \
    -H 'Content-Type: application/json' \
    -d "{\"url\":\"$url\"}")

  actual=$(echo "$body" | python -c "import sys,json; print(json.load(sys.stdin)['label'])" 2>/dev/null || echo "-")
  age=$(echo "$body" | python -c "import sys,json; print(json.load(sys.stdin)['features']['domain_age_days'])" 2>/dev/null || echo "-")
  reg=$(echo "$body" | python -c "import sys,json; print(json.load(sys.stdin)['features']['registrar_known'])" 2>/dev/null || echo "-")

  status="PASS"
  if [ "$actual" != "$expected" ] || [ "$age" != "-1" ] || [ "$reg" != "0" ]; then
    status="FAIL"; fail=$((fail+1))
  else
    pass=$((pass+1))
  fi

  printf '%-58s %-9s %-9s %-7s %s\n' "$url" "$expected" "$actual" "$age" "$status"
done < "$FIXTURES"

echo
echo "result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
