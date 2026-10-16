#!/usr/bin/env bash
# Demo: send an email body with 2 phishing URLs + 1 benign URL, verify the
# per-URL verdicts and the aggregate.

set -u

PHISHGUARD_URL="${PHISHGUARD_URL:-http://localhost:8000}"

BODY='Hi team, please review the invoice at https://www.acme-books.com/ and also
check the security alert at http://paypa1-secure-login.xyz/verify?session=abc and
the urgent billing notice at http://netfl1x-billing-update.cc/login.php?error=1
Thanks.'

echo "── email scan ──"
echo "body: 2 phishing URLs + 1 benign URL"
echo

response=$(curl -s -X POST "$PHISHGUARD_URL/predict_email" \
  -H 'Content-Type: application/json' \
  -d "$(python -c 'import json,sys; print(json.dumps({"body": sys.argv[1]}))' "$BODY")")

echo "$response" | python -c "
import json, sys
data = json.load(sys.stdin)
print(f'{'URL':58s} {'LABEL':10s} CONFIDENCE')
for entry in data['urls']:
    print(f\"{entry['url'][:56]:58s} {entry['label']:10s} {entry['confidence']:.4f}\")
print()
agg = data['aggregate']
print(f\"aggregate: verdict={agg['verdict']}  phishing={agg['phishing_count']}  total={agg['total']}\")
print(f\"truncated: {data['truncated']}\")
"

phishing_count=$(echo "$response" | python -c "import sys,json; print(json.load(sys.stdin)['aggregate']['phishing_count'])")
total=$(echo "$response" | python -c "import sys,json; print(json.load(sys.stdin)['aggregate']['total'])")
verdict=$(echo "$response" | python -c "import sys,json; print(json.load(sys.stdin)['aggregate']['verdict'])")

status="PASS"
[ "$phishing_count" = "2" ] || status="FAIL"
[ "$total" = "3" ] || status="FAIL"
[ "$verdict" = "phishing" ] || status="FAIL"

echo
echo "checks: phishing_count==2, total==3, verdict==phishing"
echo "result: $status"
[ "$status" = "PASS" ]
