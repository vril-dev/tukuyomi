#!/usr/bin/env bash
set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

API_BASE="${API_BASE:-http://localhost/tukuyomi-api}"
API_KEY="${API_KEY:-${WAF_API_KEY_PRIMARY:-}}"
TARGET_PATH="${TARGET_PATH:-rules/tukuyomi.conf}"
SIMULATE="${SIMULATE:-1}"

REQ_FILE="$(mktemp)"
RESP_FILE="$(mktemp)"
cleanup() {
  rm -f "$REQ_FILE" "$RESP_FILE"
}
trap cleanup EXIT

cat >"$REQ_FILE" <<JSON
{
  "target_path": "$TARGET_PATH",
  "event": {
    "event_id": "manual-test-001",
    "method": "GET",
    "path": "/search",
    "rule_id": 100004,
    "status": 403,
    "matched_variable": "ARGS:q",
    "matched_value": "select * from users"
  }
}
JSON

headers=(-H "Content-Type: application/json")
if [[ -n "$API_KEY" ]]; then
  headers+=(-H "X-API-Key: $API_KEY")
fi

echo "==> Propose"
curl -fsS "${headers[@]}" \
  -X POST "$API_BASE/fp-tuner/propose" \
  --data @"$REQ_FILE" | tee "$RESP_FILE"

echo

echo "==> Apply"
apply_payload="$(jq -c --argjson simulate "$([[ "$SIMULATE" == "1" ]] && echo true || echo false)" '
  {
    proposal: .proposal,
    simulate: $simulate,
    approval_token: (.approval.token // "")
  }' "$RESP_FILE")"
curl -fsS "${headers[@]}" \
  -X POST "$API_BASE/fp-tuner/apply" \
  --data "$apply_payload"
echo

echo "Done. SIMULATE=$SIMULATE"
