#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

API_BASE="${API_BASE:-http://localhost/tukuyomi-api}"
ADMIN_BEARER_TOKEN="${ADMIN_BEARER_TOKEN:-}"
WAF_ADMIN_USERNAME="${WAF_ADMIN_USERNAME:-${TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME:-admin}}"
WAF_ADMIN_PASSWORD="${WAF_ADMIN_PASSWORD:-${TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD:-dev-only-change-this-password-please}}"
TARGET_PATH="${TARGET_PATH:-tukuyomi.conf}"
SIMULATE="${SIMULATE:-1}"

REQ_FILE="$(mktemp)"
RESP_FILE="$(mktemp)"
LOGIN_RESP_FILE="$(mktemp)"
COOKIE_JAR="$(mktemp)"
CSRF_TOKEN=""
cleanup() {
  rm -f "$REQ_FILE" "$RESP_FILE" "$LOGIN_RESP_FILE" "$COOKIE_JAR"
}
trap cleanup EXIT

auth_args=()
if [[ -n "${ADMIN_BEARER_TOKEN}" ]]; then
  auth_args=(-H "Authorization: Bearer ${ADMIN_BEARER_TOKEN}")
else
  login_payload="$(jq -n --arg username "${WAF_ADMIN_USERNAME}" --arg password "${WAF_ADMIN_PASSWORD}" '{username: $username, password: $password}')"
  login_code="$(curl -sS -o "${LOGIN_RESP_FILE}" -w "%{http_code}" \
    -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
    -H "Content-Type: application/json" \
    -X POST --data "${login_payload}" \
    "${API_BASE}/auth/login")"
  if [[ "${login_code}" != "200" ]]; then
    echo "[fp-tuner-mock] admin login failed: ${login_code}" >&2
    cat "${LOGIN_RESP_FILE}" >&2 || true
    exit 1
  fi
  CSRF_TOKEN="$(
    awk 'NF >= 7 && $6 == "tukuyomi_admin_csrf" { token = $7 } END { if (token != "") print token }' "${COOKIE_JAR}"
  )"
  [[ -n "${CSRF_TOKEN}" ]] || {
    echo "[fp-tuner-mock] admin login did not issue csrf cookie" >&2
    exit 1
  }
  auth_args=(-b "${COOKIE_JAR}" -c "${COOKIE_JAR}" -H "X-CSRF-Token: ${CSRF_TOKEN}")
fi

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

echo "==> Propose"
curl -fsS "${auth_args[@]}" "${headers[@]}" \
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
curl -fsS "${auth_args[@]}" "${headers[@]}" \
  -X POST "$API_BASE/fp-tuner/apply" \
  --data "$apply_payload"
echo

echo "Done. SIMULATE=$SIMULATE"
