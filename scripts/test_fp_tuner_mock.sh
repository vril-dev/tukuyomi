#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

API_BASE="${API_BASE:-http://localhost/tukuyomi-api}"
API_KEY="${API_KEY:-}"
TARGET_PATH="${TARGET_PATH:-rules/tukuyomi.conf}"
SIMULATE="${SIMULATE:-1}"

REQ_FILE="$(mktemp)"
RESP_FILE="$(mktemp)"
cleanup() {
  rm -f "$REQ_FILE" "$RESP_FILE"
}
trap cleanup EXIT

read_env_value() {
  local env_file="$1"
  local key="$2"
  if [[ ! -f "${env_file}" ]]; then
    return 0
  fi
  awk -F= -v key="${key}" '
    $0 ~ "^[[:space:]]*" key "=" {
      val = $0
      sub("^[[:space:]]*" key "=", "", val)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
      if (val ~ /^".*"$/ || val ~ /^'\''.*'\''$/) {
        val = substr(val, 2, length(val)-2)
      }
      print val
      exit
    }
  ' "${env_file}"
}

resolve_host_config_path() {
  local container_path="$1"
  local normalized="${container_path#./}"
  if [[ "${normalized}" == /* ]]; then
    printf '%s\n' "${normalized}"
    return 0
  fi
  if [[ "${normalized}" == data/* ]]; then
    printf '%s/%s\n' "${ROOT_DIR}" "${normalized}"
    return 0
  fi
  printf '%s/data/%s\n' "${ROOT_DIR}" "${normalized}"
}

if [[ -z "${API_KEY}" ]]; then
  config_container_path="${WAF_CONFIG_FILE:-}"
  if [[ -z "${config_container_path}" ]]; then
    config_container_path="$(read_env_value "${ROOT_DIR}/.env" "WAF_CONFIG_FILE")"
  fi
  if [[ -z "${config_container_path}" ]]; then
    config_container_path="conf/config.json"
  fi
  config_host_path="$(resolve_host_config_path "${config_container_path}")"
  if [[ -f "${config_host_path}" ]]; then
    API_KEY="$(jq -r '.admin.api_key_primary // empty' "${config_host_path}")"
  fi
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
