#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_PUID="${PUID:-$(id -u)}"
HOST_GUID="${GUID:-$(id -g)}"
HOST_CORAZA_PORT="${HOST_CORAZA_PORT:-19090}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
BRIDGE_PORT="${BRIDGE_PORT:-18092}"
SIMULATE="${SIMULATE:-1}"
TARGET_PATH="${TARGET_PATH:-rules/tukuyomi.conf}"
API_KEY="${API_KEY:-${WAF_API_KEY_PRIMARY:-dev-only-change-this-key-please}}"
BRIDGE_COMMAND="${BRIDGE_COMMAND:-${ROOT_DIR}/scripts/fp_tuner_provider_cmd_example.sh}"
AUTO_DOWN="${FP_TUNER_BRIDGE_AUTO_DOWN:-0}"

REQ_FILE="$(mktemp)"
PROPOSE_RESP_FILE="$(mktemp)"
BRIDGE_LOG="$(mktemp)"
BRIDGE_REQUEST_LOG="$(mktemp)"
BRIDGE_PID=""
COMPOSE_ARGS=(--project-directory "${ROOT_DIR}")

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[fp-tuner-bridge] required command not found: $1" >&2
    exit 1
  fi
}

compose() {
  PUID="${HOST_PUID}" GUID="${HOST_GUID}" CORAZA_PORT="${HOST_CORAZA_PORT}" \
  WAF_FP_TUNER_ENDPOINT="http://host.docker.internal:${BRIDGE_PORT}/propose" \
  docker compose "${COMPOSE_ARGS[@]}" "$@"
}

wait_for_http_200() {
  local url="$1"
  local code
  local i
  for i in $(seq 1 "${WAIT_TIMEOUT_SECONDS}"); do
    code="$(curl -s -o /dev/null -w "%{http_code}" "${url}" || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

cleanup() {
  if [[ -n "${BRIDGE_PID}" ]]; then
    kill "${BRIDGE_PID}" >/dev/null 2>&1 || true
    wait "${BRIDGE_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "${REQ_FILE}" "${PROPOSE_RESP_FILE}" "${BRIDGE_LOG}" "${BRIDGE_REQUEST_LOG}"
  if [[ "${AUTO_DOWN}" == "1" ]]; then
    compose down --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

require_cmd docker
require_cmd curl
require_cmd jq
require_cmd python3

if [[ ! -x "${BRIDGE_COMMAND}" ]]; then
  echo "[fp-tuner-bridge] bridge command is not executable: ${BRIDGE_COMMAND}" >&2
  exit 1
fi

if [[ ! -f "${ROOT_DIR}/.env" ]]; then
  if [[ -f "${ROOT_DIR}/.env.example" ]]; then
    cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
    echo "[fp-tuner-bridge] .env was missing; copied from .env.example"
  else
    echo "[fp-tuner-bridge] .env and .env.example are missing" >&2
    exit 1
  fi
fi

FP_TUNER_BRIDGE_MODE="command" \
FP_TUNER_BRIDGE_COMMAND="${BRIDGE_COMMAND}" \
FP_TUNER_BRIDGE_PORT="${BRIDGE_PORT}" \
FP_TUNER_BRIDGE_REQUEST_LOG="${BRIDGE_REQUEST_LOG}" \
python3 "${ROOT_DIR}/scripts/fp_tuner_provider_bridge.py" >"${BRIDGE_LOG}" 2>&1 &
BRIDGE_PID="$!"

echo "[fp-tuner-bridge] started bridge on 127.0.0.1:${BRIDGE_PORT}"
if ! wait_for_http_200 "http://127.0.0.1:${BRIDGE_PORT}/healthz"; then
  echo "[fp-tuner-bridge] bridge did not become healthy in time" >&2
  cat "${BRIDGE_LOG}" >&2 || true
  exit 1
fi

compose up -d --build coraza

echo "[fp-tuner-bridge] waiting for coraza health endpoint (http://localhost:${HOST_CORAZA_PORT}/healthz, max ${WAIT_TIMEOUT_SECONDS}s)"
if ! wait_for_http_200 "http://localhost:${HOST_CORAZA_PORT}/healthz"; then
  echo "[fp-tuner-bridge] coraza did not become healthy in time" >&2
  compose ps >&2 || true
  compose logs --tail=120 coraza >&2 || true
  exit 1
fi

cat >"${REQ_FILE}" <<JSON
{
  "target_path": "${TARGET_PATH}",
  "event": {
    "event_id": "manual-bridge-test-001",
    "method": "GET",
    "scheme": "https",
    "host": "search.example.com",
    "path": "/search",
    "rule_id": 100004,
    "status": 403,
    "matched_variable": "ARGS:q",
    "matched_value": "token=sensitive-value&email=a@example.com&ip=10.1.2.3"
  }
}
JSON

headers=(-H "Content-Type: application/json")
if [[ -n "${API_KEY}" ]]; then
  headers+=(-H "X-API-Key: ${API_KEY}")
fi

echo "==> Propose (http + command bridge)"
curl -fsS "${headers[@]}" \
  -X POST "http://localhost:${HOST_CORAZA_PORT}/tukuyomi-api/fp-tuner/propose" \
  --data @"${REQ_FILE}" | tee "${PROPOSE_RESP_FILE}"
echo

if ! jq -e '.ok == true and .mode == "http" and (.proposal.id | length > 0)' "${PROPOSE_RESP_FILE}" >/dev/null; then
  echo "[fp-tuner-bridge] propose response is not in expected format" >&2
  exit 1
fi

if [[ ! -s "${BRIDGE_REQUEST_LOG}" ]]; then
  echo "[fp-tuner-bridge] bridge did not receive provider payload" >&2
  exit 1
fi

provider_input="$(tail -n 1 "${BRIDGE_REQUEST_LOG}")"
if ! printf '%s\n' "${provider_input}" | jq -e '.input.matched_value | contains("token=[redacted]") and contains("[redacted-email]") and contains("[redacted-ip]")' >/dev/null; then
  echo "[fp-tuner-bridge] provider payload was not masked as expected" >&2
  printf '%s\n' "${provider_input}" >&2
  exit 1
fi
if printf '%s\n' "${provider_input}" | grep -q 'a@example.com\|sensitive-value\|10.1.2.3'; then
  echo "[fp-tuner-bridge] provider payload leaked unmasked value" >&2
  printf '%s\n' "${provider_input}" >&2
  exit 1
fi

echo "==> Apply"
apply_payload="$(jq -c --argjson simulate "$([[ "${SIMULATE}" == "1" ]] && echo true || echo false)" '
  {
    proposal: .proposal,
    simulate: $simulate,
    approval_token: (.approval.token // "")
  }' "${PROPOSE_RESP_FILE}")"
curl -fsS "${headers[@]}" \
  -X POST "http://localhost:${HOST_CORAZA_PORT}/tukuyomi-api/fp-tuner/apply" \
  --data "${apply_payload}"
echo

echo "[fp-tuner-bridge] completed. SIMULATE=${SIMULATE}"
