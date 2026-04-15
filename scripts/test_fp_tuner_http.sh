#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_PUID="${PUID:-$(id -u)}"
HOST_GUID="${GUID:-$(id -g)}"
HOST_CORAZA_PORT="${HOST_CORAZA_PORT:-19090}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
MOCK_PROVIDER_PORT="${MOCK_PROVIDER_PORT:-18091}"
SIMULATE="${SIMULATE:-1}"
TARGET_PATH="${TARGET_PATH:-rules/tukuyomi.conf}"
API_KEY="${API_KEY:-${WAF_API_KEY_PRIMARY:-dev-only-change-this-key-please}}"
AUTO_DOWN="${FP_TUNER_HTTP_AUTO_DOWN:-0}"

REQ_FILE="$(mktemp)"
PROPOSE_RESP_FILE="$(mktemp)"
PROVIDER_LOG="$(mktemp)"
PROVIDER_PID=""
COMPOSE_ARGS=(--project-directory "${ROOT_DIR}")

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[fp-tuner-http] required command not found: $1" >&2
    exit 1
  fi
}

compose() {
  PUID="${HOST_PUID}" GUID="${HOST_GUID}" CORAZA_PORT="${HOST_CORAZA_PORT}" \
  WAF_FP_TUNER_ENDPOINT="http://host.docker.internal:${MOCK_PROVIDER_PORT}/propose" \
  docker compose "${COMPOSE_ARGS[@]}" "$@"
}

wait_for_coraza() {
  local code
  local i
  for i in $(seq 1 "${WAIT_TIMEOUT_SECONDS}"); do
    code="$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${HOST_CORAZA_PORT}/healthz" || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

cleanup() {
  if [[ -n "${PROVIDER_PID}" ]]; then
    kill "${PROVIDER_PID}" >/dev/null 2>&1 || true
    wait "${PROVIDER_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "${REQ_FILE}" "${PROPOSE_RESP_FILE}" "${PROVIDER_LOG}"
  if [[ "${AUTO_DOWN}" == "1" ]]; then
    compose down --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

require_cmd docker
require_cmd curl
require_cmd jq
require_cmd python3

if [[ ! -f "${ROOT_DIR}/.env" ]]; then
  if [[ -f "${ROOT_DIR}/.env.example" ]]; then
    cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
    echo "[fp-tuner-http] .env was missing; copied from .env.example"
  else
    echo "[fp-tuner-http] .env and .env.example are missing" >&2
    exit 1
  fi
fi

python3 - "${MOCK_PROVIDER_PORT}" "${PROVIDER_LOG}" <<'PY' &
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])
log_path = sys.argv[2]

proposal = {
    "id": "fp-http-stub-001",
    "title": "Scoped false-positive tuning suggestion",
    "summary": "Stub provider response for HTTP mode testing.",
    "reason": "Local stub response used to verify send/receive/apply flow.",
    "confidence": 0.88,
    "target_path": "rules/tukuyomi.conf",
    "rule_line": "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\"",
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(raw)
            f.write("\n")

        payload = json.dumps({"proposal": proposal}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        return


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
PROVIDER_PID="$!"

echo "[fp-tuner-http] started local stub provider on 127.0.0.1:${MOCK_PROVIDER_PORT}"

compose up -d --build coraza

echo "[fp-tuner-http] waiting for coraza health endpoint (http://localhost:${HOST_CORAZA_PORT}/healthz, max ${WAIT_TIMEOUT_SECONDS}s)"
if ! wait_for_coraza; then
  echo "[fp-tuner-http] coraza did not become healthy in time" >&2
  compose ps >&2 || true
  compose logs --tail=120 coraza >&2 || true
  exit 1
fi

cat >"${REQ_FILE}" <<JSON
{
  "target_path": "${TARGET_PATH}",
  "event": {
    "event_id": "manual-http-test-001",
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

echo "==> Propose (http mode)"
curl -fsS "${headers[@]}" \
  -X POST "http://localhost:${HOST_CORAZA_PORT}/tukuyomi-api/fp-tuner/propose" \
  --data @"${REQ_FILE}" | tee "${PROPOSE_RESP_FILE}"
echo

if ! jq -e '.ok == true and .mode == "http"' "${PROPOSE_RESP_FILE}" >/dev/null; then
  echo "[fp-tuner-http] propose response is not in expected http mode format" >&2
  exit 1
fi

if [[ ! -s "${PROVIDER_LOG}" ]]; then
  echo "[fp-tuner-http] provider did not receive payload" >&2
  exit 1
fi

provider_input="$(tail -n 1 "${PROVIDER_LOG}")"
if ! printf '%s\n' "${provider_input}" | jq -e '.input.matched_value | contains("token=[redacted]") and contains("[redacted-email]") and contains("[redacted-ip]")' >/dev/null; then
  echo "[fp-tuner-http] provider payload was not masked as expected" >&2
  printf '%s\n' "${provider_input}" >&2
  exit 1
fi
if printf '%s\n' "${provider_input}" | grep -q 'a@example.com\|sensitive-value\|10.1.2.3'; then
  echo "[fp-tuner-http] provider payload leaked unmasked value" >&2
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

echo "[fp-tuner-http] completed. SIMULATE=${SIMULATE}"
