#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_PUID="${PUID:-$(id -u)}"
HOST_GUID="${GUID:-$(id -g)}"
HOST_CORAZA_PORT="${HOST_CORAZA_PORT:-19090}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
MOCK_PROVIDER_PORT="${MOCK_PROVIDER_PORT:-18091}"
SIMULATE="${SIMULATE:-1}"
TARGET_PATH="${TARGET_PATH:-tukuyomi.conf}"
API_KEY="${API_KEY:-}"
AUTO_DOWN="${FP_TUNER_HTTP_AUTO_DOWN:-0}"

REQ_FILE="$(mktemp)"
PROPOSE_RESP_FILE="$(mktemp)"
PROVIDER_LOG="$(mktemp)"
PROVIDER_PID=""
COMPOSE_ARGS=(--project-directory "${ROOT_DIR}")
CONFIG_ENV_FILE="${ROOT_DIR}/.env"
HOST_CONFIG_FILE=""
TEMP_CONFIG_CONTAINER_PATH=""
HOST_TEMP_CONFIG_FILE=""

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[fp-tuner-http] required command not found: $1" >&2
    exit 1
  fi
}

compose() {
  PUID="${HOST_PUID}" GUID="${HOST_GUID}" CORAZA_PORT="${HOST_CORAZA_PORT}" \
  WAF_CONFIG_FILE="${TEMP_CONFIG_CONTAINER_PATH}" \
  docker compose "${COMPOSE_ARGS[@]}" "$@"
}

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

prepare_fp_tuner_http_config() {
  local config_container_path="${WAF_CONFIG_FILE:-}"
  local config_dir config_base config_stem endpoint

  if [[ -z "${config_container_path}" ]]; then
    config_container_path="$(read_env_value "${CONFIG_ENV_FILE}" "WAF_CONFIG_FILE")"
  fi
  if [[ -z "${config_container_path}" ]]; then
    config_container_path="conf/config.json"
  fi

  HOST_CONFIG_FILE="$(resolve_host_config_path "${config_container_path}")"
  if [[ ! -f "${HOST_CONFIG_FILE}" ]]; then
    echo "[fp-tuner-http] config file not found: ${HOST_CONFIG_FILE}" >&2
    exit 1
  fi

  if [[ -z "${API_KEY}" ]]; then
    API_KEY="$(jq -r '.admin.api_key_primary // empty' "${HOST_CONFIG_FILE}")"
  fi

  config_dir="$(dirname "${config_container_path}")"
  config_base="$(basename "${config_container_path}")"
  if [[ "${config_base}" == *.json ]]; then
    config_stem="${config_base%.json}"
    TEMP_CONFIG_CONTAINER_PATH="${config_dir}/${config_stem}.fp-tuner-http.json"
  else
    TEMP_CONFIG_CONTAINER_PATH="${config_container_path}.fp-tuner-http.json"
  fi
  HOST_TEMP_CONFIG_FILE="$(resolve_host_config_path "${TEMP_CONFIG_CONTAINER_PATH}")"
  mkdir -p "$(dirname "${HOST_TEMP_CONFIG_FILE}")"

  endpoint="http://host.docker.internal:${MOCK_PROVIDER_PORT}/propose"
  jq --arg endpoint "${endpoint}" \
    '.fp_tuner.endpoint = $endpoint' \
    "${HOST_CONFIG_FILE}" > "${HOST_TEMP_CONFIG_FILE}"
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
  if [[ -n "${HOST_TEMP_CONFIG_FILE}" ]]; then
    rm -f "${HOST_TEMP_CONFIG_FILE}"
  fi
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

prepare_fp_tuner_http_config

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
    "target_path": "tukuyomi.conf",
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
    "query": "token=sensitive-value&email=a@example.com&ip=10.1.2.3",
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
if ! printf '%s\n' "${provider_input}" | jq -e '.input.host == "search.example.com"' >/dev/null; then
  echo "[fp-tuner-http] provider payload did not preserve host context" >&2
  printf '%s\n' "${provider_input}" >&2
  exit 1
fi
if ! printf '%s\n' "${provider_input}" | jq -e '.input.scheme == "https"' >/dev/null; then
  echo "[fp-tuner-http] provider payload did not preserve scheme context" >&2
  printf '%s\n' "${provider_input}" >&2
  exit 1
fi
if ! printf '%s\n' "${provider_input}" | jq -e '.input.query | contains("token=[redacted]") and contains("[redacted-email]") and contains("[redacted-ip]")' >/dev/null; then
  echo "[fp-tuner-http] provider query payload was not masked as expected" >&2
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
