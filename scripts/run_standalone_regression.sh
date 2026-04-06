#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: run_standalone_regression.sh <example-name> [fast|extended]" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLE_NAME="$1"
MODE="${2:-fast}"
EXAMPLE_DIR="${ROOT_DIR}/examples/${EXAMPLE_NAME}"
PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
STANDALONE_SKIP_SETUP="${STANDALONE_SKIP_SETUP:-0}"
STANDALONE_AUTO_DOWN="${STANDALONE_AUTO_DOWN:-1}"
STANDALONE_RESET_OPERATIONAL_LOGS="${STANDALONE_RESET_OPERATIONAL_LOGS:-1}"
STANDALONE_POLICY_FIXTURE_IMAGE="${STANDALONE_POLICY_FIXTURE_IMAGE:-curlimages/curl:8.8.0}"
PENDING_CONF_CLEANUP=()
PENDING_TMP_CLEANUP=()
COMPOSE_ENV=()
COMPOSE_PROFILES=()
POLICY_FIXTURE_ENABLED=0
POLICY_FIXTURE_NETWORK=""
POLICY_ORIGINAL_BYPASS_RAW=""
POLICY_ORIGINAL_COUNTRY_RAW=""

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[standalone-regression][ERROR] missing command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[standalone-regression] $*"
}

fail() {
  echo "[standalone-regression][ERROR] $*" >&2
  exit 1
}

cleanup_tmp_file() {
  local path="$1"
  PENDING_TMP_CLEANUP+=("${path}")
}

track_optional_conf_cleanup() {
  local path="$1"
  if [[ ! -e "${path}" ]]; then
    PENDING_CONF_CLEANUP+=("${path}")
  fi
}

read_env_value() {
  local env_file="$1"
  local key="$2"
  local line
  local value

  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" ]] && continue
    [[ "${line}" =~ ^[[:space:]]*# ]] && continue
    if [[ "${line}" != "${key}="* ]]; then
      continue
    fi
    value="${line#*=}"
    value="${value%$'\r'}"
    if [[ "${value}" == \"*\" && "${value}" == *\" ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "${value}" == \'*\' && "${value}" == *\' ]]; then
      value="${value:1:${#value}-2}"
    fi
    printf '%s' "${value}"
    return 0
  done < "${env_file}"

  return 1
}

wait_for_http_200() {
  local url="$1"
  local header_name="${2:-}"
  local header_value="${3:-}"
  local code=""
  local i

  for i in $(seq 1 "${WAIT_TIMEOUT_SECONDS}"); do
    if [[ -n "${header_name}" ]]; then
      code="$(curl -sS -o /dev/null -w "%{http_code}" -H "${header_name}: ${header_value}" "${url}" || true)"
    else
      code="$(curl -sS -o /dev/null -w "%{http_code}" "${url}" || true)"
    fi
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

curl_expect_code() {
  local expected_code="$1"
  shift
  local url="$1"
  shift || true
  local tmp_body
  local code
  tmp_body="$(mktemp)"
  code="$(curl -sS -o "${tmp_body}" -w "%{http_code}" "$@" "${url}" || true)"
  if [[ "${code}" != "${expected_code}" ]]; then
    cat "${tmp_body}" >&2 || true
    rm -f "${tmp_body}"
    fail "expected ${expected_code} from ${url}, got ${code}"
  fi
  rm -f "${tmp_body}"
}

curl_expect_200() {
  local url="$1"
  shift || true
  curl_expect_code "200" "${url}" "$@"
}

curl_expect_nonempty_lines() {
  local url="$1"
  shift
  local tmp_body
  local code
  tmp_body="$(mktemp)"
  code="$(curl -sS -o "${tmp_body}" -w "%{http_code}" "$@" "${url}" || true)"
  if [[ "${code}" != "200" ]]; then
    cat "${tmp_body}" >&2 || true
    rm -f "${tmp_body}"
    fail "expected 200 from ${url}, got ${code}"
  fi
  python3 - "${tmp_body}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
lines = payload.get("lines")
if not isinstance(lines, list) or not lines:
    raise SystemExit("logs payload has no lines")
PY
  rm -f "${tmp_body}"
}

compose_in_example() {
  (
    cd "${EXAMPLE_DIR}"
    env "${COMPOSE_ENV[@]}" docker compose "${COMPOSE_PROFILES[@]}" "$@"
  )
}

api_get_raw_to_file() {
  local endpoint="$1"
  local out_file="$2"
  local tmp_body
  local code

  tmp_body="$(mktemp)"
  cleanup_tmp_file "${tmp_body}"
  code="$(curl -sS -o "${tmp_body}" -w "%{http_code}" \
    -H "X-API-Key: ${API_KEY}" \
    "${BASE_URL}${API_BASEPATH}/${endpoint}" || true)"
  if [[ "${code}" != "200" ]]; then
    cat "${tmp_body}" >&2 || true
    fail "expected 200 from ${endpoint}, got ${code}"
  fi

  python3 - "${tmp_body}" "${out_file}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
raw = payload.get("raw")
if not isinstance(raw, str):
    raise SystemExit("payload.raw missing or not a string")
pathlib.Path(sys.argv[2]).write_text(raw)
PY
}

api_put_raw_from_file() {
  local endpoint="$1"
  local in_file="$2"
  local tmp_body
  local tmp_payload
  local code

  tmp_body="$(mktemp)"
  tmp_payload="$(mktemp)"
  cleanup_tmp_file "${tmp_body}"
  cleanup_tmp_file "${tmp_payload}"

  python3 - "${in_file}" "${tmp_payload}" <<'PY'
import json
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_text()
pathlib.Path(sys.argv[2]).write_text(json.dumps({"raw": raw}))
PY

  code="$(curl -sS -o "${tmp_body}" -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: ${API_KEY}" \
    -X PUT \
    --data-binary "@${tmp_payload}" \
    "${BASE_URL}${API_BASEPATH}/${endpoint}" || true)"
  if [[ "${code}" != "200" ]]; then
    cat "${tmp_body}" >&2 || true
    return 1
  fi

  return 0
}

policy_fixture_http_code() {
  local target_url="$1"
  shift

  docker run --rm --network "${POLICY_FIXTURE_NETWORK}" "${STANDALONE_POLICY_FIXTURE_IMAGE}" \
    -sS -o /dev/null -w "%{http_code}" "$@" "${target_url}" 2>/dev/null || true
}

restore_policy_fixtures() {
  if [[ -n "${POLICY_ORIGINAL_COUNTRY_RAW}" ]]; then
    api_put_raw_from_file "country-block-rules" "${POLICY_ORIGINAL_COUNTRY_RAW}" >/dev/null 2>&1 || \
      echo "[standalone-regression][WARN] failed to restore country-block rules" >&2
  fi
  if [[ -n "${POLICY_ORIGINAL_BYPASS_RAW}" ]]; then
    api_put_raw_from_file "bypass-rules" "${POLICY_ORIGINAL_BYPASS_RAW}" >/dev/null 2>&1 || \
      echo "[standalone-regression][WARN] failed to restore bypass rules" >&2
  fi
}

run_api_gateway_policy_fixture_checks() {
  local front_internal_url="$1"
  local direct_host_url="$2"
  local direct_internal_url="$3"
  local tmp_bypass
  local tmp_country
  local tmp_mutation
  local trusted_code
  local untrusted_code

  if [[ "${POLICY_FIXTURE_ENABLED}" != "1" ]]; then
    fail "policy fixture requested without trusted front-proxy fixture"
  fi

  tmp_bypass="$(mktemp)"
  tmp_country="$(mktemp)"
  tmp_mutation="$(mktemp)"
  cleanup_tmp_file "${tmp_bypass}"
  cleanup_tmp_file "${tmp_country}"
  cleanup_tmp_file "${tmp_mutation}"
  POLICY_ORIGINAL_BYPASS_RAW="${tmp_bypass}"
  POLICY_ORIGINAL_COUNTRY_RAW="${tmp_country}"

  log "capturing current bypass and country-block config"
  api_get_raw_to_file "bypass-rules" "${tmp_bypass}"
  api_get_raw_to_file "country-block-rules" "${tmp_country}"

  log "running api-gateway bypass fixture check"
  printf '/v1/whoami\n' > "${tmp_mutation}"
  api_put_raw_from_file "bypass-rules" "${tmp_mutation}" || fail "failed to apply bypass fixture"
  curl_expect_code "200" "${direct_host_url}/v1/whoami?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" -H "Host: ${PROTECTED_HOST}"
  curl_expect_code "403" "${direct_host_url}/v1/products?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" -H "Host: ${PROTECTED_HOST}"

  log "running api-gateway country-block fixture check (trusted front proxy)"
  printf 'JP\n' > "${tmp_mutation}"
  api_put_raw_from_file "country-block-rules" "${tmp_mutation}" || fail "failed to apply JP country block fixture"
  trusted_code="$(policy_fixture_http_code "${front_internal_url}/v1/health" -H "Host: ${PROTECTED_HOST}" -H "CF-IPCountry: JP")"
  if [[ "${trusted_code}" != "403" ]]; then
    fail "expected trusted front-proxy country block to return 403, got ${trusted_code}"
  fi

  log "running api-gateway country-block fixture check (untrusted headers ignored)"
  untrusted_code="$(policy_fixture_http_code "${direct_internal_url}/v1/health" -H "Host: ${PROTECTED_HOST}" -H "CF-IPCountry: JP")"
  if [[ "${untrusted_code}" != "200" ]]; then
    fail "expected untrusted direct country header to be ignored under JP block, got ${untrusted_code}"
  fi

  log "running api-gateway country-block fixture check (untrusted headers degrade to UNKNOWN)"
  printf 'UNKNOWN\n' > "${tmp_mutation}"
  api_put_raw_from_file "country-block-rules" "${tmp_mutation}" || fail "failed to apply UNKNOWN country block fixture"
  untrusted_code="$(policy_fixture_http_code "${direct_internal_url}/v1/health" -H "Host: ${PROTECTED_HOST}" -H "CF-IPCountry: JP")"
  if [[ "${untrusted_code}" != "403" ]]; then
    fail "expected untrusted direct country header to degrade to UNKNOWN and return 403, got ${untrusted_code}"
  fi
}

run_api_gateway_extended_checks() {
  local base_url="$1"
  local tmp_body
  local hit_429="0"
  local i
  local code

  tmp_body="$(mktemp)"
  trap 'rm -f "${tmp_body}"' RETURN

  log "running api-gateway rate-limit check"
  for i in $(seq 1 12); do
    code="$(curl -sS -o "${tmp_body}" -w "%{http_code}" \
      -H "Host: ${PROTECTED_HOST}" \
      -H 'content-type: application/json' \
      -X POST \
      "${base_url}/v1/auth/login" \
      -d '{"username":"demo","password":"demo"}' || true)"
    if [[ "${code}" == "429" ]]; then
      hit_429="1"
      break
    fi
  done
  if [[ "${hit_429}" != "1" ]]; then
    cat "${tmp_body}" >&2 || true
    fail "api-gateway extended rate-limit check did not observe 429"
  fi
}

if [[ ! -d "${EXAMPLE_DIR}" ]]; then
  fail "unknown example: ${EXAMPLE_NAME}"
fi
if [[ ! -x "${EXAMPLE_DIR}/smoke.sh" ]]; then
  fail "example has no executable smoke.sh: ${EXAMPLE_DIR}"
fi
if [[ "${MODE}" != "fast" && "${MODE}" != "extended" ]]; then
  fail "unsupported mode: ${MODE}"
fi

need_cmd curl
need_cmd docker
need_cmd python3

cleanup() {
  local path
  if [[ -n "${POLICY_ORIGINAL_BYPASS_RAW}" || -n "${POLICY_ORIGINAL_COUNTRY_RAW}" ]]; then
    restore_policy_fixtures
  fi
  if [[ "${STANDALONE_AUTO_DOWN}" == "1" ]]; then
    compose_in_example down --remove-orphans >/dev/null 2>&1 || true
  fi
  for path in "${PENDING_CONF_CLEANUP[@]:-}"; do
    rm -f "${path}" >/dev/null 2>&1 || true
  done
  for path in "${PENDING_TMP_CLEANUP[@]:-}"; do
    rm -f "${path}" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

export COMPOSE_PROJECT_NAME="tukuyomi-${EXAMPLE_NAME//[^a-zA-Z0-9]/}-standalone"

if [[ ! -f "${EXAMPLE_DIR}/.env" ]]; then
  cp "${EXAMPLE_DIR}/.env.example" "${EXAMPLE_DIR}/.env"
  log "copied ${EXAMPLE_NAME}/.env from .env.example"
fi

if [[ "${STANDALONE_SKIP_SETUP}" != "1" ]]; then
  if [[ ! -d "${EXAMPLE_DIR}/data/rules/crs/rules" || ! -f "${EXAMPLE_DIR}/.env" ]]; then
    (cd "${EXAMPLE_DIR}" && ./setup.sh)
  else
    log "setup already satisfied; skipping ./setup.sh"
  fi
fi

ENV_FILE="${EXAMPLE_DIR}/.env"
track_optional_conf_cleanup "${EXAMPLE_DIR}/data/conf/ip-reputation.conf"
track_optional_conf_cleanup "${EXAMPLE_DIR}/data/conf/notifications.conf"
CORAZA_PORT_VALUE="$(read_env_value "${ENV_FILE}" "CORAZA_PORT" || true)"
NGINX_PORT_VALUE="$(read_env_value "${ENV_FILE}" "NGINX_PORT" || true)"
WAF_API_BASEPATH_VALUE="$(read_env_value "${ENV_FILE}" "WAF_API_BASEPATH" || true)"
VITE_APP_BASE_PATH_VALUE="$(read_env_value "${ENV_FILE}" "VITE_APP_BASE_PATH" || true)"
WAF_UI_BASEPATH_VALUE="$(read_env_value "${ENV_FILE}" "WAF_UI_BASEPATH" || true)"
WAF_API_KEY_PRIMARY_VALUE="$(read_env_value "${ENV_FILE}" "WAF_API_KEY_PRIMARY" || true)"
VITE_API_KEY_VALUE="$(read_env_value "${ENV_FILE}" "VITE_API_KEY" || true)"
FRONT_PROXY_FIXTURE_IP_VALUE="$(read_env_value "${ENV_FILE}" "FRONT_PROXY_FIXTURE_IP" || true)"

BASE_URL="${STANDALONE_BASE_URL:-http://127.0.0.1:${CORAZA_PORT_VALUE:-19090}}"
FRONT_BASE_URL="${STANDALONE_FRONT_BASE_URL:-http://127.0.0.1:${NGINX_PORT_VALUE:-18083}}"
API_BASEPATH="${STANDALONE_API_BASEPATH:-${WAF_API_BASEPATH_VALUE:-/tukuyomi-api}}"
UI_BASEPATH="${STANDALONE_UI_BASEPATH:-${VITE_APP_BASE_PATH_VALUE:-${WAF_UI_BASEPATH_VALUE:-/tukuyomi-admin}}}"
API_KEY="${STANDALONE_API_KEY:-${WAF_API_KEY_PRIMARY_VALUE:-${VITE_API_KEY_VALUE:-}}}"
FRONT_PROXY_FIXTURE_IP="${STANDALONE_FRONT_PROXY_FIXTURE_IP:-${FRONT_PROXY_FIXTURE_IP_VALUE:-172.31.83.10}}"

if [[ "${MODE}" == "extended" && "${EXAMPLE_NAME}" == "api-gateway" ]]; then
  POLICY_FIXTURE_ENABLED="1"
  COMPOSE_PROFILES=(--profile front-proxy)
  COMPOSE_ENV+=("WAF_TRUSTED_PROXY_CIDRS=${FRONT_PROXY_FIXTURE_IP}/32")
  COMPOSE_ENV+=("WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true")
  POLICY_FIXTURE_NETWORK="${COMPOSE_PROJECT_NAME}_default"
fi

if [[ "${STANDALONE_RESET_OPERATIONAL_LOGS}" == "1" ]]; then
  rm -f "${EXAMPLE_DIR}/data/logs/nginx/access-error.ndjson" \
        "${EXAMPLE_DIR}/data/logs/nginx/interesting.ndjson"
fi

log "starting ${EXAMPLE_NAME} example for direct tukuyomi checks (${MODE})"
compose_in_example up -d --build

log "waiting for coraza health endpoint (${BASE_URL}/healthz, max ${WAIT_TIMEOUT_SECONDS}s)"
if ! wait_for_http_200 "${BASE_URL}/healthz"; then
  compose_in_example ps -a >&2 || true
  compose_in_example logs --no-color >&2 || true
  fail "coraza did not become healthy in time"
fi

log "checking admin UI on direct coraza path"
curl_expect_200 "${BASE_URL}${UI_BASEPATH}/"

if [[ -z "${API_KEY}" ]]; then
  fail "missing API key for admin API checks"
fi

log "checking admin API status and logs on direct coraza path"
curl_expect_200 "${BASE_URL}${API_BASEPATH}/status" -H "X-API-Key: ${API_KEY}"
curl_expect_200 "${BASE_URL}${API_BASEPATH}/logs/read?src=waf&tail=1" -H "X-API-Key: ${API_KEY}"
curl_expect_200 "${BASE_URL}${API_BASEPATH}/logs/read?src=intr&tail=1" -H "X-API-Key: ${API_KEY}"
curl_expect_200 "${BASE_URL}${API_BASEPATH}/logs/read?src=accerr&tail=1" -H "X-API-Key: ${API_KEY}"

log "running protected-host smoke directly against coraza"
(cd "${EXAMPLE_DIR}" && PROTECTED_HOST="${PROTECTED_HOST}" BASE_URL="${BASE_URL}" ./smoke.sh)

log "checking standalone operational log parity after smoke"
curl_expect_nonempty_lines "${BASE_URL}${API_BASEPATH}/logs/read?src=intr&tail=5" -H "X-API-Key: ${API_KEY}"
curl_expect_nonempty_lines "${BASE_URL}${API_BASEPATH}/logs/read?src=accerr&tail=5" -H "X-API-Key: ${API_KEY}"

if [[ "${MODE}" == "extended" && "${EXAMPLE_NAME}" == "api-gateway" ]]; then
  run_api_gateway_extended_checks "${BASE_URL}"
  run_api_gateway_policy_fixture_checks "http://nginx" "${BASE_URL}" "http://coraza:9090"
fi

log "OK ${EXAMPLE_NAME} standalone regression passed via ${BASE_URL}"
