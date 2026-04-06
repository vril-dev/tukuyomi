#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: run_binary_deployment_smoke.sh [api-gateway]" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLE_NAME="${1:-api-gateway}"
PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
BINARY_DEPLOYMENT_SKIP_SETUP="${BINARY_DEPLOYMENT_SKIP_SETUP:-0}"
BINARY_DEPLOYMENT_SKIP_BUILD="${BINARY_DEPLOYMENT_SKIP_BUILD:-0}"
BINARY_DEPLOYMENT_APP_PORT="${BINARY_DEPLOYMENT_APP_PORT:-18091}"
BINARY_DEPLOYMENT_AUTO_DOWN="${BINARY_DEPLOYMENT_AUTO_DOWN:-1}"
BINARY_DEPLOYMENT_API_KEY="${BINARY_DEPLOYMENT_API_KEY:-binary-deployment-smoke-primary-key}"
BINARY_DEPLOYMENT_SESSION_SECRET="${BINARY_DEPLOYMENT_SESSION_SECRET:-binary-deployment-smoke-session-secret}"
BINARY_DEPLOYMENT_SESSION_TTL_SEC="${BINARY_DEPLOYMENT_SESSION_TTL_SEC:-28800}"
RUNTIME_BASE_URL="http://127.0.0.1:9090"

RUNTIME_DIR=""
APP_CONTAINER_NAME=""
SERVER_PID=""
AUTH_COOKIE_JAR=""

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[binary-deployment-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[binary-deployment-smoke] $*"
}

fail() {
  echo "[binary-deployment-smoke][ERROR] $*" >&2
  exit 1
}

wait_for_http_code() {
  local expected_code="$1"
  local url="$2"
  local i
  local code=""

  for i in $(seq 1 "${WAIT_TIMEOUT_SECONDS}"); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "${expected_code}" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

curl_expect_200() {
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
  rm -f "${tmp_body}"
}

curl_expect_code() {
  local expected_code="$1"
  local url="$2"
  shift 2
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

curl_expect_body_contains() {
  local expected_code="$1"
  local expected_fragment="$2"
  local url="$3"
  shift 3
  local tmp_body
  local code
  tmp_body="$(mktemp)"
  code="$(curl -sS -o "${tmp_body}" -w "%{http_code}" "$@" "${url}" || true)"
  if [[ "${code}" != "${expected_code}" ]]; then
    cat "${tmp_body}" >&2 || true
    rm -f "${tmp_body}"
    fail "expected ${expected_code} from ${url}, got ${code}"
  fi
  if ! grep -Fq "${expected_fragment}" "${tmp_body}"; then
    cat "${tmp_body}" >&2 || true
    rm -f "${tmp_body}"
    fail "expected response from ${url} to contain: ${expected_fragment}"
  fi
  rm -f "${tmp_body}"
}

read_cookie_value() {
  local cookie_jar="$1"
  local cookie_name="$2"
  awk -v name="${cookie_name}" '$0 !~ /^#/ && $6 == name { print $7 }' "${cookie_jar}" | tail -n 1
}

cleanup() {
  local status="$1"

  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${APP_CONTAINER_NAME}" ]]; then
    docker rm -f "${APP_CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${AUTH_COOKIE_JAR}" ]]; then
    rm -f "${AUTH_COOKIE_JAR}" >/dev/null 2>&1 || true
  fi

  if [[ "${status}" -ne 0 && -n "${RUNTIME_DIR}" ]]; then
    if [[ -f "${RUNTIME_DIR}/logs/coraza/binary-smoke.log" ]]; then
      echo "[binary-deployment-smoke][ERROR] captured server log:" >&2
      sed -n '1,220p' "${RUNTIME_DIR}/logs/coraza/binary-smoke.log" >&2 || true
    fi
  fi

  if [[ "${BINARY_DEPLOYMENT_AUTO_DOWN}" == "1" && -n "${RUNTIME_DIR}" ]]; then
    rm -rf "${RUNTIME_DIR}" >/dev/null 2>&1 || true
  fi
}
trap 'cleanup "$?"' EXIT

need_cmd curl
need_cmd docker
need_cmd make
need_cmd rsync
need_cmd install

if [[ "${EXAMPLE_NAME}" != "api-gateway" ]]; then
  fail "unsupported example for binary deployment smoke: ${EXAMPLE_NAME}"
fi

APP_IMAGE_NAME="tukuyomi-binary-smoke-${EXAMPLE_NAME}"
APP_CONTAINER_NAME="tukuyomi-binary-smoke-${EXAMPLE_NAME}-app"

if [[ "${BINARY_DEPLOYMENT_SKIP_SETUP}" != "1" ]]; then
  if [[ ! -f "${ROOT_DIR}/.env" || ! -d "${ROOT_DIR}/data/rules/crs/rules" ]]; then
    log "running make setup"
    (cd "${ROOT_DIR}" && make setup)
  else
    log "setup already satisfied; skipping make setup"
  fi
fi

if [[ "${BINARY_DEPLOYMENT_SKIP_BUILD}" != "1" ]]; then
  log "building embedded admin UI and binary"
  (cd "${ROOT_DIR}" && make ui-build-sync && make go-build)
else
  log "skipping build by request"
fi

if [[ ! -x "${ROOT_DIR}/bin/tukuyomi" ]]; then
  fail "missing built binary: ${ROOT_DIR}/bin/tukuyomi"
fi

log "building ${EXAMPLE_NAME} app image"
docker build -t "${APP_IMAGE_NAME}" "${ROOT_DIR}/examples/${EXAMPLE_NAME}/api" >/dev/null

log "starting ${EXAMPLE_NAME} app container on 127.0.0.1:${BINARY_DEPLOYMENT_APP_PORT}"
docker rm -f "${APP_CONTAINER_NAME}" >/dev/null 2>&1 || true
docker run -d --rm \
  --name "${APP_CONTAINER_NAME}" \
  -p "127.0.0.1:${BINARY_DEPLOYMENT_APP_PORT}:8080" \
  "${APP_IMAGE_NAME}" >/dev/null

if ! wait_for_http_code "200" "http://127.0.0.1:${BINARY_DEPLOYMENT_APP_PORT}/v1/health"; then
  docker logs "${APP_CONTAINER_NAME}" >&2 || true
  fail "example app did not become healthy in time"
fi

RUNTIME_DIR="$(mktemp -d "${ROOT_DIR}/.tmp-binary-deployment-smoke.XXXXXX")"
log "staging runtime tree at ${RUNTIME_DIR}"
install -d -m 755 \
  "${RUNTIME_DIR}/bin" \
  "${RUNTIME_DIR}/conf" \
  "${RUNTIME_DIR}/rules" \
  "${RUNTIME_DIR}/logs/coraza" \
  "${RUNTIME_DIR}/logs/nginx" \
  "${RUNTIME_DIR}/etc"
install -m 755 "${ROOT_DIR}/bin/tukuyomi" "${RUNTIME_DIR}/bin/tukuyomi"
rsync -a "${ROOT_DIR}/data/conf/" "${RUNTIME_DIR}/conf/"
rsync -a "${ROOT_DIR}/data/rules/" "${RUNTIME_DIR}/rules/"
touch "${RUNTIME_DIR}/conf/crs-disabled.conf"
cp "${ROOT_DIR}/docs/build/tukuyomi.env.example" "${RUNTIME_DIR}/etc/tukuyomi.env"
cat >> "${RUNTIME_DIR}/etc/tukuyomi.env" <<EOF
WAF_APP_URL=http://127.0.0.1:${BINARY_DEPLOYMENT_APP_PORT}
WAF_RULES_FILE=rules/tukuyomi.conf
WAF_BYPASS_FILE=conf/waf.bypass
WAF_COUNTRY_BLOCK_FILE=conf/country-block.conf
WAF_RATE_LIMIT_FILE=conf/rate-limit.conf
WAF_BOT_DEFENSE_FILE=conf/bot-defense.conf
WAF_SEMANTIC_FILE=conf/semantic.conf
WAF_NOTIFICATION_FILE=conf/notifications.conf
WAF_API_KEY_PRIMARY=${BINARY_DEPLOYMENT_API_KEY}
WAF_ADMIN_SESSION_SECRET=${BINARY_DEPLOYMENT_SESSION_SECRET}
WAF_ADMIN_SESSION_TTL_SEC=${BINARY_DEPLOYMENT_SESSION_TTL_SEC}
WAF_CRS_ENABLE=true
WAF_CRS_SETUP_FILE=rules/crs/crs-setup.conf
WAF_CRS_RULES_DIR=rules/crs/rules
WAF_CRS_DISABLED_FILE=conf/crs-disabled.conf
EOF

log "starting staged binary from working directory"
(
  cd "${RUNTIME_DIR}"
  set -a
  source "${RUNTIME_DIR}/etc/tukuyomi.env"
  set +a
  ./bin/tukuyomi >"${RUNTIME_DIR}/logs/coraza/binary-smoke.log" 2>&1
) &
SERVER_PID="$!"

if ! wait_for_http_code "200" "${RUNTIME_BASE_URL}/healthz"; then
  fail "binary did not become healthy in time on :9090"
fi

log "checking admin UI and admin API"
curl_expect_200 "${RUNTIME_BASE_URL}/tukuyomi-admin/"
AUTH_COOKIE_JAR="$(mktemp)"
curl_expect_body_contains "200" "\"authenticated\":false" "${RUNTIME_BASE_URL}/tukuyomi-api/auth/session"
curl_expect_code "401" "${RUNTIME_BASE_URL}/tukuyomi-api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"api_key":"wrong-key"}'
curl_expect_body_contains "200" "\"authenticated\":true" "${RUNTIME_BASE_URL}/tukuyomi-api/auth/login" \
  -c "${AUTH_COOKIE_JAR}" \
  -H "Content-Type: application/json" \
  -d "{\"api_key\":\"${BINARY_DEPLOYMENT_API_KEY}\"}"
CSRF_TOKEN="$(read_cookie_value "${AUTH_COOKIE_JAR}" "tukuyomi_admin_csrf")"
if [[ -z "${CSRF_TOKEN}" ]]; then
  fail "expected CSRF cookie after admin login"
fi
curl_expect_body_contains "200" "\"authenticated\":true" "${RUNTIME_BASE_URL}/tukuyomi-api/auth/session" -b "${AUTH_COOKIE_JAR}"
curl_expect_code "200" "${RUNTIME_BASE_URL}/tukuyomi-api/status" -b "${AUTH_COOKIE_JAR}"
curl_expect_code "401" "${RUNTIME_BASE_URL}/tukuyomi-api/status" \
  -H "Cookie: tukuyomi_admin_session=invalid-session"
curl_expect_code "403" "${RUNTIME_BASE_URL}/tukuyomi-api/auth/logout" \
  -b "${AUTH_COOKIE_JAR}" \
  -H "Content-Type: application/json" \
  -d '{}'
curl_expect_code "403" "${RUNTIME_BASE_URL}/tukuyomi-api/auth/logout" \
  -b "${AUTH_COOKIE_JAR}" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: wrong-token" \
  -d '{}'
curl_expect_body_contains "200" "\"ok\":true" "${RUNTIME_BASE_URL}/tukuyomi-api/auth/logout" \
  -b "${AUTH_COOKIE_JAR}" \
  -c "${AUTH_COOKIE_JAR}" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -d '{}'
curl_expect_body_contains "200" "\"authenticated\":false" "${RUNTIME_BASE_URL}/tukuyomi-api/auth/session" -b "${AUTH_COOKIE_JAR}"

log "running protected-host smoke through staged binary"
(
  cd "${ROOT_DIR}/examples/${EXAMPLE_NAME}"
  PROTECTED_HOST="${PROTECTED_HOST}" \
  BASE_URL="${RUNTIME_BASE_URL}" \
  ./smoke.sh
)

if [[ ! -f "${RUNTIME_DIR}/conf/log-output.json" ]]; then
  fail "expected auto-created ${RUNTIME_DIR}/conf/log-output.json"
fi

log "OK binary deployment smoke passed"
