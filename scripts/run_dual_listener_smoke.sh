#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DUAL_LISTENER_SMOKE_SKIP_BUILD="${DUAL_LISTENER_SMOKE_SKIP_BUILD:-0}"
DUAL_LISTENER_SMOKE_AUTO_DOWN="${DUAL_LISTENER_SMOKE_AUTO_DOWN:-1}"
DUAL_LISTENER_SMOKE_PUBLIC_PORT="${DUAL_LISTENER_SMOKE_PUBLIC_PORT:-19096}"
DUAL_LISTENER_SMOKE_ADMIN_PORT="${DUAL_LISTENER_SMOKE_ADMIN_PORT:-19097}"
DUAL_LISTENER_SMOKE_UPSTREAM_PORT="${DUAL_LISTENER_SMOKE_UPSTREAM_PORT:-18082}"
DUAL_LISTENER_SMOKE_ADMIN_USERNAME="${DUAL_LISTENER_SMOKE_ADMIN_USERNAME:-admin}"
DUAL_LISTENER_SMOKE_ADMIN_PASSWORD="${DUAL_LISTENER_SMOKE_ADMIN_PASSWORD:-dual-listener-smoke-admin-password}"
DUAL_LISTENER_SMOKE_SESSION_SECRET="${DUAL_LISTENER_SMOKE_SESSION_SECRET:-dual-listener-smoke-session-secret}"
DUAL_LISTENER_SMOKE_WAIT_SECONDS="${DUAL_LISTENER_SMOKE_WAIT_SECONDS:-60}"
PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"

RUNTIME_DIR=""
RUNTIME_ROOT=""
ENV_FILE=""
SERVER_PID=""
UPSTREAM_PID=""
SERVER_LOG=""
UPSTREAM_LOG=""
WAF_STAGE_ROOT=""

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[dual-listener-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[dual-listener-smoke] $*"
}

fail() {
  echo "[dual-listener-smoke][ERROR] $*" >&2
  exit 1
}

wait_for_http_code() {
  local expected_code="$1"
  local url="$2"
  local code=""
  local i

  for i in $(seq 1 "${DUAL_LISTENER_SMOKE_WAIT_SECONDS}"); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "${expected_code}" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

cleanup() {
  local status="$1"

  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${UPSTREAM_PID}" ]] && kill -0 "${UPSTREAM_PID}" >/dev/null 2>&1; then
    kill "${UPSTREAM_PID}" >/dev/null 2>&1 || true
    wait "${UPSTREAM_PID}" >/dev/null 2>&1 || true
  fi

  if [[ "${status}" -ne 0 ]]; then
    if [[ -n "${SERVER_LOG}" && -f "${SERVER_LOG}" ]]; then
      echo "[dual-listener-smoke][ERROR] captured proxy log:" >&2
      sed -n '1,240p' "${SERVER_LOG}" >&2 || true
    fi
    if [[ -n "${UPSTREAM_LOG}" && -f "${UPSTREAM_LOG}" ]]; then
      echo "[dual-listener-smoke][ERROR] captured upstream log:" >&2
      sed -n '1,120p' "${UPSTREAM_LOG}" >&2 || true
    fi
  fi

  if [[ "${DUAL_LISTENER_SMOKE_AUTO_DOWN}" == "1" && -n "${RUNTIME_ROOT}" ]]; then
    rm -rf "${RUNTIME_ROOT}" >/dev/null 2>&1 || true
  fi
}
trap 'cleanup "$?"' EXIT

need_cmd curl
need_cmd jq
need_cmd make
need_cmd python3
need_cmd rsync
need_cmd install

if [[ "${DUAL_LISTENER_SMOKE_SKIP_BUILD}" != "1" ]]; then
  log "building embedded admin UI and binary"
  (cd "${ROOT_DIR}" && make build)
else
  log "skipping build by request"
fi

if [[ ! -x "${ROOT_DIR}/bin/tukuyomi" ]]; then
  fail "missing built binary: ${ROOT_DIR}/bin/tukuyomi"
fi

RUNTIME_ROOT="$(mktemp -d "${ROOT_DIR}/.tmp-dual-listener-smoke.XXXXXX")"
RUNTIME_DIR="${RUNTIME_ROOT}/opt/tukuyomi"
ENV_FILE="${RUNTIME_ROOT}/etc/tukuyomi/tukuyomi.env"
SERVER_LOG="${RUNTIME_DIR}/data/tmp/dual-listener-smoke.log"
UPSTREAM_LOG="${RUNTIME_ROOT}/proxy-echo.log"

log "staging dual-listener runtime tree at ${RUNTIME_DIR}"
  install -d -m 755 \
    "${RUNTIME_DIR}/bin" \
    "${RUNTIME_DIR}/conf" \
    "${RUNTIME_DIR}/db" \
    "${RUNTIME_DIR}/data/tmp" \
    "${RUNTIME_DIR}/data/scheduled-tasks" \
    "${RUNTIME_DIR}/audit" \
    "${RUNTIME_DIR}/cache/response" \
    "${RUNTIME_ROOT}/etc/tukuyomi"

install -m 755 "${ROOT_DIR}/bin/tukuyomi" "${RUNTIME_DIR}/bin/tukuyomi"
rsync -a --exclude '*.bak' "${ROOT_DIR}/data/conf/" "${RUNTIME_DIR}/conf/"
if [[ -d "${ROOT_DIR}/data/scheduled-tasks" ]]; then
  rsync -a "${ROOT_DIR}/data/scheduled-tasks/" "${RUNTIME_DIR}/data/scheduled-tasks/"
fi
touch "${RUNTIME_DIR}/conf/crs-disabled.conf"

cp "${ROOT_DIR}/docs/build/tukuyomi.env.example" "${ENV_FILE}"
sed -i "s#/opt/tukuyomi#${RUNTIME_DIR}#g" "${ENV_FILE}"

jq \
  --arg public_addr ":${DUAL_LISTENER_SMOKE_PUBLIC_PORT}" \
  --arg admin_addr ":${DUAL_LISTENER_SMOKE_ADMIN_PORT}" \
  --arg session_secret "${DUAL_LISTENER_SMOKE_SESSION_SECRET}" \
  '.server.listen_addr = $public_addr
   | .admin.listen_addr = $admin_addr
   | .admin.session_secret = $session_secret
   | .admin.api_auth_disable = false' \
  "${RUNTIME_DIR}/conf/config.json" > "${RUNTIME_DIR}/conf/config.json.tmp"
mv "${RUNTIME_DIR}/conf/config.json.tmp" "${RUNTIME_DIR}/conf/config.json"

mkdir -p "${RUNTIME_DIR}/tmp"
WAF_STAGE_ROOT="$(mktemp -d "${RUNTIME_DIR}/tmp/waf-import.XXXXXX")"
(
  cd "${RUNTIME_DIR}"
  "${ROOT_DIR}/scripts/stage_waf_rule_assets.sh" "${WAF_STAGE_ROOT}"
  WAF_CONFIG_FILE="conf/config.json" ./bin/tukuyomi db-migrate
  WAF_RULE_ASSET_FS_ROOT="${WAF_STAGE_ROOT}" WAF_CONFIG_FILE="conf/config.json" ./bin/tukuyomi db-import-waf-rule-assets
)
rm -rf "${WAF_STAGE_ROOT}"
WAF_STAGE_ROOT=""

log "starting local proxy echo upstream on 127.0.0.1:${DUAL_LISTENER_SMOKE_UPSTREAM_PORT}"
python3 "${ROOT_DIR}/scripts/proxy_echo_server.py" "${DUAL_LISTENER_SMOKE_UPSTREAM_PORT}" >"${UPSTREAM_LOG}" 2>&1 &
UPSTREAM_PID="$!"
if ! wait_for_http_code "200" "http://127.0.0.1:${DUAL_LISTENER_SMOKE_UPSTREAM_PORT}/healthz"; then
  fail "proxy echo upstream did not become healthy in time"
fi

log "starting staged binary with split public/admin listeners"
(
  cd "${RUNTIME_DIR}"
  set -a
  source "${ENV_FILE}"
  set +a
  TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME="${DUAL_LISTENER_SMOKE_ADMIN_USERNAME}" \
  TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD="${DUAL_LISTENER_SMOKE_ADMIN_PASSWORD}" \
  ./bin/tukuyomi >"${SERVER_LOG}" 2>&1
) &
SERVER_PID="$!"

if ! wait_for_http_code "200" "http://127.0.0.1:${DUAL_LISTENER_SMOKE_PUBLIC_PORT}/healthz"; then
  fail "public listener did not become healthy in time"
fi
if ! wait_for_http_code "200" "http://127.0.0.1:${DUAL_LISTENER_SMOKE_ADMIN_PORT}/healthz"; then
  fail "admin listener did not become healthy in time"
fi

if [[ "$(curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:${DUAL_LISTENER_SMOKE_PUBLIC_PORT}/tukuyomi-api/auth/session" || true)" != "404" ]]; then
  fail "public listener should return 404 for admin auth path in split mode"
fi
if [[ "$(curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:${DUAL_LISTENER_SMOKE_PUBLIC_PORT}/tukuyomi-ui" || true)" != "404" ]]; then
  fail "public listener should return 404 for admin UI path in split mode"
fi
if [[ "$(curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:${DUAL_LISTENER_SMOKE_ADMIN_PORT}/not-a-proxy-route" || true)" != "404" ]]; then
  fail "admin listener should return 404 for arbitrary proxy traffic in split mode"
fi

log "running admin + proxy-rules smoke through split listeners"
(
  cd "${ROOT_DIR}"
  PROXY_BASE_URL="http://127.0.0.1:${DUAL_LISTENER_SMOKE_PUBLIC_PORT}" \
  PROXY_ADMIN_BASE_URL="http://127.0.0.1:${DUAL_LISTENER_SMOKE_ADMIN_PORT}" \
  HOST_CORAZA_PORT="${DUAL_LISTENER_SMOKE_PUBLIC_PORT}" \
  WAF_LISTEN_PORT="${DUAL_LISTENER_SMOKE_PUBLIC_PORT}" \
  WAF_ADMIN_USERNAME="${DUAL_LISTENER_SMOKE_ADMIN_USERNAME}" \
  WAF_ADMIN_PASSWORD="${DUAL_LISTENER_SMOKE_ADMIN_PASSWORD}" \
  PROTECTED_HOST="${PROTECTED_HOST}" \
  PROXY_ECHO_PORT="${DUAL_LISTENER_SMOKE_UPSTREAM_PORT}" \
  PROXY_ECHO_URL="http://127.0.0.1:${DUAL_LISTENER_SMOKE_UPSTREAM_PORT}" \
  PROXY_ENV_FILE="${ENV_FILE}" \
  ./scripts/ci_proxy_admin_smoke.sh
)

if [[ ! -f "${RUNTIME_DIR}/audit/proxy-rules-audit.ndjson" ]]; then
  fail "expected staged runtime to create audit/proxy-rules-audit.ndjson"
fi

log "OK dual-listener smoke passed"
