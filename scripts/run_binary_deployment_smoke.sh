#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BINARY_DEPLOYMENT_SKIP_BUILD="${BINARY_DEPLOYMENT_SKIP_BUILD:-0}"
BINARY_DEPLOYMENT_AUTO_DOWN="${BINARY_DEPLOYMENT_AUTO_DOWN:-1}"
BINARY_DEPLOYMENT_PROXY_PORT="${BINARY_DEPLOYMENT_PROXY_PORT:-19094}"
BINARY_DEPLOYMENT_UPSTREAM_PORT="${BINARY_DEPLOYMENT_UPSTREAM_PORT:-18081}"
BINARY_DEPLOYMENT_API_KEY="${BINARY_DEPLOYMENT_API_KEY:-binary-deployment-smoke-admin-key}"
BINARY_DEPLOYMENT_SESSION_SECRET="${BINARY_DEPLOYMENT_SESSION_SECRET:-binary-deployment-smoke-session-secret}"
BINARY_DEPLOYMENT_WAIT_SECONDS="${BINARY_DEPLOYMENT_WAIT_SECONDS:-60}"
PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"

RUNTIME_DIR=""
RUNTIME_ROOT=""
ENV_FILE=""
SERVER_PID=""
UPSTREAM_PID=""
SERVER_LOG=""
UPSTREAM_LOG=""

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
  local code=""
  local i

  for i in $(seq 1 "${BINARY_DEPLOYMENT_WAIT_SECONDS}"); do
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
      echo "[binary-deployment-smoke][ERROR] captured proxy log:" >&2
      sed -n '1,240p' "${SERVER_LOG}" >&2 || true
    fi
    if [[ -n "${UPSTREAM_LOG}" && -f "${UPSTREAM_LOG}" ]]; then
      echo "[binary-deployment-smoke][ERROR] captured upstream log:" >&2
      sed -n '1,120p' "${UPSTREAM_LOG}" >&2 || true
    fi
  fi

  if [[ "${BINARY_DEPLOYMENT_AUTO_DOWN}" == "1" && -n "${RUNTIME_ROOT}" ]]; then
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

if [[ "${BINARY_DEPLOYMENT_SKIP_BUILD}" != "1" ]]; then
  log "building embedded admin UI and binary"
  (cd "${ROOT_DIR}" && make build)
else
  log "skipping build by request"
fi

if [[ ! -x "${ROOT_DIR}/bin/tukuyomi" ]]; then
  fail "missing built binary: ${ROOT_DIR}/bin/tukuyomi"
fi

RUNTIME_ROOT="$(mktemp -d "${ROOT_DIR}/.tmp-binary-deployment-smoke.XXXXXX")"
RUNTIME_DIR="${RUNTIME_ROOT}/opt/tukuyomi"
ENV_FILE="${RUNTIME_ROOT}/etc/tukuyomi/tukuyomi.env"
SERVER_LOG="${RUNTIME_DIR}/logs/coraza/binary-deployment-smoke.log"
UPSTREAM_LOG="${RUNTIME_ROOT}/proxy-echo.log"

log "staging runtime tree at ${RUNTIME_DIR}"
install -d -m 755 \
  "${RUNTIME_DIR}/bin" \
  "${RUNTIME_DIR}/conf" \
  "${RUNTIME_DIR}/data/geoip" \
  "${RUNTIME_DIR}/data/scheduled-tasks" \
  "${RUNTIME_DIR}/rules" \
  "${RUNTIME_DIR}/scripts" \
  "${RUNTIME_DIR}/logs/coraza" \
  "${RUNTIME_DIR}/logs/proxy" \
  "${RUNTIME_ROOT}/etc/tukuyomi"

install -m 755 "${ROOT_DIR}/bin/tukuyomi" "${RUNTIME_DIR}/bin/tukuyomi"
install -m 755 "${ROOT_DIR}/scripts/update_country_db.sh" "${RUNTIME_DIR}/scripts/update_country_db.sh"
rsync -a --exclude '*.bak' "${ROOT_DIR}/data/conf/" "${RUNTIME_DIR}/conf/"
if [[ -f "${ROOT_DIR}/data/geoip/README.md" ]]; then
  install -m 644 "${ROOT_DIR}/data/geoip/README.md" "${RUNTIME_DIR}/data/geoip/README.md"
fi
if [[ -f "${ROOT_DIR}/data/scheduled-tasks/README.md" ]]; then
  install -m 644 "${ROOT_DIR}/data/scheduled-tasks/README.md" "${RUNTIME_DIR}/data/scheduled-tasks/README.md"
fi
install -m 644 "${ROOT_DIR}/data/rules/tukuyomi.conf" "${RUNTIME_DIR}/rules/tukuyomi.conf"

if [[ -d "${ROOT_DIR}/data/rules/crs/rules" ]]; then
  rsync -a "${ROOT_DIR}/data/rules/crs/" "${RUNTIME_DIR}/rules/crs/"
else
  log "data/rules/crs missing; installing CRS into staged runtime"
  DEST_DIR="${RUNTIME_DIR}/rules/crs" "${ROOT_DIR}/scripts/install_crs.sh"
fi

touch "${RUNTIME_DIR}/conf/crs-disabled.conf"

cp "${ROOT_DIR}/docs/build/tukuyomi.env.example" "${ENV_FILE}"
sed -i "s#/opt/tukuyomi#${RUNTIME_DIR}#g" "${ENV_FILE}"

jq \
  --arg listen_addr ":${BINARY_DEPLOYMENT_PROXY_PORT}" \
  --arg api_key "${BINARY_DEPLOYMENT_API_KEY}" \
  --arg session_secret "${BINARY_DEPLOYMENT_SESSION_SECRET}" \
  '.server.listen_addr = $listen_addr
   | .admin.api_key_primary = $api_key
   | .admin.session_secret = $session_secret
   | .admin.api_auth_disable = false' \
  "${RUNTIME_DIR}/conf/config.json" > "${RUNTIME_DIR}/conf/config.json.tmp"
mv "${RUNTIME_DIR}/conf/config.json.tmp" "${RUNTIME_DIR}/conf/config.json"

log "starting local proxy echo upstream on 127.0.0.1:${BINARY_DEPLOYMENT_UPSTREAM_PORT}"
python3 "${ROOT_DIR}/scripts/proxy_echo_server.py" "${BINARY_DEPLOYMENT_UPSTREAM_PORT}" >"${UPSTREAM_LOG}" 2>&1 &
UPSTREAM_PID="$!"
if ! wait_for_http_code "200" "http://127.0.0.1:${BINARY_DEPLOYMENT_UPSTREAM_PORT}/healthz"; then
  fail "proxy echo upstream did not become healthy in time"
fi

log "starting staged binary from systemd-style working directory"
(
  cd "${RUNTIME_DIR}"
  set -a
  source "${ENV_FILE}"
  set +a
  ./bin/tukuyomi >"${SERVER_LOG}" 2>&1
) &
SERVER_PID="$!"

if ! wait_for_http_code "200" "http://127.0.0.1:${BINARY_DEPLOYMENT_PROXY_PORT}/healthz"; then
  fail "binary did not become healthy in time on :${BINARY_DEPLOYMENT_PROXY_PORT}"
fi

log "running admin + proxy-rules smoke through staged binary"
(
  cd "${ROOT_DIR}"
  HOST_CORAZA_PORT="${BINARY_DEPLOYMENT_PROXY_PORT}" \
  WAF_LISTEN_PORT="${BINARY_DEPLOYMENT_PROXY_PORT}" \
  WAF_API_KEY_PRIMARY="${BINARY_DEPLOYMENT_API_KEY}" \
  PROTECTED_HOST="${PROTECTED_HOST}" \
  PROXY_ECHO_PORT="${BINARY_DEPLOYMENT_UPSTREAM_PORT}" \
  PROXY_ECHO_URL="http://127.0.0.1:${BINARY_DEPLOYMENT_UPSTREAM_PORT}" \
  PROXY_ENV_FILE="${ENV_FILE}" \
  ./scripts/ci_proxy_admin_smoke.sh
)

if [[ ! -f "${RUNTIME_DIR}/logs/coraza/proxy-rules-audit.ndjson" ]]; then
  fail "expected staged runtime to create logs/coraza/proxy-rules-audit.ndjson"
fi

log "OK binary deployment smoke passed"
