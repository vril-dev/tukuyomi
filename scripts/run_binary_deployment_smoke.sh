#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BINARY_DEPLOYMENT_SKIP_BUILD="${BINARY_DEPLOYMENT_SKIP_BUILD:-0}"
BINARY_DEPLOYMENT_AUTO_DOWN="${BINARY_DEPLOYMENT_AUTO_DOWN:-1}"
BINARY_DEPLOYMENT_PROXY_PORT="${BINARY_DEPLOYMENT_PROXY_PORT:-19094}"
BINARY_DEPLOYMENT_UPSTREAM_PORT="${BINARY_DEPLOYMENT_UPSTREAM_PORT:-18081}"
BINARY_DEPLOYMENT_ADMIN_USERNAME="${BINARY_DEPLOYMENT_ADMIN_USERNAME:-admin}"
BINARY_DEPLOYMENT_ADMIN_PASSWORD="${BINARY_DEPLOYMENT_ADMIN_PASSWORD:-binary-deployment-smoke-admin-password}"
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

stage_runtime_db_if_needed() {
  local db_path="${RUNTIME_DIR}/db/tukuyomi.db"
  local needs_seed="1"
  local stage_root=""

  if [[ -f "${db_path}" ]]; then
    needs_seed="$(python3 - "${db_path}" <<'PY'
import sqlite3
import sys

path = sys.argv[1]
try:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("select count(*) from php_runtime_inventory")
    count = cur.fetchone()[0]
    print("0" if count > 0 else "1")
except Exception:
    print("1")
finally:
    try:
        conn.close()
    except Exception:
        pass
PY
)"
  fi

  if [[ "${needs_seed}" != "1" ]]; then
    return 0
  fi

  log "seeding staged runtime DB with preview bootstrap defaults"
  mkdir -p "${RUNTIME_DIR}/tmp"
  stage_root="$(mktemp -d "${RUNTIME_DIR}/tmp/waf-import.XXXXXX")"
  (
    cd "${RUNTIME_DIR}"
    set -a
    source "${ENV_FILE}"
    set +a
    "${ROOT_DIR}/scripts/stage_waf_rule_assets.sh" "${stage_root}"
    ./bin/tukuyomi db-migrate
    WAF_RULE_ASSET_FS_ROOT="${stage_root}" ./bin/tukuyomi db-import-waf-rule-assets
    UI_PREVIEW_PUBLIC_ADDR=":${BINARY_DEPLOYMENT_PROXY_PORT}" \
    UI_PREVIEW_ADMIN_ADDR="" \
    ./bin/tukuyomi db-import-preview
  )
  rm -rf "${stage_root}"
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
SERVER_LOG="${RUNTIME_DIR}/data/tmp/binary-deployment-smoke.log"
UPSTREAM_LOG="${RUNTIME_ROOT}/proxy-echo.log"

log "staging runtime tree at ${RUNTIME_DIR}"
  install -d -m 755 \
    "${RUNTIME_DIR}/bin" \
    "${RUNTIME_DIR}/conf" \
    "${RUNTIME_DIR}/db" \
    "${RUNTIME_DIR}/audit" \
    "${RUNTIME_DIR}/cache/response" \
    "${RUNTIME_DIR}/data/tmp" \
    "${RUNTIME_DIR}/data/scheduled-tasks" \
    "${RUNTIME_DIR}/scripts" \
    "${RUNTIME_ROOT}/etc/tukuyomi"

install -m 755 "${ROOT_DIR}/bin/tukuyomi" "${RUNTIME_DIR}/bin/tukuyomi"
install -m 755 "${ROOT_DIR}/scripts/update_country_db.sh" "${RUNTIME_DIR}/scripts/update_country_db.sh"
rsync -a --exclude '*.bak' "${ROOT_DIR}/data/conf/" "${RUNTIME_DIR}/conf/"
if [[ -f "${ROOT_DIR}/data/scheduled-tasks/README.md" ]]; then
  install -m 644 "${ROOT_DIR}/data/scheduled-tasks/README.md" "${RUNTIME_DIR}/data/scheduled-tasks/README.md"
fi
touch "${RUNTIME_DIR}/conf/crs-disabled.conf"

cp "${ROOT_DIR}/docs/build/tukuyomi.env.example" "${ENV_FILE}"
sed -i "s#/opt/tukuyomi#${RUNTIME_DIR}#g" "${ENV_FILE}"

jq \
  --arg listen_addr ":${BINARY_DEPLOYMENT_PROXY_PORT}" \
  --arg session_secret "${BINARY_DEPLOYMENT_SESSION_SECRET}" \
  '.server.listen_addr = $listen_addr
   | .admin.session_secret = $session_secret
   | .admin.api_auth_disable = false' \
  "${RUNTIME_DIR}/conf/config.json" > "${RUNTIME_DIR}/conf/config.json.tmp"
mv "${RUNTIME_DIR}/conf/config.json.tmp" "${RUNTIME_DIR}/conf/config.json"

stage_runtime_db_if_needed

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
  TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME="${BINARY_DEPLOYMENT_ADMIN_USERNAME}" \
  TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD="${BINARY_DEPLOYMENT_ADMIN_PASSWORD}" \
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
  WAF_ADMIN_USERNAME="${BINARY_DEPLOYMENT_ADMIN_USERNAME}" \
  WAF_ADMIN_PASSWORD="${BINARY_DEPLOYMENT_ADMIN_PASSWORD}" \
  PROTECTED_HOST="${PROTECTED_HOST}" \
  PROXY_ECHO_PORT="${BINARY_DEPLOYMENT_UPSTREAM_PORT}" \
  PROXY_ECHO_URL="http://127.0.0.1:${BINARY_DEPLOYMENT_UPSTREAM_PORT}" \
  PROXY_ENV_FILE="${ENV_FILE}" \
  ./scripts/ci_proxy_admin_smoke.sh
)

if [[ ! -f "${RUNTIME_DIR}/audit/proxy-rules-audit.ndjson" ]]; then
  fail "expected staged runtime to create audit/proxy-rules-audit.ndjson"
fi

log "OK binary deployment smoke passed"
