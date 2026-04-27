#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

HTTP3_SMOKE_SKIP_BUILD="${HTTP3_SMOKE_SKIP_BUILD:-0}"
HTTP3_SMOKE_PROXY_PORT="${HTTP3_SMOKE_PROXY_PORT:-19096}"
HTTP3_SMOKE_UPSTREAM_PORT="${HTTP3_SMOKE_UPSTREAM_PORT:-18082}"
HTTP3_SMOKE_ADMIN_USERNAME="${HTTP3_SMOKE_ADMIN_USERNAME:-admin}"
HTTP3_SMOKE_ADMIN_PASSWORD="${HTTP3_SMOKE_ADMIN_PASSWORD:-http3-public-entry-smoke-admin-password}"
HTTP3_SMOKE_SESSION_SECRET="${HTTP3_SMOKE_SESSION_SECRET:-http3-public-entry-smoke-session-secret}"
HTTP3_SMOKE_WAIT_SECONDS="${HTTP3_SMOKE_WAIT_SECONDS:-60}"
PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"

RUNTIME_ROOT=""
RUNTIME_DIR=""
ENV_FILE=""
SERVER_PID=""
UPSTREAM_PID=""
SERVER_LOG=""
UPSTREAM_LOG=""
CERT_FILE=""
KEY_FILE=""
HTTPS_HEADERS=""
HTTPS_BODY=""
STATUS_BODY=""
ADMIN_COOKIE_JAR=""
WAF_STAGE_ROOT=""

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[http3-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[http3-smoke] $*"
}

fail() {
  echo "[http3-smoke][ERROR] $*" >&2
  exit 1
}

wait_for_http_code() {
  local expected_code="$1"
  local url="$2"
  local extra_args="${3:-}"
  local code=""
  local i

  for i in $(seq 1 "${HTTP3_SMOKE_WAIT_SECONDS}"); do
    # shellcheck disable=SC2086
    code="$(curl -sS ${extra_args} -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || true)"
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
      echo "[http3-smoke][ERROR] captured proxy log:" >&2
      sed -n '1,260p' "${SERVER_LOG}" >&2 || true
    fi
    if [[ -n "${UPSTREAM_LOG}" && -f "${UPSTREAM_LOG}" ]]; then
      echo "[http3-smoke][ERROR] captured upstream log:" >&2
      sed -n '1,120p' "${UPSTREAM_LOG}" >&2 || true
    fi
  fi

  if [[ -n "${RUNTIME_ROOT}" ]]; then
    rm -rf "${RUNTIME_ROOT}" >/dev/null 2>&1 || true
  fi
  [[ -n "${ADMIN_COOKIE_JAR}" ]] && rm -f "${ADMIN_COOKIE_JAR}" >/dev/null 2>&1 || true
}
trap 'cleanup "$?"' EXIT

need_cmd curl
need_cmd go
need_cmd jq
need_cmd make
need_cmd python3
need_cmd rsync
need_cmd install

if [[ "${HTTP3_SMOKE_SKIP_BUILD}" != "1" ]]; then
  log "building embedded admin UI and binary"
  (cd "${ROOT_DIR}" && make build)
else
  log "skipping build by request"
fi

if [[ ! -x "${ROOT_DIR}/bin/tukuyomi" ]]; then
  fail "missing built binary: ${ROOT_DIR}/bin/tukuyomi"
fi

RUNTIME_ROOT="$(mktemp -d "${ROOT_DIR}/.tmp-http3-public-entry-smoke.XXXXXX")"
RUNTIME_DIR="${RUNTIME_ROOT}/opt/tukuyomi"
ENV_FILE="${RUNTIME_ROOT}/etc/tukuyomi/tukuyomi.env"
SERVER_LOG="${RUNTIME_DIR}/data/tmp/http3-public-entry-smoke.log"
UPSTREAM_LOG="${RUNTIME_ROOT}/proxy-echo.log"
CERT_FILE="${RUNTIME_DIR}/conf/http3-smoke-cert.pem"
KEY_FILE="${RUNTIME_DIR}/conf/http3-smoke-key.pem"
HTTPS_HEADERS="${RUNTIME_ROOT}/https-headers.txt"
HTTPS_BODY="${RUNTIME_ROOT}/https-body.json"
STATUS_BODY="${RUNTIME_ROOT}/status.json"
ADMIN_COOKIE_JAR="${RUNTIME_ROOT}/admin-cookie.txt"

log "staging runtime tree at ${RUNTIME_DIR}"
  install -d -m 755 \
    "${RUNTIME_DIR}/bin" \
    "${RUNTIME_DIR}/conf" \
    "${RUNTIME_DIR}/db" \
    "${RUNTIME_DIR}/audit" \
    "${RUNTIME_DIR}/cache/response" \
    "${RUNTIME_DIR}/data/tmp" \
    "${RUNTIME_ROOT}/etc/tukuyomi"

install -m 755 "${ROOT_DIR}/bin/tukuyomi" "${RUNTIME_DIR}/bin/tukuyomi"
rsync -a --exclude '*.bak' "${ROOT_DIR}/data/conf/" "${RUNTIME_DIR}/conf/"
touch "${RUNTIME_DIR}/conf/crs-disabled.conf"

cp "${ROOT_DIR}/docs/build/tukuyomi.env.example" "${ENV_FILE}"
sed -i "s#/opt/tukuyomi#${RUNTIME_DIR}#g" "${ENV_FILE}"

log "generating temporary self-signed certificate"
(
  cd "${ROOT_DIR}/server"
  go run ./cmd/http3smoke gen-cert \
    --cert-file "${CERT_FILE}" \
    --key-file "${KEY_FILE}" \
    --host "127.0.0.1" \
    --host "localhost"
)

jq \
  --arg listen_addr ":${HTTP3_SMOKE_PROXY_PORT}" \
  --arg session_secret "${HTTP3_SMOKE_SESSION_SECRET}" \
  --arg cert_file "./conf/http3-smoke-cert.pem" \
  --arg key_file "./conf/http3-smoke-key.pem" \
  '.server.listen_addr = $listen_addr
   | .server.tls.enabled = true
   | .server.tls.cert_file = $cert_file
   | .server.tls.key_file = $key_file
   | .server.tls.redirect_http = false
   | .server.http3.enabled = true
   | .server.http3.alt_svc_max_age_sec = 86400
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

jq -n \
  --arg protected_host "${PROTECTED_HOST}" \
  --arg upstream "http://127.0.0.1:${HTTP3_SMOKE_UPSTREAM_PORT}" \
  '{
    upstreams: [
      {
        name: "http3-smoke",
        url: $upstream,
        weight: 1,
        enabled: true
      }
    ],
    routes: [
      {
        name: "http3-smoke",
        enabled: true,
        priority: 10,
        match: {
          hosts: [$protected_host],
          path: { type: "prefix", value: "/http3/" }
        },
        action: {
          upstream: "http3-smoke",
          host_rewrite: $protected_host,
          request_headers: {
            set: { "X-Service": "http3-smoke" },
            add: { "X-Route": "http3-smoke" }
          }
        }
      }
    ],
    default_route: {
      name: "default",
      enabled: true,
      action: { upstream: $upstream }
    },
    force_http2: true,
    disable_compression: false
  }' > "${RUNTIME_DIR}/conf/proxy.json"

log "starting local proxy echo upstream on 127.0.0.1:${HTTP3_SMOKE_UPSTREAM_PORT}"
python3 "${ROOT_DIR}/scripts/proxy_echo_server.py" "${HTTP3_SMOKE_UPSTREAM_PORT}" >"${UPSTREAM_LOG}" 2>&1 &
UPSTREAM_PID="$!"
if ! wait_for_http_code "200" "http://127.0.0.1:${HTTP3_SMOKE_UPSTREAM_PORT}/healthz"; then
  fail "proxy echo upstream did not become healthy in time"
fi

log "starting binary with built-in TLS + HTTP/3"
(
  cd "${RUNTIME_DIR}"
  set -a
  source "${ENV_FILE}"
  set +a
  TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME="${HTTP3_SMOKE_ADMIN_USERNAME}" \
  TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD="${HTTP3_SMOKE_ADMIN_PASSWORD}" \
  ./bin/tukuyomi >"${SERVER_LOG}" 2>&1
) &
SERVER_PID="$!"

if ! wait_for_http_code "200" "https://127.0.0.1:${HTTP3_SMOKE_PROXY_PORT}/healthz" "-k"; then
  fail "https listener did not become healthy in time on :${HTTP3_SMOKE_PROXY_PORT}"
fi

log "checking HTTPS Alt-Svc advertisement on routed request"
https_code="$(curl -ksS -D "${HTTPS_HEADERS}" -o "${HTTPS_BODY}" -w "%{http_code}" \
  -H "Host: ${PROTECTED_HOST}" \
  "https://127.0.0.1:${HTTP3_SMOKE_PROXY_PORT}/http3/users?lang=ja")"
if [[ "${https_code}" != "200" ]]; then
  fail "https routed request failed: ${https_code}"
fi
if ! grep -iq '^Alt-Svc: .*h3=' "${HTTPS_HEADERS}"; then
  fail "https response did not advertise Alt-Svc"
fi
if ! jq -e \
  --arg host "${PROTECTED_HOST}" \
  '.path == "/http3/users?lang=ja"
   and .host == $host
   and .x_service == "http3-smoke"
   and .x_route == "http3-smoke"' \
  "${HTTPS_BODY}" >/dev/null; then
  echo "[http3-smoke][ERROR] unexpected HTTPS routed body" >&2
  cat "${HTTPS_BODY}" >&2 || true
  exit 1
fi

log "checking admin status reports advertised HTTP/3 runtime"
login_payload="$(jq -n --arg username "${HTTP3_SMOKE_ADMIN_USERNAME}" --arg password "${HTTP3_SMOKE_ADMIN_PASSWORD}" '{username: $username, password: $password}')"
login_code="$(curl -ksS -o "${RUNTIME_ROOT}/admin-login.json" -w "%{http_code}" \
  -c "${ADMIN_COOKIE_JAR}" -b "${ADMIN_COOKIE_JAR}" \
  -H "Content-Type: application/json" \
  -X POST --data "${login_payload}" \
  "https://127.0.0.1:${HTTP3_SMOKE_PROXY_PORT}/tukuyomi-api/auth/login")"
if [[ "${login_code}" != "200" ]]; then
  fail "admin login failed: ${login_code}"
fi
status_code="$(curl -ksS -o "${STATUS_BODY}" -w "%{http_code}" \
  -b "${ADMIN_COOKIE_JAR}" -c "${ADMIN_COOKIE_JAR}" \
  "https://127.0.0.1:${HTTP3_SMOKE_PROXY_PORT}/tukuyomi-api/status")"
if [[ "${status_code}" != "200" ]]; then
  fail "status request failed: ${status_code}"
fi
if ! jq -e '.server_http3_enabled == true and .server_http3_advertised == true and (.server_http3_alt_svc // "" | contains("h3="))' "${STATUS_BODY}" >/dev/null; then
  echo "[http3-smoke][ERROR] unexpected HTTP/3 status payload" >&2
  cat "${STATUS_BODY}" >&2 || true
  exit 1
fi

log "checking actual HTTP/3 request over UDP"
(
  cd "${ROOT_DIR}/server"
  go run ./cmd/http3smoke check \
    --url "https://127.0.0.1:${HTTP3_SMOKE_PROXY_PORT}/http3/users?lang=ja" \
    --host "${PROTECTED_HOST}" \
    --insecure \
    --expect-status 200 \
    --expect-substring '"path": "/http3/users?lang=ja"' \
    --expect-substring "\"host\": \"${PROTECTED_HOST}\"" \
    --expect-substring '"x_service": "http3-smoke"' \
    --expect-substring '"x_route": "http3-smoke"'
)

log "OK HTTP/3 public-entry smoke passed"
