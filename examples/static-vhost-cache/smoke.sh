#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:${CORAZA_PORT:-19094}}"
PROTECTED_HOST="${PROTECTED_HOST:-static-vhost-cache.example.test}"
ADMIN_USERNAME="${ADMIN_USERNAME:-${TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME:-admin}}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-${TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD:-static-vhost-cache-example-admin-password}}"
CACHE_PATH="${CACHE_PATH:-/test.html}"
CACHE_STORE_DIR="${CACHE_STORE_DIR:-cache/response}"
CACHE_MAX_BYTES="${CACHE_MAX_BYTES:-1048576}"

tmp_dir="$(mktemp -d)"
admin_cookie_jar="${tmp_dir}/admin-cookie.txt"
admin_csrf_token=""

cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[static-vhost-cache-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd python3

admin_login() {
  local login_body="${tmp_dir}/admin-login.json"
  local login_resp="${tmp_dir}/admin-login-response.json"
  local code

  python3 - "${ADMIN_USERNAME}" "${ADMIN_PASSWORD}" >"${login_body}" <<'PY'
import json
import sys

print(json.dumps({"username": sys.argv[1], "password": sys.argv[2]}))
PY
  code="$(curl -sS -o "${login_resp}" -w "%{http_code}" \
    -c "${admin_cookie_jar}" -b "${admin_cookie_jar}" \
    -H "Content-Type: application/json" \
    -X POST --data-binary "@${login_body}" \
    "${BASE_URL}/tukuyomi-api/auth/login")"
  if [[ "${code}" != "200" ]]; then
    echo "[static-vhost-cache-smoke][ERROR] admin login failed: ${code}" >&2
    cat "${login_resp}" >&2 || true
    exit 1
  fi
  admin_csrf_token="$(
    awk 'NF >= 7 && $6 == "tukuyomi_admin_csrf" { token = $7 } END { if (token != "") print token }' "${admin_cookie_jar}"
  )"
  if [[ -z "${admin_csrf_token}" ]]; then
    echo "[static-vhost-cache-smoke][ERROR] admin login did not issue csrf cookie" >&2
    exit 1
  fi
}

api_request() {
  local method="$1"
  local path="$2"
  shift 2
  curl -fsS -X "${method}" \
    -b "${admin_cookie_jar}" -c "${admin_cookie_jar}" \
    -H "X-CSRF-Token: ${admin_csrf_token}" \
    "$@" \
    "${BASE_URL}${path}"
}

cache_store_stats() {
  local output="$1"
  if ! api_request GET "/tukuyomi-api/cache-store" -o "${output}"; then
    echo "[static-vhost-cache-smoke][ERROR] failed to read cache-store" >&2
    exit 1
  fi
}

enable_and_clear_cache_store() {
  local store_json etag put_body
  store_json="${tmp_dir}/cache-store.json"
  cache_store_stats "${store_json}"

  etag="$(python3 - "${store_json}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(payload.get("etag", ""))
PY
)"

  put_body="${tmp_dir}/cache-store-put.json"
  python3 - "${CACHE_STORE_DIR}" "${CACHE_MAX_BYTES}" >"${put_body}" <<'PY'
import json
import sys

store_dir = sys.argv[1]
max_bytes = int(sys.argv[2])
print(json.dumps({
    "enabled": True,
    "store_dir": store_dir,
    "max_bytes": max_bytes,
    "memory_enabled": False,
    "memory_max_bytes": 0,
    "memory_max_entries": 0,
}))
PY

  if ! api_request PUT "/tukuyomi-api/cache-store" \
    -H "Content-Type: application/json" \
    -H "If-Match: ${etag}" \
    --data-binary "@${put_body}" >/dev/null; then
    echo "[static-vhost-cache-smoke][ERROR] failed to enable cache-store" >&2
    exit 1
  fi
  if ! api_request POST "/tukuyomi-api/cache-store/clear" >/dev/null; then
    echo "[static-vhost-cache-smoke][ERROR] failed to clear cache-store" >&2
    exit 1
  fi
}

wait_for_ready() {
  local status
  for _ in $(seq 1 60); do
    status="$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: ${PROTECTED_HOST}" "${BASE_URL}/healthz" || true)"
    if [[ "${status}" == "200" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "[static-vhost-cache-smoke][ERROR] runtime did not become ready at ${BASE_URL}" >&2
  exit 1
}

fetch_cache_probe() {
  local prefix="$1"
  local headers="${tmp_dir}/${prefix}.headers"
  local body="${tmp_dir}/${prefix}.body"
  local status

  status="$(curl -sS -o "${body}" -D "${headers}" -w "%{http_code}" \
    -H "Host: ${PROTECTED_HOST}" \
    -H "Cache-Control:" \
    -H "Pragma:" \
    -H "Cookie:" \
    -H "If-None-Match:" \
    -H "If-Modified-Since:" \
    "${BASE_URL}${CACHE_PATH}")"

  if [[ "${status}" != "200" ]]; then
    echo "[static-vhost-cache-smoke][ERROR] ${CACHE_PATH} returned HTTP ${status}" >&2
    cat "${headers}" >&2 || true
    cat "${body}" >&2 || true
    exit 1
  fi
}

header_value() {
  local headers="$1"
  local name="$2"
  python3 - "${headers}" "${name}" <<'PY'
import pathlib
import sys

target = sys.argv[2].lower()
for line in pathlib.Path(sys.argv[1]).read_text(errors="replace").splitlines():
    if ":" not in line:
        continue
    name, value = line.split(":", 1)
    if name.strip().lower() == target:
        print(value.strip())
        break
PY
}

require_header() {
  local headers="$1"
  local name="$2"
  local want="$3"
  local got
  got="$(header_value "${headers}" "${name}")"
  if [[ "${got}" != "${want}" ]]; then
    echo "[static-vhost-cache-smoke][ERROR] ${name}=${got:-<missing>} want ${want}" >&2
    cat "${headers}" >&2 || true
    exit 1
  fi
}

require_cache_stats_progress() {
  local before="$1"
  local after="$2"
  python3 - "${before}" "${after}" <<'PY'
import json
import pathlib
import sys

before = json.loads(pathlib.Path(sys.argv[1]).read_text()).get("stats", {})
after = json.loads(pathlib.Path(sys.argv[2]).read_text()).get("stats", {})

for field in ("misses_total", "stores_total", "hits_total"):
    advanced = int(after.get(field, 0)) - int(before.get(field, 0))
    if advanced < 1:
        raise SystemExit(f"[static-vhost-cache-smoke][ERROR] cache stat {field} advanced by {advanced}, want >= 1")

if int(after.get("entry_count", 0)) < 1:
    raise SystemExit("[static-vhost-cache-smoke][ERROR] cache stat entry_count is 0, want >= 1")
PY
}

wait_for_ready
admin_login
enable_and_clear_cache_store
cache_store_stats "${tmp_dir}/cache-store-before.json"

fetch_cache_probe first
require_header "${tmp_dir}/first.headers" "X-Tukuyomi-Cacheable" "1"
require_header "${tmp_dir}/first.headers" "X-Tukuyomi-Cache" "MISS"

fetch_cache_probe second
require_header "${tmp_dir}/second.headers" "X-Tukuyomi-Cacheable" "1"
require_header "${tmp_dir}/second.headers" "X-Tukuyomi-Cache" "HIT"

cache_store_stats "${tmp_dir}/cache-store-after.json"
require_cache_stats_progress "${tmp_dir}/cache-store-before.json" "${tmp_dir}/cache-store-after.json"

echo "[static-vhost-cache-smoke][OK] direct static vhost cache passed for ${CACHE_PATH} via ${BASE_URL}"
