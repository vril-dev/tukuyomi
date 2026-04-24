#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:${CORAZA_PORT:-19091}}"
PROTECTED_HOST="${PROTECTED_HOST:-}"
ADMIN_API_KEY="${ADMIN_API_KEY:-nextjs-example-admin-key-12345}"
CACHE_PATH="${CACHE_PATH:-/tukuyomi-cache-smoke.txt}"
CACHE_STORE_DIR="${CACHE_STORE_DIR:-cache/response}"
CACHE_MAX_BYTES="${CACHE_MAX_BYTES:-1048576}"

tmp_dir="$(mktemp -d)"
curl_host_args=()
if [[ -n "${PROTECTED_HOST}" ]]; then
  curl_host_args=(-H "Host: ${PROTECTED_HOST}")
fi

cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[nextjs-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd python3

api_request() {
  local method="$1"
  local path="$2"
  shift 2
  curl -fsS -X "${method}" \
    -H "X-API-Key: ${ADMIN_API_KEY}" \
    "$@" \
    "${BASE_URL}${path}"
}

enable_cache_store_if_possible() {
  if [[ -z "${ADMIN_API_KEY}" ]]; then
    echo "[nextjs-smoke] ADMIN_API_KEY is not set; assuming internal cache store is already enabled"
    return 0
  fi

  local store_json etag put_body
  store_json="${tmp_dir}/cache-store.json"
  if ! api_request GET "/tukuyomi-api/cache-store" -o "${store_json}"; then
    echo "[nextjs-smoke][ERROR] failed to read cache-store config" >&2
    exit 1
  fi

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
    echo "[nextjs-smoke][ERROR] failed to enable cache-store" >&2
    exit 1
  fi

  if ! api_request POST "/tukuyomi-api/cache-store/clear" >/dev/null; then
    echo "[nextjs-smoke][ERROR] failed to clear cache-store" >&2
    exit 1
  fi
}

capture_cache_stats() {
  local output="$1"
  if [[ -z "${ADMIN_API_KEY}" ]]; then
    return 0
  fi
  if ! api_request GET "/tukuyomi-api/cache-store" -o "${output}"; then
    echo "[nextjs-smoke][ERROR] failed to read cache-store stats" >&2
    exit 1
  fi
}

require_cache_stats_progress() {
  local before="$1"
  local after="$2"
  if [[ -z "${ADMIN_API_KEY}" ]]; then
    return 0
  fi
  python3 - "${before}" "${after}" <<'PY'
import json
import pathlib
import sys

before = json.loads(pathlib.Path(sys.argv[1]).read_text()).get("stats", {})
after = json.loads(pathlib.Path(sys.argv[2]).read_text()).get("stats", {})

checks = [
    ("misses_total", 1),
    ("stores_total", 1),
    ("hits_total", 1),
]
for field, delta in checks:
    got = int(after.get(field, 0)) - int(before.get(field, 0))
    if got < delta:
        raise SystemExit(f"[nextjs-smoke][ERROR] cache stat {field} advanced by {got}, want >= {delta}")

if int(after.get("entry_count", 0)) < 1:
    raise SystemExit("[nextjs-smoke][ERROR] cache stat entry_count is 0, want >= 1")
PY
}

wait_for_ready() {
  local status
  for _ in $(seq 1 60); do
    status="$(curl -sS -o /dev/null -w "%{http_code}" "${curl_host_args[@]}" "${BASE_URL}/" || true)"
    if [[ "${status}" == "200" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "[nextjs-smoke][ERROR] Next.js example did not become ready at ${BASE_URL}" >&2
  exit 1
}

fetch_cache_probe() {
  local prefix="$1"
  local headers="${tmp_dir}/${prefix}.headers"
  local body="${tmp_dir}/${prefix}.body"
  local status

  status="$(curl -sS -o "${body}" -D "${headers}" -w "%{http_code}" \
    "${curl_host_args[@]}" \
    -H "Cache-Control:" \
    -H "Pragma:" \
    -H "Cookie:" \
    -H "If-None-Match:" \
    -H "If-Modified-Since:" \
    "${BASE_URL}${CACHE_PATH}")"

  if [[ "${status}" != "200" ]]; then
    echo "[nextjs-smoke][ERROR] ${CACHE_PATH} returned HTTP ${status}" >&2
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
    echo "[nextjs-smoke][ERROR] ${name}=${got:-<missing>} want ${want}" >&2
    cat "${headers}" >&2 || true
    exit 1
  fi
}

wait_for_ready
enable_cache_store_if_possible
capture_cache_stats "${tmp_dir}/cache-store-before.json"

fetch_cache_probe first
require_header "${tmp_dir}/first.headers" "X-Tukuyomi-Cacheable" "1"
require_header "${tmp_dir}/first.headers" "X-Tukuyomi-Cache" "MISS"

fetch_cache_probe second
require_header "${tmp_dir}/second.headers" "X-Tukuyomi-Cacheable" "1"
require_header "${tmp_dir}/second.headers" "X-Tukuyomi-Cache" "HIT"
capture_cache_stats "${tmp_dir}/cache-store-after.json"
require_cache_stats_progress "${tmp_dir}/cache-store-before.json" "${tmp_dir}/cache-store-after.json"

echo "[nextjs-smoke][OK] cache smoke passed for ${CACHE_PATH} via ${BASE_URL}"
