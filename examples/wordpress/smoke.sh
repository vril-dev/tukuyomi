#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:${CORAZA_PORT:-19092}}"
PROTECTED_HOST="${PROTECTED_HOST:-wordpress.example.test}"
USER_AGENT="${USER_AGENT:-tukuyomi-wordpress-smoke/1.0}"
ADMIN_USERNAME="${ADMIN_USERNAME:-${TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME:-admin}}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-${TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD:-wordpress-example-admin-password}}"

tmp_dir="$(mktemp -d)"
admin_cookie_jar="${tmp_dir}/admin-cookie.txt"

cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[wordpress-smoke][ERROR] missing command: $1" >&2
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
    echo "[wordpress-smoke][ERROR] admin login failed: ${code}" >&2
    cat "${login_resp}" >&2 || true
    exit 1
  fi
}

curl_common=(
  -H "Host: ${PROTECTED_HOST}"
  -H "User-Agent: ${USER_AGENT}"
)

for _ in $(seq 1 120); do
  status="$(curl -sS -o "${tmp_dir}/root.body" -w "%{http_code}" "${curl_common[@]}" "${BASE_URL}/" || true)"
  if [[ "${status}" == "200" || "${status}" == "302" ]]; then
    break
  fi
  sleep 1
done
if [[ "${status:-}" != "200" && "${status:-}" != "302" ]]; then
  echo "[wordpress-smoke][ERROR] WordPress did not become ready at ${BASE_URL}: ${status:-<missing>}" >&2
  cat "${tmp_dir}/root.body" >&2 || true
  exit 1
fi

admin_login
status="$(curl -sS -o "${tmp_dir}/status.body" -w "%{http_code}" -b "${admin_cookie_jar}" -c "${admin_cookie_jar}" "${curl_common[@]}" "${BASE_URL}/tukuyomi-api/status" || true)"
if [[ "${status}" != "200" ]]; then
  echo "[wordpress-smoke][ERROR] admin status failed: ${status}" >&2
  cat "${tmp_dir}/status.body" >&2 || true
  exit 1
fi

status="$(curl -sS -o "${tmp_dir}/block.body" -w "%{http_code}" "${curl_common[@]}" "${BASE_URL}/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" || true)"
if [[ "${status}" != "403" ]]; then
  echo "[wordpress-smoke][ERROR] expected WAF block 403, got ${status}" >&2
  cat "${tmp_dir}/block.body" >&2 || true
  exit 1
fi

echo "[wordpress-smoke][OK] wordpress proxy and WAF smoke passed for ${PROTECTED_HOST} via ${BASE_URL}"
