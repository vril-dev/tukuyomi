#!/usr/bin/env bash
set -euo pipefail

PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"
PROXY_PORT="${PROXY_PORT:-19093}"
BASE_URL="${BASE_URL:-http://127.0.0.1:${PROXY_PORT}}"
ADMIN_USERNAME="${ADMIN_USERNAME:-${TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME:-admin}}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-${TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD:-release-smoke-admin-password}}"
COOKIE_JAR="$(mktemp)"
tmp_body="$(mktemp)"
tmp_headers="$(mktemp)"
tmp_gzip_body="$(mktemp)"

cleanup() {
  rm -f "${tmp_body}" "${tmp_headers}" "${tmp_gzip_body}" "${COOKIE_JAR}"
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[release-binary-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd python3

for _ in $(seq 1 30); do
  status="$(curl -sS -o /dev/null -w "%{http_code}" "${BASE_URL}/healthz" || true)"
  if [[ "${status}" == "200" ]]; then
    break
  fi
  sleep 1
done
if [[ "${status:-}" != "200" ]]; then
  echo "[release-binary-smoke][ERROR] proxy did not become ready at ${BASE_URL}" >&2
  exit 1
fi

login_payload="$(python3 - "${ADMIN_USERNAME}" "${ADMIN_PASSWORD}" <<'PY'
import json
import sys

print(json.dumps({"username": sys.argv[1], "password": sys.argv[2]}))
PY
)"

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" \
  -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
  -H "Content-Type: application/json" \
  -X POST --data "${login_payload}" \
  "${BASE_URL}/tukuyomi-api/auth/login")"
if [[ "${status}" != "200" ]]; then
  echo "[release-binary-smoke][ERROR] admin login failed: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi

csrf_token="$(awk 'NF >= 7 && $6 == "tukuyomi_admin_csrf" { token = $7 } END { if (token != "") print token }' "${COOKIE_JAR}")"
if [[ -z "${csrf_token}" ]]; then
  echo "[release-binary-smoke][ERROR] missing csrf cookie after login" >&2
  exit 1
fi

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" \
  -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
  "${BASE_URL}/tukuyomi-api/auth/session")"
if [[ "${status}" != "200" ]]; then
  echo "[release-binary-smoke][ERROR] auth/session failed: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi
python3 - "${tmp_body}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
if payload.get("authenticated") is not True or payload.get("mode") != "session":
    raise SystemExit(f"unexpected auth/session payload: {payload!r}")
PY

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" \
  -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
  "${BASE_URL}/tukuyomi-api/status")"
if [[ "${status}" != "200" ]]; then
  echo "[release-binary-smoke][ERROR] admin status failed: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" \
  "${BASE_URL}/tukuyomi-ui")"
if [[ "${status}" != "200" ]]; then
  echo "[release-binary-smoke][ERROR] embedded admin UI failed: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi
if ! grep -qiE '<!doctype html|<html' "${tmp_body}"; then
  echo "[release-binary-smoke][ERROR] embedded admin UI did not return html" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" -H "Host: ${PROTECTED_HOST}" "${BASE_URL}/v1/whoami")"
if [[ "${status}" != "200" ]]; then
  echo "[release-binary-smoke][ERROR] protected whoami request failed: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi

python3 - "${PROTECTED_HOST}" "${tmp_body}" <<'PY'
import json
import pathlib
import sys

expected_host = sys.argv[1]
payload = json.loads(pathlib.Path(sys.argv[2]).read_text())

if payload.get("host") != expected_host:
    raise SystemExit(f"expected host={expected_host!r}, got {payload.get('host')!r}")
if payload.get("x_protected_host") != "matched":
    raise SystemExit(f"expected x_protected_host='matched', got {payload.get('x_protected_host')!r}")
PY

status="$(curl -sS -D "${tmp_headers}" -o "${tmp_gzip_body}" -w "%{http_code}" \
  -H "Host: ${PROTECTED_HOST}" -H "Accept-Encoding: gzip" \
  "${BASE_URL}/v1/whoami")"
if [[ "${status}" != "200" ]]; then
  echo "[release-binary-smoke][ERROR] protected gzip whoami request failed: ${status}" >&2
  exit 1
fi
if ! grep -qi '^Content-Encoding: gzip' "${tmp_headers}"; then
  echo "[release-binary-smoke][ERROR] expected gzip content encoding" >&2
  cat "${tmp_headers}" >&2 || true
  exit 1
fi
if ! grep -qi '^Vary: .*Accept-Encoding' "${tmp_headers}"; then
  echo "[release-binary-smoke][ERROR] expected Vary: Accept-Encoding" >&2
  cat "${tmp_headers}" >&2 || true
  exit 1
fi
python3 - "${PROTECTED_HOST}" "${tmp_gzip_body}" <<'PY'
import gzip
import json
import pathlib
import sys

expected_host = sys.argv[1]
payload = json.loads(gzip.decompress(pathlib.Path(sys.argv[2]).read_bytes()).decode())

if payload.get("host") != expected_host:
    raise SystemExit(f"expected host={expected_host!r}, got {payload.get('host')!r}")
if payload.get("x_protected_host") != "matched":
    raise SystemExit(f"expected x_protected_host='matched', got {payload.get('x_protected_host')!r}")
PY

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" -H "Host: ${PROTECTED_HOST}" "${BASE_URL}/v1/whoami?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")"
if [[ "${status}" != "403" ]]; then
  echo "[release-binary-smoke][ERROR] expected WAF block, got: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" \
  -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
  -H "X-CSRF-Token: ${csrf_token}" \
  -H "Content-Type: application/json" \
  -X POST --data '{}' \
  "${BASE_URL}/tukuyomi-api/auth/logout")"
if [[ "${status}" != "200" ]]; then
  echo "[release-binary-smoke][ERROR] admin logout failed: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" \
  -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
  "${BASE_URL}/tukuyomi-api/status")"
if [[ "${status}" != "401" ]]; then
  echo "[release-binary-smoke][ERROR] expected admin status=401 after logout, got: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" \
  -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
  "${BASE_URL}/tukuyomi-api/auth/session")"
if [[ "${status}" != "200" ]]; then
  echo "[release-binary-smoke][ERROR] auth/session failed after logout: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi
python3 - "${tmp_body}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
if payload.get("authenticated") is not False:
    raise SystemExit(f"expected logged-out auth/session payload, got {payload!r}")
PY

echo "[release-binary-smoke][OK] admin login/session/logout + protected host + WAF block passed via ${BASE_URL}"
