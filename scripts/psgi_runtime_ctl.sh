#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="${1:-}"
RUNTIME_APP_NAME="${RUNTIME_APP:-${VHOST:-${VHOST_NAME:-}}}"
ADMIN_PORT="${CORAZA_PORT:-8080}"
ADMIN_USER="${WAF_ADMIN_USERNAME:-}"
ADMIN_PASS="${WAF_ADMIN_PASSWORD:-}"
COOKIE_FILE="$(mktemp)"
RESP_FILE="$(mktemp)"

cleanup() {
  rm -f "${COOKIE_FILE}" "${RESP_FILE}"
}
trap cleanup EXIT

case "${ACTION}" in
  up|down|reload) ;;
  *)
    echo "[psgi-ctl][ERROR] expected action: up|down|reload" >&2
    exit 1
    ;;
esac

if [[ -z "${RUNTIME_APP_NAME}" ]]; then
  echo "[psgi-ctl][ERROR] RUNTIME_APP=<app-name> is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "[psgi-ctl][ERROR] jq is required" >&2
  exit 1
fi

if [[ -z "${ADMIN_USER}" || -z "${ADMIN_PASS}" ]]; then
  echo "[psgi-ctl][ERROR] WAF_ADMIN_USERNAME and WAF_ADMIN_PASSWORD are required" >&2
  exit 1
fi

base_url="http://127.0.0.1:${ADMIN_PORT}/tukuyomi-api"
login_status="$(
  curl -sS -o "${RESP_FILE}" -w '%{http_code}' \
    -c "${COOKIE_FILE}" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":$(jq -Rn --arg v "${ADMIN_USER}" '$v'),\"password\":$(jq -Rn --arg v "${ADMIN_PASS}" '$v')}" \
    "${base_url}/auth/login"
)"
if [[ "${login_status}" != "200" ]]; then
  echo "[psgi-ctl][ERROR] admin login failed (HTTP ${login_status})" >&2
  cat "${RESP_FILE}" >&2
  exit 1
fi

csrf_token="$(
  awk 'NF >= 7 && $6 == "tukuyomi_admin_csrf" { token = $7 } END { if (token != "") print token }' "${COOKIE_FILE}"
)"
if [[ -z "${csrf_token}" ]]; then
  echo "[psgi-ctl][ERROR] admin login did not issue csrf cookie" >&2
  exit 1
fi

encoded_app="$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "${RUNTIME_APP_NAME}")"
status_code="$(
  curl -sS -o "${RESP_FILE}" -w '%{http_code}' \
    -b "${COOKIE_FILE}" \
    -H "X-CSRF-Token: ${csrf_token}" \
    -H 'Content-Type: application/json' \
    -d '{}' \
    "${base_url}/psgi-processes/${encoded_app}/${ACTION}"
)"
if [[ "${status_code}" != "200" ]]; then
  echo "[psgi-ctl][ERROR] ${ACTION} ${RUNTIME_APP_NAME} failed (HTTP ${status_code})" >&2
  cat "${RESP_FILE}" >&2
  exit 1
fi

echo "[psgi-ctl] ${ACTION} ${RUNTIME_APP_NAME} ok"
