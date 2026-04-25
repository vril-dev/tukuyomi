#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
action="${1:-}"
runtime_id="${RUNTIME:-${2:-}}"
api_base="${PHP_FPM_API_BASE:-http://127.0.0.1:${CORAZA_PORT:-9090}/tukuyomi-api}"
admin_username="${WAF_ADMIN_USERNAME:-${TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME:-admin}}"
admin_password="${WAF_ADMIN_PASSWORD:-${TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD:-dev-only-change-this-password-please}}"

case "${action}" in
  up|down|reload) ;;
  *)
    echo "[php-fpm-ctl][ERROR] expected action: up|down|reload" >&2
    exit 1
    ;;
esac

runtime_id="$(printf '%s' "${runtime_id}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9._-')"
if [[ -z "${runtime_id}" ]]; then
  echo "[php-fpm-ctl][ERROR] RUNTIME=php83|php84|php85 is required" >&2
  exit 1
fi
runtime_dir="${ROOT_DIR}/data/php-fpm/binaries/${runtime_id}"
if [[ ! -d "${runtime_dir}" ]]; then
  echo "[php-fpm-ctl][ERROR] runtime ${runtime_id} is not built" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "[php-fpm-ctl][ERROR] jq is required" >&2
  exit 1
fi
if [[ -z "${admin_username}" || -z "${admin_password}" ]]; then
  echo "[php-fpm-ctl][ERROR] WAF_ADMIN_USERNAME and WAF_ADMIN_PASSWORD are required" >&2
  exit 1
fi

tmp_body="$(mktemp)"
cookie_jar="$(mktemp)"
trap 'rm -f "${tmp_body}" "${cookie_jar}"' EXIT

login_body="$(jq -n --arg username "${admin_username}" --arg password "${admin_password}" '{username: $username, password: $password}')"
login_status="$(
  curl -sS -o "${tmp_body}" -w '%{http_code}' \
    -c "${cookie_jar}" -b "${cookie_jar}" \
    -H 'Content-Type: application/json' \
    -X POST --data "${login_body}" \
    "${api_base}/auth/login"
)"
if [[ "${login_status}" != "200" ]]; then
  echo "[php-fpm-ctl][ERROR] admin login failed (HTTP ${login_status})" >&2
  cat "${tmp_body}" >&2
  exit 1
fi
csrf_token="$(
  awk 'NF >= 7 && $6 == "tukuyomi_admin_csrf" { token = $7 } END { if (token != "") print token }' "${cookie_jar}"
)"
if [[ -z "${csrf_token}" ]]; then
  echo "[php-fpm-ctl][ERROR] admin login did not issue csrf cookie" >&2
  exit 1
fi

status_code="$(
  curl -sS -o "${tmp_body}" -w '%{http_code}' \
    -X POST \
    -b "${cookie_jar}" -c "${cookie_jar}" \
    -H "X-Tukuyomi-Actor: make-${action}" \
    -H "X-CSRF-Token: ${csrf_token}" \
    -H 'Content-Type: application/json' \
    "${api_base}/php-runtimes/${runtime_id}/${action}"
)"

if [[ "${status_code}" != "200" ]]; then
  echo "[php-fpm-ctl][ERROR] ${action} ${runtime_id} failed (HTTP ${status_code})" >&2
  cat "${tmp_body}" >&2
  exit 1
fi

echo "[php-fpm-ctl] ${action} ${runtime_id} ok"
