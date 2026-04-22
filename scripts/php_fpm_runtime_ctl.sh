#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
action="${1:-}"
runtime_id="${RUNTIME:-${2:-}}"
api_base="${PHP_FPM_API_BASE:-http://127.0.0.1:${CORAZA_PORT:-9090}/tukuyomi-api}"
api_key="${WAF_API_KEY_PRIMARY:-}"

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
if [[ -z "${api_key}" ]]; then
  echo "[php-fpm-ctl][ERROR] WAF_API_KEY_PRIMARY is required" >&2
  exit 1
fi

tmp_body="$(mktemp)"
trap 'rm -f "${tmp_body}"' EXIT

status_code="$(
  curl -sS -o "${tmp_body}" -w '%{http_code}' \
    -X POST \
    -H "X-Tukuyomi-Actor: make-${action}" \
    -H "X-API-Key: ${api_key}" \
    -H 'Content-Type: application/json' \
    "${api_base}/php-runtimes/${runtime_id}/${action}"
)"

if [[ "${status_code}" != "200" ]]; then
  echo "[php-fpm-ctl][ERROR] ${action} ${runtime_id} failed (HTTP ${status_code})" >&2
  cat "${tmp_body}" >&2
  exit 1
fi

echo "[php-fpm-ctl] ${action} ${runtime_id} ok"
