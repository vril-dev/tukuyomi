#!/usr/bin/env bash
set -euo pipefail

PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"
EXAMPLE_TOPOLOGY="${EXAMPLE_TOPOLOGY:-direct}"

if [[ -z "${BASE_URL:-}" ]]; then
  case "${EXAMPLE_TOPOLOGY}" in
    front)
      BASE_URL="http://127.0.0.1:${NGINX_PORT:-18081}"
      ;;
    direct)
      BASE_URL="http://127.0.0.1:${CORAZA_PORT:-19091}"
      ;;
    *)
      echo "[example-smoke][ERROR] unsupported EXAMPLE_TOPOLOGY=${EXAMPLE_TOPOLOGY}" >&2
      exit 1
      ;;
  esac
else
  BASE_URL="${BASE_URL}"
fi

tmp_body="$(mktemp)"

cleanup() {
  rm -f "${tmp_body}"
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[example-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd python3

for _ in $(seq 1 30); do
  status="$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: ${PROTECTED_HOST}" "${BASE_URL}/api/whoami" || true)"
  if [[ "${status}" == "200" ]]; then
    break
  fi
  sleep 1
done
if [[ "${status:-}" != "200" ]]; then
  echo "[example-smoke][ERROR] nextjs example did not become ready at ${BASE_URL}" >&2
  exit 1
fi

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" -H "Host: ${PROTECTED_HOST}" "${BASE_URL}/api/whoami")"
if [[ "${status}" != "200" ]]; then
  echo "[example-smoke][ERROR] whoami request failed: ${status}" >&2
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
PY

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" -H "Host: ${PROTECTED_HOST}" "${BASE_URL}/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")"
if [[ "${status}" != "403" ]]; then
  echo "[example-smoke][ERROR] expected WAF block for protected host, got: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi

echo "[example-smoke][OK] protected host smoke passed for ${PROTECTED_HOST} via ${BASE_URL}"
