#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -n "${PROXY_BIN:-}" ]]; then
  exec "${PROXY_BIN}" update-country-db "$@"
fi

for candidate in \
  "${ROOT_DIR}/tukuyomi" \
  "${ROOT_DIR}/bin/tukuyomi" \
  "${ROOT_DIR}/server"
do
  if [[ -x "${candidate}" ]]; then
    exec "${candidate}" update-country-db "$@"
  fi
done

if command -v tukuyomi >/dev/null 2>&1; then
  exec "$(command -v tukuyomi)" update-country-db "$@"
fi

echo "[update-country-db][ERROR] tukuyomi binary not found; set PROXY_BIN or place tukuyomi in PATH" >&2
exit 1
