#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${ROOT_DIR}/../_shared/install_crs.sh" "${ROOT_DIR}/data/rules/crs" "${1:-v4.23.0}"

if [[ ! -f "${ROOT_DIR}/.env" ]]; then
  cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
  echo "[setup] copied .env from .env.example"
fi

echo "[setup] wordpress example is ready"
echo "[setup] run: cd ${ROOT_DIR} && docker compose up -d --build"
echo "[setup] thin front proxy: cd ${ROOT_DIR} && WAF_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true docker compose --profile front-proxy up -d --build"
