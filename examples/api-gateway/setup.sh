#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${ROOT_DIR}/../_shared/install_crs.sh" "${ROOT_DIR}/data/rules/crs" "${1:-v4.23.0}"

if [[ ! -f "${ROOT_DIR}/.env" ]]; then
  cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
  echo "[setup] copied .env from .env.example"
fi

echo "[setup] api-gateway example is ready"
echo "[setup] run: cd ${ROOT_DIR} && docker compose up -d --build"
