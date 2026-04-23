#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUID_VALUE="${PUID:-$(id -u)}"
GUID_VALUE="${GUID:-$(id -g)}"

compose() {
  PUID="${PUID_VALUE}" GUID="${GUID_VALUE}" docker compose "$@"
}

"${ROOT_DIR}/../_shared/install_crs.sh" "${ROOT_DIR}/data/rules/crs" "${1:-v4.23.0}"

if [[ ! -f "${ROOT_DIR}/.env" ]]; then
  cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
  echo "[setup] copied .env from .env.example"
fi

mkdir -p \
  "${ROOT_DIR}/data/db" \
  "${ROOT_DIR}/data/audit" \
  "${ROOT_DIR}/data/cache/response" \
  "${ROOT_DIR}/data/php-fpm" \
  "${ROOT_DIR}/data/logs" \
  "${ROOT_DIR}/data/rules"

compose down --remove-orphans >/dev/null 2>&1 || true
rm -f "${ROOT_DIR}/data/db/tukuyomi.db" "${ROOT_DIR}/data/db/tukuyomi.db-wal" "${ROOT_DIR}/data/db/tukuyomi.db-shm"

compose build coraza
compose run --rm --no-deps coraza /app/server db-migrate
compose run --rm --no-deps coraza /app/server db-import-waf-rule-assets
compose run --rm --no-deps coraza /app/server db-import

echo "[setup] api-gateway example DB bootstrap is ready"
echo "[setup] run: cd ${ROOT_DIR} && docker compose up -d --build"
