#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUID_VALUE="${PUID:-$(id -u)}"
GUID_VALUE="${GUID:-$(id -g)}"
STAGE_PARENT="${ROOT_DIR}/data/tmp"
STAGE_ROOT=""

compose() {
  PUID="${PUID_VALUE}" GUID="${GUID_VALUE}" docker compose "$@"
}

cleanup() {
  if [[ -n "${STAGE_ROOT}" ]]; then
    rm -rf "${STAGE_ROOT}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "${STAGE_PARENT}"
STAGE_ROOT="$(mktemp -d "${STAGE_PARENT}/crs.XXXXXX")"
WAF_RULE_SEED_CRS_SETUP_OVERRIDE="${ROOT_DIR}/../../seeds/waf/rules/crs-setup-high-paranoia.conf" \
  "${ROOT_DIR}/../../scripts/stage_waf_rule_assets.sh" "${STAGE_ROOT}" "${1:-v4.23.0}"

if [[ ! -f "${ROOT_DIR}/.env" ]]; then
  cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
  echo "[setup] copied .env from .env.example"
fi

mkdir -p \
  "${ROOT_DIR}/data/db" \
  "${ROOT_DIR}/data/audit" \
  "${ROOT_DIR}/data/cache/response" \
  "${ROOT_DIR}/data/php-fpm"

compose down --remove-orphans >/dev/null 2>&1 || true
rm -f "${ROOT_DIR}/data/db/tukuyomi.db" "${ROOT_DIR}/data/db/tukuyomi.db-wal" "${ROOT_DIR}/data/db/tukuyomi.db-shm"

compose build coraza
compose run --rm --no-deps coraza /app/server db-migrate
compose run --rm --no-deps \
  -v "${STAGE_ROOT}:/seed-root:ro" \
  -e WAF_RULE_ASSET_FS_ROOT=/seed-root \
  coraza /app/server db-import-waf-rule-assets
compose run --rm --no-deps \
  -e WAF_DB_IMPORT_PROFILE=wordpress \
  coraza /app/server db-import

echo "[setup] wordpress example DB bootstrap is ready from built-in wordpress profile"
echo "[setup] run: cd ${ROOT_DIR} && docker compose up -d --build"
