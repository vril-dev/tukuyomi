#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/testenv/release-binary/runtime"
RUNTIME_CONF_DIR="${RUNTIME_DIR}/conf"
RUNTIME_LOG_DIR="${RUNTIME_DIR}/logs"
RUNTIME_CACHE_DIR="${RUNTIME_DIR}/cache"
COMPOSE_ENV_FILE="${ROOT_DIR}/testenv/release-binary/.env"
BINARY_PATH="${ROOT_DIR}/tukuyomi"

if [[ -d "${ROOT_DIR}/conf" ]]; then
  SOURCE_CONF_DIR="${ROOT_DIR}/conf"
else
  SOURCE_CONF_DIR="${ROOT_DIR}/data/conf"
fi

copy_if_exists() {
  local src="$1"
  local dest="$2"
  if [[ ! -f "${src}" ]]; then
    return 0
  fi
  mkdir -p "$(dirname "${dest}")"
  cp "${src}" "${dest}"
}

mkdir -p \
  "${RUNTIME_CONF_DIR}" \
  "${RUNTIME_CONF_DIR}/rules" \
  "${RUNTIME_DIR}/audit" \
  "${RUNTIME_DIR}/cache/response" \
  "${RUNTIME_LOG_DIR}/waf" \
  "${RUNTIME_LOG_DIR}/proxy" \
  "${RUNTIME_CACHE_DIR}"

cat > "${COMPOSE_ENV_FILE}" <<EOF
PUID=$(id -u)
GUID=$(id -g)
EOF

if [[ ! -x "${BINARY_PATH}" && -f "${ROOT_DIR}/coraza/src/go.mod" ]] && command -v go >/dev/null 2>&1; then
  echo "[release-binary-setup] building local tukuyomi binary"
  (
    cd "${ROOT_DIR}/coraza/src"
    go build -o "${BINARY_PATH}" ./cmd/server
  )
fi

copy_if_exists "${ROOT_DIR}/testenv/release-binary/proxy-routes.json" "${RUNTIME_CONF_DIR}/proxy-routes.json"
copy_if_exists "${ROOT_DIR}/testenv/release-binary/cache-store.json" "${RUNTIME_CONF_DIR}/cache-store.json"
copy_if_exists "${SOURCE_CONF_DIR}/sites.json" "${RUNTIME_CONF_DIR}/sites.json"
copy_if_exists "${SOURCE_CONF_DIR}/waf-bypass.json" "${RUNTIME_CONF_DIR}/waf-bypass.json"
copy_if_exists "${SOURCE_CONF_DIR}/waf-bypass.sample.json" "${RUNTIME_CONF_DIR}/waf-bypass.sample.json"
copy_if_exists "${SOURCE_CONF_DIR}/country-block.json" "${RUNTIME_CONF_DIR}/country-block.json"
copy_if_exists "${SOURCE_CONF_DIR}/cache-rules.json" "${RUNTIME_CONF_DIR}/cache-rules.json"
copy_if_exists "${SOURCE_CONF_DIR}/waf.bypass" "${RUNTIME_CONF_DIR}/waf.bypass"
copy_if_exists "${SOURCE_CONF_DIR}/country-block.conf" "${RUNTIME_CONF_DIR}/country-block.conf"
copy_if_exists "${SOURCE_CONF_DIR}/cache.conf" "${RUNTIME_CONF_DIR}/cache.conf"
copy_if_exists "${SOURCE_CONF_DIR}/rate-limit.json" "${RUNTIME_CONF_DIR}/rate-limit.json"
copy_if_exists "${SOURCE_CONF_DIR}/bot-defense.json" "${RUNTIME_CONF_DIR}/bot-defense.json"
copy_if_exists "${SOURCE_CONF_DIR}/semantic.json" "${RUNTIME_CONF_DIR}/semantic.json"
copy_if_exists "${SOURCE_CONF_DIR}/notifications.json" "${RUNTIME_CONF_DIR}/notifications.json"
copy_if_exists "${SOURCE_CONF_DIR}/ip-reputation.json" "${RUNTIME_CONF_DIR}/ip-reputation.json"
if [[ -d "${SOURCE_CONF_DIR}/rules" ]]; then
  mkdir -p "${RUNTIME_CONF_DIR}/rules"
  cp -R "${SOURCE_CONF_DIR}/rules/." "${RUNTIME_CONF_DIR}/rules/"
fi
copy_if_exists "${SOURCE_CONF_DIR}/crs-disabled.conf" "${RUNTIME_CONF_DIR}/crs-disabled.conf"

if [[ ! -f "${RUNTIME_CONF_DIR}/crs-disabled.conf" ]]; then
  : > "${RUNTIME_CONF_DIR}/crs-disabled.conf"
fi

stage_root="$(mktemp -d "${ROOT_DIR}/.tmp-release-binary-crs.XXXXXX")"
trap 'rm -rf "${stage_root}"' EXIT

echo "[release-binary-setup] staging CRS import tree"
DEST_DIR="${stage_root}/testenv/release-binary/runtime/rules/crs" "${ROOT_DIR}/scripts/install_crs.sh"

echo "[release-binary-setup] seeding runtime DB rule assets"
(
  cd "${ROOT_DIR}"
  WAF_CONFIG_FILE="testenv/release-binary/proxy-config.json" "${BINARY_PATH}" db-migrate
  WAF_RULE_ASSET_FS_ROOT="${stage_root}" WAF_CONFIG_FILE="testenv/release-binary/proxy-config.json" "${BINARY_PATH}" db-import-waf-rule-assets
)

echo "[release-binary-setup] ready"
echo "[release-binary-setup] run: cd ${ROOT_DIR}/testenv/release-binary && docker compose up -d --build"
