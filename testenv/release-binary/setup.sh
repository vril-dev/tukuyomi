#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/testenv/release-binary/runtime"
RUNTIME_CONF_DIR="${RUNTIME_DIR}/conf"
RUNTIME_RULES_DIR="${RUNTIME_DIR}/rules"
RUNTIME_LOG_DIR="${RUNTIME_DIR}/logs"
RUNTIME_CACHE_DIR="${RUNTIME_DIR}/cache"
COMPOSE_ENV_FILE="${ROOT_DIR}/testenv/release-binary/.env"
CRS_RULE="${RUNTIME_RULES_DIR}/crs/rules/REQUEST-901-INITIALIZATION.conf"
BINARY_PATH="${ROOT_DIR}/tukuyomi"

if [[ -d "${ROOT_DIR}/conf" ]]; then
  SOURCE_CONF_DIR="${ROOT_DIR}/conf"
else
  SOURCE_CONF_DIR="${ROOT_DIR}/data/conf"
fi

if [[ -d "${ROOT_DIR}/rules" ]]; then
  SOURCE_RULES_DIR="${ROOT_DIR}/rules"
else
  SOURCE_RULES_DIR="${ROOT_DIR}/data/rules"
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
  "${RUNTIME_RULES_DIR}" \
  "${RUNTIME_LOG_DIR}/coraza" \
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
copy_if_exists "${SOURCE_RULES_DIR}/tukuyomi.conf" "${RUNTIME_RULES_DIR}/tukuyomi.conf"

if [[ -d "${SOURCE_RULES_DIR}/crs" ]]; then
  echo "[release-binary-setup] staging CRS files into runtime"
  rm -rf "${RUNTIME_RULES_DIR}/crs"
  cp -R "${SOURCE_RULES_DIR}/crs" "${RUNTIME_RULES_DIR}/crs"
fi

if [[ ! -f "${RUNTIME_CONF_DIR}/crs-disabled.conf" ]]; then
  : > "${RUNTIME_CONF_DIR}/crs-disabled.conf"
fi

if [[ ! -f "${CRS_RULE}" ]]; then
  echo "[release-binary-setup] installing CRS into ${RUNTIME_RULES_DIR}/crs"
  DEST_DIR="${RUNTIME_RULES_DIR}/crs" "${ROOT_DIR}/scripts/install_crs.sh"
else
  echo "[release-binary-setup] CRS already present"
fi

echo "[release-binary-setup] ready"
echo "[release-binary-setup] run: cd ${ROOT_DIR}/testenv/release-binary && docker compose up -d --build"
