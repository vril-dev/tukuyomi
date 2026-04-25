#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/testenv/release-binary/runtime"
RUNTIME_CONF_DIR="${RUNTIME_DIR}/conf"
RUNTIME_LOG_DIR="${RUNTIME_DIR}/logs"
RUNTIME_CACHE_DIR="${RUNTIME_DIR}/cache"
STAGE_PARENT="${RUNTIME_DIR}/tmp"
STAGE_ROOT=""
COMPOSE_ENV_FILE="${ROOT_DIR}/testenv/release-binary/.env"
BINARY_PATH="${ROOT_DIR}/tukuyomi"

mkdir -p \
  "${RUNTIME_CONF_DIR}" \
  "${RUNTIME_CONF_DIR}/rules" \
  "${RUNTIME_DIR}/audit" \
  "${RUNTIME_DIR}/cache/response" \
  "${RUNTIME_LOG_DIR}/waf" \
  "${RUNTIME_LOG_DIR}/proxy" \
  "${RUNTIME_CACHE_DIR}" \
  "${STAGE_PARENT}"

cleanup() {
  if [[ -n "${STAGE_ROOT}" ]]; then
    rm -rf "${STAGE_ROOT}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

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

cat > "${RUNTIME_CONF_DIR}/config.json" <<'EOF'
{
  "server": {
    "listen_addr": ":9090",
    "http3": {
      "enabled": false,
      "alt_svc_max_age_sec": 86400
    }
  },
  "admin": {
    "api_base_path": "/tukuyomi-api",
    "ui_base_path": "/tukuyomi-ui",
    "session_secret": "release-smoke-session-secret-123456",
    "session_ttl_sec": 28800,
    "api_auth_disable": false,
    "cors_allowed_origins": [],
    "strict_override": false,
    "allow_insecure_defaults": false,
    "external_mode": "api_only_external",
    "trusted_cidrs": [
      "127.0.0.1/32",
      "::1/128",
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ],
    "trust_forwarded_for": false
  },
  "paths": {
    "rules_file": "tukuyomi.conf",
    "crs_setup_file": "rules/crs/crs-setup.conf",
    "crs_rules_dir": "rules/crs/rules",
    "crs_disabled_file": "conf/crs-disabled.conf",
    "security_audit_file": "audit/security-audit.ndjson",
    "security_audit_blob_dir": "audit/security-audit-blobs"
  },
  "proxy": {
    "rollback_history_size": 8,
    "audit_file": "audit/proxy-rules-audit.ndjson"
  },
  "crs": {
    "enable": true
  },
  "storage": {
    "db_driver": "sqlite",
    "db_path": "db/tukuyomi.db"
  }
}
EOF
: > "${RUNTIME_CONF_DIR}/crs-disabled.conf"

STAGE_ROOT="$(mktemp -d "${STAGE_PARENT}/crs.XXXXXX")"

echo "[release-binary-setup] staging CRS import tree"
DEST_DIR="${STAGE_ROOT}/rules/crs" "${ROOT_DIR}/scripts/install_crs.sh"

echo "[release-binary-setup] seeding runtime DB rule assets"
(
  cd "${RUNTIME_DIR}"
  WAF_CONFIG_FILE="conf/config.json" "${BINARY_PATH}" db-migrate
  WAF_RULE_ASSET_FS_ROOT="${STAGE_ROOT}" WAF_CONFIG_FILE="conf/config.json" "${BINARY_PATH}" db-import-waf-rule-assets
  WAF_DB_IMPORT_PROFILE="release-binary" WAF_CONFIG_FILE="conf/config.json" "${BINARY_PATH}" db-import
)

echo "[release-binary-setup] ready"
echo "[release-binary-setup] run: cd ${ROOT_DIR}/testenv/release-binary && docker compose up -d --build"
