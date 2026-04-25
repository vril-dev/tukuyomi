#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=./lib/proxy_api.sh
source "${SCRIPT_DIR}/lib/proxy_api.sh"

proxy_api_need_cmd curl
proxy_api_need_cmd jq
proxy_api_need_cmd docker

VER="${VER:-8.3}"
CORAZA_PORT="${CORAZA_PORT:-9090}"
WAF_LISTEN_PORT="${WAF_LISTEN_PORT:-9090}"
WAF_ADMIN_USERNAME="${WAF_ADMIN_USERNAME:-${TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME:-admin}}"
WAF_ADMIN_PASSWORD="${WAF_ADMIN_PASSWORD:-${TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD:-dev-only-change-this-password-please}}"
runtime_id="php${VER/./}"

SMOKE_SUFFIX="php-fpm-smoke"
SMOKE_CONFIG="${ROOT_DIR}/data/conf/config.${SMOKE_SUFFIX}.json"
SMOKE_PROXY="${ROOT_DIR}/data/conf/proxy.${SMOKE_SUFFIX}.json"
SMOKE_INVENTORY="${ROOT_DIR}/data/php-fpm/inventory.${SMOKE_SUFFIX}.json"
SMOKE_VHOSTS="${ROOT_DIR}/data/php-fpm/vhosts.${SMOKE_SUFFIX}.json"

php_runtime_resp="$(mktemp)"
php_body="$(mktemp)"

cleanup() {
  rm -f "${php_runtime_resp}" "${php_body}" "${SMOKE_CONFIG}" "${SMOKE_PROXY}" "${SMOKE_INVENTORY}" "${SMOKE_VHOSTS}"
  docker compose down --remove-orphans >/dev/null 2>&1 || true
  proxy_api_cleanup
}
trap cleanup EXIT

VER="${VER}" "${SCRIPT_DIR}/php_fpm_runtime_build.sh" >/dev/null

cat >"${SMOKE_INVENTORY}" <<'EOF'
{}
EOF

cat >"${SMOKE_VHOSTS}" <<EOF
{
  "vhosts": [
    {
      "name": "smoke-php",
      "mode": "php-fpm",
      "hostname": "php.smoke.test",
      "listen_port": 9183,
      "document_root": "data/vhosts/samples/php-site/public",
      "runtime_id": "${runtime_id}",
      "generated_target": "smoke-php",
      "try_files": [
        "\$uri",
        "\$uri/",
        "/index.php?\$query_string"
      ]
    }
  ]
}
EOF

cat >"${SMOKE_PROXY}" <<'EOF'
{
  "routes": [
    {
      "name": "smoke-php",
      "enabled": true,
      "priority": 10,
      "match": {
        "hosts": [
          "php.smoke.test"
        ]
      },
      "action": {
        "upstream": "smoke-php"
      }
    }
  ],
  "response_header_sanitize": {
    "mode": "auto"
  }
}
EOF

python3 - "${ROOT_DIR}/data/conf/config.json" "${SMOKE_CONFIG}" <<'PY'
import json
import pathlib
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
cfg = json.loads(src.read_text(encoding="utf-8"))
paths = cfg.setdefault("paths", {})
paths["proxy_config_file"] = "conf/proxy.php-fpm-smoke.json"
paths["php_runtime_inventory_file"] = "data/php-fpm/inventory.php-fpm-smoke.json"
paths["vhost_config_file"] = "data/php-fpm/vhosts.php-fpm-smoke.json"
dst.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
PY

export WAF_CONFIG_FILE="conf/config.${SMOKE_SUFFIX}.json"
export HOST_CORAZA_PORT="${CORAZA_PORT}"
export WAF_ADMIN_USERNAME WAF_ADMIN_PASSWORD

TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME="${WAF_ADMIN_USERNAME}" \
TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD="${WAF_ADMIN_PASSWORD}" \
docker compose up -d --build coraza >/dev/null

proxy_api_init
proxy_api_wait_health 90 1
proxy_api_set_admin_auth_args

curl -fsS "${PROXY_ADMIN_AUTH_ARGS[@]}" "${PROXY_API_URL}/php-runtimes" >"${php_runtime_resp}"

if ! jq -e --arg runtime_id "${runtime_id}" '
  any(.runtimes.runtimes[]; .runtime_id == $runtime_id and .available == true) and
  any(.materialized[]; .runtime_id == $runtime_id and any(.generated_targets[]; . == "smoke-php")) and
  any(.processes[]; .runtime_id == $runtime_id and .running == true)
' "${php_runtime_resp}" >/dev/null; then
  echo "[php-fpm-smoke][ERROR] php runtime snapshot assertion failed" >&2
  cat "${php_runtime_resp}" >&2
  exit 1
fi

php_code="$(curl -fsS -o "${php_body}" -w "%{http_code}" -H 'Host: php.smoke.test' "${PROXY_BASE_URL}/up.php")"
if [[ "${php_code}" != "200" ]] || ! grep -q '"status":"ok"' "${php_body}" || ! grep -q '"service":"php-sample"' "${php_body}"; then
  echo "[php-fpm-smoke][ERROR] php sample assertion failed" >&2
  cat "${php_body}" >&2 || true
  exit 1
fi

echo "[php-fpm-smoke] ok"
