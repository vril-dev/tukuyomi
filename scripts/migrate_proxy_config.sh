#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"
OUTPUT_PATH=""
FORCE=0
CHECK_ONLY=0

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/migrate_proxy_config.sh [options]

Options:
  -e, --env-file <path>  Path to .env file (default: ./.env)
  -o, --output <path>    Output path for proxy JSON (default: derived from WAF_PROXY_CONFIG_FILE)
  -f, --force            Overwrite existing proxy JSON
  -c, --check            Validate proxy JSON only (no write)
  -h, --help             Show this help

Notes:
  - Legacy source value: WAF_APP_URL
  - If WAF_PROXY_CONFIG_FILE is "conf/proxy.json", host-side output becomes "data/conf/proxy.json"
USAGE
}

need_cmd() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "[migrate-proxy-config][ERROR] missing command: ${name}" >&2
    exit 1
  fi
}

read_env_value() {
  local file="$1"
  local key="$2"
  if [[ ! -f "${file}" ]]; then
    return 0
  fi
  local line
  line="$(grep -E "^${key}=" "${file}" | tail -n 1 || true)"
  if [[ -z "${line}" ]]; then
    return 0
  fi
  line="${line#*=}"
  line="${line%\"}"
  line="${line#\"}"
  line="${line%\'}"
  line="${line#\'}"
  printf '%s' "${line}"
}

map_container_path_to_host() {
  local path="$1"
  if [[ "${path}" == conf/* || "${path}" == rules/* || "${path}" == logs/* ]]; then
    printf 'data/%s' "${path}"
    return 0
  fi
  printf '%s' "${path}"
}

validate_proxy_json() {
  local file="$1"
  if [[ ! -s "${file}" ]]; then
    echo "[migrate-proxy-config][ERROR] proxy config file does not exist or is empty: ${file}" >&2
    return 1
  fi
  jq -e '
    (.upstreams | type == "array" and length > 0) and
    (.dial_timeout | type == "number" and . > 0) and
    (.response_header_timeout | type == "number" and . > 0) and
    (.idle_conn_timeout | type == "number" and . > 0) and
    (.max_idle_conns | type == "number" and . > 0) and
    (.max_idle_conns_per_host | type == "number" and . > 0) and
    (.max_conns_per_host | type == "number" and . > 0) and
    (.expect_continue_timeout | type == "number" and . > 0) and
    (.max_response_buffer_bytes | type == "number" and . >= 0) and
    (.flush_interval_ms | type == "number" and . >= 0) and
    (.health_check_interval_sec | type == "number" and . > 0) and
    (.health_check_timeout_sec | type == "number" and . > 0)
  ' "${file}" >/dev/null
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -e|--env-file)
      ENV_FILE="$2"
      shift 2
      ;;
    -o|--output)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    -f|--force)
      FORCE=1
      shift
      ;;
    -c|--check)
      CHECK_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[migrate-proxy-config][ERROR] unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

need_cmd jq

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "[migrate-proxy-config][ERROR] env file not found: ${ENV_FILE}" >&2
  exit 1
fi

if [[ -z "${OUTPUT_PATH}" ]]; then
  cfg_path="$(read_env_value "${ENV_FILE}" "WAF_PROXY_CONFIG_FILE")"
  if [[ -z "${cfg_path}" ]]; then
    cfg_path="conf/proxy.json"
  fi
  OUTPUT_PATH="$(map_container_path_to_host "${cfg_path}")"
fi

if [[ "${CHECK_ONLY}" -eq 1 ]]; then
  validate_proxy_json "${OUTPUT_PATH}"
  echo "[migrate-proxy-config][OK] valid proxy config: ${OUTPUT_PATH}"
  exit 0
fi

if [[ -f "${OUTPUT_PATH}" && "${FORCE}" -ne 1 ]]; then
  echo "[migrate-proxy-config][SKIP] ${OUTPUT_PATH} already exists (use --force to overwrite)"
  validate_proxy_json "${OUTPUT_PATH}"
  echo "[migrate-proxy-config][OK] existing file is valid"
  exit 0
fi

legacy_upstream="$(read_env_value "${ENV_FILE}" "WAF_APP_URL")"
if [[ -z "${legacy_upstream}" ]]; then
  legacy_upstream="http://host.docker.internal:3000"
  echo "[migrate-proxy-config][WARN] WAF_APP_URL not found. fallback upstream=${legacy_upstream}" >&2
fi

mkdir -p "$(dirname "${OUTPUT_PATH}")"

jq -n \
  --arg upstream "${legacy_upstream}" \
  '{
    upstreams: [
      {
        name: "primary",
        url: $upstream,
        weight: 1,
        enabled: true
      }
    ],
    dial_timeout: 5,
    response_header_timeout: 10,
    idle_conn_timeout: 90,
    max_idle_conns: 100,
    max_idle_conns_per_host: 100,
    max_conns_per_host: 200,
    force_http2: false,
    disable_compression: false,
    expect_continue_timeout: 1,
    tls_insecure_skip_verify: false,
    tls_client_cert: "",
    tls_client_key: "",
    buffer_request_body: false,
    max_response_buffer_bytes: 0,
    flush_interval_ms: 0,
    health_check_path: "/healthz",
    health_check_interval_sec: 15,
    health_check_timeout_sec: 2
  }' > "${OUTPUT_PATH}"

validate_proxy_json "${OUTPUT_PATH}"
echo "[migrate-proxy-config][OK] wrote ${OUTPUT_PATH} from ${ENV_FILE}"
