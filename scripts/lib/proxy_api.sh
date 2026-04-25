#!/usr/bin/env bash

proxy_api_read_env_value() {
  local env_file="$1"
  local key="$2"
  if [[ ! -f "${env_file}" ]]; then
    return 0
  fi

  awk -F= -v key="${key}" '
    $0 ~ "^[[:space:]]*" key "=" {
      val = $0
      sub("^[[:space:]]*" key "=", "", val)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
      if (val ~ /^".*"$/ || val ~ /^'\''.*'\''$/) {
        val = substr(val, 2, length(val)-2)
      }
      print val
      exit
    }
  ' "${env_file}"
}

proxy_api_resolve_host_config_path() {
  local project_dir="$1"
  local container_path="$2"
  local normalized

  normalized="${container_path#./}"
  if [[ "${normalized}" == /* ]]; then
    printf '%s\n' "${normalized}"
    return 0
  fi
  if [[ "${normalized}" == data/* ]]; then
    printf '%s/%s\n' "${project_dir}" "${normalized}"
    return 0
  fi
  printf '%s/data/%s\n' "${project_dir}" "${normalized}"
}

proxy_api_init() {
  local lib_dir env_config_file env_api_basepath env_ui_basepath

  lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  PROXY_PROJECT_DIR="${PROXY_PROJECT_DIR:-$(cd "${lib_dir}/../.." && pwd)}"
  PROXY_ENV_FILE="${PROXY_ENV_FILE:-${PROXY_PROJECT_DIR}/.env}"

  HOST_CORAZA_PORT="${HOST_CORAZA_PORT:-19090}"
  WAF_LISTEN_PORT="${WAF_LISTEN_PORT:-9090}"

  env_config_file="${WAF_CONFIG_FILE:-}"
  env_api_basepath="${WAF_API_BASEPATH:-}"
  env_ui_basepath="${WAF_UI_BASEPATH:-}"

  if [[ -z "${env_config_file}" ]]; then
    env_config_file="$(proxy_api_read_env_value "${PROXY_ENV_FILE}" "WAF_CONFIG_FILE")"
  fi
  WAF_CONFIG_FILE="${env_config_file:-conf/config.json}"
  PROXY_HOST_CONFIG_FILE="$(proxy_api_resolve_host_config_path "${PROXY_PROJECT_DIR}" "${WAF_CONFIG_FILE}")"

  cfg_api_basepath=""
  cfg_ui_basepath=""
  if command -v jq >/dev/null 2>&1 && [[ -f "${PROXY_HOST_CONFIG_FILE}" ]]; then
    cfg_api_basepath="$(jq -r '.admin.api_base_path // empty' "${PROXY_HOST_CONFIG_FILE}" 2>/dev/null || true)"
    cfg_ui_basepath="$(jq -r '.admin.ui_base_path // empty' "${PROXY_HOST_CONFIG_FILE}" 2>/dev/null || true)"
  fi

  WAF_API_BASEPATH="${env_api_basepath:-${cfg_api_basepath:-/tukuyomi-api}}"
  WAF_UI_BASEPATH="${env_ui_basepath:-${cfg_ui_basepath:-/tukuyomi-ui}}"
  WAF_ADMIN_USERNAME="${WAF_ADMIN_USERNAME:-${TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME:-admin}}"
  WAF_ADMIN_PASSWORD="${WAF_ADMIN_PASSWORD:-${TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD:-dev-only-change-this-password-please}}"
  WAF_ADMIN_TOKEN="${WAF_ADMIN_TOKEN:-}"
  if [[ "${WAF_API_BASEPATH}" != /* ]]; then
    WAF_API_BASEPATH="/${WAF_API_BASEPATH}"
  fi
  if [[ "${WAF_UI_BASEPATH}" != /* ]]; then
    WAF_UI_BASEPATH="/${WAF_UI_BASEPATH}"
  fi

  PROXY_BASE_URL="${PROXY_BASE_URL:-http://127.0.0.1:${HOST_CORAZA_PORT}}"
  PROXY_ADMIN_BASE_URL="${PROXY_ADMIN_BASE_URL:-${PROXY_BASE_URL}}"
  PROXY_API_URL="${PROXY_ADMIN_BASE_URL}${WAF_API_BASEPATH}"
  PROXY_UI_URL="${PROXY_ADMIN_BASE_URL}${WAF_UI_BASEPATH}"
  PROXY_AUTH_HEADER="Authorization: Bearer ${WAF_ADMIN_TOKEN}"
  PROXY_API_USE_SESSION="${PROXY_API_USE_SESSION:-0}"
  PROXY_COOKIE_JAR="${PROXY_COOKIE_JAR:-${TMPDIR:-/tmp}/proxy_api_cookie_$$.txt}"
  PROXY_CSRF_TOKEN="${PROXY_CSRF_TOKEN:-}"
  PROXY_ADMIN_AUTH_ARGS=()
}

proxy_api_cleanup() {
  rm -f "${PROXY_COOKIE_JAR:-}"
}

proxy_api_need_cmd() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "[proxy-api][ERROR] missing command: ${name}" >&2
    return 1
  fi
}

proxy_api_wait_health() {
  local retries="${1:-60}"
  local interval="${2:-1}"
  local i code
  for i in $(seq 1 "${retries}"); do
    code="$(curl -s -o /dev/null -w "%{http_code}" "${PROXY_BASE_URL}/healthz" || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep "${interval}"
  done
  echo "[proxy-api][ERROR] healthz timeout" >&2
  return 1
}

proxy_api_expect_http_code() {
  local method="$1"
  local url="$2"
  local expected="$3"
  local code
  if [[ "${method}" == "HEAD" ]]; then
    code="$(curl -sS -I -o /dev/null -w "%{http_code}" "${url}" || true)"
  else
    code="$(curl -sS -o /dev/null -w "%{http_code}" -X "${method}" "${url}" || true)"
  fi
  if [[ "${code}" != "${expected}" ]]; then
    echo "[proxy-api][ERROR] ${method} ${url} => ${code} (expected ${expected})" >&2
    return 1
  fi
}

proxy_api_refresh_csrf_token() {
  local csrf_token=""
  if [[ -f "${PROXY_COOKIE_JAR}" ]]; then
    csrf_token="$(
      awk 'NF >= 7 && $6 == "tukuyomi_admin_csrf" { token = $7 } END { if (token != "") print token }' "${PROXY_COOKIE_JAR}"
    )"
  fi
  PROXY_CSRF_TOKEN="${csrf_token}"
}

proxy_api_set_admin_auth_args() {
  PROXY_ADMIN_AUTH_ARGS=()
  if [[ "${PROXY_API_USE_SESSION}" == "1" ]]; then
    proxy_api_refresh_csrf_token
    PROXY_ADMIN_AUTH_ARGS=(-b "${PROXY_COOKIE_JAR}" -c "${PROXY_COOKIE_JAR}")
    if [[ -n "${PROXY_CSRF_TOKEN}" ]]; then
      PROXY_ADMIN_AUTH_ARGS+=(-H "X-CSRF-Token: ${PROXY_CSRF_TOKEN}")
    fi
    return 0
  fi

  if [[ -z "${WAF_ADMIN_TOKEN}" ]]; then
    proxy_api_login_session || return 1
    PROXY_ADMIN_AUTH_ARGS=(-b "${PROXY_COOKIE_JAR}" -c "${PROXY_COOKIE_JAR}")
    if [[ -n "${PROXY_CSRF_TOKEN}" ]]; then
      PROXY_ADMIN_AUTH_ARGS+=(-H "X-CSRF-Token: ${PROXY_CSRF_TOKEN}")
    fi
    return 0
  fi
  PROXY_ADMIN_AUTH_ARGS=(-H "${PROXY_AUTH_HEADER}")
}

proxy_api_login_session() {
  local response_file code payload

  PROXY_API_USE_SESSION=1
  : > "${PROXY_COOKIE_JAR}"
  if [[ -z "${WAF_ADMIN_USERNAME}" || -z "${WAF_ADMIN_PASSWORD}" ]]; then
    echo "[proxy-api][ERROR] WAF_ADMIN_USERNAME and WAF_ADMIN_PASSWORD are required for session login" >&2
    return 1
  fi
  response_file="$(mktemp)"
  payload="$(jq -n --arg username "${WAF_ADMIN_USERNAME}" --arg password "${WAF_ADMIN_PASSWORD}" '{username: $username, password: $password}')"
  code="$(curl -sS -o "${response_file}" -w "%{http_code}" \
    -c "${PROXY_COOKIE_JAR}" -b "${PROXY_COOKIE_JAR}" \
    -H "Content-Type: application/json" \
    -X POST --data "${payload}" "${PROXY_API_URL}/auth/login")"
  if [[ "${code}" != "200" ]]; then
    echo "[proxy-api][ERROR] admin login failed: ${code}" >&2
    cat "${response_file}" >&2 || true
    rm -f "${response_file}"
    return 1
  fi
  rm -f "${response_file}"
  proxy_api_refresh_csrf_token
  if [[ -z "${PROXY_CSRF_TOKEN}" ]]; then
    echo "[proxy-api][ERROR] login did not issue csrf cookie" >&2
    return 1
  fi
}

proxy_api_logout_session() {
  local response_file code

  if [[ "${PROXY_API_USE_SESSION}" != "1" ]]; then
    return 0
  fi
  proxy_api_set_admin_auth_args
  response_file="$(mktemp)"
  code="$(curl -sS -o "${response_file}" -w "%{http_code}" \
    "${PROXY_ADMIN_AUTH_ARGS[@]}" \
    -H "Content-Type: application/json" \
    -X POST --data '{}' "${PROXY_API_URL}/auth/logout")"
  if [[ "${code}" != "200" ]]; then
    echo "[proxy-api][ERROR] admin logout failed: ${code}" >&2
    cat "${response_file}" >&2 || true
    rm -f "${response_file}"
    return 1
  fi
  rm -f "${response_file}"
  PROXY_CSRF_TOKEN=""
  proxy_api_refresh_csrf_token
}

proxy_api_get_snapshot() {
  proxy_api_set_admin_auth_args
  curl -fsS "${PROXY_ADMIN_AUTH_ARGS[@]}" "${PROXY_API_URL}/proxy-rules"
}

proxy_api_apply_raw() {
  local raw="$1"
  local response_file="${2:-/tmp/proxy_api_put_resp.json}"
  local snapshot etag body code

  snapshot="$(proxy_api_get_snapshot)"
  etag="$(jq -r '.etag // empty' <<<"${snapshot}")"
  if [[ -z "${etag}" ]]; then
    echo "[proxy-api][ERROR] missing etag in proxy snapshot" >&2
    return 1
  fi
  body="$(jq -n --arg raw "${raw}" '{raw: $raw}')"
  proxy_api_set_admin_auth_args
  code="$(curl -sS -o "${response_file}" -w "%{http_code}" \
    "${PROXY_ADMIN_AUTH_ARGS[@]}" \
    -H "If-Match: ${etag}" -H "Content-Type: application/json" \
    -X PUT --data "${body}" "${PROXY_API_URL}/proxy-rules")"
  if [[ "${code}" != "200" ]]; then
    echo "[proxy-api][ERROR] failed to apply proxy rules: ${code}" >&2
    cat "${response_file}" >&2 || true
    return 1
  fi
}
