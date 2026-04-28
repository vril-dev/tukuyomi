#!/usr/bin/env bash

benchmark_runtime_secret() {
  local secret

  secret="$(od -An -N32 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' || true)"
  if [[ -z "${secret}" ]]; then
    secret="benchmark-session-secret-$(date -u +%s)-$$"
  fi
  printf '%s\n' "${secret}"
}

benchmark_runtime_init() {
  local label="$1"
  local base_config configured_config run_id secret

  BENCH_ISOLATED_RUNTIME="${BENCH_ISOLATED_RUNTIME:-1}"
  if [[ "${BENCH_ISOLATED_RUNTIME}" != "0" && "${BENCH_ISOLATED_RUNTIME}" != "1" ]]; then
    echo "[benchmark-runtime][ERROR] BENCH_ISOLATED_RUNTIME must be 0 or 1" >&2
    return 1
  fi
  if [[ "${BENCH_ISOLATED_RUNTIME}" != "1" ]]; then
    return 0
  fi

  configured_config="${WAF_CONFIG_FILE:-conf/config.json}"
  base_config="$(proxy_api_resolve_host_config_path "${ROOT_DIR}" "${configured_config}")"
  if [[ ! -f "${base_config}" ]]; then
    echo "[benchmark-runtime][ERROR] base config not found: ${configured_config}" >&2
    return 1
  fi

  run_id="${label}-$$"
  BENCH_RUNTIME_DATA_DIR="tmp/bench"
  BENCH_RUNTIME_HOST_DIR="${ROOT_DIR}/data/${BENCH_RUNTIME_DATA_DIR}"
  BENCH_CONFIG_DATA_REF="${BENCH_RUNTIME_DATA_DIR}/${run_id}.config.json"
  BENCH_CONFIG_HOST_REF="data/${BENCH_CONFIG_DATA_REF}"
  BENCH_CONFIG_HOST_FILE="${ROOT_DIR}/${BENCH_CONFIG_HOST_REF}"
  BENCH_DB_DATA_REF="${BENCH_RUNTIME_DATA_DIR}/${run_id}.db"
  BENCH_DB_CONTAINER_REF="data/${BENCH_DB_DATA_REF}"
  BENCH_DB_HOST_FILE="${ROOT_DIR}/data/${BENCH_DB_DATA_REF}"

  mkdir -p "${BENCH_RUNTIME_HOST_DIR}"
  rm -f "${BENCH_CONFIG_HOST_FILE}" "${BENCH_DB_HOST_FILE}" "${BENCH_DB_HOST_FILE}-shm" "${BENCH_DB_HOST_FILE}-wal"

  secret="$(benchmark_runtime_secret)"
  jq --arg session_secret "${secret}" '
    .admin = (.admin // {})
    | .admin.session_secret = $session_secret
    | .admin.api_auth_disable = false
    | .admin.allow_insecure_defaults = false
    | .admin.read_only = false
  ' "${base_config}" > "${BENCH_CONFIG_HOST_FILE}"

  export WAF_CONFIG_FILE="${BENCH_CONFIG_HOST_REF}"
}

benchmark_runtime_seed_db() {
  local label="$1"

  if [[ "${BENCH_ISOLATED_RUNTIME:-1}" != "1" ]]; then
    return 0
  fi
  echo "${label} preparing isolated benchmark config and DB"
  (
    cd "${ROOT_DIR}"
    WAF_CONFIG_FILE="${BENCH_CONFIG_HOST_REF}" \
    WAF_STORAGE_DB_PATH="${BENCH_DB_DATA_REF}" \
    make crs-install db-import
  )
}

benchmark_runtime_docker_db_path() {
  if [[ "${BENCH_ISOLATED_RUNTIME:-1}" == "1" ]]; then
    printf '%s\n' "${BENCH_DB_CONTAINER_REF}"
    return 0
  fi
  printf '%s\n' "${WAF_STORAGE_DB_PATH:-}"
}

benchmark_runtime_local_config_path() {
  if [[ "${BENCH_ISOLATED_RUNTIME:-1}" == "1" ]]; then
    printf '%s\n' "${BENCH_CONFIG_DATA_REF}"
    return 0
  fi
  printf '%s\n' "${WAF_CONFIG_FILE:-conf/config.json}"
}

benchmark_runtime_local_db_path() {
  if [[ "${BENCH_ISOLATED_RUNTIME:-1}" == "1" ]]; then
    printf '%s\n' "${BENCH_DB_DATA_REF}"
    return 0
  fi
  printf '%s\n' "${WAF_STORAGE_DB_PATH:-}"
}

benchmark_runtime_cleanup() {
  if [[ "${BENCH_ISOLATED_RUNTIME:-1}" != "1" ]]; then
    return 0
  fi
  if [[ -n "${BENCH_CONFIG_HOST_FILE:-}" ]]; then
    rm -f "${BENCH_CONFIG_HOST_FILE}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${BENCH_DB_HOST_FILE:-}" ]]; then
    rm -f "${BENCH_DB_HOST_FILE}" "${BENCH_DB_HOST_FILE}-shm" "${BENCH_DB_HOST_FILE}-wal" >/dev/null 2>&1 || true
  fi
  rmdir "${BENCH_RUNTIME_HOST_DIR:-}" >/dev/null 2>&1 || true
}
