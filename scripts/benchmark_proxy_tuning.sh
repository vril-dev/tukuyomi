#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/proxy_api.sh
source "${SCRIPT_DIR}/lib/proxy_api.sh"

GO_BIN="${GO:-go}"
BENCH_REQUESTS="${BENCH_REQUESTS:-600}"
WARMUP_REQUESTS="${WARMUP_REQUESTS:-100}"
BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-1,10,50}"
BENCH_PATH="${BENCH_PATH:-/bench}"
BENCH_TIMEOUT_SEC="${BENCH_TIMEOUT_SEC:-30}"
BENCH_MAX_FAIL_RATE_PCT="${BENCH_MAX_FAIL_RATE_PCT:-}"
BENCH_MIN_RPS="${BENCH_MIN_RPS:-}"
BENCH_DISABLE_RATE_LIMIT="${BENCH_DISABLE_RATE_LIMIT:-1}"
BENCH_DISABLE_REQUEST_GUARDS="${BENCH_DISABLE_REQUEST_GUARDS:-1}"
BENCH_ACCESS_LOG_MODE="${BENCH_ACCESS_LOG_MODE:-full}"
BENCH_CLIENT_KEEPALIVE="${BENCH_CLIENT_KEEPALIVE:-1}"
BENCH_PROXY_MODE="${BENCH_PROXY_MODE:-current}"
BENCH_PROXY_ENGINE="${BENCH_PROXY_ENGINE:-tukuyomi_proxy}"
BENCH_PROFILE="${BENCH_PROFILE:-0}"
BENCH_PROFILE_ADDR="${BENCH_PROFILE_ADDR:-127.0.0.1:6060}"
BENCH_PROFILE_SECONDS="${BENCH_PROFILE_SECONDS:-10}"
UPSTREAM_PORT="${UPSTREAM_PORT:-}"
OUTPUT_FILE="${OUTPUT_FILE:-data/logs/proxy/proxy-benchmark-summary.md}"
OUTPUT_JSON_FILE="${OUTPUT_JSON_FILE:-data/logs/proxy/proxy-benchmark-summary.json}"

benchmark_failed=0
bench_ip_counter=10
baseline_rate_limit_raw=""
rate_limit_overridden=0
json_rows_file=""
upstream_log_file=""
config_backup_pairs=()
proxy_rules_host_file=""
rate_limit_host_file=""
bot_defense_host_file=""
semantic_host_file=""
ip_reputation_host_file=""
bypass_host_file=""
profile_cpu_pid=""
profile_cpu_file=""
profile_heap_file=""
profile_allocs_file=""
compose_pprof_addr=""

need_cmd() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "[proxy-bench][ERROR] missing command: ${name}" >&2
    exit 1
  fi
}

need_cmd docker
need_cmd curl
need_cmd jq
need_cmd ab
need_cmd "${GO_BIN}"

validate_uint_at_least() {
  local name="$1"
  local value="$2"
  local min="$3"
  if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
    echo "[proxy-bench][ERROR] ${name} must be an integer" >&2
    exit 1
  fi
  if [[ "${value}" -lt "${min}" ]]; then
    echo "[proxy-bench][ERROR] ${name} must be >= ${min}" >&2
    exit 1
  fi
}

validate_uint_at_least BENCH_REQUESTS "${BENCH_REQUESTS}" 5
validate_uint_at_least WARMUP_REQUESTS "${WARMUP_REQUESTS}" 0
validate_uint_at_least BENCH_TIMEOUT_SEC "${BENCH_TIMEOUT_SEC}" 1

if [[ ! "${BENCH_PATH}" =~ ^/ ]]; then
  echo "[proxy-bench][ERROR] BENCH_PATH must start with '/'" >&2
  exit 1
fi

if [[ "${#BENCH_PATH}" -gt 256 || "${BENCH_PATH}" == *".."* || "${BENCH_PATH}" == *"?"* || "${BENCH_PATH}" == *"#"* ]]; then
  echo "[proxy-bench][ERROR] BENCH_PATH must be a plain absolute path without '..', query, or fragment" >&2
  exit 1
fi

if [[ "${BENCH_PATH}" == */ ]]; then
  echo "[proxy-bench][ERROR] BENCH_PATH must identify a file-like path and must not end with '/'" >&2
  exit 1
fi

if [[ -n "${UPSTREAM_PORT}" ]] && ! [[ "${UPSTREAM_PORT}" =~ ^[0-9]+$ ]]; then
  echo "[proxy-bench][ERROR] UPSTREAM_PORT must be an integer" >&2
  exit 1
fi
if [[ -n "${UPSTREAM_PORT}" && ( "${UPSTREAM_PORT}" -lt 1 || "${UPSTREAM_PORT}" -gt 65535 ) ]]; then
  echo "[proxy-bench][ERROR] UPSTREAM_PORT must be between 1 and 65535" >&2
  exit 1
fi

if [[ "${BENCH_DISABLE_RATE_LIMIT}" != "0" && "${BENCH_DISABLE_RATE_LIMIT}" != "1" ]]; then
  echo "[proxy-bench][ERROR] BENCH_DISABLE_RATE_LIMIT must be 0 or 1" >&2
  exit 1
fi

if [[ "${BENCH_DISABLE_REQUEST_GUARDS}" != "0" && "${BENCH_DISABLE_REQUEST_GUARDS}" != "1" ]]; then
  echo "[proxy-bench][ERROR] BENCH_DISABLE_REQUEST_GUARDS must be 0 or 1" >&2
  exit 1
fi

if [[ "${BENCH_CLIENT_KEEPALIVE}" != "0" && "${BENCH_CLIENT_KEEPALIVE}" != "1" ]]; then
  echo "[proxy-bench][ERROR] BENCH_CLIENT_KEEPALIVE must be 0 or 1" >&2
  exit 1
fi

case "${BENCH_ACCESS_LOG_MODE}" in
  full|minimal|off)
    ;;
  *)
    echo "[proxy-bench][ERROR] BENCH_ACCESS_LOG_MODE must be full, minimal, or off" >&2
    exit 1
    ;;
esac

case "${BENCH_PROXY_MODE}" in
  current|proxy-only)
    ;;
  *)
    echo "[proxy-bench][ERROR] BENCH_PROXY_MODE must be current or proxy-only" >&2
    exit 1
    ;;
esac

case "${BENCH_PROXY_ENGINE}" in
  net_http|tukuyomi_proxy)
    ;;
  *)
    echo "[proxy-bench][ERROR] BENCH_PROXY_ENGINE must be net_http or tukuyomi_proxy" >&2
    exit 1
    ;;
esac

if [[ "${BENCH_PROFILE}" != "0" && "${BENCH_PROFILE}" != "1" ]]; then
  echo "[proxy-bench][ERROR] BENCH_PROFILE must be 0 or 1" >&2
  exit 1
fi

validate_profile_addr() {
  local raw="$1"
  local host port

  if [[ "${raw}" == \[*\]:* ]]; then
    host="${raw%%]*}"
    host="${host#[}"
    port="${raw##*:}"
  elif [[ "${raw}" == *:* && "${raw}" != *:*:* ]]; then
    host="${raw%:*}"
    port="${raw##*:}"
  else
    echo "[proxy-bench][ERROR] BENCH_PROFILE_ADDR must be loopback host:port" >&2
    exit 1
  fi

  if [[ -z "${host}" || -z "${port}" || ! "${port}" =~ ^[0-9]+$ ]]; then
    echo "[proxy-bench][ERROR] BENCH_PROFILE_ADDR must include a valid loopback host and port" >&2
    exit 1
  fi
  if (( port < 1 || port > 65535 )); then
    echo "[proxy-bench][ERROR] BENCH_PROFILE_ADDR port must be between 1 and 65535" >&2
    exit 1
  fi
  case "${host}" in
    localhost|127.*|::1)
      ;;
    *)
      echo "[proxy-bench][ERROR] BENCH_PROFILE_ADDR must bind to localhost or a loopback IP" >&2
      exit 1
      ;;
  esac
}

if [[ "${BENCH_PROFILE}" == "1" ]]; then
  validate_uint_at_least BENCH_PROFILE_SECONDS "${BENCH_PROFILE_SECONDS}" 1
  validate_profile_addr "${BENCH_PROFILE_ADDR}"
fi

proxy_api_init

tmp_dir="$(mktemp -d)"
upstream_pid=""
baseline_raw=""

cleanup() {
  if [[ -n "${profile_cpu_pid}" ]]; then
    kill "${profile_cpu_pid}" >/dev/null 2>&1 || true
    wait "${profile_cpu_pid}" >/dev/null 2>&1 || true
  fi
  if [[ "${rate_limit_overridden}" -eq 1 ]]; then
    restore_rate_limit_rules || true
  fi
  if [[ -n "${baseline_raw}" ]]; then
    restore_proxy_rules || true
  fi
  if [[ -n "${upstream_pid}" ]]; then
    kill "${upstream_pid}" >/dev/null 2>&1 || true
    wait "${upstream_pid}" >/dev/null 2>&1 || true
  fi
  (
    cd "${ROOT_DIR}"
    CORAZA_PORT="${HOST_CORAZA_PORT}" docker compose down --remove-orphans >/dev/null 2>&1 || true
  )
  restore_config_file_backups || true
  rm -rf "${tmp_dir}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

config_path_from_app_config() {
  local key="$1"
  local fallback="$2"
  local configured

  configured="$(jq -r --arg key "${key}" --arg fallback "${fallback}" '.paths[$key] // $fallback' "${PROXY_HOST_CONFIG_FILE}" 2>/dev/null || true)"
  if [[ -z "${configured}" || "${configured}" == "null" ]]; then
    configured="${fallback}"
  fi
  proxy_api_resolve_host_config_path "${ROOT_DIR}" "${configured}"
}

init_benchmark_config_files() {
  proxy_rules_host_file="$(config_path_from_app_config proxy_config_file conf/proxy.json)"
  rate_limit_host_file="$(config_path_from_app_config rate_limit_file conf/rate-limit.json)"
  bot_defense_host_file="$(config_path_from_app_config bot_defense_file conf/bot-defense.json)"
  semantic_host_file="$(config_path_from_app_config semantic_file conf/semantic.json)"
  ip_reputation_host_file="$(config_path_from_app_config ip_reputation_file conf/ip-reputation.json)"
  bypass_host_file="$(config_path_from_app_config bypass_file conf/waf-bypass.json)"
}

backup_config_file() {
  local path="$1"
  local name backup

  if [[ -z "${path}" ]]; then
    return 0
  fi
  name="$(basename "${path}")"
  backup="${tmp_dir}/${name}.backup.${#config_backup_pairs[@]}"
  if [[ -f "${path}" ]]; then
    cp "${path}" "${backup}"
    config_backup_pairs+=("${path}:${backup}")
  else
    config_backup_pairs+=("${path}:")
  fi
}

restore_config_file_backups() {
  local pair path backup

  for pair in "${config_backup_pairs[@]}"; do
    path="${pair%%:*}"
    backup="${pair#*:}"
    if [[ -f "${backup}" ]]; then
      cp "${backup}" "${path}"
    elif [[ -z "${backup}" ]]; then
      rm -f "${path}"
    fi
  done
}

apply_json_file_transform() {
  local path="$1"
  local label="$2"
  local filter="$3"
  local out

  if [[ -z "${path}" || ! -f "${path}" ]]; then
    return 0
  fi
  out="${tmp_dir}/${label}.json"
  jq "${filter}" "${path}" > "${out}"
  mv "${out}" "${path}"
}

disable_rate_limit_file_for_benchmark() {
  apply_json_file_transform "${rate_limit_host_file}" rate-limit-disabled '
    def disable_scope:
      .enabled = false
      | .default_policy.enabled = false
      | .rules = [];

    if has("default") or has("hosts") then
      .default |= ((. // {}) | disable_scope)
      | .hosts |= ((. // {}) | with_entries(.value |= ((. // {}) | disable_scope)))
    else
      disable_scope
    end
  '
  echo "[proxy-bench] rate-limit file temporarily disabled"
}

disable_request_guard_files_for_benchmark() {
  apply_json_file_transform "${bot_defense_host_file}" bot-defense-disabled '
    def disable_scope:
      .enabled = false
      | .dry_run = true
      | .path_policies = []
      | .behavioral_detection.enabled = false
      | .browser_signals.enabled = false
      | .device_signals.enabled = false
      | .header_signals.enabled = false
      | .tls_signals.enabled = false
      | .quarantine.enabled = false;

    if has("default") or has("hosts") then
      .default |= ((. // {}) | disable_scope)
      | .hosts |= ((. // {}) | with_entries(.value |= ((. // {}) | disable_scope)))
    else
      disable_scope
    end
  '

  apply_json_file_transform "${semantic_host_file}" semantic-disabled '
    def disable_scope:
      .enabled = false
      | .provider.enabled = false;

    if has("default") or has("hosts") then
      .default |= ((. // {}) | disable_scope)
      | .hosts |= ((. // {}) | with_entries(.value |= ((. // {}) | disable_scope)))
    else
      disable_scope
    end
  '

  apply_json_file_transform "${ip_reputation_host_file}" ip-reputation-disabled '
    def disable_scope:
      .enabled = false
      | .feed_urls = []
      | .blocklist = [];

    if has("default") or has("hosts") then
      .default |= ((. // {}) | disable_scope)
      | .hosts |= ((. // {}) | with_entries(.value |= ((. // {}) | disable_scope)))
    else
      disable_scope
    end
  '
  echo "[proxy-bench] request-security guard files temporarily disabled"
}

apply_proxy_engine_for_benchmark() {
  local out

  if [[ -z "${PROXY_HOST_CONFIG_FILE}" || ! -f "${PROXY_HOST_CONFIG_FILE}" ]]; then
    echo "[proxy-bench][ERROR] config file not found for proxy engine selection: ${PROXY_HOST_CONFIG_FILE}" >&2
    exit 1
  fi
  out="${tmp_dir}/config-proxy-engine.json"
  jq --arg mode "${BENCH_PROXY_ENGINE}" '
    .proxy = (.proxy // {})
    | .proxy.engine = (.proxy.engine // {})
    | .proxy.engine.mode = $mode
  ' "${PROXY_HOST_CONFIG_FILE}" > "${out}"
  mv "${out}" "${PROXY_HOST_CONFIG_FILE}"
  echo "[proxy-bench] proxy engine temporarily set to ${BENCH_PROXY_ENGINE}"
}

enable_waf_bypass_for_proxy_only_mode() {
  local out

  if [[ -z "${bypass_host_file}" ]]; then
    echo "[proxy-bench][ERROR] bypass file path is empty" >&2
    exit 1
  fi

  mkdir -p "$(dirname "${bypass_host_file}")"
  if [[ ! -f "${bypass_host_file}" ]]; then
    out="${tmp_dir}/waf-bypass-profile-only.json"
    jq -n --arg path "${BENCH_PATH}" '{default: {entries: [{path: $path}]}}' > "${out}"
    mv "${out}" "${bypass_host_file}"
    echo "[proxy-bench] WAF bypass temporarily enabled for proxy-only mode path=${BENCH_PATH}"
    return 0
  fi

  if grep -q '^[[:space:]]*{' "${bypass_host_file}"; then
    out="${tmp_dir}/waf-bypass-profile-only.json"
    jq --arg path "${BENCH_PATH}" '
      if has("entries") then
        {default: {entries: (.entries // [])}, hosts: (.hosts // {})}
      else
        .
      end
      | .default = (.default // {})
      | .default.entries = ((.default.entries // []) + [{path: $path}])
    ' "${bypass_host_file}" > "${out}"
    mv "${out}" "${bypass_host_file}"
  else
    printf '\n%s\n' "${BENCH_PATH}" >> "${bypass_host_file}"
  fi
  echo "[proxy-bench] WAF bypass temporarily enabled for proxy-only mode path=${BENCH_PATH}"
}

append_json_row() {
  local preset="$1"
  local concurrency="$2"
  local complete="$3"
  local failed="$4"
  local non2xx="$5"
  local fail_rate="$6"
  local avg="$7"
  local p95="$8"
  local p99="$9"
  local rps="${10}"

  jq -n \
    --arg preset "${preset}" \
    --arg concurrency "${concurrency}" \
    --arg complete "${complete}" \
    --arg failed "${failed}" \
    --arg non2xx "${non2xx}" \
    --arg fail_rate "${fail_rate}" \
    --arg avg "${avg}" \
    --arg p95 "${p95}" \
    --arg p99 "${p99}" \
    --arg rps "${rps}" \
    '{
      preset: $preset,
      concurrency: ($concurrency | tonumber),
      complete: ($complete | tonumber),
      failed: ($failed | tonumber),
      non_2xx: ($non2xx | tonumber),
      fail_rate_pct: ($fail_rate | tonumber),
      avg_latency_ms: ($avg | tonumber),
      p95_latency_ms: ($p95 | tonumber),
      p99_latency_ms: ($p99 | tonumber),
      rps: ($rps | tonumber)
    }' >> "${json_rows_file}"
}

apply_proxy_raw() {
  local raw="$1"
  proxy_api_apply_raw "${raw}" "${tmp_dir}/put_resp.json"
}

restore_proxy_rules() {
  if [[ -z "${baseline_raw}" ]]; then
    return 0
  fi
  echo "[proxy-bench] restoring baseline proxy rules"
  apply_proxy_raw "${baseline_raw}"
}

rate_limit_get_snapshot() {
  curl -fsS -H "${PROXY_AUTH_HEADER}" "${PROXY_API_URL}/rate-limit-rules"
}

rate_limit_apply_raw() {
  local raw="$1"
  local response_file="${tmp_dir}/put_rate_limit_resp.json"
  local snapshot etag body code

  snapshot="$(rate_limit_get_snapshot)"
  etag="$(jq -r '.etag // empty' <<<"${snapshot}")"
  if [[ -z "${etag}" ]]; then
    echo "[proxy-bench][ERROR] missing etag in rate-limit snapshot" >&2
    return 1
  fi

  body="$(jq -n --arg raw "${raw}" '{raw: $raw}')"
  code="$(curl -sS -o "${response_file}" -w "%{http_code}" \
    -H "${PROXY_AUTH_HEADER}" -H "If-Match: ${etag}" -H "Content-Type: application/json" \
    -X PUT --data "${body}" "${PROXY_API_URL}/rate-limit-rules")"
  if [[ "${code}" != "200" ]]; then
    echo "[proxy-bench][ERROR] failed to apply rate-limit rules: ${code}" >&2
    cat "${response_file}" >&2 || true
    return 1
  fi
}

override_rate_limit_rules_for_benchmark() {
  local snapshot
  local disabled_raw

  snapshot="$(rate_limit_get_snapshot)"
  baseline_rate_limit_raw="$(jq -r '.raw // empty' <<<"${snapshot}")"
  if [[ -z "${baseline_rate_limit_raw}" ]]; then
    echo "[proxy-bench][WARN] rate-limit raw is empty, skip override" >&2
    return 0
  fi

  disabled_raw="$(jq '
    def disable_scope:
      .enabled = false
      | .default_policy.enabled = false
      | .rules = [];

    if has("default") or has("hosts") then
      .default |= ((. // {}) | disable_scope)
      | .hosts |= ((. // {}) | with_entries(.value |= ((. // {}) | disable_scope)))
    else
      disable_scope
    end
  ' <<<"${baseline_rate_limit_raw}")"

  rate_limit_apply_raw "${disabled_raw}"
  rate_limit_overridden=1
  echo "[proxy-bench] rate-limit rules temporarily disabled"
}

restore_rate_limit_rules() {
  if [[ -z "${baseline_rate_limit_raw}" ]]; then
    return 0
  fi
  echo "[proxy-bench] restoring baseline rate-limit rules"
  rate_limit_apply_raw "${baseline_rate_limit_raw}"
}

validate_concurrency_levels() {
  local csv="$1"
  local lvl trimmed
  local levels=()

  IFS=',' read -r -a levels <<<"${csv}"
  if [[ "${#levels[@]}" -eq 0 ]]; then
    echo "[proxy-bench][ERROR] BENCH_CONCURRENCY is empty" >&2
    return 1
  fi

  for lvl in "${levels[@]}"; do
    trimmed="${lvl//[[:space:]]/}"
    if [[ -z "${trimmed}" ]]; then
      echo "[proxy-bench][ERROR] BENCH_CONCURRENCY contains empty value" >&2
      return 1
    fi
    if ! [[ "${trimmed}" =~ ^[0-9]+$ ]]; then
      echo "[proxy-bench][ERROR] invalid concurrency value: ${trimmed}" >&2
      return 1
    fi
    if [[ "${trimmed}" -le 0 ]]; then
      echo "[proxy-bench][ERROR] concurrency must be > 0: ${trimmed}" >&2
      return 1
    fi
  done
}

extract_ab_metric() {
  local file="$1"
  local pattern="$2"
  local fallback="${3:-0}"
  local out

  out="$(sed -nE "${pattern}" "${file}" | head -n1 || true)"
  if [[ -n "${out}" ]]; then
    printf "%s" "${out}"
    return 0
  fi
  printf "%s" "${fallback}"
}

bench_count_for_concurrency() {
  local count="$1"
  local concurrency="$2"
  if [[ "${count}" -lt "${concurrency}" ]]; then
    printf "%s" "${concurrency}"
    return 0
  fi
  printf "%s" "${count}"
}

run_ab() {
  local count="$1"
  local concurrency="$2"
  local url="$3"
  local output_file="$4"
  local bench_ip="${5:-198.18.0.10}"
  local -a ab_args

  ab_args=(-n "${count}" -c "${concurrency}" -s "${BENCH_TIMEOUT_SEC}")
  if [[ "${BENCH_CLIENT_KEEPALIVE}" == "1" ]]; then
    ab_args+=(-k)
  fi
  ab_args+=(-H "X-Forwarded-For: ${bench_ip}" -H "X-Real-IP: ${bench_ip}")

  ab "${ab_args[@]}" "${url}" > "${output_file}"
}

profile_url_base() {
  printf "http://%s" "${BENCH_PROFILE_ADDR}"
}

prepare_profile_artifacts() {
  local output_dir run_id

  if [[ "${BENCH_PROFILE}" != "1" ]]; then
    return 0
  fi

  output_dir="$(dirname "${OUTPUT_FILE}")"
  mkdir -p "${output_dir}"
  run_id="$(date -u +"%Y%m%dT%H%M%SZ")-${BENCH_PROXY_MODE}-${BENCH_PROXY_ENGINE}"
  profile_cpu_file="${output_dir}/proxy-benchmark-${run_id}.cpu.pprof"
  profile_heap_file="${output_dir}/proxy-benchmark-${run_id}.heap.pprof"
  profile_allocs_file="${output_dir}/proxy-benchmark-${run_id}.allocs.pprof"
}

wait_for_profile_endpoint() {
  local i url

  if [[ "${BENCH_PROFILE}" != "1" ]]; then
    return 0
  fi

  url="$(profile_url_base)/debug/pprof/"
  for i in $(seq 1 50); do
    if (
      cd "${ROOT_DIR}"
      docker compose exec -T coraza sh -lc "wget -q -O /dev/null '${url}'"
    ); then
      return 0
    fi
    sleep 0.2
  done
  echo "[proxy-bench][ERROR] pprof endpoint did not become reachable at ${BENCH_PROFILE_ADDR}" >&2
  return 1
}

assert_public_pprof_not_exposed() {
  local body_file

  if [[ "${BENCH_PROFILE}" != "1" ]]; then
    return 0
  fi

  body_file="${tmp_dir}/public_pprof_body.txt"
  curl -sS -o "${body_file}" "${PROXY_BASE_URL}/debug/pprof/" >/dev/null 2>&1 || true
  if grep -qi 'Types of profiles available' "${body_file}" || grep -qi '/debug/pprof/profile' "${body_file}"; then
    echo "[proxy-bench][ERROR] public listener exposes pprof content" >&2
    return 1
  fi
  echo "[proxy-bench] public listener pprof exposure check passed"
}

start_cpu_profile_capture() {
  local url

  if [[ "${BENCH_PROFILE}" != "1" ]]; then
    return 0
  fi

  url="$(profile_url_base)/debug/pprof/profile?seconds=${BENCH_PROFILE_SECONDS}"
  echo "[proxy-bench] capturing CPU profile: ${profile_cpu_file}"
  (
    cd "${ROOT_DIR}"
    docker compose exec -T coraza sh -lc "wget -q -O - '${url}'"
  ) > "${profile_cpu_file}" &
  profile_cpu_pid="$!"
}

finish_cpu_profile_capture() {
  if [[ "${BENCH_PROFILE}" != "1" || -z "${profile_cpu_pid}" ]]; then
    return 0
  fi

  if ! wait "${profile_cpu_pid}"; then
    profile_cpu_pid=""
    echo "[proxy-bench][ERROR] CPU profile capture failed" >&2
    return 1
  fi
  profile_cpu_pid=""
  if [[ ! -s "${profile_cpu_file}" ]]; then
    echo "[proxy-bench][ERROR] CPU profile artifact is empty: ${profile_cpu_file}" >&2
    return 1
  fi
}

capture_profile_snapshot() {
  local name="$1"
  local output="$2"
  local url

  if [[ "${BENCH_PROFILE}" != "1" ]]; then
    return 0
  fi

  url="$(profile_url_base)/debug/pprof/${name}"
  echo "[proxy-bench] capturing ${name} profile: ${output}"
  (
    cd "${ROOT_DIR}"
    docker compose exec -T coraza sh -lc "wget -q -O - '${url}'"
  ) > "${output}"
  if [[ ! -s "${output}" ]]; then
    echo "[proxy-bench][ERROR] ${name} profile artifact is empty: ${output}" >&2
    return 1
  fi
}

capture_memory_profiles() {
  capture_profile_snapshot heap "${profile_heap_file}"
  capture_profile_snapshot allocs "${profile_allocs_file}"
}

wait_for_upstream() {
  local i code
  for i in $(seq 1 30); do
    code="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${UPSTREAM_PORT}${BENCH_PATH}" || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    if [[ -n "${upstream_pid}" ]] && ! kill -0 "${upstream_pid}" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  echo "[proxy-bench][ERROR] upstream did not become reachable on 127.0.0.1:${UPSTREAM_PORT}${BENCH_PATH}" >&2
  if [[ -n "${upstream_log_file}" && -s "${upstream_log_file}" ]]; then
    cat "${upstream_log_file}" >&2 || true
  fi
  return 1
}

wait_for_upstream_port_file() {
  local port_file="$1"
  local i port
  for i in $(seq 1 150); do
    if [[ -s "${port_file}" ]]; then
      port="$(tr -d '[:space:]' < "${port_file}")"
      if [[ "${port}" =~ ^[0-9]+$ && "${port}" -ge 1 && "${port}" -le 65535 ]]; then
        UPSTREAM_PORT="${port}"
        return 0
      fi
      echo "[proxy-bench][ERROR] invalid upstream port file content: ${port}" >&2
      return 1
    fi
    if [[ -n "${upstream_pid}" ]] && ! kill -0 "${upstream_pid}" >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done
  echo "[proxy-bench][ERROR] benchmark upstream did not publish a port" >&2
  if [[ -n "${upstream_log_file}" && -s "${upstream_log_file}" ]]; then
    cat "${upstream_log_file}" >&2 || true
  fi
  return 1
}

start_benchmark_upstream() {
  local upstream_bin="${tmp_dir}/benchmark_upstream"
  local upstream_port_file="${tmp_dir}/upstream.port"
  local listen_port="${UPSTREAM_PORT:-0}"

  "${GO_BIN}" build -o "${upstream_bin}" "${ROOT_DIR}/scripts/benchmark_upstream.go"
  upstream_log_file="${tmp_dir}/upstream.log"
  "${upstream_bin}" -addr "127.0.0.1:${listen_port}" -path "${BENCH_PATH}" -port-file "${upstream_port_file}" >"${upstream_log_file}" 2>&1 &
  upstream_pid="$!"
  wait_for_upstream_port_file "${upstream_port_file}"
  wait_for_upstream
}

check_bench_thresholds() {
  local preset="$1"
  local concurrency="$2"
  local fail_rate="$3"
  local rps="$4"

  if [[ -n "${BENCH_MAX_FAIL_RATE_PCT}" ]]; then
    if awk -v v="${fail_rate}" -v m="${BENCH_MAX_FAIL_RATE_PCT}" 'BEGIN {exit (v<=m)?0:1}'; then
      :
    else
      echo "[proxy-bench][WARN] threshold breach preset=${preset} c=${concurrency} fail_rate_pct=${fail_rate} > ${BENCH_MAX_FAIL_RATE_PCT}" >&2
      benchmark_failed=1
    fi
  fi

  if [[ -n "${BENCH_MIN_RPS}" ]]; then
    if awk -v v="${rps}" -v m="${BENCH_MIN_RPS}" 'BEGIN {exit (v>=m)?0:1}'; then
      :
    else
      echo "[proxy-bench][WARN] threshold breach preset=${preset} c=${concurrency} rps=${rps} < ${BENCH_MIN_RPS}" >&2
      benchmark_failed=1
    fi
  fi
}

build_preset_raw() {
  local base_raw="$1"
  local preset="$2"
  local upstream="http://host.docker.internal:${UPSTREAM_PORT}"
  case "${preset}" in
    balanced)
      jq --arg upstream "${upstream}" --arg path "${BENCH_PATH}" --arg access_log_mode "${BENCH_ACCESS_LOG_MODE}" '
        .upstreams = [{"name":"primary","url":$upstream,"weight":1,"enabled":true}]
        | .access_log_mode = $access_log_mode
        | .force_http2 = false
        | .disable_compression = false
        | .buffer_request_body = false
        | .max_response_buffer_bytes = 0
        | .flush_interval_ms = 0
        | .health_check_path = $path
      ' <<<"${base_raw}"
      ;;
    low-latency)
      jq --arg upstream "${upstream}" --arg path "${BENCH_PATH}" --arg access_log_mode "${BENCH_ACCESS_LOG_MODE}" '
        .upstreams = [{"name":"primary","url":$upstream,"weight":1,"enabled":true}]
        | .access_log_mode = $access_log_mode
        | .force_http2 = false
        | .disable_compression = true
        | .buffer_request_body = false
        | .max_response_buffer_bytes = 0
        | .flush_interval_ms = 0
        | .health_check_path = $path
      ' <<<"${base_raw}"
      ;;
    buffered-guard)
      jq --arg upstream "${upstream}" --arg path "${BENCH_PATH}" --arg access_log_mode "${BENCH_ACCESS_LOG_MODE}" '
        .upstreams = [{"name":"primary","url":$upstream,"weight":1,"enabled":true}]
        | .access_log_mode = $access_log_mode
        | .force_http2 = false
        | .disable_compression = false
        | .buffer_request_body = true
        | .max_response_buffer_bytes = 1048576
        | .flush_interval_ms = 0
        | .health_check_path = $path
      ' <<<"${base_raw}"
      ;;
    *)
      echo "[proxy-bench][ERROR] unknown preset: ${preset}" >&2
      return 1
      ;;
  esac
}

run_preset_concurrency() {
  local preset="$1"
  local concurrency="$2"
  local bench_url="${PROXY_BASE_URL}${BENCH_PATH}"
  local out_file="${tmp_dir}/ab_${preset}_c${concurrency}.txt"
  local warmup_file="${tmp_dir}/ab_warmup_${preset}_c${concurrency}.txt"
  local bench_ip
  local warmup_count run_count
  local complete failed non2xx fail_rate avg p95 p99 rps

  bench_ip="198.18.0.${bench_ip_counter}"
  bench_ip_counter=$((bench_ip_counter + 1))
  if [[ "${bench_ip_counter}" -ge 240 ]]; then
    bench_ip_counter=10
  fi

  warmup_count="$(bench_count_for_concurrency "${WARMUP_REQUESTS}" "${concurrency}")"
  run_count="$(bench_count_for_concurrency "${BENCH_REQUESTS}" "${concurrency}")"

  if [[ "${WARMUP_REQUESTS}" -gt 0 ]]; then
    run_ab "${warmup_count}" "${concurrency}" "${bench_url}" "${warmup_file}" "${bench_ip}"
  fi
  run_ab "${run_count}" "${concurrency}" "${bench_url}" "${out_file}" "${bench_ip}"

  complete="$(extract_ab_metric "${out_file}" 's/^Complete requests:[[:space:]]+([0-9]+)$/\1/p')"
  failed="$(extract_ab_metric "${out_file}" 's/^Failed requests:[[:space:]]+([0-9]+)$/\1/p')"
  non2xx="$(extract_ab_metric "${out_file}" 's/^Non-2xx responses:[[:space:]]+([0-9]+)$/\1/p')"
  avg="$(extract_ab_metric "${out_file}" 's/^Time per request:[[:space:]]+([0-9.]+)[[:space:]]+\[ms\][[:space:]]+\(mean\)$/\1/p' '0.0')"
  rps="$(extract_ab_metric "${out_file}" 's/^Requests per second:[[:space:]]+([0-9.]+)[[:space:]]+\[#\/sec\][[:space:]]+\(mean\)$/\1/p' '0.0')"
  p95="$(extract_ab_metric "${out_file}" 's/^[[:space:]]*95%[[:space:]]+([0-9.]+)$/\1/p' '0.0')"
  p99="$(extract_ab_metric "${out_file}" 's/^[[:space:]]*99%[[:space:]]+([0-9.]+)$/\1/p' '0.0')"
  fail_rate="$(awk -v c="${complete}" -v f="${failed}" -v n="${non2xx}" 'BEGIN {if (c>0) printf "%.2f", ((f+n)*100.0)/c; else print "0.00"}')"

  check_bench_thresholds "${preset}" "${concurrency}" "${fail_rate}" "${rps}"
  append_json_row "${preset}" "${concurrency}" "${complete}" "${failed}" "${non2xx}" "${fail_rate}" "${avg}" "${p95}" "${p99}" "${rps}"

  printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
    "${preset}" "${concurrency}" "${complete}" "${failed}" "${non2xx}" "${fail_rate}" "${avg}" "${p95}" "${p99}" "${rps}"
}

run_preset() {
  local preset="$1"
  local preset_raw lvl concurrency
  local levels=()

  preset_raw="$(build_preset_raw "${baseline_raw}" "${preset}")"
  apply_proxy_raw "${preset_raw}"

  IFS=',' read -r -a levels <<<"${BENCH_CONCURRENCY}"
  for lvl in "${levels[@]}"; do
    concurrency="${lvl//[[:space:]]/}"
    run_preset_concurrency "${preset}" "${concurrency}"
  done
}

validate_concurrency_levels "${BENCH_CONCURRENCY}"

init_benchmark_config_files
backup_config_file "${PROXY_HOST_CONFIG_FILE}"
apply_proxy_engine_for_benchmark
backup_config_file "${proxy_rules_host_file}"
if [[ "${BENCH_DISABLE_RATE_LIMIT}" == "1" ]]; then
  backup_config_file "${rate_limit_host_file}"
  disable_rate_limit_file_for_benchmark
fi
if [[ "${BENCH_DISABLE_REQUEST_GUARDS}" == "1" ]]; then
  backup_config_file "${bot_defense_host_file}"
  backup_config_file "${semantic_host_file}"
  backup_config_file "${ip_reputation_host_file}"
  disable_request_guard_files_for_benchmark
fi
if [[ "${BENCH_PROXY_MODE}" == "proxy-only" ]]; then
  backup_config_file "${bypass_host_file}"
  enable_waf_bypass_for_proxy_only_mode
fi

json_rows_file="${tmp_dir}/proxy_benchmark_rows.jsonl"
prepare_profile_artifacts
mkdir -p "$(dirname "${OUTPUT_FILE}")" "$(dirname "${OUTPUT_JSON_FILE}")"
rm -f "${json_rows_file}"

start_benchmark_upstream
if [[ "${BENCH_PROFILE}" == "1" ]]; then
  compose_pprof_addr="${BENCH_PROFILE_ADDR}"
fi

(
  cd "${ROOT_DIR}"
  CORAZA_PORT="${HOST_CORAZA_PORT}" WAF_LISTEN_PORT="${WAF_LISTEN_PORT}" TUKUYOMI_PPROF_ADDR="${compose_pprof_addr}" docker compose up -d --build --force-recreate coraza >/dev/null
)
proxy_api_wait_health 90 1
wait_for_profile_endpoint
assert_public_pprof_not_exposed

snapshot="$(proxy_api_get_snapshot)"
baseline_raw="$(jq -r '.raw // empty' <<<"${snapshot}")"
if [[ -z "${baseline_raw}" ]]; then
  echo "[proxy-bench][ERROR] failed to read baseline proxy config" >&2
  exit 1
fi

if [[ "${BENCH_DISABLE_RATE_LIMIT}" == "1" ]]; then
  override_rate_limit_rules_for_benchmark
fi

generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
if [[ "${BENCH_REQUESTS}" -ge 600 ]]; then
  decision_run_policy="eligible-requests-ge-600"
else
  decision_run_policy="smoke-only-requests-lt-600"
fi
start_cpu_profile_capture
{
  echo "# Proxy Tuning Benchmark"
  echo
  echo "- benchmark_tool: ab"
  echo "- benchmark_mode: ${BENCH_PROXY_MODE}"
  echo "- proxy_engine: ${BENCH_PROXY_ENGINE}"
  echo "- requests_per_case: ${BENCH_REQUESTS}"
  echo "- warmup_requests_per_case: ${WARMUP_REQUESTS}"
  echo "- concurrency_levels: ${BENCH_CONCURRENCY}"
  echo "- benchmark_path: ${BENCH_PATH}"
  echo "- benchmark_timeout_sec: ${BENCH_TIMEOUT_SEC}"
  echo "- disable_rate_limit: ${BENCH_DISABLE_RATE_LIMIT}"
  echo "- disable_request_guards: ${BENCH_DISABLE_REQUEST_GUARDS}"
  echo "- access_log_mode: ${BENCH_ACCESS_LOG_MODE}"
  echo "- client_keepalive: ${BENCH_CLIENT_KEEPALIVE}"
  echo "- upstream_port: ${UPSTREAM_PORT}"
  echo "- profile_enabled: ${BENCH_PROFILE}"
  if [[ "${BENCH_PROFILE}" == "1" ]]; then
    echo "- profile_addr: ${BENCH_PROFILE_ADDR}"
    echo "- profile_seconds: ${BENCH_PROFILE_SECONDS}"
    echo "- profile_cpu: ${profile_cpu_file}"
    echo "- profile_heap: ${profile_heap_file}"
    echo "- profile_allocs: ${profile_allocs_file}"
  fi
  echo "- decision_run_policy: ${decision_run_policy}"
  echo "- host port: ${HOST_CORAZA_PORT}"
  echo "- listen port: ${WAF_LISTEN_PORT}"
  echo "- generated_at: ${generated_at}"
  echo
  echo "| preset | concurrency | complete | failed | non_2xx | fail_rate_pct | avg_latency_ms | p95_latency_ms | p99_latency_ms | rps |"
  echo "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
  run_preset balanced
  run_preset low-latency
  run_preset buffered-guard
} | tee "${OUTPUT_FILE}"
finish_cpu_profile_capture
capture_memory_profiles

concurrency_levels_json="$(jq -Rn --arg csv "${BENCH_CONCURRENCY}" '[($csv | split(",")[] | gsub("\\s+"; "") | select(length > 0) | tonumber)]')"
jq -n \
  --arg benchmark_tool "ab" \
  --arg benchmark_mode "${BENCH_PROXY_MODE}" \
  --arg proxy_engine "${BENCH_PROXY_ENGINE}" \
  --arg requests_per_case "${BENCH_REQUESTS}" \
  --arg warmup_requests_per_case "${WARMUP_REQUESTS}" \
  --argjson concurrency_levels "${concurrency_levels_json}" \
  --arg benchmark_path "${BENCH_PATH}" \
  --arg benchmark_timeout_sec "${BENCH_TIMEOUT_SEC}" \
  --arg disable_rate_limit "${BENCH_DISABLE_RATE_LIMIT}" \
  --arg disable_request_guards "${BENCH_DISABLE_REQUEST_GUARDS}" \
  --arg access_log_mode "${BENCH_ACCESS_LOG_MODE}" \
  --arg client_keepalive "${BENCH_CLIENT_KEEPALIVE}" \
  --arg upstream_port "${UPSTREAM_PORT}" \
  --arg host_port "${HOST_CORAZA_PORT}" \
  --arg listen_port "${WAF_LISTEN_PORT}" \
  --arg profile_enabled "${BENCH_PROFILE}" \
  --arg profile_addr "${BENCH_PROFILE_ADDR}" \
  --arg profile_seconds "${BENCH_PROFILE_SECONDS}" \
  --arg profile_cpu_file "${profile_cpu_file}" \
  --arg profile_heap_file "${profile_heap_file}" \
  --arg profile_allocs_file "${profile_allocs_file}" \
  --arg decision_run_policy "${decision_run_policy}" \
  --arg generated_at "${generated_at}" \
  --arg max_fail_rate_pct "${BENCH_MAX_FAIL_RATE_PCT}" \
  --arg min_rps "${BENCH_MIN_RPS}" \
  --arg failed "${benchmark_failed}" \
  --slurpfile rows "${json_rows_file}" \
  '
    def optnum($value):
      if ($value | length) == 0 then null else ($value | tonumber) end;

    {
      metadata: {
        benchmark_tool: $benchmark_tool,
        benchmark_mode: $benchmark_mode,
        proxy_engine: $proxy_engine,
        requests_per_case: ($requests_per_case | tonumber),
        warmup_requests_per_case: ($warmup_requests_per_case | tonumber),
        concurrency_levels: $concurrency_levels,
        benchmark_path: $benchmark_path,
        benchmark_timeout_sec: ($benchmark_timeout_sec | tonumber),
        disable_rate_limit: ($disable_rate_limit == "1"),
        disable_request_guards: ($disable_request_guards == "1"),
        access_log_mode: $access_log_mode,
        client_keepalive: ($client_keepalive == "1"),
        upstream_port: ($upstream_port | tonumber),
        host_port: ($host_port | tonumber),
        listen_port: ($listen_port | tonumber),
        profile: {
          enabled: ($profile_enabled == "1"),
          pprof_addr: (if $profile_enabled == "1" then $profile_addr else null end),
          seconds: (if $profile_enabled == "1" then ($profile_seconds | tonumber) else null end),
          artifacts: {
            cpu: (if $profile_enabled == "1" then $profile_cpu_file else null end),
            heap: (if $profile_enabled == "1" then $profile_heap_file else null end),
            allocs: (if $profile_enabled == "1" then $profile_allocs_file else null end)
          }
        },
        decision_run_policy: $decision_run_policy,
        generated_at: $generated_at,
        thresholds: {
          max_fail_rate_pct: optnum($max_fail_rate_pct),
          min_rps: optnum($min_rps)
        }
      },
      rows: $rows,
      failed: ($failed == "1")
    }
  ' > "${OUTPUT_JSON_FILE}"

if [[ "${benchmark_failed}" -ne 0 ]]; then
  echo "[proxy-bench][ERROR] benchmark thresholds were breached" >&2
  exit 1
fi

echo "[proxy-bench][OK] benchmark summary saved: ${OUTPUT_FILE}"
echo "[proxy-bench][OK] benchmark json saved: ${OUTPUT_JSON_FILE}"
