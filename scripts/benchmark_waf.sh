#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/proxy_api.sh
source "${SCRIPT_DIR}/lib/proxy_api.sh"

GO_BIN="${GO:-go}"
BENCH_REQUESTS="${BENCH_REQUESTS:-300}"
WARMUP_REQUESTS="${WARMUP_REQUESTS:-50}"
BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-1,10,50}"
BENCH_PATH="${BENCH_PATH:-/bench}"
BENCH_TIMEOUT_SEC="${BENCH_TIMEOUT_SEC:-30}"
BENCH_MAX_FAIL_RATE_PCT="${BENCH_MAX_FAIL_RATE_PCT:-}"
BENCH_MIN_RPS="${BENCH_MIN_RPS:-}"
BENCH_DISABLE_RATE_LIMIT="${BENCH_DISABLE_RATE_LIMIT:-1}"
BENCH_DISABLE_REQUEST_GUARDS="${BENCH_DISABLE_REQUEST_GUARDS:-1}"
WAF_BENCH_SCENARIOS="${WAF_BENCH_SCENARIOS:-allow,block-xss}"
UPSTREAM_PORT="${UPSTREAM_PORT:-}"
OUTPUT_FILE="${OUTPUT_FILE:-data/tmp/reports/proxy/waf-benchmark-summary.md}"
OUTPUT_JSON_FILE="${OUTPUT_JSON_FILE:-data/tmp/reports/proxy/waf-benchmark-summary.json}"
HOST_PUID="${PUID:-$(id -u)}"
HOST_GUID="${GUID:-$(id -g)}"

benchmark_failed=0
bench_ip_counter=40
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

need_cmd() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "[waf-bench][ERROR] missing command: ${name}" >&2
    exit 1
  fi
}

need_cmd docker
need_cmd curl
need_cmd jq
need_cmd ab
need_cmd make
need_cmd "${GO_BIN}"

validate_uint_at_least() {
  local name="$1"
  local value="$2"
  local min="$3"
  if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
    echo "[waf-bench][ERROR] ${name} must be an integer" >&2
    exit 1
  fi
  if [[ "${value}" -lt "${min}" ]]; then
    echo "[waf-bench][ERROR] ${name} must be >= ${min}" >&2
    exit 1
  fi
}

validate_uint_at_least BENCH_REQUESTS "${BENCH_REQUESTS}" 5
validate_uint_at_least WARMUP_REQUESTS "${WARMUP_REQUESTS}" 0
validate_uint_at_least BENCH_TIMEOUT_SEC "${BENCH_TIMEOUT_SEC}" 1

if [[ ! "${BENCH_PATH}" =~ ^/ ]]; then
  echo "[waf-bench][ERROR] BENCH_PATH must start with '/'" >&2
  exit 1
fi

if [[ "${#BENCH_PATH}" -gt 256 || "${BENCH_PATH}" == *".."* || "${BENCH_PATH}" == *"?"* || "${BENCH_PATH}" == *"#"* ]]; then
  echo "[waf-bench][ERROR] BENCH_PATH must be a plain absolute path without '..', query, or fragment" >&2
  exit 1
fi

if [[ "${BENCH_PATH}" == */ ]]; then
  echo "[waf-bench][ERROR] BENCH_PATH must identify a file-like path and must not end with '/'" >&2
  exit 1
fi

if [[ "${BENCH_DISABLE_RATE_LIMIT}" != "0" && "${BENCH_DISABLE_RATE_LIMIT}" != "1" ]]; then
  echo "[waf-bench][ERROR] BENCH_DISABLE_RATE_LIMIT must be 0 or 1" >&2
  exit 1
fi

if [[ "${BENCH_DISABLE_REQUEST_GUARDS}" != "0" && "${BENCH_DISABLE_REQUEST_GUARDS}" != "1" ]]; then
  echo "[waf-bench][ERROR] BENCH_DISABLE_REQUEST_GUARDS must be 0 or 1" >&2
  exit 1
fi

if [[ -n "${UPSTREAM_PORT}" ]] && ! [[ "${UPSTREAM_PORT}" =~ ^[0-9]+$ ]]; then
  echo "[waf-bench][ERROR] UPSTREAM_PORT must be an integer" >&2
  exit 1
fi
if [[ -n "${UPSTREAM_PORT}" && ( "${UPSTREAM_PORT}" -lt 1 || "${UPSTREAM_PORT}" -gt 65535 ) ]]; then
  echo "[waf-bench][ERROR] UPSTREAM_PORT must be between 1 and 65535" >&2
  exit 1
fi

proxy_api_init

tmp_dir="$(mktemp -d)"
upstream_pid=""
baseline_raw=""

cleanup() {
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
    PUID="${HOST_PUID}" GUID="${HOST_GUID}" CORAZA_PORT="${HOST_CORAZA_PORT}" docker compose down --remove-orphans >/dev/null 2>&1 || true
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
}

backup_config_file() {
  local path="$1"
  local name backup

  if [[ -z "${path}" || ! -f "${path}" ]]; then
    return 0
  fi
  name="$(basename "${path}")"
  backup="${tmp_dir}/${name}.backup.${#config_backup_pairs[@]}"
  cp "${path}" "${backup}"
  config_backup_pairs+=("${path}:${backup}")
}

restore_config_file_backups() {
  local pair path backup

  for pair in "${config_backup_pairs[@]}"; do
    path="${pair%%:*}"
    backup="${pair#*:}"
    if [[ -f "${backup}" ]]; then
      cp "${backup}" "${path}"
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
  echo "[waf-bench] rate-limit file temporarily disabled"
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
  echo "[waf-bench] request-security guard files temporarily disabled"
}

append_json_row() {
  local scenario="$1"
  local description="$2"
  local expected_status="$3"
  local probe_status="$4"
  local concurrency="$5"
  local complete="$6"
  local failed="$7"
  local non2xx="$8"
  local unexpected="$9"
  local unexpected_rate="${10}"
  local avg="${11}"
  local p95="${12}"
  local p99="${13}"
  local rps="${14}"

  jq -n \
    --arg scenario "${scenario}" \
    --arg description "${description}" \
    --arg expected_status "${expected_status}" \
    --arg probe_status "${probe_status}" \
    --arg concurrency "${concurrency}" \
    --arg complete "${complete}" \
    --arg failed "${failed}" \
    --arg non2xx "${non2xx}" \
    --arg unexpected "${unexpected}" \
    --arg unexpected_rate "${unexpected_rate}" \
    --arg avg "${avg}" \
    --arg p95 "${p95}" \
    --arg p99 "${p99}" \
    --arg rps "${rps}" \
    '{
      scenario: $scenario,
      description: $description,
      expected_status: ($expected_status | tonumber),
      probe_status: ($probe_status | tonumber),
      concurrency: ($concurrency | tonumber),
      complete: ($complete | tonumber),
      failed: ($failed | tonumber),
      non_2xx: ($non2xx | tonumber),
      unexpected: ($unexpected | tonumber),
      unexpected_rate_pct: ($unexpected_rate | tonumber),
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
  echo "[waf-bench] restoring baseline proxy rules"
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
    echo "[waf-bench][ERROR] missing etag in rate-limit snapshot" >&2
    return 1
  fi

  body="$(jq -n --arg raw "${raw}" '{raw: $raw}')"
  code="$(curl -sS -o "${response_file}" -w "%{http_code}" \
    -H "${PROXY_AUTH_HEADER}" -H "If-Match: ${etag}" -H "Content-Type: application/json" \
    -X PUT --data "${body}" "${PROXY_API_URL}/rate-limit-rules")"
  if [[ "${code}" != "200" ]]; then
    echo "[waf-bench][ERROR] failed to apply rate-limit rules: ${code}" >&2
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
    echo "[waf-bench][WARN] rate-limit raw is empty, skip override" >&2
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
  echo "[waf-bench] rate-limit rules temporarily disabled"
}

restore_rate_limit_rules() {
  if [[ -z "${baseline_rate_limit_raw}" ]]; then
    return 0
  fi
  echo "[waf-bench] restoring baseline rate-limit rules"
  rate_limit_apply_raw "${baseline_rate_limit_raw}"
}

validate_concurrency_levels() {
  local csv="$1"
  local lvl trimmed
  local levels=()

  IFS=',' read -r -a levels <<<"${csv}"
  if [[ "${#levels[@]}" -eq 0 ]]; then
    echo "[waf-bench][ERROR] BENCH_CONCURRENCY is empty" >&2
    return 1
  fi

  for lvl in "${levels[@]}"; do
    trimmed="${lvl//[[:space:]]/}"
    if [[ -z "${trimmed}" ]]; then
      echo "[waf-bench][ERROR] BENCH_CONCURRENCY contains empty value" >&2
      return 1
    fi
    if ! [[ "${trimmed}" =~ ^[0-9]+$ ]]; then
      echo "[waf-bench][ERROR] invalid concurrency value: ${trimmed}" >&2
      return 1
    fi
    if [[ "${trimmed}" -le 0 ]]; then
      echo "[waf-bench][ERROR] concurrency must be > 0: ${trimmed}" >&2
      return 1
    fi
  done
}

validate_scenarios() {
  local csv="$1"
  local item scenario
  local scenarios=()

  IFS=',' read -r -a scenarios <<<"${csv}"
  if [[ "${#scenarios[@]}" -eq 0 ]]; then
    echo "[waf-bench][ERROR] WAF_BENCH_SCENARIOS is empty" >&2
    return 1
  fi

  for item in "${scenarios[@]}"; do
    scenario="${item//[[:space:]]/}"
    case "${scenario}" in
      allow|block-xss)
        ;;
      "")
        echo "[waf-bench][ERROR] WAF_BENCH_SCENARIOS contains empty value" >&2
        return 1
        ;;
      *)
        echo "[waf-bench][ERROR] unknown WAF scenario: ${scenario}" >&2
        return 1
        ;;
    esac
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
  local bench_ip="${5:-198.18.0.40}"

  ab -n "${count}" -c "${concurrency}" -s "${BENCH_TIMEOUT_SEC}" \
    -H "X-Forwarded-For: ${bench_ip}" -H "X-Real-IP: ${bench_ip}" \
    "${url}" > "${output_file}"
}

check_bench_thresholds() {
  local scenario="$1"
  local concurrency="$2"
  local unexpected_rate="$3"
  local rps="$4"

  if [[ -n "${BENCH_MAX_FAIL_RATE_PCT}" ]]; then
    if awk -v v="${unexpected_rate}" -v m="${BENCH_MAX_FAIL_RATE_PCT}" 'BEGIN {exit (v<=m)?0:1}'; then
      :
    else
      echo "[waf-bench][WARN] threshold breach scenario=${scenario} c=${concurrency} unexpected_rate_pct=${unexpected_rate} > ${BENCH_MAX_FAIL_RATE_PCT}" >&2
      benchmark_failed=1
    fi
  fi

  if [[ -n "${BENCH_MIN_RPS}" ]]; then
    if awk -v v="${rps}" -v m="${BENCH_MIN_RPS}" 'BEGIN {exit (v>=m)?0:1}'; then
      :
    else
      echo "[waf-bench][WARN] threshold breach scenario=${scenario} c=${concurrency} rps=${rps} < ${BENCH_MIN_RPS}" >&2
      benchmark_failed=1
    fi
  fi
}

build_benchmark_proxy_raw() {
  local base_raw="$1"
  local upstream="http://host.docker.internal:${UPSTREAM_PORT}"
  jq --arg upstream "${upstream}" --arg path "${BENCH_PATH}" '
    .upstreams = [{"name":"waf-bench-primary","url":$upstream,"weight":1,"enabled":true}]
    | .force_http2 = false
    | .disable_compression = false
    | .buffer_request_body = false
    | .max_response_buffer_bytes = 0
    | .flush_interval_ms = 0
    | .health_check_path = $path
  ' <<<"${base_raw}"
}

scenario_description() {
  case "$1" in
    allow)
      printf "benign request expected to pass WAF"
      ;;
    block-xss)
      printf "encoded XSS query expected to be blocked by CRS"
      ;;
    *)
      return 1
      ;;
  esac
}

scenario_request_path() {
  case "$1" in
    allow)
      printf "%s?q=hello-world" "${BENCH_PATH}"
      ;;
    block-xss)
      printf "%s?q=%%3Cscript%%3Ealert(1)%%3C%%2Fscript%%3E" "${BENCH_PATH}"
      ;;
    *)
      return 1
      ;;
  esac
}

scenario_expected_status() {
  case "$1" in
    allow)
      printf "200"
      ;;
    block-xss)
      printf "403"
      ;;
    *)
      return 1
      ;;
  esac
}

probe_scenario() {
  local url="$1"
  local bench_ip="$2"
  curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Forwarded-For: ${bench_ip}" -H "X-Real-IP: ${bench_ip}" \
    "${url}" || true
}

unexpected_count() {
  local complete="$1"
  local failed="$2"
  local non2xx="$3"
  local expected_status="$4"

  awk -v c="${complete}" -v f="${failed}" -v n="${non2xx}" -v e="${expected_status}" '
    BEGIN {
      if (e >= 200 && e < 300) {
        u = f + n
      } else {
        u = f + (c - n)
      }
      if (u < 0) {
        u = 0
      }
      printf "%d", u
    }
  '
}

run_scenario_concurrency() {
  local scenario="$1"
  local description="$2"
  local expected_status="$3"
  local probe_status="$4"
  local scenario_url="$5"
  local concurrency="$6"
  local out_file="${tmp_dir}/ab_${scenario}_c${concurrency}.txt"
  local warmup_file="${tmp_dir}/ab_warmup_${scenario}_c${concurrency}.txt"
  local bench_ip
  local warmup_count run_count
  local complete failed non2xx unexpected unexpected_rate avg p95 p99 rps

  bench_ip="198.18.0.${bench_ip_counter}"
  bench_ip_counter=$((bench_ip_counter + 1))
  if [[ "${bench_ip_counter}" -ge 240 ]]; then
    bench_ip_counter=40
  fi

  warmup_count="$(bench_count_for_concurrency "${WARMUP_REQUESTS}" "${concurrency}")"
  run_count="$(bench_count_for_concurrency "${BENCH_REQUESTS}" "${concurrency}")"

  if [[ "${WARMUP_REQUESTS}" -gt 0 ]]; then
    run_ab "${warmup_count}" "${concurrency}" "${scenario_url}" "${warmup_file}" "${bench_ip}"
  fi
  run_ab "${run_count}" "${concurrency}" "${scenario_url}" "${out_file}" "${bench_ip}"

  complete="$(extract_ab_metric "${out_file}" 's/^Complete requests:[[:space:]]+([0-9]+)$/\1/p')"
  failed="$(extract_ab_metric "${out_file}" 's/^Failed requests:[[:space:]]+([0-9]+)$/\1/p')"
  non2xx="$(extract_ab_metric "${out_file}" 's/^Non-2xx responses:[[:space:]]+([0-9]+)$/\1/p')"
  avg="$(extract_ab_metric "${out_file}" 's/^Time per request:[[:space:]]+([0-9.]+)[[:space:]]+\[ms\][[:space:]]+\(mean\)$/\1/p' '0.0')"
  rps="$(extract_ab_metric "${out_file}" 's/^Requests per second:[[:space:]]+([0-9.]+)[[:space:]]+\[#\/sec\][[:space:]]+\(mean\)$/\1/p' '0.0')"
  p95="$(extract_ab_metric "${out_file}" 's/^[[:space:]]*95%[[:space:]]+([0-9.]+)$/\1/p' '0.0')"
  p99="$(extract_ab_metric "${out_file}" 's/^[[:space:]]*99%[[:space:]]+([0-9.]+)$/\1/p' '0.0')"
  unexpected="$(unexpected_count "${complete}" "${failed}" "${non2xx}" "${expected_status}")"
  unexpected_rate="$(awk -v c="${complete}" -v u="${unexpected}" 'BEGIN {if (c>0) printf "%.2f", (u*100.0)/c; else print "0.00"}')"

  check_bench_thresholds "${scenario}" "${concurrency}" "${unexpected_rate}" "${rps}"
  append_json_row "${scenario}" "${description}" "${expected_status}" "${probe_status}" "${concurrency}" "${complete}" "${failed}" "${non2xx}" "${unexpected}" "${unexpected_rate}" "${avg}" "${p95}" "${p99}" "${rps}"

  printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
    "${scenario}" "${expected_status}" "${probe_status}" "${concurrency}" "${complete}" "${failed}" "${non2xx}" "${unexpected}" "${unexpected_rate}" "${avg}" "${p95}" "${p99}" "${rps}"
}

run_scenario() {
  local scenario="$1"
  local request_path scenario_url expected_status description probe_status lvl concurrency
  local levels=()

  request_path="$(scenario_request_path "${scenario}")"
  scenario_url="${PROXY_BASE_URL}${request_path}"
  expected_status="$(scenario_expected_status "${scenario}")"
  description="$(scenario_description "${scenario}")"
  probe_status="$(probe_scenario "${scenario_url}" "198.18.0.39")"
  if [[ "${probe_status}" != "${expected_status}" ]]; then
    echo "[waf-bench][ERROR] scenario=${scenario} probe returned ${probe_status}, expected ${expected_status}" >&2
    return 1
  fi

  IFS=',' read -r -a levels <<<"${BENCH_CONCURRENCY}"
  for lvl in "${levels[@]}"; do
    concurrency="${lvl//[[:space:]]/}"
    run_scenario_concurrency "${scenario}" "${description}" "${expected_status}" "${probe_status}" "${scenario_url}" "${concurrency}"
  done
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
  echo "[waf-bench][ERROR] upstream did not become reachable on 127.0.0.1:${UPSTREAM_PORT}${BENCH_PATH}" >&2
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
      echo "[waf-bench][ERROR] invalid upstream port file content: ${port}" >&2
      return 1
    fi
    if [[ -n "${upstream_pid}" ]] && ! kill -0 "${upstream_pid}" >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done
  echo "[waf-bench][ERROR] benchmark upstream did not publish a port" >&2
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

validate_concurrency_levels "${BENCH_CONCURRENCY}"
validate_scenarios "${WAF_BENCH_SCENARIOS}"

init_benchmark_config_files
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

echo "[waf-bench] ensuring DB-backed WAF rule assets"
(cd "${ROOT_DIR}" && make crs-install)

json_rows_file="${tmp_dir}/waf_benchmark_rows.jsonl"
mkdir -p "$(dirname "${OUTPUT_FILE}")" "$(dirname "${OUTPUT_JSON_FILE}")"
rm -f "${json_rows_file}"

start_benchmark_upstream

(
  cd "${ROOT_DIR}"
  PUID="${HOST_PUID}" GUID="${HOST_GUID}" CORAZA_PORT="${HOST_CORAZA_PORT}" WAF_LISTEN_PORT="${WAF_LISTEN_PORT}" docker compose up -d --build --force-recreate coraza >/dev/null
)
proxy_api_wait_health 90 1

snapshot="$(proxy_api_get_snapshot)"
baseline_raw="$(jq -r '.raw // empty' <<<"${snapshot}")"
if [[ -z "${baseline_raw}" ]]; then
  echo "[waf-bench][ERROR] failed to read baseline proxy config" >&2
  exit 1
fi

benchmark_raw="$(build_benchmark_proxy_raw "${baseline_raw}")"
apply_proxy_raw "${benchmark_raw}"

if [[ "${BENCH_DISABLE_RATE_LIMIT}" == "1" ]]; then
  override_rate_limit_rules_for_benchmark
fi

generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
{
  echo "# WAF Benchmark"
  echo
  echo "- benchmark_tool: ab"
  echo "- requests_per_case: ${BENCH_REQUESTS}"
  echo "- warmup_requests_per_case: ${WARMUP_REQUESTS}"
  echo "- concurrency_levels: ${BENCH_CONCURRENCY}"
  echo "- benchmark_path: ${BENCH_PATH}"
  echo "- waf_scenarios: ${WAF_BENCH_SCENARIOS}"
  echo "- benchmark_timeout_sec: ${BENCH_TIMEOUT_SEC}"
  echo "- disable_rate_limit: ${BENCH_DISABLE_RATE_LIMIT}"
  echo "- disable_request_guards: ${BENCH_DISABLE_REQUEST_GUARDS}"
  echo "- upstream_port: ${UPSTREAM_PORT}"
  echo "- host_port: ${HOST_CORAZA_PORT}"
  echo "- listen_port: ${WAF_LISTEN_PORT}"
  echo "- generated_at: ${generated_at}"
  echo
  echo "| scenario | expected_status | probe_status | concurrency | complete | failed | non_2xx | unexpected | unexpected_rate_pct | avg_latency_ms | p95_latency_ms | p99_latency_ms | rps |"
  echo "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
  IFS=',' read -r -a scenarios <<<"${WAF_BENCH_SCENARIOS}"
  for scenario in "${scenarios[@]}"; do
    run_scenario "${scenario//[[:space:]]/}"
  done
} | tee "${OUTPUT_FILE}"

concurrency_levels_json="$(jq -Rn --arg csv "${BENCH_CONCURRENCY}" '[($csv | split(",")[] | gsub("\\s+"; "") | select(length > 0) | tonumber)]')"
scenarios_json="$(jq -Rn --arg csv "${WAF_BENCH_SCENARIOS}" '[($csv | split(",")[] | gsub("\\s+"; "") | select(length > 0))]')"
jq -n \
  --arg benchmark_tool "ab" \
  --arg requests_per_case "${BENCH_REQUESTS}" \
  --arg warmup_requests_per_case "${WARMUP_REQUESTS}" \
  --argjson concurrency_levels "${concurrency_levels_json}" \
  --argjson waf_scenarios "${scenarios_json}" \
  --arg benchmark_path "${BENCH_PATH}" \
  --arg benchmark_timeout_sec "${BENCH_TIMEOUT_SEC}" \
  --arg disable_rate_limit "${BENCH_DISABLE_RATE_LIMIT}" \
  --arg disable_request_guards "${BENCH_DISABLE_REQUEST_GUARDS}" \
  --arg upstream_port "${UPSTREAM_PORT}" \
  --arg host_port "${HOST_CORAZA_PORT}" \
  --arg listen_port "${WAF_LISTEN_PORT}" \
  --arg generated_at "${generated_at}" \
  --arg max_unexpected_rate_pct "${BENCH_MAX_FAIL_RATE_PCT}" \
  --arg min_rps "${BENCH_MIN_RPS}" \
  --arg failed "${benchmark_failed}" \
  --slurpfile rows "${json_rows_file}" \
  '
    def optnum($value):
      if ($value | length) == 0 then null else ($value | tonumber) end;

    {
      metadata: {
        benchmark_tool: $benchmark_tool,
        requests_per_case: ($requests_per_case | tonumber),
        warmup_requests_per_case: ($warmup_requests_per_case | tonumber),
        concurrency_levels: $concurrency_levels,
        waf_scenarios: $waf_scenarios,
        benchmark_path: $benchmark_path,
        benchmark_timeout_sec: ($benchmark_timeout_sec | tonumber),
        disable_rate_limit: ($disable_rate_limit == "1"),
        disable_request_guards: ($disable_request_guards == "1"),
        upstream_port: ($upstream_port | tonumber),
        host_port: ($host_port | tonumber),
        listen_port: ($listen_port | tonumber),
        generated_at: $generated_at,
        thresholds: {
          max_unexpected_rate_pct: optnum($max_unexpected_rate_pct),
          min_rps: optnum($min_rps)
        }
      },
      rows: $rows,
      failed: ($failed == "1")
    }
  ' > "${OUTPUT_JSON_FILE}"

if [[ "${benchmark_failed}" -ne 0 ]]; then
  echo "[waf-bench][ERROR] benchmark thresholds were breached" >&2
  exit 1
fi

echo "[waf-bench][OK] benchmark summary saved: ${OUTPUT_FILE}"
echo "[waf-bench][OK] benchmark json saved: ${OUTPUT_JSON_FILE}"
