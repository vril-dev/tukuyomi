#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: run_capacity_baseline.sh <example-name> <front|direct> <scenario>" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORAZA_SRC_DIR="${ROOT_DIR}/coraza/src"
EXAMPLE_NAME="$1"
TOPOLOGY="$2"
SCENARIO="$3"
EXAMPLE_DIR="${ROOT_DIR}/examples/${EXAMPLE_NAME}"
PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
BENCH_DURATION="${BENCH_DURATION:-15s}"
BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-20}"
BENCH_TIMEOUT="${BENCH_TIMEOUT:-5s}"
BENCH_SKIP_SETUP="${BENCH_SKIP_SETUP:-0}"
BENCH_SKIP_STACK_UP="${BENCH_SKIP_STACK_UP:-0}"
BENCH_AUTO_DOWN="${BENCH_AUTO_DOWN:-1}"
BENCH_DISABLE_RATE_LIMIT="${BENCH_DISABLE_RATE_LIMIT:-1}"
BENCH_ADMIN_SIDE_TRAFFIC="${BENCH_ADMIN_SIDE_TRAFFIC:-0}"
BENCH_ADMIN_INTERVAL_SEC="${BENCH_ADMIN_INTERVAL_SEC:-0.5}"
BENCH_OUTPUT_ROOT="${BENCH_OUTPUT_ROOT:-${ROOT_DIR}/artifacts/benchmarks}"
BENCH_RUN_ID="${BENCH_RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
BENCH_BASE_URL="${BENCH_BASE_URL:-}"
BENCH_COMPOSE_PROJECT_NAME="${BENCH_COMPOSE_PROJECT_NAME:-tukuyomi-${EXAMPLE_NAME//[^a-zA-Z0-9]/}-${TOPOLOGY}-bench}"
FRONT_PROXY_TRUSTED_PROXY_CIDRS="${FRONT_PROXY_TRUSTED_PROXY_CIDRS:-127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"

COMPOSE_ENV=()
PENDING_CONF_CLEANUP=()
PENDING_DIR_CLEANUP=()
ADMIN_PID=""
EXAMPLE_CONF_DIR=""
EXAMPLE_LOG_OUTPUT_PATH=""
EXAMPLE_LOG_OUTPUT_PRESENT_BEFORE=0
EXAMPLE_BAK_BASELINE=()

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[benchmark][ERROR] missing command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[benchmark] $*"
}

fail() {
  echo "[benchmark][ERROR] $*" >&2
  exit 1
}

path_in_array() {
  local needle="$1"
  shift || true
  local item
  for item in "$@"; do
    if [[ "${item}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

compose_in_example() {
  (
    cd "${EXAMPLE_DIR}" && \
      env "${COMPOSE_ENV[@]}" COMPOSE_PROJECT_NAME="${BENCH_COMPOSE_PROJECT_NAME}" docker compose "$@"
  )
}

track_optional_conf_cleanup() {
  local path="$1"
  if [[ ! -e "${path}" ]]; then
    PENDING_CONF_CLEANUP+=("${path}")
  fi
}

track_dir_cleanup() {
  local path="$1"
  PENDING_DIR_CLEANUP+=("${path}")
}

snapshot_example_conf_artifacts() {
  local path

  EXAMPLE_CONF_DIR="${EXAMPLE_DIR}/data/conf"
  EXAMPLE_LOG_OUTPUT_PATH="${EXAMPLE_CONF_DIR}/log-output.json"

  if [[ -f "${EXAMPLE_LOG_OUTPUT_PATH}" ]]; then
    EXAMPLE_LOG_OUTPUT_PRESENT_BEFORE=1
  fi

  if [[ -d "${EXAMPLE_CONF_DIR}" ]]; then
    while IFS= read -r -d '' path; do
      EXAMPLE_BAK_BASELINE+=("${path}")
    done < <(find "${EXAMPLE_CONF_DIR}" -maxdepth 1 -type f -name '*.bak' -print0)
  fi
}

cleanup_example_conf_artifacts() {
  local path

  if [[ -n "${EXAMPLE_LOG_OUTPUT_PATH}" && "${EXAMPLE_LOG_OUTPUT_PRESENT_BEFORE}" != "1" ]]; then
    rm -f "${EXAMPLE_LOG_OUTPUT_PATH}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${EXAMPLE_CONF_DIR}" && -d "${EXAMPLE_CONF_DIR}" ]]; then
    while IFS= read -r -d '' path; do
      if ! path_in_array "${path}" "${EXAMPLE_BAK_BASELINE[@]:-}"; then
        rm -f "${path}" >/dev/null 2>&1 || true
      fi
    done < <(find "${EXAMPLE_CONF_DIR}" -maxdepth 1 -type f -name '*.bak' -print0)
  fi
}

read_env_value() {
  local env_file="$1"
  local key="$2"
  local line
  local value

  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" ]] && continue
    [[ "${line}" =~ ^[[:space:]]*# ]] && continue
    if [[ "${line}" != "${key}="* ]]; then
      continue
    fi
    value="${line#*=}"
    value="${value%$'\r'}"
    if [[ "${value}" == \"*\" && "${value}" == *\" ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "${value}" == \'*\' && "${value}" == *\' ]]; then
      value="${value:1:${#value}-2}"
    fi
    printf '%s' "${value}"
    return 0
  done < "${env_file}"

  return 1
}

wait_for_http_200() {
  local url="$1"
  local code=""
  local i

  for i in $(seq 1 "${WAIT_TIMEOUT_SECONDS}"); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "${url}" || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

build_request_shape() {
  REQUEST_PATH=""
  EXPECT_STATUS="200"
  case "${EXAMPLE_NAME}:${SCENARIO}" in
    api-gateway:pass)
      REQUEST_PATH="/v1/health"
      EXPECT_STATUS="200"
      ;;
    api-gateway:block)
      REQUEST_PATH="/v1/whoami?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
      EXPECT_STATUS="403"
      ;;
    nextjs:pass)
      REQUEST_PATH="/api/whoami"
      EXPECT_STATUS="200"
      ;;
    nextjs:block)
      REQUEST_PATH="/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
      EXPECT_STATUS="403"
      ;;
    nextjs:cache)
      REQUEST_PATH="/"
      EXPECT_STATUS="200"
      ;;
    wordpress:pass)
      REQUEST_PATH="/tukuyomi-whoami.php"
      EXPECT_STATUS="200"
      ;;
    wordpress:block)
      REQUEST_PATH="/tukuyomi-whoami.php?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
      EXPECT_STATUS="403"
      ;;
    *)
      fail "unsupported example/scenario: ${EXAMPLE_NAME} ${SCENARIO}"
      ;;
  esac
}

example_services() {
  case "${EXAMPLE_NAME}:${TOPOLOGY}" in
    api-gateway:front) echo "coraza nginx api" ;;
    api-gateway:direct) echo "coraza api" ;;
    nextjs:front) echo "coraza nginx nextjs" ;;
    nextjs:direct) echo "coraza nextjs" ;;
    wordpress:front) echo "coraza nginx wordpress db" ;;
    wordpress:direct) echo "coraza wordpress db" ;;
    *) echo "coraza" ;;
  esac
}

collect_compose_stats() {
  local outfile="$1"
  : > "${outfile}"
  local service
  local cid
  local stats_json

  if [[ "${BENCH_SKIP_STACK_UP}" == "1" ]]; then
    return 0
  fi

  for service in $(example_services); do
    cid="$(compose_in_example ps -q "${service}" 2>/dev/null || true)"
    if [[ -z "${cid}" ]]; then
      continue
    fi
    stats_json="$(docker stats --no-stream --format '{{json .}}' "${cid}" 2>/dev/null || true)"
    if [[ -z "${stats_json}" ]]; then
      continue
    fi
    python3 - "$service" "$cid" "$stats_json" >> "${outfile}" <<'PY'
import json
import sys

service = sys.argv[1]
cid = sys.argv[2]
stats = json.loads(sys.argv[3])
print(json.dumps({"service": service, "container_id": cid, "stats": stats}, separators=(",", ":")))
PY
  done
}

start_admin_side_traffic() {
  if [[ "${BENCH_ADMIN_SIDE_TRAFFIC}" != "1" ]]; then
    return 0
  fi
  if [[ -z "${API_KEY}" ]]; then
    fail "BENCH_ADMIN_SIDE_TRAFFIC=1 requires API key"
  fi
  (
    while true; do
      curl -sS -o /dev/null -H "X-API-Key: ${API_KEY}" "${BASE_URL}${API_BASEPATH}/status" || true
      curl -sS -o /dev/null -H "X-API-Key: ${API_KEY}" "${BASE_URL}${API_BASEPATH}/logs/read?src=waf&tail=10" || true
      sleep "${BENCH_ADMIN_INTERVAL_SEC}"
    done
  ) &
  ADMIN_PID="$!"
}

stop_admin_side_traffic() {
  if [[ -n "${ADMIN_PID}" ]]; then
    kill "${ADMIN_PID}" >/dev/null 2>&1 || true
    wait "${ADMIN_PID}" >/dev/null 2>&1 || true
    ADMIN_PID=""
  fi
}

cleanup() {
  local path
  stop_admin_side_traffic
  if [[ "${BENCH_AUTO_DOWN}" == "1" && "${BENCH_SKIP_STACK_UP}" != "1" ]]; then
    if [[ "${TOPOLOGY}" == "front" ]]; then
      compose_in_example --profile front-proxy down --remove-orphans >/dev/null 2>&1 || true
    else
      compose_in_example down --remove-orphans >/dev/null 2>&1 || true
    fi
  fi
  for path in "${PENDING_CONF_CLEANUP[@]:-}"; do
    rm -f "${path}" >/dev/null 2>&1 || true
  done
  for path in "${PENDING_DIR_CLEANUP[@]:-}"; do
    rm -rf "${path}" >/dev/null 2>&1 || true
  done
  cleanup_example_conf_artifacts
}
trap cleanup EXIT

runtime_path_to_example_host() {
  local runtime_path="$1"
  runtime_path="${runtime_path#./}"
  case "${runtime_path}" in
    logs/*)
      printf '%s/data/%s' "${EXAMPLE_DIR}" "${runtime_path}"
      return 0
      ;;
  esac
  return 1
}

if [[ ! -d "${EXAMPLE_DIR}" ]]; then
  fail "unknown example: ${EXAMPLE_NAME}"
fi
if [[ "${TOPOLOGY}" != "front" && "${TOPOLOGY}" != "direct" ]]; then
  fail "unsupported topology: ${TOPOLOGY}"
fi

need_cmd curl
need_cmd docker
need_cmd go
need_cmd python3

if [[ ! -f "${EXAMPLE_DIR}/.env" ]]; then
  cp "${EXAMPLE_DIR}/.env.example" "${EXAMPLE_DIR}/.env"
  log "copied ${EXAMPLE_NAME}/.env from .env.example"
fi
snapshot_example_conf_artifacts

if [[ "${BENCH_SKIP_SETUP}" != "1" ]]; then
  if [[ ! -d "${EXAMPLE_DIR}/data/rules/crs/rules" || ! -f "${EXAMPLE_DIR}/.env" ]]; then
    (cd "${EXAMPLE_DIR}" && ./setup.sh)
  else
    log "setup already satisfied; skipping ./setup.sh"
  fi
fi

ENV_FILE="${EXAMPLE_DIR}/.env"
track_optional_conf_cleanup "${EXAMPLE_DIR}/data/conf/ip-reputation.conf"
track_optional_conf_cleanup "${EXAMPLE_DIR}/data/conf/notifications.conf"

CORAZA_PORT_VALUE="$(read_env_value "${ENV_FILE}" "CORAZA_PORT" || true)"
NGINX_PORT_VALUE="$(read_env_value "${ENV_FILE}" "NGINX_PORT" || true)"
WAF_API_BASEPATH_VALUE="$(read_env_value "${ENV_FILE}" "WAF_API_BASEPATH" || true)"
WAF_API_KEY_PRIMARY_VALUE="$(read_env_value "${ENV_FILE}" "WAF_API_KEY_PRIMARY" || true)"
WAF_RATE_LIMIT_FILE_VALUE="$(read_env_value "${ENV_FILE}" "WAF_RATE_LIMIT_FILE" || true)"

API_BASEPATH="${WAF_API_BASEPATH_VALUE:-/tukuyomi-api}"
API_KEY="${WAF_API_KEY_PRIMARY_VALUE:-}"

if [[ "${BENCH_DISABLE_RATE_LIMIT}" == "1" && "${BENCH_SKIP_STACK_UP}" != "1" ]]; then
  BENCH_RATE_LIMIT_OVERRIDE_PATH="${EXAMPLE_DIR}/data/conf/rate-limit.benchmark-disabled.conf"
  track_optional_conf_cleanup "${BENCH_RATE_LIMIT_OVERRIDE_PATH}"
  cat > "${BENCH_RATE_LIMIT_OVERRIDE_PATH}" <<'EOF'
{
  "enabled": false,
  "allowlist_ips": [],
  "allowlist_countries": [],
  "default_policy": {
    "enabled": false,
    "limit": 1,
    "window_seconds": 60,
    "burst": 0,
    "key_by": "ip",
    "action": {
      "status": 429,
      "retry_after_seconds": 60
    }
  },
  "rules": []
}
EOF
  COMPOSE_ENV+=("WAF_RATE_LIMIT_FILE=conf/$(basename "${BENCH_RATE_LIMIT_OVERRIDE_PATH}")")
  log "rate limit disabled for baseline capture via $(basename "${BENCH_RATE_LIMIT_OVERRIDE_PATH}")"
elif [[ -n "${WAF_RATE_LIMIT_FILE_VALUE}" ]]; then
  COMPOSE_ENV+=("WAF_RATE_LIMIT_FILE=${WAF_RATE_LIMIT_FILE_VALUE}")
fi

if [[ -z "${BENCH_BASE_URL}" ]]; then
  case "${TOPOLOGY}" in
    front)
      BASE_URL="http://127.0.0.1:${NGINX_PORT_VALUE:-18080}"
      ;;
    direct)
      BASE_URL="http://127.0.0.1:${CORAZA_PORT_VALUE:-19090}"
      ;;
  esac
else
  BASE_URL="${BENCH_BASE_URL}"
fi

if [[ "${TOPOLOGY}" == "front" ]]; then
  COMPOSE_ENV+=("WAF_TRUSTED_PROXY_CIDRS=${FRONT_PROXY_TRUSTED_PROXY_CIDRS}")
  COMPOSE_ENV+=("WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true")
fi
if [[ "${TOPOLOGY}" == "direct" && "${SCENARIO}" == "cache" ]]; then
  BENCH_RESPONSE_CACHE_MODE_VALUE="${BENCH_RESPONSE_CACHE_MODE:-memory}"
  COMPOSE_ENV+=("WAF_RESPONSE_CACHE_MODE=${BENCH_RESPONSE_CACHE_MODE_VALUE}")
  if [[ "${BENCH_RESPONSE_CACHE_MODE_VALUE}" == "disk" ]]; then
    BENCH_RESPONSE_CACHE_DIR_VALUE="${BENCH_RESPONSE_CACHE_DIR:-logs/coraza/response-cache-benchmark}"
    COMPOSE_ENV+=("WAF_RESPONSE_CACHE_DIR=${BENCH_RESPONSE_CACHE_DIR_VALUE}")
    if BENCH_RESPONSE_CACHE_HOST_DIR="$(runtime_path_to_example_host "${BENCH_RESPONSE_CACHE_DIR_VALUE}" 2>/dev/null)"; then
      rm -rf "${BENCH_RESPONSE_CACHE_HOST_DIR}" >/dev/null 2>&1 || true
      mkdir -p "$(dirname "${BENCH_RESPONSE_CACHE_HOST_DIR}")"
      track_dir_cleanup "${BENCH_RESPONSE_CACHE_HOST_DIR}"
    fi
  fi
fi

build_request_shape
TARGET_URL="${BASE_URL}${REQUEST_PATH}"

if [[ "${BENCH_SKIP_STACK_UP}" != "1" ]]; then
  if [[ "${TOPOLOGY}" == "front" ]]; then
    compose_in_example --profile front-proxy down --remove-orphans >/dev/null 2>&1 || true
  else
    compose_in_example down --remove-orphans >/dev/null 2>&1 || true
  fi
  log "starting ${EXAMPLE_NAME} stack (${TOPOLOGY})"
  if [[ "${TOPOLOGY}" == "front" ]]; then
    compose_in_example --profile front-proxy up -d --build
  else
    compose_in_example up -d --build
  fi
fi

log "waiting for health endpoint via ${BASE_URL}/healthz"
if ! wait_for_http_200 "${BASE_URL}/healthz"; then
  if [[ "${BENCH_SKIP_STACK_UP}" != "1" ]]; then
    compose_in_example ps -a >&2 || true
    compose_in_example logs --no-color >&2 || true
  fi
  fail "health endpoint did not become ready in time"
fi

log "warming up ${TARGET_URL}"
for _ in $(seq 1 5); do
  curl -sS -o /dev/null -H "Host: ${PROTECTED_HOST}" "${TARGET_URL}" || true
done

OUTPUT_DIR="${BENCH_OUTPUT_ROOT}/${BENCH_RUN_ID}"
mkdir -p "${OUTPUT_DIR}"
REPORT_STEM="${EXAMPLE_NAME}-${TOPOLOGY}-${SCENARIO}"
if [[ "${BENCH_ADMIN_SIDE_TRAFFIC}" == "1" ]]; then
  REPORT_STEM="${REPORT_STEM}-admin-side"
fi
REPORT_PATH="${OUTPUT_DIR}/${REPORT_STEM}.json"
BENCH_RAW_PATH="${OUTPUT_DIR}/${REPORT_STEM}.bench.json"
STATS_BEFORE_PATH="${OUTPUT_DIR}/${REPORT_STEM}.stats-before.ndjson"
STATS_AFTER_PATH="${OUTPUT_DIR}/${REPORT_STEM}.stats-after.ndjson"

collect_compose_stats "${STATS_BEFORE_PATH}"
start_admin_side_traffic

log "running benchmark ${EXAMPLE_NAME}/${TOPOLOGY}/${SCENARIO} for ${BENCH_DURATION} at c=${BENCH_CONCURRENCY}"
(cd "${CORAZA_SRC_DIR}" && \
  go run ./cmd/httpbench \
    -url "${TARGET_URL}" \
    -method GET \
    -duration "${BENCH_DURATION}" \
    -concurrency "${BENCH_CONCURRENCY}" \
    -timeout "${BENCH_TIMEOUT}" \
    -expect-status "${EXPECT_STATUS}" \
    -H "Host: ${PROTECTED_HOST}" > "${BENCH_RAW_PATH}")

stop_admin_side_traffic
collect_compose_stats "${STATS_AFTER_PATH}"

python3 - "${BENCH_RAW_PATH}" "${STATS_BEFORE_PATH}" "${STATS_AFTER_PATH}" "${REPORT_PATH}" <<'PY'
import json
import pathlib
import sys
from datetime import UTC, datetime

bench = json.loads(pathlib.Path(sys.argv[1]).read_text())

def load_ndjson(path):
    p = pathlib.Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out

report = {
    "generated_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
    "benchmark": bench,
    "docker_stats_before": load_ndjson(sys.argv[2]),
    "docker_stats_after": load_ndjson(sys.argv[3]),
}
pathlib.Path(sys.argv[4]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY

python3 - "${REPORT_PATH}" "$EXAMPLE_NAME" "$TOPOLOGY" "$SCENARIO" "$BENCH_ADMIN_SIDE_TRAFFIC" "$PROTECTED_HOST" "$BASE_URL" "$REQUEST_PATH" "$EXPECT_STATUS" "$BENCH_DURATION" "$BENCH_CONCURRENCY" "${BENCH_RESPONSE_CACHE_MODE_VALUE:-off}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text())
payload.update(
    {
        "example": sys.argv[2],
        "topology": sys.argv[3],
        "scenario": sys.argv[4],
        "admin_side_traffic": sys.argv[5] == "1",
        "protected_host": sys.argv[6],
        "base_url": sys.argv[7],
        "request_path": sys.argv[8],
        "expected_status": int(sys.argv[9]),
        "requested_duration": sys.argv[10],
        "requested_concurrency": int(sys.argv[11]),
        "response_cache_mode": sys.argv[12],
    }
)
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY

python3 - "${REPORT_PATH}" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text())
bench = report["benchmark"]
lat = bench["latencies"]
print(f"[benchmark] report: {sys.argv[1]}")
print(
    f"[benchmark] rps={bench['requests_per_sec']:.2f} "
    f"error_rate={bench['error_rate']:.4f} "
    f"p50={lat['p50_ms']:.3f}ms p95={lat['p95_ms']:.3f}ms p99={lat['p99_ms']:.3f}ms"
)
PY
