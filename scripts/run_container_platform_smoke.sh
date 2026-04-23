#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CONTAINER_PLATFORM_SMOKE_SKIP_BUILD="${CONTAINER_PLATFORM_SMOKE_SKIP_BUILD:-0}"
CONTAINER_PLATFORM_SMOKE_WAIT_SECONDS="${CONTAINER_PLATFORM_SMOKE_WAIT_SECONDS:-60}"
CONTAINER_PLATFORM_SMOKE_READ_ONLY_PORT="${CONTAINER_PLATFORM_SMOKE_READ_ONLY_PORT:-19098}"
CONTAINER_PLATFORM_SMOKE_API_KEY="${CONTAINER_PLATFORM_SMOKE_API_KEY:-container-platform-smoke-admin-key}"
CONTAINER_PLATFORM_SMOKE_SESSION_SECRET="${CONTAINER_PLATFORM_SMOKE_SESSION_SECRET:-container-platform-smoke-session-secret}"
CONTAINER_PLATFORM_SMOKE_AUTO_DOWN="${CONTAINER_PLATFORM_SMOKE_AUTO_DOWN:-1}"

RUNTIME_ROOT=""
RUNTIME_DIR=""
SERVER_PID=""
SERVER_LOG=""

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[container-platform-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[container-platform-smoke] $*"
}

fail() {
  echo "[container-platform-smoke][ERROR] $*" >&2
  exit 1
}

wait_for_http_code() {
  local expected_code="$1"
  local url="$2"
  local code=""
  local i

  for i in $(seq 1 "${CONTAINER_PLATFORM_SMOKE_WAIT_SECONDS}"); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "${expected_code}" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

cleanup() {
  local status="$1"

  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi

  if [[ "${status}" -ne 0 && -n "${SERVER_LOG}" && -f "${SERVER_LOG}" ]]; then
    echo "[container-platform-smoke][ERROR] captured read-only runtime log:" >&2
    sed -n '1,240p' "${SERVER_LOG}" >&2 || true
  fi

  if [[ "${CONTAINER_PLATFORM_SMOKE_AUTO_DOWN}" == "1" && -n "${RUNTIME_ROOT}" ]]; then
    rm -rf "${RUNTIME_ROOT}" >/dev/null 2>&1 || true
  fi
}
trap 'cleanup "$?"' EXIT

need_cmd curl
need_cmd docker
need_cmd jq
need_cmd make
need_cmd python3
need_cmd rsync
need_cmd install

if [[ "${CONTAINER_PLATFORM_SMOKE_SKIP_BUILD}" != "1" ]]; then
  log "building embedded admin UI and binary"
  (
    cd "${ROOT_DIR}"
    make build
  )
else
  log "skipping build by request"
fi

if [[ ! -x "${ROOT_DIR}/bin/tukuyomi" ]]; then
  fail "missing built binary: ${ROOT_DIR}/bin/tukuyomi"
fi

run_official_single_instance_smoke() {
  log "running sample single-instance container deployment smoke"
  (
    cd "${ROOT_DIR}"
    ./scripts/run_container_deployment_smoke.sh
  )

  log "running official scheduled-task single-instance smoke"
  (
    cd "${ROOT_DIR}"
    SCHEDULED_TASKS_SMOKE_SKIP_BUILD=1 ./scripts/run_scheduled_tasks_smoke.sh
  )
}

stage_read_only_runtime() {
  local stage_root=""
  RUNTIME_ROOT="$(mktemp -d "${ROOT_DIR}/.tmp-container-platform-read-only.XXXXXX")"
  RUNTIME_DIR="${RUNTIME_ROOT}/opt/tukuyomi"
  SERVER_LOG="${RUNTIME_DIR}/logs/waf/container-platform-read-only.log"

  log "staging read-only runtime at ${RUNTIME_DIR}"
  install -d -m 755 \
    "${RUNTIME_DIR}/bin" \
    "${RUNTIME_DIR}/conf" \
    "${RUNTIME_DIR}/db" \
    "${RUNTIME_DIR}/data/scheduled-tasks" \
    "${RUNTIME_DIR}/audit" \
    "${RUNTIME_DIR}/cache/response" \
    "${RUNTIME_DIR}/logs/waf" \
    "${RUNTIME_DIR}/logs/proxy"
  install -m 755 "${ROOT_DIR}/bin/tukuyomi" "${RUNTIME_DIR}/bin/tukuyomi"
  rsync -a --exclude '*.bak' "${ROOT_DIR}/data/conf/" "${RUNTIME_DIR}/conf/"
  if [[ -d "${ROOT_DIR}/data/scheduled-tasks" ]]; then
    rsync -a "${ROOT_DIR}/data/scheduled-tasks/" "${RUNTIME_DIR}/data/scheduled-tasks/"
  fi
  touch "${RUNTIME_DIR}/conf/crs-disabled.conf"

  jq \
    --arg listen_addr ":${CONTAINER_PLATFORM_SMOKE_READ_ONLY_PORT}" \
    --arg api_key "${CONTAINER_PLATFORM_SMOKE_API_KEY}" \
    --arg session_secret "${CONTAINER_PLATFORM_SMOKE_SESSION_SECRET}" \
    '.server.listen_addr = $listen_addr
     | .admin.api_key_primary = $api_key
     | .admin.session_secret = $session_secret
     | .admin.api_auth_disable = false
     | .admin.read_only = true' \
    "${RUNTIME_DIR}/conf/config.json" > "${RUNTIME_DIR}/conf/config.json.tmp"
  mv "${RUNTIME_DIR}/conf/config.json.tmp" "${RUNTIME_DIR}/conf/config.json"

  stage_root="$(mktemp -d "${RUNTIME_DIR}/.tmp-waf-import.XXXXXX")"
  (
    cd "${RUNTIME_DIR}"
    DEST_DIR="${stage_root}/rules/crs" "${ROOT_DIR}/scripts/install_crs.sh"
    WAF_CONFIG_FILE="conf/config.json" ./bin/tukuyomi db-migrate
    WAF_RULE_ASSET_FS_ROOT="${stage_root}" WAF_CONFIG_FILE="conf/config.json" ./bin/tukuyomi db-import-waf-rule-assets
  )
  rm -rf "${stage_root}"
}

curl_json() {
  local method="$1"
  local url="$2"
  local output="$3"
  local body="${4:-}"
  shift 4 || true
  local extra_args=("$@")

  if [[ -n "${body}" ]]; then
    curl -sS -X "${method}" \
      -H "X-API-Key: ${CONTAINER_PLATFORM_SMOKE_API_KEY}" \
      -H "Content-Type: application/json" \
      "${extra_args[@]}" \
      --data "${body}" \
      -o "${output}" \
      -w "%{http_code}" \
      "${url}"
  else
    curl -sS -X "${method}" \
      -H "X-API-Key: ${CONTAINER_PLATFORM_SMOKE_API_KEY}" \
      "${extra_args[@]}" \
      -o "${output}" \
      -w "%{http_code}" \
      "${url}"
  fi
}

run_read_only_prerequisite_smoke() {
  local status_json
  local tasks_json
  local validate_json
  local mutate_json
  local proxy_mutate_json
  local payload
  local code

  stage_read_only_runtime

  log "starting read-only admin runtime on :${CONTAINER_PLATFORM_SMOKE_READ_ONLY_PORT}"
  (
    cd "${RUNTIME_DIR}"
    WAF_CONFIG_FILE="conf/config.json" ./bin/tukuyomi >"${SERVER_LOG}" 2>&1
  ) &
  SERVER_PID="$!"

  if ! wait_for_http_code "200" "http://127.0.0.1:${CONTAINER_PLATFORM_SMOKE_READ_ONLY_PORT}/healthz"; then
    fail "read-only runtime did not become healthy in time"
  fi

  status_json="$(mktemp "${ROOT_DIR}/.tmp-container-platform-status.XXXXXX.json")"
  tasks_json="$(mktemp "${ROOT_DIR}/.tmp-container-platform-tasks.XXXXXX.json")"
  validate_json="$(mktemp "${ROOT_DIR}/.tmp-container-platform-validate.XXXXXX.json")"
  mutate_json="$(mktemp "${ROOT_DIR}/.tmp-container-platform-mutate.XXXXXX.json")"
  proxy_mutate_json="$(mktemp "${ROOT_DIR}/.tmp-container-platform-proxy-mutate.XXXXXX.json")"
  payload="$(jq -cn --arg raw '{"tasks":[]}' '{raw: $raw}')"

  code="$(curl_json "GET" "http://127.0.0.1:${CONTAINER_PLATFORM_SMOKE_READ_ONLY_PORT}/tukuyomi-api/status" "${status_json}" "")"
  [[ "${code}" == "200" ]] || fail "expected /status to succeed, got ${code}"
  jq -e '.admin_read_only == true' "${status_json}" >/dev/null || fail "/status did not expose admin_read_only=true"

  code="$(curl_json "GET" "http://127.0.0.1:${CONTAINER_PLATFORM_SMOKE_READ_ONLY_PORT}/tukuyomi-api/scheduled-tasks" "${tasks_json}" "")"
  [[ "${code}" == "200" ]] || fail "expected /scheduled-tasks GET to succeed, got ${code}"
  jq -e '.tasks.tasks | type == "array"' "${tasks_json}" >/dev/null || fail "/scheduled-tasks GET did not return task array"

  code="$(curl_json "POST" "http://127.0.0.1:${CONTAINER_PLATFORM_SMOKE_READ_ONLY_PORT}/tukuyomi-api/scheduled-tasks/validate" "${validate_json}" "${payload}")"
  [[ "${code}" == "200" ]] || fail "expected /scheduled-tasks/validate to succeed in read-only mode, got ${code}"

  code="$(curl_json "PUT" "http://127.0.0.1:${CONTAINER_PLATFORM_SMOKE_READ_ONLY_PORT}/tukuyomi-api/scheduled-tasks" "${mutate_json}" "${payload}")"
  [[ "${code}" == "403" ]] || fail "expected /scheduled-tasks PUT to be rejected in read-only mode, got ${code}"
  jq -e '.read_only == true' "${mutate_json}" >/dev/null || fail "read-only mutation response did not include read_only=true"
  jq -e '.error == "admin is read-only in this deployment; apply changes via rollout"' "${mutate_json}" >/dev/null \
    || fail "read-only mutation response did not expose the expected error message"

  code="$(curl_json "PUT" "http://127.0.0.1:${CONTAINER_PLATFORM_SMOKE_READ_ONLY_PORT}/tukuyomi-api/proxy-rules" "${proxy_mutate_json}" '{"raw":"{}"}')"
  [[ "${code}" == "403" ]] || fail "expected /proxy-rules PUT to be rejected in read-only mode, got ${code}"
  jq -e '.read_only == true' "${proxy_mutate_json}" >/dev/null || fail "proxy-rules mutation response did not include read_only=true"

  rm -f "${status_json}" "${tasks_json}" "${validate_json}" "${mutate_json}" "${proxy_mutate_json}"
}

check_platform_artifacts() {
  log "checking single-instance and replicated platform sample artifacts"
  jq empty "${ROOT_DIR}/docs/build/ecs-single-instance.task-definition.example.json" >/dev/null
  jq empty "${ROOT_DIR}/docs/build/ecs-single-instance.service.example.json" >/dev/null
  jq empty "${ROOT_DIR}/docs/build/ecs-replicated-frontend-scheduler.task-definition.example.json" >/dev/null
  jq empty "${ROOT_DIR}/docs/build/ecs-replicated-frontend-scheduler.service.example.json" >/dev/null

  python3 - <<'PY' \
    "${ROOT_DIR}/docs/build/kubernetes-single-instance.example.yaml" \
    "${ROOT_DIR}/docs/build/azure-container-apps-single-instance.example.yaml" \
    "${ROOT_DIR}/docs/build/kubernetes-replicated-frontend-scheduler.example.yaml" \
    "${ROOT_DIR}/docs/build/azure-container-apps-scheduler-singleton.example.yaml"
import sys
import yaml

for path in sys.argv[1:]:
    with open(path, "r", encoding="utf-8") as handle:
        docs = list(yaml.safe_load_all(handle))
    if not docs:
        raise SystemExit(f"empty yaml document: {path}")
PY
}

check_operator_disclosure() {
  log "checking operator-visible support-boundary disclosure"
  rg -n 'Tier 1: Mutable single-instance' "${ROOT_DIR}/docs/build/container-deployment.md" >/dev/null
  rg -n 'admin\.read_only=true' \
    "${ROOT_DIR}/docs/build/container-deployment.md" \
    "${ROOT_DIR}/docs/build/container-deployment.ja.md" \
    "${ROOT_DIR}/docs/operations/php-scheduled-tasks.md" \
    "${ROOT_DIR}/docs/operations/php-scheduled-tasks.ja.md" >/dev/null
  rg -n 'distributed mutable' \
    "${ROOT_DIR}/docs/build/container-deployment.md" \
    "${ROOT_DIR}/docs/build/container-deployment.ja.md" >/dev/null
  rg -n 'single-instance sidecar|single-instance mutable topology' \
    "${ROOT_DIR}/docs/operations/php-scheduled-tasks.md" \
    "${ROOT_DIR}/docs/operations/php-scheduled-tasks.ja.md" >/dev/null
  rg -n 'dedicated singleton scheduler|dedicated scheduler role' \
    "${ROOT_DIR}/docs/build/container-deployment.md" \
    "${ROOT_DIR}/docs/build/container-deployment.ja.md" \
    "${ROOT_DIR}/docs/operations/php-scheduled-tasks.md" \
    "${ROOT_DIR}/docs/operations/php-scheduled-tasks.ja.md" >/dev/null
  rg -n 'Admin Read-Only|This deployment is admin read-only' \
    "${ROOT_DIR}/web/tukuyomi-admin/src/components/Layout.tsx" >/dev/null
}

run_official_single_instance_smoke
run_read_only_prerequisite_smoke
check_platform_artifacts
check_operator_disclosure

log "OK container platform smoke passed"
