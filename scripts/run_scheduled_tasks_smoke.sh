#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SCHEDULED_TASKS_SMOKE_SKIP_BUILD="${SCHEDULED_TASKS_SMOKE_SKIP_BUILD:-0}"
SCHEDULED_TASKS_SMOKE_AUTO_DOWN="${SCHEDULED_TASKS_SMOKE_AUTO_DOWN:-1}"
SCHEDULED_TASKS_SMOKE_WAIT_SECONDS="${SCHEDULED_TASKS_SMOKE_WAIT_SECONDS:-60}"
SCHEDULED_TASKS_SMOKE_COMPOSE_PORT="${SCHEDULED_TASKS_SMOKE_COMPOSE_PORT:-19096}"
SCHEDULED_TASKS_SMOKE_PREVIEW_PORT="${SCHEDULED_TASKS_SMOKE_PREVIEW_PORT:-19097}"

PUID_VALUE="${PUID:-$(id -u)}"
GUID_VALUE="${GUID:-$(id -g)}"
COMPOSE_PROJECT_SUFFIX="$$"

BINARY_ROOT=""
COMPOSE_WORKSPACE=""
PREVIEW_WORKSPACE=""
COMPOSE_PROJECT="tukuyomi-scheduled-tasks-compose-smoke-${COMPOSE_PROJECT_SUFFIX}"
PREVIEW_PROJECT="tukuyomi-scheduled-tasks-preview-smoke-${COMPOSE_PROJECT_SUFFIX}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[scheduled-tasks-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[scheduled-tasks-smoke] $*"
}

fail() {
  echo "[scheduled-tasks-smoke][ERROR] $*" >&2
  exit 1
}

wait_for_http_code() {
  local expected_code="$1"
  local url="$2"
  local code=""
  local i

  for i in $(seq 1 "${SCHEDULED_TASKS_SMOKE_WAIT_SECONDS}"); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "${expected_code}" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

wait_for_task_success() {
  local state_file="$1"
  local task_name="$2"
  local task_log="$3"
  local command_output="$4"
  local i

  for i in $(seq 1 "${SCHEDULED_TASKS_SMOKE_WAIT_SECONDS}"); do
    if [[ -f "${state_file}" ]] && \
      jq -e --arg task "${task_name}" '.tasks[$task].last_result == "success"' "${state_file}" >/dev/null 2>&1 && \
      [[ -f "${task_log}" ]] && [[ -f "${command_output}" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

write_task_config() {
  local path="$1"
  local task_name="$2"
  local command="$3"
  cat >"${path}" <<EOF
{
  "tasks": [
    {
      "name": "${task_name}",
      "enabled": true,
      "schedule": "* * * * *",
      "timezone": "UTC",
      "command": "${command}",
      "timeout_sec": 300
    }
  ]
}
EOF
}

reset_scheduled_task_runtime_dir() {
  local runtime_dir="$1"
  rm -rf "${runtime_dir}"
  mkdir -p "${runtime_dir}"
}

stage_compose_workspace() {
  local workspace="$1"
  install -d -m 755 \
    "${workspace}" \
    "${workspace}/data" \
    "${workspace}/scripts"
  install -m 644 "${ROOT_DIR}/docker-compose.yml" "${workspace}/docker-compose.yml"
  rsync -a "${ROOT_DIR}/coraza/" "${workspace}/coraza/"
  rsync -a "${ROOT_DIR}/data/conf/" "${workspace}/data/conf/"
  rsync -a "${ROOT_DIR}/data/rules/" "${workspace}/data/rules/"
  if [[ -d "${ROOT_DIR}/data/php-fpm" ]]; then
    rsync -a "${ROOT_DIR}/data/php-fpm/" "${workspace}/data/php-fpm/"
  else
    mkdir -p "${workspace}/data/php-fpm"
  fi
  if [[ -d "${ROOT_DIR}/data/vhosts" ]]; then
    rsync -a "${ROOT_DIR}/data/vhosts/" "${workspace}/data/vhosts/"
  else
    mkdir -p "${workspace}/data/vhosts"
  fi
  if [[ -d "${ROOT_DIR}/data/logs" ]]; then
    rsync -a "${ROOT_DIR}/data/logs/" "${workspace}/data/logs/"
  else
    mkdir -p "${workspace}/data/logs"
  fi
  rsync -a "${ROOT_DIR}/scripts/" "${workspace}/scripts/"
  reset_scheduled_task_runtime_dir "${workspace}/data/scheduled-tasks"
}

cleanup() {
  local status="$1"

  if [[ -n "${PREVIEW_WORKSPACE}" && -d "${PREVIEW_WORKSPACE}" ]]; then
    if [[ "${status}" -ne 0 ]]; then
      (
        cd "${PREVIEW_WORKSPACE}"
        COMPOSE_PROJECT_NAME="${PREVIEW_PROJECT}" docker compose logs coraza scheduled-task-runner 2>/dev/null || true
      ) >&2
    fi
    (
      cd "${PREVIEW_WORKSPACE}"
      COMPOSE_PROJECT_NAME="${PREVIEW_PROJECT}" PUID="${PUID_VALUE}" GUID="${GUID_VALUE}" bash ./scripts/ui_preview.sh down >/dev/null 2>&1 || true
    )
  fi

  if [[ -n "${COMPOSE_WORKSPACE}" && -d "${COMPOSE_WORKSPACE}" ]]; then
    if [[ "${status}" -ne 0 ]]; then
      (
        cd "${COMPOSE_WORKSPACE}"
        COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT}" docker compose logs coraza scheduled-task-runner 2>/dev/null || true
      ) >&2
    fi
    (
      cd "${COMPOSE_WORKSPACE}"
      COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT}" PUID="${PUID_VALUE}" GUID="${GUID_VALUE}" docker compose --profile scheduled-tasks down --remove-orphans >/dev/null 2>&1 || true
    )
  fi

  if [[ "${SCHEDULED_TASKS_SMOKE_AUTO_DOWN}" == "1" ]]; then
    [[ -n "${BINARY_ROOT}" ]] && rm -rf "${BINARY_ROOT}" >/dev/null 2>&1 || true
    [[ -n "${COMPOSE_WORKSPACE}" ]] && rm -rf "${COMPOSE_WORKSPACE}" >/dev/null 2>&1 || true
    [[ -n "${PREVIEW_WORKSPACE}" ]] && rm -rf "${PREVIEW_WORKSPACE}" >/dev/null 2>&1 || true
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

if [[ "${SCHEDULED_TASKS_SMOKE_SKIP_BUILD}" != "1" ]]; then
  log "building embedded admin UI and binary"
  (cd "${ROOT_DIR}" && make build)
else
  log "skipping build by request"
fi

if [[ ! -x "${ROOT_DIR}/bin/tukuyomi" ]]; then
  fail "missing built binary: ${ROOT_DIR}/bin/tukuyomi"
fi

run_binary_smoke() {
  local runtime_dir
  local state_file
  local task_log
  local command_output

  BINARY_ROOT="$(mktemp -d "${ROOT_DIR}/.tmp-scheduled-tasks-binary-smoke.XXXXXX")"
  runtime_dir="${BINARY_ROOT}/opt/tukuyomi"
  state_file="${runtime_dir}/data/scheduled-tasks/state.json"
  task_log="${runtime_dir}/data/scheduled-tasks/logs/scheduled-task-binary-smoke.log"
  command_output="${runtime_dir}/logs/scheduled-task-binary-command.log"

  log "staging binary scheduled-task smoke runtime at ${runtime_dir}"
  install -d -m 755 \
    "${runtime_dir}/bin" \
    "${runtime_dir}/conf" \
    "${runtime_dir}/data/scheduled-tasks" \
    "${runtime_dir}/data/php-fpm" \
    "${runtime_dir}/logs"
  install -m 755 "${ROOT_DIR}/bin/tukuyomi" "${runtime_dir}/bin/tukuyomi"
  rsync -a --exclude '*.bak' "${ROOT_DIR}/data/conf/" "${runtime_dir}/conf/"
  if [[ -d "${ROOT_DIR}/data/php-fpm" ]]; then
    rsync -a "${ROOT_DIR}/data/php-fpm/" "${runtime_dir}/data/php-fpm/"
  fi
  write_task_config "${runtime_dir}/conf/scheduled-tasks.json" "scheduled-task-binary-smoke" "date >> logs/scheduled-task-binary-command.log"
  (
    cd "${runtime_dir}"
    WAF_CONFIG_FILE="${runtime_dir}/conf/config.json" ./bin/tukuyomi run-scheduled-tasks
  )
  wait_for_task_success "${state_file}" "scheduled-task-binary-smoke" "${task_log}" "${command_output}" || fail "binary scheduled-task smoke did not produce expected state/log/output"
}

run_compose_smoke() {
  local state_file
  local task_log
  local command_output

  COMPOSE_WORKSPACE="$(mktemp -d "${ROOT_DIR}/.tmp-scheduled-tasks-compose-smoke.XXXXXX")"
  stage_compose_workspace "${COMPOSE_WORKSPACE}"
  state_file="${COMPOSE_WORKSPACE}/data/scheduled-tasks/state.json"
  task_log="${COMPOSE_WORKSPACE}/data/scheduled-tasks/logs/scheduled-task-compose-smoke.log"
  command_output="${COMPOSE_WORKSPACE}/data/logs/scheduled-task-compose-command.log"

  write_task_config "${COMPOSE_WORKSPACE}/data/conf/scheduled-tasks.json" "scheduled-task-compose-smoke" "date >> /app/logs/scheduled-task-compose-command.log"

  log "starting docker scheduled-task sidecar smoke on port ${SCHEDULED_TASKS_SMOKE_COMPOSE_PORT}"
  (
    cd "${COMPOSE_WORKSPACE}"
    COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT}" \
    PUID="${PUID_VALUE}" \
    GUID="${GUID_VALUE}" \
    CORAZA_PORT="${SCHEDULED_TASKS_SMOKE_COMPOSE_PORT}" \
    WAF_LISTEN_PORT="9090" \
    docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner
  )
  wait_for_http_code "200" "http://127.0.0.1:${SCHEDULED_TASKS_SMOKE_COMPOSE_PORT}/healthz" || fail "compose scheduled-task smoke runtime did not become healthy"
  wait_for_task_success "${state_file}" "scheduled-task-compose-smoke" "${task_log}" "${command_output}" || fail "docker scheduled-task sidecar smoke did not produce expected state/log/output"
  (
    cd "${COMPOSE_WORKSPACE}"
    COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT}" PUID="${PUID_VALUE}" GUID="${GUID_VALUE}" docker compose --profile scheduled-tasks down --remove-orphans >/dev/null
  )
}

run_preview_smoke() {
  local state_file
  local task_log
  local command_output

  PREVIEW_WORKSPACE="$(mktemp -d "${ROOT_DIR}/.tmp-scheduled-tasks-preview-smoke.XXXXXX")"
  stage_compose_workspace "${PREVIEW_WORKSPACE}"
  state_file="${PREVIEW_WORKSPACE}/data/scheduled-tasks/state.json"
  task_log="${PREVIEW_WORKSPACE}/data/scheduled-tasks/logs/scheduled-task-preview-smoke.log"
  command_output="${PREVIEW_WORKSPACE}/data/logs/scheduled-task-preview-command.log"

  log "starting ui-preview scheduled-task smoke on port ${SCHEDULED_TASKS_SMOKE_PREVIEW_PORT}"
  (
    cd "${PREVIEW_WORKSPACE}"
    COMPOSE_PROJECT_NAME="${PREVIEW_PROJECT}" \
    PUID="${PUID_VALUE}" \
    GUID="${GUID_VALUE}" \
    CORAZA_PORT="${SCHEDULED_TASKS_SMOKE_PREVIEW_PORT}" \
    bash ./scripts/ui_preview.sh up >/dev/null
  )
  wait_for_http_code "200" "http://127.0.0.1:${SCHEDULED_TASKS_SMOKE_PREVIEW_PORT}/healthz" || fail "ui-preview scheduled-task smoke runtime did not become healthy"

  write_task_config "${PREVIEW_WORKSPACE}/data/conf/scheduled-tasks.ui-preview.json" "scheduled-task-preview-smoke" "date >> /app/logs/scheduled-task-preview-command.log"
  wait_for_task_success "${state_file}" "scheduled-task-preview-smoke" "${task_log}" "${command_output}" || fail "preview scheduled-task smoke did not produce expected state/log/output"
  (
    cd "${PREVIEW_WORKSPACE}"
    COMPOSE_PROJECT_NAME="${PREVIEW_PROJECT}" bash ./scripts/ui_preview.sh down >/dev/null
  )
}

run_binary_smoke
run_compose_smoke
run_preview_smoke

log "OK scheduled tasks smoke passed"
