#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SCHEDULED_TASKS_SMOKE_SKIP_BUILD="${SCHEDULED_TASKS_SMOKE_SKIP_BUILD:-0}"
SCHEDULED_TASKS_SMOKE_AUTO_DOWN="${SCHEDULED_TASKS_SMOKE_AUTO_DOWN:-1}"
SCHEDULED_TASKS_SMOKE_WAIT_SECONDS="${SCHEDULED_TASKS_SMOKE_WAIT_SECONDS:-60}"
SCHEDULED_TASKS_SMOKE_COMPOSE_PORT="${SCHEDULED_TASKS_SMOKE_COMPOSE_PORT:-19096}"
SCHEDULED_TASKS_SMOKE_PREVIEW_PORT="${SCHEDULED_TASKS_SMOKE_PREVIEW_PORT:-19097}"
SCHEDULED_TASKS_SMOKE_ADMIN_USERNAME="${SCHEDULED_TASKS_SMOKE_ADMIN_USERNAME:-admin}"
SCHEDULED_TASKS_SMOKE_ADMIN_PASSWORD="${SCHEDULED_TASKS_SMOKE_ADMIN_PASSWORD:-scheduled-tasks-smoke-admin-password}"

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

resolve_db_path() {
  local config_path="$1"
  local base_dir="$2"
  local preview_mode="${3:-0}"
  python3 - "$config_path" "$base_dir" "$preview_mode" <<'PY'
import json
import pathlib
import sys

config_path = pathlib.Path(sys.argv[1])
base_dir = pathlib.Path(sys.argv[2])
preview_mode = sys.argv[3] == "1"

with config_path.open("r", encoding="utf-8") as fh:
    payload = json.load(fh)

storage = payload.get("storage")
db_path = ""
if isinstance(storage, dict):
    raw = storage.get("db_path")
    if raw is not None:
        db_path = str(raw).strip()
if not db_path:
    db_path = "db/tukuyomi.db"

pure = pathlib.PurePosixPath(db_path)
if preview_mode:
    parent = pathlib.PurePosixPath(*pure.parts[:-1]) if len(pure.parts) > 1 else pathlib.PurePosixPath(".")
    pure = pathlib.PurePosixPath(parent, "tukuyomi-ui-preview.db")

if pure.is_absolute():
    target = pathlib.Path(str(pure))
else:
    target = base_dir / pathlib.Path(*pure.parts)
print(target.resolve(strict=False))
PY
}

resolve_container_db_path() {
  local config_path="$1"
  python3 - "$config_path" <<'PY'
import json
import pathlib
import sys

config_path = pathlib.Path(sys.argv[1])
with config_path.open("r", encoding="utf-8") as fh:
    payload = json.load(fh)
storage = payload.get("storage")
db_path = ""
if isinstance(storage, dict):
    raw = storage.get("db_path")
    if raw is not None:
        db_path = str(raw).strip()
if not db_path:
    db_path = "db/tukuyomi.db"
print(pathlib.PurePosixPath("data", db_path).as_posix())
PY
}

db_has_task_success() {
  local db_path="$1"
  local task_name="$2"
  python3 - "$db_path" "$task_name" <<'PY'
import pathlib
import sqlite3
import sys

db_path = pathlib.Path(sys.argv[1])
task_name = sys.argv[2]
if not db_path.exists():
    raise SystemExit(1)

conn = sqlite3.connect(str(db_path))
try:
    row = conn.execute(
        "SELECT last_result FROM scheduled_task_runtime_state WHERE task_name = ?",
        (task_name,),
    ).fetchone()
finally:
    conn.close()

raise SystemExit(0 if row and row[0] == "success" else 1)
PY
}

wait_for_task_success() {
  local db_path="$1"
  local task_name="$2"
  local task_log="$3"
  local i

  for i in $(seq 1 "${SCHEDULED_TASKS_SMOKE_WAIT_SECONDS}"); do
    if db_has_task_success "${db_path}" "${task_name}" && \
      [[ -s "${task_log}" ]]; then
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

write_minimal_runtime_seeds() {
  local conf_dir="$1"
  local php_dir="$2"
  local task_name="$3"
  local command="$4"

  mkdir -p "${conf_dir}" "${php_dir}"
  cat >"${conf_dir}/proxy.json" <<'EOF'
{}
EOF
  cat >"${conf_dir}/sites.json" <<'EOF'
{
  "sites": []
}
EOF
  cat >"${php_dir}/inventory.json" <<'EOF'
{}
EOF
  cat >"${php_dir}/vhosts.json" <<'EOF'
{
  "vhosts": []
}
EOF
  write_task_config "${conf_dir}/scheduled-tasks.json" "${task_name}" "${command}"
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
    "${workspace}/bin" \
    "${workspace}/data" \
    "${workspace}/scripts"
  install -m 755 "${ROOT_DIR}/bin/tukuyomi" "${workspace}/bin/tukuyomi"
  install -m 644 "${ROOT_DIR}/docker-compose.yml" "${workspace}/docker-compose.yml"
  rsync -a "${ROOT_DIR}/coraza/" "${workspace}/coraza/"
  rsync -a "${ROOT_DIR}/data/conf/" "${workspace}/data/conf/"
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
  rsync -a "${ROOT_DIR}/scripts/" "${workspace}/scripts/"
  reset_scheduled_task_runtime_dir "${workspace}/data/scheduled-tasks"
}

put_task_config_via_preview_api() {
  local port="$1"
  local task_name="$2"
  local command="$3"
  local base_url="http://127.0.0.1:${port}/tukuyomi-api"
  local cookie_jar
  local csrf_token
  local login_json
  local login_payload
  local get_json
  local put_body
  local put_json
  local etag
  local raw
  local code

  cookie_jar="$(mktemp)"
  login_json="$(mktemp)"
  get_json="$(mktemp)"
  put_body="$(mktemp)"
  put_json="$(mktemp)"

  login_payload="$(jq -n --arg username "${SCHEDULED_TASKS_SMOKE_ADMIN_USERNAME}" --arg password "${SCHEDULED_TASKS_SMOKE_ADMIN_PASSWORD}" '{username: $username, password: $password}')"
  code="$(curl -sS -o "${login_json}" -w "%{http_code}" \
    -c "${cookie_jar}" -b "${cookie_jar}" \
    -H "Content-Type: application/json" \
    -X POST --data "${login_payload}" \
    "${base_url}/auth/login")"
  if [[ "${code}" != "200" ]]; then
    cat "${login_json}" >&2 || true
    rm -f "${cookie_jar}" "${login_json}" "${get_json}" "${put_body}" "${put_json}"
    fail "preview admin login failed with status ${code}"
  fi
  csrf_token="$(
    awk 'NF >= 7 && $6 == "tukuyomi_admin_csrf" { token = $7 } END { if (token != "") print token }' "${cookie_jar}"
  )"
  [[ -n "${csrf_token}" ]] || fail "preview admin login did not issue csrf cookie"

  code="$(curl -sS -o "${get_json}" -w "%{http_code}" -b "${cookie_jar}" -c "${cookie_jar}" "${base_url}/scheduled-tasks")"
  [[ "${code}" == "200" ]] || fail "preview scheduled-tasks GET failed with status ${code}"
  etag="$(jq -r '.etag // empty' "${get_json}")"
  [[ -n "${etag}" ]] || fail "preview scheduled-tasks GET did not return an etag"

  write_task_config "${put_body}" "${task_name}" "${command}"
  raw="$(cat "${put_body}")"
  jq -n --arg raw "${raw}" '{raw: $raw}' > "${put_json}"
  code="$(
    curl -sS -o "${get_json}" -w "%{http_code}" \
      -X PUT \
      -b "${cookie_jar}" -c "${cookie_jar}" \
      -H "Content-Type: application/json" \
      -H "X-CSRF-Token: ${csrf_token}" \
      -H "If-Match: ${etag}" \
      --data-binary "@${put_json}" \
      "${base_url}/scheduled-tasks"
  )"
  if [[ "${code}" != "200" ]]; then
    cat "${get_json}" >&2
    fail "preview scheduled-tasks PUT failed with status ${code}"
  fi
  rm -f "${cookie_jar}" "${login_json}" "${get_json}" "${put_body}" "${put_json}"
}

seed_runtime_db_from_files() {
  local data_dir="$1"
  local binary_path="$2"
  local stage_root=""

  mkdir -p "${data_dir}/tmp"
  stage_root="$(mktemp -d "${data_dir}/tmp/waf-import.XXXXXX")"

  (
    cd "${data_dir}"
    "${ROOT_DIR}/scripts/stage_waf_rule_assets.sh" "${stage_root}"
    WAF_CONFIG_FILE="conf/config.json" "${binary_path}" db-migrate
    WAF_RULE_ASSET_FS_ROOT="${stage_root}" WAF_CONFIG_FILE="conf/config.json" "${binary_path}" db-import-waf-rule-assets
    WAF_CONFIG_FILE="conf/config.json" "${binary_path}" db-import
  )
  rm -rf "${stage_root}"
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
  local db_path
  local task_log

  BINARY_ROOT="$(mktemp -d "${ROOT_DIR}/.tmp-scheduled-tasks-binary-smoke.XXXXXX")"
  runtime_dir="${BINARY_ROOT}/opt/tukuyomi"
  db_path="$(resolve_db_path "${ROOT_DIR}/data/conf/config.json" "${runtime_dir}" 0)"
  task_log="${runtime_dir}/data/scheduled-tasks/logs/scheduled-task-binary-smoke.log"

  log "staging binary scheduled-task smoke runtime at ${runtime_dir}"
  install -d -m 755 \
    "${runtime_dir}/bin" \
    "${runtime_dir}/conf" \
    "${runtime_dir}/data/scheduled-tasks" \
    "${runtime_dir}/data/php-fpm"
  install -m 755 "${ROOT_DIR}/bin/tukuyomi" "${runtime_dir}/bin/tukuyomi"
  rsync -a --exclude '*.bak' "${ROOT_DIR}/data/conf/" "${runtime_dir}/conf/"
  if [[ -d "${ROOT_DIR}/data/php-fpm" ]]; then
    rsync -a "${ROOT_DIR}/data/php-fpm/" "${runtime_dir}/data/php-fpm/"
  fi
  write_minimal_runtime_seeds "${runtime_dir}/conf" "${runtime_dir}/data/php-fpm" "scheduled-task-binary-smoke" "date"
  seed_runtime_db_from_files "${runtime_dir}" "./bin/tukuyomi"
  (
    cd "${runtime_dir}"
    WAF_CONFIG_FILE="${runtime_dir}/conf/config.json" ./bin/tukuyomi run-scheduled-tasks
  )
  wait_for_task_success "${db_path}" "scheduled-task-binary-smoke" "${task_log}" || fail "binary scheduled-task smoke did not produce expected state/log/output"
}

run_compose_smoke() {
  local db_path
  local container_db_path
  local task_log

  COMPOSE_WORKSPACE="$(mktemp -d "${ROOT_DIR}/.tmp-scheduled-tasks-compose-smoke.XXXXXX")"
  stage_compose_workspace "${COMPOSE_WORKSPACE}"
  db_path="$(resolve_db_path "${COMPOSE_WORKSPACE}/data/conf/config.json" "${COMPOSE_WORKSPACE}/data" 0)"
  container_db_path="$(resolve_container_db_path "${COMPOSE_WORKSPACE}/data/conf/config.json")"
  task_log="${COMPOSE_WORKSPACE}/data/scheduled-tasks/logs/scheduled-task-compose-smoke.log"

  write_minimal_runtime_seeds "${COMPOSE_WORKSPACE}/data/conf" "${COMPOSE_WORKSPACE}/data/php-fpm" "scheduled-task-compose-smoke" "date"
  seed_runtime_db_from_files "${COMPOSE_WORKSPACE}/data" "../bin/tukuyomi"

  log "starting docker scheduled-task sidecar smoke on port ${SCHEDULED_TASKS_SMOKE_COMPOSE_PORT}"
  (
    cd "${COMPOSE_WORKSPACE}"
    COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT}" \
    PUID="${PUID_VALUE}" \
    GUID="${GUID_VALUE}" \
    CORAZA_PORT="${SCHEDULED_TASKS_SMOKE_COMPOSE_PORT}" \
    WAF_LISTEN_PORT="9090" \
    WAF_STORAGE_DB_PATH="${container_db_path}" \
    TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME="${SCHEDULED_TASKS_SMOKE_ADMIN_USERNAME}" \
    TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD="${SCHEDULED_TASKS_SMOKE_ADMIN_PASSWORD}" \
    docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner
  )
  wait_for_http_code "200" "http://127.0.0.1:${SCHEDULED_TASKS_SMOKE_COMPOSE_PORT}/healthz" || fail "compose scheduled-task smoke runtime did not become healthy"
  wait_for_task_success "${db_path}" "scheduled-task-compose-smoke" "${task_log}" || fail "docker scheduled-task sidecar smoke did not produce expected state/log/output"
  (
    cd "${COMPOSE_WORKSPACE}"
    COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT}" PUID="${PUID_VALUE}" GUID="${GUID_VALUE}" docker compose --profile scheduled-tasks down --remove-orphans >/dev/null
  )
}

run_preview_smoke() {
  local db_path
  local task_log

  PREVIEW_WORKSPACE="$(mktemp -d "${ROOT_DIR}/.tmp-scheduled-tasks-preview-smoke.XXXXXX")"
  stage_compose_workspace "${PREVIEW_WORKSPACE}"
  db_path="$(resolve_db_path "${PREVIEW_WORKSPACE}/data/conf/config.json" "${PREVIEW_WORKSPACE}/data" 1)"
  task_log="${PREVIEW_WORKSPACE}/data/scheduled-tasks/logs/scheduled-task-preview-smoke.log"

  log "starting ui-preview scheduled-task smoke on port ${SCHEDULED_TASKS_SMOKE_PREVIEW_PORT}"
  (
    cd "${PREVIEW_WORKSPACE}"
    COMPOSE_PROJECT_NAME="${PREVIEW_PROJECT}" \
    PUID="${PUID_VALUE}" \
    GUID="${GUID_VALUE}" \
    UI_PREVIEW_PUBLIC_ADDR=":${SCHEDULED_TASKS_SMOKE_PREVIEW_PORT}" \
    TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME="${SCHEDULED_TASKS_SMOKE_ADMIN_USERNAME}" \
    TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD="${SCHEDULED_TASKS_SMOKE_ADMIN_PASSWORD}" \
    bash ./scripts/ui_preview.sh up >/dev/null
  )
  wait_for_http_code "200" "http://127.0.0.1:${SCHEDULED_TASKS_SMOKE_PREVIEW_PORT}/healthz" || fail "ui-preview scheduled-task smoke runtime did not become healthy"

  put_task_config_via_preview_api "${SCHEDULED_TASKS_SMOKE_PREVIEW_PORT}" "scheduled-task-preview-smoke" "date"
  wait_for_task_success "${db_path}" "scheduled-task-preview-smoke" "${task_log}" || fail "preview scheduled-task smoke did not produce expected state/log/output"
  (
    cd "${PREVIEW_WORKSPACE}"
    COMPOSE_PROJECT_NAME="${PREVIEW_PROJECT}" bash ./scripts/ui_preview.sh down >/dev/null
  )
}

run_binary_smoke
run_compose_smoke
run_preview_smoke

log "OK scheduled tasks smoke passed"
