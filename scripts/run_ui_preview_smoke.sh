#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

UI_PREVIEW_SMOKE_SKIP_BUILD="${UI_PREVIEW_SMOKE_SKIP_BUILD:-0}"
UI_PREVIEW_SMOKE_AUTO_DOWN="${UI_PREVIEW_SMOKE_AUTO_DOWN:-1}"
UI_PREVIEW_SMOKE_WAIT_SECONDS="${UI_PREVIEW_SMOKE_WAIT_SECONDS:-60}"
UI_PREVIEW_SMOKE_SINGLE_PORT="${UI_PREVIEW_SMOKE_SINGLE_PORT:-19108}"
UI_PREVIEW_SMOKE_PUBLIC_PORT="${UI_PREVIEW_SMOKE_PUBLIC_PORT:-19109}"
UI_PREVIEW_SMOKE_ADMIN_PORT="${UI_PREVIEW_SMOKE_ADMIN_PORT:-19110}"
UI_PREVIEW_SMOKE_PROJECT="tukuyomi-ui-preview-smoke-$$"
UI_PREVIEW_SQLITE_DB_REL="logs/coraza/tukuyomi-ui-preview.db"

PUID_VALUE="${PUID:-$(id -u)}"
GUID_VALUE="${GUID:-$(id -g)}"
WORKSPACE=""

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[ui-preview-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[ui-preview-smoke] $*"
}

fail() {
  echo "[ui-preview-smoke][ERROR] $*" >&2
  exit 1
}

wait_for_http_code() {
  local expected_code="$1"
  local url="$2"
  local code=""
  local i

  for i in $(seq 1 "${UI_PREVIEW_SMOKE_WAIT_SECONDS}"); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "${expected_code}" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

preview_up() {
  local persist="${1:-0}"
  (
    cd "${WORKSPACE}"
    COMPOSE_PROJECT_NAME="${UI_PREVIEW_SMOKE_PROJECT}" \
    PUID="${PUID_VALUE}" \
    GUID="${GUID_VALUE}" \
    UI_PREVIEW_PERSIST="${persist}" \
    bash ./scripts/ui_preview.sh up
  )
}

preview_down() {
  local persist="${1:-0}"
  (
    cd "${WORKSPACE}"
    COMPOSE_PROJECT_NAME="${UI_PREVIEW_SMOKE_PROJECT}" \
    PUID="${PUID_VALUE}" \
    GUID="${GUID_VALUE}" \
    UI_PREVIEW_PERSIST="${persist}" \
    bash ./scripts/ui_preview.sh down >/dev/null 2>&1 || true
  )
}

write_base_config() {
  local public_addr="$1"
  local admin_addr="$2"
  python3 - "${WORKSPACE}/data/conf/config.json" "${public_addr}" "${admin_addr}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
public_addr = sys.argv[2]
admin_addr = sys.argv[3]
cfg = json.loads(path.read_text(encoding="utf-8"))
cfg.setdefault("server", {})["listen_addr"] = public_addr
cfg.setdefault("admin", {})["listen_addr"] = admin_addr
path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
PY
}

write_preview_config() {
  local public_addr="$1"
  local admin_addr="$2"
  python3 - "${WORKSPACE}/data/conf/config.json" "${WORKSPACE}/data/conf/config.ui-preview.json" "${public_addr}" "${admin_addr}" <<'PY'
import json
import pathlib
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
public_addr = sys.argv[3]
admin_addr = sys.argv[4]
cfg = json.loads(src.read_text(encoding="utf-8"))
cfg.setdefault("server", {})["listen_addr"] = public_addr
cfg.setdefault("admin", {})["listen_addr"] = admin_addr
paths = cfg.setdefault("paths", {})
paths["proxy_config_file"] = "conf/proxy.ui-preview.json"
paths["scheduled_task_config_file"] = "conf/scheduled-tasks.ui-preview.json"
paths["php_runtime_inventory_file"] = "data/php-fpm/inventory.ui-preview.json"
paths["vhost_config_file"] = "data/php-fpm/vhosts.ui-preview.json"
storage = cfg.setdefault("storage", {})
storage["db_driver"] = "sqlite"
storage["db_dsn"] = ""
storage["db_path"] = "logs/coraza/tukuyomi-ui-preview.db"
dst.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
PY
}

write_preview_scheduled_tasks() {
  local task_name="$1"
  python3 - "${WORKSPACE}/data/conf/scheduled-tasks.ui-preview.json" "${task_name}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
task_name = sys.argv[2]
payload = {
    "tasks": [
        {
            "name": task_name,
            "enabled": True,
            "schedule": "* * * * *",
            "timezone": "UTC",
            "command": "date >> /app/logs/ui-preview-smoke-command.log",
            "timeout_sec": 300,
        }
    ]
}
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
}

assert_task_count() {
  local path="$1"
  local expected="$2"
  local actual

  actual="$(jq '.tasks | length' "${path}")"
  if [[ "${actual}" != "${expected}" ]]; then
    fail "expected ${path} to contain ${expected} tasks, got ${actual}"
  fi
}

assert_preview_db_config() {
  local path="${WORKSPACE}/data/conf/config.ui-preview.json"
  local driver
  local db_path

  driver="$(jq -r '.storage.db_driver // ""' "${path}")"
  db_path="$(jq -r '.storage.db_path // ""' "${path}")"
  if [[ "${driver}" != "sqlite" ]]; then
    fail "preview db_driver=${driver} want sqlite"
  fi
  if [[ "${db_path}" != "${UI_PREVIEW_SQLITE_DB_REL}" ]]; then
    fail "preview db_path=${db_path} want ${UI_PREVIEW_SQLITE_DB_REL}"
  fi
}

write_stale_preview_db() {
  local db_path="${WORKSPACE}/data/${UI_PREVIEW_SQLITE_DB_REL}"

  mkdir -p "$(dirname "${db_path}")"
  printf 'not a sqlite database\n' >"${db_path}"
  printf 'stale wal\n' >"${db_path}-wal"
  printf 'stale shm\n' >"${db_path}-shm"
}

poison_preview_db_config() {
  python3 - "${WORKSPACE}/data/conf/config.ui-preview.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
cfg = json.loads(path.read_text(encoding="utf-8"))
storage = cfg.setdefault("storage", {})
storage["db_driver"] = "mysql"
storage["db_dsn"] = "should-not-survive-preview-normalization"
storage["db_path"] = "logs/coraza/stale-shared.db"
path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
PY
}

assert_preview_db_removed() {
  local db_path="${WORKSPACE}/data/${UI_PREVIEW_SQLITE_DB_REL}"

  [[ ! -f "${db_path}" ]] || fail "preview DB should be removed: ${db_path}"
  [[ ! -f "${db_path}-wal" ]] || fail "preview DB WAL should be removed: ${db_path}-wal"
  [[ ! -f "${db_path}-shm" ]] || fail "preview DB SHM should be removed: ${db_path}-shm"
}

stage_workspace() {
  install -d -m 755 \
    "${WORKSPACE}" \
    "${WORKSPACE}/data" \
    "${WORKSPACE}/scripts"
  install -m 644 "${ROOT_DIR}/docker-compose.yml" "${WORKSPACE}/docker-compose.yml"
  rsync -a "${ROOT_DIR}/coraza/" "${WORKSPACE}/coraza/"
  rsync -a "${ROOT_DIR}/data/conf/" "${WORKSPACE}/data/conf/"
  rsync -a "${ROOT_DIR}/data/rules/" "${WORKSPACE}/data/rules/"
  rsync -a "${ROOT_DIR}/scripts/" "${WORKSPACE}/scripts/"
  if [[ -d "${ROOT_DIR}/data/php-fpm" ]]; then
    rsync -a "${ROOT_DIR}/data/php-fpm/" "${WORKSPACE}/data/php-fpm/"
  else
    install -d -m 755 "${WORKSPACE}/data/php-fpm"
  fi
  if [[ -d "${ROOT_DIR}/data/vhosts" ]]; then
    rsync -a "${ROOT_DIR}/data/vhosts/" "${WORKSPACE}/data/vhosts/"
  else
    install -d -m 755 "${WORKSPACE}/data/vhosts"
  fi
  if [[ -d "${ROOT_DIR}/data/logs" ]]; then
    rsync -a "${ROOT_DIR}/data/logs/" "${WORKSPACE}/data/logs/"
  else
    install -d -m 755 "${WORKSPACE}/data/logs"
  fi
  install -d -m 755 "${WORKSPACE}/data/scheduled-tasks"
}

cleanup() {
  local status="$1"

  if [[ -n "${WORKSPACE}" && -d "${WORKSPACE}" ]]; then
    if [[ "${status}" -ne 0 ]]; then
      (
        cd "${WORKSPACE}"
        COMPOSE_PROJECT_NAME="${UI_PREVIEW_SMOKE_PROJECT}" docker compose logs coraza scheduled-task-runner 2>/dev/null || true
      ) >&2
    fi
    preview_down 1
    preview_down 0
  fi

  if [[ "${UI_PREVIEW_SMOKE_AUTO_DOWN}" == "1" && -n "${WORKSPACE}" ]]; then
    rm -rf "${WORKSPACE}" >/dev/null 2>&1 || true
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

if [[ "${UI_PREVIEW_SMOKE_SKIP_BUILD}" != "1" ]]; then
  log "building embedded admin UI"
  (cd "${ROOT_DIR}" && make ui-build-sync)
else
  log "skipping build by request"
fi

WORKSPACE="$(mktemp -d "${ROOT_DIR}/.tmp-ui-preview-smoke.XXXXXX")"
stage_workspace

log "verifying default reset/remove behavior without UI_PREVIEW_PERSIST"
write_base_config ":${UI_PREVIEW_SMOKE_SINGLE_PORT}" ""
write_preview_scheduled_tasks "ui-preview-reset-smoke"
write_stale_preview_db
preview_up 0 >/dev/null
wait_for_http_code "200" "http://127.0.0.1:${UI_PREVIEW_SMOKE_SINGLE_PORT}/healthz" || fail "single-listener ui-preview did not become healthy"
assert_preview_db_config
assert_task_count "${WORKSPACE}/data/conf/scheduled-tasks.ui-preview.json" "0"
preview_down 0
[[ ! -f "${WORKSPACE}/data/conf/config.ui-preview.json" ]] || fail "config.ui-preview.json should be removed without UI_PREVIEW_PERSIST"
[[ ! -f "${WORKSPACE}/data/conf/scheduled-tasks.ui-preview.json" ]] || fail "scheduled-tasks.ui-preview.json should be removed without UI_PREVIEW_PERSIST"
assert_preview_db_removed

log "verifying UI_PREVIEW_PERSIST=1 with split public/admin ports"
write_preview_config ":${UI_PREVIEW_SMOKE_PUBLIC_PORT}" ":${UI_PREVIEW_SMOKE_ADMIN_PORT}"
poison_preview_db_config
cat >"${WORKSPACE}/data/conf/proxy.ui-preview.json" <<'EOF'
{}
EOF
write_preview_scheduled_tasks "ui-preview-persist-smoke"
cat >"${WORKSPACE}/data/php-fpm/inventory.ui-preview.json" <<'EOF'
{}
EOF
cat >"${WORKSPACE}/data/php-fpm/vhosts.ui-preview.json" <<'EOF'
{
  "vhosts": []
}
EOF
preview_up 1 >/dev/null
assert_preview_db_config
wait_for_http_code "200" "http://127.0.0.1:${UI_PREVIEW_SMOKE_PUBLIC_PORT}/healthz" || fail "split public listener did not become healthy"
wait_for_http_code "200" "http://127.0.0.1:${UI_PREVIEW_SMOKE_ADMIN_PORT}/healthz" || fail "split admin listener did not become healthy"
[[ "$(curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:${UI_PREVIEW_SMOKE_PUBLIC_PORT}/tukuyomi-ui" || true)" == "404" ]] || fail "public preview listener should not serve admin UI path in split mode"
[[ "$(curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:${UI_PREVIEW_SMOKE_ADMIN_PORT}/tukuyomi-ui" || true)" == "200" ]] || fail "admin preview listener should serve admin UI path in split mode"
preview_down 1
[[ -f "${WORKSPACE}/data/conf/config.ui-preview.json" ]] || fail "config.ui-preview.json should persist with UI_PREVIEW_PERSIST=1"
[[ -f "${WORKSPACE}/data/conf/scheduled-tasks.ui-preview.json" ]] || fail "scheduled-tasks.ui-preview.json should persist with UI_PREVIEW_PERSIST=1"
assert_task_count "${WORKSPACE}/data/conf/scheduled-tasks.ui-preview.json" "1"

log "verifying split preview can come back up from preserved files"
preview_up 1 >/dev/null
wait_for_http_code "200" "http://127.0.0.1:${UI_PREVIEW_SMOKE_PUBLIC_PORT}/healthz" || fail "preserved split public listener did not come back healthy"
wait_for_http_code "200" "http://127.0.0.1:${UI_PREVIEW_SMOKE_ADMIN_PORT}/healthz" || fail "preserved split admin listener did not come back healthy"
preview_down 1

log "verifying loopback listener bind is rejected with a clear message"
write_preview_config "localhost:${UI_PREVIEW_SMOKE_PUBLIC_PORT}" ":${UI_PREVIEW_SMOKE_ADMIN_PORT}"
set +e
loopback_output="$(
  cd "${WORKSPACE}" && \
  COMPOSE_PROJECT_NAME="${UI_PREVIEW_SMOKE_PROJECT}" \
  PUID="${PUID_VALUE}" \
  GUID="${GUID_VALUE}" \
  UI_PREVIEW_PERSIST="1" \
  bash ./scripts/ui_preview.sh up 2>&1
)"
loopback_status="$?"
set -e
if [[ "${loopback_status}" -eq 0 ]]; then
  fail "loopback listener preview startup should fail"
fi
if [[ "${loopback_output}" != *"uses loopback host"* ]]; then
  echo "${loopback_output}" >&2
  fail "loopback listener rejection message should mention loopback host"
fi

log "OK ui-preview smoke passed"
