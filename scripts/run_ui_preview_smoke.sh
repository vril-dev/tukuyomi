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

preview_db_rel_path() {
  python3 - "${WORKSPACE}" <<'PY'
import json
import pathlib
import sys

workspace = pathlib.Path(sys.argv[1]).resolve()
config_path = workspace / "data" / "conf" / "config.json"
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
if db_path.startswith("/"):
    raise SystemExit(f"preview storage.db_path must be relative: {db_path}")
parts = pathlib.PurePosixPath(db_path).parts
if any(part in ("", ".", "..") for part in parts):
    raise SystemExit(f"preview storage.db_path contains unsafe path segment: {db_path}")
parent = pathlib.PurePosixPath(*parts[:-1]) if len(parts) > 1 else pathlib.PurePosixPath(".")
print(pathlib.PurePosixPath(parent, "tukuyomi-ui-preview.db").as_posix())
PY
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
  local public_addr="${2:-}"
  local admin_addr="${3:-}"
  (
    cd "${WORKSPACE}"
    COMPOSE_PROJECT_NAME="${UI_PREVIEW_SMOKE_PROJECT}" \
    PUID="${PUID_VALUE}" \
    GUID="${GUID_VALUE}" \
    UI_PREVIEW_PERSIST="${persist}" \
    UI_PREVIEW_PUBLIC_ADDR="${public_addr}" \
    UI_PREVIEW_ADMIN_ADDR="${admin_addr}" \
    bash ./scripts/ui_preview.sh up
  )
}

preview_down() {
  local persist="${1:-0}"
  local public_addr="${2:-}"
  local admin_addr="${3:-}"
  (
    cd "${WORKSPACE}"
    COMPOSE_PROJECT_NAME="${UI_PREVIEW_SMOKE_PROJECT}" \
    PUID="${PUID_VALUE}" \
    GUID="${GUID_VALUE}" \
    UI_PREVIEW_PERSIST="${persist}" \
    UI_PREVIEW_PUBLIC_ADDR="${public_addr}" \
    UI_PREVIEW_ADMIN_ADDR="${admin_addr}" \
    bash ./scripts/ui_preview.sh down >/dev/null 2>&1 || true
  )
}

write_minimal_config() {
  cat >"${WORKSPACE}/data/conf/config.json" <<EOF
{
  "storage": {
    "db_driver": "sqlite",
    "db_path": "db/tukuyomi.db",
    "db_dsn": "",
    "db_retention_days": 30,
    "db_sync_interval_sec": 0
  }
}
EOF
}

write_stale_preview_db() {
  local db_path="${WORKSPACE}/data/$(preview_db_rel_path)"

  mkdir -p "$(dirname "${db_path}")"
  printf 'not a sqlite database\n' >"${db_path}"
  printf 'stale wal\n' >"${db_path}-wal"
  printf 'stale shm\n' >"${db_path}-shm"
}

assert_no_preview_seed_files() {
  local paths=(
    "${WORKSPACE}/data/conf/config.ui-preview.json"
    "${WORKSPACE}/data/conf/proxy.ui-preview.json"
    "${WORKSPACE}/data/conf/scheduled-tasks.ui-preview.json"
    "${WORKSPACE}/data/php-fpm/inventory.ui-preview.json"
    "${WORKSPACE}/data/php-fpm/vhosts.ui-preview.json"
  )
  local path
  for path in "${paths[@]}"; do
    [[ ! -f "${path}" ]] || fail "preview seed file should not exist: ${path}"
  done
}

assert_preview_db_removed() {
  local db_path="${WORKSPACE}/data/$(preview_db_rel_path)"

  [[ ! -f "${db_path}" ]] || fail "preview DB should be removed: ${db_path}"
  [[ ! -f "${db_path}-wal" ]] || fail "preview DB WAL should be removed: ${db_path}-wal"
  [[ ! -f "${db_path}-shm" ]] || fail "preview DB SHM should be removed: ${db_path}-shm"
}

assert_preview_db_exists() {
  local db_path="${WORKSPACE}/data/$(preview_db_rel_path)"
  [[ -f "${db_path}" ]] || fail "preview DB should exist: ${db_path}"
}

remove_preview_db() {
  local db_path="${WORKSPACE}/data/$(preview_db_rel_path)"
  rm -f "${db_path}" "${db_path}-wal" "${db_path}-shm"
}

stage_workspace() {
  install -d -m 755 \
	    "${WORKSPACE}" \
	    "${WORKSPACE}/bin" \
	    "${WORKSPACE}/data/persistent" \
	    "${WORKSPACE}/data/cache/response" \
	    "${WORKSPACE}/data" \
    "${WORKSPACE}/scripts"
  install -m 755 "${ROOT_DIR}/bin/tukuyomi" "${WORKSPACE}/bin/tukuyomi"
  install -m 644 "${ROOT_DIR}/docker-compose.yml" "${WORKSPACE}/docker-compose.yml"
  rsync -a "${ROOT_DIR}/server/" "${WORKSPACE}/server/"
  rsync -a "${ROOT_DIR}/data/conf/" "${WORKSPACE}/data/conf/"
  rsync -a "${ROOT_DIR}/seeds/" "${WORKSPACE}/seeds/"
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
    preview_down 1 || true
    preview_down 0 || true
  fi

  if [[ "${UI_PREVIEW_SMOKE_AUTO_DOWN}" == "1" && -n "${WORKSPACE}" ]]; then
    rm -rf "${WORKSPACE}" >/dev/null 2>&1 || true
  fi
}
trap 'cleanup "$?"' EXIT

need_cmd curl
need_cmd docker
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
write_minimal_config

log "verifying default reset/remove behavior without UI_PREVIEW_PERSIST"
write_stale_preview_db
preview_up 0 ":${UI_PREVIEW_SMOKE_SINGLE_PORT}" "" >/dev/null
wait_for_http_code "200" "http://127.0.0.1:${UI_PREVIEW_SMOKE_SINGLE_PORT}/healthz" || fail "single-listener ui-preview did not become healthy"
assert_no_preview_seed_files
preview_down 0 ":${UI_PREVIEW_SMOKE_SINGLE_PORT}" ""
assert_no_preview_seed_files
assert_preview_db_removed

log "verifying UI_PREVIEW_PERSIST=1 with split public/admin ports"
preview_up 1 ":${UI_PREVIEW_SMOKE_PUBLIC_PORT}" ":${UI_PREVIEW_SMOKE_ADMIN_PORT}" >/dev/null
wait_for_http_code "200" "http://127.0.0.1:${UI_PREVIEW_SMOKE_PUBLIC_PORT}/healthz" || fail "split public listener did not become healthy"
wait_for_http_code "200" "http://127.0.0.1:${UI_PREVIEW_SMOKE_ADMIN_PORT}/healthz" || fail "split admin listener did not become healthy"
[[ "$(curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:${UI_PREVIEW_SMOKE_PUBLIC_PORT}/tukuyomi-ui" || true)" == "404" ]] || fail "public preview listener should not serve admin UI path in split mode"
[[ "$(curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:${UI_PREVIEW_SMOKE_ADMIN_PORT}/tukuyomi-ui" || true)" == "200" ]] || fail "admin preview listener should serve admin UI path in split mode"
assert_no_preview_seed_files
preview_down 1 ":${UI_PREVIEW_SMOKE_PUBLIC_PORT}" ":${UI_PREVIEW_SMOKE_ADMIN_PORT}"
assert_no_preview_seed_files
assert_preview_db_exists

log "verifying split preview can come back up from persisted DB without preview env files"
preview_up 1 "" "" >/dev/null
wait_for_http_code "200" "http://127.0.0.1:${UI_PREVIEW_SMOKE_PUBLIC_PORT}/healthz" || fail "preserved split public listener did not come back healthy"
wait_for_http_code "200" "http://127.0.0.1:${UI_PREVIEW_SMOKE_ADMIN_PORT}/healthz" || fail "preserved split admin listener did not come back healthy"
preview_down 1 "" ""
assert_no_preview_seed_files

log "verifying loopback listener bind is rejected with a clear message"
remove_preview_db
set +e
loopback_output="$(
  cd "${WORKSPACE}" && \
  COMPOSE_PROJECT_NAME="${UI_PREVIEW_SMOKE_PROJECT}" \
  PUID="${PUID_VALUE}" \
  GUID="${GUID_VALUE}" \
  UI_PREVIEW_PERSIST="0" \
  UI_PREVIEW_PUBLIC_ADDR="localhost:${UI_PREVIEW_SMOKE_PUBLIC_PORT}" \
  UI_PREVIEW_ADMIN_ADDR=":${UI_PREVIEW_SMOKE_ADMIN_PORT}" \
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
