#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREVIEW_OVERRIDE="$ROOT_DIR/.tmp/ui-preview/docker-compose.override.yml"
PREVIEW_BOOTSTRAP_CONFIG="conf/config.json"
LEGACY_PREVIEW_SQLITE_DB_PATH="logs/coraza/tukuyomi-ui-preview.db"
PUID_VALUE="${PUID:-$(id -u)}"
GUID_VALUE="${GUID:-$(id -g)}"
UI_PREVIEW_PERSIST_VALUE="${UI_PREVIEW_PERSIST:-0}"
UI_PREVIEW_PUBLIC_ADDR_VALUE="${UI_PREVIEW_PUBLIC_ADDR:-}"
UI_PREVIEW_ADMIN_ADDR_VALUE="${UI_PREVIEW_ADMIN_ADDR:-}"

preview_db_relative_path() {
  python3 - "$ROOT_DIR" "$PREVIEW_BOOTSTRAP_CONFIG" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
config_ref = str(sys.argv[2]).strip()
if not config_ref:
    raise SystemExit("preview bootstrap config is empty")
config_path = pathlib.Path(config_ref)
if not config_path.is_absolute():
    config_path = (root / "data" / config_path).resolve(strict=False)
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
if len(parts) == 0:
    raise SystemExit("preview storage.db_path is empty")
parent = pathlib.PurePosixPath(*parts[:-1]) if len(parts) > 1 else pathlib.PurePosixPath(".")
preview_path = pathlib.PurePosixPath(parent, "tukuyomi-ui-preview.db")
if str(preview_path) in ("", "."):
    raise SystemExit(f"preview db path is invalid: {preview_path}")
print(preview_path.as_posix())
PY
}

preview_db_container_path() {
  local preview_db_rel=""
  preview_db_rel="$(preview_db_relative_path)"
  printf 'data/%s\n' "$preview_db_rel"
}

cleanup_legacy_preview_artifacts() {
  rm -f \
    "$ROOT_DIR/data/conf/config.ui-preview.json" \
    "$ROOT_DIR/data/conf/proxy.ui-preview.json" \
    "$ROOT_DIR/data/conf/scheduled-tasks.ui-preview.json" \
    "$ROOT_DIR/data/php-fpm/inventory.ui-preview.json" \
    "$ROOT_DIR/data/php-fpm/vhosts.ui-preview.json" \
    "$ROOT_DIR/data/php-fpm/vhosts.ui-preview.json".*.bak
  local preview_db_rel=""
  preview_db_rel="$(preview_db_relative_path)"
  if [[ "$preview_db_rel" != "$LEGACY_PREVIEW_SQLITE_DB_PATH" ]]; then
    rm -f \
      "$ROOT_DIR/data/$LEGACY_PREVIEW_SQLITE_DB_PATH" \
      "$ROOT_DIR/data/$LEGACY_PREVIEW_SQLITE_DB_PATH-wal" \
      "$ROOT_DIR/data/$LEGACY_PREVIEW_SQLITE_DB_PATH-shm"
  fi
}

preview_db_host_paths() {
  local preview_db_rel=""
  preview_db_rel="$(preview_db_relative_path)"
  python3 - "$ROOT_DIR" "$preview_db_rel" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
db_path = str(sys.argv[2]).strip()
if not db_path:
    raise SystemExit("preview storage.db_path is empty")
if db_path.startswith("/"):
    raise SystemExit(f"preview storage.db_path must be relative: {db_path}")
parts = pathlib.PurePosixPath(db_path).parts
if any(part in ("", ".", "..") for part in parts):
    raise SystemExit(f"preview storage.db_path contains unsafe path segment: {db_path}")
target = (root / "data" / pathlib.Path(*parts)).resolve(strict=False)
allowed = (root / "data").resolve(strict=False)
if target != allowed and allowed not in target.parents:
    raise SystemExit(f"preview storage.db_path escapes data/: {db_path}")
print(target)
print(str(target) + "-wal")
print(str(target) + "-shm")
PY
}

reset_preview_database() {
  local db_paths=()
  mapfile -t db_paths < <(preview_db_host_paths)
  if [[ "${#db_paths[@]}" -eq 0 ]]; then
    echo "[ui-preview][ERROR] failed to resolve preview database path" >&2
    return 1
  fi
  mkdir -p "$(dirname "${db_paths[0]}")"
  rm -f "${db_paths[@]}"
}

preview_database_exists() {
  local db_paths=()
  mapfile -t db_paths < <(preview_db_host_paths)
  [[ "${#db_paths[@]}" -gt 0 && -f "${db_paths[0]}" ]]
}

run_preview_command() {
  local command="$1"
  shift || true
  local bin="$ROOT_DIR/bin/tukuyomi"
  local preview_db_rel=""
  if [[ ! -x "$bin" ]]; then
    echo "[ui-preview][ERROR] missing executable: $bin" >&2
    return 1
  fi
  preview_db_rel="$(preview_db_relative_path)"
  (
    cd "$ROOT_DIR/data"
    WAF_CONFIG_FILE="$PREVIEW_BOOTSTRAP_CONFIG" \
    WAF_STORAGE_DB_DRIVER="sqlite" \
    WAF_STORAGE_DB_DSN="" \
    WAF_STORAGE_DB_PATH="$preview_db_rel" \
    UI_PREVIEW_PUBLIC_ADDR="$UI_PREVIEW_PUBLIC_ADDR_VALUE" \
    UI_PREVIEW_ADMIN_ADDR="$UI_PREVIEW_ADMIN_ADDR_VALUE" \
      "$bin" "$command" "$@"
  )
}

seed_preview_database() {
  local stage_root=""
  mkdir -p "$ROOT_DIR/data/tmp"
  stage_root="$(mktemp -d "$ROOT_DIR/data/tmp/preview-crs-import.XXXXXX")"
  trap 'rm -rf "$stage_root"' RETURN
  "$ROOT_DIR/scripts/stage_waf_rule_assets.sh" "$stage_root"
  run_preview_command db-migrate
  WAF_RULE_ASSET_FS_ROOT="$stage_root" run_preview_command db-import-waf-rule-assets
  run_preview_command db-import-preview
}

upgrade_preview_database() {
  run_preview_command db-migrate
}

load_preview_topology() {
  local assignments
  assignments="$(
    run_preview_command preview-print-topology
  )" || {
    echo "[ui-preview][ERROR] failed to derive preview topology" >&2
    return 1
  }
  eval "$assignments"
}

write_preview_override() {
  rm -f "$PREVIEW_OVERRIDE"
  if [[ "${UI_PREVIEW_SPLIT_ADMIN:-0}" != "1" ]]; then
    return
  fi
  mkdir -p "$(dirname "$PREVIEW_OVERRIDE")"
  cat >"$PREVIEW_OVERRIDE" <<EOF
services:
  coraza:
    ports:
      - "${CORAZA_ADMIN_PORT}:${WAF_ADMIN_LISTEN_PORT}"
EOF
}

run_preview_compose() {
  local action="$1"
  shift || true
  local preview_db_rel=""
  local preview_db_container=""
  preview_db_rel="$(preview_db_relative_path)"
  preview_db_container="$(preview_db_container_path)"
  if [[ -f "$PREVIEW_OVERRIDE" ]]; then
    PUID="$PUID_VALUE" GUID="$GUID_VALUE" \
    WAF_CONFIG_FILE="$PREVIEW_BOOTSTRAP_CONFIG" \
    WAF_STORAGE_DB_DRIVER="sqlite" \
    WAF_STORAGE_DB_DSN="" \
    WAF_STORAGE_DB_PATH="$preview_db_container" \
    WAF_LISTEN_PORT="${WAF_LISTEN_PORT:-9090}" \
    WAF_HEALTHCHECK_PORT="${WAF_HEALTHCHECK_PORT:-9090}" \
    CORAZA_PORT="${CORAZA_PORT:-9090}" \
    WAF_ADMIN_LISTEN_PORT="${WAF_ADMIN_LISTEN_PORT:-}" \
    CORAZA_ADMIN_PORT="${CORAZA_ADMIN_PORT:-}" \
      docker compose -f "$ROOT_DIR/docker-compose.yml" -f "$PREVIEW_OVERRIDE" --profile scheduled-tasks "$action" "$@"
    return
  fi
  PUID="$PUID_VALUE" GUID="$GUID_VALUE" \
  WAF_CONFIG_FILE="$PREVIEW_BOOTSTRAP_CONFIG" \
  WAF_STORAGE_DB_DRIVER="sqlite" \
  WAF_STORAGE_DB_DSN="" \
  WAF_STORAGE_DB_PATH="$preview_db_container" \
  WAF_LISTEN_PORT="${WAF_LISTEN_PORT:-9090}" \
  WAF_HEALTHCHECK_PORT="${WAF_HEALTHCHECK_PORT:-9090}" \
  CORAZA_PORT="${CORAZA_PORT:-9090}" \
    docker compose --profile scheduled-tasks "$action" "$@"
}

cd "$ROOT_DIR"

case "${1:-}" in
  up)
    cleanup_legacy_preview_artifacts
    if [[ "$UI_PREVIEW_PERSIST_VALUE" != "1" ]]; then
      run_preview_compose down --remove-orphans >/dev/null 2>&1 || true
      reset_preview_database
      seed_preview_database
    elif preview_database_exists; then
      upgrade_preview_database
    else
      seed_preview_database
    fi
    load_preview_topology
    write_preview_override
    run_preview_compose up -d --build coraza scheduled-task-runner
    echo "[ui-preview] public: ${UI_PREVIEW_PUBLIC_URL}"
    echo "[ui-preview] admin ui: ${UI_PREVIEW_ADMIN_UI_URL}"
    echo "[ui-preview] admin api: ${UI_PREVIEW_ADMIN_API_URL}"
    echo "[ui-preview] scheduled-task runner is started by ui-preview-up"
    if [[ "$UI_PREVIEW_PERSIST_VALUE" == "1" ]]; then
      echo "[ui-preview] UI_PREVIEW_PERSIST=1 keeps preview DB state across down/up"
    else
      echo "[ui-preview] preview SQLite DB resets on each ui-preview-up"
    fi
    ;;
  down)
    cleanup_legacy_preview_artifacts
    if preview_database_exists; then
      if load_preview_topology; then
        :
      else
        WAF_LISTEN_PORT="${WAF_LISTEN_PORT:-9090}"
        CORAZA_PORT="${CORAZA_PORT:-9090}"
        WAF_HEALTHCHECK_PORT="${WAF_HEALTHCHECK_PORT:-9090}"
      fi
      write_preview_override
    else
      WAF_LISTEN_PORT="${WAF_LISTEN_PORT:-9090}"
      CORAZA_PORT="${CORAZA_PORT:-9090}"
      WAF_HEALTHCHECK_PORT="${WAF_HEALTHCHECK_PORT:-9090}"
      rm -f "$PREVIEW_OVERRIDE"
    fi
    run_preview_compose down --remove-orphans >/dev/null 2>&1 || true
    rm -f "$PREVIEW_OVERRIDE"
    cleanup_legacy_preview_artifacts
    if [[ "$UI_PREVIEW_PERSIST_VALUE" != "1" ]]; then
      reset_preview_database || true
    fi
    echo "[ui-preview] stopped"
    ;;
  *)
    echo "usage: $0 <up|down>" >&2
    exit 1
    ;;
esac
