#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREVIEW_OVERRIDE="$ROOT_DIR/.tmp/gateway-preview/docker-compose.override.yml"
PREVIEW_SOURCE_CONFIG="${GATEWAY_PREVIEW_SOURCE_CONFIG:-conf/config.json}"
PREVIEW_BOOTSTRAP_CONFIG="${GATEWAY_PREVIEW_CONFIG:-conf/config.gateway-preview.json}"
LEGACY_UI_PREVIEW_SQLITE_DB_PATH="logs/coraza/tukuyomi-ui-preview.db"
PUID_VALUE="${PUID:-$(id -u)}"
GUID_VALUE="${GUID:-$(id -g)}"
GATEWAY_PREVIEW_PERSIST_VALUE="${GATEWAY_PREVIEW_PERSIST:-0}"
GATEWAY_PREVIEW_PUBLIC_ADDR_VALUE="${GATEWAY_PREVIEW_PUBLIC_ADDR:-}"
GATEWAY_PREVIEW_ADMIN_ADDR_VALUE="${GATEWAY_PREVIEW_ADMIN_ADDR:-}"

preview_config_host_path() {
  local config_ref="$1"
  local label="$2"
  python3 - "$ROOT_DIR" "$config_ref" "$label" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
ref = str(sys.argv[2]).strip()
label = str(sys.argv[3]).strip()
if not ref:
    raise SystemExit(f"{label} is empty")
path = pathlib.Path(ref)
if path.is_absolute():
    raise SystemExit(f"{label} must be relative to data/: {ref}")
parts = pathlib.PurePosixPath(ref).parts
if any(part in ("", ".", "..") for part in parts):
    raise SystemExit(f"{label} contains unsafe path segment: {ref}")
target = (root / "data" / pathlib.Path(*parts)).resolve(strict=False)
data_root = (root / "data").resolve(strict=False)
if target != data_root and data_root not in target.parents:
    raise SystemExit(f"{label} escapes data/: {ref}")
print(target)
PY
}

write_preview_bootstrap_config() {
  local source_path=""
  local target_path=""
  source_path="$(preview_config_host_path "$PREVIEW_SOURCE_CONFIG" "preview source config")"
  target_path="$(preview_config_host_path "$PREVIEW_BOOTSTRAP_CONFIG" "preview bootstrap config")"
  if [[ "$source_path" == "$target_path" ]]; then
    echo "[gateway-preview][ERROR] preview bootstrap config must differ from preview source config" >&2
    return 1
  fi
  python3 - "$source_path" "$target_path" <<'PY'
import json
import os
import pathlib
import secrets
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])

base = target if target.exists() else source
with base.open("r", encoding="utf-8") as fh:
    payload = json.load(fh)
if not isinstance(payload, dict):
    raise SystemExit("preview config root must be a JSON object")

admin = payload.get("admin")
if not isinstance(admin, dict):
    admin = {}
    payload["admin"] = admin

env_secret = os.environ.get("GATEWAY_PREVIEW_SESSION_SECRET", "").strip()
if env_secret and len(env_secret) < 16:
    raise SystemExit("GATEWAY_PREVIEW_SESSION_SECRET must be 16+ chars")

existing_secret = str(admin.get("session_secret") or "").strip()
if env_secret:
    session_secret = env_secret
elif len(existing_secret) >= 16:
    session_secret = existing_secret
else:
    session_secret = secrets.token_urlsafe(48)

admin["session_secret"] = session_secret
admin["api_auth_disable"] = False
admin["allow_insecure_defaults"] = False

target.parent.mkdir(parents=True, exist_ok=True)
tmp = target.with_name(target.name + ".tmp")
with tmp.open("w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
os.replace(tmp, target)
PY
}

remove_preview_bootstrap_config() {
  local source_path=""
  local target_path=""
  source_path="$(preview_config_host_path "$PREVIEW_SOURCE_CONFIG" "preview source config")"
  target_path="$(preview_config_host_path "$PREVIEW_BOOTSTRAP_CONFIG" "preview bootstrap config")"
  if [[ "$source_path" != "$target_path" ]]; then
    rm -f "$target_path"
  fi
}

preview_db_relative_path() {
  local bootstrap_path=""
  local source_path=""
  local config_path=""
  bootstrap_path="$(preview_config_host_path "$PREVIEW_BOOTSTRAP_CONFIG" "preview bootstrap config")"
  source_path="$(preview_config_host_path "$PREVIEW_SOURCE_CONFIG" "preview source config")"
  if [[ -f "$bootstrap_path" ]]; then
    config_path="$bootstrap_path"
  elif [[ -f "$source_path" ]]; then
    config_path="$source_path"
  else
    echo "[gateway-preview][ERROR] preview config not found" >&2
    return 1
  fi
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
if db_path.startswith("/"):
    raise SystemExit(f"preview storage.db_path must be relative: {db_path}")
parts = pathlib.PurePosixPath(db_path).parts
if any(part in ("", ".", "..") for part in parts):
    raise SystemExit(f"preview storage.db_path contains unsafe path segment: {db_path}")
if len(parts) == 0:
    raise SystemExit("preview storage.db_path is empty")
parent = pathlib.PurePosixPath(*parts[:-1]) if len(parts) > 1 else pathlib.PurePosixPath(".")
preview_path = pathlib.PurePosixPath(parent, "tukuyomi-gateway-preview.db")
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
    "$ROOT_DIR/data/php-fpm/vhosts.ui-preview.json".*.bak \
    "$ROOT_DIR/data/conf/proxy.gateway-preview.json" \
    "$ROOT_DIR/data/conf/scheduled-tasks.gateway-preview.json" \
    "$ROOT_DIR/data/php-fpm/inventory.gateway-preview.json" \
    "$ROOT_DIR/data/php-fpm/vhosts.gateway-preview.json" \
    "$ROOT_DIR/data/php-fpm/vhosts.gateway-preview.json".*.bak
  rm -f \
    "$ROOT_DIR/data/$LEGACY_UI_PREVIEW_SQLITE_DB_PATH" \
    "$ROOT_DIR/data/$LEGACY_UI_PREVIEW_SQLITE_DB_PATH-wal" \
    "$ROOT_DIR/data/$LEGACY_UI_PREVIEW_SQLITE_DB_PATH-shm" \
    "$ROOT_DIR/data/db/tukuyomi-ui-preview.db" \
    "$ROOT_DIR/data/db/tukuyomi-ui-preview.db-wal" \
    "$ROOT_DIR/data/db/tukuyomi-ui-preview.db-shm"
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
    echo "[gateway-preview][ERROR] failed to resolve preview database path" >&2
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

ensure_preview_runtime_dirs() {
  mkdir -p "$ROOT_DIR/data/persistent" "$ROOT_DIR/data/cache/response" "$ROOT_DIR/data/tmp"
}

run_preview_command() {
  local command="$1"
  shift || true
  local bin="$ROOT_DIR/bin/tukuyomi"
  local preview_db_rel=""
  if [[ ! -x "$bin" ]]; then
    echo "[gateway-preview][ERROR] missing executable: $bin" >&2
    return 1
  fi
  preview_db_rel="$(preview_db_relative_path)"
  (
    cd "$ROOT_DIR/data"
    WAF_CONFIG_FILE="$PREVIEW_BOOTSTRAP_CONFIG" \
    WAF_DB_IMPORT_SEED_CONF_DIR="$ROOT_DIR/seeds/conf" \
    WAF_STORAGE_DB_DRIVER="sqlite" \
    WAF_STORAGE_DB_DSN="" \
    WAF_STORAGE_DB_PATH="$preview_db_rel" \
    GATEWAY_PREVIEW_PUBLIC_ADDR="$GATEWAY_PREVIEW_PUBLIC_ADDR_VALUE" \
    GATEWAY_PREVIEW_ADMIN_ADDR="$GATEWAY_PREVIEW_ADMIN_ADDR_VALUE" \
      "$bin" "$command" "$@"
  )
}

seed_preview_database() {
  local stage_root=""
  ensure_preview_runtime_dirs
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
    echo "[gateway-preview][ERROR] failed to derive preview topology" >&2
    return 1
  }
  eval "$assignments"
}

write_preview_override() {
  rm -f "$PREVIEW_OVERRIDE"
  if [[ "${GATEWAY_PREVIEW_SPLIT_ADMIN:-0}" != "1" ]]; then
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
    write_preview_bootstrap_config
    cleanup_legacy_preview_artifacts
    if [[ "$GATEWAY_PREVIEW_PERSIST_VALUE" != "1" ]]; then
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
    ensure_preview_runtime_dirs
    run_preview_compose up -d --build coraza scheduled-task-runner
    echo "[gateway-preview] public: ${GATEWAY_PREVIEW_PUBLIC_URL}"
    echo "[gateway-preview] admin ui: ${GATEWAY_PREVIEW_ADMIN_UI_URL}"
    echo "[gateway-preview] admin api: ${GATEWAY_PREVIEW_ADMIN_API_URL}"
    echo "[gateway-preview] scheduled-task runner is started by gateway-preview-up"
    if [[ "$GATEWAY_PREVIEW_PERSIST_VALUE" == "1" ]]; then
      echo "[gateway-preview] GATEWAY_PREVIEW_PERSIST=1 keeps preview DB state across down/up"
    else
      echo "[gateway-preview] preview SQLite DB resets on each gateway-preview-up"
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
    if [[ "$GATEWAY_PREVIEW_PERSIST_VALUE" != "1" ]]; then
      reset_preview_database || true
      remove_preview_bootstrap_config
    fi
    echo "[gateway-preview] stopped"
    ;;
  *)
    echo "usage: $0 <up|down>" >&2
    exit 1
    ;;
esac
