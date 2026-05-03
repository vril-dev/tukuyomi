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
CENTER_PROTECTED_PREVIEW_VALUE="${CENTER_PROTECTED_PREVIEW:-0}"
FLEET_PREVIEW_NETWORK_NAME_VALUE="${FLEET_PREVIEW_NETWORK_NAME:-tukuyomi-fleet-preview}"
CENTER_PREVIEW_NETWORK_ALIAS_VALUE="${CENTER_PREVIEW_NETWORK_ALIAS:-center-preview}"
CENTER_PREVIEW_CONTAINER_PORT_VALUE="${CENTER_PREVIEW_CONTAINER_PORT:-9090}"
CENTER_PREVIEW_CONFIG_VALUE="${CENTER_PREVIEW_CONFIG:-conf/config.center-preview.json}"
CENTER_PREVIEW_DB_REL_VALUE="${CENTER_PREVIEW_DB_PATH:-db/tukuyomi-center-preview.db}"
GATEWAY_PREVIEW_CENTER_UPSTREAM_URL_VALUE="${GATEWAY_PREVIEW_CENTER_UPSTREAM_URL:-http://${CENTER_PREVIEW_NETWORK_ALIAS_VALUE}:${CENTER_PREVIEW_CONTAINER_PORT_VALUE}}"
CENTER_PROTECTED_GATEWAY_API_BASE_PATH_VALUE="${CENTER_PROTECTED_GATEWAY_API_BASE_PATH:-${CENTER_PREVIEW_GATEWAY_API_BASE_PATH:-/center-api}}"
CENTER_PROTECTED_CENTER_API_BASE_PATH_VALUE="${CENTER_PROTECTED_CENTER_API_BASE_PATH:-${CENTER_PREVIEW_API_BASE_PATH:-/center-api}}"
CENTER_PROTECTED_CENTER_UI_BASE_PATH_VALUE="${CENTER_PROTECTED_CENTER_UI_BASE_PATH:-${CENTER_PREVIEW_UI_BASE_PATH:-/center-ui}}"

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

runtime = payload.get("runtime")
if not isinstance(runtime, dict):
    runtime = {}
    payload["runtime"] = runtime
runtime["process_model"] = "supervised"

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

preview_validate_data_path() {
  local ref="$1"
  local label="$2"
  python3 - "$ref" "$label" <<'PY'
import pathlib
import sys

ref = str(sys.argv[1]).strip()
label = str(sys.argv[2]).strip()
if not ref:
    raise SystemExit(f"{label} is empty")
path = pathlib.PurePosixPath(ref)
if path.is_absolute():
    raise SystemExit(f"{label} must be relative: {ref}")
if any(part in ("", ".", "..") for part in path.parts):
    raise SystemExit(f"{label} contains unsafe path segment: {ref}")
print(path.as_posix())
PY
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

center_protected_preview_enabled() {
  [[ "$CENTER_PROTECTED_PREVIEW_VALUE" == "1" ]]
}

ensure_fleet_preview_network() {
  if ! center_protected_preview_enabled; then
    return
  fi
  docker network inspect "$FLEET_PREVIEW_NETWORK_NAME_VALUE" >/dev/null 2>&1 || docker network create "$FLEET_PREVIEW_NETWORK_NAME_VALUE" >/dev/null
}

preview_database_exists() {
  local db_paths=()
  mapfile -t db_paths < <(preview_db_host_paths)
  [[ "${#db_paths[@]}" -gt 0 && -f "${db_paths[0]}" ]]
}

protected_preview_seed_bundle_path() {
  printf '%s\n' "$ROOT_DIR/.tmp/gateway-preview/center-protected-config-bundle.json"
}

preview_seed_bundle_file() {
  if center_protected_preview_enabled; then
    protected_preview_seed_bundle_path
    return
  fi
  printf '%s\n' "$ROOT_DIR/seeds/conf/config-bundle.json"
}

preview_proxy_seed_from_startup() {
  if center_protected_preview_enabled; then
    printf '1\n'
    return
  fi
  printf '0\n'
}

write_center_protected_seed_bundle() {
  if ! center_protected_preview_enabled; then
    return
  fi
  local src="$ROOT_DIR/seeds/conf/config-bundle.json"
  local dst=""
  dst="$(protected_preview_seed_bundle_path)"
  mkdir -p "$(dirname "$dst")"
  python3 - "$src" "$dst" "$GATEWAY_PREVIEW_CENTER_UPSTREAM_URL_VALUE" "$CENTER_PROTECTED_GATEWAY_API_BASE_PATH_VALUE" "$CENTER_PROTECTED_CENTER_API_BASE_PATH_VALUE" "$CENTER_PROTECTED_CENTER_UI_BASE_PATH_VALUE" <<'PY'
import json
import pathlib
import posixpath
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
upstream_url = str(sys.argv[3]).strip()
if not upstream_url:
    raise SystemExit("center upstream URL is empty")

def normalize_base_path(label, raw, fallback):
    value = str(raw).strip() or fallback
    if not value.startswith("/"):
        value = "/" + value
    if any(part in (".", "..") for part in value.split("/")):
        raise SystemExit(f"{label} must not contain dot segments")
    value = posixpath.normpath(value)
    if value == "/" or "*" in value:
        raise SystemExit(f"{label} must be a non-root absolute path")
    return value

gateway_api_base = normalize_base_path("gateway API base path", sys.argv[4], "/center-api")
center_api_base = normalize_base_path("center API base path", sys.argv[5], "/center-api")
center_ui_base = normalize_base_path("center UI base path", sys.argv[6], "/center-ui")
if gateway_api_base == center_ui_base or center_api_base == center_ui_base:
    raise SystemExit("center API paths and UI base path must differ")
with src.open(encoding="utf-8") as fh:
    bundle = json.load(fh)
if not isinstance(bundle, dict):
    raise SystemExit("config bundle root must be an object")
domains = bundle.setdefault("domains", {})
if not isinstance(domains, dict):
    raise SystemExit("config bundle domains must be an object")
proxy = domains.get("proxy")
if not isinstance(proxy, dict):
    proxy = {}
proxy["upstreams"] = [
    {
        "enabled": True,
        "name": "center",
        "url": upstream_url,
        "weight": 1,
    }
]
proxy["backend_pools"] = []
api_action = {"upstream": "center"}
if gateway_api_base != center_api_base:
    api_action["path_rewrite"] = {"prefix": center_api_base}
proxy["routes"] = [
    {
        "name": "center-api",
        "priority": 10,
        "match": {"path": {"type": "prefix", "value": gateway_api_base}},
        "action": api_action,
    },
    {
        "name": "center-ui",
        "priority": 20,
        "match": {"path": {"type": "prefix", "value": center_ui_base}},
        "action": {"upstream": "center"},
    },
]
proxy["default_route"] = None
proxy["health_check_path"] = "/healthz"
domains["proxy"] = proxy
waf_bypass = domains.get("waf_bypass")
protected_bypass_paths = {gateway_api_base, center_api_base, center_ui_base}

def keep_bypass_entry(entry):
    if not isinstance(entry, dict):
        return True
    if str(entry.get("extra_rule", "")).strip():
        return True
    return str(entry.get("path", "")).strip().rstrip("/") not in protected_bypass_paths

if isinstance(waf_bypass, dict):
    scopes = []
    default_bypass = waf_bypass.get("default")
    if isinstance(default_bypass, dict):
        scopes.append(default_bypass)
    hosts = waf_bypass.get("hosts")
    if isinstance(hosts, dict):
        scopes.extend(scope for scope in hosts.values() if isinstance(scope, dict))
    for scope in scopes:
        entries = scope.get("entries")
        if isinstance(entries, list):
            scope["entries"] = [entry for entry in entries if keep_bypass_entry(entry)]
bundle["source"] = "center-protected-preview-seed"
tmp = dst.with_name(dst.name + ".tmp")
with tmp.open("w", encoding="utf-8") as fh:
    json.dump(bundle, fh, indent=2, sort_keys=True)
    fh.write("\n")
tmp.replace(dst)
PY
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
    WAF_DB_IMPORT_SEED_BUNDLE_FILE="$(preview_seed_bundle_file)" \
    WAF_DB_IMPORT_SEED_CONF_DIR="$ROOT_DIR/seeds/conf" \
    TUKUYOMI_PREVIEW_PROXY_SEED_FROM_STARTUP="$(preview_proxy_seed_from_startup)" \
    WAF_STORAGE_DB_DRIVER="sqlite" \
    WAF_STORAGE_DB_DSN="" \
    WAF_STORAGE_DB_PATH="$preview_db_rel" \
    GATEWAY_PREVIEW_PUBLIC_ADDR="$GATEWAY_PREVIEW_PUBLIC_ADDR_VALUE" \
    GATEWAY_PREVIEW_ADMIN_ADDR="$GATEWAY_PREVIEW_ADMIN_ADDR_VALUE" \
      "$bin" "$command" "$@"
  )
}

run_center_preview_bootstrap_command() {
  local command="$1"
  shift || true
  local bin="$ROOT_DIR/bin/tukuyomi"
  local center_db_rel=""
  if [[ ! -x "$bin" ]]; then
    echo "[gateway-preview][ERROR] missing executable: $bin" >&2
    return 1
  fi
  center_db_rel="$(preview_validate_data_path "$CENTER_PREVIEW_DB_REL_VALUE" "center preview db path")"
  (
    cd "$ROOT_DIR/data"
    WAF_CONFIG_FILE="$CENTER_PREVIEW_CONFIG_VALUE" \
    WAF_STORAGE_DB_DRIVER="sqlite" \
    WAF_STORAGE_DB_DSN="" \
    WAF_STORAGE_DB_PATH="$center_db_rel" \
      "$bin" "$command" "$@"
  )
}

bootstrap_center_protected_preview_enrollment() {
  center_protected_preview_enabled || return 0
  local identity_rel="tmp/center-protected-preview-device.json"
  local approved_rel="tmp/center-protected-preview-approved-device.json"
  local center_config_path=""
  center_config_path="$(preview_config_host_path "$CENTER_PREVIEW_CONFIG_VALUE" "center preview config")"
  if [[ ! -f "$center_config_path" ]]; then
    echo "[gateway-preview][ERROR] CENTER_PROTECTED_PREVIEW=1 requires center-preview-up before gateway-preview-up" >&2
    return 1
  fi
  ensure_preview_runtime_dirs
  run_preview_command bootstrap-center-protected-gateway \
    --center-url "$GATEWAY_PREVIEW_CENTER_UPSTREAM_URL_VALUE" \
    --gateway-api-base-path "$CENTER_PROTECTED_GATEWAY_API_BASE_PATH_VALUE" \
    --center-api-base-path "$CENTER_PROTECTED_CENTER_API_BASE_PATH_VALUE" \
    --center-ui-base-path "$CENTER_PROTECTED_CENTER_UI_BASE_PATH_VALUE" \
    --out "$identity_rel"
  run_center_preview_bootstrap_command bootstrap-center-protected-center --in "$identity_rel" --out "$approved_rel"
  run_preview_command bootstrap-center-protected-gateway \
    --center-url "$GATEWAY_PREVIEW_CENTER_UPSTREAM_URL_VALUE" \
    --gateway-api-base-path "$CENTER_PROTECTED_GATEWAY_API_BASE_PATH_VALUE" \
    --center-api-base-path "$CENTER_PROTECTED_CENTER_API_BASE_PATH_VALUE" \
    --center-ui-base-path "$CENTER_PROTECTED_CENTER_UI_BASE_PATH_VALUE" \
    --mark-approved \
    --out "$identity_rel"
  rm -f "$ROOT_DIR/data/$identity_rel"
  rm -f "$ROOT_DIR/data/$approved_rel"
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
  if [[ "${GATEWAY_PREVIEW_SPLIT_ADMIN:-0}" != "1" ]] && ! center_protected_preview_enabled; then
    return
  fi
  mkdir -p "$(dirname "$PREVIEW_OVERRIDE")"
  cat >"$PREVIEW_OVERRIDE" <<EOF
services:
  coraza:
EOF
  if [[ "${GATEWAY_PREVIEW_SPLIT_ADMIN:-0}" == "1" ]]; then
    cat >>"$PREVIEW_OVERRIDE" <<EOF
    ports:
      - "${CORAZA_ADMIN_PORT}:${WAF_ADMIN_LISTEN_PORT}"
EOF
  fi
  if center_protected_preview_enabled; then
    cat >>"$PREVIEW_OVERRIDE" <<EOF
    networks:
      default: {}
      fleet-preview: {}
networks:
  fleet-preview:
    external: true
    name: ${FLEET_PREVIEW_NETWORK_NAME_VALUE}
EOF
  fi
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
    preview_db_existed=0
    write_preview_bootstrap_config
    cleanup_legacy_preview_artifacts
    ensure_fleet_preview_network
    write_center_protected_seed_bundle
    if preview_database_exists; then
      preview_db_existed=1
    fi
    if [[ "$GATEWAY_PREVIEW_PERSIST_VALUE" != "1" ]]; then
      run_preview_compose down --remove-orphans >/dev/null 2>&1 || true
      reset_preview_database
      seed_preview_database
    elif [[ "$preview_db_existed" == "1" ]]; then
      upgrade_preview_database
    else
      seed_preview_database
    fi
    bootstrap_center_protected_preview_enrollment
    load_preview_topology
    write_preview_override
    ensure_preview_runtime_dirs
    run_preview_compose up -d --build coraza scheduled-task-runner
    echo "[gateway-preview] public: ${GATEWAY_PREVIEW_PUBLIC_URL}"
    echo "[gateway-preview] admin ui: ${GATEWAY_PREVIEW_ADMIN_UI_URL}"
    echo "[gateway-preview] admin api: ${GATEWAY_PREVIEW_ADMIN_API_URL}"
    if center_protected_preview_enabled; then
      echo "[gateway-preview] center ui via gateway: ${GATEWAY_PREVIEW_PUBLIC_URL%/}${CENTER_PROTECTED_CENTER_UI_BASE_PATH_VALUE}"
      echo "[gateway-preview] center api via gateway: ${GATEWAY_PREVIEW_PUBLIC_URL%/}${CENTER_PROTECTED_GATEWAY_API_BASE_PATH_VALUE}"
      echo "[gateway-preview] center upstream: ${GATEWAY_PREVIEW_CENTER_UPSTREAM_URL_VALUE}"
      if [[ "$GATEWAY_PREVIEW_PERSIST_VALUE" == "1" && "$preview_db_existed" == "1" ]]; then
        echo "[gateway-preview] existing persistent Gateway DB is preserved; protected Center routes are seeded only when the preview DB is created"
      fi
    fi
    echo "[gateway-preview] scheduled-task runner is started by gateway-preview-up"
    if [[ "$GATEWAY_PREVIEW_PERSIST_VALUE" == "1" ]]; then
      echo "[gateway-preview] GATEWAY_PREVIEW_PERSIST=1 keeps preview DB state across down/up"
    else
      echo "[gateway-preview] preview SQLite DB resets on each gateway-preview-up"
    fi
    ;;
  down)
    cleanup_legacy_preview_artifacts
    ensure_fleet_preview_network
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
