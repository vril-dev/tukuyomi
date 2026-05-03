#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREVIEW_OVERRIDE="$ROOT_DIR/.tmp/center-preview/docker-compose.override.yml"
PREVIEW_SOURCE_CONFIG="${CENTER_PREVIEW_SOURCE_CONFIG:-conf/config.json}"
PREVIEW_BOOTSTRAP_CONFIG="${CENTER_PREVIEW_CONFIG:-conf/config.center-preview.json}"
CENTER_PREVIEW_PORT_VALUE="${CENTER_PREVIEW_PORT:-9092}"
CENTER_PREVIEW_CONTAINER_PORT_VALUE="${CENTER_PREVIEW_CONTAINER_PORT:-9090}"
CENTER_PREVIEW_API_BASE_PATH_VALUE="${CENTER_PREVIEW_API_BASE_PATH:-/center-api}"
CENTER_PREVIEW_GATEWAY_API_BASE_PATH_VALUE="${CENTER_PREVIEW_GATEWAY_API_BASE_PATH:-/center-api}"
CENTER_PREVIEW_UI_BASE_PATH_VALUE="${CENTER_PREVIEW_UI_BASE_PATH:-/center-ui}"
CENTER_PREVIEW_CLIENT_ALLOW_CIDRS_VALUE="${CENTER_PREVIEW_CLIENT_ALLOW_CIDRS:-}"
CENTER_PREVIEW_MANAGE_API_ALLOW_CIDRS_VALUE="${CENTER_PREVIEW_MANAGE_API_ALLOW_CIDRS:-}"
CENTER_PREVIEW_API_ALLOW_CIDRS_VALUE="${CENTER_PREVIEW_API_ALLOW_CIDRS:-}"
CENTER_PREVIEW_DB_REL_VALUE="${CENTER_PREVIEW_DB_PATH:-db/tukuyomi-center-preview.db}"
CENTER_PREVIEW_PERSIST_VALUE="${CENTER_PREVIEW_PERSIST:-0}"
CENTER_PREVIEW_PROJECT_VALUE="${CENTER_PREVIEW_PROJECT:-tukuyomi-center-preview}"
CENTER_PROTECTED_PREVIEW_VALUE="${CENTER_PROTECTED_PREVIEW:-0}"
FLEET_PREVIEW_NETWORK_NAME_VALUE="${FLEET_PREVIEW_NETWORK_NAME:-tukuyomi-fleet-preview}"
CENTER_PREVIEW_NETWORK_ALIAS_VALUE="${CENTER_PREVIEW_NETWORK_ALIAS:-center-preview}"
PUID_VALUE="${PUID:-$(id -u)}"
GUID_VALUE="${GUID:-$(id -g)}"

center_preview_config_host_path() {
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
path = pathlib.PurePosixPath(ref)
if path.is_absolute():
    raise SystemExit(f"{label} must be relative to data/: {ref}")
if any(part in ("", ".", "..") for part in path.parts):
    raise SystemExit(f"{label} contains unsafe path segment: {ref}")
target = (root / "data" / pathlib.Path(*path.parts)).resolve(strict=False)
data_root = (root / "data").resolve(strict=False)
if target != data_root and data_root not in target.parents:
    raise SystemExit(f"{label} escapes data/: {ref}")
print(target)
PY
}

center_preview_validate_data_path() {
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

write_center_preview_bootstrap_config() {
  local source_path=""
  local target_path=""
  source_path="$(center_preview_config_host_path "$PREVIEW_SOURCE_CONFIG" "center preview source config")"
  target_path="$(center_preview_config_host_path "$PREVIEW_BOOTSTRAP_CONFIG" "center preview bootstrap config")"
  if [[ "$source_path" == "$target_path" ]]; then
    echo "[center-preview][ERROR] preview bootstrap config must differ from source config" >&2
    return 1
  fi
  python3 - "$source_path" "$target_path" "$CENTER_PREVIEW_DB_REL_VALUE" <<'PY'
import json
import os
import pathlib
import secrets
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
db_path = str(sys.argv[3]).strip()

base = target if target.exists() else source
with base.open("r", encoding="utf-8") as fh:
    payload = json.load(fh)
if not isinstance(payload, dict):
    raise SystemExit("center preview config root must be a JSON object")

admin = payload.get("admin")
if not isinstance(admin, dict):
    admin = {}
    payload["admin"] = admin

env_secret = os.environ.get("CENTER_PREVIEW_SESSION_SECRET", "").strip()
if env_secret and len(env_secret) < 16:
    raise SystemExit("CENTER_PREVIEW_SESSION_SECRET must be 16+ chars")
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

storage = payload.get("storage")
if not isinstance(storage, dict):
    storage = {}
    payload["storage"] = storage
storage["db_driver"] = "sqlite"
storage["db_path"] = db_path
storage["db_dsn"] = ""
storage["db_sync_interval_sec"] = 0

target.parent.mkdir(parents=True, exist_ok=True)
tmp = target.with_name(target.name + ".tmp")
with tmp.open("w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
os.replace(tmp, target)
PY
}

remove_center_preview_bootstrap_config() {
  local source_path=""
  local target_path=""
  source_path="$(center_preview_config_host_path "$PREVIEW_SOURCE_CONFIG" "center preview source config")"
  target_path="$(center_preview_config_host_path "$PREVIEW_BOOTSTRAP_CONFIG" "center preview bootstrap config")"
  if [[ "$source_path" != "$target_path" ]]; then
    rm -f "$target_path"
  fi
}

center_preview_db_host_paths() {
  local db_rel=""
  db_rel="$(center_preview_validate_data_path "$CENTER_PREVIEW_DB_REL_VALUE" "center preview db path")"
  python3 - "$ROOT_DIR" "$db_rel" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
db_rel = pathlib.PurePosixPath(str(sys.argv[2]).strip())
target = (root / "data" / pathlib.Path(*db_rel.parts)).resolve(strict=False)
data_root = (root / "data").resolve(strict=False)
if target != data_root and data_root not in target.parents:
    raise SystemExit(f"center preview db path escapes data/: {db_rel}")
print(target)
print(str(target) + "-wal")
print(str(target) + "-shm")
PY
}

reset_center_preview_database() {
  local db_paths=()
  mapfile -t db_paths < <(center_preview_db_host_paths)
  if [[ "${#db_paths[@]}" -eq 0 ]]; then
    echo "[center-preview][ERROR] failed to resolve preview database path" >&2
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

center_preview_host_port_mapping() {
  if center_protected_preview_enabled && [[ "$CENTER_PREVIEW_PORT_VALUE" != *:* ]]; then
    printf '127.0.0.1:%s\n' "$CENTER_PREVIEW_PORT_VALUE"
    return
  fi
  printf '%s\n' "$CENTER_PREVIEW_PORT_VALUE"
}

center_preview_host_url() {
  if center_protected_preview_enabled; then
    if [[ "$CENTER_PREVIEW_PORT_VALUE" == *:* ]]; then
      printf 'http://%s\n' "$CENTER_PREVIEW_PORT_VALUE"
    else
      printf 'http://127.0.0.1:%s\n' "$CENTER_PREVIEW_PORT_VALUE"
    fi
    return
  fi
  printf 'http://localhost:%s\n' "$CENTER_PREVIEW_PORT_VALUE"
}

write_center_preview_override() {
  mkdir -p "$(dirname "$PREVIEW_OVERRIDE")"
  cat >"$PREVIEW_OVERRIDE" <<EOF
services:
  coraza:
    command: ["/app/server", "center"]
    environment:
      - TUKUYOMI_CENTER_LISTEN_ADDR=:${CENTER_PREVIEW_CONTAINER_PORT_VALUE}
      - TUKUYOMI_CENTER_API_BASE_PATH=${CENTER_PREVIEW_API_BASE_PATH_VALUE}
      - TUKUYOMI_CENTER_GATEWAY_API_BASE_PATH=${CENTER_PREVIEW_GATEWAY_API_BASE_PATH_VALUE}
      - TUKUYOMI_CENTER_UI_BASE_PATH=${CENTER_PREVIEW_UI_BASE_PATH_VALUE}
      - TUKUYOMI_CENTER_CLIENT_ALLOW_CIDRS=${CENTER_PREVIEW_CLIENT_ALLOW_CIDRS_VALUE}
      - TUKUYOMI_CENTER_MANAGE_API_ALLOW_CIDRS=${CENTER_PREVIEW_MANAGE_API_ALLOW_CIDRS_VALUE}
      - TUKUYOMI_CENTER_API_ALLOW_CIDRS=${CENTER_PREVIEW_API_ALLOW_CIDRS_VALUE}
EOF
  if center_protected_preview_enabled; then
    cat >>"$PREVIEW_OVERRIDE" <<EOF
    networks:
      default: {}
      fleet-preview:
        aliases:
          - ${CENTER_PREVIEW_NETWORK_ALIAS_VALUE}
EOF
  fi
  if [[ -S /var/run/docker.sock ]]; then
    docker_sock_gid="$(stat -c '%g' /var/run/docker.sock 2>/dev/null || true)"
    cat >>"$PREVIEW_OVERRIDE" <<EOF
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
EOF
    if [[ -n "${docker_sock_gid}" ]]; then
      cat >>"$PREVIEW_OVERRIDE" <<EOF
    group_add:
      - "${docker_sock_gid}"
EOF
    fi
  fi
  if center_protected_preview_enabled; then
    cat >>"$PREVIEW_OVERRIDE" <<EOF
networks:
  fleet-preview:
    external: true
    name: ${FLEET_PREVIEW_NETWORK_NAME_VALUE}
EOF
  fi
}

run_center_preview_command() {
  local command="$1"
  shift || true
  local bin="$ROOT_DIR/bin/tukuyomi"
  local db_rel=""
  if [[ ! -x "$bin" ]]; then
    echo "[center-preview][ERROR] missing executable: $bin" >&2
    return 1
  fi
  db_rel="$(center_preview_validate_data_path "$CENTER_PREVIEW_DB_REL_VALUE" "center preview db path")"
  (
    cd "$ROOT_DIR/data"
    WAF_CONFIG_FILE="$PREVIEW_BOOTSTRAP_CONFIG" \
    WAF_STORAGE_DB_DRIVER="sqlite" \
    WAF_STORAGE_DB_DSN="" \
    WAF_STORAGE_DB_PATH="$db_rel" \
      "$bin" "$command" "$@"
  )
}

run_center_preview_compose() {
  local action="$1"
  shift || true
  local db_rel=""
  db_rel="$(center_preview_validate_data_path "$CENTER_PREVIEW_DB_REL_VALUE" "center preview db path")"
  PUID="$PUID_VALUE" GUID="$GUID_VALUE" \
  COMPOSE_PROJECT_NAME="$CENTER_PREVIEW_PROJECT_VALUE" \
  WAF_CONFIG_FILE="$PREVIEW_BOOTSTRAP_CONFIG" \
  WAF_STORAGE_DB_DRIVER="sqlite" \
  WAF_STORAGE_DB_DSN="" \
  WAF_STORAGE_DB_PATH="data/$db_rel" \
  WAF_LISTEN_PORT="$CENTER_PREVIEW_CONTAINER_PORT_VALUE" \
  WAF_HEALTHCHECK_PORT="$CENTER_PREVIEW_CONTAINER_PORT_VALUE" \
  CORAZA_PORT="$(center_preview_host_port_mapping)" \
    docker compose -f "$ROOT_DIR/docker-compose.yml" -f "$PREVIEW_OVERRIDE" "$action" "$@"
}

cd "$ROOT_DIR"

case "${1:-}" in
  up)
    write_center_preview_bootstrap_config
    ensure_fleet_preview_network
    write_center_preview_override
    if [[ "$CENTER_PREVIEW_PERSIST_VALUE" != "1" ]]; then
      run_center_preview_compose down --remove-orphans >/dev/null 2>&1 || true
      reset_center_preview_database
    fi
    run_center_preview_command db-migrate
    run_center_preview_compose up -d --build coraza
    center_preview_base_url="$(center_preview_host_url)"
    echo "[center-preview] center ui: ${center_preview_base_url}${CENTER_PREVIEW_UI_BASE_PATH_VALUE}"
    echo "[center-preview] center api: ${center_preview_base_url}${CENTER_PREVIEW_API_BASE_PATH_VALUE}"
    if center_protected_preview_enabled; then
      echo "[center-preview] protected network alias: ${CENTER_PREVIEW_NETWORK_ALIAS_VALUE}:${CENTER_PREVIEW_CONTAINER_PORT_VALUE}"
    fi
    if [[ "$CENTER_PREVIEW_PERSIST_VALUE" == "1" ]]; then
      echo "[center-preview] CENTER_PREVIEW_PERSIST=1 keeps preview DB state across down/up"
    else
      echo "[center-preview] preview SQLite DB resets on each center-preview-up"
    fi
    ;;
  down)
    ensure_fleet_preview_network
    write_center_preview_override
    run_center_preview_compose down --remove-orphans >/dev/null 2>&1 || true
    rm -f "$PREVIEW_OVERRIDE"
    if [[ "$CENTER_PREVIEW_PERSIST_VALUE" != "1" ]]; then
      reset_center_preview_database || true
      remove_center_preview_bootstrap_config
    fi
    echo "[center-preview] stopped"
    ;;
  *)
    echo "usage: $0 <up|down>" >&2
    exit 1
    ;;
esac
