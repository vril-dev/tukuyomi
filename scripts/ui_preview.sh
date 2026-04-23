#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREVIEW_CONFIG="$ROOT_DIR/data/conf/config.ui-preview.json"
PREVIEW_PROXY="$ROOT_DIR/data/conf/proxy.ui-preview.json"
PREVIEW_SCHEDULED_TASKS="$ROOT_DIR/data/conf/scheduled-tasks.ui-preview.json"
PREVIEW_INVENTORY="$ROOT_DIR/data/php-fpm/inventory.ui-preview.json"
PREVIEW_VHOSTS="$ROOT_DIR/data/php-fpm/vhosts.ui-preview.json"
PREVIEW_OVERRIDE="$ROOT_DIR/data/conf/docker-compose.ui-preview.override.yml"
PREVIEW_CONFIG_BASENAME="$(basename "$PREVIEW_CONFIG")"
PREVIEW_SQLITE_DB_PATH="logs/coraza/tukuyomi-ui-preview.db"
PUID_VALUE="${PUID:-$(id -u)}"
GUID_VALUE="${GUID:-$(id -g)}"
UI_PREVIEW_PERSIST_VALUE="${UI_PREVIEW_PERSIST:-0}"

write_preview_proxy() {
  cat >"$PREVIEW_PROXY" <<'EOF'
{}
EOF
}

write_preview_scheduled_tasks() {
  cat >"$PREVIEW_SCHEDULED_TASKS" <<'EOF'
{
  "tasks": []
}
EOF
}

write_preview_inventory() {
  cat >"$PREVIEW_INVENTORY" <<'EOF'
{}
EOF
}

write_preview_vhosts() {
  cat >"$PREVIEW_VHOSTS" <<'EOF'
{
  "vhosts": []
}
EOF
}

write_preview_config() {
  local src_config="${1:-$ROOT_DIR/data/conf/config.json}"
  mkdir -p "$(dirname "$PREVIEW_CONFIG")" "$(dirname "$PREVIEW_PROXY")" "$(dirname "$PREVIEW_INVENTORY")"
  python3 - "$src_config" "$PREVIEW_CONFIG" "$PREVIEW_SQLITE_DB_PATH" <<'PY'
import json
import pathlib
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
db_path = sys.argv[3]
cfg = json.loads(src.read_text(encoding="utf-8"))
paths = cfg.setdefault("paths", {})
paths["proxy_config_file"] = "conf/proxy.ui-preview.json"
paths["scheduled_task_config_file"] = "conf/scheduled-tasks.ui-preview.json"
paths["php_runtime_inventory_file"] = "data/php-fpm/inventory.ui-preview.json"
paths["vhost_config_file"] = "data/php-fpm/vhosts.ui-preview.json"
storage = cfg.setdefault("storage", {})
storage["db_driver"] = "sqlite"
storage["db_dsn"] = ""
storage["db_path"] = db_path
dst.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
PY
}

reset_preview_files() {
  write_preview_proxy
  write_preview_scheduled_tasks
  write_preview_inventory
  write_preview_vhosts
  write_preview_config
}

preview_db_host_paths() {
  python3 - "$ROOT_DIR" "$PREVIEW_CONFIG" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
cfg_path = pathlib.Path(sys.argv[2])
cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
storage = cfg.get("storage") or {}
driver = str(storage.get("db_driver") or "").strip().lower()
if driver != "sqlite":
    raise SystemExit(f"preview db_driver must be sqlite, got {driver or '<empty>'}")
db_path = str(storage.get("db_path") or "").strip()
if not db_path:
    raise SystemExit("preview storage.db_path is empty")
if db_path.startswith("/"):
    raise SystemExit(f"preview storage.db_path must be relative: {db_path}")
parts = pathlib.PurePosixPath(db_path).parts
if any(part in ("", ".", "..") for part in parts):
    raise SystemExit(f"preview storage.db_path contains unsafe path segment: {db_path}")
if len(parts) < 2 or parts[0] != "logs":
    raise SystemExit(f"preview storage.db_path must be under logs/: {db_path}")
target = (root / "data" / pathlib.Path(*parts)).resolve(strict=False)
allowed = (root / "data" / "logs").resolve(strict=False)
if target != allowed and allowed not in target.parents:
    raise SystemExit(f"preview storage.db_path escapes data/logs: {db_path}")
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

ensure_preview_files() {
  mkdir -p "$(dirname "$PREVIEW_CONFIG")" "$(dirname "$PREVIEW_PROXY")" "$(dirname "$PREVIEW_INVENTORY")"
  if [[ "$UI_PREVIEW_PERSIST_VALUE" == "1" ]]; then
    [[ -f "$PREVIEW_PROXY" ]] || write_preview_proxy
    [[ -f "$PREVIEW_SCHEDULED_TASKS" ]] || write_preview_scheduled_tasks
    [[ -f "$PREVIEW_INVENTORY" ]] || write_preview_inventory
    [[ -f "$PREVIEW_VHOSTS" ]] || write_preview_vhosts
    [[ -f "$PREVIEW_CONFIG" ]] || write_preview_config
    write_preview_config "$PREVIEW_CONFIG"
    return
  fi
  reset_preview_files
}

load_preview_topology() {
  local assignments
  assignments="$(
    python3 - "$PREVIEW_CONFIG" <<'PY'
import ipaddress
import json
import pathlib
import sys

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

def parse_listen(value: str):
    value = str(value or "").strip()
    if not value:
        return None
    host = ""
    port = ""
    if value.startswith(":"):
        port = value[1:]
    elif value.startswith("["):
        idx = value.find("]")
        if idx == -1 or idx + 1 >= len(value) or value[idx + 1] != ":":
            raise ValueError(f"unsupported listener address: {value}")
        host = value[1:idx]
        port = value[idx + 2:]
    else:
        if ":" not in value:
            raise ValueError(f"listener address must include host:port or :port: {value}")
        host, port = value.rsplit(":", 1)
    if not port.isdigit():
        raise ValueError(f"listener address port must be numeric: {value}")
    port_num = int(port)
    if port_num < 1 or port_num > 65535:
        raise ValueError(f"listener address port must be between 1 and 65535: {value}")
    host = host.strip()
    if host:
        normalized = host.lower()
        if normalized == "localhost":
            raise ValueError(f"preview listener {value} uses loopback host {host}; use :{port_num} or 0.0.0.0:{port_num} instead")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and ip.is_loopback:
            raise ValueError(f"preview listener {value} uses loopback host {host}; use :{port_num} or 0.0.0.0:{port_num} instead")
    return {"host": host, "port": port_num, "raw": value}

server = parse_listen(cfg.get("server", {}).get("listen_addr", ""))
if not server:
    raise ValueError("preview config server.listen_addr is required")
admin = parse_listen(cfg.get("admin", {}).get("listen_addr", ""))
api_base_path = str(cfg.get("admin", {}).get("api_base_path", "/tukuyomi-api")).strip() or "/tukuyomi-api"
ui_base_path = str(cfg.get("admin", {}).get("ui_base_path", "/tukuyomi-ui")).strip() or "/tukuyomi-ui"
split = admin is not None
health = admin["port"] if split else server["port"]

print(f"WAF_LISTEN_PORT={server['port']}")
print(f"CORAZA_PORT={server['port']}")
print(f"WAF_HEALTHCHECK_PORT={health}")
print(f"UI_PREVIEW_PUBLIC_PORT={server['port']}")
print(f"UI_PREVIEW_PUBLIC_URL=http://127.0.0.1:{server['port']}")
print(f"UI_PREVIEW_SPLIT_ADMIN={'1' if split else '0'}")
print(f"UI_PREVIEW_ADMIN_API_PATH={api_base_path}")
print(f"UI_PREVIEW_ADMIN_UI_PATH={ui_base_path}")
if split:
    print(f"WAF_ADMIN_LISTEN_PORT={admin['port']}")
    print(f"CORAZA_ADMIN_PORT={admin['port']}")
    print(f"UI_PREVIEW_ADMIN_PORT={admin['port']}")
    print(f"UI_PREVIEW_ADMIN_UI_URL=http://127.0.0.1:{admin['port']}{ui_base_path}")
    print(f"UI_PREVIEW_ADMIN_API_URL=http://127.0.0.1:{admin['port']}{api_base_path}")
else:
    print("WAF_ADMIN_LISTEN_PORT=")
    print("CORAZA_ADMIN_PORT=")
    print("UI_PREVIEW_ADMIN_PORT=")
    print(f"UI_PREVIEW_ADMIN_UI_URL=http://127.0.0.1:{server['port']}{ui_base_path}")
    print(f"UI_PREVIEW_ADMIN_API_URL=http://127.0.0.1:{server['port']}{api_base_path}")
PY
  )" || {
    echo "[ui-preview][ERROR] failed to derive preview topology from ${PREVIEW_CONFIG}" >&2
    return 1
  }
  eval "$assignments"
}

write_preview_override() {
  rm -f "$PREVIEW_OVERRIDE"
  if [[ "${UI_PREVIEW_SPLIT_ADMIN:-0}" != "1" ]]; then
    return
  fi
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
  if [[ -f "$PREVIEW_OVERRIDE" ]]; then
    PUID="$PUID_VALUE" GUID="$GUID_VALUE" \
    WAF_CONFIG_FILE="conf/$PREVIEW_CONFIG_BASENAME" \
    WAF_LISTEN_PORT="$WAF_LISTEN_PORT" \
    WAF_HEALTHCHECK_PORT="$WAF_HEALTHCHECK_PORT" \
    CORAZA_PORT="$CORAZA_PORT" \
    WAF_ADMIN_LISTEN_PORT="${WAF_ADMIN_LISTEN_PORT:-}" \
    CORAZA_ADMIN_PORT="${CORAZA_ADMIN_PORT:-}" \
      docker compose -f "$ROOT_DIR/docker-compose.yml" -f "$PREVIEW_OVERRIDE" --profile scheduled-tasks "$action" "$@"
    return
  fi
  PUID="$PUID_VALUE" GUID="$GUID_VALUE" \
  WAF_CONFIG_FILE="conf/$PREVIEW_CONFIG_BASENAME" \
  WAF_LISTEN_PORT="$WAF_LISTEN_PORT" \
  WAF_HEALTHCHECK_PORT="$WAF_HEALTHCHECK_PORT" \
  CORAZA_PORT="$CORAZA_PORT" \
    docker compose --profile scheduled-tasks "$action" "$@"
}

cd "$ROOT_DIR"

case "${1:-}" in
  up)
    ensure_preview_files
    load_preview_topology
    write_preview_override
    if [[ "$UI_PREVIEW_PERSIST_VALUE" != "1" ]]; then
      run_preview_compose down --remove-orphans >/dev/null 2>&1 || true
      reset_preview_database
    fi
    run_preview_compose up -d --build coraza scheduled-task-runner
    echo "[ui-preview] public: ${UI_PREVIEW_PUBLIC_URL}"
    echo "[ui-preview] admin ui: ${UI_PREVIEW_ADMIN_UI_URL}"
    echo "[ui-preview] admin api: ${UI_PREVIEW_ADMIN_API_URL}"
    echo "[ui-preview] scheduled-task runner is started by ui-preview-up"
    if [[ "$UI_PREVIEW_PERSIST_VALUE" == "1" ]]; then
      echo "[ui-preview] UI_PREVIEW_PERSIST=1 keeps preview config and DB state across down/up"
    else
      echo "[ui-preview] preview config files and SQLite DB reset on each ui-preview-up"
    fi
    ;;
  down)
    if [[ -f "$PREVIEW_CONFIG" ]]; then
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
    if [[ "$UI_PREVIEW_PERSIST_VALUE" != "1" ]]; then
      if [[ -f "$PREVIEW_CONFIG" ]]; then
        reset_preview_database || true
      fi
      rm -f "$PREVIEW_CONFIG" "$PREVIEW_PROXY" "$PREVIEW_SCHEDULED_TASKS" "$PREVIEW_INVENTORY" "$PREVIEW_VHOSTS"
    fi
    echo "[ui-preview] stopped"
    ;;
  *)
    echo "usage: $0 <up|down>" >&2
    exit 1
    ;;
esac
