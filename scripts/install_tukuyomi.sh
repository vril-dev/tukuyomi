#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TARGET="${TARGET:-${INSTALL_TARGET:-linux-systemd}}"
PREFIX="${PREFIX:-${INSTALL_PREFIX:-/opt/tukuyomi}}"
DESTDIR="${DESTDIR:-}"
INSTALL_ROLE="${INSTALL_ROLE:-gateway}"
INSTALL_PROCESS_MODEL="${INSTALL_PROCESS_MODEL:-}"
INSTALL_USER="${INSTALL_USER:-}"
INSTALL_GROUP="${INSTALL_GROUP:-}"
INSTALL_ENV_DIR="${INSTALL_ENV_DIR:-/etc/tukuyomi}"
INSTALL_SYSTEMD_DIR="${INSTALL_SYSTEMD_DIR:-/etc/systemd/system}"
INSTALL_SKIP_BUILD="${INSTALL_SKIP_BUILD:-0}"
INSTALL_CREATE_USER="${INSTALL_CREATE_USER:-auto}"
INSTALL_OVERWRITE_CONFIG="${INSTALL_OVERWRITE_CONFIG:-0}"
INSTALL_OVERWRITE_ENV="${INSTALL_OVERWRITE_ENV:-0}"
INSTALL_ENABLE_SYSTEMD="${INSTALL_ENABLE_SYSTEMD:-1}"
INSTALL_ENABLE_BOOT="${INSTALL_ENABLE_BOOT:-1}"
INSTALL_START="${INSTALL_START:-1}"
INSTALL_ENABLE_SCHEDULED_TASKS="${INSTALL_ENABLE_SCHEDULED_TASKS:-1}"
INSTALL_REFRESH_WAF_ASSETS="${INSTALL_REFRESH_WAF_ASSETS:-1}"
INSTALL_DB_SEED="${INSTALL_DB_SEED:-auto}"
INSTALL_DRY_RUN="${INSTALL_DRY_RUN:-0}"
CRS_VERSION="${CRS_VERSION:-v4.23.0}"

INSTALL_CONFIG_REL=""
INSTALL_ENV_BASENAME=""
INSTALL_DERIVED_PROCESS_MODEL=""
INSTALL_CENTER_CONFIG_REL="conf/config.center.json"
INSTALL_CENTER_ENV_BASENAME="tukuyomi-center.env"
INSTALL_CENTER_SERVICE_BASENAME="tukuyomi-center.service"

log() {
  echo "[install] $*"
}

die() {
  echo "[install][ERROR] $*" >&2
  exit 1
}

is_enabled() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

use_service_account() {
  [[ -z "${DESTDIR}" && -n "${INSTALL_USER}" ]]
}

install_role_is_gateway() {
  [[ "${INSTALL_ROLE}" == "gateway" ]]
}

install_role_is_center() {
  [[ "${INSTALL_ROLE}" == "center" ]]
}

install_role_is_center_protected() {
  [[ "${INSTALL_ROLE}" == "center-protected" ]]
}

install_role_includes_gateway() {
  [[ "${INSTALL_ROLE}" == "gateway" || "${INSTALL_ROLE}" == "center-protected" ]]
}

install_role_includes_center() {
  [[ "${INSTALL_ROLE}" == "center" || "${INSTALL_ROLE}" == "center-protected" ]]
}

configure_install_role() {
  case "${INSTALL_ROLE}" in
    gateway)
      INSTALL_CONFIG_REL="conf/config.json"
      INSTALL_ENV_BASENAME="tukuyomi.env"
      ;;
    center)
      INSTALL_CONFIG_REL="conf/config.center.json"
      INSTALL_ENV_BASENAME="tukuyomi-center.env"
      ;;
    center-protected)
      INSTALL_CONFIG_REL="conf/config.json"
      INSTALL_ENV_BASENAME="tukuyomi.env"
      ;;
    *)
      die "INSTALL_ROLE must be gateway, center, or center-protected"
      ;;
  esac

  if [[ -n "${INSTALL_PROCESS_MODEL}" ]]; then
    die "INSTALL_PROCESS_MODEL is no longer supported; use INSTALL_ROLE=gateway, INSTALL_ROLE=center, or INSTALL_ROLE=center-protected"
  fi
  if install_role_includes_gateway; then
    INSTALL_DERIVED_PROCESS_MODEL="supervised"
  else
    INSTALL_DERIVED_PROCESS_MODEL="single"
  fi
}

use_login_user_home_install() {
  local owner owner_home
  owner="$(invoking_user)"
  owner_home="$(home_for_user "${owner}")"
  [[ "${INSTALL_USER}" == "${owner}" ]] && path_is_under "${PREFIX}" "${owner_home}"
}

create_service_account() {
  [[ -z "${DESTDIR}" ]] && is_enabled "${INSTALL_CREATE_USER}"
}

quote_words() {
  local out=()
  local item
  for item in "$@"; do
    out+=("$(printf '%q' "${item}")")
  done
  printf '%s' "${out[*]}"
}

run_cmd() {
  log "+ $(quote_words "$@")"
  if ! is_enabled "${INSTALL_DRY_RUN}"; then
    "$@"
  fi
}

run_priv() {
  if [[ -n "${DESTDIR}" || "${EUID}" -eq 0 ]]; then
    run_cmd "$@"
    return
  fi
  command -v sudo >/dev/null 2>&1 || die "sudo is required for host install; rerun as root or set DESTDIR for staged install"
  run_cmd sudo "$@"
}

join_dest() {
  local path="$1"
  if [[ -n "${DESTDIR}" ]]; then
    printf '%s%s\n' "${DESTDIR%/}" "${path}"
  else
    printf '%s\n' "${path}"
  fi
}

migrate_config_process_model() {
  local dst="$1"
  local mode="$2"
  local process_model="$3"
  local tmp
  local changed
  tmp="$(mktemp)"
  if ! changed="$(python3 - "$dst" "$tmp" "$process_model" <<'PY'
import json
import sys

src, dst, process_model = sys.argv[1:4]
with open(src, encoding="utf-8") as fh:
    data = json.load(fh)
if not isinstance(data, dict):
    raise SystemExit("config root must be a JSON object")
runtime = data.setdefault("runtime", {})
if not isinstance(runtime, dict):
    runtime = {}
    data["runtime"] = runtime
if runtime.get("process_model") == process_model:
    raise SystemExit(0)
runtime["process_model"] = process_model
with open(dst, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")
print("changed")
PY
  )"; then
    rm -f "${tmp}"
    return 1
  fi
  if [[ "${changed}" == "changed" ]]; then
    log "update existing config runtime.process_model=${process_model}"
    run_priv install -m "${mode}" "${tmp}" "${dst}" || {
      rm -f "${tmp}"
      return 1
    }
  fi
  rm -f "${tmp}"
}

install_config_preserve() {
  local src="$1"
  local dst="$2"
  local mode="$3"
  local overwrite="$4"
  local role="$5"
  local process_model="$6"
  local tmp
  if [[ -e "${dst}" ]] && ! is_enabled "${overwrite}"; then
    log "preserve existing ${dst}"
    migrate_config_process_model "${dst}" "${mode}" "${process_model}"
    return
  fi
  tmp="$(mktemp)"
  if ! python3 - "$src" "$tmp" "$role" "$process_model" <<'PY'
import json
import secrets
import sys

src, dst, role, process_model = sys.argv[1:5]
with open(src, encoding="utf-8") as fh:
    data = json.load(fh)

admin = data.setdefault("admin", {})
if not str(admin.get("session_secret") or "").strip():
    admin["session_secret"] = secrets.token_urlsafe(48)

runtime = data.setdefault("runtime", {})
runtime["process_model"] = process_model

if role == "center":
    storage = data.setdefault("storage", {})
    storage["db_driver"] = "sqlite"
    storage["db_dsn"] = ""
    storage["db_path"] = "db/tukuyomi-center.db"

with open(dst, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")
PY
  then
    rm -f "${tmp}"
    return 1
  fi
  run_priv install -m "${mode}" "${tmp}" "${dst}" || {
    rm -f "${tmp}"
    return 1
  }
  rm -f "${tmp}"
}

render_env_preserve() {
  local src="$1"
  local dst="$2"
  local overwrite="$3"
  local tmp
  if [[ -e "${dst}" ]] && ! is_enabled "${overwrite}"; then
    log "preserve existing ${dst}"
    return
  fi
  tmp="$(mktemp)"
  if ! python3 - "$src" "$tmp" "$PREFIX" <<'PY'
import sys

src, dst, prefix = sys.argv[1:4]
with open(src, encoding="utf-8") as fh:
    data = fh.read()
data = data.replace("/opt/tukuyomi", prefix)
with open(dst, "w", encoding="utf-8") as fh:
    fh.write(data)
PY
  then
    rm -f "${tmp}"
    return 1
  fi
  run_priv install -m 640 "${tmp}" "${dst}" || {
    rm -f "${tmp}"
    return 1
  }
  rm -f "${tmp}"
}

render_systemd_unit() {
  local src="$1"
  local dst="$2"
  local env_basename="$3"
  local tmp
  tmp="$(mktemp)"
  if ! python3 - "$src" "$tmp" "$PREFIX" "$INSTALL_ENV_DIR" "$env_basename" "$INSTALL_USER" "$INSTALL_GROUP" <<'PY'
import sys

src, dst, prefix, env_dir, env_basename, user, group = sys.argv[1:8]
with open(src, encoding="utf-8") as fh:
    data = fh.read()

data = data.replace("User=tukuyomi", f"User={user}")
data = data.replace("Group=tukuyomi", f"Group={group}")
data = data.replace("WorkingDirectory=/opt/tukuyomi", f"WorkingDirectory={prefix}")
data = data.replace("EnvironmentFile=/etc/tukuyomi/tukuyomi.env", f"EnvironmentFile={env_dir}/{env_basename}")
data = data.replace("EnvironmentFile=/etc/tukuyomi/tukuyomi-center.env", f"EnvironmentFile={env_dir}/{env_basename}")
data = data.replace("ExecStart=/opt/tukuyomi/bin/tukuyomi", f"ExecStart={prefix}/bin/tukuyomi")

with open(dst, "w", encoding="utf-8") as fh:
    fh.write(data)
PY
  then
    rm -f "${tmp}"
    return 1
  fi
  run_priv install -m 644 "${tmp}" "${dst}" || {
    rm -f "${tmp}"
    return 1
  }
  rm -f "${tmp}"
}

invoking_user() {
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    printf '%s\n' "${SUDO_USER}"
    return
  fi
  id -un
}

primary_group_for_user() {
  local user="$1"
  id -gn "${user}" 2>/dev/null || printf '%s\n' "${user}"
}

home_for_user() {
  local user="$1"
  getent passwd "${user}" | awk -F: '{print $6}'
}

path_is_under() {
  local path="$1"
  local parent="$2"
  [[ -n "${parent}" ]] || return 1
  [[ "${path}" == "${parent}" || "${path}" == "${parent%/}/"* ]]
}

resolve_install_account() {
  local owner owner_home
  owner="$(invoking_user)"
  owner_home="$(home_for_user "${owner}")"

  case "${INSTALL_CREATE_USER}" in
    auto)
      if path_is_under "${PREFIX}" "${owner_home}"; then
        INSTALL_CREATE_USER=0
        if [[ -z "${INSTALL_USER}" ]]; then
          INSTALL_USER="${owner}"
        fi
      else
        INSTALL_CREATE_USER=1
        if [[ -z "${INSTALL_USER}" ]]; then
          INSTALL_USER="tukuyomi"
        fi
      fi
      ;;
    1|true|TRUE|yes|YES|on|ON)
      INSTALL_CREATE_USER=1
      if [[ -z "${INSTALL_USER}" ]]; then
        INSTALL_USER="tukuyomi"
      fi
      ;;
    0|false|FALSE|no|NO|off|OFF)
      INSTALL_CREATE_USER=0
      if [[ -z "${INSTALL_USER}" ]]; then
        INSTALL_USER="${owner}"
      fi
      ;;
    *)
      die "INSTALL_CREATE_USER must be auto, 1, or 0"
      ;;
  esac

  if [[ -z "${INSTALL_GROUP}" ]]; then
    INSTALL_GROUP="$(primary_group_for_user "${INSTALL_USER}")"
  fi
}

ensure_linux_systemd_target() {
  [[ "${TARGET}" == "linux-systemd" ]] || die "unsupported install TARGET=${TARGET}; use make deploy-render for cloud/container targets"
  [[ "${PREFIX}" == /* ]] || die "PREFIX must be absolute"
  [[ "${INSTALL_ENV_DIR}" == /* ]] || die "INSTALL_ENV_DIR must be absolute"
  [[ "${INSTALL_SYSTEMD_DIR}" == /* ]] || die "INSTALL_SYSTEMD_DIR must be absolute"
  [[ "${PREFIX}" != *[[:space:]]* ]] || die "PREFIX must not contain whitespace"
  [[ "${INSTALL_ENV_DIR}" != *[[:space:]]* ]] || die "INSTALL_ENV_DIR must not contain whitespace"
  [[ "${INSTALL_SYSTEMD_DIR}" != *[[:space:]]* ]] || die "INSTALL_SYSTEMD_DIR must not contain whitespace"
  [[ "${PREFIX}" != "/" ]] || die "PREFIX must not be /"
  [[ "${INSTALL_ENV_DIR}" != "/" ]] || die "INSTALL_ENV_DIR must not be /"
  [[ "${INSTALL_SYSTEMD_DIR}" != "/" ]] || die "INSTALL_SYSTEMD_DIR must not be /"
  [[ "${DESTDIR}" != "/" ]] || die "DESTDIR=/ is unsafe; leave DESTDIR empty for a host install"
  case "${INSTALL_DB_SEED}" in
    auto|always|never) ;;
    *) die "INSTALL_DB_SEED must be auto, always, or never" ;;
  esac
}

ensure_user_group() {
  if ! create_service_account; then
    if use_service_account || { [[ -z "${DESTDIR}" ]] && is_enabled "${INSTALL_ENABLE_SYSTEMD}"; }; then
      id -u "${INSTALL_USER}" >/dev/null 2>&1 || die "INSTALL_USER=${INSTALL_USER} does not exist; set INSTALL_CREATE_USER=1 or choose an existing user"
      getent group "${INSTALL_GROUP}" >/dev/null 2>&1 || die "INSTALL_GROUP=${INSTALL_GROUP} does not exist; set INSTALL_CREATE_USER=1 or choose an existing group"
    fi
    return
  fi
  if ! getent group "${INSTALL_GROUP}" >/dev/null 2>&1; then
    run_priv groupadd --system "${INSTALL_GROUP}"
  fi
  if ! id -u "${INSTALL_USER}" >/dev/null 2>&1; then
    run_priv useradd --system --home "${PREFIX}" --shell /usr/sbin/nologin --gid "${INSTALL_GROUP}" "${INSTALL_USER}"
  fi
}

set_runtime_permissions() {
  if ! use_service_account; then
    return
  fi
  local conf_file
  local -a config_files=()
  if install_role_includes_gateway; then
    config_files+=("${RUNTIME_DIR}/conf/config.json" "${RUNTIME_DIR}/conf/crs-disabled.conf")
  fi
  if install_role_includes_center; then
    config_files+=("${RUNTIME_DIR}/${INSTALL_CENTER_CONFIG_REL}")
  fi
  if use_login_user_home_install; then
    run_priv chown -R "${INSTALL_USER}:${INSTALL_GROUP}" "${RUNTIME_DIR}"
    run_priv chmod 755 "${RUNTIME_DIR}"
    run_priv chmod 750 "${RUNTIME_DIR}/conf"
    for conf_file in "${config_files[@]}"; do
      [[ -e "${conf_file}" ]] || continue
      if [[ -L "${conf_file}" ]]; then
        log "preserve symlink permissions for ${conf_file}"
        continue
      fi
      run_priv chmod 640 "${conf_file}"
    done
    return
  fi
  run_priv chown root:root "${RUNTIME_DIR}"
  run_priv chown -R root:root "${RUNTIME_DIR}/bin"
  if [[ -d "${RUNTIME_DIR}/scripts" ]]; then
    run_priv chown -R root:root "${RUNTIME_DIR}/scripts"
  fi
  run_priv chown root:"${INSTALL_GROUP}" "${RUNTIME_DIR}/conf"
  run_priv chmod 750 "${RUNTIME_DIR}/conf"
  for conf_file in "${config_files[@]}"; do
    [[ -e "${conf_file}" ]] || continue
    if [[ -L "${conf_file}" ]]; then
      log "preserve symlink permissions for ${conf_file}"
      continue
    fi
    run_priv chown root:"${INSTALL_GROUP}" "${conf_file}"
    run_priv chmod 640 "${conf_file}"
  done
  local writable_paths=("${RUNTIME_DIR}/db" "${RUNTIME_DIR}/audit" "${RUNTIME_DIR}/data")
  if [[ -d "${RUNTIME_DIR}/cache" ]]; then
    writable_paths+=("${RUNTIME_DIR}/cache")
  fi
  run_priv chown -R "${INSTALL_USER}:${INSTALL_GROUP}" "${writable_paths[@]}"
}

assert_runtime_accessible() {
  if ! use_service_account || is_enabled "${INSTALL_DRY_RUN}"; then
    return
  fi
  local check_script
  check_script='runtime_dir="$1"; test -x "$runtime_dir" && test -w "$runtime_dir/db"'
  if install_role_includes_gateway; then
    check_script="${check_script}"' && test -r "$runtime_dir/conf/config.json"'
  fi
  if install_role_includes_center; then
    check_script="${check_script}"' && test -r "$runtime_dir/conf/config.center.json"'
  fi
  local -a cmd=(bash -c "${check_script}" bash "${RUNTIME_DIR}")
  if [[ "${EUID}" -eq 0 && -x /sbin/runuser ]]; then
    /sbin/runuser -u "${INSTALL_USER}" -- "${cmd[@]}" || die "runtime path is not accessible to ${INSTALL_USER}: ${RUNTIME_DIR}; choose INSTALL_USER=$(invoking_user) for a home-directory PREFIX or install under /opt/tukuyomi"
    return
  fi
  if command -v runuser >/dev/null 2>&1 && [[ "${EUID}" -eq 0 ]]; then
    runuser -u "${INSTALL_USER}" -- "${cmd[@]}" || die "runtime path is not accessible to ${INSTALL_USER}: ${RUNTIME_DIR}; choose INSTALL_USER=$(invoking_user) for a home-directory PREFIX or install under /opt/tukuyomi"
    return
  fi
  command -v sudo >/dev/null 2>&1 || die "sudo is required to validate runtime access for ${INSTALL_USER}"
  sudo -H -u "${INSTALL_USER}" -- "${cmd[@]}" || die "runtime path is not accessible to ${INSTALL_USER}: ${RUNTIME_DIR}; choose INSTALL_USER=$(invoking_user) for a home-directory PREFIX or install under /opt/tukuyomi"
}

run_runtime_with_config() {
  local config_rel="$1"
  shift
  local -a env_args=("WAF_CONFIG_FILE=${config_rel}")
  while [[ "$#" -gt 0 && "$1" == *=* ]]; do
    env_args+=("$1")
    shift
  done
  local -a cmd=(env "${env_args[@]}" ./bin/tukuyomi "$@")

  log "+ (cd ${RUNTIME_DIR} && $(quote_words "${cmd[@]}"))"
  if is_enabled "${INSTALL_DRY_RUN}"; then
    return
  fi

  if ! use_service_account; then
    (cd "${RUNTIME_DIR}" && "${cmd[@]}")
    return
  fi

  if [[ "${EUID}" -eq 0 && -x /sbin/runuser ]]; then
    /sbin/runuser -u "${INSTALL_USER}" -- bash -c 'cd "$1" && shift && "$@"' bash "${RUNTIME_DIR}" "${cmd[@]}"
    return
  fi
  if command -v runuser >/dev/null 2>&1 && [[ "${EUID}" -eq 0 ]]; then
    runuser -u "${INSTALL_USER}" -- bash -c 'cd "$1" && shift && "$@"' bash "${RUNTIME_DIR}" "${cmd[@]}"
    return
  fi
  command -v sudo >/dev/null 2>&1 || die "sudo is required to run DB commands as ${INSTALL_USER}"
  sudo -H -u "${INSTALL_USER}" -- bash -c 'cd "$1" && shift && "$@"' bash "${RUNTIME_DIR}" "${cmd[@]}"
}

run_runtime() {
  run_runtime_with_config "${INSTALL_CONFIG_REL}" "$@"
}

read_storage_field() {
  local config_rel="$1"
  local field="$2"
  python3 - "$RUNTIME_DIR/${config_rel}" "$field" <<'PY'
import json
import sys

path, field = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    data = json.load(fh)
value = data.get("storage", {}).get(field, "")
print(value if value is not None else "")
PY
}

sqlite_db_exists_before_migrate() {
  local config_rel="$1"
  local driver db_path db_file
  driver="$(read_storage_field "${config_rel}" db_driver | tr '[:upper:]' '[:lower:]')"
  [[ "${driver}" == "sqlite" ]] || return 2
  db_path="$(read_storage_field "${config_rel}" db_path)"
  [[ -n "${db_path}" ]] || return 1
  if [[ "${db_path}" == /* ]]; then
    db_file="${db_path}"
  else
    db_file="${RUNTIME_DIR}/${db_path}"
  fi
  [[ -f "${db_file}" ]]
}

should_seed_db() {
  local config_rel="$1"
  case "${INSTALL_DB_SEED}" in
    always) return 0 ;;
    never) return 1 ;;
  esac

  local driver
  driver="$(read_storage_field "${config_rel}" db_driver | tr '[:upper:]' '[:lower:]')"
  if [[ "${driver}" != "sqlite" ]]; then
    log "INSTALL_DB_SEED=auto skips db-import for ${driver}; use INSTALL_DB_SEED=always for a known-empty external DB"
    return 1
  fi
  if sqlite_db_exists_before_migrate "${config_rel}"; then
    log "existing SQLite DB detected; skip db-import seed"
    return 1
  fi
  return 0
}

bootstrap_center_protected_enrollment() {
  install_role_is_center_protected || return 0
  local identity_rel="data/tmp/center-protected-device.json"
  local approved_rel="data/tmp/center-protected-approved-device.json"
  local center_url="http://127.0.0.1:9092"
  log "bootstrap center-protected Gateway enrollment"
  run_runtime bootstrap-center-protected-gateway --center-url "${center_url}" --out "${identity_rel}"
  run_runtime_with_config "${INSTALL_CENTER_CONFIG_REL}" bootstrap-center-protected-center --in "${identity_rel}" --out "${approved_rel}"
  run_runtime bootstrap-center-protected-gateway --center-url "${center_url}" --mark-approved --out "${identity_rel}"
  run_priv rm -f "${RUNTIME_DIR}/${identity_rel}" || true
  run_priv rm -f "${RUNTIME_DIR}/${approved_rel}" || true
}

build_if_needed() {
  if is_enabled "${INSTALL_SKIP_BUILD}"; then
    log "skip build by request"
    return
  fi
  run_cmd make -C "${ROOT_DIR}" build
}

write_center_protected_seed_bundle() {
  local src="${ROOT_DIR}/seeds/conf/config-bundle.json"
  local dst="${RUNTIME_DIR}/seeds/conf/config-bundle.json"
  local tmp
  tmp="$(mktemp)"
  if ! python3 - "$src" "$tmp" <<'PY'
import json
import sys

src, dst = sys.argv[1:3]
with open(src, encoding="utf-8") as fh:
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
        "url": "http://127.0.0.1:9092",
        "weight": 1,
    }
]
proxy["backend_pools"] = []
proxy["routes"] = [
    {
        "name": "center-api",
        "priority": 10,
        "match": {"path": {"type": "prefix", "value": "/center-api"}},
        "action": {"upstream": "center"},
    },
    {
        "name": "center-ui",
        "priority": 20,
        "match": {"path": {"type": "prefix", "value": "/center-ui"}},
        "action": {"upstream": "center"},
    },
]
proxy["default_route"] = None
proxy["health_check_path"] = "/healthz"
domains["proxy"] = proxy
bundle["source"] = "center-protected-seed"
with open(dst, "w", encoding="utf-8") as fh:
    json.dump(bundle, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  then
    rm -f "${tmp}"
    return 1
  fi
  run_priv install -m 644 "${tmp}" "${dst}" || {
    rm -f "${tmp}"
    return 1
  }
  rm -f "${tmp}"
}

install_files() {
  local env_dir systemd_dir
  RUNTIME_DIR="$(join_dest "${PREFIX}")"
  env_dir="$(join_dest "${INSTALL_ENV_DIR}")"
  systemd_dir="$(join_dest "${INSTALL_SYSTEMD_DIR}")"

  run_priv install -d -m 755 \
    "${RUNTIME_DIR}/bin" \
    "${RUNTIME_DIR}/conf" \
    "${RUNTIME_DIR}/db" \
    "${RUNTIME_DIR}/audit" \
    "${RUNTIME_DIR}/cache/response" \
    "${RUNTIME_DIR}/data/persistent" \
    "${RUNTIME_DIR}/data/releases" \
    "${RUNTIME_DIR}/data/run" \
    "${RUNTIME_DIR}/data/tmp" \
    "${RUNTIME_DIR}/seeds/conf" \
    "${RUNTIME_DIR}/scripts" \
    "${env_dir}"

  [[ -x "${ROOT_DIR}/bin/tukuyomi" ]] || die "missing built binary: ${ROOT_DIR}/bin/tukuyomi"
  [[ -f "${ROOT_DIR}/data/conf/config.json" ]] || die "missing bootstrap config: data/conf/config.json"
  if install_role_includes_gateway; then
    [[ -f "${ROOT_DIR}/seeds/conf/config-bundle.json" ]] || die "missing runtime seed bundle: seeds/conf/config-bundle.json"
  fi

  run_priv install -m 755 "${ROOT_DIR}/bin/tukuyomi" "${RUNTIME_DIR}/bin/tukuyomi"
  if install_role_includes_gateway; then
    run_priv install -m 755 "${ROOT_DIR}/scripts/update_country_db.sh" "${RUNTIME_DIR}/scripts/update_country_db.sh"
    run_priv cp -R "${ROOT_DIR}/seeds/conf/." "${RUNTIME_DIR}/seeds/conf/"
  fi
  if install_role_is_center_protected; then
    write_center_protected_seed_bundle
  fi
  if install_role_includes_gateway; then
    install_config_preserve "${ROOT_DIR}/data/conf/config.json" "${RUNTIME_DIR}/conf/config.json" 644 "${INSTALL_OVERWRITE_CONFIG}" "gateway" "supervised"
    render_env_preserve "${ROOT_DIR}/docs/build/tukuyomi.env.example" "${env_dir}/${INSTALL_ENV_BASENAME}" "${INSTALL_OVERWRITE_ENV}"
  fi
  if install_role_includes_center; then
    install_config_preserve "${ROOT_DIR}/data/conf/config.json" "${RUNTIME_DIR}/${INSTALL_CENTER_CONFIG_REL}" 644 "${INSTALL_OVERWRITE_CONFIG}" "center" "single"
    render_env_preserve "${ROOT_DIR}/docs/build/tukuyomi-center.env.example" "${env_dir}/${INSTALL_CENTER_ENV_BASENAME}" "${INSTALL_OVERWRITE_ENV}"
  fi

  if install_role_includes_gateway && [[ ! -e "${RUNTIME_DIR}/conf/crs-disabled.conf" ]]; then
    run_priv touch "${RUNTIME_DIR}/conf/crs-disabled.conf"
  fi

  set_runtime_permissions

  if is_enabled "${INSTALL_ENABLE_SYSTEMD}"; then
    run_priv install -d -m 755 "${systemd_dir}"
    if install_role_includes_gateway; then
      render_systemd_unit "${ROOT_DIR}/docs/build/tukuyomi.service.example" "${systemd_dir}/tukuyomi.service" "${INSTALL_ENV_BASENAME}"
      if install_role_is_gateway; then
        render_systemd_unit "${ROOT_DIR}/docs/build/tukuyomi-scheduled-tasks.service.example" "${systemd_dir}/tukuyomi-scheduled-tasks.service" "${INSTALL_ENV_BASENAME}"
        run_priv install -m 644 "${ROOT_DIR}/docs/build/tukuyomi-scheduled-tasks.timer.example" "${systemd_dir}/tukuyomi-scheduled-tasks.timer"
      fi
    fi
    if install_role_includes_center; then
      render_systemd_unit "${ROOT_DIR}/docs/build/tukuyomi-center.service.example" "${systemd_dir}/tukuyomi-center.service" "${INSTALL_CENTER_ENV_BASENAME}"
    fi
  fi
}

initialize_db() {
  if install_role_includes_center; then
    run_runtime_with_config "${INSTALL_CENTER_CONFIG_REL}" db-migrate
    if install_role_is_center; then
      log "center role skips WAF/CRS asset import and gateway DB seed"
      return
    fi
  fi

  local seed_db="0"
  if should_seed_db "${INSTALL_CONFIG_REL}"; then
    seed_db="1"
  fi

  run_runtime db-migrate

  if is_enabled "${INSTALL_REFRESH_WAF_ASSETS}"; then
    local stage_root="${RUNTIME_DIR}/data/tmp/waf-rule-assets"
    run_priv rm -rf "${stage_root}"
    run_priv install -d -m 755 "${stage_root}"
    run_priv "${ROOT_DIR}/scripts/stage_waf_rule_assets.sh" "${stage_root}" "${CRS_VERSION}"
    if use_service_account; then
      run_priv chown -R "${INSTALL_USER}:${INSTALL_GROUP}" "${stage_root}"
    fi
    run_runtime "WAF_RULE_ASSET_FS_ROOT=data/tmp/waf-rule-assets" db-import-waf-rule-assets
    run_priv rm -rf "${stage_root}"
  fi

  if [[ "${seed_db}" == "1" ]]; then
    run_runtime db-import
  fi
  bootstrap_center_protected_enrollment
}

activate_service() {
  local service="$1"
  if is_enabled "${INSTALL_ENABLE_BOOT}"; then
    run_priv systemctl enable "${service}"
  fi
  if is_enabled "${INSTALL_START}"; then
    if systemctl is-active --quiet "${service}"; then
      run_priv systemctl restart "${service}"
    else
      run_priv systemctl start "${service}"
    fi
  fi
}

activate_systemd() {
  if ! is_enabled "${INSTALL_ENABLE_SYSTEMD}" || [[ -n "${DESTDIR}" ]]; then
    return
  fi
  command -v systemctl >/dev/null 2>&1 || die "systemctl is required when INSTALL_ENABLE_SYSTEMD=1"
  run_priv systemctl daemon-reload

  if install_role_includes_center; then
    activate_service "${INSTALL_CENTER_SERVICE_BASENAME}"
  fi
  if install_role_includes_gateway; then
    activate_service "tukuyomi.service"
  fi

  if install_role_is_gateway && is_enabled "${INSTALL_ENABLE_SCHEDULED_TASKS}"; then
    if is_enabled "${INSTALL_ENABLE_BOOT}"; then
      run_priv systemctl enable tukuyomi-scheduled-tasks.timer
    fi
    if is_enabled "${INSTALL_START}"; then
      run_priv systemctl start tukuyomi-scheduled-tasks.timer
    fi
  elif is_enabled "${INSTALL_ENABLE_SCHEDULED_TASKS}"; then
    log "${INSTALL_ROLE} role does not install scheduled-task timer"
  fi
}

ensure_linux_systemd_target
configure_install_role
resolve_install_account
build_if_needed
ensure_user_group
install_files
assert_runtime_accessible
initialize_db
activate_systemd

log "completed TARGET=${TARGET} INSTALL_ROLE=${INSTALL_ROLE} PROCESS_MODEL=${INSTALL_DERIVED_PROCESS_MODEL} PREFIX=${PREFIX} INSTALL_USER=${INSTALL_USER} INSTALL_CREATE_USER=${INSTALL_CREATE_USER}${DESTDIR:+ DESTDIR=${DESTDIR}}"
