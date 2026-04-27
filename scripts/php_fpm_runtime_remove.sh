#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime_id="${RUNTIME:-${1:-}}"
runtime_id="$(printf '%s' "${runtime_id}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9._-')"

if [[ -z "${runtime_id}" ]]; then
  echo "[php-fpm-remove][ERROR] RUNTIME=php83|php84|php85 is required" >&2
  exit 1
fi

runtime_dir="${ROOT_DIR}/data/php-fpm/binaries/${runtime_id}"
materialized_dir="${ROOT_DIR}/data/php-fpm/runtime/${runtime_id}"
vhost_file="${ROOT_DIR}/data/php-fpm/vhosts.json"

if [[ ! -d "${runtime_dir}" ]]; then
  echo "[php-fpm-remove][ERROR] runtime ${runtime_id} is not built" >&2
  exit 1
fi

if [[ -f "${vhost_file}" ]]; then
  refs="$(RUNTIME_ID="${runtime_id}" VHOST_FILE="${vhost_file}" python3 - <<'PY'
import json
import os
import pathlib

runtime_id = os.environ["RUNTIME_ID"]
path = pathlib.Path(os.environ["VHOST_FILE"])
data = json.loads(path.read_text(encoding="utf-8"))
names = [entry.get("name", "") for entry in data.get("vhosts", []) if entry.get("runtime_id", "").strip().lower() == runtime_id]
print(",".join([name for name in names if name]))
PY
)"
  if [[ -n "${refs}" ]]; then
    echo "[php-fpm-remove][ERROR] runtime ${runtime_id} is still referenced by Runtime Apps: ${refs}" >&2
    exit 1
  fi
fi

pid_file="${materialized_dir}/php-fpm.pid"
if [[ -f "${pid_file}" ]]; then
  pid="$(tr -d '[:space:]' <"${pid_file}")"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    echo "[php-fpm-remove][ERROR] runtime ${runtime_id} is still running (pid ${pid})" >&2
    exit 1
  fi
fi

rm -rf "${runtime_dir}" "${materialized_dir}"
echo "[php-fpm-remove] removed ${runtime_id}"
