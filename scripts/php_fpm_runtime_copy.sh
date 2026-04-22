#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime_id="${RUNTIME:-${1:-}}"
runtime_id="$(printf '%s' "${runtime_id}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9._-')"
dest_dir="${DEST:-${DEST_DIR:-${2:-/opt/tukuyomi}}}"

if [[ -z "${runtime_id}" ]]; then
  echo "[php-fpm-copy][ERROR] RUNTIME=php83|php84|php85 is required" >&2
  exit 1
fi
if [[ -z "${dest_dir}" ]]; then
  echo "[php-fpm-copy][ERROR] DEST or DEST_DIR is required" >&2
  exit 1
fi

dest_dir="${dest_dir%/}"
if [[ -z "${dest_dir}" || "${dest_dir}" == "/" ]]; then
  echo "[php-fpm-copy][ERROR] destination must be a specific deployment root, not /" >&2
  exit 1
fi

if ! command -v rsync >/dev/null 2>&1; then
  echo "[php-fpm-copy][ERROR] rsync is required" >&2
  exit 1
fi

src_dir="${ROOT_DIR}/data/php-fpm/binaries/${runtime_id}"
dest_php_dir="${dest_dir}/data/php-fpm"
dest_runtime_dir="${dest_php_dir}/binaries/${runtime_id}"
inventory_file="${dest_php_dir}/inventory.json"
vhosts_file="${dest_php_dir}/vhosts.json"

if [[ ! -d "${src_dir}" ]]; then
  echo "[php-fpm-copy][ERROR] runtime ${runtime_id} is not built under data/php-fpm/binaries" >&2
  exit 1
fi
if [[ ! -d "${dest_dir}" ]]; then
  echo "[php-fpm-copy][ERROR] destination root ${dest_dir} does not exist" >&2
  exit 1
fi
if [[ ! -d "${dest_dir}/bin" ]] || [[ ! -d "${dest_dir}/conf" ]]; then
  echo "[php-fpm-copy][ERROR] destination ${dest_dir} does not look like a tukuyomi runtime tree" >&2
  echo "[php-fpm-copy][ERROR] expected at least ${dest_dir}/bin and ${dest_dir}/conf" >&2
  exit 1
fi

mkdir -p "${dest_php_dir}/binaries" "${dest_php_dir}/runtime"
rsync -a --delete "${src_dir}/" "${dest_runtime_dir}/"

if [[ ! -f "${inventory_file}" ]]; then
  printf '{}\n' >"${inventory_file}"
fi
if [[ ! -f "${vhosts_file}" ]]; then
  printf '{\n  "vhosts": []\n}\n' >"${vhosts_file}"
fi

echo "[php-fpm-copy] staged ${runtime_id} -> ${dest_runtime_dir}"
