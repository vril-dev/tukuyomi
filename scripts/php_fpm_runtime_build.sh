#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="${ROOT_DIR}/build/Dockerfile.php-fpm-runtime"
VER="${VER:-}"
RUNTIME_ID="${RUNTIME:-}"
ARG1="${1:-}"

runtime_to_ver() {
  case "${1}" in
    php83) printf '8.3\n' ;;
    php84) printf '8.4\n' ;;
    php85) printf '8.5\n' ;;
    *)
      echo "[php-fpm-build][ERROR] unsupported RUNTIME=${1} (expected php83, php84, or php85)" >&2
      exit 1
      ;;
  esac
}

if [[ -z "${VER}" ]]; then
  if [[ -n "${RUNTIME_ID}" ]]; then
    VER="$(runtime_to_ver "${RUNTIME_ID}")"
  elif [[ -n "${ARG1}" ]]; then
    case "${ARG1}" in
      php83|php84|php85)
        VER="$(runtime_to_ver "${ARG1}")"
        ;;
      *)
        VER="${ARG1}"
        ;;
    esac
  else
    VER="8.3"
  fi
fi

case "${VER}" in
  8.3|8.4|8.5) ;;
  *)
    echo "[php-fpm-build][ERROR] unsupported VER=${VER} (expected 8.3, 8.4, or 8.5)" >&2
    exit 1
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "[php-fpm-build][ERROR] docker is required" >&2
  exit 1
fi

runtime_id="php${VER/./}"
runtime_dir="${ROOT_DIR}/data/php-fpm/binaries/${runtime_id}"
rootfs_dir="${runtime_dir}/rootfs"
image_tag="tukuyomi/php-fpm-runtime:${runtime_id}-local"
container_name=""

cleanup() {
  if [[ -n "${container_name}" ]]; then
    docker rm -f "${container_name}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

flatten_arch_lib_dir() {
  local from_dir="$1"
  local to_dir="$2"
  local subdir
  local source_path
  local base_name

  [[ -d "${from_dir}" && -d "${to_dir}" ]] || return 0
  subdir="$(basename "${from_dir}")"

  while IFS= read -r source_path; do
    base_name="$(basename "${source_path}")"
    if [[ -e "${to_dir}/${base_name}" || -L "${to_dir}/${base_name}" ]]; then
      continue
    fi
    ln -s "${subdir}/${base_name}" "${to_dir}/${base_name}"
  done < <(find "${from_dir}" -maxdepth 1 \( -type f -o -type l \) | sort)
}

rm -rf "${runtime_dir}"
mkdir -p "${rootfs_dir}"

docker build \
  --build-arg "PHP_VERSION=${VER}" \
  -f "${DOCKERFILE}" \
  -t "${image_tag}" \
  "${ROOT_DIR}" >/dev/null

container_name="$(docker create "${image_tag}")"
docker export "${container_name}" | tar -C "${rootfs_dir}" -xf -

flatten_arch_lib_dir "${rootfs_dir}/lib/x86_64-linux-gnu" "${rootfs_dir}/lib"
flatten_arch_lib_dir "${rootfs_dir}/usr/lib/x86_64-linux-gnu" "${rootfs_dir}/usr/lib"
flatten_arch_lib_dir "${rootfs_dir}/lib/aarch64-linux-gnu" "${rootfs_dir}/lib"
flatten_arch_lib_dir "${rootfs_dir}/usr/lib/aarch64-linux-gnu" "${rootfs_dir}/usr/lib"

version_line="$(docker run --rm "${image_tag}" php -r 'echo PHP_VERSION;')"
modules_raw="$(docker run --rm "${image_tag}" php -m)"

MODULES_RAW="${modules_raw}" python3 - <<'PY' >"${runtime_dir}/modules.json"
import json
import os

modules = []
seen = set()
for line in os.environ.get("MODULES_RAW", "").splitlines():
    line = line.strip()
    if not line or line.startswith("["):
        continue
    line = line.lower()
    if line in seen:
        continue
    seen.add(line)
    modules.append(line)
json.dump(modules, fp=os.sys.stdout, indent=2)
os.sys.stdout.write("\n")
PY

cat >"${runtime_dir}/runtime.json" <<EOF
{
  "runtime_id": "${runtime_id}",
  "display_name": "PHP ${VER}",
  "detected_version": "${version_line}",
  "binary_path": "data/php-fpm/binaries/${runtime_id}/php-fpm",
  "cli_binary_path": "data/php-fpm/binaries/${runtime_id}/php",
  "source": "bundled"
}
EOF

cat >"${runtime_dir}/php-fpm" <<'EOF'
#!/usr/bin/env sh
set -eu

SELF_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
ROOTFS="${SELF_DIR}/rootfs"

find_loader() {
  for candidate in \
    "${ROOTFS}/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" \
    "${ROOTFS}/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" \
    "${ROOTFS}/lib64/ld-linux-x86-64.so.2" \
    "${ROOTFS}/lib/ld-linux-aarch64.so.1" \
    "${ROOTFS}/lib/ld-musl-x86_64.so.1" \
    "${ROOTFS}/lib/ld-musl-aarch64.so.1"
  do
    if [ -x "${candidate}" ]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  found="$(find "${ROOTFS}" -maxdepth 4 -type f \( -name 'ld-linux-*.so.*' -o -name 'ld-musl-*.so.1' \) | sort | head -n 1)"
  if [ -n "${found}" ]; then
    printf '%s\n' "${found}"
    return 0
  fi
  return 1
}

LOADER="$(find_loader || true)"
if [ -z "${LOADER}" ]; then
  echo "[php-fpm-wrapper][ERROR] dynamic loader not found in ${ROOTFS}" >&2
  exit 1
fi

BIN=""
for candidate in \
  "${ROOTFS}/usr/local/sbin/php-fpm" \
  "${ROOTFS}/usr/sbin/php-fpm"
do
  if [ -x "${candidate}" ]; then
    BIN="${candidate}"
    break
  fi
done
if [ -z "${BIN}" ]; then
  echo "[php-fpm-wrapper][ERROR] php-fpm binary not found in ${ROOTFS}" >&2
  exit 1
fi

LIB_PATH=""
for dir in \
  "${ROOTFS}/lib" \
  "${ROOTFS}/lib64" \
  "${ROOTFS}/usr/lib" \
  "${ROOTFS}/usr/local/lib"
do
  if [ -d "${dir}" ]; then
    if [ -n "${LIB_PATH}" ]; then
      LIB_PATH="${LIB_PATH}:"
    fi
    LIB_PATH="${LIB_PATH}${dir}"
  fi
done

export PHPRC="${ROOTFS}/usr/local/etc/php"
export PHP_INI_SCAN_DIR="${ROOTFS}/usr/local/etc/php/conf.d"
export PATH="${ROOTFS}/usr/local/bin:${ROOTFS}/usr/local/sbin:${PATH}"

PHP_INI_FILE=""
for candidate in \
  "${ROOTFS}/usr/local/etc/php/php.ini" \
  "${ROOTFS}/usr/local/etc/php/php.ini-production" \
  "${ROOTFS}/usr/local/etc/php/php.ini-development"
do
  if [ -f "${candidate}" ]; then
    PHP_INI_FILE="${candidate}"
    break
  fi
done

EXTENSION_DIR=""
for candidate in $(find "${ROOTFS}/usr/local/lib/php/extensions" -mindepth 1 -maxdepth 1 -type d | sort)
do
  EXTENSION_DIR="${candidate}"
  break
done

if [ -n "${PHP_INI_FILE}" ]; then
  set -- -c "${PHP_INI_FILE}" "$@"
fi
if [ -n "${EXTENSION_DIR}" ]; then
  set -- -d "extension_dir=${EXTENSION_DIR}" "$@"
fi

exec "${LOADER}" --library-path "${LIB_PATH}" "${BIN}" "$@"
EOF
chmod 755 "${runtime_dir}/php-fpm"

cat >"${runtime_dir}/php" <<'EOF'
#!/usr/bin/env sh
set -eu

SELF_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
ROOTFS="${SELF_DIR}/rootfs"

find_loader() {
  for candidate in \
    "${ROOTFS}/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" \
    "${ROOTFS}/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" \
    "${ROOTFS}/lib64/ld-linux-x86-64.so.2" \
    "${ROOTFS}/lib/ld-linux-aarch64.so.1" \
    "${ROOTFS}/lib/ld-musl-x86_64.so.1" \
    "${ROOTFS}/lib/ld-musl-aarch64.so.1"
  do
    if [ -x "${candidate}" ]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  found="$(find "${ROOTFS}" -maxdepth 4 -type f \( -name 'ld-linux-*.so.*' -o -name 'ld-musl-*.so.1' \) | sort | head -n 1)"
  if [ -n "${found}" ]; then
    printf '%s\n' "${found}"
    return 0
  fi
  return 1
}

LOADER="$(find_loader || true)"
if [ -z "${LOADER}" ]; then
  echo "[php-wrapper][ERROR] dynamic loader not found in ${ROOTFS}" >&2
  exit 1
fi

BIN=""
for candidate in \
  "${ROOTFS}/usr/local/bin/php" \
  "${ROOTFS}/usr/bin/php"
do
  if [ -x "${candidate}" ]; then
    BIN="${candidate}"
    break
  fi
done
if [ -z "${BIN}" ]; then
  echo "[php-wrapper][ERROR] php binary not found in ${ROOTFS}" >&2
  exit 1
fi

LIB_PATH=""
for dir in \
  "${ROOTFS}/lib" \
  "${ROOTFS}/lib64" \
  "${ROOTFS}/usr/lib" \
  "${ROOTFS}/usr/local/lib"
do
  if [ -d "${dir}" ]; then
    if [ -n "${LIB_PATH}" ]; then
      LIB_PATH="${LIB_PATH}:"
    fi
    LIB_PATH="${LIB_PATH}${dir}"
  fi
done

export PHPRC="${ROOTFS}/usr/local/etc/php"
export PHP_INI_SCAN_DIR="${ROOTFS}/usr/local/etc/php/conf.d"
export PATH="${ROOTFS}/usr/local/bin:${ROOTFS}/usr/local/sbin:${PATH}"

PHP_INI_FILE=""
for candidate in \
  "${ROOTFS}/usr/local/etc/php/php.ini" \
  "${ROOTFS}/usr/local/etc/php/php.ini-production" \
  "${ROOTFS}/usr/local/etc/php/php.ini-development"
do
  if [ -f "${candidate}" ]; then
    PHP_INI_FILE="${candidate}"
    break
  fi
done

EXTENSION_DIR=""
for candidate in $(find "${ROOTFS}/usr/local/lib/php/extensions" -mindepth 1 -maxdepth 1 -type d | sort)
do
  EXTENSION_DIR="${candidate}"
  break
done

if [ -n "${PHP_INI_FILE}" ]; then
  set -- -c "${PHP_INI_FILE}" "$@"
fi
if [ -n "${EXTENSION_DIR}" ]; then
  set -- -d "extension_dir=${EXTENSION_DIR}" "$@"
fi

exec "${LOADER}" --library-path "${LIB_PATH}" "${BIN}" "$@"
EOF
chmod 755 "${runtime_dir}/php"

echo "[php-fpm-build] built ${runtime_id} -> data/php-fpm/binaries/${runtime_id}"
