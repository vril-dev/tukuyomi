#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-v4.23.0}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_DIR="${ROOT_DIR}/data/rules/crs"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

archive_url="https://github.com/coreruleset/coreruleset/archive/refs/tags/${VERSION}.tar.gz"
archive_path="${tmp_dir}/crs.tar.gz"

echo "[CRS] Downloading ${VERSION} from ${archive_url}"
curl -fsSL "${archive_url}" -o "${archive_path}"

echo "[CRS] Extracting archive"
tar -xzf "${archive_path}" -C "${tmp_dir}"

src_dir="${tmp_dir}/coreruleset-${VERSION#v}"
if [[ ! -d "${src_dir}" ]]; then
  echo "[CRS] extracted directory not found: ${src_dir}" >&2
  exit 1
fi

echo "[CRS] Installing into ${DEST_DIR}"
rm -rf "${DEST_DIR}"
mkdir -p "${DEST_DIR}"
cp "${src_dir}/crs-setup.conf.example" "${DEST_DIR}/crs-setup.conf"
cp -R "${src_dir}/rules" "${DEST_DIR}/rules"
cp -R "${src_dir}/plugins" "${DEST_DIR}/plugins"

echo "[CRS] Installed ${VERSION}"
echo "[CRS] Setup file: data/rules/crs/crs-setup.conf"
echo "[CRS] Rules dir:   data/rules/crs/rules"
