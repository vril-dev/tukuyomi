#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <destination_dir> [version]" >&2
  exit 1
fi

DEST_DIR="$1"
VERSION="${2:-v4.23.0}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

ARCHIVE_URL="https://github.com/coreruleset/coreruleset/archive/refs/tags/${VERSION}.tar.gz"
ARCHIVE_PATH="${TMP_DIR}/crs.tar.gz"

echo "[CRS] Downloading ${VERSION} from ${ARCHIVE_URL}"
curl -fsSL "${ARCHIVE_URL}" -o "${ARCHIVE_PATH}"

echo "[CRS] Extracting archive"
tar -xzf "${ARCHIVE_PATH}" -C "${TMP_DIR}"

SRC_DIR="${TMP_DIR}/coreruleset-${VERSION#v}"
if [[ ! -d "${SRC_DIR}" ]]; then
  echo "[CRS] extracted directory not found: ${SRC_DIR}" >&2
  exit 1
fi

echo "[CRS] Installing into ${DEST_DIR}"
rm -rf "${DEST_DIR}"
mkdir -p "${DEST_DIR}"
cp "${SRC_DIR}/crs-setup.conf.example" "${DEST_DIR}/crs-setup.conf"
cp -R "${SRC_DIR}/rules" "${DEST_DIR}/rules"
cp -R "${SRC_DIR}/plugins" "${DEST_DIR}/plugins"

echo "[CRS] Installed ${VERSION}"
echo "[CRS] Setup file: ${DEST_DIR}/crs-setup.conf"
echo "[CRS] Rules dir:   ${DEST_DIR}/rules"
