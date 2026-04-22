#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RELEASE_BINARY_SMOKE_ARCH="${RELEASE_BINARY_SMOKE_ARCH:-amd64}"
RELEASE_BINARY_SMOKE_SKIP_BUILD="${RELEASE_BINARY_SMOKE_SKIP_BUILD:-0}"
RELEASE_BINARY_SMOKE_AUTO_DOWN="${RELEASE_BINARY_SMOKE_AUTO_DOWN:-1}"
RELEASE_BINARY_SMOKE_KEEP_EXTRACTED="${RELEASE_BINARY_SMOKE_KEEP_EXTRACTED:-0}"
RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH="${RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH:-0}"
VERSION="${VERSION:-dev}"
APP_NAME="${APP_NAME:-tukuyomi}"
RELEASE_DIR="${RELEASE_DIR:-dist/release}"

EXTRACT_ROOT=""
BUNDLE_DIR=""

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[release-binary-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[release-binary-smoke] $*"
}

fail() {
  echo "[release-binary-smoke][ERROR] $*" >&2
  exit 1
}

detect_host_arch() {
  local machine
  machine="$(uname -m)"
  case "${machine}" in
    x86_64|amd64)
      printf 'amd64\n'
      ;;
    aarch64|arm64)
      printf 'arm64\n'
      ;;
    *)
      printf 'unknown\n'
      ;;
  esac
}

cleanup() {
  local status="$1"

  if [[ "${RELEASE_BINARY_SMOKE_AUTO_DOWN}" == "1" && -n "${BUNDLE_DIR}" && -d "${BUNDLE_DIR}/testenv/release-binary" ]]; then
    (
      cd "${BUNDLE_DIR}/testenv/release-binary"
      docker compose down --remove-orphans >/dev/null 2>&1 || true
    )
  fi

  if [[ "${RELEASE_BINARY_SMOKE_KEEP_EXTRACTED}" != "1" && -n "${EXTRACT_ROOT}" ]]; then
    rm -rf "${EXTRACT_ROOT}" >/dev/null 2>&1 || true
  fi

  if [[ "${status}" -ne 0 && -n "${BUNDLE_DIR}" ]]; then
    echo "[release-binary-smoke][ERROR] extracted bundle retained at ${BUNDLE_DIR}" >&2
  fi
}
trap 'cleanup "$?"' EXIT

need_cmd docker
need_cmd make
need_cmd tar

case "${RELEASE_BINARY_SMOKE_ARCH}" in
  amd64|arm64)
    ;;
  *)
    fail "RELEASE_BINARY_SMOKE_ARCH must be amd64 or arm64"
    ;;
esac

HOST_ARCH="$(detect_host_arch)"
if [[ "${HOST_ARCH}" != "unknown" && "${HOST_ARCH}" != "${RELEASE_BINARY_SMOKE_ARCH}" ]]; then
  if [[ "${RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH}" != "1" ]]; then
    fail "host arch is ${HOST_ARCH}, requested artifact is ${RELEASE_BINARY_SMOKE_ARCH}; use matching hardware or set RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH=1 if you intentionally want to try a cross-arch run"
  fi
  log "cross-arch run requested: host=${HOST_ARCH} artifact=${RELEASE_BINARY_SMOKE_ARCH}"
fi

TARBALL_NAME="${APP_NAME}_${VERSION}_linux_${RELEASE_BINARY_SMOKE_ARCH}.tar.gz"
TARBALL_PATH="${ROOT_DIR}/${RELEASE_DIR}/${TARBALL_NAME}"
ARCH_TARGET="release-linux-${RELEASE_BINARY_SMOKE_ARCH}"

if [[ "${RELEASE_BINARY_SMOKE_SKIP_BUILD}" != "1" ]]; then
  log "building public release tarball via make ${ARCH_TARGET} VERSION=${VERSION}"
  (
    cd "${ROOT_DIR}"
    make "${ARCH_TARGET}" VERSION="${VERSION}"
  )
else
  log "skipping release build by request"
fi

if [[ ! -f "${TARBALL_PATH}" ]]; then
  fail "missing release tarball: ${TARBALL_PATH}"
fi

EXTRACT_ROOT="$(mktemp -d "${ROOT_DIR}/.tmp-release-binary-smoke.XXXXXX")"
log "extracting ${TARBALL_NAME} into ${EXTRACT_ROOT}"
tar -xzf "${TARBALL_PATH}" -C "${EXTRACT_ROOT}"

BUNDLE_DIR="${EXTRACT_ROOT}/${APP_NAME}_${VERSION}_linux_${RELEASE_BINARY_SMOKE_ARCH}"
if [[ ! -d "${BUNDLE_DIR}" ]]; then
  fail "expected extracted bundle directory: ${BUNDLE_DIR}"
fi

[[ -f "${BUNDLE_DIR}/LICENSE" ]] || fail "missing bundled LICENSE"
[[ -f "${BUNDLE_DIR}/NOTICE" ]] || fail "missing bundled NOTICE"

log "preparing extracted release bundle"
(
  cd "${BUNDLE_DIR}"
  ./testenv/release-binary/setup.sh
)

log "starting release-binary docker testenv"
(
  cd "${BUNDLE_DIR}/testenv/release-binary"
  docker compose up -d --build
  ./smoke.sh
)

log "OK release-binary smoke passed for ${TARBALL_NAME}"
