#!/usr/bin/env bash
set -euo pipefail

MIN_NODE_MAJOR=22
MIN_NODE_MINOR=12
MIN_NPM_MAJOR=10
NODE_IMAGE="${TUKUYOMI_NODE_IMAGE:-node:22-alpine}"
DOCKER_BIN="${DOCKER:-docker}"
export npm_config_update_notifier="${npm_config_update_notifier:-false}"
export npm_config_fund="${npm_config_fund:-false}"

version_part() {
  local value="${1#v}"
  local index="$2"
  IFS='.' read -r major minor patch <<<"$value"
  case "$index" in
    1) printf '%s\n' "${major:-0}" ;;
    2) printf '%s\n' "${minor:-0}" ;;
    3) printf '%s\n' "${patch:-0}" ;;
    *) printf '0\n' ;;
  esac
}

local_runtime_ok() {
  if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    return 1
  fi

  local node_version npm_version node_major node_minor npm_major
  node_version="$(node --version 2>/dev/null || true)"
  npm_version="$(npm --version 2>/dev/null || true)"
  node_major="$(version_part "$node_version" 1)"
  node_minor="$(version_part "$node_version" 2)"
  npm_major="$(version_part "$npm_version" 1)"

  [[ "$node_major" =~ ^[0-9]+$ ]] || return 1
  [[ "$node_minor" =~ ^[0-9]+$ ]] || return 1
  [[ "$npm_major" =~ ^[0-9]+$ ]] || return 1

  if (( node_major > MIN_NODE_MAJOR )); then
    (( npm_major >= MIN_NPM_MAJOR ))
    return
  fi
  if (( node_major == MIN_NODE_MAJOR && node_minor >= MIN_NODE_MINOR && npm_major >= MIN_NPM_MAJOR )); then
    return 0
  fi
  return 1
}

if local_runtime_ok; then
  exec npm "$@"
fi

if ! command -v "$DOCKER_BIN" >/dev/null 2>&1; then
  cat >&2 <<EOF
Node.js 22.12+ and npm 10+ are required for Tukuyomi UI builds.
Install Node 22, or install Docker so this wrapper can run ${NODE_IMAGE}.
EOF
  exit 127
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKDIR="$(pwd)"

case "${WORKDIR}/" in
  "${REPO_ROOT}/"*) REL_WORKDIR="${WORKDIR#${REPO_ROOT}/}" ;;
  *)
    echo "npm-node22: working directory must be inside ${REPO_ROOT}" >&2
    exit 1
    ;;
esac

if [[ "$WORKDIR" == "$REPO_ROOT" ]]; then
  REL_WORKDIR=""
fi

exec "$DOCKER_BIN" run --rm \
  -u "$(id -u):$(id -g)" \
  -v "${REPO_ROOT}:/workspace" \
  -w "/workspace/${REL_WORKDIR}" \
  -e npm_config_cache=/workspace/.npm-cache \
  -e npm_config_update_notifier=false \
  -e npm_config_fund=false \
  "$NODE_IMAGE" npm "$@"
