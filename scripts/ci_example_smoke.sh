#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: ci_example_smoke.sh <example-name>" >&2
  exit 1
fi

example_name="$1"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
example_dir="${repo_root}/examples/${example_name}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[ci-example-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

if [ ! -d "${example_dir}" ]; then
  echo "[ci-example-smoke][ERROR] unknown example: ${example_name}" >&2
  exit 1
fi

if [ ! -x "${example_dir}/smoke.sh" ]; then
  echo "[ci-example-smoke][ERROR] example has no executable smoke.sh: ${example_dir}" >&2
  exit 1
fi

need_cmd docker

export COMPOSE_PROJECT_NAME="tukuyomi-${example_name//[^a-zA-Z0-9]/}-smoke"
export PUID="${PUID:-$(id -u)}"
export GUID="${GUID:-$(id -g)}"
export FRONT_PROXY_TRUSTED_PROXY_CIDRS="${FRONT_PROXY_TRUSTED_PROXY_CIDRS:-127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"

prepare_example_dirs() {
  mkdir -p \
    "${example_dir}/data/logs/nginx" \
    "${example_dir}/data/logs/coraza" \
    "${example_dir}/data/logs/openresty"
}

cleanup() {
  status="$1"
  if [ "$status" -ne 0 ]; then
    echo "[ci-example-smoke][ERROR] ${example_name} smoke failed; collecting docker diagnostics" >&2
    (
      cd "${example_dir}"
      docker compose ps -a >&2 || true
      docker compose logs --no-color >&2 || true
    )
  fi
  (
    cd "${example_dir}"
    docker compose --profile front-proxy down --remove-orphans >/dev/null 2>&1 || true
  )
}
trap 'cleanup "$?"' EXIT

(
  cd "${example_dir}"
  ./setup.sh
  prepare_example_dirs
  WAF_TRUSTED_PROXY_CIDRS="${FRONT_PROXY_TRUSTED_PROXY_CIDRS}" \
  WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true \
  docker compose --profile front-proxy up -d --build
  EXAMPLE_TOPOLOGY=front ./smoke.sh
)

echo "[ci-example-smoke][OK] ${example_name} protected-host smoke passed"
