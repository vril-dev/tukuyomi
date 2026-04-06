#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: run_container_deployment_smoke.sh [api-gateway]" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLE_NAME="${1:-api-gateway}"
PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
CONTAINER_DEPLOYMENT_APP_PORT="${CONTAINER_DEPLOYMENT_APP_PORT:-18091}"
CONTAINER_DEPLOYMENT_RUNTIME_PORT="${CONTAINER_DEPLOYMENT_RUNTIME_PORT:-19095}"
CONTAINER_DEPLOYMENT_API_KEY="${CONTAINER_DEPLOYMENT_API_KEY:-container-deployment-smoke-primary-key}"
CONTAINER_DEPLOYMENT_AUTO_DOWN="${CONTAINER_DEPLOYMENT_AUTO_DOWN:-1}"
RUNTIME_BASE_URL="http://127.0.0.1:${CONTAINER_DEPLOYMENT_RUNTIME_PORT}"

APP_CONTAINER_NAME=""
RUNTIME_CONTAINER_NAME=""

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[container-deployment-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[container-deployment-smoke] $*"
}

fail() {
  echo "[container-deployment-smoke][ERROR] $*" >&2
  exit 1
}

wait_for_http_code() {
  local expected_code="$1"
  local url="$2"
  local i
  local code=""

  for i in $(seq 1 "${WAIT_TIMEOUT_SECONDS}"); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "${expected_code}" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

curl_expect_200() {
  local url="$1"
  shift
  local tmp_body
  local code
  tmp_body="$(mktemp)"
  code="$(curl -sS -o "${tmp_body}" -w "%{http_code}" "$@" "${url}" || true)"
  if [[ "${code}" != "200" ]]; then
    cat "${tmp_body}" >&2 || true
    rm -f "${tmp_body}"
    fail "expected 200 from ${url}, got ${code}"
  fi
  rm -f "${tmp_body}"
}

cleanup() {
  local status="$1"

  if [[ "${status}" -ne 0 && -n "${RUNTIME_CONTAINER_NAME}" ]]; then
    echo "[container-deployment-smoke][ERROR] captured container log:" >&2
    docker logs "${RUNTIME_CONTAINER_NAME}" >&2 || true
  fi

  if [[ -n "${RUNTIME_CONTAINER_NAME}" ]]; then
    docker rm -f "${RUNTIME_CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${APP_CONTAINER_NAME}" ]]; then
    docker rm -f "${APP_CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
}
trap 'cleanup "$?"' EXIT

need_cmd curl
need_cmd docker

if [[ "${EXAMPLE_NAME}" != "api-gateway" ]]; then
  fail "unsupported example for container deployment smoke: ${EXAMPLE_NAME}"
fi

APP_IMAGE_NAME="tukuyomi-container-smoke-${EXAMPLE_NAME}"
APP_CONTAINER_NAME="tukuyomi-container-smoke-${EXAMPLE_NAME}-app"
RUNTIME_IMAGE_NAME="tukuyomi-container-deploy-smoke"
RUNTIME_CONTAINER_NAME="tukuyomi-container-deploy-smoke-runtime"

log "building ${EXAMPLE_NAME} app image"
docker build -t "${APP_IMAGE_NAME}" "${ROOT_DIR}/examples/${EXAMPLE_NAME}/api" >/dev/null

log "starting ${EXAMPLE_NAME} app container on 127.0.0.1:${CONTAINER_DEPLOYMENT_APP_PORT}"
docker rm -f "${APP_CONTAINER_NAME}" >/dev/null 2>&1 || true
docker run -d --rm \
  --name "${APP_CONTAINER_NAME}" \
  -p "127.0.0.1:${CONTAINER_DEPLOYMENT_APP_PORT}:8080" \
  "${APP_IMAGE_NAME}" >/dev/null

if ! wait_for_http_code "200" "http://127.0.0.1:${CONTAINER_DEPLOYMENT_APP_PORT}/v1/health"; then
  docker logs "${APP_CONTAINER_NAME}" >&2 || true
  fail "example app did not become healthy in time"
fi

log "building deployment image from docs/build/Dockerfile.example"
docker build -f "${ROOT_DIR}/docs/build/Dockerfile.example" -t "${RUNTIME_IMAGE_NAME}" "${ROOT_DIR}" >/dev/null

log "starting deployment image on 127.0.0.1:${CONTAINER_DEPLOYMENT_RUNTIME_PORT}"
docker rm -f "${RUNTIME_CONTAINER_NAME}" >/dev/null 2>&1 || true
docker run -d --rm \
  --name "${RUNTIME_CONTAINER_NAME}" \
  --add-host host.docker.internal:host-gateway \
  -p "127.0.0.1:${CONTAINER_DEPLOYMENT_RUNTIME_PORT}:9090" \
  -e "WAF_APP_URL=http://host.docker.internal:${CONTAINER_DEPLOYMENT_APP_PORT}" \
  -e "WAF_API_KEY_PRIMARY=${CONTAINER_DEPLOYMENT_API_KEY}" \
  "${RUNTIME_IMAGE_NAME}" >/dev/null

if ! wait_for_http_code "200" "${RUNTIME_BASE_URL}/healthz"; then
  fail "deployment container did not become healthy in time"
fi

log "checking admin UI and admin API"
curl_expect_200 "${RUNTIME_BASE_URL}/tukuyomi-admin/"
curl_expect_200 "${RUNTIME_BASE_URL}/tukuyomi-api/status" -H "X-API-Key: ${CONTAINER_DEPLOYMENT_API_KEY}"

log "checking runtime paths inside the container"
docker exec "${RUNTIME_CONTAINER_NAME}" test -d /app/conf
docker exec "${RUNTIME_CONTAINER_NAME}" test -d /app/rules
docker exec "${RUNTIME_CONTAINER_NAME}" test -d /app/logs
docker exec "${RUNTIME_CONTAINER_NAME}" test -f /app/rules/tukuyomi.conf
docker exec "${RUNTIME_CONTAINER_NAME}" test -f /app/conf/waf.bypass
docker exec "${RUNTIME_CONTAINER_NAME}" test -f /app/conf/log-output.json

log "running protected-host smoke through deployment container"
(
  cd "${ROOT_DIR}/examples/${EXAMPLE_NAME}"
  PROTECTED_HOST="${PROTECTED_HOST}" \
  BASE_URL="${RUNTIME_BASE_URL}" \
  ./smoke.sh
)

log "OK container deployment smoke passed"
