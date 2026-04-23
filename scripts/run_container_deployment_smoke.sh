#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CONTAINER_DEPLOYMENT_AUTO_DOWN="${CONTAINER_DEPLOYMENT_AUTO_DOWN:-1}"
CONTAINER_DEPLOYMENT_RUNTIME_PORT="${CONTAINER_DEPLOYMENT_RUNTIME_PORT:-19095}"
CONTAINER_DEPLOYMENT_IMAGE_NAME="${CONTAINER_DEPLOYMENT_IMAGE_NAME:-tukuyomi-container-deployment-smoke}"
CONTAINER_DEPLOYMENT_CONTAINER_NAME="${CONTAINER_DEPLOYMENT_CONTAINER_NAME:-tukuyomi-container-deployment-smoke-runtime}"
CONTAINER_DEPLOYMENT_NETWORK="${CONTAINER_DEPLOYMENT_NETWORK:-tukuyomi-container-deployment-smoke-net}"
CONTAINER_DEPLOYMENT_UPSTREAM_NAME="${CONTAINER_DEPLOYMENT_UPSTREAM_NAME:-tukuyomi-container-deployment-smoke-echo}"
CONTAINER_DEPLOYMENT_UPSTREAM_PORT="${CONTAINER_DEPLOYMENT_UPSTREAM_PORT:-18080}"
CONTAINER_DEPLOYMENT_API_KEY="${CONTAINER_DEPLOYMENT_API_KEY:-container-deployment-smoke-admin-key}"
CONTAINER_DEPLOYMENT_SESSION_SECRET="${CONTAINER_DEPLOYMENT_SESSION_SECRET:-container-deployment-smoke-session-secret}"
CONTAINER_DEPLOYMENT_WAIT_SECONDS="${CONTAINER_DEPLOYMENT_WAIT_SECONDS:-60}"
PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"

BUILD_CONTEXT=""

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
  local code=""
  local i

  for i in $(seq 1 "${CONTAINER_DEPLOYMENT_WAIT_SECONDS}"); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "${expected_code}" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

cleanup() {
  local status="$1"

  if [[ "${status}" -ne 0 ]]; then
    echo "[container-deployment-smoke][ERROR] captured runtime log:" >&2
    docker logs "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" >&2 || true
    echo "[container-deployment-smoke][ERROR] captured upstream log:" >&2
    docker logs "${CONTAINER_DEPLOYMENT_UPSTREAM_NAME}" >&2 || true
  fi

  docker rm -f "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" >/dev/null 2>&1 || true
  docker rm -f "${CONTAINER_DEPLOYMENT_UPSTREAM_NAME}" >/dev/null 2>&1 || true
  docker network rm "${CONTAINER_DEPLOYMENT_NETWORK}" >/dev/null 2>&1 || true

  if [[ "${CONTAINER_DEPLOYMENT_AUTO_DOWN}" == "1" && -n "${BUILD_CONTEXT}" ]]; then
    rm -rf "${BUILD_CONTEXT}" >/dev/null 2>&1 || true
  fi
}
trap 'cleanup "$?"' EXIT

need_cmd curl
need_cmd docker
need_cmd jq
need_cmd rsync
need_cmd install

BUILD_CONTEXT="$(mktemp -d "${ROOT_DIR}/.tmp-container-deployment-context.XXXXXX")"
log "staging container build context at ${BUILD_CONTEXT}"
install -d -m 755 \
  "${BUILD_CONTEXT}/coraza" \
  "${BUILD_CONTEXT}/web" \
  "${BUILD_CONTEXT}/data/conf" \
  "${BUILD_CONTEXT}/scripts" \
  "${BUILD_CONTEXT}/docs/build"
rsync -a "${ROOT_DIR}/coraza/" "${BUILD_CONTEXT}/coraza/"
rsync -a --exclude 'node_modules' --exclude 'dist' "${ROOT_DIR}/web/tukuyomi-admin/" "${BUILD_CONTEXT}/web/tukuyomi-admin/"
rsync -a --exclude '*.bak' "${ROOT_DIR}/data/conf/" "${BUILD_CONTEXT}/data/conf/"
install -m 755 "${ROOT_DIR}/scripts/install_crs.sh" "${BUILD_CONTEXT}/scripts/install_crs.sh"
install -m 644 "${ROOT_DIR}/docs/build/Dockerfile.example" "${BUILD_CONTEXT}/docs/build/Dockerfile.example"

jq \
  --arg api_key "${CONTAINER_DEPLOYMENT_API_KEY}" \
  --arg session_secret "${CONTAINER_DEPLOYMENT_SESSION_SECRET}" \
  '.admin.api_key_primary = $api_key
   | .admin.session_secret = $session_secret
   | .admin.api_auth_disable = false' \
  "${BUILD_CONTEXT}/data/conf/config.json" > "${BUILD_CONTEXT}/data/conf/config.json.tmp"
mv "${BUILD_CONTEXT}/data/conf/config.json.tmp" "${BUILD_CONTEXT}/data/conf/config.json"

log "building deployment image from docs/build/Dockerfile.example"
docker build -f "${BUILD_CONTEXT}/docs/build/Dockerfile.example" -t "${CONTAINER_DEPLOYMENT_IMAGE_NAME}" "${BUILD_CONTEXT}" >/dev/null

docker rm -f "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" >/dev/null 2>&1 || true
docker rm -f "${CONTAINER_DEPLOYMENT_UPSTREAM_NAME}" >/dev/null 2>&1 || true
docker network rm "${CONTAINER_DEPLOYMENT_NETWORK}" >/dev/null 2>&1 || true
docker network create "${CONTAINER_DEPLOYMENT_NETWORK}" >/dev/null

log "starting sidecar upstream on docker network ${CONTAINER_DEPLOYMENT_NETWORK}"
docker run -d --rm \
  --name "${CONTAINER_DEPLOYMENT_UPSTREAM_NAME}" \
  --network "${CONTAINER_DEPLOYMENT_NETWORK}" \
  -v "${ROOT_DIR}/scripts:/app/scripts:ro" \
  python:3.12-alpine \
  python /app/scripts/proxy_echo_server.py "${CONTAINER_DEPLOYMENT_UPSTREAM_PORT}" >/dev/null

log "starting deployment container on 127.0.0.1:${CONTAINER_DEPLOYMENT_RUNTIME_PORT}"
docker run -d --rm \
  --name "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" \
  --network "${CONTAINER_DEPLOYMENT_NETWORK}" \
  -p "127.0.0.1:${CONTAINER_DEPLOYMENT_RUNTIME_PORT}:9090" \
  "${CONTAINER_DEPLOYMENT_IMAGE_NAME}" >/dev/null

if ! wait_for_http_code "200" "http://127.0.0.1:${CONTAINER_DEPLOYMENT_RUNTIME_PORT}/healthz"; then
  fail "deployment container did not become healthy in time"
fi

log "checking runtime paths inside the deployment container"
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -x /app/tukuyomi
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -d /app/conf
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -d /app/db
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -d /app/logs
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -f /app/conf/config.json
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -f /app/db/tukuyomi.db
if docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" sh -lc 'find /app/conf -type f -name "*.bak" | grep -q .'; then
  fail "deployment image still contains *.bak config files"
fi

log "running admin + proxy-rules smoke through deployment container"
(
  cd "${ROOT_DIR}"
  HOST_CORAZA_PORT="${CONTAINER_DEPLOYMENT_RUNTIME_PORT}" \
  WAF_LISTEN_PORT="9090" \
  WAF_API_BASEPATH="/tukuyomi-api" \
  WAF_UI_BASEPATH="/tukuyomi-ui" \
  WAF_API_KEY_PRIMARY="${CONTAINER_DEPLOYMENT_API_KEY}" \
  PROTECTED_HOST="${PROTECTED_HOST}" \
  PROXY_ECHO_PORT="${CONTAINER_DEPLOYMENT_UPSTREAM_PORT}" \
  PROXY_ECHO_URL="http://${CONTAINER_DEPLOYMENT_UPSTREAM_NAME}:${CONTAINER_DEPLOYMENT_UPSTREAM_PORT}" \
  ./scripts/ci_proxy_admin_smoke.sh
)

docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -f /app/audit/proxy-rules-audit.ndjson

log "OK container deployment smoke passed"
