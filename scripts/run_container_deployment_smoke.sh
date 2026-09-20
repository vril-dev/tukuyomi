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
CONTAINER_DEPLOYMENT_ADMIN_USERNAME="${CONTAINER_DEPLOYMENT_ADMIN_USERNAME:-admin}"
CONTAINER_DEPLOYMENT_ADMIN_PASSWORD="${CONTAINER_DEPLOYMENT_ADMIN_PASSWORD:-container-deployment-smoke-admin-password}"
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
  local _

  for _ in $(seq 1 "${CONTAINER_DEPLOYMENT_WAIT_SECONDS}"); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "${expected_code}" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

expect_admin_login() {
  local expected_code="$1"
  local username="$2"
  local password="$3"
  local code

  code="$(jq -n --arg username "${username}" --arg password "${password}" \
    '{username: $username, password: $password}' | \
    curl -sS -o /dev/null -w "%{http_code}" -c "${BUILD_CONTEXT}/admin-cookies" \
      -H 'Content-Type: application/json' --data-binary @- \
      "http://127.0.0.1:${CONTAINER_DEPLOYMENT_RUNTIME_PORT}/tukuyomi-api/auth/login")"
  [[ "${code}" == "${expected_code}" ]] || fail "admin login returned ${code}, expected ${expected_code}"
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
need_cmd python3
need_cmd rsync
need_cmd install

if [[ "${CONTAINER_DEPLOYMENT_ADMIN_USERNAME}" == "admin" && "${CONTAINER_DEPLOYMENT_ADMIN_PASSWORD}" == "dev-only-change-this-password-please" ]]; then
  fail "smoke credentials must differ from the development seed credentials"
fi

BUILD_CONTEXT="$(mktemp -d "${ROOT_DIR}/.tmp-container-deployment-context.XXXXXX")"
log "staging container build context at ${BUILD_CONTEXT}"
install -d -m 755 \
  "${BUILD_CONTEXT}/server" \
  "${BUILD_CONTEXT}/web" \
  "${BUILD_CONTEXT}/data/conf" \
  "${BUILD_CONTEXT}/seeds" \
  "${BUILD_CONTEXT}/scripts" \
  "${BUILD_CONTEXT}/docs/build"
rsync -a "${ROOT_DIR}/server/" "${BUILD_CONTEXT}/server/"
rsync -a --exclude 'node_modules' --exclude 'dist' "${ROOT_DIR}/web/tukuyomi-admin/" "${BUILD_CONTEXT}/web/tukuyomi-admin/"
rsync -a --exclude 'node_modules' --exclude 'dist' "${ROOT_DIR}/web/tukuyomi-center/" "${BUILD_CONTEXT}/web/tukuyomi-center/"
rsync -a --exclude '*.bak' "${ROOT_DIR}/data/conf/" "${BUILD_CONTEXT}/data/conf/"
install -m 755 "${ROOT_DIR}/scripts/install_crs.sh" "${BUILD_CONTEXT}/scripts/install_crs.sh"
install -m 755 "${ROOT_DIR}/scripts/stage_waf_rule_assets.sh" "${BUILD_CONTEXT}/scripts/stage_waf_rule_assets.sh"
rsync -a "${ROOT_DIR}/seeds/" "${BUILD_CONTEXT}/seeds/"
install -m 644 "${ROOT_DIR}/docs/build/Dockerfile.example" "${BUILD_CONTEXT}/docs/build/Dockerfile.example"

jq \
  --arg session_secret "${CONTAINER_DEPLOYMENT_SESSION_SECRET}" \
  '.admin.session_secret = $session_secret
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

log "checking deployment image has no seeded admin users"
docker create --rm \
  --name "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" \
  --network "${CONTAINER_DEPLOYMENT_NETWORK}" \
  -p "127.0.0.1:${CONTAINER_DEPLOYMENT_RUNTIME_PORT}:9090" \
  -e "TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME=${CONTAINER_DEPLOYMENT_ADMIN_USERNAME}" \
  -e "TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD=${CONTAINER_DEPLOYMENT_ADMIN_PASSWORD}" \
  "${CONTAINER_DEPLOYMENT_IMAGE_NAME}" >/dev/null

docker cp "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}:/app/seeds/conf/config-bundle.json" "${BUILD_CONTEXT}/image-config-bundle.json"
jq -e '.domains.admin_users.users == []' "${BUILD_CONTEXT}/image-config-bundle.json" >/dev/null
install -d -m 700 "${BUILD_CONTEXT}/image-db"
docker cp "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}:/app/db/." "${BUILD_CONTEXT}/image-db/"
python3 - "${BUILD_CONTEXT}/image-db/tukuyomi.db" <<'PY'
import sqlite3
import sys

db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
try:
    count = db.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
    if count != 0:
        raise SystemExit("deployment image contains pre-created admin users")
finally:
    db.close()
PY

log "starting deployment container on 127.0.0.1:${CONTAINER_DEPLOYMENT_RUNTIME_PORT}"
docker start "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" >/dev/null

if ! wait_for_http_code "200" "http://127.0.0.1:${CONTAINER_DEPLOYMENT_RUNTIME_PORT}/healthz"; then
  fail "deployment container did not become healthy in time"
fi

log "checking runtime paths inside the deployment container"
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -x /app/tukuyomi
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -d /app/conf
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -d /app/db
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -d /app/audit
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -f /app/conf/config.json
docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" test -f /app/db/tukuyomi.db
if docker exec "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" sh -lc 'find /app/conf -type f -name "*.bak" | grep -q .'; then
  fail "deployment image still contains *.bak config files"
fi

log "checking runtime owner bootstrap and development credential rejection"
expect_admin_login "200" "${CONTAINER_DEPLOYMENT_ADMIN_USERNAME}" "${CONTAINER_DEPLOYMENT_ADMIN_PASSWORD}"
expect_admin_login "401" "admin" "dev-only-change-this-password-please"
replacement_password="container-deployment-smoke-replacement-password"
if [[ "${replacement_password}" == "${CONTAINER_DEPLOYMENT_ADMIN_PASSWORD}" ]]; then
  replacement_password="${replacement_password}-2"
fi
docker exec \
  -e "TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME=${CONTAINER_DEPLOYMENT_ADMIN_USERNAME}" \
  -e "TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD=${replacement_password}" \
  "${CONTAINER_DEPLOYMENT_CONTAINER_NAME}" /app/tukuyomi admin-bootstrap >/dev/null
expect_admin_login "200" "${CONTAINER_DEPLOYMENT_ADMIN_USERNAME}" "${CONTAINER_DEPLOYMENT_ADMIN_PASSWORD}"
expect_admin_login "401" "${CONTAINER_DEPLOYMENT_ADMIN_USERNAME}" "${replacement_password}"

log "running admin + proxy-rules smoke through deployment container"
(
  cd "${ROOT_DIR}"
  HOST_CORAZA_PORT="${CONTAINER_DEPLOYMENT_RUNTIME_PORT}" \
  WAF_LISTEN_PORT="9090" \
  WAF_API_BASEPATH="/tukuyomi-api" \
  WAF_UI_BASEPATH="/tukuyomi-ui" \
  WAF_ADMIN_USERNAME="${CONTAINER_DEPLOYMENT_ADMIN_USERNAME}" \
  WAF_ADMIN_PASSWORD="${CONTAINER_DEPLOYMENT_ADMIN_PASSWORD}" \
  PROTECTED_HOST="${PROTECTED_HOST}" \
  PROXY_ECHO_PORT="${CONTAINER_DEPLOYMENT_UPSTREAM_PORT}" \
  PROXY_ECHO_URL="http://${CONTAINER_DEPLOYMENT_UPSTREAM_NAME}:${CONTAINER_DEPLOYMENT_UPSTREAM_PORT}" \
  ./scripts/ci_proxy_admin_smoke.sh
)

log "checking persisted proxy apply and rollback audit entries"
expect_admin_login "200" "${CONTAINER_DEPLOYMENT_ADMIN_USERNAME}" "${CONTAINER_DEPLOYMENT_ADMIN_PASSWORD}"
curl -fsS -b "${BUILD_CONTEXT}/admin-cookies" \
  "http://127.0.0.1:${CONTAINER_DEPLOYMENT_RUNTIME_PORT}/tukuyomi-api/proxy-rules/audit" | \
  jq -e 'any(.entries[]; .event == "proxy_rules_apply") and any(.entries[]; .event == "proxy_rules_rollback")' >/dev/null

log "OK container deployment smoke passed"
