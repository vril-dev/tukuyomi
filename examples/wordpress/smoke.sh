#!/usr/bin/env bash
set -euo pipefail

PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"
BASE_URL_DEFAULT="http://127.0.0.1:${NGINX_PORT:-18082}"
BASE_URL="${BASE_URL:-${BASE_URL_DEFAULT}}"
WHOAMI_PATH="${WHOAMI_PATH:-/tukuyomi-whoami.php}"
WORDPRESS_INSTALL_URL="${WORDPRESS_INSTALL_URL:-http://${PROTECTED_HOST}}"
WORDPRESS_ADMIN_USER="${WORDPRESS_ADMIN_USER:-tukuyomi}"
WORDPRESS_ADMIN_PASSWORD="${WORDPRESS_ADMIN_PASSWORD:-tukuyomi-dev-password}"
WORDPRESS_ADMIN_EMAIL="${WORDPRESS_ADMIN_EMAIL:-admin@example.test}"
tmp_body="$(mktemp)"

cleanup() {
  rm -f "${tmp_body}"
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[example-smoke][ERROR] missing command: $1" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd python3

install_wordpress_if_needed() {
  if [[ "${BASE_URL}" != "${BASE_URL_DEFAULT}" ]]; then
    return 0
  fi

  need_cmd docker

  for _ in $(seq 1 45); do
    if docker compose exec -T wordpress php -r 'exit(file_exists("/var/www/html/wp-load.php") ? 0 : 1);' >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done

  for _ in $(seq 1 45); do
    if docker compose exec \
      -T \
      -e PROTECTED_HOST="${PROTECTED_HOST}" \
      -e WORDPRESS_INSTALL_URL="${WORDPRESS_INSTALL_URL}" \
      -e WORDPRESS_ADMIN_USER="${WORDPRESS_ADMIN_USER}" \
      -e WORDPRESS_ADMIN_PASSWORD="${WORDPRESS_ADMIN_PASSWORD}" \
      -e WORDPRESS_ADMIN_EMAIL="${WORDPRESS_ADMIN_EMAIL}" \
      wordpress php <<'PHP'
<?php
$_SERVER['HTTP_HOST'] = getenv('PROTECTED_HOST') ?: 'protected.example.test';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['SERVER_NAME'] = $_SERVER['HTTP_HOST'];
$_SERVER['SERVER_PORT'] = '80';

define('WP_INSTALLING', true);

require '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';

if (!is_blog_installed()) {
    wp_install(
        'Tukuyomi Smoke',
        getenv('WORDPRESS_ADMIN_USER') ?: 'tukuyomi',
        getenv('WORDPRESS_ADMIN_EMAIL') ?: 'admin@example.test',
        true,
        '',
        getenv('WORDPRESS_ADMIN_PASSWORD') ?: 'tukuyomi-dev-password'
    );
}

$installUrl = getenv('WORDPRESS_INSTALL_URL') ?: 'http://protected.example.test';
update_option('siteurl', $installUrl);
update_option('home', $installUrl);
update_option('blog_public', '0');

echo "wordpress-ready\n";
PHP
    then
      return 0
    fi
    sleep 2
  done

  echo "[example-smoke][ERROR] wordpress auto-install did not complete in time" >&2
  return 1
}

install_wordpress_if_needed

for _ in $(seq 1 45); do
  status="$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: ${PROTECTED_HOST}" "${BASE_URL}${WHOAMI_PATH}" || true)"
  if [[ "${status}" == "200" ]]; then
    break
  fi
  sleep 2
done
if [[ "${status:-}" != "200" ]]; then
  echo "[example-smoke][ERROR] wordpress example did not become ready at ${BASE_URL}${WHOAMI_PATH}" >&2
  exit 1
fi

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" -H "Host: ${PROTECTED_HOST}" "${BASE_URL}${WHOAMI_PATH}")"
if [[ "${status}" != "200" ]]; then
  echo "[example-smoke][ERROR] whoami request failed: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi

python3 - "${PROTECTED_HOST}" "${tmp_body}" <<'PY'
import json
import pathlib
import sys

expected_host = sys.argv[1]
payload = json.loads(pathlib.Path(sys.argv[2]).read_text())

if payload.get("host") != expected_host:
    raise SystemExit(f"expected host={expected_host!r}, got {payload.get('host')!r}")
PY

status="$(curl -sS -o "${tmp_body}" -w "%{http_code}" -H "Host: ${PROTECTED_HOST}" "${BASE_URL}${WHOAMI_PATH}?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")"
if [[ "${status}" != "403" ]]; then
  echo "[example-smoke][ERROR] expected WAF block for protected host, got: ${status}" >&2
  cat "${tmp_body}" >&2 || true
  exit 1
fi

echo "[example-smoke][OK] protected host smoke passed for ${PROTECTED_HOST} via ${BASE_URL}"
