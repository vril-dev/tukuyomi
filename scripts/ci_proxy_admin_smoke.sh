#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/proxy_api.sh
source "${SCRIPT_DIR}/lib/proxy_api.sh"

proxy_api_init
proxy_api_need_cmd curl
proxy_api_need_cmd jq
proxy_api_need_cmd python3

PROXY_ECHO_PORT="${PROXY_ECHO_PORT:-18080}"
PROXY_ECHO_URL="${PROXY_ECHO_URL:-http://127.0.0.1:${PROXY_ECHO_PORT}}"
PROTECTED_HOST="${PROTECTED_HOST:-protected.example.test}"
PROXY_COOKIE_JAR="$(mktemp)"
proxy_route_headers="/tmp/proxy_route_headers.txt"
proxy_route_body="/tmp/proxy_route_body.json"
proxy_route_gzip_body="/tmp/proxy_route_body.json.gz"
proxy_session_body="/tmp/proxy_session_resp.json"

cleanup() {
  proxy_api_cleanup
  rm -f \
    "${proxy_route_headers}" \
    "${proxy_route_body}" \
    "${proxy_route_gzip_body}" \
    "${proxy_session_body}" \
    /tmp/proxy_validate_resp.json \
    /tmp/proxy_probe_resp.json \
    /tmp/proxy_dry_run_resp.json \
    /tmp/proxy_route_validate_resp.json \
    /tmp/proxy_route_dry_run_resp.json \
    /tmp/proxy_put_resp.json \
    /tmp/proxy_conflict_resp.json \
    /tmp/proxy_rollback_resp.json \
    /tmp/proxy_logout_status_resp.json
  if [[ -n "${UPSTREAM_PID:-}" ]]; then
    if kill -0 "${UPSTREAM_PID}" >/dev/null 2>&1; then
      kill "${UPSTREAM_PID}" >/dev/null 2>&1 || true
      wait "${UPSTREAM_PID}" >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT

if ! curl -fsS "http://127.0.0.1:${PROXY_ECHO_PORT}/healthz" >/dev/null 2>&1; then
  python3 "${SCRIPT_DIR}/proxy_echo_server.py" "${PROXY_ECHO_PORT}" >/tmp/proxy_echo.log 2>&1 &
  UPSTREAM_PID=$!
fi

proxy_api_wait_health

proxy_api_expect_http_code "GET" "${PROXY_UI_URL}" "200"
proxy_api_expect_http_code "HEAD" "${PROXY_UI_URL}" "200"
proxy_api_expect_http_code "HEAD" "${PROXY_UI_URL}/" "200"
proxy_api_login_session

session_code="$(curl -sS -o "${proxy_session_body}" -w "%{http_code}" \
  -b "${PROXY_COOKIE_JAR}" -c "${PROXY_COOKIE_JAR}" \
  "${PROXY_API_URL}/auth/session")"
if [[ "${session_code}" != "200" ]]; then
  echo "[proxy-smoke][ERROR] auth/session failed after login: ${session_code}" >&2
  cat "${proxy_session_body}" >&2 || true
  exit 1
fi
if ! jq -e '.authenticated == true and .mode == "session"' "${proxy_session_body}" >/dev/null; then
  echo "[proxy-smoke][ERROR] auth/session response missing session state" >&2
  cat "${proxy_session_body}" >&2 || true
  exit 1
fi

proxy_get_json="$(proxy_api_get_snapshot)"
etag="$(jq -r '.etag // empty' <<<"${proxy_get_json}")"
raw="$(jq -r '.raw // empty' <<<"${proxy_get_json}")"

if [[ -z "${etag}" || -z "${raw}" ]]; then
  echo "[proxy-smoke][ERROR] proxy-rules response missing etag/raw" >&2
  exit 1
fi

validate_body="$(jq -n --arg raw "${raw}" '{raw: $raw}')"
proxy_api_set_admin_auth_args
validate_code="$(curl -sS -o /tmp/proxy_validate_resp.json -w "%{http_code}" \
  "${PROXY_ADMIN_AUTH_ARGS[@]}" -H "Content-Type: application/json" \
  -X POST --data "${validate_body}" "${PROXY_API_URL}/proxy-rules/validate")"
if [[ "${validate_code}" != "200" ]]; then
  echo "[proxy-smoke][ERROR] validate failed: ${validate_code}" >&2
  cat /tmp/proxy_validate_resp.json >&2 || true
  exit 1
fi

probe_raw="$(jq --arg upstream "http://127.0.0.1:${WAF_LISTEN_PORT}" \
  '.upstreams = [{"name":"probe","url":$upstream,"weight":1,"enabled":true}]' <<<"${raw}")"
probe_body="$(jq -n --arg raw "${probe_raw}" --argjson timeout_ms 1000 '{raw: $raw, timeout_ms: $timeout_ms}')"
proxy_api_set_admin_auth_args
probe_code="$(curl -sS -o /tmp/proxy_probe_resp.json -w "%{http_code}" \
  "${PROXY_ADMIN_AUTH_ARGS[@]}" -H "Content-Type: application/json" \
  -X POST --data "${probe_body}" "${PROXY_API_URL}/proxy-rules/probe")"
if [[ "${probe_code}" != "200" ]]; then
  echo "[proxy-smoke][ERROR] probe failed: ${probe_code}" >&2
  cat /tmp/proxy_probe_resp.json >&2 || true
  exit 1
fi

dry_run_body="$(jq -n --arg raw "${probe_raw}" --arg host "example.test" --arg path "/healthz" '{raw: $raw, host: $host, path: $path}')"
proxy_api_set_admin_auth_args
dry_run_code="$(curl -sS -o /tmp/proxy_dry_run_resp.json -w "%{http_code}" \
  "${PROXY_ADMIN_AUTH_ARGS[@]}" -H "Content-Type: application/json" \
  -X POST --data "${dry_run_body}" "${PROXY_API_URL}/proxy-rules/dry-run")"
if [[ "${dry_run_code}" != "200" ]]; then
  echo "[proxy-smoke][ERROR] dry-run failed: ${dry_run_code}" >&2
  cat /tmp/proxy_dry_run_resp.json >&2 || true
  exit 1
fi

route_raw="$(jq -n \
  --arg protectedHost "${PROTECTED_HOST}" \
  --arg upstream "${PROXY_ECHO_URL}" \
  '{
    upstreams: [
      {
        name: "service-a",
        url: $upstream,
        weight: 1,
        enabled: true
      }
    ],
    routes: [
      {
        name: "service-a-prefix",
        enabled: true,
        priority: 10,
        match: {
          hosts: [$protectedHost],
          path: { type: "prefix", value: "/servicea/" }
        },
        action: {
          upstream: "service-a",
          host_rewrite: "service-a.internal",
          path_rewrite: { prefix: "/service-a/" },
          query_rewrite: {
            remove: ["debug"],
            remove_prefixes: ["utm_"],
            set: { "lang": "ja" },
            add: { "preview": "1" }
          },
          request_headers: {
            set: { "X-Service": "service-a" },
            add: { "X-Route": "service-a-prefix" },
            remove: ["X-Debug"]
          },
          response_headers: {
            add: { "Cache-Control": "no-store" }
          }
        }
      }
    ],
    default_route: {
      name: "default",
      enabled: true,
      action: { upstream: "service-a" }
    },
    dial_timeout: 5,
    response_header_timeout: 10,
    idle_conn_timeout: 90,
    max_idle_conns: 100,
    max_idle_conns_per_host: 100,
    max_conns_per_host: 200,
    force_http2: true,
    disable_compression: false,
    response_compression: {
      enabled: true,
      algorithms: ["zstd", "br", "gzip"],
      min_bytes: 1,
      mime_types: ["application/json", "text/*"]
    },
    expect_continue_timeout: 1,
    tls_insecure_skip_verify: false,
    tls_client_cert: "",
    tls_client_key: "",
    buffer_request_body: true,
    max_response_buffer_bytes: 1048576,
    flush_interval_ms: 25,
    health_check_path: "/healthz",
    health_check_interval_sec: 15,
    health_check_timeout_sec: 2,
    error_html_file: "",
    error_redirect_url: ""
  }')"

route_validate_body="$(jq -n --arg raw "${route_raw}" '{raw: $raw}')"
proxy_api_set_admin_auth_args
route_validate_code="$(curl -sS -o /tmp/proxy_route_validate_resp.json -w "%{http_code}" \
  "${PROXY_ADMIN_AUTH_ARGS[@]}" -H "Content-Type: application/json" \
  -X POST --data "${route_validate_body}" "${PROXY_API_URL}/proxy-rules/validate")"
if [[ "${route_validate_code}" != "200" ]]; then
  echo "[proxy-smoke][ERROR] route validate failed: ${route_validate_code}" >&2
  cat /tmp/proxy_route_validate_resp.json >&2 || true
  exit 1
fi

route_dry_run_body="$(jq -n --arg raw "${route_raw}" --arg host "${PROTECTED_HOST}" --arg path "/servicea/users?lang=en&utm_source=ads&debug=true&tag=base" '{raw: $raw, host: $host, path: $path}')"
proxy_api_set_admin_auth_args
route_dry_run_code="$(curl -sS -o /tmp/proxy_route_dry_run_resp.json -w "%{http_code}" \
  "${PROXY_ADMIN_AUTH_ARGS[@]}" -H "Content-Type: application/json" \
  -X POST --data "${route_dry_run_body}" "${PROXY_API_URL}/proxy-rules/dry-run")"
if [[ "${route_dry_run_code}" != "200" ]]; then
  echo "[proxy-smoke][ERROR] route dry-run failed: ${route_dry_run_code}" >&2
  cat /tmp/proxy_route_dry_run_resp.json >&2 || true
  exit 1
fi
if ! jq -e \
  --arg upstream "${PROXY_ECHO_URL}" \
  '.dry_run.source == "route"
   and .dry_run.route_name == "service-a-prefix"
   and .dry_run.rewritten_host == "service-a.internal"
   and .dry_run.rewritten_path == "/service-a/users"
   and .dry_run.original_query == "lang=en&utm_source=ads&debug=true&tag=base"
   and .dry_run.rewritten_query == "lang=ja&preview=1&tag=base"
   and .dry_run.selected_upstream == "service-a"
   and .dry_run.selected_upstream_url == $upstream
   and .dry_run.final_url == ($upstream + "/service-a/users?lang=ja&preview=1&tag=base")' \
  /tmp/proxy_route_dry_run_resp.json >/dev/null; then
  echo "[proxy-smoke][ERROR] route dry-run assertion failed" >&2
  cat /tmp/proxy_route_dry_run_resp.json >&2 || true
  exit 1
fi

put_body="$(jq -n --arg raw "${route_raw}" '{raw: $raw}')"
proxy_api_set_admin_auth_args
put_code="$(curl -sS -o /tmp/proxy_put_resp.json -w "%{http_code}" \
  "${PROXY_ADMIN_AUTH_ARGS[@]}" -H "If-Match: ${etag}" -H "Content-Type: application/json" \
  -X PUT --data "${put_body}" "${PROXY_API_URL}/proxy-rules")"
if [[ "${put_code}" != "200" ]]; then
  echo "[proxy-smoke][ERROR] put failed: ${put_code}" >&2
  cat /tmp/proxy_put_resp.json >&2 || true
  exit 1
fi

route_snapshot="$(proxy_api_get_snapshot)"
if ! jq -e '.proxy.routes | length == 1' <<<"${route_snapshot}" >/dev/null; then
  echo "[proxy-smoke][ERROR] applied route config missing from snapshot" >&2
  jq '.proxy.routes' <<<"${route_snapshot}" >&2 || true
  exit 1
fi

route_request_code="$(curl -sS -D "${proxy_route_headers}" -o "${proxy_route_body}" -w "%{http_code}" \
  -H "Host: ${PROTECTED_HOST}" \
  "${PROXY_BASE_URL}/servicea/users?lang=en&utm_source=ads&debug=true&tag=base")"
if [[ "${route_request_code}" != "200" ]]; then
  echo "[proxy-smoke][ERROR] routed request failed: ${route_request_code}" >&2
  cat "${proxy_route_body}" >&2 || true
  exit 1
fi
if ! jq -e '.path == "/service-a/users?lang=ja&preview=1&tag=base" and .host == "service-a.internal" and .x_service == "service-a" and .x_route == "service-a-prefix"' "${proxy_route_body}" >/dev/null; then
  echo "[proxy-smoke][ERROR] route request assertion failed" >&2
  cat "${proxy_route_body}" >&2 || true
  exit 1
fi
if ! grep -iq '^Cache-Control: no-store' "${proxy_route_headers}"; then
  echo "[proxy-smoke][ERROR] response header rewrite assertion failed" >&2
  cat "${proxy_route_headers}" >&2 || true
  exit 1
fi

route_request_gzip_code="$(curl -sS -D "${proxy_route_headers}" -o "${proxy_route_gzip_body}" -w "%{http_code}" \
  -H "Host: ${PROTECTED_HOST}" -H "Accept-Encoding: gzip" \
  "${PROXY_BASE_URL}/servicea/users?lang=en&utm_source=ads&debug=true&tag=base")"
if [[ "${route_request_gzip_code}" != "200" ]]; then
  echo "[proxy-smoke][ERROR] routed gzip request failed: ${route_request_gzip_code}" >&2
  exit 1
fi
if ! grep -iq '^Content-Encoding: gzip' "${proxy_route_headers}"; then
  echo "[proxy-smoke][ERROR] gzip response missing content-encoding" >&2
  cat "${proxy_route_headers}" >&2 || true
  exit 1
fi
if ! grep -iq '^Vary: .*Accept-Encoding' "${proxy_route_headers}"; then
  echo "[proxy-smoke][ERROR] gzip response missing Vary: Accept-Encoding" >&2
  cat "${proxy_route_headers}" >&2 || true
  exit 1
fi
python3 - "${proxy_route_gzip_body}" <<'PY'
import gzip
import json
import pathlib
import sys

payload = json.loads(gzip.decompress(pathlib.Path(sys.argv[1]).read_bytes()).decode())

if payload.get("path") != "/service-a/users?lang=ja&preview=1&tag=base":
    raise SystemExit(f"unexpected rewritten path: {payload.get('path')!r}")
if payload.get("host") != "service-a.internal":
    raise SystemExit(f"unexpected upstream host: {payload.get('host')!r}")
if payload.get("x_service") != "service-a":
    raise SystemExit(f"unexpected x_service: {payload.get('x_service')!r}")
if payload.get("x_route") != "service-a-prefix":
    raise SystemExit(f"unexpected x_route: {payload.get('x_route')!r}")
PY

proxy_api_set_admin_auth_args
conflict_code="$(curl -sS -o /tmp/proxy_conflict_resp.json -w "%{http_code}" \
  "${PROXY_ADMIN_AUTH_ARGS[@]}" -H "If-Match: stale-etag" -H "Content-Type: application/json" \
  -X PUT --data "${put_body}" "${PROXY_API_URL}/proxy-rules")"
if [[ "${conflict_code}" != "409" ]]; then
  echo "[proxy-smoke][ERROR] etag conflict check failed: ${conflict_code}" >&2
  cat /tmp/proxy_conflict_resp.json >&2 || true
  exit 1
fi

proxy_api_set_admin_auth_args
rollback_code="$(curl -sS -o /tmp/proxy_rollback_resp.json -w "%{http_code}" \
  "${PROXY_ADMIN_AUTH_ARGS[@]}" -H "Content-Type: application/json" \
  -X POST --data '{}' "${PROXY_API_URL}/proxy-rules/rollback")"
if [[ "${rollback_code}" != "200" ]]; then
  echo "[proxy-smoke][ERROR] rollback failed: ${rollback_code}" >&2
  cat /tmp/proxy_rollback_resp.json >&2 || true
  exit 1
fi

rolled_back_snapshot="$(proxy_api_get_snapshot)"
if ! jq -e '.proxy.routes | length == 0' <<<"${rolled_back_snapshot}" >/dev/null; then
  echo "[proxy-smoke][ERROR] rollback did not restore original proxy config" >&2
  jq '.proxy.routes' <<<"${rolled_back_snapshot}" >&2 || true
  exit 1
fi

proxy_api_logout_session

status_after_logout="$(curl -sS -o /tmp/proxy_logout_status_resp.json -w "%{http_code}" \
  -b "${PROXY_COOKIE_JAR}" -c "${PROXY_COOKIE_JAR}" \
  "${PROXY_API_URL}/status")"
if [[ "${status_after_logout}" != "401" ]]; then
  echo "[proxy-smoke][ERROR] expected status=401 after logout, got ${status_after_logout}" >&2
  cat /tmp/proxy_logout_status_resp.json >&2 || true
  exit 1
fi

session_after_logout="$(curl -sS -o "${proxy_session_body}" -w "%{http_code}" \
  -b "${PROXY_COOKIE_JAR}" -c "${PROXY_COOKIE_JAR}" \
  "${PROXY_API_URL}/auth/session")"
if [[ "${session_after_logout}" != "200" ]]; then
  echo "[proxy-smoke][ERROR] auth/session failed after logout: ${session_after_logout}" >&2
  cat "${proxy_session_body}" >&2 || true
  exit 1
fi
if ! jq -e '.authenticated == false' "${proxy_session_body}" >/dev/null; then
  echo "[proxy-smoke][ERROR] expected logged-out auth/session state" >&2
  cat "${proxy_session_body}" >&2 || true
  exit 1
fi

echo "[proxy-smoke][OK] ui + admin session + proxy-rules + route rewrite smoke checks passed"
