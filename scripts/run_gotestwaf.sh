#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${ROOT_DIR}/data/logs/gotestwaf"
REPORT_NAME="${GOTESTWAF_REPORT_NAME:-gotestwaf-report}"
REPORT_JSON="${REPORT_DIR}/${REPORT_NAME}.json"
SUMMARY_TXT="${REPORT_DIR}/${REPORT_NAME}-summary.txt"
SUMMARY_MD="${REPORT_DIR}/${REPORT_NAME}-summary.md"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
HOST_CORAZA_PORT="${HOST_CORAZA_PORT:-19090}"
WAF_LISTEN_PORT="${WAF_LISTEN_PORT:-9090}"
HOST_PUID="${PUID:-$(id -u)}"
HOST_GUID="${GUID:-$(id -g)}"

MIN_BLOCKED_RATIO="${MIN_BLOCKED_RATIO:-70}"
MIN_TRUE_NEGATIVE_PASSED_RATIO="${MIN_TRUE_NEGATIVE_PASSED_RATIO:-}"
MAX_FALSE_POSITIVE_RATIO="${MAX_FALSE_POSITIVE_RATIO:-}"
MAX_BYPASS_RATIO="${MAX_BYPASS_RATIO:-}"

AUTO_DOWN="${GOTESTWAF_AUTO_DOWN:-0}"
COMPOSE_ARGS=(--project-directory "${ROOT_DIR}" --profile waf-test)

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[gotestwaf] required command not found: $1" >&2
    exit 1
  fi
}

compose() {
  PUID="${HOST_PUID}" \
  GUID="${HOST_GUID}" \
  CORAZA_PORT="${HOST_CORAZA_PORT}" \
  WAF_LISTEN_PORT="${WAF_LISTEN_PORT}" \
  GOTESTWAF_TARGET_URL="http://coraza:${WAF_LISTEN_PORT}" \
  docker compose "${COMPOSE_ARGS[@]}" "$@"
}

cleanup() {
  compose down --remove-orphans >/dev/null 2>&1 || true
}

to_ratio() {
  awk -v n="$1" -v d="$2" 'BEGIN { if (d <= 0) { printf "0.00"; exit } printf "%.2f", (n / d) * 100 }'
}

lt() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit !(a < b) }'
}

gt() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit !(a > b) }'
}

wait_for_coraza() {
  local code
  local i
  for i in $(seq 1 "${WAIT_TIMEOUT_SECONDS}"); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "http://localhost:${HOST_CORAZA_PORT}/healthz" || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

require_cmd docker
require_cmd curl
require_cmd jq
require_cmd make

if [[ ! -f "${ROOT_DIR}/.env" ]]; then
  if [[ -f "${ROOT_DIR}/.env.example" ]]; then
    cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
    echo "[gotestwaf] .env was missing; copied from .env.example"
  else
    echo "[gotestwaf] .env and .env.example are missing" >&2
    exit 1
  fi
fi

echo "[gotestwaf] ensuring DB-backed WAF rule assets"
(cd "${ROOT_DIR}" && make crs-install)

mkdir -p "${REPORT_DIR}"
rm -f "${REPORT_JSON}" "${SUMMARY_TXT}" "${SUMMARY_MD}"

if [[ "${AUTO_DOWN}" == "1" ]]; then
  trap cleanup EXIT
fi

echo "[gotestwaf] starting coraza"
echo "[gotestwaf] using container uid:gid ${HOST_PUID}:${HOST_GUID}"
compose up -d --build coraza

echo "[gotestwaf] waiting for coraza health endpoint (http://localhost:${HOST_CORAZA_PORT}/healthz, max ${WAIT_TIMEOUT_SECONDS}s)"
if ! wait_for_coraza; then
  echo "[gotestwaf] coraza did not become healthy in time" >&2
  compose ps >&2 || true
  echo "[gotestwaf] recent coraza logs:" >&2
  compose logs --tail=120 coraza >&2 || true
  exit 1
fi

echo "[gotestwaf] running GoTestWAF"
compose run --rm gotestwaf

if [[ ! -s "${REPORT_JSON}" ]]; then
  echo "[gotestwaf] report not found: ${REPORT_JSON}" >&2
  exit 1
fi

blocked_ratio="$(jq -r '.summary.true_positive_tests.score // 0' "${REPORT_JSON}")"
tn_passed_ratio="$(jq -r '.summary.true_negative_tests.score // 0' "${REPORT_JSON}")"

tp_resolved="$(jq -r '.summary.true_positive_tests.summary.resolved_tests // 0' "${REPORT_JSON}")"
tp_bypassed="$(jq -r '.summary.true_positive_tests.summary.bypassed_tests // 0' "${REPORT_JSON}")"
tp_unresolved="$(jq -r '.summary.true_positive_tests.summary.unresolved_tests // 0' "${REPORT_JSON}")"
tp_sent="$(jq -r '.summary.true_positive_tests.summary.total_sent // 0' "${REPORT_JSON}")"
tn_resolved="$(jq -r '.summary.true_negative_tests.summary.resolved_tests // 0' "${REPORT_JSON}")"
tn_blocked="$(jq -r '.summary.true_negative_tests.summary.blocked_tests // 0' "${REPORT_JSON}")"
tn_unresolved="$(jq -r '.summary.true_negative_tests.summary.unresolved_tests // 0' "${REPORT_JSON}")"
tn_sent="$(jq -r '.summary.true_negative_tests.summary.total_sent // 0' "${REPORT_JSON}")"

bypass_ratio="$(to_ratio "${tp_bypassed}" "${tp_resolved}")"
false_positive_ratio="$(to_ratio "${tn_blocked}" "${tn_resolved}")"
tp_unresolved_ratio="$(to_ratio "${tp_unresolved}" "${tp_sent}")"
tn_unresolved_ratio="$(to_ratio "${tn_unresolved}" "${tn_sent}")"

tn_threshold_display="---"
fp_threshold_display="---"
bypass_threshold_display="---"

if [[ -n "${MIN_TRUE_NEGATIVE_PASSED_RATIO}" ]]; then
  tn_threshold_display=">= ${MIN_TRUE_NEGATIVE_PASSED_RATIO}%"
fi
if [[ -n "${MAX_FALSE_POSITIVE_RATIO}" ]]; then
  fp_threshold_display="<= ${MAX_FALSE_POSITIVE_RATIO}%"
fi
if [[ -n "${MAX_BYPASS_RATIO}" ]]; then
  bypass_threshold_display="<= ${MAX_BYPASS_RATIO}%"
fi

{
  echo "report_json=${REPORT_JSON}"
  echo "blocked_ratio=${blocked_ratio}"
  echo "true_negative_passed_ratio=${tn_passed_ratio}"
  echo "false_positive_ratio=${false_positive_ratio}"
  echo "bypass_ratio=${bypass_ratio}"
  echo "true_positive_unresolved_ratio=${tp_unresolved_ratio}"
  echo "true_negative_unresolved_ratio=${tn_unresolved_ratio}"
  echo "min_blocked_ratio=${MIN_BLOCKED_RATIO}"
  echo "min_true_negative_passed_ratio=${MIN_TRUE_NEGATIVE_PASSED_RATIO}"
  echo "max_false_positive_ratio=${MAX_FALSE_POSITIVE_RATIO}"
  echo "max_bypass_ratio=${MAX_BYPASS_RATIO}"
} >"${SUMMARY_TXT}"

{
  echo "# GoTestWAF Summary"
  echo
  echo "| Metric | Value | Threshold |"
  echo "| --- | ---: | ---: |"
  echo "| blocked_ratio | ${blocked_ratio}% | >= ${MIN_BLOCKED_RATIO}% |"
  echo "| true_negative_passed_ratio | ${tn_passed_ratio}% | ${tn_threshold_display} |"
  echo "| false_positive_ratio | ${false_positive_ratio}% | ${fp_threshold_display} |"
  echo "| bypass_ratio | ${bypass_ratio}% | ${bypass_threshold_display} |"
  echo "| true_positive_unresolved_ratio | ${tp_unresolved_ratio}% | informational |"
  echo "| true_negative_unresolved_ratio | ${tn_unresolved_ratio}% | informational |"
} >"${SUMMARY_MD}"

failed=0

if lt "${blocked_ratio}" "${MIN_BLOCKED_RATIO}"; then
  echo "[gotestwaf][FAIL] blocked_ratio ${blocked_ratio}% is below ${MIN_BLOCKED_RATIO}%"
  failed=1
else
  echo "[gotestwaf][PASS] blocked_ratio ${blocked_ratio}% >= ${MIN_BLOCKED_RATIO}%"
fi

if [[ -n "${MIN_TRUE_NEGATIVE_PASSED_RATIO}" ]]; then
  if lt "${tn_passed_ratio}" "${MIN_TRUE_NEGATIVE_PASSED_RATIO}"; then
    echo "[gotestwaf][FAIL] true_negative_passed_ratio ${tn_passed_ratio}% is below ${MIN_TRUE_NEGATIVE_PASSED_RATIO}%"
    failed=1
  else
    echo "[gotestwaf][PASS] true_negative_passed_ratio ${tn_passed_ratio}% >= ${MIN_TRUE_NEGATIVE_PASSED_RATIO}%"
  fi
fi

if [[ -n "${MAX_FALSE_POSITIVE_RATIO}" ]]; then
  if gt "${false_positive_ratio}" "${MAX_FALSE_POSITIVE_RATIO}"; then
    echo "[gotestwaf][FAIL] false_positive_ratio ${false_positive_ratio}% exceeds ${MAX_FALSE_POSITIVE_RATIO}%"
    failed=1
  else
    echo "[gotestwaf][PASS] false_positive_ratio ${false_positive_ratio}% <= ${MAX_FALSE_POSITIVE_RATIO}%"
  fi
fi

if [[ -n "${MAX_BYPASS_RATIO}" ]]; then
  if gt "${bypass_ratio}" "${MAX_BYPASS_RATIO}"; then
    echo "[gotestwaf][FAIL] bypass_ratio ${bypass_ratio}% exceeds ${MAX_BYPASS_RATIO}%"
    failed=1
  else
    echo "[gotestwaf][PASS] bypass_ratio ${bypass_ratio}% <= ${MAX_BYPASS_RATIO}%"
  fi
fi

if [[ "${failed}" -ne 0 ]]; then
  exit 1
fi

if gt "${tp_unresolved_ratio}" "50"; then
  echo "[gotestwaf][WARN] true_positive_unresolved_ratio is high (${tp_unresolved_ratio}%). Ensure upstream app responses are reachable."
fi
if gt "${tn_unresolved_ratio}" "50"; then
  echo "[gotestwaf][WARN] true_negative_unresolved_ratio is high (${tn_unresolved_ratio}%). Ensure upstream app responses are reachable."
fi

echo "[gotestwaf] completed successfully"
