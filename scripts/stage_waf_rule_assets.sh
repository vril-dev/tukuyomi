#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE_ROOT="${1:?usage: scripts/stage_waf_rule_assets.sh <stage-root> [crs-version]}"
CRS_VERSION="${2:-v4.23.0}"
SEED_DIR="${ROOT_DIR}/seeds/waf/rules"

mkdir -p "${STAGE_ROOT}"
cp "${SEED_DIR}/tukuyomi.conf" "${STAGE_ROOT}/tukuyomi.conf"

DEST_DIR="${STAGE_ROOT}/rules/crs" "${ROOT_DIR}/scripts/install_crs.sh" "${CRS_VERSION}"

if [[ -n "${WAF_RULE_SEED_CRS_SETUP_OVERRIDE:-}" ]]; then
  {
    printf '\n'
    cat "${WAF_RULE_SEED_CRS_SETUP_OVERRIDE}"
  } >> "${STAGE_ROOT}/rules/crs/crs-setup.conf"
fi
