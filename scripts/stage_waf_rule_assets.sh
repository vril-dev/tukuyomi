#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE_ROOT="${1:?usage: scripts/stage_waf_rule_assets.sh <stage-root> [crs-version]}"
CRS_VERSION="${2:-v4.23.0}"
SEED_DIR="${ROOT_DIR}/seeds/waf/rules"

mkdir -p "${STAGE_ROOT}"
cp "${SEED_DIR}/tukuyomi.conf" "${STAGE_ROOT}/tukuyomi.conf"

DEST_DIR="${STAGE_ROOT}/rules/crs" "${ROOT_DIR}/scripts/install_crs.sh" "${CRS_VERSION}"

cat >> "${STAGE_ROOT}/rules/crs/crs-setup.conf" <<'EOF'

# tukuyomi uses REST-style UI and control-plane APIs. Keep CRS method
# enforcement enabled, but include the verbs used by those APIs.
SecAction "id:1090100,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"
EOF

if [[ -n "${WAF_RULE_SEED_CRS_SETUP_OVERRIDE:-}" ]]; then
  {
    printf '\n'
    cat "${WAF_RULE_SEED_CRS_SETUP_OVERRIDE}"
  } >> "${STAGE_ROOT}/rules/crs/crs-setup.conf"
fi
