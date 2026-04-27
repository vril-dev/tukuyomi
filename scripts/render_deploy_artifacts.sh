#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TARGET="${TARGET:-${DEPLOY_TARGET:-}}"
DEPLOY_RENDER_OUT_DIR="${DEPLOY_RENDER_OUT_DIR:-dist/deploy}"
DEPLOY_RENDER_OVERWRITE="${DEPLOY_RENDER_OVERWRITE:-0}"
IMAGE_URI="${IMAGE_URI:-}"

log() {
  echo "[deploy-render] $*"
}

die() {
  echo "[deploy-render][ERROR] $*" >&2
  exit 1
}

is_enabled() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

render_file() {
  local src="$1"
  local dst="$2"
  python3 - "$src" "$dst" <<'PY'
import os
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as fh:
    data = fh.read()

replacements = {
    "<IMAGE_URI>": os.environ.get("IMAGE_URI", ""),
    "<AWS_REGION>": os.environ.get("AWS_REGION", ""),
    "<ACCOUNT_ID>": os.environ.get("AWS_ACCOUNT_ID", ""),
    "<ECS_EXECUTION_ROLE>": os.environ.get("ECS_EXECUTION_ROLE", ""),
    "<ECS_TASK_ROLE>": os.environ.get("ECS_TASK_ROLE", ""),
    "fs-0123456789abcdef0": os.environ.get("EFS_FILE_SYSTEM_ID", ""),
    "<LOCATION>": os.environ.get("AZURE_LOCATION", ""),
    "<SUBSCRIPTION_ID>": os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
    "<RESOURCE_GROUP_NAME>": os.environ.get("AZURE_RESOURCE_GROUP", ""),
    "<ENVIRONMENT_NAME>": os.environ.get("AZURE_CONTAINER_APPS_ENVIRONMENT", ""),
}

for marker, value in replacements.items():
    if value:
        data = data.replace(marker, value)

with open(dst, "w", encoding="utf-8") as fh:
    fh.write(data)
PY
}

prepare_out_dir() {
  OUT_DIR="${OUT_ROOT}/${TARGET}"
  if [[ -e "${OUT_DIR}" ]]; then
    if ! is_enabled "${DEPLOY_RENDER_OVERWRITE}"; then
      die "output already exists: ${OUT_DIR} (set DEPLOY_RENDER_OVERWRITE=1 to replace)"
    fi
    rm -rf "${OUT_DIR}"
  fi
  mkdir -p "${OUT_DIR}"
}

require_image_uri() {
  [[ -n "${IMAGE_URI}" ]] || die "IMAGE_URI is required for TARGET=${TARGET}"
}

warn_unresolved_placeholders() {
  local matches
  matches="$(grep -Rho '<[A-Z0-9_][A-Z0-9_]*>' "${OUT_DIR}" 2>/dev/null | sort -u || true)"
  if [[ -n "${matches}" ]]; then
    log "unresolved placeholders remain:"
    printf '%s\n' "${matches}" | sed 's/^/[deploy-render]   /'
  fi
}

validate_json_outputs() {
  command -v jq >/dev/null 2>&1 || return 0
  find "${OUT_DIR}" -type f -name '*.json' -print0 | while IFS= read -r -d '' file; do
    jq empty "${file}" >/dev/null
  done
}

resolve_output_root() {
  python3 - "$ROOT_DIR" "$DEPLOY_RENDER_OUT_DIR" <<'PY'
import os
import sys

root = os.path.realpath(sys.argv[1])
raw = sys.argv[2].strip()
if not raw:
    raise SystemExit("DEPLOY_RENDER_OUT_DIR must not be empty")
if os.path.isabs(raw):
    raise SystemExit("DEPLOY_RENDER_OUT_DIR must be repository-relative")
out = os.path.realpath(os.path.join(root, raw))
if os.path.commonpath([root, out]) != root:
    raise SystemExit("DEPLOY_RENDER_OUT_DIR must stay inside the repository")
if out == root:
    raise SystemExit("DEPLOY_RENDER_OUT_DIR must not be the repository root")
print(out)
PY
}

write_readme() {
  local title="$1"
  local body="$2"
  {
    printf '# %s\n\n' "${title}"
    printf '%s\n' "${body}"
  } > "${OUT_DIR}/README.md"
}

render_ecs() {
  require_image_uri
  prepare_out_dir
  render_file "${ROOT_DIR}/docs/build/ecs-single-instance.task-definition.example.json" "${OUT_DIR}/task-definition.json"
  render_file "${ROOT_DIR}/docs/build/ecs-single-instance.service.example.json" "${OUT_DIR}/service.json"
  render_file "${ROOT_DIR}/docs/build/ecs-replicated-frontend-scheduler.task-definition.example.json" "${OUT_DIR}/replicated-scheduler-task-definition.json"
  render_file "${ROOT_DIR}/docs/build/ecs-replicated-frontend-scheduler.service.example.json" "${OUT_DIR}/replicated-scheduler-service.json"
  write_readme "ECS deployment artifacts" \
"Generated from docs/build ECS samples.

Rendered image: ${IMAGE_URI}

Review unresolved placeholders, create the EFS roots, register the task
definition, then update the ECS service. This command does not call AWS APIs."
  validate_json_outputs
  warn_unresolved_placeholders
}

render_kubernetes() {
  require_image_uri
  prepare_out_dir
  render_file "${ROOT_DIR}/docs/build/kubernetes-single-instance.example.yaml" "${OUT_DIR}/single-instance.yaml"
  render_file "${ROOT_DIR}/docs/build/kubernetes-replicated-frontend-scheduler.example.yaml" "${OUT_DIR}/replicated-scheduler.yaml"
  write_readme "Kubernetes deployment artifacts" \
"Generated from docs/build Kubernetes samples.

Rendered image: ${IMAGE_URI}

Create the referenced PVCs first, then apply single-instance.yaml. The
replicated scheduler artifact is for the future immutable frontend split and is
not a distributed mutable runtime model."
  warn_unresolved_placeholders
}

render_azure_container_apps() {
  require_image_uri
  prepare_out_dir
  render_file "${ROOT_DIR}/docs/build/azure-container-apps-single-instance.example.yaml" "${OUT_DIR}/single-instance.yaml"
  render_file "${ROOT_DIR}/docs/build/azure-container-apps-scheduler-singleton.example.yaml" "${OUT_DIR}/scheduler-singleton.yaml"
  write_readme "Azure Container Apps deployment artifacts" \
"Generated from docs/build Azure Container Apps samples.

Rendered image: ${IMAGE_URI}

Review unresolved Azure placeholders and ensure the referenced Azure Files
storage definitions exist before applying. This command does not call Azure
APIs."
  warn_unresolved_placeholders
}

render_container_image() {
  if [[ -z "${IMAGE_URI}" ]]; then
    IMAGE_URI="tukuyomi:deploy"
  fi
  export IMAGE_URI
  prepare_out_dir
  cp "${ROOT_DIR}/docs/build/Dockerfile.example" "${OUT_DIR}/Dockerfile"
  cat > "${OUT_DIR}/build.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="\${SCRIPT_DIR}"
while [[ "\${ROOT_DIR}" != "/" ]]; do
  if [[ -f "\${ROOT_DIR}/Makefile" && -d "\${ROOT_DIR}/server" ]]; then
    break
  fi
  ROOT_DIR="\$(dirname "\${ROOT_DIR}")"
done
if [[ ! -f "\${ROOT_DIR}/Makefile" || ! -d "\${ROOT_DIR}/server" ]]; then
  echo "[build][ERROR] repository root not found above \${SCRIPT_DIR}" >&2
  exit 1
fi
docker build -f "\${SCRIPT_DIR}/Dockerfile" -t "${IMAGE_URI}" "\${ROOT_DIR}"
EOF
  chmod +x "${OUT_DIR}/build.sh"
  write_readme "Container image build artifact" \
"Generated from docs/build/Dockerfile.example.

Run ./build.sh from this directory to build ${IMAGE_URI}. This command builds a
local image only; it does not push to a registry."
}

OUT_ROOT="$(resolve_output_root)"

case "${TARGET}" in
  ecs) render_ecs ;;
  kubernetes) render_kubernetes ;;
  azure-container-apps) render_azure_container_apps ;;
  container-image) render_container_image ;;
  "")
    die "TARGET is required: ecs, kubernetes, azure-container-apps, container-image"
    ;;
  *)
    die "unsupported TARGET=${TARGET}"
    ;;
esac

log "wrote ${OUT_DIR}"
