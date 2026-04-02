#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_HOME="${ROOT_DIR}/.local/node"

if [[ ! -x "${NODE_HOME}/bin/node" ]]; then
  echo "Node.js is not installed at ${NODE_HOME}" >&2
  echo "Install command:" >&2
  echo "  curl -fsSL https://nodejs.org/dist/v24.14.0/node-v24.14.0-linux-x64.tar.xz -o /tmp/node.tar.xz" >&2
  exit 1
fi

export PATH="${NODE_HOME}/bin:${PATH}"
echo "Using node: $(node -v)"
echo "Using npm:  $(npm -v)"
