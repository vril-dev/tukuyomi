#!/usr/bin/env bash

set -euo pipefail

if [[ -n "${VERSION:-}" ]]; then
  printf '%s\n' "$VERSION"
  exit 0
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

branch="$(git branch --show-current 2>/dev/null || true)"
case "$branch" in
  v[0-9]*.[0-9]*.[0-9]*)
    printf '%s\n' "$branch"
    exit 0
    ;;
  [0-9]*.[0-9]*.[0-9]*)
    printf 'v%s\n' "$branch"
    exit 0
    ;;
esac

if exact_tag="$(git describe --tags --exact-match 2>/dev/null)"; then
  printf '%s\n' "$exact_tag"
  exit 0
fi

if described="$(git describe --tags --dirty --always 2>/dev/null)"; then
  printf '%s\n' "$described"
  exit 0
fi

printf 'dev\n'
