#!/usr/bin/env bash
# Build tukuyomi operator guide EPUBs.
#
# Usage:
#   docs/guide/build-epub.sh all
#   docs/guide/build-epub.sh ja
#   docs/guide/build-epub.sh en
#
# Pipeline: pandoc (Markdown -> EPUB 3)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DOCS_ROOT/.." && pwd)"
DIST="$DOCS_ROOT/dist"
CSS="$SCRIPT_DIR/epub.css"

# shellcheck source=./lib/guide_book.sh
source "$SCRIPT_DIR/lib/guide_book.sh"

mkdir -p "$DIST"

DOC_VERSION="${VERSION:-}"
if [[ -z "$DOC_VERSION" ]]; then
  DOC_VERSION="$("$REPO_ROOT/scripts/detect_version.sh")"
fi
TODAY="$(date +%Y-%m-%d)"

usage() {
  echo "usage: $0 all|ja|en" >&2
}

build_one() {
  local lang="$1"
  local book out

  if ! guide_book_load "$lang" "$DOC_VERSION"; then
    usage
    exit 64
  fi
  book="$GUIDE_BOOK_DIR"
  out="$DIST/tukuyomi-guide-${lang}.epub"

  # east_asian_line_breaks drops the line breaks inside wrapped Japanese
  # paragraphs instead of turning them into spaces.
  local from="gfm+yaml_metadata_block+east_asian_line_breaks"

  # Do not leave a previous build in place if this one fails.
  rm -f "$out"

  local files=()
  local chapter
  for chapter in "${GUIDE_BOOK_CHAPTERS[@]}"; do
    local path="$book/$chapter"
    if [[ ! -f "$path" ]]; then
      echo "missing: $path" >&2
      exit 1
    fi
    files+=("$path")
  done

  echo "[1/3][$lang] pandoc: building EPUB 3"

  # Chapters reference images relative to the language directory
  # (../../images/ui-samples/), so resolve resources from there.
  pandoc \
    --from "$from" \
    --to epub3 \
    --toc \
    --toc-depth=3 \
    --metadata "title=${GUIDE_BOOK_TITLE}" \
    --metadata "subtitle=${GUIDE_BOOK_EDITION_SUBTITLE}" \
    --metadata "lang=${lang}" \
    --metadata "date=${TODAY}" \
    --metadata "toc-title=${GUIDE_BOOK_TOC_TITLE}" \
    --css="$CSS" \
    --resource-path="$book" \
    -o "$out" \
    "${files[@]}"

  echo "[2/3][$lang] checking embedded images"

  # pandoc only warns when an image cannot be found, so compare the distinct
  # image targets in the parsed Markdown with the media files in the EPUB.
  if ! EPUB_PATH="$out" PANDOC_FROM="$from" python3 - "${files[@]}" <<'PY'
import json
import os
import subprocess
import sys
import zipfile


def collect_images(node, found):
    if isinstance(node, dict):
        if node.get("t") == "Image":
            found.add(node["c"][2][0])
        for value in node.values():
            collect_images(value, found)
    elif isinstance(node, list):
        for value in node:
            collect_images(value, found)


ast = subprocess.run(
    ["pandoc", "--from", os.environ["PANDOC_FROM"], "--to", "json", *sys.argv[1:]],
    check=True,
    capture_output=True,
).stdout
refs = set()
collect_images(json.loads(ast), refs)

with zipfile.ZipFile(os.environ["EPUB_PATH"]) as epub:
    media = [name for name in epub.namelist() if name.startswith("EPUB/media/")]

if len(media) != len(refs):
    print(f"images: {len(refs)} referenced, {len(media)} embedded", file=sys.stderr)
    sys.exit(1)
print(f"  images: {len(media)} embedded")
PY
  then
    rm -f "$out"
    echo "EPUB image check failed: $out" >&2
    exit 2
  fi

  echo "[3/3][$lang] done"
  echo "  -> $out  ($(du -h "$out" | cut -f1))"
}

target="${1:-all}"
case "$target" in
  all)
    build_one ja
    build_one en
    ;;
  ja|en)
    build_one "$target"
    ;;
  *)
    usage
    exit 64
    ;;
esac
