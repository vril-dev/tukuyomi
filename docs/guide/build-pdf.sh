#!/usr/bin/env bash
# Build tukuyomi operator guide PDFs.
#
# Usage:
#   docs/guide/build-pdf.sh all
#   docs/guide/build-pdf.sh ja
#   docs/guide/build-pdf.sh en
#
# Pipeline: pandoc (Markdown -> HTML5) -> Chrome headless (HTML -> PDF)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DOCS_ROOT/.." && pwd)"
DIST="$DOCS_ROOT/dist"
TMP_BASE="$DOCS_ROOT/.tmp/build-pdf"
CSS="$SCRIPT_DIR/book.css"

mkdir -p "$DIST" "$TMP_BASE"

DOC_VERSION="${VERSION:-}"
if [[ -z "$DOC_VERSION" ]]; then
  DOC_VERSION="$("$REPO_ROOT/scripts/detect_version.sh")"
fi
TODAY="$(date +%Y-%m-%d)"

CHAPTERS=(
  "00-preface.md"
  "01-introduction.md"
  "02-quickstart.md"
  "03-binary-deployment.md"
  "04-container-deployment.md"
  "05-routing-upstream-pool.md"
  "06-upstream-http2.md"
  "07-waf-tuning.md"
  "08-fp-tuner-api.md"
  "09-request-security-plugins.md"
  "10-php-fpm-runtime-apps.md"
  "11-psgi-runtime.md"
  "12-scheduled-tasks.md"
  "13-db-operations.md"
  "14-listener-reuseport.md"
  "15-http3-tls.md"
  "16-iot-edge-enrollment.md"
  "17-remote-ssh.md"
  "18-benchmark-regression.md"
  "19-static-fastpath.md"
  "A-operator-reference.md"
  "B-release-notes.md"
)

usage() {
  echo "usage: $0 all|ja|en" >&2
}

build_one() {
  local lang="$1"
  local book title subtitle cover_tagline meta_version out

  case "$lang" in
    ja)
      book="$SCRIPT_DIR/ja"
      title="tukuyomi 運用ガイド（日本語版）"
      subtitle="Coraza + CRS WAF を中核とする application-edge control plane の導入と運用"
      cover_tagline="運用ガイド ── 日本語版"
      meta_version="${DOC_VERSION} ベース"
      out="$DIST/tukuyomi-guide-ja.pdf"
      ;;
    en)
      book="$SCRIPT_DIR/en"
      title="tukuyomi Operation Guide (English Edition)"
      subtitle="Deploying and operating an application-edge control plane built around Coraza + CRS WAF"
      cover_tagline="Operation Guide ── English Edition"
      meta_version="based on ${DOC_VERSION}"
      out="$DIST/tukuyomi-guide-en.pdf"
      ;;
    *)
      usage
      exit 64
      ;;
  esac

  local tmp="$TMP_BASE-$lang"
  rm -rf "$tmp"
  mkdir -p "$tmp"

  local files=()
  local chapter
  for chapter in "${CHAPTERS[@]}"; do
    local path="$book/$chapter"
    if [[ ! -f "$path" ]]; then
      echo "missing: $path" >&2
      exit 1
    fi
    files+=("$path")
  done

  local cover_html
  cover_html=$(cat <<EOF
<section class="cover">
  <div class="eyebrow">Operation Guide</div>
  <h1>tukuyomi</h1>
  <div class="tagline">${cover_tagline}</div>
  <div class="subtitle">${subtitle}</div>
  <div class="meta">
    ${meta_version}<br/>
    ${TODAY}
  </div>
</section>
EOF
)

  echo "[1/3][$lang] pandoc: combining Markdown into a single HTML5"

  ln -sfn "$book/images" "$tmp/images"

  TMP_DIR="$tmp" CSS_PATH="$CSS" COVER_HTML="$cover_html" \
  pandoc \
    --from gfm+yaml_metadata_block \
    --to html5 \
    --standalone \
    --toc \
    --toc-depth=3 \
    --metadata "title=${title}" \
    --metadata "lang=${lang}" \
    --css="$CSS" \
    --section-divs \
    --variable=document-css:false \
    -o "$tmp/_body.html" \
    "${files[@]}"

  TMP_DIR="$tmp" CSS_PATH="$CSS" COVER_HTML="$cover_html" python3 - <<'PY'
import os
import pathlib
import re

tmp = pathlib.Path(os.environ["TMP_DIR"])
css = pathlib.Path(os.environ["CSS_PATH"]).resolve()
src = (tmp / "_body.html").read_text(encoding="utf-8")
cover = os.environ["COVER_HTML"]

src = re.sub(r"<style>[\s\S]*?</style>\s*", "", src, count=1)

def absify(match):
    href = match.group(1)
    if href.startswith("file://") or href.startswith("http"):
        return match.group(0)
    return f'<link rel="stylesheet" href="file://{css}"'

src = re.sub(r'<link rel="stylesheet" href="([^"]+)"', absify, src)
src = src.replace("<body>", f"<body>\n{cover}", 1)

(tmp / "book.html").write_text(src, encoding="utf-8")
print(f"  HTML: {tmp / 'book.html'}  ({(tmp / 'book.html').stat().st_size} bytes)")
PY

  echo "[2/3][$lang] Chrome headless: rendering HTML -> PDF"

  google-chrome \
    --headless \
    --disable-gpu \
    --no-sandbox \
    --no-pdf-header-footer \
    --hide-scrollbars \
    --virtual-time-budget=10000 \
    --run-all-compositor-stages-before-draw \
    --print-to-pdf="$out" \
    "file://$tmp/book.html" \
    2>&1 | grep -v -E "(DevTools listening|Fontconfig|^$)" || true

  if [[ ! -s "$out" ]]; then
    echo "PDF was not generated: $out" >&2
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
