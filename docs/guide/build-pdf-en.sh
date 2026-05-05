#!/usr/bin/env bash
# tukuyomi Operation Guide (English Edition) PDF builder
#
# Pipeline: pandoc (Markdown → HTML5) → Chrome headless (HTML → PDF)
#
# Output: dist/tukuyomi-en.pdf

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BOOK="$ROOT/guide/en"
DIST="$ROOT/dist"
TMP="$ROOT/.tmp/build-pdf-en"
CSS="$ROOT/guide/book.css"

mkdir -p "$DIST" "$TMP"

TITLE="tukuyomi Operation Guide (English Edition)"
SUBTITLE="Deploying and operating an application-edge control plane built around Coraza + CRS WAF"
VERSION="based on v1.3.0"
TODAY="$(date +%Y-%m-%d)"
COVER_EYEBROW="Operation Guide"
COVER_BRAND="tukuyomi"
COVER_TAGLINE="Operation Guide ── English Edition"

FILES=(
  "$BOOK/00-preface.md"
  "$BOOK/01-introduction.md"
  "$BOOK/02-quickstart.md"
  "$BOOK/03-binary-deployment.md"
  "$BOOK/04-container-deployment.md"
  "$BOOK/05-routing-upstream-pool.md"
  "$BOOK/06-upstream-http2.md"
  "$BOOK/07-waf-tuning.md"
  "$BOOK/08-fp-tuner-api.md"
  "$BOOK/09-request-security-plugins.md"
  "$BOOK/10-php-fpm-runtime-apps.md"
  "$BOOK/11-psgi-runtime.md"
  "$BOOK/12-scheduled-tasks.md"
  "$BOOK/13-db-operations.md"
  "$BOOK/14-listener-reuseport.md"
  "$BOOK/15-http3-tls.md"
  "$BOOK/16-iot-edge-enrollment.md"
  "$BOOK/17-remote-ssh.md"
  "$BOOK/18-benchmark-regression.md"
  "$BOOK/19-static-fastpath.md"
  "$BOOK/A-operator-reference.md"
  "$BOOK/B-release-notes.md"
)

for f in "${FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "missing: $f" >&2
    exit 1
  fi
done

COVER_HTML=$(cat <<EOF
<section class="cover">
  <div class="eyebrow">${COVER_EYEBROW}</div>
  <h1>${COVER_BRAND}</h1>
  <div class="tagline">${COVER_TAGLINE}</div>
  <div class="subtitle">${SUBTITLE}</div>
  <div class="meta">
    ${VERSION}<br/>
    ${TODAY}
  </div>
</section>
EOF
)

echo "[1/3] pandoc: combining Markdown into a single HTML5"

ln -sfn "$BOOK/images" "$TMP/images"

export TMP_DIR="$TMP"
export CSS_PATH="$CSS"
export COVER_HTML="$COVER_HTML"

pandoc \
  --from gfm+yaml_metadata_block \
  --to html5 \
  --standalone \
  --toc \
  --toc-depth=3 \
  --metadata "title=${TITLE}" \
  --metadata "lang=en" \
  --css="$CSS" \
  --section-divs \
  -o "$TMP/_body.html" \
  "${FILES[@]}"

python3 - <<'PY'
import re, pathlib, os

tmp = pathlib.Path(os.environ["TMP_DIR"])
css = pathlib.Path(os.environ["CSS_PATH"]).resolve()
src = (tmp / "_body.html").read_text(encoding="utf-8")
cover = os.environ["COVER_HTML"]

src = re.sub(r"<style>[\s\S]*?</style>\s*", "", src, count=1)

def absify(m):
    href = m.group(1)
    if href.startswith("file://") or href.startswith("http"):
        return m.group(0)
    return f'<link rel="stylesheet" href="file://{pathlib.Path(href).resolve()}"'
src = re.sub(r'<link rel="stylesheet" href="([^"]+)"', absify, src)

src = src.replace("<body>", f"<body>\n{cover}", 1)

(tmp / "book.html").write_text(src, encoding="utf-8")
print(f"  HTML: {tmp/'book.html'}  ({(tmp/'book.html').stat().st_size} bytes)")
PY

echo "[2/3] Chrome headless: rendering HTML → PDF"

OUT="$DIST/tukuyomi-guide-en.pdf"

google-chrome \
  --headless \
  --disable-gpu \
  --no-sandbox \
  --no-pdf-header-footer \
  --hide-scrollbars \
  --virtual-time-budget=10000 \
  --run-all-compositor-stages-before-draw \
  --print-to-pdf="$OUT" \
  "file://$TMP/book.html" \
  2>&1 | grep -v -E "(DevTools listening|Fontconfig|^$)" || true

if [[ ! -s "$OUT" ]]; then
  echo "PDF was not generated: $OUT" >&2
  exit 2
fi

echo "[3/3] done"
echo "  -> $OUT  ($(du -h "$OUT" | cut -f1))"
