#!/usr/bin/env bash
# tukuyomi 運用ガイド（日本語版） PDF ビルドスクリプト
#
# 経路: pandoc (Markdown → HTML5) → Chrome headless (HTML → PDF)
#
# 出力: dist/tukuyomi-guide-ja.pdf.pdf

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BOOK="$ROOT/guide/ja"
DIST="$ROOT/dist"
TMP="$ROOT/.tmp/build-pdf"
CSS="$ROOT/guide/book.css"

mkdir -p "$DIST" "$TMP"

TITLE="tukuyomi 運用ガイド（日本語版）"
SUBTITLE="Coraza + CRS WAF を中核とする application-edge control plane の導入と運用"
VERSION="v1.3.0 ベース"
TODAY="$(date +%Y-%m-%d)"
COVER_EYEBROW="Operation Guide"
COVER_BRAND="tukuyomi"
COVER_TAGLINE="運用ガイド ── 日本語版"

# 章ファイル（index.md は frontmatter 用なので含めない）
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

# 表紙ページ（pandoc 通さず、最終 HTML に直接埋め込む）
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

echo "[1/3] pandoc で Markdown を結合 → HTML5 を生成"

# 画像が相対 path で参照されているので、TMP に images シンボリックリンクを張る
ln -sfn "$BOOK/images" "$TMP/images"

# Python ヒアドキュメント用に環境変数を export
export TMP_DIR="$TMP"
export CSS_PATH="$CSS"
export COVER_HTML="$COVER_HTML"

# pandoc 本体
pandoc \
  --from gfm+yaml_metadata_block \
  --to html5 \
  --standalone \
  --toc \
  --toc-depth=3 \
  --metadata "title=${TITLE}" \
  --metadata "lang=ja" \
  --css="$CSS" \
  --section-divs \
  --variable=document-css:false \
  -o "$TMP/_body.html" \
  "${FILES[@]}"

# 表紙を先頭に挿入し、Pandoc 既定の <style> ブロックを除去、CSS を絶対 file:// に
python3 - <<'PY'
import re, pathlib, os

tmp = pathlib.Path(os.environ["TMP_DIR"])
css = pathlib.Path(os.environ["CSS_PATH"]).resolve()
src = (tmp / "_body.html").read_text(encoding="utf-8")
cover = os.environ["COVER_HTML"]

# Pandoc が <head> に勝手に入れる default <style>...</style> を全削除
# (max-width: 36em / padding 50px などが入っている)
src = re.sub(r"<style>[\s\S]*?</style>\s*", "", src, count=1)

# 外部 CSS を絶対 file:// に書き換え
def absify(m):
    href = m.group(1)
    if href.startswith("file://") or href.startswith("http"):
        return m.group(0)
    return f'<link rel="stylesheet" href="file://{pathlib.Path(href).resolve()}"'
src = re.sub(r'<link rel="stylesheet" href="([^"]+)"', absify, src)

# <body> 直後に表紙を挿入
src = src.replace("<body>", f"<body>\n{cover}", 1)

(tmp / "book.html").write_text(src, encoding="utf-8")
print(f"  HTML: {tmp/'book.html'}  ({(tmp/'book.html').stat().st_size} bytes)")
PY

echo "[2/3] Chrome headless で PDF へ変換"

OUT="$DIST/tukuyomi-guide-ja.pdf"

# Chrome の flag は version によって違うので両方試す
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
  echo "PDF が生成されなかった: $OUT" >&2
  exit 2
fi

echo "[3/3] 完成"
echo "  -> $OUT  ($(du -h "$OUT" | cut -f1))"
