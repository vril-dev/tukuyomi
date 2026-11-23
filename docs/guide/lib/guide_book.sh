#!/usr/bin/env bash
# Chapter list and per-language metadata shared by the operator guide builders
# (build-pdf.sh, build-epub.sh). Source this file; it only defines variables
# and functions.

GUIDE_BOOK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

GUIDE_BOOK_CHAPTERS=(
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

# guide_book_load LANG VERSION
#
# Sets GUIDE_BOOK_DIR, GUIDE_BOOK_TITLE, GUIDE_BOOK_SUBTITLE,
# GUIDE_BOOK_COVER_TAGLINE, GUIDE_BOOK_META_VERSION, GUIDE_BOOK_EDITION_SUBTITLE
# and GUIDE_BOOK_TOC_TITLE for LANG. Returns 1 for an unknown LANG.
guide_book_load() {
  local lang="$1"
  local version="$2"

  case "$lang" in
    ja)
      GUIDE_BOOK_DIR="$GUIDE_BOOK_ROOT/ja"
      GUIDE_BOOK_TITLE="tukuyomi 運用ガイド（日本語版）"
      GUIDE_BOOK_SUBTITLE="Coraza + CRS WAF を中核とする application-edge control plane の導入と運用"
      GUIDE_BOOK_COVER_TAGLINE="運用ガイド ── 日本語版"
      GUIDE_BOOK_META_VERSION="${version} ベース"
      GUIDE_BOOK_EDITION_SUBTITLE="${GUIDE_BOOK_SUBTITLE}（${GUIDE_BOOK_META_VERSION}）"
      GUIDE_BOOK_TOC_TITLE="目次"
      ;;
    en)
      GUIDE_BOOK_DIR="$GUIDE_BOOK_ROOT/en"
      GUIDE_BOOK_TITLE="tukuyomi Operation Guide (English Edition)"
      GUIDE_BOOK_SUBTITLE="Deploying and operating an application-edge control plane built around Coraza + CRS WAF"
      GUIDE_BOOK_COVER_TAGLINE="Operation Guide ── English Edition"
      GUIDE_BOOK_META_VERSION="based on ${version}"
      GUIDE_BOOK_EDITION_SUBTITLE="${GUIDE_BOOK_SUBTITLE} (${GUIDE_BOOK_META_VERSION})"
      GUIDE_BOOK_TOC_TITLE="Contents"
      ;;
    *)
      return 1
      ;;
  esac
}
