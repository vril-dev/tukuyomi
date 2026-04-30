---
title: "tukuyomi 運用ガイド"
subtitle: "Coraza + CRS WAF を中核とする application-edge control plane の導入と運用"
language: ja
audience: "tukuyomi を導入・運用するエンジニア（インフラ／SRE／プラットフォーム担当）"
version: "1.2.0 ベース"
build: "pandoc → HTML → Chrome headless で PDF 化"
---

# tukuyomi 運用ガイド（日本語版）

本書は、上流リポジトリ `/home/ky491/git/vril/tukuyomi` に置かれた日本語ドキュメント
（`README.ja.md` および `docs/**/*.ja.md`）を再編し、日本のエンジニアが上から順に
読み通せる **書籍** として再構成したものです。

## 本書の方針

- **対象読者**: tukuyomi を導入する SRE / インフラエンジニア、および既存の WAF /
  リバースプロキシ運用経験者。Linux、Docker、HTTP、TLS、systemd の基礎は既知とします。
- **文体**: 「です・ます」調で統一。技術用語は英語のまま使い、対応する日本語訳を
  必要に応じて初出時に併記します。
- **構成**: 各章は「概要 → 仕組み → 設定例 → 運用上の注意」という流れに揃えます。
- **整合**: 設定 key 名・テーブル名・Make ターゲット名は上流ドキュメントと完全一致させ、
  読者が tukuyomi リポジトリのソースを参照しても迷わないようにします。

## 目次（章立て案）

### 第I部　序章

- **第1章　tukuyomi 入門** — 製品の位置づけと、single-binary application-edge
  control plane としての全体像。
- **第2章　クイックスタート** — `make preset-apply` と `make gateway-preview-up` で
  ローカル preview を起動し、Gateway UI と API に到達するまで。

### 第II部　配備

- **第3章　バイナリ配備（systemd）** — `make install TARGET=linux-systemd` を中心に、
  実行レイアウト、永続 byte storage、public/admin リスナー分離、PHP-FPM bundle、
  環境変数、overload tuning、secret 取り扱い、socket activation。
  （source: docs/build/binary-deployment.ja.md）
- **第4章　コンテナ配備** — Tier 1〜3 のサポート区分、現時点の official topology、
  ECS / Kubernetes / Azure Container Apps の deploy artifact、共有 writable path、
  config と secret の供給経路。
  （source: docs/build/container-deployment.ja.md）

### 第III部　リバースプロキシ

- **第5章　ルーティング、Upstream、Backend Pool** — Routes / Upstreams /
  Backend Pools の三層モデル、route-scoped pool 例、sticky sessions、
  Dynamic DNS Backend Discovery、`Backends` 画面と direct named upstream への
  runtime 操作。
  （source: README.ja.md, operator-reference.ja.md の Proxy セクション）
- **第6章　Upstream HTTP/2 と h2c** — `force_http2` / `h2c_upstream` の意味、
  混在 topology の設計、TLS 制御と direct route target の扱い、runtime で
  見える項目。
  （source: docs/operations/upstream-http2.ja.md）

### 第IV部　WAF と Request Security

- **第7章　WAF 誤検知チューニング** — 証跡採取、影響範囲の切り分け、狭い緩和
  （`override_rules` / managed bypass）、CRS 設定の見直し、検証、変更管理。
  （source: docs/operations/waf-tuning.ja.md）
- **第8章　FP Tuner API と AI 連携** — Propose / Apply エンドポイントの契約、
  simulate と real apply、関連 env、OpenAI 互換 / Claude Messages の Command
  Provider。
  （source: docs/operations/fp-tuner-api.ja.md）
- **第9章　Request-Time Security Plugins** — metadata resolver と request-security
  plugin の境界、`SecurityEvent` 契約、ordering、bounded shared feedback、
  registration、minimal example、design rules。
  （source: docs/request_security_plugins.ja.md）

### 第V部　Runtime Apps と Scheduled Tasks

- **第10章　PHP-FPM Runtime と Runtime Apps** — 役割分担、データ配置、
  runtime build と inventory、Runtime App の起動経路、Upstream との境界、
  Process Lifecycle、smoke。
  （source: docs/operations/php-fpm-vhosts.ja.md）
- **第11章　PSGI Runtime（Movable Type など）** — Runtime Model、Movable Type
  での形、Process Controls、build。
  （source: docs/operations/psgi-vhosts.ja.md）
- **第12章　Scheduled Tasks** — 責務分離、Data Layout、Task Model、UI workflow、
  Runner コマンド、binary / container 配備パターン、bundled PHP CLI、
  GeoIP 自動更新。
  （source: docs/operations/php-scheduled-tasks.ja.md）

### 第VI部　運用とトラブルシューティング

- **第13章　DB 運用（SQLite / MySQL / PostgreSQL）** — Driver Selection、
  保存対象（waf_events、versioned runtime config、config_blobs、schema_migrations）、
  retention / pruning、backup、SQLite vacuum、recovery。
  （source: docs/operations/db-ops.ja.md）
- **第14章　リスナートポロジと Reuse-Port** — 現時点の判断、評価止まりとした理由、
  当面の方針、再検討条件、Host/runtime matrix、Docker published-port policy、
  benchmark / smoke gate shape、再開 checklist。
  （source: docs/operations/listener-topology.ja.md, reuseport-policy.ja.md, reuseport-evaluation.ja.md）
- **第15章　HTTP/3 と TLS** — built-in TLS termination、ACME 自動 TLS、
  HTTP/3 の専用 listener、`server.tls.redirect_http`、HTTP/3 public-entry smoke。
  （source: operator-reference.ja.md, docs/operations/http3-public-entry-smoke.ja.md）
- **第16章　IoT / Edge デバイス登録** — 役割、運用フロー、preview URL、
  Center URL ルール、Identity と fingerprint、token の扱い、troubleshooting。
  （source: docs/operations/device-auth-enrollment.ja.md）

### 第VII部　性能と回帰検証

- **第17章　ベンチマークと回帰マトリクス** — `make bench-proxy` / `make bench-waf` /
  `make bench-full`、入力パラメータ、出力の正本、profile capture、
  閾値ポリシー、`make smoke` 系の役割と保証マトリクス、推奨 confidence ladder、
  release-binary smoke。
  （source: benchmark-baseline.ja.md, regression-matrix.ja.md, release-binary-smoke.ja.md）
- **第18章　Static Fast-path 評価** — 判断と理由、zero-copy が噛み合いにくい場所、
  すでにある bounded fast-path、再検討する条件。
  （source: docs/operations/static-fastpath-evaluation.ja.md）

### 付録

- **付録A　運用リファレンス** — `data/conf/config.json` と DB `app_config_*` の
  全 block、Inbound Timeout Boundary、Overload Backpressure、Persistent File
  Storage、Host Network Hardening、管理ダッシュボード、Make ターゲット一覧、
  管理 API。
  （source: docs/reference/operator-reference.ja.md, docs/api/admin-openapi.yaml）
- **付録B　リリースノート（v1.2.0 / v1.1.0）** — Center 追加、IoT / Edge
  enrollment、`INSTALL_ROLE`、device approval lifecycle（v1.2.0）と、
  DB-backed runtime authority、admin 認証刷新、`make install` 整備（v1.1.0）。
  （source: docs/releases/1.2.0.ja.md, docs/releases/1.1.0.ja.md）

## ファイル配置

```
books/tukuyomi/
├── index.md            … 本ファイル（章立て案・本書の方針）
├── 00-preface.md       … はじめに
├── 01-introduction.md  … 第1章
├── 02-quickstart.md    … 第2章
├── 03-...〜18-...md   … 第3〜18章
├── A-operator-reference.md
├── B-release-notes.md
└── images/
    └── ui-samples/     … tukuyomi/docs/images/ui-samples/ から複製済み
```

## ビルド方針（メモ）

- 単一 PDF: 章ファイルを `index.md` の順に pandoc で連結し、目次・扉・章番号を生成。
- HTML 中間: pandoc の HTML5 出力に Noto Sans CJK / IPAex フォント、章扉の改ページ
  CSS、code block の monospace を当てる。
- 印刷: `google-chrome --headless --print-to-pdf` で PDF を出力。`@page` で A4 余白
  を統一し、ヘッダ／フッタにタイトルとページ番号を入れる。
- ビルドスクリプトは `scripts/build-pdf.sh`（後続タスクで作成）。
