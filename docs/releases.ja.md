# Release Notes

このファイルは tukuyomi のリリース内容を、利用者影響が分かる形でまとめるためのものです。

- tag 前の版は draft として追記・調整します。
- ここに要約していない詳細は、Git tag と commit 履歴から追えます。

## v0.2.1（2026-04-07）

### 主な変更

- 埋め込み Admin UI / Admin API 向けに、built-in の admin exposure 制御を追加しました。
  - 既定 posture は `WAF_ADMIN_EXTERNAL_MODE=api_only_external` です。
  - trusted/private な直結 peer は管理UI/APIの両方へ到達できます。
  - untrusted external は認証付き管理APIだけへ到達できます。
- `WAF_ADMIN_TRUSTED_CIDRS` を追加し、埋め込み管理UIへ到達させる
  直結 peer range を明示指定できるようにしました。
- 危険な admin exposure posture に対する起動 warning を追加しました。
  - `WAF_ADMIN_EXTERNAL_MODE=full_external`
  - catch-all な trusted admin CIDR

### 運用とデプロイ

- 次の文書に admin exposure 設定を追記しました。
  - [`README.ja.md`](../README.ja.md)
  - [`docs/build/binary-deployment.ja.md`](./build/binary-deployment.ja.md)
  - [`docs/build/container-deployment.ja.md`](./build/container-deployment.ja.md)
  - [`docs/build/tukuyomi.env.example`](./build/tukuyomi.env.example)
- compose と example stack も、文書どおりの既定 posture を使うように更新しました。

### 運用者向け注意

- `WAF_TRUSTED_PROXY_CIDRS` は forwarded header の信頼境界だけを決めます。埋め込み管理UIの到達可否は広げません。
- remote admin API 自体が不要なら `WAF_ADMIN_EXTERNAL_MODE=deny_external` を使ってください。
- front proxy / LB が private ではない source IP で接続しつつ埋め込み管理UIも使う場合は、その直結 peer range を `WAF_ADMIN_TRUSTED_CIDRS` へ設定してください。

### 検証概要

`v0.2.1` 対応中に、主に次を実施しています。

- `go test ./internal/config ./internal/middleware ./internal/handler`
- `docker compose config`
- `git diff --check`

## v0.2.0（2026-04-06）

### 主な変更

- Admin UI を `tukuyomi` バイナリへ埋め込みました。
  - Vite の frontend は任意の開発用経路になりました。
  - ブラウザ管理UIを Go runtime と同一 origin で扱えます。
- `client -> front proxy/LB -> tukuyomi -> apps` を前提にした standalone runtime の整備を進めました。
  - trusted proxy 境界の明確化
  - trusted country header chain
  - 内部レスポンスヘッダの sanitize
- 内蔵 response cache を拡張しました。
  - in-memory cache
  - request coalescing
  - stale cache の耐性と refresh backoff
  - disk-backed cache mode
- ブラウザ管理認証を、埋め込み再利用キー方式から session cookie 方式へ移行しました。
  - login / logout / session endpoint を追加
  - state-changing な管理操作に CSRF 対策を追加
  - CLI / 自動化用の `X-API-Key` は継続利用可能

### 運用とデプロイ

- binary deployment ガイドを追加しました。
  - [`docs/build/binary-deployment.ja.md`](./build/binary-deployment.ja.md)
- container deployment ガイドを追加しました。
  - [`docs/build/container-deployment.ja.md`](./build/container-deployment.ja.md)
- デプロイ用の sample asset を追加しました。
  - [`docs/build/tukuyomi.service.example`](./build/tukuyomi.service.example)
  - [`docs/build/tukuyomi.env.example`](./build/tukuyomi.env.example)
  - [`docs/build/Dockerfile.example`](./build/Dockerfile.example)
- ローカル binary build 用に `make go-build` を追加しました。
- 文書化した経路そのものを検証する smoke を追加しました。
  - `make binary-deployment-smoke`
  - `make container-deployment-smoke`
  - `make deployment-smoke`

### 管理UIと観測

- Admin UI の `waf / intr / accerr` に対して、standalone runtime でも意味を持つ operational log parity を追加しました。
- Admin UI から次を扱えるようにしました。
  - log-output profile
  - cache runtime visibility
- session auth に合わせて admin OpenAPI を更新しました。
  - `/tukuyomi-api/auth/session`
  - `/tukuyomi-api/auth/login`
  - `/tukuyomi-api/auth/logout`

### 運用者向け注意

- ローカル以外では `WAF_ADMIN_SESSION_SECRET` を必ず設定してください。
- `VITE_*` は secret として扱わないでください。
- ALB / nginx / HAProxy / CDN 配下で使う場合は、少なくとも次を見直してください。
  - `WAF_TRUSTED_PROXY_CIDRS`
  - `WAF_COUNTRY_HEADER_NAMES`
  - `WAF_FORWARD_INTERNAL_RESPONSE_HEADERS`
- response cache は deployment ごとに明示して選ぶ形になりました。
  - `off`
  - `memory`
  - `disk`

### 検証概要

`v0.2.0` 対応中に、主に次を実施しています。

- `go test ./...`
- `go test -race ./...`
- `make ui-test`
- `make ui-build`
- `make standalone-regression-fast`
- `make standalone-regression-extended`
- `make binary-deployment-smoke`
- `make container-deployment-smoke`
- `make deployment-smoke`
- direct / front-proxy topology を対象にした benchmark scenario
