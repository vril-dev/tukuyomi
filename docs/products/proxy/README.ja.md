# tukuyomi-proxy

[English](README.md) | [日本語](README.ja.md)

`tukuyomi-proxy` は、Tukuyomi ファミリーの汎用シングルバイナリ WAF / リバースプロキシです。Coraza + CRS の中核的なセキュリティ制御を維持しつつ、内蔵のルート管理と admin UI を備え、前段に `nginx` を置くことを前提としません。

## 想定ユースケース

- シングルバイナリまたは軽量コンテナでの配備
- API gateway / reverse proxy の用途
- TLS 終端、ルーティング、WAF 制御を 1 つの実行環境にまとめたい運用

## 主な特徴

- Coraza WAF + OWASP CRS
- 内蔵 admin UI とルートエディタ
- 中核制御: IP reputation、bot defense、semantic security、rate limiting、country block
- ファイルバックエンドと DB バックエンドのポリシー / ランタイムデータ経路

## 公開配布

- 最新の公開バイナリ: [`v0.7.6`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.7.6)
- ファミリー全体のリリース一覧: [`tukuyomi-releases`](https://github.com/vril-dev/tukuyomi-releases/releases)
- そのリリースページで GitHub が自動生成するソースアーカイブは `tukuyomi-releases` リポジトリに対応するものであり、`tukuyomi-proxy` の非公開ビルドリポジトリのソースではありません

## 関連ドキュメント

- ファミリー概要: [`../../../README.ja.md`](../../../README.ja.md)
- 製品比較: [`../../product-comparison.ja.md`](../../product-comparison.ja.md)

詳細なランタイム / 設定ドキュメントはバイナリバンドルに同梱されます。
