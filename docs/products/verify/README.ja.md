# tukuyomi-verify

[English](README.md) | [日本語](README.ja.md)

`tukuyomi-verify` は、Tukuyomi WAF 製品向けの外部検証・レポートツールです。エクスポートされた `verify-manifest` を取り込み、ブラウザおよび HTTP のシナリオを実行して、機械可読・人間可読の検証レポートを出力します。

## 想定ユースケース

- WAF 製品の公開前検証
- エクスポートされた `verify-manifest` を基準にしたリグレッションチェック
- HTML / JSON / CI 向けの検証出力を必要とするチーム

## 主な特徴

- ブラウザ / HTTP ランナーによる検証
- `tukuyomi`、`tukuyomi-proxy`、`tukuyomi-edge` 向けのマニフェスト駆動チェック
- HTML / JSON / JUnit / CI サマリー出力
- `[web]` に必須の実行時依存を持ち込まない外部検証ツールとしての役割

## 公開配布

- 最新の公開バイナリ: [`v0.1.5`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.1.5)
- ファミリー全体のリリース一覧: [`tukuyomi-releases`](https://github.com/vril-dev/tukuyomi-releases/releases)

## 関連ドキュメント

- ファミリー概要: [`../../../README.ja.md`](../../../README.ja.md)
- 製品比較: [`../../product-comparison.ja.md`](../../product-comparison.ja.md)

詳細なレポート / UI ドキュメントはバイナリバンドルに同梱されます。
