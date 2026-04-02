# tukuyomi-center

[English](README.md) | [日本語](README.ja.md)

`tukuyomi-center` は、`tukuyomi-edge` fleet 向けのコントロールプレーンサービスです。デバイス登録、heartbeat 検証、承認済み policy / release の配布を、単一バイナリのサービスで一元管理します。

## 想定ユースケース

- 複数の `tukuyomi-edge` node を運用管理する環境
- 署名付きデバイス登録と heartbeat チェックが必要な環境
- 承認済み policy / binary release の割り当てを伴う rollout

## 主な特徴

- デバイス登録と永続レジストリ管理
- replay / skew check を含む署名付き heartbeat 検証
- 承認済み policy / release の配布ワークフロー
- edge fleet 向けの API-first コントロールプレーン

## 公開配布

- 最新の公開バイナリ: [`v0.6.4`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.6.4)
- ファミリー全体のリリース一覧: [`tukuyomi-releases`](https://github.com/vril-dev/tukuyomi-releases/releases)

## 関連ドキュメント

- ファミリー概要: [`../../../README.ja.md`](../../../README.ja.md)
- 製品比較: [`../../product-comparison.ja.md`](../../product-comparison.ja.md)

詳細な API / 運用ドキュメントはバイナリバンドルに同梱されます。
