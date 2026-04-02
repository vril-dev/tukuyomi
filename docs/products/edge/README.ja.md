# tukuyomi-edge

[English](README.md) | [日本語](README.ja.md)

`tukuyomi-edge` は、Tukuyomi ファミリーのデバイス指向シングルバイナリ・イングレスセキュリティゲートウェイです。`tukuyomi` や `tukuyomi-proxy` と同じ中核 L7 制御を維持しつつ、デバイスアイデンティティとエッジ運用向け機能を追加しています。

## 想定ユースケース

- `systemd + single binary` を前提とする IoT / 拠点配備
- 内蔵ルーティングとポリシー適用を必要とするエッジノード
- 将来的に center コントロールプレーンと連携する fleet 運用

## 主な特徴

- Coraza WAF + OWASP CRS
- 内蔵 admin UI とルートエディタ
- デバイス認証と center 連携を前提とした運用機能
- 通常の L7 制御に加えた実験的なホスト側ハードニング

## 公開配布

- 最新の公開バイナリ: [`v0.12.6`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.12.6)
- ファミリー全体のリリース一覧: [`tukuyomi-releases`](https://github.com/vril-dev/tukuyomi-releases/releases)

## 関連ドキュメント

- ファミリー概要: [`../../../README.ja.md`](../../../README.ja.md)
- 製品比較: [`../../product-comparison.ja.md`](../../product-comparison.ja.md)

詳細な運用ドキュメントと画面キャプチャはバイナリバンドルに同梱されます。
