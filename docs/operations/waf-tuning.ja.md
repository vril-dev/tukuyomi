[English](waf-tuning.md) | [日本語](waf-tuning.ja.md)

# WAF誤検知チューニング手順

このドキュメントは、tukuyomi + Coraza + CRS の誤検知（False Positive）を安全に減らすための実運用手順です。

## 1. まず証跡を取る

1. 管理APIでログを取得し、`rule_id` と `path` を確認する。
2. `interesting.ndjson`（`logs/proxy/`）で `req_id` を追跡し、クライアント条件（IP/UA/クエリ）を絞る。
3. 再現可能なHTTPリクエスト（curlやE2E）を必ず残す。

## 2. 影響範囲を切り分ける

1. 単一エンドポイントだけで発生するか確認する。
2. 特定パラメータ・特定メソッドに限定されるか確認する。
3. 本当に攻撃パターンではないと判断できる根拠（仕様、画面、バックエンド実装）を残す。

## 3. 緩和は狭く行う

推奨順序:

1. `data/conf/waf-bypass.json` に対象パスのみの「特別ルール」を設定する。
2. 必要なら専用 `*.conf` を用意し、対象Ruleを `ctl:ruleRemoveById` で限定無効化する。
3. 最終手段として広いパスのバイパスを使う（期限付きで実施し、後で戻す）。

`waf-bypass.json` 例:

```json
{
  "default": {
    "entries": []
  },
  "hosts": {
    "example.com": {
      "entries": [
        { "path": "/search", "extra_rule": "conf/rules/orders-preview.conf" }
      ]
    }
  }
}
```

host scope の優先順は exact `host:port`、次に bare `host`、最後に `default` です。host-specific scope は default を merge せず置き換えます。

`orders-preview.conf` 例:

```conf
SecRuleEngine On

SecRule ARGS:q "@rx (?i)(<script|union([[:space:]]+all)?[[:space:]]+select|benchmark\s*\(|sleep\s*\()" \
  "id:100001,phase:2,deny,status:403,log,msg:'suspicious search query'"
```

## 4. CRS設定の見直し

1. `rules/crs/crs-setup.conf` から import された DB-backed CRS setup asset の Paranoia Level を確認する。
2. 初期導入時は `PL1` から開始し、段階的に上げる。
3. anomaly threshold を下げ過ぎていないか確認する。

## 5. 変更の検証

1. 誤検知が解消された再現リクエストをCI/自動テストに追加する。
2. 代表的な攻撃ペイロード（XSS/SQLi）が引き続きブロックされることを確認する。
3. 変更後24時間はログで過検知/見逃しを監視する。

## 6. 変更管理

1. チューニング内容はPRでレビューする。
2. 変更理由、対象パス、対象Rule ID、有効期限をPR説明に残す。
3. 一時回避を入れた場合は、削除期限をIssue化する。
