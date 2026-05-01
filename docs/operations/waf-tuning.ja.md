[English](waf-tuning.md) | [日本語](waf-tuning.ja.md)

# WAF 誤検知チューニング手順

この文書は、tukuyomi + Coraza + CRS で発生した誤検知を、安全に減らすための運用手順です。

## 1. まず証跡を取る

1. 管理 API でログを取得し、`rule_id` と `path` を確認する。
2. 同じ `req_id` を `/tukuyomi-api/logs/read?src=waf&req_id=<id>` で追跡し、クライアント条件（IP/UA/クエリ）を絞る。
3. 再現できる HTTP リクエスト（curl や E2E）を必ず残す。

## 2. 影響範囲を切り分ける

1. 単一エンドポイントだけで発生するか確認する。
2. 特定パラメータ・特定メソッドに限定されるか確認する。
3. 攻撃パターンではないと判断できる根拠（仕様、画面動作、バックエンド実装）を残す。

## 3. 緩和は狭く行う

推奨順序:

1. `Bypass Rules` で対象パスだけに `extra_rule` を指定する。
2. 必要なら `Rules` > Advanced > `Bypass snippets` で専用の `*.conf` を用意し、対象 Rule だけを `ctl:ruleRemoveById` で無効化する。
3. 最終手段として広いパスのバイパスを使う。期限付きで実施し、後で必ず戻す。

`extra_rule` は、Coraza を前提にしたチューニング用の差し込み設定です。Coraza 以外の WAF engine を使っている場合は、
Coraza 用 snippet ではなく、full bypass entry か、その engine が提供するチューニング方式を使います。

Bypass Rules の JSON 例:

```json
{
  "default": {
    "entries": []
  },
  "hosts": {
    "example.com": {
      "entries": [
        { "path": "/search", "extra_rule": "orders-preview.conf" }
      ]
    }
  }
}
```

host scope の優先順は、完全一致の `host:port`、次に port を含まない `host`、最後に `default` です。host-specific scope は `default` と merge されず、該当 host の設定で置き換わります。

`Rules` で管理する `orders-preview.conf` の例:

```conf
SecRuleEngine On

SecRule ARGS:q "@rx (?i)(<script|union([[:space:]]+all)?[[:space:]]+select|benchmark\s*\(|sleep\s*\()" \
  "id:100001,phase:2,deny,status:403,log,msg:'suspicious search query'"
```

## 4. CRS設定の見直し

1. `rules/crs/crs-setup.conf` から取り込まれた DB 管理の CRS setup 設定で、Paranoia Level を確認する。
2. 初期導入時は `PL1` から開始し、段階的に上げる。
3. anomaly threshold を下げ過ぎていないか確認する。

## 5. 変更の検証

1. 誤検知が解消された再現リクエストを CI / 自動テストに追加する。
2. 代表的な攻撃ペイロード（XSS / SQLi）が引き続きブロックされることを確認する。
3. 変更後 24 時間はログを確認し、過検知や見逃しが増えていないか監視する。

## 6. 変更管理

1. チューニング内容は PR でレビューする。
2. 変更理由、対象パス、対象 Rule ID、有効期限を PR 説明に残す。
3. 一時回避を入れた場合は、削除期限を Issue として残す。
