[English](fp-tuner-api.md) | [日本語](fp-tuner-api.ja.md)

# FP Tuner API 仕様 (v1)

この文書は、HTTP プロバイダー連携で FP Tuner を使うための API 仕様です。
Coraza によるブロックが誤検知と見込まれるリクエストについて、安全に範囲を絞った除外ルールを提案し、承認後に適用するまでのリクエスト / レスポンスを定義します。

## エンドポイント

- `POST /tukuyomi-api/fp-tuner/propose`
- `POST /tukuyomi-api/fp-tuner/apply`

## 1) Propose（除外案の作成）

### リクエスト

```json
{
  "target_path": "tukuyomi.conf",
  "event": {
    "event_id": "manual-test-001",
    "method": "GET",
    "scheme": "https",
    "host": "search.example.com",
    "path": "/search",
    "query": "q=select+*+from+users",
    "rule_id": 100004,
    "status": 403,
    "matched_variable": "ARGS:q",
    "matched_value": "select * from users"
  }
}
```

補足:

- `event` は任意です。省略した場合、サーバーは DB の `waf_events` から最新の `waf_block` event を取得します。
- 未定義のフィールドは拒否されます。
- プロバイダーは、適用範囲を安全に絞った Coraza 向けの除外案を 1 件返すか、明示的に `no_proposal` を返します。

### レスポンス

```json
{
  "ok": true,
  "contract_version": "fp_tuner.v1",
  "mode": "http",
  "source": "request",
  "approval": {
    "required": true,
    "token": "6f9d...token..."
  },
  "input": {
    "event_id": "manual-test-001",
    "method": "GET",
    "scheme": "https",
    "host": "search.example.com",
    "path": "/search",
    "query": "q=select+*+from+users",
    "rule_id": 100004,
    "status": 403,
    "matched_variable": "ARGS:q",
    "matched_value": "select * from users"
  },
  "proposal": {
    "id": "fp-http-001",
    "title": "Scoped false-positive tuning suggestion",
    "summary": "Scoped false-positive tuning suggestion.",
    "reason": "FP Tuner の HTTP 経路向けにプロバイダーが生成したレスポンス。",
    "confidence": 0.84,
    "target_path": "tukuyomi.conf",
    "rule_line": "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""
  }
}
```

補足:

- `approval.required=true` の場合、`simulate=false` で実際に適用するには `approval_token` が必要です。

### レスポンス (`no_proposal`)

```json
{
  "ok": true,
  "contract_version": "fp_tuner.v1",
  "mode": "http",
  "source": "request",
  "approval": {
    "required": false
  },
  "input": {
    "event_id": "manual-test-001",
    "method": "GET",
    "scheme": "https",
    "host": "search.example.com",
    "path": "/search",
    "query": "q=select+*+from+users",
    "rule_id": 100004,
    "status": 403,
    "matched_variable": "ARGS:q",
    "matched_value": "select * from users"
  },
  "no_proposal": {
    "decision": "no_proposal",
    "reason": "この event には、安全な Coraza 除外ルールを適用するだけの根拠がありません。",
    "confidence": 0.12
  }
}
```

## 2) Apply（除外案の適用）

### リクエスト

```json
{
  "proposal": {
    "id": "fp-http-001",
    "target_path": "tukuyomi.conf",
    "rule_line": "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""
  },
  "simulate": true,
  "approval_token": "6f9d...token..."
}
```

補足:

- `simulate` のデフォルトは `true` です。
- `rule_line` は厳格な許可リストで検証されます。
- `WAF_FP_TUNER_REQUIRE_APPROVAL=true` かつ `simulate=false` の場合、`approval_token` が必要です。

### レスポンス (simulate)

```json
{
  "ok": true,
  "contract_version": "fp_tuner.v1",
  "simulated": true,
  "hot_reloaded": false,
  "reloaded_file": "tukuyomi.conf",
  "preview_etag": "W/\"sha256:...\""
}
```

### レスポンス (実適用)

```json
{
  "ok": true,
  "contract_version": "fp_tuner.v1",
  "etag": "W/\"sha256:...\"",
  "hot_reloaded": true,
  "reloaded_file": "tukuyomi.conf"
}
```

## セキュリティ上の動作

- プロバイダーへ送信するリクエスト本文は、外部送信前にサニタイズされます。
- プロバイダーには、Coraza / ModSecurity 互換の「ホスト条件付き・範囲限定」の除外ルールだけを検討するよう指示します。
- 対象 event が誤検知と判断できない場合、または根拠が不足している場合、プロバイダーは `no_proposal` を返せます。
- 安全な除外案は、観測された `scheme + host[:default-port] + path + rule_id + matched_variable` に紐付けられます。
- `http:80` / `https:443` では、host の条件に `^example\.com(:80)?$` や `^example\.com(:443)?$` のような、デフォルトポートだけを任意扱いにする正規表現を使うことがあります。
- マスク対象には、Bearer / JWT 形式に近いトークン、email、IPv4、一般的な secret query key が含まれます。
- apply で受け付けるのは、範囲限定の除外ルール形式のみです。
- propose / apply の操作は `WAF_FP_TUNER_AUDIT_FILE` に追記されます。デフォルトは `audit/fp-tuner-audit.ndjson` です。
- 監査ログの出力先は、実行時 UID/GID、つまり `PUID` / `GUID`、で書き込めるようにしてください。

## 関連する環境変数

- `WAF_FP_TUNER_REQUIRE_APPROVAL`、デフォルトは `true`
- `WAF_FP_TUNER_APPROVAL_TTL_SEC`、デフォルトは `600`
- `WAF_FP_TUNER_AUDIT_FILE`、デフォルトは `audit/fp-tuner-audit.ndjson`

## ローカル HTTP モードの仕様確認

`scripts/test_fp_tuner_http.sh` を実行すると、次を確認できます。

- HTTP プロバイダー経由の propose / apply の処理
- プロバイダーへ送るリクエストのマスク処理
- ローカル stub プロバイダーを使ったレスポンス処理

## Command Bridge の確認

`scripts/test_fp_tuner_bridge_command.sh` を実行すると、コマンド実行型プロバイダーとの連携を確認できます。

- Bridge サーバー: `scripts/fp_tuner_provider_bridge.py`
- コマンドプロバイダー例: `scripts/fp_tuner_provider_cmd_example.sh`
- `BRIDGE_COMMAND=/path/to/cmd.sh` でプロバイダーコマンドを上書きできます。

### OpenAI 互換コマンドプロバイダー

- スクリプト: `scripts/fp_tuner_provider_openai.sh`
- 必須環境変数:
  - `FP_TUNER_OPENAI_API_KEY`、または `OPENAI_API_KEY`
  - `FP_TUNER_OPENAI_MODEL`、または `OPENAI_MODEL`、またはプロバイダーへ送るリクエストの `model`
- 任意環境変数:
  - `FP_TUNER_OPENAI_API_TYPE`、デフォルトは `responses`、または `chat`
  - `FP_TUNER_OPENAI_BASE_URL`、デフォルトは `https://api.openai.com/v1`
  - `FP_TUNER_OPENAI_ENDPOINT`、エンドポイント URL 全体を上書き
  - `FP_TUNER_OPENAI_TIMEOUT_SEC`、デフォルトは `30`

ローカルモック検証:

- `scripts/test_fp_tuner_openai_command.sh`

### Claude Messages コマンドプロバイダー

- スクリプト: `scripts/fp_tuner_provider_claude.sh`
- 必須環境変数:
  - `FP_TUNER_CLAUDE_API_KEY`、または `ANTHROPIC_API_KEY`
  - `FP_TUNER_CLAUDE_MODEL`、または `ANTHROPIC_MODEL`、またはプロバイダーへ送るリクエストの `model`
- 任意環境変数:
  - `FP_TUNER_CLAUDE_BASE_URL`、デフォルトは `https://api.anthropic.com`
  - `FP_TUNER_CLAUDE_ENDPOINT`、エンドポイント URL 全体を上書き。デフォルトは `/v1/messages`
  - `FP_TUNER_CLAUDE_API_VERSION`、デフォルトは `2023-06-01`
  - `FP_TUNER_CLAUDE_BETA`、任意の `anthropic-beta` ヘッダー値
  - `FP_TUNER_CLAUDE_TIMEOUT_SEC`、デフォルトは `30`
  - `FP_TUNER_CLAUDE_MAX_TOKENS`、デフォルトは `700`

ローカルモック検証:

- `scripts/test_fp_tuner_claude_command.sh`
