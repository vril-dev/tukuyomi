[English](fp-tuner-api.md) | [日本語](fp-tuner-api.ja.md)

# FP Tuner API Contract (v1)

この文書は、外部 HTTP プロバイダを使う FP tuning flow の current API contract を定義します。

## Endpoints

- `POST /tukuyomi-api/fp-tuner/propose`
- `POST /tukuyomi-api/fp-tuner/apply`
- `GET /tukuyomi-api/fp-tuner/recent-waf-blocks`

## 1) Propose

### Request

```json
{
  "target_path": "rules/tukuyomi.conf",
  "event": {
    "event_id": "manual-test-001",
    "method": "GET",
    "path": "/search",
    "rule_id": 100004,
    "status": 403,
    "matched_variable": "ARGS:q",
    "matched_value": "select * from users"
  }
}
```

注意:
- `event` は optional です。省略した場合、server は `waf-events.ndjson` から最新の `waf_block` event を探します。
- unknown field は reject されます。

### Response

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
    "reason": "外部 HTTP プロバイダを使う提案フローのレスポンス。",
    "confidence": 0.84,
    "target_path": "rules/tukuyomi.conf",
    "rule_line": "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""
  }
}
```

注意:
- `approval.required=true` の場合、simulate しない apply には `approval_token` が必要です。
- 安全な scoped exclusion を正当化できない場合、provider は `proposal` の代わりに `no_proposal` を返せます。

## 2) Apply

### Request

```json
{
  "proposal": {
    "id": "fp-http-001",
    "target_path": "rules/tukuyomi.conf",
    "rule_line": "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""
  },
  "simulate": true,
  "approval_token": "6f9d...token..."
}
```

注意:
- `simulate` の default は `true` です。
- `rule_line` は strict allow-list pattern で validation されます。
- `WAF_FP_TUNER_REQUIRE_APPROVAL=true` かつ `simulate=false` の場合、`approval_token` が必要です。

### Response (simulate)

```json
{
  "ok": true,
  "contract_version": "fp_tuner.v1",
  "simulated": true,
  "hot_reloaded": false,
  "reloaded_file": "rules/tukuyomi.conf",
  "preview_etag": "W/\"sha256:...\""
}
```

### Response (real apply)

```json
{
  "ok": true,
  "contract_version": "fp_tuner.v1",
  "etag": "W/\"sha256:...\"",
  "hot_reloaded": true,
  "reloaded_file": "rules/tukuyomi.conf"
}
```

## Security Behavior

- provider request payload は外部送信前に sanitize されます。
- masked category には bearer/jwt-like token、email、IPv4、common secret query key が含まれます。
- apply で受け付けるのは scoped exclusion format だけです。
- propose / apply action は `WAF_FP_TUNER_AUDIT_FILE`（default `logs/coraza/fp-tuner-audit.ndjson`）へ追記されます。
- audit path は runtime UID/GID（`PUID` / `GUID`）で書き込めるようにしてください。

## Related Env Vars

- `WAF_FP_TUNER_ENDPOINT`
- `WAF_FP_TUNER_API_KEY`
- `WAF_FP_TUNER_MODEL`
- `WAF_FP_TUNER_TIMEOUT_SEC`
- `WAF_FP_TUNER_REQUIRE_APPROVAL`（default `true`）
- `WAF_FP_TUNER_APPROVAL_TTL_SEC`（default `600`）
- `WAF_FP_TUNER_AUDIT_FILE`（default `logs/coraza/fp-tuner-audit.ndjson`）

## Local HTTP Mode Contract Test

`scripts/test_fp_tuner_http.sh` を実行すると次を確認できます。

- HTTP ベースの propose / apply flow
- provider request masking behavior
- local stub provider を使った response contract handling

## Command Bridge Test

`scripts/test_fp_tuner_bridge_command.sh` を実行すると command-based provider integration を確認できます。

- Bridge server: `scripts/fp_tuner_provider_bridge.py`
- Example command provider: `scripts/fp_tuner_provider_cmd_example.sh`
- `BRIDGE_COMMAND=/path/to/cmd.sh` で provider command を override できます。

### OpenAI-Compatible Command Provider

- Script: `scripts/fp_tuner_provider_openai.sh`
- Required env:
  - `FP_TUNER_OPENAI_API_KEY`（または `OPENAI_API_KEY`）
  - `FP_TUNER_OPENAI_MODEL`（または `OPENAI_MODEL`、または provider request の `model`）
- Optional env:
  - `FP_TUNER_OPENAI_API_TYPE`（default `responses`、または `chat`）
  - `FP_TUNER_OPENAI_BASE_URL`（default `https://api.openai.com/v1`）
  - `FP_TUNER_OPENAI_ENDPOINT`（full endpoint URL を override）
  - `FP_TUNER_OPENAI_TIMEOUT_SEC`（default `30`）

local mock validation:

- `scripts/test_fp_tuner_openai_command.sh`

### Claude Messages Command Provider

- Script: `scripts/fp_tuner_provider_claude.sh`
- Required env:
  - `FP_TUNER_CLAUDE_API_KEY`（または `ANTHROPIC_API_KEY`）
  - `FP_TUNER_CLAUDE_MODEL`（または `ANTHROPIC_MODEL`、または provider request の `model`）
- Optional env:
  - `FP_TUNER_CLAUDE_BASE_URL`（default `https://api.anthropic.com`）
  - `FP_TUNER_CLAUDE_ENDPOINT`（full endpoint URL を override。default `/v1/messages`）
  - `FP_TUNER_CLAUDE_API_VERSION`（default `2023-06-01`）
  - `FP_TUNER_CLAUDE_BETA`（optional な `anthropic-beta` header value）
  - `FP_TUNER_CLAUDE_TIMEOUT_SEC`（default `30`）
  - `FP_TUNER_CLAUDE_MAX_TOKENS`（default `700`）

local mock validation:

- `scripts/test_fp_tuner_claude_command.sh`
