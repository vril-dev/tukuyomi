[English](fp-tuner-api.md) | [日本語](fp-tuner-api.ja.md)

# FP Tuner API Contract (v1)

This document defines the current API contract for Coraza false-positive exclusion tuning over the HTTP provider path.

## Endpoints

- `POST /tukuyomi-api/fp-tuner/propose`
- `POST /tukuyomi-api/fp-tuner/apply`

## 1) Propose

### Request

```json
{
  "target_path": "rules/tukuyomi.conf",
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

Notes:
- `event` is optional. If omitted, server tries the latest `waf_block` event from DB `waf_events`.
- Unknown fields are rejected.
- The provider is expected to either return one safe scoped Coraza exclusion proposal or an explicit `no_proposal`.

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
    "reason": "Provider-generated response for HTTP FP tuner flow.",
    "confidence": 0.84,
    "target_path": "rules/tukuyomi.conf",
    "rule_line": "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""
  }
}
```

Notes:
- `approval.required=true` means non-simulated apply requires `approval_token`.

### Response (`no_proposal`)

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
    "reason": "The evidence does not justify a safe Coraza scoped exclusion for this event.",
    "confidence": 0.12
  }
}
```

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

Notes:
- `simulate` defaults to `true`.
- `rule_line` is validated against a strict allow-list pattern.
- When `WAF_FP_TUNER_REQUIRE_APPROVAL=true` and `simulate=false`, `approval_token` is required.

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

- Provider request payload is sanitized before external send.
- Provider is instructed to reason about Coraza / ModSecurity-compatible host-aware scoped exclusions only.
- Provider may return `no_proposal` when the event is not a credible false positive or evidence is insufficient.
- Safe proposal scope is bound to observed `scheme + host[:default-port] + path + rule_id + matched_variable`.
- For `http:80` and `https:443`, host scope may use a narrow optional-default-port regex such as `^example\.com(:80)?$` or `^example\.com(:443)?$`.
- Masked categories include bearer/jwt-like tokens, email, IPv4, and common secret query keys.
- Only scoped exclusion format is accepted for apply.
- Propose/apply actions are appended to `WAF_FP_TUNER_AUDIT_FILE` (default `audit/fp-tuner-audit.ndjson`).
- Ensure the audit path is writable by the runtime UID/GID (`PUID`/`GUID`).

## Related Env Vars

- `WAF_FP_TUNER_REQUIRE_APPROVAL` (`true` by default)
- `WAF_FP_TUNER_APPROVAL_TTL_SEC` (default `600`)
- `WAF_FP_TUNER_AUDIT_FILE` (default `audit/fp-tuner-audit.ndjson`)

## Local HTTP Mode Contract Test

Run `scripts/test_fp_tuner_http.sh` to verify:

- HTTP-provider propose/apply flow
- provider request masking behavior
- response contract handling with a local stub provider

## Command Bridge Test

Run `scripts/test_fp_tuner_bridge_command.sh` to verify command-based provider integration.

- Bridge server: `scripts/fp_tuner_provider_bridge.py`
- Example command provider: `scripts/fp_tuner_provider_cmd_example.sh`
- Override provider command via `BRIDGE_COMMAND=/path/to/cmd.sh`

### OpenAI-Compatible Command Provider

- Script: `scripts/fp_tuner_provider_openai.sh`
- Required envs:
  - `FP_TUNER_OPENAI_API_KEY` (or `OPENAI_API_KEY`)
  - `FP_TUNER_OPENAI_MODEL` (or `OPENAI_MODEL`, or provider request `model`)
- Optional envs:
  - `FP_TUNER_OPENAI_API_TYPE` (`responses` default, or `chat`)
  - `FP_TUNER_OPENAI_BASE_URL` (default `https://api.openai.com/v1`)
  - `FP_TUNER_OPENAI_ENDPOINT` (override full endpoint URL)
  - `FP_TUNER_OPENAI_TIMEOUT_SEC` (default `30`)

Local mock validation:

- `scripts/test_fp_tuner_openai_command.sh`

### Claude Messages Command Provider

- Script: `scripts/fp_tuner_provider_claude.sh`
- Required envs:
  - `FP_TUNER_CLAUDE_API_KEY` (or `ANTHROPIC_API_KEY`)
  - `FP_TUNER_CLAUDE_MODEL` (or `ANTHROPIC_MODEL`, or provider request `model`)
- Optional envs:
  - `FP_TUNER_CLAUDE_BASE_URL` (default `https://api.anthropic.com`)
  - `FP_TUNER_CLAUDE_ENDPOINT` (override full endpoint URL, default `/v1/messages`)
  - `FP_TUNER_CLAUDE_API_VERSION` (default `2023-06-01`)
  - `FP_TUNER_CLAUDE_BETA` (optional `anthropic-beta` header value)
  - `FP_TUNER_CLAUDE_TIMEOUT_SEC` (default `30`)
  - `FP_TUNER_CLAUDE_MAX_TOKENS` (default `700`)

Local mock validation:

- `scripts/test_fp_tuner_claude_command.sh`
