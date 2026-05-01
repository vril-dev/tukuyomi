# Chapter 8. FP Tuner API and AI integration

Chapter 7 covered the **manual** false-positive workflow. This chapter
covers tukuyomi's **FP Tuner (False-Positive Tuner)**. FP Tuner takes
observed WAF block events, has an AI provider draft **safe, scoped
Coraza exclusion rules**, and applies them under operator approval.

![FP Tuner screen](../../images/ui-samples/10-fp-tuner.png)

The contract here is v1: the HTTP-provider Coraza false-positive
exclusion tuning flow. We cover the Propose and Apply endpoints, the
approval token, audit trail, related env vars, and the OpenAI- /
Claude-Messages-compatible command providers.

## 8.1 Why FP Tuner exists

Walking through Chapter 7 honestly takes real effort per false
positive — capture evidence, scope the impact, draft a narrow rule,
validate it. Most false positives, however, follow a simple shape:
"a specific host / path / parameter triggers a specific rule_id". That
makes **writing every rule from scratch each time** disproportionate to
the actual decision being made.

FP Tuner compresses the flow into three steps:

- Pass an observed block event as input.
- Have an AI provider draft a **scoped exclusion rule**.
- After **operator approval**, apply it to `tukuyomi.conf`.

The AI never rewrites rules on its own, and **an unapproved apply
cannot reach production** — that is the foundational contract.

## 8.2 Endpoints

The two endpoints offered by FP Tuner v1:

- `POST /tukuyomi-api/fp-tuner/propose`
- `POST /tukuyomi-api/fp-tuner/apply`

`propose` has the AI provider draft a proposal; `apply` puts it into
the live environment.

## 8.3 Propose

### 8.3.1 Request

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

Notes:

- `event` is **optional**. When omitted, the server looks up the most
  recent `waf_block` event from DB `waf_events`.
- **Unknown fields are rejected.**
- The provider is expected to return either a single safe scoped Coraza
  exclusion proposal, or an explicit `no_proposal`.

### 8.3.2 Response (with a proposal)

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
    "reason": "Provider-generated response from the HTTP FP tuner flow.",
    "confidence": 0.84,
    "target_path": "tukuyomi.conf",
    "rule_line": "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""
  }
}
```

Key points:

- When `approval.required=true`, **a non-simulate apply requires an
  `approval_token`**.
- `proposal.rule_line` is a `SecRule` chain. It narrows the host with
  a regex, narrows the path with `@beginsWith /search`, and uses
  `ctl:ruleRemoveTargetById` to **remove only the targeted variable on
  the targeted rule**.
- `confidence` is a subjective score from the provider. It alone never
  triggers an automatic apply (it is a piece of supporting evidence).

### 8.3.3 Response (`no_proposal`)

If the provider judges that "no safe exclusion is justified", it
returns `no_proposal` instead of a proposal:

```json
{
  "ok": true,
  "contract_version": "fp_tuner.v1",
  "mode": "http",
  "source": "request",
  "approval": { "required": false },
  "input": { /* same as above */ },
  "no_proposal": {
    "decision": "no_proposal",
    "reason": "Insufficient evidence to justify a safe Coraza scoped exclusion for this event.",
    "confidence": 0.12
  }
}
```

This applies when the block looks legitimate, when the request might
plausibly be an attack, or when the scope cannot be carved cleanly.
**FP Tuner does not invent an exclusion when there is no good
justification** — that is the safe-side default.

## 8.4 Apply

### 8.4.1 Request

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

Notes:

- **`simulate` defaults to `true`.** The change does not reach
  production unless you set it to `false` explicitly.
- `rule_line` is validated against a **strict allow-list pattern**;
  only scoped exclusion shapes are permitted. You cannot inject
  arbitrary `SecRule`s through this endpoint.
- When `WAF_FP_TUNER_REQUIRE_APPROVAL=true` and `simulate=false`, an
  **`approval_token` is required**.

### 8.4.2 Response (simulate)

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

Simulation does not write the file. `preview_etag` is a weak etag used
to identify the diff.

### 8.4.3 Response (real apply)

```json
{
  "ok": true,
  "contract_version": "fp_tuner.v1",
  "etag": "W/\"sha256:...\"",
  "hot_reloaded": true,
  "reloaded_file": "tukuyomi.conf"
}
```

`hot_reloaded=true` means the rule asset behind `tukuyomi.conf` was
reloaded live.

## 8.5 Security behavior

Safe-side behaviors of FP Tuner:

- **The request payload sent to the provider is sanitized first.**
- The provider is told to consider only **Coraza /
  ModSecurity-compatible host-aware scoped exclusions**.
- When the provider judges the event is not a credible false positive
  or the basis is insufficient, **`no_proposal` is the expected
  response**.
- Safe proposal scope is bound to the observed `scheme +
  host[:default-port] + path + rule_id + matched_variable`.
- For `http:80` / `https:443`, a host scope may use a **narrow
  optional-default-port regex** like `^example\.com(:80)?$` /
  `^example\.com(:443)?$`.
- Mask categories include bearer / JWT-like tokens, email addresses,
  IPv4 addresses, and common secret query keys.
- **Apply only accepts the scoped exclusion form.** Arbitrary rule
  insertion is impossible.
- Propose / apply actions are **appended to
  `WAF_FP_TUNER_AUDIT_FILE`** (default
  `audit/fp-tuner-audit.ndjson`).
- The audit path must be writable by the runtime UID / GID
  (`PUID` / `GUID`).

## 8.6 Related env vars

The three relevant environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `WAF_FP_TUNER_REQUIRE_APPROVAL` | `true` | Whether apply requires an approval token |
| `WAF_FP_TUNER_APPROVAL_TTL_SEC` | `600` | Lifetime of an approval token (seconds) |
| `WAF_FP_TUNER_AUDIT_FILE` | `audit/fp-tuner-audit.ndjson` | Audit log destination |

Disabling the approval token would let an operator apply changes
without explicit approval. Production keeps it at `true` as the
**safe-side default**.

## 8.7 Local HTTP-mode contract test

The repository ships scripts that verify the propose / apply flow
against the HTTP provider, including provider request masking and
response contract handling against a local stub provider:

```bash
scripts/test_fp_tuner_http.sh
```

Wiring it into CI is a good way to make sure the provider-side contract
does not silently break.

## 8.8 Command bridge tests

Beyond HTTP providers, **command-based providers** can also be wired
in. The minimal contract is "start a single shell command, send the
request on stdin, read the response on stdout":

```bash
scripts/test_fp_tuner_bridge_command.sh
```

Components:

- Bridge server: `scripts/fp_tuner_provider_bridge.py`
- Example command provider: `scripts/fp_tuner_provider_cmd_example.sh`
- `BRIDGE_COMMAND=/path/to/cmd.sh` overrides the provider command.

This lets you plug in any heuristic or AI system you have in-house as
an FP Tuner provider.

### 8.8.1 OpenAI-compatible command provider

A provider that calls an OpenAI-compatible API (OpenAI, Azure OpenAI,
or any compatible LLM gateway) is shipped:

- Script: `scripts/fp_tuner_provider_openai.sh`
- Required env:
  - `FP_TUNER_OPENAI_API_KEY` (or `OPENAI_API_KEY`)
  - `FP_TUNER_OPENAI_MODEL` (or `OPENAI_MODEL`, or the request's
    `model`)
- Optional env:
  - `FP_TUNER_OPENAI_API_TYPE` (default `responses`, or `chat`)
  - `FP_TUNER_OPENAI_BASE_URL` (default `https://api.openai.com/v1`)
  - `FP_TUNER_OPENAI_ENDPOINT` (override the full endpoint URL)
  - `FP_TUNER_OPENAI_TIMEOUT_SEC` (default `30`)

Local mock validation:

```bash
scripts/test_fp_tuner_openai_command.sh
```

### 8.8.2 Claude Messages command provider

A provider that calls the Anthropic Claude Messages API is also
shipped:

- Script: `scripts/fp_tuner_provider_claude.sh`
- Required env:
  - `FP_TUNER_CLAUDE_API_KEY` (or `ANTHROPIC_API_KEY`)
  - `FP_TUNER_CLAUDE_MODEL` (or `ANTHROPIC_MODEL`, or the request's
    `model`)
- Optional env:
  - `FP_TUNER_CLAUDE_BASE_URL` (default `https://api.anthropic.com`)
  - `FP_TUNER_CLAUDE_ENDPOINT` (override the full endpoint URL;
    default `/v1/messages`)
  - `FP_TUNER_CLAUDE_API_VERSION` (default `2023-06-01`)
  - `FP_TUNER_CLAUDE_BETA` (optional `anthropic-beta` header value)
  - `FP_TUNER_CLAUDE_TIMEOUT_SEC` (default `30`)
  - `FP_TUNER_CLAUDE_MAX_TOKENS` (default `700`)

Local mock validation:

```bash
scripts/test_fp_tuner_claude_command.sh
```

In both cases, the `proposal.rule_line` emitted by the provider obeys
the contracts we already covered (scoped exclusion shape, strict
allow-list, approval token). **The safety boundary of FP Tuner is the
same regardless of provider type** — that is the design point of this
chapter.

## 8.9 Recap

- FP Tuner is the flow where **the AI drafts an exclusion proposal,
  the operator approves, and the system applies**.
- The propose / apply pair is hardened by **a strict allow-list, an
  approval token, and an audit log**.
- Providers are pluggable via a command-provider format — OpenAI,
  Claude, and so on.
- The safe-side defaults are `simulate=true` and
  `WAF_FP_TUNER_REQUIRE_APPROVAL=true`.

## 8.10 Bridge to the next chapter

Chapters 7 and 8 dealt with post-hoc handling of the Coraza WAF's
inspection result. Chapter 9 covers the separate axis tukuyomi
provides for **request-time security plugins** — the interface, the
`SecurityEvent` contract, ordering, registration, and a minimal example.
