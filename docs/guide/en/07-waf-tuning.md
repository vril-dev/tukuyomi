# Chapter 7. Tuning WAF false positives

The first thing you face after putting a WAF into production is **how to
deal with false positives**. Coraza + OWASP CRS is powerful, but
business-application queries and parameters often look uncomfortably
close to attack patterns.

This chapter walks through how to **safely, narrowly, and traceably**
reduce false positives in a tukuyomi + Coraza + CRS stack. AI-assisted FP
Tuner is covered separately in Chapter 8; this chapter is about the
**baseline operator workflow you do by hand**.

![Logs screen](../../images/ui-samples/02-logs.png)

## 7.1 The baseline mindset

Before commands, here is the stance to keep:

- **Move only after capturing evidence.** Always record the `req_id`,
  the rule that fired, the path involved, and the client information for
  the blocked request.
- **Scope the impact.** Articulate whether the block is limited to a
  single endpoint, a single parameter, or a single method.
- **Mitigate at the smallest possible unit.** Do not start with a wide
  bypass. A per-path `extra_rule` snippet is the first option.
- **Validate and record.** Add a regression-style request to CI and
  confirm that attack payloads are still blocked.
- **Time-bound any temporary workaround.** Always apply with an expiry,
  and create an issue to remove it later.

Mitigations that fail any of these five tend to grow into **loose holes
that nobody remembers the reason for**. The tukuyomi WAF tuning flow is
shaped to keep these five in order.

## 7.2 Step 1: capture evidence

### 7.2.1 Confirm rule_id and path from logs

Pull logs through the admin API and identify the offending `rule_id`
and `path`. The Logs screen exposes the same data.

`/tukuyomi-api/logs/read?src=waf&req_id=<id>` filters WAF events to a
single `req_id`. Narrow client IP, UA, and query down to a single case.

### 7.2.2 Keep a reproducible HTTP request

Working only from "an approximate description of the request" in
tickets or hallway conversations breaks the validation step later. Use
`curl`, an E2E script, or a test fixture to pin down a **reproducible
HTTP request**. It feeds §7.6.

## 7.3 Step 2: scope the impact

Use the evidence to answer three questions:

1. Is the block limited to a **single endpoint**?
2. Is it limited to a **specific parameter / method / Content-Type**?
3. What is the basis for concluding the request is **not** an attack
   pattern (specification, screen behavior, backend implementation,
   internal ticket)?

The last question fixes the responsibility boundary for the
mitigation. Write down the basis in plain language so that someone
else can read it later and agree.

## 7.4 Step 3: mitigate narrowly

Three mitigation options exist, **listed from narrowest to widest**.
**Pick from the top whenever possible.**

1. **Set a per-path `extra_rule` in `Bypass Rules`.**
2. **Author a dedicated `*.conf` asset under `Rules > Advanced > Bypass
   snippets` and use `ctl:ruleRemoveById` for narrow-scoped rule
   removal.**
3. **As a last resort, use a wider bypass on a path.** Always with an
   expiry, and remove it later.

We look at each in turn.

![Bypass Rules](../../images/ui-samples/05-bypass-rules.png)

### 7.4.1 Per-path tuning with `extra_rule`

The JSON for `Bypass Rules` looks like:

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

Host scope precedence:

1. Exact `host:port`
2. Bare `host`
3. `default`

A subtle point: **a host-specific scope replaces `default` rather than
merging with it**. The moment you write `hosts."example.com"`,
`default.entries` no longer applies for that host. If you want both,
you have to repeat the entries on the host scope.

`extra_rule` is a **Coraza-backed tuning hook**. It applies a snippet
managed under `Rules`, such as `orders-preview.conf`, to the targeted
path only:

```conf
SecRuleEngine On

SecRule ARGS:q "@rx (?i)(<script|union([[:space:]]+all)?[[:space:]]+select|benchmark\s*\(|sleep\s*\()" \
  "id:100001,phase:2,deny,status:403,log,msg:'suspicious search query'"
```

This adds a more narrowly tuned deny rule against `ARGS:q` for that
path. Conceptually it lets you **layer your own deny rule on top of
the broad CRS rule set, only on that path**.

If the active WAF engine is not Coraza (for instance, if a future
ModSecurity adapter ships), `extra_rule`'s Coraza snippet is not
applicable directly. In that case use a full bypass entry or
engine-native tuning.

### 7.4.2 Narrow disable with `ctl:ruleRemoveById`

Sometimes the right move is to **disable a specific CRS rule id in a
narrow scope**, rather than wiring up your own `extra_rule` snippet.
Add a `*.conf` under `Rules > Advanced > Bypass snippets` that uses
`ctl:ruleRemoveById`:

```conf
SecRule REQUEST_URI "@beginsWith /api/legacy/"
  "id:200001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
```

`ctl:ruleRemoveById` removes the named rule **only for that request**.
With `@beginsWith` narrowing the path and a single rule id removed,
the overall sensitivity does not change — only that path passes.

### 7.4.3 Wider bypass as a last resort

When neither of the above can absorb the case, fall back to a wider
path bypass. Always do the following:

- **Set an expiry** (with reasoning, for example 30 / 60 days).
- **File an issue** that documents whose responsibility it is to
  remove it on schedule.
- **Document the removal condition in the PR** ("retire when
  `/legacy/foo` is deprecated", and so on).

The whole operations process should keep these expiries on the radar,
so loose holes do not silently age.

## 7.5 Step 4: review CRS settings

Sometimes the right answer is at the **CRS-wide sensitivity level**
rather than a per-path tweak. Touch points:

1. **Confirm the Paranoia Level** of the DB-backed CRS setup asset
   imported from `rules/crs/crs-setup.conf`.
2. **Start at `PL1`** for initial deployments and ramp gradually.
3. **Do not lower the anomaly threshold** too aggressively.

Paranoia Level (PL) is a four-stage sensitivity dial in CRS. Higher PL
means stronger detection but higher false-positive rate. The safe
production starting point is PL1, with PL2 as a candidate after
operations stabilize.

The anomaly threshold is the score-cumulative threshold at which CRS
blocks. Lowering it too much makes the WAF block on minor anomalies
and breeds false positives.

## 7.6 Step 5: validate the change

After applying a mitigation, verify it actually does what you intend
in **two directions**.

### 7.6.1 Confirm the false positive no longer reproduces

Add the reproducible request from §7.2 to your CI / automated tests.
In production, the mitigated request is expected to pass with `200`;
in CI you assert that **"this request is not blocked by the WAF"**.
With that asserted, you will catch a regression quickly if a future
CRS upgrade breaks the mitigation.

### 7.6.2 Confirm attack payloads are still blocked

Verify that the mitigation has not widened too much. Send representative
XSS / SQLi payloads to the same path and confirm the WAF still blocks
them with `403`.

### 7.6.3 24-hour log monitoring

For the first 24 hours after rollout, watch both:

- Did false positives drop?
- Did **misses** rise?

via the Logs / Notifications screens.

## 7.7 Step 6: change management

Finally, leave the mitigation itself in a form that **can be traced
later**:

1. The tuning content goes through **PR review**.
2. The PR description always records:
   - The reason (basis for the false positive: spec, screen,
     backend behavior).
   - The targeted path.
   - The targeted Rule ID.
   - The expiry, for any temporary workaround.
3. Temporary workarounds get a **deletion-deadline issue**.

These are the minimum scaffolding for a "people change but the
knowledge does not get lost" workflow. The tukuyomi admin UI persists
changes to the DB, but **the operational reasoning** lives in git PR
history and the issue tracker.

## 7.8 Recap

- Approach false positives through six steps: **evidence → scope →
  narrow mitigation → CRS review → validation → change management**.
- The mitigation hierarchy goes from narrow to wide: **per-path
  `extra_rule` snippet → `ctl:ruleRemoveById` rule removal → wide
  bypass with an expiry**.
- A host scope in `Bypass Rules` **does not merge** with `default`.
- Verifying that attack payloads still get blocked is part of the
  mitigation, not an afterthought.
- Time-bound temporary workarounds and track them in issues.

## 7.9 Bridge to the next chapter

This chapter was about the **manual** false-positive workflow. tukuyomi
also offers an **AI-assisted false-positive reduction tool — FP Tuner**.
The next chapter covers the API contract, the Propose / Apply behavior,
and the OpenAI- / Claude-Messages-compatible command providers.
