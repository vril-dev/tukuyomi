[English](waf-tuning.md) | [日本語](waf-tuning.ja.md)

# WAF False Positive Tuning Procedure

This document describes practical operating steps to safely reduce false positives with tukuyomi + Coraza + CRS.

## 1. Collect Evidence First

1. Retrieve logs through the admin API and identify the `rule_id` and `path`.
2. Trace the `req_id` in tukuyomi's `interesting.ndjson` and narrow the client conditions (IP/UA/query).
3. Always keep a reproducible HTTP request (curl or E2E).

## 2. Narrow the Impact Scope

1. Confirm whether it happens only on a single endpoint.
2. Confirm whether it is limited to a specific parameter or specific method.
3. Keep evidence that justifies the conclusion that it is not actually an attack pattern (specification, screen behavior, backend implementation).

## 3. Mitigate Narrowly

Recommended order:

1. Add a path-specific special rule to `data/conf/waf.bypass`.
2. If needed, create a dedicated `*.conf` and disable the target rule narrowly with `ctl:ruleRemoveById`.
3. Use a broader path bypass only as a last resort (time-boxed, and roll it back later).

`waf.bypass` example:

```conf
/api/orders/preview rules/overrides/orders-preview.conf
```

`orders-preview.conf` example:

```conf
SecRule REQUEST_URI "@streq /api/orders/preview" \
  "id:100001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
```

## 4. Review CRS Settings

1. Check the Paranoia Level in `data/rules/crs/crs-setup.conf`.
2. Start from `PL1` during initial rollout and raise it gradually.
3. Confirm that the anomaly threshold has not been lowered too aggressively.

## 5. Validate the Change

1. Add the reproducer request that used to false-positive to CI/automated tests.
2. Confirm that representative attack payloads (XSS/SQLi) are still blocked.
3. Monitor logs for over-blocking and misses during the first 24 hours after the change.

## 6. Change Management

1. Review tuning changes through a PR.
2. Record the reason, target path, target Rule ID, and expiry in the PR description.
3. If you add a temporary workaround, create an Issue for its removal deadline.
