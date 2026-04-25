import assert from "node:assert/strict";
import test from "node:test";
import {
  extractRequestEventFields,
  filterLogLinesByReqID,
  formatRequestEventRoleLabel,
  sortLogLinesNewestFirst,
  summarizeRequestEvents,
  type LogLine,
} from "./logRequestDetails.js";

test("filterLogLinesByReqID matches trimmed request IDs", () => {
  const lines: LogLine[] = [
    { req_id: "req-1", event: "waf_block" },
    { req_id: "req-2", event: "rate_limited" },
    { req_id: "req-1", event: "bot_challenge" },
  ];

  assert.deepEqual(
    filterLogLinesByReqID(lines, " req-1 ").map((line) => line.event),
    ["waf_block", "bot_challenge"]
  );
});

test("sortLogLinesNewestFirst orders newest first and keeps invalid timestamps last", () => {
  const lines: LogLine[] = [
    { ts: "2026-04-01T00:01:00Z", event: "old" },
    { ts: "not-a-time", event: "invalid" },
    { ts: "2026-04-01T00:02:00Z", event: "same-first" },
    { ts: "2026-04-01T00:03:00Z", event: "newest" },
    { ts: "2026-04-01T00:02:00Z", event: "same-second" },
  ];

  assert.deepEqual(
    sortLogLinesNewestFirst(lines).map((line) => line.event),
    ["newest", "same-second", "same-first", "old", "invalid"]
  );
});

test("summarizeRequestEvents derives blocked decision for waf blocks", () => {
  const summary = summarizeRequestEvents("req-waf", [
    { ts: "2026-04-01T00:02:00Z", event: "waf_block", rule_id: 942100, status: 403 },
  ]);

  assert.equal(summary.explanation.decision, "blocked");
  assert.equal(summary.explanation.primaryReason?.policyFamily, "waf");
  assert.equal(summary.explanation.primaryReason?.event, "waf_block");
  assert.equal(summary.explanation.primaryReasonText, "waf");
  assert.equal(summary.explanation.httpStatus, 403);
  assert.deepEqual(summary.explanation.contributingPolicies, ["waf"]);
  assert.equal(summary.explanation.rationale, "Blocked by waf_block (rule 942100)");
  assert.equal(summary.orderedEvents[0]?.role, "enforced");
});

test("summarizeRequestEvents keeps rate limit as final enforced decision", () => {
  const summary = summarizeRequestEvents("req-rate", [
    {
      ts: "2026-04-01T00:01:00Z",
      event: "bot_challenge_dry_run",
      status: 429,
    },
    {
      ts: "2026-04-01T00:02:00Z",
      event: "semantic_anomaly",
      action: "log_only",
      score: 5,
    },
    {
      ts: "2026-04-01T00:03:00Z",
      event: "rate_limited",
      status: 429,
      policy_id: "login",
    },
  ]);

  assert.equal(summary.explanation.decision, "rate_limited");
  assert.equal(summary.explanation.primaryReason?.policyFamily, "rate_limit");
  assert.equal(summary.explanation.httpStatus, 429);
  assert.deepEqual(summary.explanation.contributingPolicies, [
    "bot_defense",
    "semantic",
    "rate_limit",
  ]);
  assert.deepEqual(summary.explanation.dryRunPolicies, ["bot_defense"]);
});

test("summarizeRequestEvents derives semantic challenge decisions from enforcing status", () => {
  const summary = summarizeRequestEvents("req-sem-challenge", [
    {
      ts: "2026-04-01T00:01:00Z",
      event: "semantic_anomaly",
      action: "challenge",
      status: 429,
      score: 7,
    },
  ]);

  assert.equal(summary.explanation.decision, "challenged");
  assert.equal(summary.explanation.primaryReason?.policyFamily, "semantic");
  assert.equal(summary.explanation.primaryReason?.role, "enforced");
  assert.equal(summary.explanation.httpStatus, 429);
  assert.equal(summary.explanation.primaryReasonText, "semantic");
});

test("summarizeRequestEvents keeps legacy semantic challenge logs challenged without status", () => {
  const summary = summarizeRequestEvents("req-sem-legacy", [
    {
      ts: "2026-04-01T00:01:00Z",
      event: "semantic_anomaly",
      action: "challenge",
      score: 7,
    },
  ]);

  assert.equal(summary.explanation.decision, "challenged");
  assert.equal(summary.explanation.primaryReason?.policyFamily, "semantic");
  assert.equal(summary.explanation.primaryReason?.role, "enforced");
  assert.equal(summary.explanation.httpStatus, null);
  assert.equal(summary.explanation.httpStatusText, "not enforced");
  assert.equal(summary.explanation.primaryReasonText, "semantic");
});

test("summarizeRequestEvents treats semantic log only as allowed with findings", () => {
  const summary = summarizeRequestEvents("req-sem-log", [
    {
      ts: "2026-04-01T00:01:00Z",
      event: "semantic_anomaly",
      action: "log_only",
      score: 4,
    },
  ]);

  assert.equal(summary.explanation.decision, "allowed_with_findings");
  assert.equal(summary.explanation.primaryReason?.policyFamily, "semantic");
  assert.equal(summary.explanation.primaryReason?.role, "observed");
  assert.equal(summary.explanation.httpStatus, null);
  assert.equal(summary.explanation.httpStatusText, "not enforced");
  assert.equal(summary.explanation.primaryReasonText, "semantic (observed only)");
});

test("summarizeRequestEvents reports dry-run findings without enforced status", () => {
  const summary = summarizeRequestEvents("req-bot-dry", [
    {
      ts: "2026-04-01T00:01:00Z",
      event: "bot_challenge_dry_run",
      status: 429,
      dry_run: true,
    },
  ]);

  assert.equal(summary.explanation.decision, "allowed_with_findings");
  assert.equal(summary.explanation.primaryReason?.policyFamily, "bot_defense");
  assert.equal(summary.explanation.primaryReason?.role, "dry_run");
  assert.equal(summary.explanation.primaryReason?.enforced, false);
  assert.deepEqual(summary.explanation.contributingPolicies, ["bot_defense"]);
  assert.deepEqual(summary.explanation.dryRunPolicies, ["bot_defense"]);
  assert.equal(summary.explanation.httpStatus, null);
  assert.equal(summary.explanation.primaryReasonText, "bot defense (dry-run, non-enforcing)");
});

test("summarizeRequestEvents ignores informational events for primary reason selection", () => {
  const summary = summarizeRequestEvents("req-mixed", [
    {
      ts: "2026-04-01T00:01:00Z",
      event: "proxy_route",
    },
    {
      ts: "2026-04-01T00:02:00Z",
      event: "waf_block",
      rule_id: 949110,
      status: 403,
    },
    {
      ts: "2026-04-01T00:03:00Z",
      event: "waf_hit_allow",
      status: 200,
    },
  ]);

  assert.equal(summary.explanation.primaryReason?.event, "waf_block");
  assert.equal(summary.orderedEvents[0]?.role, "informational");
  assert.equal(summary.orderedEvents[1]?.role, "enforced");
  assert.equal(summary.orderedEvents[2]?.role, "informational");
});

test("formatRequestEventRoleLabel renders info badge label for informational events", () => {
  assert.equal(formatRequestEventRoleLabel("informational"), "info");
  assert.equal(formatRequestEventRoleLabel("dry_run"), "dry-run");
  assert.equal(formatRequestEventRoleLabel("enforced"), "enforced");
});

test("extractRequestEventFields formats arrays and objects for cards", () => {
  const fields = extractRequestEventFields({
    status: 403,
    rule_id: 942100,
    base_score: 1,
    stateful_score: 3,
    provider_score: 2,
    actor_key: "subject:abcd1234",
    path_class: "/api/v1/users/{num}",
    target_class: "admin_management",
    surface_class: "query+json_body+headers",
    reason_list: ["ua", "velocity"],
    base_reason_list: ["ua"],
    stateful_reason_list: ["stateful:admin_after_suspicious_activity"],
    provider_reason_list: ["provider:attack_family:sql_injection", "provider:evidence:semantic_sql"],
    score_breakdown: [{ name: "ua", score: 20 }],
    base_score_breakdown: [{ reason: "query:xss_pattern", score: 1 }],
    stateful_score_breakdown: [{ reason: "stateful:admin_after_suspicious_activity", score: 3 }],
    provider_score_breakdown: [{ reason: "provider:sql_injection", score: 2 }],
    provider_name: "builtin_attack_family",
    provider_attack_family: "sql_injection",
    provider_confidence: "high",
    semantic_context: { actor_basis: "subject", path_class: "/api/v1/users/{num}" },
    semantic_fingerprints: { query_hash: "semfp:query:1234", combined_hash: "semfp:combined:5678" },
    semantic_feature_buckets: ["actor:subject", "surface:query"],
    semantic_stateful_history: { prior_requests: 2, prior_suspicious_requests: 2, max_seen_target_class: "authenticated_app" },
  });

  assert.deepEqual(fields, [
    { label: "Status", value: "403" },
    { label: "Rule ID", value: "942100" },
    { label: "Base Score", value: "1" },
    { label: "Stateful Score", value: "3" },
    { label: "Provider Score", value: "2" },
    { label: "Actor Key", value: "subject:abcd1234" },
    { label: "Path Class", value: "/api/v1/users/{num}" },
    { label: "Target Class", value: "admin_management" },
    { label: "Surface Class", value: "query+json_body+headers" },
    { label: "Reasons", value: '["ua","velocity"]' },
    { label: "Score Breakdown", value: '[{"name":"ua","score":20}]' },
    { label: "Base Reasons", value: '["ua"]' },
    { label: "Stateful Reasons", value: '["stateful:admin_after_suspicious_activity"]' },
    { label: "Provider Reasons", value: '["provider:attack_family:sql_injection","provider:evidence:semantic_sql"]' },
    { label: "Base Score Breakdown", value: '[{"reason":"query:xss_pattern","score":1}]' },
    { label: "Stateful Score Breakdown", value: '[{"reason":"stateful:admin_after_suspicious_activity","score":3}]' },
    { label: "Provider Score Breakdown", value: '[{"reason":"provider:sql_injection","score":2}]' },
    { label: "Provider", value: "builtin_attack_family" },
    { label: "Provider Attack Family", value: "sql_injection" },
    { label: "Provider Confidence", value: "high" },
    { label: "Semantic Context", value: '{"actor_basis":"subject","path_class":"/api/v1/users/{num}"}' },
    { label: "Semantic Fingerprints", value: '{"query_hash":"semfp:query:1234","combined_hash":"semfp:combined:5678"}' },
    { label: "Semantic Buckets", value: '["actor:subject","surface:query"]' },
    { label: "Stateful History", value: '{"prior_requests":2,"prior_suspicious_requests":2,"max_seen_target_class":"authenticated_app"}' },
  ]);
});
