import assert from "node:assert/strict";
import test from "node:test";
import {
  buildProxyRulesAuditPreview,
  buildProxyRulesAuditMetadata,
  filterProxyRulesAuditEntries,
  formatProxyRulesAuditAction,
  formatProxyRulesAuditSummary,
  formatProxyRulesAuditTransition,
  runProxyRulesAuditReload,
  serializeProxyRulesAuditEntries,
} from "./proxyRulesAudit.js";

test("formatProxyRulesAuditAction and transition summarize audit rows", () => {
  assert.equal(formatProxyRulesAuditAction("proxy_rules_apply"), "apply");
  assert.equal(formatProxyRulesAuditAction("proxy_rules_rollback"), "rollback");
  assert.equal(
    formatProxyRulesAuditTransition({
      prev_etag: "etag-old",
      next_etag: "etag-new",
      actor: "alice@example.com",
    }),
    "etag-old -> etag-new"
  );
});

test("buildProxyRulesAuditPreview derives read-only diff preview from audit snapshots", () => {
  const preview = buildProxyRulesAuditPreview({
    event: "proxy_rules_rollback",
    actor: "ops@example.com",
    ip: "203.0.113.10",
    ts: "2026-04-01T00:00:00Z",
    before_raw: '{"upstreams":[{"name":"primary","url":"http://127.0.0.1:8082","weight":1,"enabled":true}]}',
    after_raw: '{"upstreams":[{"name":"primary","url":"http://127.0.0.1:8081","weight":1,"enabled":true}]}',
    prev_etag: "etag-2",
    next_etag: "etag-1",
    restored_from: {
      etag: "etag-1",
      timestamp: "2026-03-31T23:59:00Z",
    },
  });

  assert.equal(preview.mode, "audit");
  assert.equal(preview.applyLabel, undefined);
  assert.equal(preview.title, "Review rolled back change");
  assert.equal(preview.parseError, "");
  assert.equal(preview.metadata?.find((item) => item.label === "IP")?.value, "203.0.113.10");
  assert.equal(preview.metadata?.find((item) => item.label === "Restored At")?.value, "2026-03-31T23:59:00Z");
  assert.match(preview.copyText ?? "", /ops@example.com/);
  assert.ok(preview.lines.some((line) => line.kind === "remove" && line.text.includes("8082")));
  assert.ok(preview.lines.some((line) => line.kind === "add" && line.text.includes("8081")));
});

test("buildProxyRulesAuditPreview surfaces invalid snapshot JSON", () => {
  const preview = buildProxyRulesAuditPreview({
    event: "proxy_rules_apply",
    before_raw: "{bad",
    after_raw: '{"upstreams":[{"name":"primary","url":"http://127.0.0.1:8081","weight":1,"enabled":true}]}',
  });

  assert.match(preview.parseError, /Current config JSON is invalid/);
  assert.equal(preview.lines.length, 0);
});

test("filterProxyRulesAuditEntries applies actor and action filters", () => {
  const entries = [
    { event: "proxy_rules_apply", actor: "alice@example.com", next_etag: "etag-1" },
    { event: "proxy_rules_rollback", actor: "ops@example.com", next_etag: "etag-2" },
    { event: "proxy_rules_apply", actor: "bob@example.com", next_etag: "etag-3" },
  ];

  assert.equal(filterProxyRulesAuditEntries(entries, "", "all").length, 3);
  assert.deepEqual(
    filterProxyRulesAuditEntries(entries, "ops", "rollback").map((entry) => entry.next_etag),
    ["etag-2"]
  );
  assert.deepEqual(
    filterProxyRulesAuditEntries(entries, "EXAMPLE.COM", "apply").map((entry) => entry.next_etag),
    ["etag-1", "etag-3"]
  );
});

test("serializeProxyRulesAuditEntries supports JSON and NDJSON export payloads", () => {
  const entries = [
    { event: "proxy_rules_apply", actor: "alice@example.com", next_etag: "etag-1" },
    { event: "proxy_rules_rollback", actor: "ops@example.com", next_etag: "etag-2" },
  ];

  const json = serializeProxyRulesAuditEntries(entries, "json");
  const ndjson = serializeProxyRulesAuditEntries(entries, "ndjson");

  assert.match(json, /\[\n/);
  assert.match(json, /"etag-1"/);
  assert.equal(ndjson.split("\n").length, 2);
  assert.match(ndjson, /"etag-2"/);
});

test("formatProxyRulesAuditSummary and metadata include rollback context", () => {
  const entry = {
    event: "proxy_rules_rollback",
    actor: "ops@example.com",
    ip: "203.0.113.10",
    ts: "2026-04-01T00:00:00Z",
    prev_etag: "etag-2",
    next_etag: "etag-1",
    restored_from: {
      etag: "etag-1",
      timestamp: "2026-03-31T23:59:00Z",
    },
  };

  assert.equal(
    formatProxyRulesAuditSummary(entry),
    "rollback | actor=ops@example.com | time=2026-04-01T00:00:00Z | etag=etag-2 -> etag-1 | ip=203.0.113.10 | restored_at=2026-03-31T23:59:00Z"
  );
  assert.deepEqual(
    buildProxyRulesAuditMetadata(entry).map((item) => item.label),
    ["Action", "Actor", "Time", "ETag", "IP", "Restored ETag", "Restored At"]
  );
});

test("runProxyRulesAuditReload limits limit-change reloads to audit only", async () => {
  const calls: string[] = [];

  await runProxyRulesAuditReload("limit_change", {
    loadConfig: async () => {
      calls.push("config");
    },
    loadAudit: async () => {
      calls.push("audit");
    },
  });

  assert.deepEqual(calls, ["audit"]);
});

test("runProxyRulesAuditReload loads config and audit for initial/manual refresh", async () => {
  const calls: string[] = [];

  await runProxyRulesAuditReload("initial", {
    loadConfig: async () => {
      calls.push("config");
    },
    loadAudit: async () => {
      calls.push("audit");
    },
  });
  await runProxyRulesAuditReload("manual", {
    loadConfig: async () => {
      calls.push("config");
    },
    loadAudit: async () => {
      calls.push("audit");
    },
  });

  assert.equal(calls.filter((call) => call === "config").length, 2);
  assert.equal(calls.filter((call) => call === "audit").length, 2);
});
