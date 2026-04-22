import assert from "node:assert/strict";
import test from "node:test";

import {
  formatSecurityAuditAction,
  formatSecurityAuditVerify,
  summarizeSecurityAuditNode,
} from "./securityAudit.js";

test("formatSecurityAuditAction renders friendly labels", () => {
  assert.equal(formatSecurityAuditAction("blocked"), "blocked");
  assert.equal(formatSecurityAuditAction("challenge"), "challenged");
  assert.equal(formatSecurityAuditAction("rate_limited"), "rate limited");
  assert.equal(formatSecurityAuditAction("allow_with_findings"), "allowed with findings");
});

test("formatSecurityAuditVerify distinguishes anchored and retained segments", () => {
  assert.equal(
    formatSecurityAuditVerify({
      ok: true,
      anchored: true,
      entries: 4,
      files: 1,
      checked_at: "2026-04-02T00:00:00Z",
    }),
    "valid and anchored"
  );
  assert.equal(
    formatSecurityAuditVerify({
      ok: true,
      anchored: false,
      entries: 4,
      files: 2,
      checked_at: "2026-04-02T00:00:00Z",
    }),
    "valid (retained segment)"
  );
  assert.equal(
    formatSecurityAuditVerify({
      ok: false,
      anchored: false,
      entries: 3,
      files: 1,
      checked_at: "2026-04-02T00:00:00Z",
      error: "signature mismatch",
    }),
    "invalid: signature mismatch"
  );
});

test("summarizeSecurityAuditNode prefers signal and action context", () => {
  assert.equal(
    summarizeSecurityAuditNode({
      step: 3,
      policy_family: "semantic",
      signal_id: "query:union_select",
      score_delta: 4,
      action_effective: "observe",
    }),
    "semantic / query:union_select / +4 / => observe"
  );
});
