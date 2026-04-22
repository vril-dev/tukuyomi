import assert from "node:assert/strict";
import test from "node:test";
import {
  buildFPTunerAuditDetails,
  formatFPTunerAuditAction,
  formatFPTunerAuditStatus,
  formatFPTunerProposalSummary,
} from "./fPTunerAudit.js";

test("formatFPTunerAuditAction and status map representative events", () => {
  assert.equal(formatFPTunerAuditAction("fp_tuner_propose"), "propose");
  assert.equal(formatFPTunerAuditAction("fp_tuner_apply_success"), "apply");
  assert.equal(formatFPTunerAuditStatus("fp_tuner_propose"), "proposed");
  assert.equal(formatFPTunerAuditStatus("fp_tuner_apply_simulate"), "simulated");
  assert.equal(formatFPTunerAuditStatus("fp_tuner_apply_error"), "error");
});

test("formatFPTunerProposalSummary compacts proposal metadata", () => {
  assert.equal(
    formatFPTunerProposalSummary({
      proposal_id: "fp-2026-001",
      proposal_hash: "abcdef1234567890",
    }),
    "fp-2026-001 (abcdef12)"
  );
  assert.equal(formatFPTunerProposalSummary({ proposal_hash: "1234567890" }), "12345678");
  assert.equal(formatFPTunerProposalSummary({}), "-");
});

test("buildFPTunerAuditDetails returns representative detail fields", () => {
  const details = buildFPTunerAuditDetails({
    ts: "2026-04-01T00:00:00Z",
    event: "fp_tuner_apply_denied",
    actor: "alice@example.com",
    ip: "203.0.113.10",
    proposal_id: "fp-2026-001",
    proposal_hash: "abcdef1234567890",
    target_path: "rules/tukuyomi.conf",
    simulate: false,
    approval_required: true,
    approval_error: "approval token expired",
  });

  assert.deepEqual(details.slice(0, 5), [
    { label: "Time", value: "2026-04-01T00:00:00Z" },
    { label: "Event", value: "fp_tuner_apply_denied" },
    { label: "Actor", value: "alice@example.com" },
    { label: "IP", value: "203.0.113.10" },
    { label: "Target Path", value: "rules/tukuyomi.conf" },
  ]);
  assert.ok(details.some((detail) => detail.label === "Proposal" && detail.value === "fp-2026-001 (abcdef12)"));
  assert.ok(details.some((detail) => detail.label === "Approval Error" && detail.value === "approval token expired"));
});
