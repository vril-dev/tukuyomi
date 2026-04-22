export type FPTunerAuditEntry = {
  ts?: string;
  service?: string;
  event?: string;
  actor?: string;
  ip?: string;
  proposal_id?: string;
  proposal_hash?: string;
  target_path?: string;
  mode?: string;
  source?: string;
  count?: number;
  simulate?: boolean;
  approval_required?: boolean;
  approval_token?: unknown;
  approval_error?: string;
  hot_reloaded?: boolean;
  error?: string;
};

export type FPTunerAuditDetail = {
  label: string;
  value: string;
};

export function formatFPTunerAuditAction(event: string | undefined): string {
  switch (String(event ?? "").trim()) {
    case "fp_tuner_propose":
      return translateCurrent("propose");
    case "fp_tuner_apply_simulate":
    case "fp_tuner_apply_success":
    case "fp_tuner_apply_duplicate":
    case "fp_tuner_apply_denied":
    case "fp_tuner_apply_error":
      return translateCurrent("apply");
    default:
      return translateCurrent("action");
  }
}

export function formatFPTunerAuditStatus(event: string | undefined): string {
  switch (String(event ?? "").trim()) {
    case "fp_tuner_propose":
      return translateCurrent("proposed");
    case "fp_tuner_apply_simulate":
      return translateCurrent("simulated");
    case "fp_tuner_apply_success":
      return translateCurrent("applied");
    case "fp_tuner_apply_duplicate":
      return translateCurrent("duplicate");
    case "fp_tuner_apply_denied":
      return translateCurrent("denied");
    case "fp_tuner_apply_error":
      return translateCurrent("error");
    default:
      return translateCurrent("unknown");
  }
}

export function formatFPTunerProposalSummary(entry: FPTunerAuditEntry): string {
  const proposalID = String(entry.proposal_id ?? "").trim();
  const proposalHash = String(entry.proposal_hash ?? "").trim();
  if (proposalID && proposalHash) {
    return `${proposalID} (${proposalHash.slice(0, 8)})`;
  }
  if (proposalID) {
    return proposalID;
  }
  if (proposalHash) {
    return proposalHash.slice(0, 8);
  }
  return "-";
}

export function buildFPTunerAuditDetails(entry: FPTunerAuditEntry): FPTunerAuditDetail[] {
  const details: FPTunerAuditDetail[] = [];
  pushDetail(details, translateCurrent("Time"), entry.ts);
  pushDetail(details, translateCurrent("Event"), entry.event);
  pushDetail(details, translateCurrent("Actor"), entry.actor);
  pushDetail(details, translateCurrent("IP"), entry.ip);
  pushDetail(details, translateCurrent("Target Path"), entry.target_path);
  pushDetail(details, translateCurrent("Proposal"), formatFPTunerProposalSummary(entry), formatFPTunerProposalSummary(entry) !== "-");
  pushDetail(details, translateCurrent("Mode"), entry.mode);
  pushDetail(details, translateCurrent("Source"), entry.source);
  pushDetail(details, translateCurrent("Count"), typeof entry.count === "number" ? String(entry.count) : "");
  pushDetail(details, translateCurrent("Simulate"), typeof entry.simulate === "boolean" ? String(entry.simulate) : "");
  pushDetail(details, translateCurrent("Approval Required"), typeof entry.approval_required === "boolean" ? String(entry.approval_required) : "");
  pushDetail(details, translateCurrent("Approval Token"), stringifyUnknown(entry.approval_token));
  pushDetail(details, translateCurrent("Approval Error"), entry.approval_error);
  pushDetail(details, translateCurrent("Hot Reloaded"), typeof entry.hot_reloaded === "boolean" ? String(entry.hot_reloaded) : "");
  pushDetail(details, translateCurrent("Error"), entry.error);
  return details;
}

function pushDetail(details: FPTunerAuditDetail[], label: string, value: string | undefined, include = true) {
  const normalized = String(value ?? "").trim();
  if (!include || normalized === "") {
    return;
  }
  details.push({ label, value: normalized });
}

function stringifyUnknown(value: unknown): string {
  if (value == null) {
    return "";
  }
  if (typeof value === "string") {
    return value.trim();
  }
  return JSON.stringify(value);
}
import { translateCurrent } from "./i18n.js";
