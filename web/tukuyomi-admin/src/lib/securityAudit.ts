export type SecurityAuditDecisionNode = {
  step: number;
  phase?: string;
  policy_family?: string;
  matched?: boolean;
  source_event?: string;
  rule_id?: string;
  signal_id?: string;
  score_before?: number;
  score_delta?: number;
  score_after?: number;
  threshold?: number;
  action_candidate?: string;
  action_effective?: string;
  status?: number;
  dry_run?: boolean;
  depends_on?: number[];
  metadata?: Record<string, unknown>;
};

export type SecurityAuditEvidenceMetadata = {
  capture_id: string;
  storage_ref?: string;
  cipher: string;
  key_id: string;
  sha256: string;
  size: number;
  headers_captured: boolean;
  body_captured: boolean;
  body_truncated?: boolean;
  body_redacted?: boolean;
  body_content_type?: string;
};

export type SecurityAuditIntegrity = {
  version: number;
  key_id: string;
  prev_hash?: string;
  entry_hash: string;
  signature: string;
  sequence: number;
};

export type SecurityAuditRecord = {
  version: number;
  ts: string;
  service: string;
  event: string;
  decision_id: string;
  req_id: string;
  trace_id?: string;
  ip?: string;
  country?: string;
  method?: string;
  host?: string;
  path?: string;
  query?: string;
  final_action: string;
  final_status?: number;
  terminal_policy?: string;
  terminal_event?: string;
  decision_chain?: SecurityAuditDecisionNode[];
  evidence?: SecurityAuditEvidenceMetadata;
  warnings?: string[];
  integrity: SecurityAuditIntegrity;
};

export type SecurityAuditResponse = {
  items: SecurityAuditRecord[];
  count: number;
};

export type SecurityAuditVerifyResponse = {
  ok: boolean;
  anchored: boolean;
  entries: number;
  files: number;
  last_hash?: string;
  last_sequence?: number;
  checked_at: string;
  error?: string;
};

export function formatSecurityAuditAction(action: string | undefined): string {
  switch ((action || "").trim()) {
    case "blocked":
      return translateCurrent("blocked");
    case "challenge":
      return translateCurrent("challenged");
    case "rate_limited":
      return translateCurrent("rate limited");
    case "allow_with_findings":
      return translateCurrent("allowed with findings");
    case "allow":
      return translateCurrent("allowed");
    default:
      return action?.trim() || translateCurrent("unknown");
  }
}

export function formatSecurityAuditVerify(result: SecurityAuditVerifyResponse | null): string {
  if (!result) {
    return translateCurrent("not verified");
  }
  if (!result.ok) {
    return result.error ? translateCurrent("invalid: {error}", { error: result.error }) : translateCurrent("invalid");
  }
  return result.anchored ? translateCurrent("valid and anchored") : translateCurrent("valid (retained segment)");
}

export function summarizeSecurityAuditNode(node: SecurityAuditDecisionNode): string {
  const parts: string[] = [];
  const family = (node.policy_family || "").trim();
  if (family) {
    parts.push(family);
  }
  if (node.signal_id) {
    parts.push(node.signal_id);
  } else if (node.rule_id) {
    parts.push(translateCurrent("rule {ruleID}", { ruleID: node.rule_id }));
  } else if (node.source_event) {
    parts.push(node.source_event);
  }
  if (typeof node.score_delta === "number") {
    parts.push(`+${node.score_delta}`);
  }
  if (node.action_effective) {
    parts.push(translateCurrent("=> {action}", { action: node.action_effective }));
  }
  return parts.join(" / ") || translateCurrent("step {step}", { step: node.step });
}
import { translateCurrent } from "./i18n.js";
