export type LogLine = {
  ts?: string;
  req_id?: string;
  rule_id?: string | number;
  status?: number;
  path?: string;
  event?: string;
  method?: string;
  country?: string;
  [k: string]: unknown;
};

export type RequestEventField = {
  label: string;
  value: string;
};

export type RequestEventRole = "enforced" | "observed" | "dry_run" | "informational";

export type PolicyFamily =
  | "country_block"
  | "ip_reputation"
  | "bot_defense"
  | "semantic"
  | "rate_limit"
  | "waf";

export type RequestDecision =
  | "blocked"
  | "rate_limited"
  | "challenged"
  | "allowed_with_findings"
  | "allowed";

export type RequestPrimaryReason = {
  event: string;
  policyFamily: PolicyFamily | null;
  role: RequestEventRole;
  enforced: boolean;
  status: number | null;
  ruleID: string;
  action: string;
};

export type ExplainedRequestEvent = {
  line: LogLine;
  role: RequestEventRole;
  policyFamily: PolicyFamily | null;
  isSecurity: boolean;
  isEnforcing: boolean;
  isDryRun: boolean;
};

export type RequestExplanation = {
  decision: RequestDecision;
  primaryReason: RequestPrimaryReason | null;
  primaryReasonText: string;
  httpStatus: number | null;
  httpStatusText: string;
  contributingPolicies: PolicyFamily[];
  dryRunPolicies: PolicyFamily[];
  rationale: string;
};

export type RequestDetailSummary = {
  reqID: string;
  orderedLines: LogLine[];
  orderedEvents: ExplainedRequestEvent[];
  eventTypes: string[];
  finalStatus: number | null;
  summaryText: string;
  explanation: RequestExplanation;
};

const DETAIL_KEYS: Array<[keyof LogLine | string, string]> = [
  ["status", "Status"],
  ["rule_id", "Rule ID"],
  ["policy_id", "Policy ID"],
  ["action", "Action"],
  ["mode", "Mode"],
  ["score", "Score"],
  ["base_score", "Base Score"],
  ["stateful_score", "Stateful Score"],
  ["provider_score", "Provider Score"],
  ["risk_score", "Risk Score"],
  ["semantic_score", "Semantic Score"],
  ["actor_key", "Actor Key"],
  ["path_class", "Path Class"],
  ["target_class", "Target Class"],
  ["surface_class", "Surface Class"],
  ["bot_risk_score", "Bot Risk Score"],
  ["signals", "Signals"],
  ["bot_signals", "Bot Signals"],
  ["flow_policy", "Flow Policy"],
  ["reason_list", "Reasons"],
  ["reasons", "Reasons"],
  ["score_breakdown", "Score Breakdown"],
  ["base_reason_list", "Base Reasons"],
  ["stateful_reason_list", "Stateful Reasons"],
  ["provider_reason_list", "Provider Reasons"],
  ["base_score_breakdown", "Base Score Breakdown"],
  ["stateful_score_breakdown", "Stateful Score Breakdown"],
  ["provider_score_breakdown", "Provider Score Breakdown"],
  ["provider_name", "Provider"],
  ["provider_attack_family", "Provider Attack Family"],
  ["provider_confidence", "Provider Confidence"],
  ["semantic_context", "Semantic Context"],
  ["semantic_fingerprints", "Semantic Fingerprints"],
  ["semantic_feature_buckets", "Semantic Buckets"],
  ["semantic_stateful_history", "Stateful History"],
  ["matched_variable", "Matched Variable"],
  ["matched_value", "Matched Value"],
  ["limit", "Limit"],
  ["base_limit", "Base Limit"],
  ["window_sec", "Window Sec"],
  ["key_by", "Key By"],
  ["adaptive", "Adaptive"],
  ["rl_key_hash", "Rate Key"],
  ["dry_run", "Dry Run"],
];

const POLICY_FAMILY_ORDER: PolicyFamily[] = [
  "country_block",
  "ip_reputation",
  "bot_defense",
  "semantic",
  "rate_limit",
  "waf",
];

export function formatPolicyFamilyLabel(policy: PolicyFamily): string {
  switch (policy) {
    case "country_block":
      return translateCurrent("country block");
    case "ip_reputation":
      return translateCurrent("ip reputation");
    case "bot_defense":
      return translateCurrent("bot defense");
    case "semantic":
      return translateCurrent("semantic");
    case "rate_limit":
      return translateCurrent("rate limit");
    case "waf":
      return translateCurrent("waf");
  }
}

export function formatRequestEventRoleLabel(role: RequestEventRole): string {
  switch (role) {
    case "dry_run":
      return translateCurrent("dry-run");
    case "informational":
      return translateCurrent("info");
    default:
      return role;
  }
}

export function filterLogLinesByReqID(lines: LogLine[], reqID: string): LogLine[] {
  const normalized = reqID.trim();
  if (!normalized) {
    return lines;
  }
  return lines.filter((line) => String(line.req_id ?? "").trim() === normalized);
}

export function sortLogLinesNewestFirst(lines: LogLine[]): LogLine[] {
  return lines
    .map((line, index) => ({ line, index, ts: parseTimestamp(line.ts) }))
    .sort((left, right) => {
      if (left.ts != null && right.ts != null && left.ts !== right.ts) {
        return right.ts - left.ts;
      }
      if (left.ts != null && right.ts == null) {
        return -1;
      }
      if (right.ts != null && left.ts == null) {
        return 1;
      }
      return right.index - left.index;
    })
    .map((entry) => entry.line);
}

export function summarizeRequestEvents(reqID: string, lines: LogLine[]): RequestDetailSummary {
  const normalizedReqID = reqID.trim();
  const orderedLines = sortRequestLines(lines);
  const orderedEvents = orderedLines.map((line) => annotateRequestEvent(line));
  const eventTypes = uniqueEventTypes(orderedLines);
  const explanation = buildRequestExplanation(orderedEvents);

  const summaryText = eventTypes.length
    ? translateCurrent("Request {reqID} - {count} events: {events}", {
        reqID: normalizedReqID,
        count: eventTypes.length,
        events: eventTypes.join(", "),
      })
    : translateCurrent("Request {reqID}", { reqID: normalizedReqID });

  return {
    reqID: normalizedReqID,
    orderedLines,
    orderedEvents,
    eventTypes,
    finalStatus: explanation.httpStatus,
    summaryText,
    explanation,
  };
}

export function extractRequestEventFields(line: LogLine): RequestEventField[] {
  const out: RequestEventField[] = [];
  for (const [key, label] of DETAIL_KEYS) {
    const value = line[key];
    if (value == null || value === "") {
      continue;
    }
    out.push({
      label: translateCurrent(label),
      value: formatDetailValue(value),
    });
  }
  return out;
}

function buildRequestExplanation(events: ExplainedRequestEvent[]): RequestExplanation {
  const latestEnforced = findLatestEvent(events, (event) => event.isSecurity && event.role === "enforced");
  const latestObserved = findLatestEvent(events, (event) => event.isSecurity && event.role === "observed");
  const latestDryRun = findLatestEvent(events, (event) => event.isSecurity && event.role === "dry_run");
  const primaryEvent = latestEnforced ?? latestObserved ?? latestDryRun;

  let decision: RequestDecision = "allowed";
  if (latestEnforced) {
    decision = decisionFromEvent(latestEnforced.line);
  } else if (latestObserved || latestDryRun) {
    decision = "allowed_with_findings";
  }

  const contributingPolicies = collectPolicyFamilies(events, (event) => event.isSecurity && event.role !== "informational");
  const dryRunPolicies = collectPolicyFamilies(events, (event) => event.role === "dry_run");
  const primaryReason = primaryEvent ? buildPrimaryReason(primaryEvent) : null;
  const httpStatus = latestEnforced ? numericStatus(latestEnforced.line.status) : null;

  return {
    decision,
    primaryReason,
    primaryReasonText: formatPrimaryReason(primaryReason),
    httpStatus,
    httpStatusText: httpStatus != null ? String(httpStatus) : translateCurrent("not enforced"),
    contributingPolicies,
    dryRunPolicies,
    rationale: buildRationale(decision, primaryReason, contributingPolicies, dryRunPolicies),
  };
}

function annotateRequestEvent(line: LogLine): ExplainedRequestEvent {
  const policyFamily = policyFamilyFromLine(line);
  const role = roleFromLine(line, policyFamily);
  return {
    line,
    role,
    policyFamily,
    isSecurity: policyFamily != null,
    isEnforcing: role === "enforced",
    isDryRun: role === "dry_run",
  };
}

function roleFromLine(line: LogLine, policyFamily: PolicyFamily | null): RequestEventRole {
  const event = eventName(line);
  switch (event) {
    case "proxy_route":
    case "waf_hit_allow":
      return "informational";
    case "bot_challenge_dry_run":
    case "bot_quarantine_dry_run":
      return "dry_run";
    case "semantic_anomaly": {
      const action = actionName(line);
      if (action === "block") {
        return "enforced";
      }
      if (action === "challenge") {
        return "enforced";
      }
      return "observed";
    }
    case "country_block":
    case "ip_reputation":
    case "bot_challenge":
    case "bot_quarantine":
    case "rate_limited":
    case "waf_block":
      return "enforced";
    default:
      return policyFamily ? "observed" : "informational";
  }
}

function policyFamilyFromLine(line: LogLine): PolicyFamily | null {
  switch (eventName(line)) {
    case "country_block":
      return "country_block";
    case "ip_reputation":
      return "ip_reputation";
    case "bot_challenge":
    case "bot_quarantine":
    case "bot_challenge_dry_run":
    case "bot_quarantine_dry_run":
      return "bot_defense";
    case "semantic_anomaly":
      return "semantic";
    case "rate_limited":
      return "rate_limit";
    case "waf_block":
      return "waf";
    default:
      return null;
  }
}

function decisionFromEvent(line: LogLine): RequestDecision {
  const event = eventName(line);
  if (event === "rate_limited") {
    return "rate_limited";
  }
  if (event === "bot_challenge") {
    return "challenged";
  }
  if (event === "semantic_anomaly" && actionName(line) === "challenge") {
    return "challenged";
  }
  return "blocked";
}

function buildPrimaryReason(event: ExplainedRequestEvent): RequestPrimaryReason {
  return {
    event: eventName(event.line),
    policyFamily: event.policyFamily,
    role: event.role,
    enforced: event.role === "enforced",
    status: numericStatus(event.line.status),
    ruleID: stringifyValue(event.line.rule_id),
    action: actionName(event.line),
  };
}

function collectPolicyFamilies(
  events: ExplainedRequestEvent[],
  predicate: (event: ExplainedRequestEvent) => boolean
): PolicyFamily[] {
  const seen = new Set<PolicyFamily>();
  for (const event of events) {
    if (!predicate(event) || !event.policyFamily) {
      continue;
    }
    seen.add(event.policyFamily);
  }
  return POLICY_FAMILY_ORDER.filter((family) => seen.has(family));
}

function findLatestEvent(
  events: ExplainedRequestEvent[],
  predicate: (event: ExplainedRequestEvent) => boolean
): ExplainedRequestEvent | null {
  for (let i = events.length - 1; i >= 0; i -= 1) {
    if (predicate(events[i])) {
      return events[i];
    }
  }
  return null;
}

function formatPrimaryReason(reason: RequestPrimaryReason | null): string {
  if (!reason) {
    return translateCurrent("none");
  }
  const label = reason.policyFamily ? formatPolicyFamilyLabel(reason.policyFamily) : reason.event;
  switch (reason.role) {
    case "dry_run":
      return translateCurrent("{label} (dry-run, non-enforcing)", { label });
    case "observed":
      return translateCurrent("{label} (observed only)", { label });
    default:
      return label;
  }
}

function buildRationale(
  decision: RequestDecision,
  primaryReason: RequestPrimaryReason | null,
  contributingPolicies: PolicyFamily[],
  dryRunPolicies: PolicyFamily[]
): string {
  const contributorLabels = contributingPolicies.map(policyFamilyLabel);
  const primaryPolicyLabel = primaryReason && primaryReason.policyFamily
    ? policyFamilyLabel(primaryReason.policyFamily)
    : "";
  const nonPrimaryLabels = primaryPolicyLabel
    ? contributorLabels.filter((label) => label !== primaryPolicyLabel)
    : contributorLabels;

  switch (decision) {
    case "blocked":
      if (primaryReason?.event === "waf_block" && primaryReason.ruleID) {
        return translateCurrent("Blocked by waf_block (rule {ruleID})", {
          ruleID: primaryReason.ruleID,
        });
      }
      if (primaryReason?.event) {
        return translateCurrent("Blocked by {event}", { event: primaryReason.event });
      }
      return translateCurrent("Blocked by security policy");
    case "rate_limited":
      if (nonPrimaryLabels.length > 0) {
        return translateCurrent("Rate limited after {labels} findings", {
          labels: joinLabels(nonPrimaryLabels),
        });
      }
      return translateCurrent("Rate limited by rate_limit");
    case "challenged":
      if (primaryReason?.event) {
        return translateCurrent("Challenged by {event}", { event: primaryReason.event });
      }
      return translateCurrent("Challenge required by security policy");
    case "allowed_with_findings":
      if (dryRunPolicies.length > 0 && contributorLabels.length === dryRunPolicies.length) {
        return translateCurrent("Allowed, but {labels} dry-run findings fired", {
          labels: joinLabels(dryRunPolicies.map(policyFamilyLabel)),
        });
      }
      if (contributorLabels.length > 0) {
        return translateCurrent("Allowed, but {labels} signals fired", {
          labels: joinLabels(contributorLabels),
        });
      }
      return translateCurrent("Allowed, but security findings were observed");
    case "allowed":
    default:
      if (dryRunPolicies.length > 0) {
        return translateCurrent("Allowed, but {labels} dry-run findings fired", {
          labels: joinLabels(dryRunPolicies.map(policyFamilyLabel)),
        });
      }
      return translateCurrent("Allowed with no security findings");
  }
}

function sortRequestLines(lines: LogLine[]): LogLine[] {
  return lines
    .map((line, index) => ({ line, index, ts: parseTimestamp(line.ts) }))
    .sort((left, right) => {
      if (left.ts != null && right.ts != null && left.ts !== right.ts) {
        return left.ts - right.ts;
      }
      if (left.ts != null) {
        return -1;
      }
      if (right.ts != null) {
        return 1;
      }
      return left.index - right.index;
    })
    .map((entry) => entry.line);
}

function parseTimestamp(raw: unknown): number | null {
  if (typeof raw !== "string" || !raw.trim()) {
    return null;
  }
  const value = Date.parse(raw);
  return Number.isNaN(value) ? null : value;
}

function uniqueEventTypes(lines: LogLine[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of lines) {
    const event = eventName(line);
    if (!event || seen.has(event)) {
      continue;
    }
    seen.add(event);
    out.push(event);
  }
  return out;
}

function eventName(line: LogLine): string {
  return stringifyValue(line.event);
}

function actionName(line: LogLine): string {
  return stringifyValue(line.action);
}

function stringifyValue(raw: unknown): string {
  return String(raw ?? "").trim();
}

function numericStatus(raw: unknown): number | null {
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return raw;
  }
  if (typeof raw === "string" && raw.trim()) {
    const value = Number(raw);
    return Number.isFinite(value) ? value : null;
  }
  return null;
}

function policyFamilyLabel(family: PolicyFamily): string {
  return formatPolicyFamilyLabel(family);
}

function joinLabels(labels: string[]): string {
  if (labels.length <= 1) {
    return labels[0] || "";
  }
  if (labels.length === 2) {
    return translateCurrent("{left} and {right}", { left: labels[0], right: labels[1] });
  }
  return translateCurrent("{items}, and {last}", {
    items: labels.slice(0, -1).join(", "),
    last: labels[labels.length - 1],
  });
}

function formatDetailValue(value: unknown): string {
  if (Array.isArray(value) || (typeof value === "object" && value !== null)) {
    return JSON.stringify(value);
  }
  return String(value);
}
import { translateCurrent } from "./i18n.js";
