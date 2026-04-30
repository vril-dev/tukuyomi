import { buildDiffLines, normalizeJSONForDiff, type DiffLine } from "./jsonDiff.js";
import { formatRevisionTransition, shortRevision } from "./revision.js";

export type ProxyRulesAuditRestoredFrom = {
  etag?: string;
  timestamp?: string;
};

export type ProxyRulesAuditEntry = {
  ts?: string;
  service?: string;
  event?: string;
  actor?: string;
  ip?: string;
  prev_etag?: string;
  next_etag?: string;
  before_raw?: string;
  after_raw?: string;
  restored_from?: ProxyRulesAuditRestoredFrom;
};

export type ProxyRulesDiffPreview = {
  mode: "save" | "rollback" | "audit";
  title: string;
  description: string;
  note?: string;
  parseError: string;
  lines: DiffLine[];
  applyLabel?: string;
  metadata?: Array<{ label: string; value: string }>;
  copyText?: string;
};

export type ProxyRulesAuditActionFilter = "all" | "apply" | "rollback";
export type ProxyRulesAuditReloadReason = "initial" | "manual" | "limit_change";

export function formatProxyRulesAuditAction(event: string | undefined): string {
  switch (String(event ?? "").trim()) {
    case "proxy_rules_rollback":
      return "rollback";
    case "proxy_rules_apply":
    default:
      return "apply";
  }
}

export function formatProxyRulesAuditTransition(entry: ProxyRulesAuditEntry): string {
  const prev = String(entry.prev_etag ?? "").trim() || "-";
  const next = String(entry.next_etag ?? "").trim() || "-";
  return formatRevisionTransition(prev, next);
}

export function filterProxyRulesAuditEntries(
  entries: ProxyRulesAuditEntry[],
  actorFilter: string,
  actionFilter: ProxyRulesAuditActionFilter
): ProxyRulesAuditEntry[] {
  const actorNeedle = actorFilter.trim().toLowerCase();
  return entries.filter((entry) => {
    const action = formatProxyRulesAuditAction(entry.event);
    if (actionFilter !== "all" && action !== actionFilter) {
      return false;
    }
    if (!actorNeedle) {
      return true;
    }
    const actor = String(entry.actor ?? "").toLowerCase();
    return actor.includes(actorNeedle);
  });
}

export function serializeProxyRulesAuditEntries(entries: ProxyRulesAuditEntry[], format: "json" | "ndjson" = "json"): string {
  if (format === "ndjson") {
    return entries.map((entry) => JSON.stringify(entry)).join("\n");
  }
  return `${JSON.stringify(entries, null, 2)}\n`;
}

export function formatProxyRulesAuditSummary(entry: ProxyRulesAuditEntry): string {
  const parts = [
    formatProxyRulesAuditAction(entry.event),
    `actor=${String(entry.actor ?? "").trim() || "unknown"}`,
    `time=${String(entry.ts ?? "").trim() || "-"}`,
    `revision=${formatProxyRulesAuditTransition(entry)}`,
  ];
  const ip = String(entry.ip ?? "").trim();
  if (ip) {
    parts.push(`ip=${ip}`);
  }
  const restoredAt = String(entry.restored_from?.timestamp ?? "").trim();
  if (restoredAt) {
    parts.push(`restored_at=${restoredAt}`);
  }
  return parts.join(" | ");
}

export function buildProxyRulesAuditMetadata(entry: ProxyRulesAuditEntry): Array<{ label: string; value: string }> {
  const metadata = [
    { label: "Action", value: formatProxyRulesAuditAction(entry.event) },
    { label: "Actor", value: String(entry.actor ?? "").trim() || "unknown" },
    { label: "Time", value: String(entry.ts ?? "").trim() || "-" },
    { label: "R", value: formatProxyRulesAuditTransition(entry) },
  ];
  const ip = String(entry.ip ?? "").trim();
  if (ip) {
    metadata.push({ label: "IP", value: ip });
  }
  const restoredETag = String(entry.restored_from?.etag ?? "").trim();
  if (restoredETag) {
    metadata.push({ label: "Restored R", value: shortRevision(restoredETag) });
  }
  const restoredAt = String(entry.restored_from?.timestamp ?? "").trim();
  if (restoredAt) {
    metadata.push({ label: "Restored At", value: restoredAt });
  }
  return metadata;
}

export async function runProxyRulesAuditReload(
  reason: ProxyRulesAuditReloadReason,
  actions: {
    loadConfig: () => Promise<void>;
    loadAudit: () => Promise<void>;
  }
): Promise<void> {
  if (reason === "limit_change") {
    await actions.loadAudit();
    return;
  }
  await Promise.all([actions.loadConfig(), actions.loadAudit()]);
}

export function buildProxyRulesDiffPreview({
  mode,
  title,
  description,
  note,
  currentRaw,
  nextRaw,
  applyLabel,
}: {
  mode: "save" | "rollback" | "audit";
  title: string;
  description: string;
  note?: string;
  currentRaw: string;
  nextRaw: string;
  applyLabel?: string;
}): ProxyRulesDiffPreview {
  const current = normalizeJSONForDiff(currentRaw);
  if (current.error) {
    return {
      mode,
      title,
      description,
      note,
      parseError: `Current config JSON is invalid: ${current.error}`,
      lines: [],
      applyLabel,
    };
  }
  const next = normalizeJSONForDiff(nextRaw);
  if (next.error) {
    return {
      mode,
      title,
      description,
      note,
      parseError: `Target config JSON is invalid: ${next.error}`,
      lines: [],
      applyLabel,
    };
  }
  return {
    mode,
    title,
    description,
    note,
    parseError: "",
    lines: buildDiffLines(current.formatted, next.formatted),
    applyLabel,
    metadata: [],
  };
}

export function buildProxyRulesAuditPreview(entry: ProxyRulesAuditEntry): ProxyRulesDiffPreview {
  const action = formatProxyRulesAuditAction(entry.event);
  const preview = buildProxyRulesDiffPreview({
    mode: "audit",
    title: action === "rollback" ? "Review rolled back change" : "Review applied change",
    description:
      action === "rollback"
        ? "Compare the config that was active before rollback with the snapshot that was restored."
        : "Compare the config before and after this applied proxy-rules change.",
    currentRaw: String(entry.before_raw ?? ""),
    nextRaw: String(entry.after_raw ?? ""),
  });
  preview.metadata = buildProxyRulesAuditMetadata(entry);
  preview.copyText = formatProxyRulesAuditSummary(entry);
  return preview;
}
