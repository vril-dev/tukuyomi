import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { apiGetJson, apiPostJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";
import { runFPTunerApply } from "@/lib/fPTunerApply";
import {
  buildFPTunerAuditDetails,
  formatFPTunerAuditAction,
  formatFPTunerAuditStatus,
  formatFPTunerProposalSummary,
  type FPTunerAuditEntry,
} from "@/lib/fPTunerAudit";

type FPTunerProposal = {
  id: string;
  title?: string;
  summary?: string;
  reason?: string;
  confidence?: number;
  target_path: string;
  rule_line: string;
};

type ProposeResponse = {
  ok?: boolean;
  contract_version?: string;
  mode?: string;
  source?: string;
  input?: Record<string, unknown>;
  approval?: {
    required?: boolean;
    token?: string;
  };
  proposal?: FPTunerProposal | null;
  no_proposal?: {
    decision?: string;
    reason?: string;
    confidence?: number;
  };
};

type ApplyResponse = {
  ok?: boolean;
  contract_version?: string;
  simulated?: boolean;
  duplicate?: boolean;
  hot_reloaded?: boolean;
  reloaded_file?: string;
  etag?: string;
  preview_etag?: string;
};

type EventInput = {
  event_id: string;
  method: string;
  scheme: string;
  host: string;
  path: string;
  query: string;
  rule_id: string;
  status: string;
  matched_variable: string;
  matched_value: string;
};

type WAFLogLine = {
  ts?: string;
  req_id?: string;
  method?: string;
  original_scheme?: string;
  original_host?: string;
  rewritten_host?: string;
  path?: string;
  original_query?: string;
  rewritten_query?: string;
  rule_id?: string | number;
  status?: string | number;
  matched_variable?: string;
  matched_value?: string;
  event?: string;
};

type WAFReadResponse = {
  lines?: WAFLogLine[];
};

type FPTunerAuditResponse = {
  entries?: FPTunerAuditEntry[];
};

const defaultEvent: EventInput = {
  event_id: "",
  method: "GET",
  scheme: "http",
  host: "",
  path: "",
  query: "",
  rule_id: "",
  status: "403",
  matched_variable: "",
  matched_value: "",
};

const defaultTargetPath = "tukuyomi.conf";

export default function FPTunerPanel() {
  const { locale, tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [targetPath, setTargetPath] = useState(defaultTargetPath);
  const [useLatestEvent, setUseLatestEvent] = useState(false);
  const [eventInput, setEventInput] = useState<EventInput>(defaultEvent);
  const [selectedEventID, setSelectedEventID] = useState("");
  const [manualEntryEnabled, setManualEntryEnabled] = useState(false);
  const [logTail, setLogTail] = useState(30);
  const [wafBlockLines, setWafBlockLines] = useState<WAFLogLine[]>([]);
  const [logLoading, setLogLoading] = useState(false);
  const [logError, setLogError] = useState<string | null>(null);
  const [auditEntries, setAuditEntries] = useState<FPTunerAuditEntry[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [selectedAudit, setSelectedAudit] = useState<FPTunerAuditEntry | null>(null);

  const [proposal, setProposal] = useState<FPTunerProposal | null>(null);
  const [approvalRequired, setApprovalRequired] = useState(false);
  const [approvalToken, setApprovalToken] = useState("");
  const [simulate, setSimulate] = useState(true);

  const [mode, setMode] = useState<string>("-");
  const [source, setSource] = useState<string>("-");
  const [contractVersion, setContractVersion] = useState<string>("-");

  const [proposeResult, setProposeResult] = useState<ProposeResponse | null>(null);
  const [applyResult, setApplyResult] = useState<ApplyResponse | null>(null);

  const [proposing, setProposing] = useState(false);
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canApply = useMemo(() => proposal && proposal.rule_line.trim() !== "", [proposal]);
  const showManualEventForm = !useLatestEvent && (manualEntryEnabled || selectedEventID !== "");
  const canPropose = useLatestEvent || showManualEventForm;

  function updateEvent<K extends keyof EventInput>(key: K, value: EventInput[K]) {
    setEventInput((prev) => ({ ...prev, [key]: value }));
  }

  function updateProposal<K extends keyof FPTunerProposal>(key: K, value: FPTunerProposal[K]) {
    setProposal((prev) => {
      if (!prev) return prev;
      return { ...prev, [key]: value };
    });
  }

  const loadWAFBlockLines = useCallback(async () => {
    setLogError(null);
    setLogLoading(true);
    try {
      const q = new URLSearchParams();
      q.set("limit", String(logTail));
      const res = await apiGetJson<WAFReadResponse>(`/fp-tuner/recent-waf-blocks?${q.toString()}`);
      setWafBlockLines(Array.isArray(res.lines) ? res.lines : []);
    } catch (error: unknown) {
      setLogError(getErrorMessage(error, tx("Failed to load waf logs")));
    } finally {
      setLogLoading(false);
    }
  }, [logTail, tx]);

  const loadAudit = useCallback(async () => {
    setAuditLoading(true);
    setAuditError(null);
    try {
      const res = await apiGetJson<FPTunerAuditResponse>("/fp-tuner:audit?limit=20");
      setAuditEntries(Array.isArray(res.entries) ? res.entries : []);
    } catch (error: unknown) {
      setAuditEntries([]);
      setAuditError(getErrorMessage(error, tx("Failed to load fp tuner audit")));
    } finally {
      setAuditLoading(false);
    }
  }, [tx]);

  useEffect(() => {
    void loadWAFBlockLines();
  }, [loadWAFBlockLines]);

  useEffect(() => {
    void loadAudit();
  }, [loadAudit]);

  function toStringField(v: unknown, fallback: string) {
    if (v == null) return fallback;
    const s = String(v).trim();
    return s === "" ? fallback : s;
  }

  function toIntString(v: unknown, fallback: number) {
    const n = Number(v);
    if (!Number.isFinite(n) || n <= 0) {
      return String(fallback);
    }
    return String(Math.trunc(n));
  }

  function toOptionalIntString(v: unknown) {
    const n = Number(v);
    if (!Number.isFinite(n) || n <= 0) {
      return "";
    }
    return String(Math.trunc(n));
  }

  function shorten(v: unknown, max = 84) {
    const s = String(v ?? "");
    if (s.length <= max) return s;
    return `${s.slice(0, max)}...`;
  }

  function onSelectWAFBlockLine(line: WAFLogLine) {
    const pickedEventID = toStringField(line.req_id, toStringField(line.ts, "manual-ui-log"));
    setSelectedEventID(pickedEventID);
    setManualEntryEnabled(true);
    setUseLatestEvent(false);
    setEventInput({
      event_id: pickedEventID,
      method: toStringField(line.method, "GET").toUpperCase(),
      scheme: toStringField(line.original_scheme, "http"),
      host: toStringField(line.original_host, toStringField(line.rewritten_host, "")),
      path: toStringField(line.path, ""),
      query: toStringField(line.original_query, toStringField(line.rewritten_query, "")),
      rule_id: toOptionalIntString(line.rule_id),
      status: toIntString(line.status, 403),
      matched_variable: toStringField(line.matched_variable, ""),
      matched_value: toStringField(line.matched_value, ""),
    });
  }

  async function onPropose() {
    setError(null);
    setApplyResult(null);
    setProposing(true);
    try {
      const payload: Record<string, unknown> = {
        target_path: targetPath.trim(),
      };

      if (!useLatestEvent) {
        payload.event = {
          event_id: eventInput.event_id.trim(),
          method: eventInput.method.trim() || "GET",
          scheme: eventInput.scheme.trim() || "http",
          host: eventInput.host.trim(),
          path: eventInput.path.trim(),
          query: eventInput.query.trim(),
          rule_id: parseInt(eventInput.rule_id, 10) || 0,
          status: parseInt(eventInput.status, 10) || 403,
          matched_variable: eventInput.matched_variable.trim(),
          matched_value: eventInput.matched_value,
        };
      }

      const res = await apiPostJson<ProposeResponse>("/fp-tuner/propose", payload);
      setProposeResult(res);
      setProposal(res.proposal ?? null);
      setApprovalRequired(!!res.proposal && !!res.approval?.required);
      setApprovalToken(res.proposal ? (res.approval?.token ?? "") : "");
      setMode(res.mode || "-");
      setSource(res.source || "-");
      setContractVersion(res.contract_version || "-");
      await loadAudit();
    } catch (error: unknown) {
      setError(getErrorMessage(error, tx("Propose failed")));
    } finally {
      setProposing(false);
    }
  }

  async function onApply() {
    if (!proposal) return;
    setError(null);
    setApplying(true);
    try {
      const payload = {
        proposal,
        simulate,
        approval_token: approvalToken,
      };
      await runFPTunerApply({
        applyRequest: () => apiPostJson<ApplyResponse>("/fp-tuner/apply", payload),
        onSuccess: async (res) => {
          setApplyResult(res);
        },
        onError: async (message) => {
          setError(message);
        },
        refreshAudit: loadAudit,
      });
    } finally {
      setApplying(false);
    }
  }

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">{tx("FP Tuner")}</h1>
        <div className="flex items-center gap-2 text-xs">
          <Badge color="gray">{tx("mode")}: {mode}</Badge>
          <Badge color="gray">{tx("source")}: {source}</Badge>
          <Badge color="gray">{tx("contract")}: {contractVersion}</Badge>
          {approvalRequired ? <Badge color="amber">{tx("approval required")}</Badge> : <Badge color="green">{tx("approval optional")}</Badge>}
          <button className="border rounded px-2 py-0.5 bg-white text-xs" onClick={() => { void Promise.all([loadWAFBlockLines(), loadAudit()]); }}>
            {tx("Refresh")}
          </button>
        </div>
      </header>

      {error && (
        <div className="border border-red-300 bg-red-50 rounded-xl p-3 text-xs">
          {tx("Error")}: {error}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-xl border bg-white p-3 space-y-3">
          <h2 className="text-xs font-semibold">{tx("Propose Input")}</h2>

          <label className="text-xs text-neutral-600 block">
            {tx("Target Path")}
            <input
              className="mt-1 w-full border rounded px-2 py-1"
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              placeholder="tukuyomi.conf"
            />
          </label>

          <div className="flex flex-wrap items-center gap-3">
            <label className="inline-flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={useLatestEvent}
                onChange={(e) => setUseLatestEvent(e.target.checked)}
              />
              {tx("Use latest `waf_block` log event")}
            </label>
            {!useLatestEvent && (
              <button
                className="text-xs border rounded px-2 py-0.5 bg-white"
                onClick={() => {
                  setManualEntryEnabled(true);
                  setSelectedEventID("");
                  setEventInput(defaultEvent);
                }}
              >
                {tx("Manual entry")}
              </button>
            )}
          </div>

          <div className="rounded border bg-neutral-50 p-2 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-semibold text-neutral-700">{tx("Pick From Recent `waf_block` Logs")}</h3>
              <div className="flex items-center gap-2">
                <label className="text-xs text-neutral-600">
                  {tx("Rows")}
                  <select
                    className="ml-1 border rounded px-1 py-0.5 bg-white"
                    value={logTail}
                    onChange={(e) => setLogTail(Number(e.target.value))}
                  >
                    {[20, 30, 50, 100].map((n) => (
                      <option key={n} value={n}>
                        {n}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  className="text-xs border rounded px-2 py-0.5 bg-white"
                  onClick={() => void loadWAFBlockLines()}
                  disabled={logLoading}
                >
                  {logLoading ? tx("Loading...") : tx("Reload")}
                </button>
              </div>
            </div>

            {logError && <p className="text-xs text-red-700">{tx("Log error")}: {logError}</p>}

            {!logError && wafBlockLines.length === 0 && (
              <p className="text-xs text-neutral-500">{tx("No `waf_block` events found in the selected range.")}</p>
            )}

            {wafBlockLines.length > 0 && (
              <div className="app-table-shell app-table-scroll-shell">
                <table className="app-table min-w-full text-xs">
                  <thead className="app-table-head sticky top-0">
                    <tr>
                      <th className="px-2 py-1 text-left">{tx("use")}</th>
                      <th className="px-2 py-1 text-left">{tx("ts")}</th>
                      <th className="px-2 py-1 text-left">{tx("rule_id")}</th>
                      <th className="px-2 py-1 text-left">{tx("host")}</th>
                      <th className="px-2 py-1 text-left">{tx("path")}</th>
                      <th className="px-2 py-1 text-left">{tx("matched_variable")}</th>
                      <th className="px-2 py-1 text-left">{tx("matched_value")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {wafBlockLines.map((line, idx) => {
                      const id = toStringField(line.req_id, toStringField(line.ts, `row-${idx}`));
                      const active = selectedEventID !== "" && selectedEventID === id;
                      return (
                        <tr key={`${id}-${idx}`} className={active ? "bg-blue-50" : ""}>
                          <td className="px-2 py-1">
                            <button
                              className="border border-neutral-200 rounded px-2 py-0.5"
                              onClick={() => onSelectWAFBlockLine(line)}
                              title={tx("Populate event input from this log line")}
                            >
                              {tx("Use")}
                            </button>
                          </td>
                          <td className="px-2 py-1 whitespace-nowrap">{toStringField(line.ts, "-")}</td>
                          <td className="px-2 py-1 whitespace-nowrap">{toStringField(line.rule_id, "-")}</td>
                          <td className="px-2 py-1 whitespace-nowrap" title={toStringField(line.original_host, toStringField(line.rewritten_host, "-"))}>
                            {shorten(toStringField(line.original_host, toStringField(line.rewritten_host, "-")), 28)}
                          </td>
                          <td className="px-2 py-1" title={toStringField(line.path, "-")}>
                            {shorten(toStringField(line.path, "-"), 36)}
                          </td>
                          <td className="px-2 py-1 whitespace-nowrap">{toStringField(line.matched_variable, "-")}</td>
                          <td className="px-2 py-1" title={toStringField(line.matched_value, "")}>
                            {shorten(toStringField(line.matched_value, ""), 44)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {!useLatestEvent && !showManualEventForm && (
            <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs text-neutral-700">
              {tx("Pick a recent `waf_block` log with Use, or start Manual entry.")}
            </div>
          )}

          {showManualEventForm && (
            <div className="grid gap-2 sm:grid-cols-2">
              <Field label="event_id" value={eventInput.event_id} onChange={(v) => updateEvent("event_id", v)} />
              <Field label="method" value={eventInput.method} onChange={(v) => updateEvent("method", v)} />
              <SelectField
                label="scheme"
                value={eventInput.scheme}
                options={["http", "https"]}
                onChange={(v) => updateEvent("scheme", v)}
              />
              <Field label="host" value={eventInput.host} onChange={(v) => updateEvent("host", v)} />
              <Field label="path" value={eventInput.path} onChange={(v) => updateEvent("path", v)} />
              <Field label="query" value={eventInput.query} onChange={(v) => updateEvent("query", v)} />
              <Field label="rule_id" value={eventInput.rule_id} onChange={(v) => updateEvent("rule_id", v)} />
              <Field label="status" value={eventInput.status} onChange={(v) => updateEvent("status", v)} />
              <Field label="matched_variable" value={eventInput.matched_variable} onChange={(v) => updateEvent("matched_variable", v)} />
              <label className="text-xs text-neutral-600 block sm:col-span-2">
                matched_value
                <textarea
                  className="mt-1 w-full border rounded px-2 py-1 font-mono text-xs h-20"
                  value={eventInput.matched_value}
                  onChange={(e) => updateEvent("matched_value", e.target.value)}
                />
              </label>
            </div>
          )}

          <button
            className="px-3 py-1.5 rounded-xl shadow text-xs bg-black text-white disabled:opacity-50"
            onClick={() => void onPropose()}
            disabled={proposing || !canPropose}
          >
            {proposing ? tx("Proposing...") : tx("Propose")}
          </button>
        </section>

        <section className="rounded-xl border bg-white p-3 space-y-3">
          <h2 className="text-xs font-semibold">{tx("Apply")}</h2>

          <label className="inline-flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={simulate}
              onChange={(e) => setSimulate(e.target.checked)}
            />
            {tx("Dry run only (do not write rule)")}
          </label>

          {!simulate && approvalRequired && (
            <label className="text-xs text-neutral-600 block">
              {tx("Approval token")}
              <input
                className="mt-1 w-full border rounded px-2 py-1 font-mono text-xs"
                value={approvalToken}
                onChange={(e) => setApprovalToken(e.target.value)}
                placeholder={tx("auto-filled from propose response")}
              />
            </label>
          )}

          <button
            className="px-3 py-1.5 rounded-xl shadow text-xs bg-black text-white disabled:opacity-50"
            onClick={() => void onApply()}
            disabled={readOnly || !canApply || applying}
          >
            {applying ? tx("Applying...") : tx("Apply")}
          </button>

          {applyResult && (
            <div className="app-code-shell">
              <pre className="app-code-block">{JSON.stringify(applyResult, null, 2)}</pre>
            </div>
          )}
        </section>
      </div>

      <section className="rounded-xl border bg-white p-3 space-y-2">
        <h2 className="text-xs font-semibold">{tx("Proposal")}</h2>

        {!proposal && !proposeResult?.no_proposal && <div className="text-xs text-neutral-500">{tx("No proposal yet.")}</div>}

        {!proposal && proposeResult?.no_proposal && (
          <div className="rounded border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 space-y-1">
            <div className="font-medium">{tx("No safe exclusion proposed.")}</div>
            <div>{proposeResult.no_proposal.reason || tx("Provider could not justify a safe scoped exclusion.")}</div>
            {typeof proposeResult.no_proposal.confidence === "number" && proposeResult.no_proposal.confidence > 0 && (
              <div className="text-xs">{tx("Confidence")}: {String(proposeResult.no_proposal.confidence)}</div>
            )}
          </div>
        )}

        {proposal && (
          <div className="grid gap-2">
            <Field label="id" value={proposal.id || ""} onChange={(v) => updateProposal("id", v)} />
            <Field label="title" value={proposal.title || ""} onChange={(v) => updateProposal("title", v)} />
            <Field label="summary" value={proposal.summary || ""} onChange={(v) => updateProposal("summary", v)} />
            <Field label="reason" value={proposal.reason || ""} onChange={(v) => updateProposal("reason", v)} />
            <Field
              label="confidence"
              value={String(proposal.confidence ?? "")}
              onChange={(v) => updateProposal("confidence", Number(v) || 0)}
            />
            <Field
              label="target_path"
              value={proposal.target_path || ""}
              onChange={(v) => updateProposal("target_path", v)}
            />
            <label className="text-xs text-neutral-600 block">
              rule_line
              <textarea
                className="mt-1 w-full border rounded px-2 py-1 font-mono text-xs h-28"
                value={proposal.rule_line || ""}
                onChange={(e) => updateProposal("rule_line", e.target.value)}
              />
            </label>
          </div>
        )}
      </section>

      {proposeResult && (
        <section className="rounded-xl border bg-white p-3 space-y-2">
          <h2 className="text-xs font-semibold">{tx("Last Propose Response")}</h2>
          <div className="app-code-shell">
            <pre className="app-code-block">{JSON.stringify(proposeResult, null, 2)}</pre>
          </div>
        </section>
      )}

      <section className="rounded-xl border bg-white p-3 space-y-3">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-xs font-semibold">{tx("Recent actions")}</h2>
          <button className="border rounded px-2 py-0.5 text-xs bg-white" onClick={() => void loadAudit()} disabled={auditLoading}>
            {auditLoading ? tx("Loading...") : tx("Reload")}
          </button>
        </div>

        {auditError && (
          <div className="rounded border border-red-300 bg-red-50 p-2 text-xs text-red-900">
            {auditError}
          </div>
        )}

        {!auditError && auditEntries.length === 0 && (
          <div className="text-xs text-neutral-500">{tx("No FP Tuner audit entries yet.")}</div>
        )}

        {auditEntries.length > 0 && (
          <div className="space-y-2">
            {auditEntries.map((entry, index) => (
              <button
                key={`${entry.ts || "audit"}-${index}`}
                type="button"
                className="w-full rounded-xl border bg-neutral-50 p-3 text-left hover:bg-white"
                onClick={() => setSelectedAudit(entry)}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-medium text-neutral-900">
                      {formatFPTunerAuditAction(entry.event)}
                    </span>
                    <Badge color={statusBadgeColor(formatFPTunerAuditStatus(entry.event))}>
                      {formatFPTunerAuditStatus(entry.event)}
                    </Badge>
                  </div>
                  <span className="text-xs text-neutral-500">{formatTimestamp(entry.ts, locale)}</span>
                </div>
                <div className="mt-2 text-xs text-neutral-900">{entry.actor || tx("unknown")}</div>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-neutral-600">
                  <span>{entry.target_path || "-"}</span>
                  <span>{formatFPTunerProposalSummary(entry)}</span>
                </div>
              </button>
            ))}
          </div>
        )}
      </section>

      {selectedAudit ? (
        <FPTunerAuditDetailModal entry={selectedAudit} onClose={() => setSelectedAudit(null)} />
      ) : null}
    </div>
  );
}

function formatTimestamp(ts?: string, locale: "en" | "ja" = "en") {
  if (!ts) {
    return "-";
  }
  return new Date(ts).toLocaleString(locale === "ja" ? "ja-JP" : "en-US");
}

function statusBadgeColor(status: string): "gray" | "green" | "amber" | "red" {
  switch (status) {
    case "applied":
      return "green";
    case "proposed":
    case "simulated":
    case "duplicate":
    case "denied":
      return "amber";
    case "error":
      return "red";
    default:
      return "gray";
  }
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <label className="text-xs text-neutral-600 block">
      {label}
      <input
        className="mt-1 w-full border rounded px-2 py-1 font-mono text-xs"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}

function SelectField({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (v: string) => void;
}) {
  return (
    <label className="text-xs text-neutral-600 block">
      {label}
      <select className="mt-1 w-full border rounded px-2 py-1 font-mono text-xs" value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

function Badge({ color, children }: { color: "gray" | "green" | "amber" | "red"; children: ReactNode }) {
  const cls =
    color === "green"
      ? "bg-green-100 text-green-800"
      : color === "amber"
      ? "bg-amber-100 text-amber-800"
      : color === "red"
      ? "bg-red-100 text-red-800"
      : "bg-neutral-100 text-neutral-700";
  return <span className={`px-2 py-0.5 text-xs rounded ${cls}`}>{children}</span>;
}

function FPTunerAuditDetailModal({
  entry,
  onClose,
}: {
  entry: FPTunerAuditEntry;
  onClose: () => void;
}) {
  const { tx } = useI18n();
  const details = buildFPTunerAuditDetails(entry);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/45 px-4 py-6">
      <div className="w-full max-w-3xl rounded-2xl border border-neutral-200 bg-white shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-neutral-200 px-5 py-4">
          <div>
            <h2 className="text-lg font-semibold">{tx("FP Tuner audit detail")}</h2>
            <p className="text-xs text-neutral-500">
              {formatFPTunerAuditAction(entry.event)} / {formatFPTunerAuditStatus(entry.event)}
            </p>
          </div>
          <button type="button" className="text-xs underline" onClick={onClose}>
            {tx("close")}
          </button>
        </div>
        <div className="grid gap-3 px-5 py-4 md:grid-cols-2">
          {details.map((detail) => (
            <div key={`${detail.label}:${detail.value}`} className="rounded bg-neutral-50 p-3">
              <div className="text-xs uppercase tracking-wide text-neutral-500">{detail.label}</div>
              <div className="mt-1 break-all font-mono text-xs text-neutral-900">{detail.value}</div>
            </div>
          ))}
        </div>
        <div className="flex justify-end border-t border-neutral-200 px-5 py-4">
          <button type="button" className="border rounded px-3 py-1.5 text-xs" onClick={onClose}>
            {tx("Close")}
          </button>
        </div>
      </div>
    </div>
  );
}
