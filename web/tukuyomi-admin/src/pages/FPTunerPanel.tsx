import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { apiGetJson, apiPostJson } from "@/lib/api";

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
  } | null;
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

const defaultTargetPath = "rules/tukuyomi.conf";

export default function FPTunerPanel() {
  const [targetPath, setTargetPath] = useState(defaultTargetPath);
  const [useLatestEvent, setUseLatestEvent] = useState(false);
  const [eventInput, setEventInput] = useState<EventInput>(defaultEvent);
  const [selectedEventID, setSelectedEventID] = useState("");
  const [manualEntryEnabled, setManualEntryEnabled] = useState(false);
  const [logTail, setLogTail] = useState(30);
  const [wafBlockLines, setWafBlockLines] = useState<WAFLogLine[]>([]);
  const [logLoading, setLogLoading] = useState(false);
  const [logError, setLogError] = useState<string | null>(null);

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
    } catch (e: any) {
      setLogError(e?.message || "Failed to load waf logs");
    } finally {
      setLogLoading(false);
    }
  }, [logTail]);

  useEffect(() => {
    void loadWAFBlockLines();
  }, [loadWAFBlockLines]);

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
      setApprovalToken(res.proposal ? res.approval?.token ?? "" : "");
      setMode(res.mode || "-");
      setSource(res.source || "-");
      setContractVersion(res.contract_version || "-");
    } catch (e: any) {
      setError(e?.message || "Propose failed");
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
      const res = await apiPostJson<ApplyResponse>("/fp-tuner/apply", payload);
      setApplyResult(res);
    } catch (e: any) {
      setError(e?.message || "Apply failed");
    } finally {
      setApplying(false);
    }
  }

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">FP Tuner</h1>
        <div className="flex items-center gap-2 text-xs">
          <Badge color="gray">mode: {mode}</Badge>
          <Badge color="gray">source: {source}</Badge>
          <Badge color="gray">contract: {contractVersion}</Badge>
          {approvalRequired ? <Badge color="amber">approval required</Badge> : <Badge color="green">approval optional</Badge>}
        </div>
      </header>

      {error && (
        <div className="border border-red-300 bg-red-50 rounded-xl p-3 text-sm">
          Error: {error}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-xl border bg-white p-3 space-y-3">
          <h2 className="text-sm font-semibold">Propose Input</h2>

          <label className="text-xs text-neutral-600 block">
            Target Path
            <input
              className="mt-1 w-full border rounded px-2 py-1"
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              placeholder="rules/tukuyomi.conf"
            />
          </label>

          <div className="flex flex-wrap items-center gap-3 text-sm">
            <label className="inline-flex items-center gap-2">
              <input
                type="checkbox"
                checked={useLatestEvent}
                onChange={(e) => {
                  setUseLatestEvent(e.target.checked);
                  if (e.target.checked) {
                    setManualEntryEnabled(false);
                  }
                }}
              />
              Use latest `waf_block` log event
            </label>
            <button
              className="text-xs border rounded px-2 py-0.5 bg-white"
              onClick={() => {
                setManualEntryEnabled(true);
                setUseLatestEvent(false);
                setSelectedEventID("");
                setEventInput(defaultEvent);
              }}
            >
              Manual entry
            </button>
          </div>

          <div className="rounded border bg-neutral-50 p-2 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-semibold text-neutral-700">Pick From Recent `waf_block` Logs</h3>
              <div className="flex items-center gap-2">
                <label className="text-xs text-neutral-600">
                  Rows
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
                  {logLoading ? "Loading..." : "Reload"}
                </button>
              </div>
            </div>

            {logError && <p className="text-xs text-red-700">Log error: {logError}</p>}

            {!logError && wafBlockLines.length === 0 && (
              <p className="text-xs text-neutral-500">No `waf_block` events found in the selected range.</p>
            )}

            {wafBlockLines.length > 0 && (
              <div className="app-table-shell">
                <div className="app-table-scroll-shell max-h-44">
                <table className="app-table min-w-full">
                  <thead className="app-table-head sticky top-0">
                    <tr>
                      <th className="px-2 py-1 text-left">use</th>
                      <th className="px-2 py-1 text-left">ts</th>
                      <th className="px-2 py-1 text-left">rule_id</th>
                      <th className="px-2 py-1 text-left">scheme</th>
                      <th className="px-2 py-1 text-left">host</th>
                      <th className="px-2 py-1 text-left">path</th>
                      <th className="px-2 py-1 text-left">matched_variable</th>
                      <th className="px-2 py-1 text-left">matched_value</th>
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
                              className="border rounded px-2 py-0.5"
                              onClick={() => onSelectWAFBlockLine(line)}
                              title="Populate event input from this log line"
                            >
                              Use
                            </button>
                          </td>
                          <td className="px-2 py-1 whitespace-nowrap">{toStringField(line.ts, "-")}</td>
                          <td className="px-2 py-1 whitespace-nowrap">{toStringField(line.rule_id, "-")}</td>
                          <td className="px-2 py-1 whitespace-nowrap">{toStringField(line.original_scheme, "-")}</td>
                          <td className="px-2 py-1 whitespace-nowrap">{toStringField(line.original_host, toStringField(line.rewritten_host, "-"))}</td>
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
              </div>
            )}
          </div>

          {!useLatestEvent && !showManualEventForm && (
            <div className="text-sm text-neutral-500">
              Pick a recent `waf_block` log with Use, or start Manual entry.
            </div>
          )}

          {showManualEventForm && (
            <div className="grid gap-2 sm:grid-cols-2">
              <Field label="event_id" value={eventInput.event_id} onChange={(v) => updateEvent("event_id", v)} />
              <Field label="method" value={eventInput.method} onChange={(v) => updateEvent("method", v)} />
              <Field label="scheme" value={eventInput.scheme} onChange={(v) => updateEvent("scheme", v)} />
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
            className="px-3 py-1.5 rounded-xl shadow text-sm bg-black text-white disabled:opacity-50"
            onClick={() => void onPropose()}
            disabled={!canPropose || proposing}
          >
            {proposing ? "Proposing..." : "Propose"}
          </button>
        </section>

        <section className="rounded-xl border bg-white p-3 space-y-3">
          <h2 className="text-sm font-semibold">Apply</h2>

          <label className="inline-flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={simulate}
              onChange={(e) => setSimulate(e.target.checked)}
            />
            Dry run only (do not write rule)
          </label>

          {approvalRequired && proposal && (
            <label className="text-xs text-neutral-600 block">
              approval_token
              <input
                className="mt-1 w-full border rounded px-2 py-1 font-mono text-xs"
                value={approvalToken}
                onChange={(e) => setApprovalToken(e.target.value)}
                placeholder="auto-filled from propose response"
              />
            </label>
          )}

          <p className="text-xs text-neutral-600">
            {simulate
              ? "Apply validates the proposal only. The rule file is not written and hot reload does not run."
              : "Apply writes the proposed rule and hot reloads the active ruleset."}
          </p>

          <button
            className="px-3 py-1.5 rounded-xl shadow text-sm bg-black text-white disabled:opacity-50"
            onClick={() => void onApply()}
            disabled={!canApply || applying}
          >
            {applying ? "Applying..." : "Apply"}
          </button>

          {applyResult && (
            <div className="app-code-shell">
              <pre className="app-code-block">{JSON.stringify(applyResult, null, 2)}</pre>
            </div>
          )}
        </section>
      </div>

      <section className="rounded-xl border bg-white p-3 space-y-2">
        <h2 className="text-sm font-semibold">Proposal</h2>

        {!proposal && !proposeResult?.no_proposal && <div className="text-sm text-neutral-500">No proposal yet.</div>}

        {proposeResult?.no_proposal && (
          <div className="rounded border border-amber-300 bg-amber-50 p-3 text-sm space-y-1">
            <div className="font-medium">No proposal returned</div>
            <div>{proposeResult.no_proposal.reason || "Provider could not justify a safe scoped exclusion."}</div>
            {typeof proposeResult.no_proposal.confidence === "number" && (
              <div className="text-xs text-neutral-600">confidence: {proposeResult.no_proposal.confidence}</div>
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
          <h2 className="text-sm font-semibold">Last Propose Response</h2>
          <div className="app-code-shell">
            <pre className="app-code-block">{JSON.stringify(proposeResult, null, 2)}</pre>
          </div>
        </section>
      )}
    </div>
  );
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

function Badge({ color, children }: { color: "gray" | "green" | "amber"; children: ReactNode }) {
  const cls =
    color === "green"
      ? "bg-green-100 text-green-800"
      : color === "amber"
      ? "bg-amber-100 text-amber-800"
      : "bg-neutral-100 text-neutral-700";
  return <span className={`px-2 py-0.5 text-xs rounded ${cls}`}>{children}</span>;
}
