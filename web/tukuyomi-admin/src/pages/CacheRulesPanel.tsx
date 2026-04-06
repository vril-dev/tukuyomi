import React, { useCallback, useEffect, useMemo, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";

type Match = {
  type: "prefix" | "regex" | "exact";
  value: string;
};

type Rule = {
  kind: "ALLOW" | "DENY";
  match: Match;
  methods?: string[];
  ttl?: number;
  vary?: string[];
};

type RulesDTO = {
  etag?: string;
  raw?: string;
  rules?: Rule[];
};

type CacheRuntimeDTO = {
  response_cache_mode?: string;
  response_cache_enabled?: boolean;
  response_cache_max_entries?: number;
  response_cache_max_body_bytes?: number;
  response_cache_stale_seconds?: number;
  response_cache_refresh_timeout_sec?: number;
  response_cache_entry_count?: number;
  response_cache_inflight_keys?: number;
  response_cache_hits?: number;
  response_cache_misses?: number;
  response_cache_stores?: number;
  response_cache_bypasses?: number;
  response_cache_evictions?: number;
  response_cache_coalesced_waits?: number;
  response_cache_stale_hits?: number;
  response_cache_stale_refreshes?: number;
  response_cache_stale_failures?: number;
};

type ValidateResp = {
  ok: boolean;
  messages?: string[];
};

type SaveResp = {
  ok: boolean;
  etag?: string;
};

const defaultRule: Rule = {
  kind: "ALLOW",
  match: { type: "prefix", value: "/" },
  methods: ["GET", "HEAD"],
  ttl: 600,
  vary: ["Accept-Encoding"],
};

function splitCSV(v: string): string[] {
  return v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export default function CacheRulePanel() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [runtime, setRuntime] = useState<CacheRuntimeDTO>({});
  const [raw, setRaw] = useState("");
  const [rawMode, setRawMode] = useState(false);
  const [etag, setEtag] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [validating, setValidating] = useState(false);
  const [valid, setValid] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
  const [serverRaw, setServerRaw] = useState("");
  const [serverRuleSig, setServerRuleSig] = useState("[]");

  const ruleSig = useMemo(() => JSON.stringify(rules), [rules]);
  const dirty = raw !== serverRaw || ruleSig !== serverRuleSig;

  const lineCount = useMemo(() => (raw ? raw.split(/\n/).length : 0), [raw]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [data, status] = await Promise.all([
        apiGetJson<RulesDTO>("/cache-rules"),
        apiGetJson<CacheRuntimeDTO>("/status").catch(() => null),
      ]);
      const nextRules = Array.isArray(data.rules) ? data.rules : [];
      const nextRaw = data.raw ?? "";
      setRules(nextRules);
      setRuntime(status ?? {});
      setRaw(nextRaw);
      setEtag(data.etag ?? null);
      setServerRaw(nextRaw);
      setServerRuleSig(JSON.stringify(nextRules));
      setValid(null);
      setMessages([]);
    } catch (e: any) {
      setError(e?.message || "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const validate = useCallback(async () => {
    setValidating(true);
    setError(null);
    setMessages([]);
    const body = rawMode ? { rawMode: true, raw } : { rawMode: false, rules };
    try {
      const js = await apiPostJson<ValidateResp>("/cache-rules:validate", body);
      setValid(!!js.ok);
      setMessages(Array.isArray(js.messages) && js.messages.length > 0 ? js.messages : js.ok ? ["OK"] : ["validation error"]);
    } catch (e: any) {
      setValid(false);
      setMessages([e?.message || "validate failed"]);
    } finally {
      setValidating(false);
    }
  }, [rawMode, raw, rules]);

  const save = useCallback(async () => {
    setSaving(true);
    setError(null);
    setMessages([]);
    const body = rawMode ? { rawMode: true, raw } : { rawMode: false, rules };

    try {
      const js = await apiPutJson<SaveResp>("/cache-rules", body, {
        headers: etag ? { "If-Match": etag } : {},
      });
      if (!js.ok) {
        throw new Error("save failed");
      }
      setEtag(js.etag ?? null);
      setLastSavedAt(Date.now());
      setMessages(["Saved. Hot reload applied immediately."]);
      await load();
    } catch (e: any) {
      setError(e?.message || "save failed");
    } finally {
      setSaving(false);
    }
  }, [rawMode, raw, rules, etag, load]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const isSave = (e.key === "s" || e.key === "S") && (e.ctrlKey || e.metaKey);
      if (!isSave) {
        return;
      }
      e.preventDefault();
      if (!saving) {
        void save();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [save, saving]);

  function updateRule(i: number, next: Rule) {
    setRules((prev) => prev.map((r, idx) => (idx === i ? next : r)));
  }

  function removeRule(i: number) {
    setRules((prev) => prev.filter((_, idx) => idx !== i));
  }

  function addRule() {
    setRules((prev) => [...prev, { ...defaultRule }]);
  }

  const statusBadge = loading ? (
    <Badge color="gray">Loading</Badge>
  ) : valid === null ? (
    <Badge color="gray">Unvalidated</Badge>
  ) : valid ? (
    <Badge color="green">Valid</Badge>
  ) : (
    <Badge color="red">Invalid</Badge>
  );

  const cacheMode = String(runtime.response_cache_mode ?? "off");
  const cacheEnabled = runtime.response_cache_enabled === true;

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Cache Rules</h1>
        <div className="flex items-center gap-2">
          {statusBadge}
          {rawMode ? <Badge color="amber">Raw Mode</Badge> : <Badge color="gray">Table Mode</Badge>}
          {dirty && <Badge color="amber">Unsaved</Badge>}
          {etag && <MonoTag label="ETag" value={etag} />}
        </div>
      </header>

      {error && <Alert kind="error" title="Error" message={error} onClose={() => setError(null)} />}

      <section className="rounded-2xl border border-neutral-200 bg-white p-4 shadow-sm space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold">Cache Runtime</h2>
            <p className="text-sm text-neutral-500">
              Runtime counters for the standalone in-memory cache. Mode remains env-driven on [web] for now.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge color={cacheEnabled ? "green" : "gray"}>{cacheEnabled ? "Enabled" : "Disabled"}</Badge>
            <Badge color={cacheMode === "memory" ? "green" : cacheMode === "off" ? "gray" : "amber"}>{cacheMode}</Badge>
          </div>
        </div>

        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-5 text-sm">
          <StatChip label="Mode" value={cacheMode} />
          <StatChip label="Max Entries" value={String(runtime.response_cache_max_entries ?? 0)} />
          <StatChip label="Max Body Bytes" value={formatBytes(runtime.response_cache_max_body_bytes)} />
          <StatChip label="Stale Window" value={`${runtime.response_cache_stale_seconds ?? 0}s`} />
          <StatChip label="Refresh Timeout" value={`${runtime.response_cache_refresh_timeout_sec ?? 0}s`} />
          <StatChip label="Entries" value={String(runtime.response_cache_entry_count ?? 0)} />
          <StatChip label="Inflight Keys" value={String(runtime.response_cache_inflight_keys ?? 0)} />
          <StatChip label="Hits" value={String(runtime.response_cache_hits ?? 0)} />
          <StatChip label="Misses" value={String(runtime.response_cache_misses ?? 0)} />
          <StatChip label="Stores" value={String(runtime.response_cache_stores ?? 0)} />
          <StatChip label="Bypasses" value={String(runtime.response_cache_bypasses ?? 0)} />
          <StatChip label="Evictions" value={String(runtime.response_cache_evictions ?? 0)} />
          <StatChip label="Coalesced Waits" value={String(runtime.response_cache_coalesced_waits ?? 0)} />
          <StatChip label="Stale Hits" value={String(runtime.response_cache_stale_hits ?? 0)} />
          <StatChip label="Refresh Attempts" value={String(runtime.response_cache_stale_refreshes ?? 0)} />
          <StatChip label="Refresh Failures" value={String(runtime.response_cache_stale_failures ?? 0)} />
          <StatChip label="Future Store Shape" value="disk-backed reserved" />
        </div>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm text-neutral-600">
          <label className="inline-flex items-center gap-2">
            <input type="checkbox" checked={rawMode} onChange={(e) => setRawMode(e.target.checked)} />
            Raw edit mode
          </label>
        </div>

        <div className="flex items-center gap-2">
          {!rawMode && (
            <button
              type="button"
              className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
              onClick={addRule}
              disabled={loading || saving}
            >
              Add rule
            </button>
          )}
          <button
            type="button"
            className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
            onClick={() => void load()}
            disabled={loading || saving}
          >
            Refresh
          </button>
          <button
            type="button"
            className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
            onClick={() => void validate()}
            disabled={loading || saving || validating}
          >
            {validating ? "Validating..." : "Validate"}
          </button>
          <button
            type="button"
            className="px-3 py-1.5 rounded-xl shadow text-sm bg-black text-white disabled:opacity-50"
            onClick={() => void save()}
            disabled={loading || saving || !dirty}
            title="Ctrl/Cmd+S"
          >
            {saving ? "Saving..." : "Save"}
          </button>
        </div>
      </div>

      {!rawMode ? (
        <div className="border rounded-xl overflow-hidden bg-white">
          <div className="overflow-auto">
            <table className="min-w-[980px] w-full text-sm">
              <thead className="bg-neutral-100">
                <tr>
                  <th className="p-2 text-left border-b">Kind</th>
                  <th className="p-2 text-left border-b">Match Type</th>
                  <th className="p-2 text-left border-b">Value</th>
                  <th className="p-2 text-left border-b">Methods</th>
                  <th className="p-2 text-left border-b">TTL(s)</th>
                  <th className="p-2 text-left border-b">Vary</th>
                  <th className="p-2 text-center border-b w-28">Action</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r, i) => (
                  <tr key={i}>
                    <td className="p-1.5 border-b">
                      <select
                        value={r.kind}
                        onChange={(e) => updateRule(i, { ...r, kind: e.target.value as Rule["kind"] })}
                        className="w-full"
                      >
                        <option value="ALLOW">ALLOW</option>
                        <option value="DENY">DENY</option>
                      </select>
                    </td>
                    <td className="p-1.5 border-b">
                      <select
                        value={r.match.type}
                        onChange={(e) =>
                          updateRule(i, {
                            ...r,
                            match: { ...r.match, type: e.target.value as Match["type"] },
                          })
                        }
                        className="w-full"
                      >
                        <option value="prefix">prefix</option>
                        <option value="regex">regex</option>
                        <option value="exact">exact</option>
                      </select>
                    </td>
                    <td className="p-1.5 border-b">
                      <input
                        className="w-full"
                        value={r.match.value}
                        onChange={(e) => updateRule(i, { ...r, match: { ...r.match, value: e.target.value } })}
                      />
                    </td>
                    <td className="p-1.5 border-b">
                      <input
                        className="w-full"
                        value={(r.methods ?? []).join(",")}
                        onChange={(e) => updateRule(i, { ...r, methods: splitCSV(e.target.value) })}
                        placeholder="GET,HEAD"
                      />
                    </td>
                    <td className="p-1.5 border-b">
                      <input
                        type="number"
                        className="w-full"
                        value={r.ttl ?? 0}
                        onChange={(e) =>
                          updateRule(i, {
                            ...r,
                            ttl: Number.isFinite(+e.target.value) ? parseInt(e.target.value || "0", 10) : 0,
                          })
                        }
                      />
                    </td>
                    <td className="p-1.5 border-b">
                      <input
                        className="w-full"
                        value={(r.vary ?? []).join(",")}
                        onChange={(e) => updateRule(i, { ...r, vary: splitCSV(e.target.value) })}
                        placeholder="Accept-Encoding,Accept-Language"
                      />
                    </td>
                    <td className="p-1.5 border-b text-center">
                      <button
                        type="button"
                        onClick={() => removeRule(i)}
                        className="px-2 py-1 text-xs border rounded bg-white hover:bg-red-50"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
                {rules.length === 0 && (
                  <tr>
                    <td colSpan={7} className="p-4 text-center text-neutral-500">
                      No rules
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <textarea
          className="w-full h-[440px] p-3 border rounded-xl font-mono text-sm leading-5 outline-none focus:ring-2 focus:ring-black/20"
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          spellCheck={false}
        />
      )}

      <div className="flex items-center justify-between text-xs text-neutral-500">
        <div className="flex items-center gap-3">
          <span>Rules: {rules.length}</span>
          <span>Raw lines: {lineCount}</span>
          {lastSavedAt && <span>Last saved: {new Date(lastSavedAt).toLocaleString()}</span>}
        </div>
        <div className="flex items-center gap-2 max-w-[60%] overflow-hidden">
          {messages.slice(0, 3).map((m, i) => (
            <span key={i} className="px-2 py-0.5 bg-neutral-100 rounded">
              {m}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function StatChip({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border bg-white px-3 py-2">
      <div className="text-xs text-neutral-500">{label}</div>
      <div className="mt-1 font-mono text-xs break-all">{value}</div>
    </div>
  );
}

function formatBytes(v: unknown) {
  const n = typeof v === "number" ? v : Number(v ?? 0);
  if (!Number.isFinite(n) || n <= 0) {
    return "0 B";
  }
  if (n < 1024) {
    return `${n} B`;
  }
  if (n < 1024 * 1024) {
    return `${(n / 1024).toFixed(1)} KiB`;
  }
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

function Badge({
  color,
  children,
}: {
  color: "gray" | "green" | "red" | "amber";
  children: React.ReactNode;
}) {
  const cls =
    color === "green"
      ? "bg-green-100 text-green-800"
      : color === "red"
        ? "bg-red-100 text-red-800"
        : color === "amber"
          ? "bg-amber-100 text-amber-800"
          : "bg-neutral-100 text-neutral-700";

  return <span className={`px-2 py-0.5 text-xs rounded ${cls}`}>{children}</span>;
}

function MonoTag({ label, value }: { label: string; value: string }) {
  return (
    <div className="hidden md:flex items-center gap-1 text-xs">
      <span className="text-neutral-500">{label}:</span>
      <code className="px-2 py-0.5 bg-neutral-100 rounded max-w-[420px] truncate">{value}</code>
    </div>
  );
}

function Alert({
  kind,
  title,
  message,
  onClose,
}: {
  kind: "error" | "info";
  title: string;
  message: string;
  onClose?: () => void;
}) {
  const cls = kind === "error" ? "border-red-300 bg-red-50" : "border-blue-300 bg-blue-50";

  return (
    <div className={`border ${cls} rounded-xl p-3 text-sm flex items-start gap-3`}>
      <div className="font-semibold">{title}</div>
      <div className="flex-1 whitespace-pre-wrap">{message}</div>
      {onClose && (
        <button className="text-xs text-neutral-500 hover:underline" onClick={onClose}>
          Close
        </button>
      )}
    </div>
  );
}
