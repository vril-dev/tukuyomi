import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";

type BotDefenseDTO = {
    etag?: string;
    raw?: string;
    enabled?: boolean;
    dry_run?: boolean;
    mode?: string;
    path_prefixes?: string[];
    path_policy_count?: number;
    behavioral_enabled?: boolean;
};

type BotDecisionRecord = {
    timestamp?: string;
    action?: string;
    dry_run?: boolean;
    status?: number;
    flow_policy?: string;
    risk_score?: number;
    path?: string;
    signals?: string[];
};

type BotDecisionListDTO = {
    items?: BotDecisionRecord[];
};

export default function BotDefensePanel() {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [raw, setRaw] = useState("");
    const [serverRaw, setServerRaw] = useState("");
    const [etag, setEtag] = useState<string | null>(null);
    const [valid, setValid] = useState<boolean | null>(null);
    const [messages, setMessages] = useState<string[]>([]);
    const [enabled, setEnabled] = useState<boolean>(false);
    const [dryRun, setDryRun] = useState<boolean>(false);
    const [mode, setMode] = useState<string>("suspicious");
    const [pathPrefixes, setPathPrefixes] = useState<string[]>([]);
    const [pathPolicyCount, setPathPolicyCount] = useState<number>(0);
    const [behavioralEnabled, setBehavioralEnabled] = useState<boolean>(false);
    const [decisions, setDecisions] = useState<BotDecisionRecord[]>([]);
    const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
    const [error, setError] = useState<string | null>(null);

    const dirty = useMemo(() => raw !== serverRaw, [raw, serverRaw]);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiGetJson<BotDefenseDTO>("/bot-defense-rules");
            const decisionData = await apiGetJson<BotDecisionListDTO>("/bot-defense-decisions?limit=8");
            setRaw(data.raw ?? "");
            setServerRaw(data.raw ?? "");
            setEtag(data.etag ?? null);
            setEnabled(!!data.enabled);
            setDryRun(!!data.dry_run);
            setMode(data.mode || "suspicious");
            setPathPrefixes(Array.isArray(data.path_prefixes) ? data.path_prefixes : []);
            setPathPolicyCount(typeof data.path_policy_count === "number" ? data.path_policy_count : 0);
            setBehavioralEnabled(!!data.behavioral_enabled);
            setDecisions(Array.isArray(decisionData.items) ? decisionData.items : []);
            setValid(null);
            setMessages([]);
        } catch (e: any) {
            setError(e?.message || String(e));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        void load();
    }, [load]);

    const debounceRef = useRef<number | null>(null);
    useEffect(() => {
        if (debounceRef.current) {
            window.clearTimeout(debounceRef.current);
        }

        if (loading) {
            return;
        }

        debounceRef.current = window.setTimeout(async () => {
            try {
                const js = await apiPostJson<{ ok: boolean; messages?: string[]; enabled?: boolean; dry_run?: boolean; mode?: string; path_prefixes?: string[]; path_policy_count?: number; behavioral_enabled?: boolean }>(
                    "/bot-defense-rules:validate",
                    { raw }
                );
                setValid(!!js.ok);
                setMessages(Array.isArray(js.messages) ? js.messages : []);
                setEnabled(!!js.enabled);
                setDryRun(!!js.dry_run);
                setMode(js.mode || "suspicious");
                setPathPrefixes(Array.isArray(js.path_prefixes) ? js.path_prefixes : []);
                setPathPolicyCount(typeof js.path_policy_count === "number" ? js.path_policy_count : 0);
                setBehavioralEnabled(!!js.behavioral_enabled);
            } catch (e: any) {
                setValid(false);
                setMessages([e?.message || "Validate failed"]);
            }
        }, 300);

        return () => {
            if (debounceRef.current) window.clearTimeout(debounceRef.current);
        };
    }, [raw, loading]);

    const doSave = useCallback(async () => {
        setSaving(true);
        setError(null);
        try {
            const js = await apiPutJson<{ ok: boolean; etag?: string; enabled?: boolean; dry_run?: boolean; mode?: string; path_prefixes?: string[]; path_policy_count?: number; behavioral_enabled?: boolean }>(
                "/bot-defense-rules",
                { raw },
                { headers: etag ? { "If-Match": etag } : {} }
            );
            if (!js.ok) {
                throw new Error("Failed to save");
            }

            setEtag(js.etag ?? null);
            setServerRaw(raw);
            setEnabled(!!js.enabled);
            setDryRun(!!js.dry_run);
            setMode(js.mode || "suspicious");
            setPathPrefixes(Array.isArray(js.path_prefixes) ? js.path_prefixes : []);
            setPathPolicyCount(typeof js.path_policy_count === "number" ? js.path_policy_count : 0);
            setBehavioralEnabled(!!js.behavioral_enabled);
            setLastSavedAt(Date.now());
            const decisionData = await apiGetJson<BotDecisionListDTO>("/bot-defense-decisions?limit=8");
            setDecisions(Array.isArray(decisionData.items) ? decisionData.items : []);
        } catch (e: any) {
            setError(e?.message || "Save failed");
        } finally {
            setSaving(false);
        }
    }, [raw, etag]);

    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            const isSave = (e.key === "s" || e.key === "S") && (e.ctrlKey || e.metaKey);
            if (!isSave) {
                return;
            }

            e.preventDefault();
            if (!saving) {
                void doSave();
            }
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [doSave, saving]);

    const lineCount = useMemo(() => (raw ? raw.split(/\n/).length : 0), [raw]);
    const statusBadge = useMemo(() => {
        if (loading) {
            return <Badge color="gray">Loading</Badge>;
        }
        if (valid === null) {
            return <Badge color="gray">Unvalidated</Badge>;
        }
        return valid ? <Badge color="green">Valid</Badge> : <Badge color="red">Invalid</Badge>;
    }, [loading, valid]);

    return (
        <div className="w-full p-4 space-y-4">
            <header className="flex items-center justify-between">
                <h1 className="text-xl font-semibold">Bot Defense</h1>
                <div className="flex items-center gap-2">
                    {statusBadge}
                    {enabled ? <Badge color="green">Enabled</Badge> : <Badge color="gray">Disabled</Badge>}
                    {dryRun && <Badge color="amber">Dry-run</Badge>}
                    {behavioralEnabled && <Badge color="amber">Behavioral</Badge>}
                    {dirty && <Badge color="amber">Unsaved</Badge>}
                    {etag && <MonoTag label="ETag" value={etag} />}
                </div>
            </header>

            {error && (
                <Alert kind="error" title="Error" message={error} onClose={() => setError(null)} />
            )}

            <div className="grid gap-3">
                <div className="flex items-center justify-between gap-2">
                    <div className="text-sm text-neutral-500">
                        Manage bot-defense rollout in JSON (`dry_run`, `path_policies`, `behavioral_detection`, challenge cookie/TTL/status).
                    </div>
                    <div className="flex items-center gap-2">
                        <button
                            type="button"
                            className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                            onClick={() => setRaw((prev) => (prev ? prev : defaultBotDefenseExample))}
                            disabled={loading}
                        >
                            Insert example
                        </button>
                        <button
                            type="button"
                            className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                            onClick={() => void load()}
                            disabled={loading}
                        >
                            Refresh
                        </button>
                        <button
                            type="button"
                            className="px-3 py-1.5 rounded-xl shadow text-sm bg-black text-white disabled:opacity-50"
                            onClick={() => void doSave()}
                            disabled={loading || saving || !dirty}
                            title="Ctrl/Cmd+S"
                        >
                            {saving ? "Saving..." : "Save"}
                        </button>
                    </div>
                </div>

                <textarea
                    className="w-full h-[440px] p-3 border rounded-xl font-mono text-sm leading-5 outline-none focus:ring-2 focus:ring-black/20"
                    value={raw}
                    onChange={(e) => setRaw(e.target.value)}
                    spellCheck={false}
                />

                <div className="flex items-center justify-between text-xs text-neutral-500">
                    <div className="flex items-center gap-3">
                        <span>Lines: {lineCount}</span>
                        <span>Mode: {mode || "-"}</span>
                        <span>Paths: {pathPrefixes.length}</span>
                        <span>Policies: {pathPolicyCount}</span>
                        {lastSavedAt && <span>Last saved: {new Date(lastSavedAt).toLocaleString()}</span>}
                    </div>
                    <div className="flex items-center gap-2 max-w-[60%] overflow-hidden">
                        {messages.slice(0, 3).map((m, i) => (
                            <span key={`msg-${i}`} className="px-2 py-0.5 bg-neutral-100 rounded">
                                {m}
                            </span>
                        ))}
                    </div>
                </div>
            </div>

            <div className="grid gap-2">
                <div className="text-sm font-medium">Recent Decisions</div>
                <div className="app-table-shell">
                    <div className="app-table-scroll-shell">
                        <table className="app-table">
                            <thead className="app-table-head">
                                <tr>
                                    <th className="px-3 py-2 text-left">Timestamp</th>
                                    <th className="px-3 py-2 text-left">Action</th>
                                    <th className="px-3 py-2 text-left">Risk</th>
                                    <th className="px-3 py-2 text-left">Path / Signals</th>
                                </tr>
                            </thead>
                            <tbody>
                                {decisions.length === 0 ? (
                                    <tr>
                                        <td colSpan={4} className="px-3 py-3 text-neutral-500">No recent decisions.</td>
                                    </tr>
                                ) : decisions.map((item, idx) => (
                                    <tr key={`decision-${idx}`}>
                                        <td className="px-3 py-2 whitespace-nowrap">{item.timestamp || "-"}</td>
                                        <td className="px-3 py-2 whitespace-nowrap">{item.dry_run ? `would-${item.action || "allow"}` : (item.action || "allow")}</td>
                                        <td className="px-3 py-2 whitespace-nowrap">{typeof item.risk_score === "number" ? item.risk_score : "-"}</td>
                                        <td className="px-3 py-2">{item.path || "-"}{Array.isArray(item.signals) && item.signals.length ? ` | ${item.signals.join(", ")}` : ""}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    );
}

const defaultBotDefenseExample = `{
  "enabled": false,
  "dry_run": false,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "path_policies": [],
  "exempt_cidrs": [],
  "suspicious_user_agents": [
    "curl",
    "wget",
    "python-requests",
    "python-urllib",
    "go-http-client",
    "libwww-perl",
    "scrapy",
    "sqlmap",
    "nikto",
    "nmap",
    "masscan"
  ],
  "behavioral_detection": {
    "enabled": false,
    "window_seconds": 60,
    "burst_threshold": 12,
    "path_fanout_threshold": 6,
    "ua_churn_threshold": 4,
    "missing_cookie_threshold": 6,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "",
  "challenge_ttl_seconds": 86400,
  "challenge_status_code": 429
}`;

function Badge({ color, children }: { color: "gray" | "green" | "red" | "amber"; children: React.ReactNode }) {
    const cls =
        color === "green" ? "bg-green-100 text-green-800" :
        color === "red" ? "bg-red-100 text-red-800" :
        color === "amber" ? "bg-amber-100 text-amber-800" :
        "bg-neutral-100 text-neutral-700";

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

function Alert({ kind, title, message, onClose }: { kind: "error" | "info"; title: string; message: string; onClose?: () => void }) {
    const cls = kind === "error" ? "border-red-300 bg-red-50" : "border-blue-300 bg-blue-50";

    return (
        <div className={`border ${cls} rounded-xl p-3 text-sm flex items-start gap-3`}>
            <div className="font-semibold">{title}</div>
            <div className="flex-1 whitespace-pre-wrap">{message}</div>
            {onClose && (
                <button className="text-xs text-neutral-500 hover:underline" onClick={onClose}>Close</button>
            )}
        </div>
    );
}
