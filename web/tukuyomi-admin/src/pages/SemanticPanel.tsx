import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";

type SemanticStats = {
    inspected_requests?: number;
    scored_requests?: number;
    log_only_actions?: number;
    challenge_actions?: number;
    block_actions?: number;
};

type SemanticDTO = {
    etag?: string;
    raw?: string;
    enabled?: boolean;
    mode?: string;
    exempt_path_prefixes?: string[];
    log_threshold?: number;
    challenge_threshold?: number;
    block_threshold?: number;
    max_inspect_body?: number;
    stats?: SemanticStats;
};

export default function SemanticPanel() {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [raw, setRaw] = useState("");
    const [serverRaw, setServerRaw] = useState("");
    const [etag, setEtag] = useState<string | null>(null);
    const [valid, setValid] = useState<boolean | null>(null);
    const [messages, setMessages] = useState<string[]>([]);
    const [enabled, setEnabled] = useState<boolean>(false);
    const [mode, setMode] = useState<string>("off");
    const [stats, setStats] = useState<SemanticStats>({});
    const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
    const [error, setError] = useState<string | null>(null);

    const dirty = useMemo(() => raw !== serverRaw, [raw, serverRaw]);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiGetJson<SemanticDTO>("/semantic-rules");
            setRaw(data.raw ?? "");
            setServerRaw(data.raw ?? "");
            setEtag(data.etag ?? null);
            setEnabled(!!data.enabled);
            setMode(data.mode || "off");
            setStats(data.stats || {});
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
                const js = await apiPostJson<{ ok: boolean; messages?: string[]; enabled?: boolean; mode?: string }>(
                    "/semantic-rules:validate",
                    { raw }
                );
                setValid(!!js.ok);
                setMessages(Array.isArray(js.messages) ? js.messages : []);
                setEnabled(!!js.enabled);
                setMode(js.mode || "off");
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
            const js = await apiPutJson<{ ok: boolean; etag?: string; enabled?: boolean; mode?: string }>(
                "/semantic-rules",
                { raw },
                { headers: etag ? { "If-Match": etag } : {} }
            );
            if (!js.ok) {
                throw new Error("Failed to save");
            }
            setEtag(js.etag ?? null);
            setServerRaw(raw);
            setEnabled(!!js.enabled);
            setMode(js.mode || "off");
            setLastSavedAt(Date.now());
        } catch (e: any) {
            setError(e?.message || "Save failed");
        } finally {
            setSaving(false);
        }
    }, [raw, etag]);

    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            const isSave = (e.key === "s" || e.key === "S") && (e.ctrlKey || e.metaKey);
            if (!isSave) return;
            e.preventDefault();
            if (!saving) {
                void doSave();
            }
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [doSave, saving]);

    const statusBadge = useMemo(() => {
        if (loading) return <Badge color="gray">Loading</Badge>;
        if (valid === null) return <Badge color="gray">Unvalidated</Badge>;
        return valid ? <Badge color="green">Valid</Badge> : <Badge color="red">Invalid</Badge>;
    }, [loading, valid]);

    const lineCount = useMemo(() => (raw ? raw.split(/\n/).length : 0), [raw]);

    return (
        <div className="w-full p-4 space-y-4">
            <header className="flex items-center justify-between">
                <h1 className="text-xl font-semibold">Semantic Security</h1>
                <div className="flex items-center gap-2">
                    {statusBadge}
                    {enabled ? <Badge color="green">Enabled</Badge> : <Badge color="gray">Disabled</Badge>}
                    <Badge color="gray">Mode: {mode}</Badge>
                    {dirty && <Badge color="amber">Unsaved</Badge>}
                    {etag && <MonoTag label="ETag" value={etag} />}
                </div>
            </header>

            {error && <Alert kind="error" title="Error" message={error} onClose={() => setError(null)} />}

            <div className="grid gap-3">
                <div className="flex items-center justify-between gap-2">
                    <div className="text-sm text-neutral-500">
                        Heuristic semantic anomaly scoring (`off|log_only|challenge|block`) with thresholds and body inspection limit.
                    </div>
                    <div className="flex items-center gap-2">
                        <button
                            type="button"
                            className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                            onClick={() => setRaw((prev) => (prev ? prev : defaultSemanticExample))}
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
                    className="w-full h-[420px] p-3 border rounded-xl font-mono text-sm leading-5 outline-none focus:ring-2 focus:ring-black/20"
                    value={raw}
                    onChange={(e) => setRaw(e.target.value)}
                    spellCheck={false}
                />

                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5 text-xs">
                    <Stat label="Inspected" value={String(stats.inspected_requests ?? 0)} />
                    <Stat label="Scored" value={String(stats.scored_requests ?? 0)} />
                    <Stat label="Log Only" value={String(stats.log_only_actions ?? 0)} />
                    <Stat label="Challenge" value={String(stats.challenge_actions ?? 0)} />
                    <Stat label="Block" value={String(stats.block_actions ?? 0)} />
                </div>

                <div className="flex items-center justify-between text-xs text-neutral-500">
                    <div className="flex items-center gap-3">
                        <span>Lines: {lineCount}</span>
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
        </div>
    );
}

const defaultSemanticExample = `{
  "enabled": false,
  "mode": "off",
  "exempt_path_prefixes": [],
  "log_threshold": 4,
  "challenge_threshold": 7,
  "block_threshold": 9,
  "max_inspect_body": 16384
}`;

function Badge({ color, children }: { color: "gray" | "green" | "red" | "amber"; children: React.ReactNode }) {
    const cls =
        color === "green" ? "bg-green-100 text-green-800" :
        color === "red" ? "bg-red-100 text-red-800" :
        color === "amber" ? "bg-amber-100 text-amber-800" :
        "bg-neutral-100 text-neutral-700";
    return <span className={`px-2 py-0.5 text-xs rounded ${cls}`}>{children}</span>;
}

function Stat({ label, value }: { label: string; value: string }) {
    return (
        <div className="rounded border bg-white px-2 py-1">
            <div className="text-neutral-500">{label}</div>
            <div className="font-mono">{value}</div>
        </div>
    );
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
            {onClose && <button className="text-xs text-neutral-500 hover:underline" onClick={onClose}>Close</button>}
        </div>
    );
}
