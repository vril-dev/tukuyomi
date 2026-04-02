import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";

type RuleFileDTO = {
    path: string;
    raw?: string;
    etag?: string;
    error?: string;
};

type RulesResp = {
    files?: RuleFileDTO[];
    rules?: Record<string, string>;
};

type RuleEditor = {
    path: string;
    raw: string;
    serverRaw: string;
    etag: string | null;
    loadError: string | null;
    valid: boolean | null;
    messages: string[];
    lastSavedAt: number | null;
};

export default function Rules() {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selectedPath, setSelectedPath] = useState<string>("");
    const [editors, setEditors] = useState<Record<string, RuleEditor>>({});

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiGetJson<RulesResp>("/rules");
            let files = Array.isArray(data.files) ? data.files : [];
            if (files.length === 0 && data.rules) {
                files = Object.entries(data.rules).map(([path, raw]) => ({ path, raw }));
            }

            const next: Record<string, RuleEditor> = {};
            for (const f of files) {
                const p = f.path || "";
                if (!p) {
                    continue;
                }
                const raw = f.raw ?? "";
                next[p] = {
                    path: p,
                    raw,
                    serverRaw: raw,
                    etag: f.etag ?? null,
                    loadError: f.error ?? null,
                    valid: null,
                    messages: [],
                    lastSavedAt: null,
                };
            }
            setEditors(next);
            const first = Object.keys(next)[0] || "";
            setSelectedPath((prev) => (prev && next[prev] ? prev : first));
        } catch (e: any) {
            setError(e?.message || String(e));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        void load();
    }, [load]);

    const paths = useMemo(() => Object.keys(editors), [editors]);
    const active = selectedPath ? editors[selectedPath] : null;
    const dirty = !!active && active.raw !== active.serverRaw;

    const setActive = useCallback((patch: Partial<RuleEditor>) => {
        if (!selectedPath) {
            return;
        }
        setEditors((prev) => {
            const cur = prev[selectedPath];
            if (!cur) {
                return prev;
            }
            return {
                ...prev,
                [selectedPath]: { ...cur, ...patch },
            };
        });
    }, [selectedPath]);

    const debounceRef = useRef<number | null>(null);
    useEffect(() => {
        if (!active || loading) {
            return;
        }
        if (active.loadError) {
            return;
        }
        if (debounceRef.current) {
            window.clearTimeout(debounceRef.current);
        }

        debounceRef.current = window.setTimeout(async () => {
            try {
                const js = await apiPostJson<{ ok: boolean; messages?: string[] }>(
                    "/rules:validate",
                    { path: active.path, raw: active.raw }
                );
                setActive({
                    valid: !!js.ok,
                    messages: Array.isArray(js.messages) ? js.messages : [],
                });
            } catch (e: any) {
                setActive({
                    valid: false,
                    messages: [e?.message || "Validate failed"],
                });
            }
        }, 300);

        return () => {
            if (debounceRef.current) {
                window.clearTimeout(debounceRef.current);
            }
        };
    }, [active?.path, active?.raw, active?.loadError, loading, setActive]);

    const doSave = useCallback(async () => {
        if (!active) {
            return;
        }
        setSaving(true);
        setError(null);
        try {
            const js = await apiPutJson<{ ok: boolean; etag?: string }>(
                "/rules",
                { path: active.path, raw: active.raw },
                { headers: active.etag ? { "If-Match": active.etag } : {} }
            );
            if (!js.ok) {
                throw new Error("Failed to save");
            }
            setActive({
                etag: js.etag ?? null,
                serverRaw: active.raw,
                lastSavedAt: Date.now(),
            });
        } catch (e: any) {
            setError(e?.message || "Save failed");
        } finally {
            setSaving(false);
        }
    }, [active, setActive]);

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

    if (loading) {
        return <div className="text-gray-500">Loading rules...</div>;
    }
    if (error) {
        return <div className="text-red-500">Error: {error}</div>;
    }
    if (!active) {
        return <div className="text-gray-500">No rule files configured.</div>;
    }

    return (
        <div className="w-full p-4 space-y-4">
            <header className="flex items-center justify-between">
                <h1 className="text-xl font-semibold">Rules</h1>
                <div className="flex items-center gap-2">
                    {active.valid === null ? <Badge color="gray">Unvalidated</Badge> : active.valid ? <Badge color="green">Valid</Badge> : <Badge color="red">Invalid</Badge>}
                    {dirty && <Badge color="amber">Unsaved</Badge>}
                    {active.etag && <MonoTag label="ETag" value={active.etag} />}
                </div>
            </header>

            <div className="flex items-center gap-2">
                <label className="text-sm text-neutral-600">Edit target</label>
                <select
                    className="border rounded px-2 py-1 text-sm min-w-[360px]"
                    value={selectedPath}
                    onChange={(e) => setSelectedPath(e.target.value)}
                >
                    {paths.map((p) => (
                        <option key={p} value={p}>{p}</option>
                    ))}
                </select>
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
                    disabled={saving || !dirty || !!active.loadError}
                    title="Ctrl/Cmd+S"
                >
                    {saving ? "Saving..." : "Save & hot reload"}
                </button>
            </div>

            {active.loadError && (
                <div className="border border-red-300 bg-red-50 rounded-xl p-3 text-sm">
                    Load failed: {active.loadError}
                </div>
            )}

            <textarea
                className="w-full h-[500px] p-3 border rounded-xl font-mono text-sm leading-5 outline-none focus:ring-2 focus:ring-black/20"
                value={active.raw}
                onChange={(e) => setActive({ raw: e.target.value })}
                spellCheck={false}
                disabled={!!active.loadError}
            />

            <div className="flex items-center justify-between text-xs text-neutral-500">
                <div className="flex items-center gap-3">
                    <span>Lines: {active.raw ? active.raw.split(/\n/).length : 0}</span>
                    <span>Chars: {active.raw.length}</span>
                    {active.lastSavedAt && <span>Last saved: {new Date(active.lastSavedAt).toLocaleString()}</span>}
                </div>
                <div className="flex items-center gap-2">
                    {active.messages.slice(0, 3).map((m, i) => (
                        <span key={i} className="px-2 py-0.5 bg-neutral-100 rounded">{m}</span>
                    ))}
                </div>
            </div>
        </div>
    );
}

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
