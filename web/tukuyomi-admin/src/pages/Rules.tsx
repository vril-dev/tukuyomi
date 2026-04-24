import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { ActionResultNotice } from "@/components/EditorChrome";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";
import { parseSavedAt } from "@/lib/savedAt";

type RuleFileDTO = {
    path: string;
    raw?: string;
    etag?: string;
    error?: string;
    saved_at?: string;
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

type RulesSaveResp = {
    ok: boolean;
    etag?: string;
    saved_at?: string;
};

export default function Rules() {
    const { locale, tx } = useI18n();
    const { readOnly } = useAdminRuntime();
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
                    lastSavedAt: parseSavedAt(f.saved_at),
                };
            }
            setEditors(next);
            const first = Object.keys(next)[0] || "";
            setSelectedPath((prev) => (prev && next[prev] ? prev : first));
        } catch (error: unknown) {
            setError(getErrorMessage(error, tx("Failed to load")));
        } finally {
            setLoading(false);
        }
    }, [tx]);

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

    const activePath = active?.path;
    const activeRaw = active?.raw;
    const activeLoadError = active?.loadError;

    const debounceRef = useRef<number | null>(null);
    useEffect(() => {
        if (!activePath || activeRaw == null || loading) {
            return;
        }
        if (activeLoadError) {
            return;
        }
        if (debounceRef.current) {
            window.clearTimeout(debounceRef.current);
        }

        debounceRef.current = window.setTimeout(async () => {
            try {
                const js = await apiPostJson<{ ok: boolean; messages?: string[] }>(
                    "/rules:validate",
                    { path: activePath, raw: activeRaw }
                );
                setActive({
                    valid: !!js.ok,
                    messages: Array.isArray(js.messages) ? js.messages : [],
                });
            } catch (error: unknown) {
                setActive({
                    valid: false,
                    messages: [getErrorMessage(error, tx("Validate failed"))],
                });
            }
        }, 300);

        return () => {
            if (debounceRef.current) {
                window.clearTimeout(debounceRef.current);
            }
        };
    }, [activeLoadError, activePath, activeRaw, loading, setActive, tx]);

    const doSave = useCallback(async () => {
        if (!active) {
            return;
        }
        setSaving(true);
        setError(null);
        try {
            const js = await apiPutJson<RulesSaveResp>(
                "/rules",
                { path: active.path, raw: active.raw },
                { headers: active.etag ? { "If-Match": active.etag } : {} }
            );
            if (!js.ok) {
                throw new Error(tx("Failed to save"));
            }
            setActive({
                etag: js.etag ?? null,
                serverRaw: active.raw,
                lastSavedAt: parseSavedAt(js.saved_at),
            });
        } catch (error: unknown) {
            setError(getErrorMessage(error, tx("Save failed")));
        } finally {
            setSaving(false);
        }
    }, [active, setActive, tx]);

    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            const isSave = (e.key === "s" || e.key === "S") && (e.ctrlKey || e.metaKey);
            if (!isSave) {
                return;
            }
            e.preventDefault();
            if (!saving && !readOnly && dirty) {
                void doSave();
            }
        };

        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [dirty, doSave, readOnly, saving]);

    const activeRuleStatus = useMemo(() => {
        if (loading) {
            return <Badge color="gray">{tx("Loading")}</Badge>;
        }
        if (!active || active.valid === null) {
            return <Badge color="gray">{tx("Unvalidated")}</Badge>;
        }
        return active.valid ? <Badge color="green">{tx("Valid")}</Badge> : <Badge color="red">{tx("Invalid")}</Badge>;
    }, [active, loading, tx]);

    if (loading) {
        return <div className="text-gray-500">{tx("Loading rules...")}</div>;
    }
    if (error) {
        return <div className="text-red-500">{tx("Error")}: {error}</div>;
    }
    if (!active) {
        return <div className="text-gray-500">{tx("No rule files configured.")}</div>;
    }

    return (
        <div className="w-full p-4 space-y-6">
            <section className="space-y-4">
                <header className="flex items-center justify-between">
                    <div>
                        <h1 className="text-xl font-semibold">{tx("Rules")}</h1>
                        <p className="text-sm text-neutral-500">{tx("Edit the DB-backed base WAF rule assets loaded into the active rule set.")}</p>
                    </div>
                    <div className="flex items-center gap-2">
                        {activeRuleStatus}
                        {dirty && <Badge color="amber">{tx("Unsaved")}</Badge>}
                        {active.etag && <MonoTag label="ETag" value={active.etag} />}
                    </div>
                </header>

                <div className="flex items-center gap-2">
                    <label className="text-sm text-neutral-600">{tx("Rule asset")}</label>
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
                        {tx("Refresh")}
                    </button>
                    <button
                        type="button"
                        className="px-3 py-1.5 rounded-xl shadow text-sm bg-black text-white disabled:opacity-50"
                        onClick={() => void doSave()}
                        disabled={readOnly || saving || !dirty || !!active.loadError}
                        title="Ctrl/Cmd+S"
                    >
                        {saving ? tx("Saving...") : tx("Save & hot reload")}
                    </button>
                </div>

                {active.loadError && (
                    <div className="border border-red-300 bg-red-50 rounded-xl p-3 text-sm">
                        {tx("Load failed: {error}", { error: active.loadError })}
                    </div>
                )}

                <ActionResultNotice
                    tone={active.loadError ? "error" : active.valid === false ? "error" : "success"}
                    messages={active.loadError ? [] : active.messages}
                />

                <textarea
                    className="w-full h-[500px] p-3 border rounded-xl font-mono text-sm leading-5 outline-none focus:ring-2 focus:ring-black/20"
                    value={active.raw}
                    onChange={(e) => setActive({ raw: e.target.value })}
                    spellCheck={false}
                    disabled={!!active.loadError}
                />

                <div className="flex items-center justify-between text-xs text-neutral-500">
                    <div className="flex items-center gap-3">
                        <span>{tx("Lines")}: {active.raw ? active.raw.split(/\n/).length : 0}</span>
                        <span>{tx("Chars")}: {active.raw.length}</span>
                        {active.lastSavedAt && <span>{tx("Last saved: {time}", { time: new Date(active.lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") })}</span>}
                    </div>
                </div>
            </section>
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
