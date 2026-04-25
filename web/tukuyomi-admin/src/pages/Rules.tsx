import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiDeleteJson, apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { ActionResultNotice } from "@/components/EditorChrome";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";
import { parseSavedAt } from "@/lib/savedAt";

type RuleAssetKind = "base" | "bypass_extra_rule";

type RuleFileDTO = {
    path: string;
    kind?: RuleAssetKind;
    position?: number;
    raw?: string;
    etag?: string;
    error?: string;
    saved_at?: string;
    usage?: string;
};

type RulesResp = {
    files?: RuleFileDTO[];
    rules?: Record<string, string>;
};

type RuleEditor = {
    path: string;
    originalPath: string;
    kind: RuleAssetKind;
    originalKind: RuleAssetKind;
    position: number;
    raw: string;
    serverRaw: string;
    etag: string | null;
    usage: string;
    loadError: string | null;
    valid: boolean | null;
    messages: string[];
    lastSavedAt: number | null;
};

type RulesSaveResp = {
    ok: boolean;
    path?: string;
    kind?: RuleAssetKind;
    etag?: string;
    saved_at?: string;
};

const kindOptions: Array<{ value: RuleAssetKind; label: string }> = [
    { value: "base", label: "Base WAF rule set" },
    { value: "bypass_extra_rule", label: "Bypass Rules extra_rule" },
];

function assetKey(kind: RuleAssetKind, path: string) {
    return `${kind}:${path}`;
}

function defaultRuleTemplate(kind: RuleAssetKind) {
    return kind === "bypass_extra_rule" ? "SecRuleEngine On\n" : "SecRuleEngine On\n";
}

export default function Rules() {
    const { locale, tx } = useI18n();
    const { readOnly } = useAdminRuntime();
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selectedKey, setSelectedKey] = useState<string>("");
    const [editors, setEditors] = useState<Record<string, RuleEditor>>({});
    const [newPath, setNewPath] = useState("");
    const [newKind, setNewKind] = useState<RuleAssetKind>("base");

    const load = useCallback(async (preferredKey = "") => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiGetJson<RulesResp>("/rules");
            let files = Array.isArray(data.files) ? data.files : [];
            if (files.length === 0 && data.rules) {
                files = Object.entries(data.rules).map(([path, raw], index) => ({ path, raw, kind: "base", position: index }));
            }

            const next: Record<string, RuleEditor> = {};
            files.forEach((f, index) => {
                const p = f.path || "";
                if (!p) {
                    return;
                }
                const kind = f.kind === "bypass_extra_rule" ? "bypass_extra_rule" : "base";
                const raw = f.raw ?? "";
                next[assetKey(kind, p)] = {
                    path: p,
                    originalPath: p,
                    kind,
                    originalKind: kind,
                    position: Number.isFinite(f.position) ? Number(f.position) : index,
                    raw,
                    serverRaw: raw,
                    etag: f.etag ?? null,
                    usage: f.usage ?? "",
                    loadError: f.error ?? null,
                    valid: null,
                    messages: [],
                    lastSavedAt: parseSavedAt(f.saved_at),
                };
            });
            setEditors(next);
            const first = Object.values(next).sort(compareEditors)[0];
            setSelectedKey((prev) => (preferredKey && next[preferredKey] ? preferredKey : prev && next[prev] ? prev : first ? assetKey(first.kind, first.path) : ""));
        } catch (error: unknown) {
            setError(getErrorMessage(error, tx("Failed to load")));
        } finally {
            setLoading(false);
        }
    }, [tx]);

    useEffect(() => {
        void load();
    }, [load]);

    const editorList = useMemo(() => Object.values(editors).sort(compareEditors), [editors]);
    const active = selectedKey ? editors[selectedKey] : null;
    const activeCurrentKey = active ? assetKey(active.kind, active.path) : "";
    const activeOriginalKey = active && active.originalPath ? assetKey(active.originalKind, active.originalPath) : "";
    const dirty = !!active && (active.raw !== active.serverRaw || active.path !== active.originalPath || active.kind !== active.originalKind);

    const setActive = useCallback((patch: Partial<RuleEditor>) => {
        if (!selectedKey) {
            return;
        }
        setEditors((prev) => {
            const cur = prev[selectedKey];
            if (!cur) {
                return prev;
            }
            return {
                ...prev,
                [selectedKey]: { ...cur, ...patch },
            };
        });
    }, [selectedKey]);

    const activePath = active?.path;
    const activeKind = active?.kind;
    const activeRaw = active?.raw;
    const activeLoadError = active?.loadError;

    const debounceRef = useRef<number | null>(null);
    useEffect(() => {
        if (!activePath || !activeKind || activeRaw == null || loading || activeLoadError) {
            return;
        }
        if (debounceRef.current) {
            window.clearTimeout(debounceRef.current);
        }

        debounceRef.current = window.setTimeout(async () => {
            try {
                const js = await apiPostJson<{ ok: boolean; messages?: string[] }>(
                    "/rules:validate",
                    { path: activePath, kind: activeKind, raw: activeRaw },
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
    }, [activeKind, activeLoadError, activePath, activeRaw, loading, setActive, tx]);

    const doSave = useCallback(async () => {
        if (!active) {
            return;
        }
        setSaving(true);
        setError(null);
        try {
            if (activeOriginalKey && activeOriginalKey !== activeCurrentKey && active.originalKind === "base" && active.kind !== "base") {
                const baseCount = editorList.filter((editor) => editor.originalKind === "base" && editor.originalPath).length;
                if (baseCount <= 1) {
                    throw new Error(tx("At least one base rule asset is required"));
                }
            }
            const js = await apiPutJson<RulesSaveResp>(
                "/rules",
                { path: active.path, kind: active.kind, raw: active.raw },
                { headers: active.etag && activeOriginalKey === activeCurrentKey ? { "If-Match": active.etag } : {} },
            );
            if (!js.ok) {
                throw new Error(tx("Failed to save"));
            }
            const nextKind = js.kind ?? active.kind;
            const nextPath = js.path ?? active.path;
            const nextKey = assetKey(nextKind, nextPath);
            if (activeOriginalKey && activeOriginalKey !== nextKey) {
                await apiDeleteJson(`/rules?path=${encodeURIComponent(active.originalPath)}&kind=${encodeURIComponent(active.originalKind)}`);
            }
            await load(nextKey);
        } catch (error: unknown) {
            setError(getErrorMessage(error, tx("Save failed")));
        } finally {
            setSaving(false);
        }
    }, [active, activeCurrentKey, activeOriginalKey, editorList, load, tx]);

    const doDelete = useCallback(async () => {
        if (!active || !active.originalPath) {
            return;
        }
        if (!window.confirm(tx("Delete this rule asset?"))) {
            return;
        }
        setSaving(true);
        setError(null);
        try {
            await apiDeleteJson(`/rules?path=${encodeURIComponent(active.originalPath)}&kind=${encodeURIComponent(active.originalKind)}`);
            await load();
        } catch (error: unknown) {
            setError(getErrorMessage(error, tx("Delete failed")));
        } finally {
            setSaving(false);
        }
    }, [active, load, tx]);

    const doMove = useCallback(async (delta: number) => {
        if (!active || dirty) {
            return;
        }
        const index = editorList.findIndex((editor) => assetKey(editor.kind, editor.path) === activeCurrentKey);
        const nextIndex = index + delta;
        if (index < 0 || nextIndex < 0 || nextIndex >= editorList.length) {
            return;
        }
        const next = editorList.slice();
        [next[index], next[nextIndex]] = [next[nextIndex], next[index]];
        setSaving(true);
        setError(null);
        try {
            await apiPutJson("/rules:order", { assets: next.map((editor) => ({ path: editor.path, kind: editor.kind })) });
            await load(activeCurrentKey);
        } catch (error: unknown) {
            setError(getErrorMessage(error, tx("Save failed")));
        } finally {
            setSaving(false);
        }
    }, [active, activeCurrentKey, dirty, editorList, load, tx]);

    const addDraft = useCallback(() => {
        const path = newPath.trim();
        if (!path) {
            setError(tx("Path is empty"));
            return;
        }
        const key = assetKey(newKind, path);
        if (editors[key]) {
            setSelectedKey(key);
            return;
        }
        const position = editorList.length;
        setEditors((prev) => ({
            ...prev,
            [key]: {
                path,
                originalPath: "",
                kind: newKind,
                originalKind: newKind,
                position,
                raw: defaultRuleTemplate(newKind),
                serverRaw: "",
                etag: null,
                usage: "",
                loadError: null,
                valid: null,
                messages: [],
                lastSavedAt: null,
            },
        }));
        setSelectedKey(key);
        setNewPath("");
    }, [editorList.length, editors, newKind, newPath, tx]);

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
    if (error && !active) {
        return <div className="text-red-500">{tx("Error")}: {error}</div>;
    }

    return (
        <div className="w-full p-4 space-y-6">
            <section className="space-y-4">
                <header className="flex items-center justify-between gap-3">
                    <div>
                        <h1 className="text-xl font-semibold">{tx("Rules")}</h1>
                        <p className="text-sm text-neutral-500">{tx("Manage DB-backed base WAF assets and Bypass Rules extra_rule assets in load order.")}</p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                        {activeRuleStatus}
                        {dirty && <Badge color="amber">{tx("Unsaved")}</Badge>}
                        {active?.etag && <MonoTag label="ETag" value={active.etag} />}
                    </div>
                </header>

                {error && <div className="border border-red-300 bg-red-50 rounded-xl p-3 text-sm text-red-700">{error}</div>}

                <div className="grid gap-3 xl:grid-cols-[minmax(260px,360px)_1fr]">
                    <aside className="space-y-3">
                        <div className="rounded-xl border border-neutral-200 p-3 space-y-3">
                            <div className="grid gap-2">
                                <label className="text-xs text-neutral-500">{tx("New rule asset")}</label>
                                <select
                                    className="border rounded px-2 py-1 text-sm"
                                    value={newKind}
                                    onChange={(e) => setNewKind(e.target.value as RuleAssetKind)}
                                    disabled={readOnly}
                                >
                                    {kindOptions.map((option) => (
                                        <option key={option.value} value={option.value}>{tx(option.label)}</option>
                                    ))}
                                </select>
                                <input
                                    className="border rounded px-2 py-1 text-sm"
                                    value={newPath}
                                    onChange={(e) => setNewPath(e.target.value)}
                                    placeholder={newKind === "base" ? "custom.conf" : "custom-extra.conf"}
                                    disabled={readOnly}
                                />
                                <button
                                    type="button"
                                    className="px-3 py-1.5 rounded-xl shadow text-sm bg-black text-white disabled:opacity-50"
                                    onClick={addDraft}
                                    disabled={readOnly}
                                >
                                    {tx("Add")}
                                </button>
                            </div>
                        </div>

                        <div className="rounded-xl border border-neutral-200 overflow-hidden">
                            {editorList.length === 0 ? (
                                <div className="p-3 text-sm text-neutral-500">{tx("No rule files configured.")}</div>
                            ) : editorList.map((editor) => {
                                const key = assetKey(editor.kind, editor.path);
                                const selected = key === selectedKey;
                                return (
                                    <button
                                        key={key}
                                        type="button"
                                        className={`w-full text-left px-3 py-2 border-b last:border-b-0 ${selected ? "bg-neutral-900 text-white" : "bg-white hover:bg-neutral-50"}`}
                                        onClick={() => setSelectedKey(key)}
                                    >
                                        <div className="text-sm font-medium truncate">{editor.path}</div>
                                        <div className={`text-xs truncate ${selected ? "text-neutral-300" : "text-neutral-500"}`}>
                                            {tx(wafRuleAssetKindLabel(editor.kind))}
                                        </div>
                                    </button>
                                );
                            })}
                        </div>
                    </aside>

                    {active ? (
                        <main className="space-y-4">
                            <div className="grid gap-3 lg:grid-cols-[minmax(180px,220px)_minmax(220px,1fr)_auto] items-end">
                                <label className="grid gap-1 text-sm">
                                    <span className="text-neutral-600">{tx("Usage")}</span>
                                    <select
                                        className="border rounded px-2 py-1 text-sm"
                                        value={active.kind}
                                        onChange={(e) => setActive({ kind: e.target.value as RuleAssetKind })}
                                        disabled={readOnly}
                                    >
                                        {kindOptions.map((option) => (
                                            <option key={option.value} value={option.value}>{tx(option.label)}</option>
                                        ))}
                                    </select>
                                </label>
                                <label className="grid gap-1 text-sm">
                                    <span className="text-neutral-600">{tx("Rule asset")}</span>
                                    <input
                                        className="border rounded px-2 py-1 text-sm"
                                        value={active.path}
                                        onChange={(e) => setActive({ path: e.target.value })}
                                        disabled={readOnly}
                                    />
                                </label>
                                <div className="flex flex-wrap items-center gap-2">
                                    <button type="button" className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border" onClick={() => void doMove(-1)} disabled={readOnly || saving || dirty}>
                                        {tx("Move up")}
                                    </button>
                                    <button type="button" className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border" onClick={() => void doMove(1)} disabled={readOnly || saving || dirty}>
                                        {tx("Move down")}
                                    </button>
                                </div>
                            </div>

                            <div className="flex flex-wrap items-center gap-2">
                                <button
                                    type="button"
                                    className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                                    onClick={() => void load(activeCurrentKey)}
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
                                <button
                                    type="button"
                                    className="px-3 py-1.5 rounded-xl shadow text-sm border border-red-200 text-red-700 hover:bg-red-50 disabled:opacity-50"
                                    onClick={() => void doDelete()}
                                    disabled={readOnly || saving || !active.originalPath}
                                >
                                    {tx("Delete")}
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
                        </main>
                    ) : (
                        <main className="text-sm text-neutral-500">{tx("No rule files configured.")}</main>
                    )}
                </div>
            </section>
        </div>
    );
}

function compareEditors(a: RuleEditor, b: RuleEditor) {
    if (a.position !== b.position) {
        return a.position - b.position;
    }
    return a.path.localeCompare(b.path);
}

function wafRuleAssetKindLabel(kind: RuleAssetKind) {
    return kind === "bypass_extra_rule" ? "Bypass Rules extra_rule" : "Base WAF rule set";
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
