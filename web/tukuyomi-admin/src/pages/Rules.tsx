import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiDeleteJson, apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { ActionResultNotice } from "@/components/EditorChrome";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";
import { parseSavedAt } from "@/lib/savedAt";
import { revisionTagParts } from "@/lib/revision";

type RuleAssetKind = "base" | "crs_setup" | "crs_asset" | "bypass_extra_rule";

type RuleFileDTO = {
    name?: string;
    path: string;
    kind?: RuleAssetKind;
    position?: number;
    raw?: string;
    etag?: string;
    error?: string;
    saved_at?: string;
    usage?: string;
    order_group?: string;
    group_position?: number;
    editable?: boolean;
    toggleable?: boolean;
    enabled?: boolean;
    runtime_loaded?: boolean;
    advanced?: boolean;
    reference_count?: number;
    referenced_by?: string[];
};

type RulesResp = {
    files?: RuleFileDTO[];
    runtime_files?: RuleFileDTO[];
    rules?: Record<string, string>;
};

type CRSRuleSetsResp = {
    crs_enabled?: boolean;
    etag?: string;
    rules?: Array<{
        name: string;
        path: string;
        enabled: boolean;
    }>;
};

type RuleEditor = {
    name: string;
    path: string;
    originalPath: string;
    kind: RuleAssetKind;
    originalKind: RuleAssetKind;
    position: number;
    raw: string;
    serverRaw: string;
    etag: string | null;
    usage: string;
    orderGroup: string;
    editable: boolean;
    toggleable: boolean;
    enabled: boolean;
    serverEnabled: boolean;
    runtimeLoaded: boolean;
    advanced: boolean;
    referenceCount: number;
    referencedBy: string[];
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
    enabled?: boolean;
    saved_at?: string;
};

const createKindOptions: Array<{ value: RuleAssetKind; label: string }> = [
    { value: "base", label: "Base rule" },
    { value: "bypass_extra_rule", label: "Bypass rule" },
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
    const [crsEtag, setCrsEtag] = useState<string | null>(null);
    const [crsEnabled, setCrsEnabled] = useState(true);
    const [serverCRSEnabled, setServerCRSEnabled] = useState<Set<string>>(new Set());
    const [crsValid, setCrsValid] = useState<boolean | null>(null);
    const [crsMessages, setCrsMessages] = useState<string[]>([]);
    const [newKind, setNewKind] = useState<RuleAssetKind>("base");
    const [newPath, setNewPath] = useState("");
    const [newEnabled, setNewEnabled] = useState(false);

    const load = useCallback(async (preferredKey = "") => {
        setLoading(true);
        setError(null);
        try {
            const [data, crsData] = await Promise.all([
                apiGetJson<RulesResp>("/rules?runtime=1"),
                apiGetJson<CRSRuleSetsResp>("/crs-rule-sets"),
            ]);
            let runtimeFiles = Array.isArray(data.runtime_files) ? data.runtime_files : [];
            let editableFiles = Array.isArray(data.files) ? data.files : [];
            if (runtimeFiles.length === 0) {
                runtimeFiles = editableFiles.filter((file) => file.kind !== "bypass_extra_rule");
            }
            if (runtimeFiles.length === 0 && data.rules) {
                runtimeFiles = Object.entries(data.rules).map(([path, raw], index) => ({ path, raw, kind: "base", position: index }));
            }
            if (editableFiles.length === 0 && data.rules) {
                editableFiles = Object.entries(data.rules).map(([path, raw], index) => ({ path, raw, kind: "base", position: index }));
            }

            const next: Record<string, RuleEditor> = {};
            const appendFile = (f: RuleFileDTO, index: number) => {
                const p = f.path || "";
                if (!p) {
                    return;
                }
                const kind = normalizeRuleAssetKind(f.kind);
                const raw = f.raw ?? "";
                const enabled = typeof f.enabled === "boolean" ? f.enabled : true;
                next[assetKey(kind, p)] = {
                    name: typeof f.name === "string" && f.name.trim() ? f.name : p.split("/").pop() ?? p,
                    path: p,
                    originalPath: p,
                    kind,
                    originalKind: kind,
                    position: Number.isFinite(f.group_position) ? Number(f.group_position) : Number.isFinite(f.position) ? Number(f.position) : index,
                    raw,
                    serverRaw: raw,
                    etag: f.etag ?? null,
                    usage: f.usage ?? "",
                    orderGroup: f.order_group ?? defaultOrderGroup(kind),
                    editable: typeof f.editable === "boolean" ? f.editable : kind === "base" || kind === "bypass_extra_rule",
                    toggleable: typeof f.toggleable === "boolean" ? f.toggleable : kind === "base" || kind === "crs_asset",
                    enabled,
                    serverEnabled: enabled,
                    runtimeLoaded: typeof f.runtime_loaded === "boolean" ? f.runtime_loaded : enabled && (kind === "base" || kind === "crs_setup" || kind === "crs_asset"),
                    advanced: typeof f.advanced === "boolean" ? f.advanced : kind === "bypass_extra_rule",
                    referenceCount: Number.isFinite(f.reference_count) ? Number(f.reference_count) : 0,
                    referencedBy: Array.isArray(f.referenced_by) ? f.referenced_by.filter((item): item is string => typeof item === "string") : [],
                    loadError: f.error ?? null,
                    valid: null,
                    messages: [],
                    lastSavedAt: parseSavedAt(f.saved_at),
                };
            };
            runtimeFiles.forEach(appendFile);
            editableFiles
                .filter((file) => file.kind === "bypass_extra_rule")
                .forEach((file, index) => appendFile(file, runtimeFiles.length + index));
            const crsServer = new Set(
                Object.values(next)
                    .filter((editor) => editor.kind === "crs_asset" && editor.enabled)
                    .map((editor) => editor.name),
            );
            setCrsEtag(crsData.etag ?? null);
            setCrsEnabled(crsData.crs_enabled !== false);
            setServerCRSEnabled(crsServer);
            setCrsValid(null);
            setCrsMessages([]);
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
    const corazaEditors = useMemo(() => editorList.filter((editor) => editor.kind === "crs_setup" || editor.kind === "crs_asset"), [editorList]);
    const baseEditors = useMemo(() => editorList.filter((editor) => editor.kind === "base"), [editorList]);
    const snippetEditors = useMemo(() => editorList.filter((editor) => editor.kind === "bypass_extra_rule"), [editorList]);
    const active = selectedKey ? editors[selectedKey] : null;
    const activeCurrentKey = active ? assetKey(active.kind, active.path) : "";
    const activeOriginalKey = active && active.originalPath ? assetKey(active.originalKind, active.originalPath) : "";
    const activeDirty = !!active && active.editable && (
        active.raw !== active.serverRaw
        || active.path !== active.originalPath
        || active.kind !== active.originalKind
        || (active.kind === "base" && active.enabled !== active.serverEnabled)
    );
    const crsEnabledNames = useMemo(
        () => corazaEditors
            .filter((editor) => editor.kind === "crs_asset" && editor.enabled)
            .map((editor) => editor.name)
            .sort(),
        [corazaEditors],
    );
    const crsDirty = useMemo(() => {
        if (crsEnabledNames.length !== serverCRSEnabled.size) {
            return true;
        }
        for (const name of crsEnabledNames) {
            if (!serverCRSEnabled.has(name)) {
                return true;
            }
        }
        return false;
    }, [crsEnabledNames, serverCRSEnabled]);
    const dirty = activeDirty || crsDirty;

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
    const activeEditable = !!active?.editable;

    const debounceRef = useRef<number | null>(null);
    useEffect(() => {
        if (!activePath || !activeKind || activeRaw == null || loading || activeLoadError || !activeEditable || !isEditableRuleAssetKind(activeKind)) {
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
    }, [activeEditable, activeKind, activeLoadError, activePath, activeRaw, loading, setActive, tx]);

    const crsDebounceRef = useRef<number | null>(null);
    useEffect(() => {
        if (loading || !crsDirty || !crsEnabled) {
            return;
        }
        if (crsDebounceRef.current) {
            window.clearTimeout(crsDebounceRef.current);
        }
        crsDebounceRef.current = window.setTimeout(async () => {
            try {
                const js = await apiPostJson<{ ok: boolean; messages?: string[] }>(
                    "/crs-rule-sets:validate",
                    { enabled: crsEnabledNames },
                );
                setCrsValid(!!js.ok);
                setCrsMessages(Array.isArray(js.messages) ? js.messages : []);
            } catch (error: unknown) {
                setCrsValid(false);
                setCrsMessages([getErrorMessage(error, tx("Validate failed"))]);
            }
        }, 300);
        return () => {
            if (crsDebounceRef.current) {
                window.clearTimeout(crsDebounceRef.current);
            }
        };
    }, [crsDirty, crsEnabled, crsEnabledNames, loading, tx]);

    const doSave = useCallback(async () => {
        if (!active || !active.editable || !isEditableRuleAssetKind(active.kind)) {
            return;
        }
        setSaving(true);
        setError(null);
        try {
            const payload: { path: string; kind: RuleAssetKind; raw: string; enabled?: boolean } = {
                path: active.path,
                kind: active.kind,
                raw: active.raw,
            };
            if (active.kind === "base") {
                payload.enabled = active.enabled;
            }
            const js = await apiPutJson<RulesSaveResp>(
                "/rules",
                payload,
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
    }, [active, activeCurrentKey, activeOriginalKey, load, tx]);

    const doSaveCRS = useCallback(async () => {
        setSaving(true);
        setError(null);
        try {
            const js = await apiPutJson<{ ok: boolean; etag?: string }>(
                "/crs-rule-sets",
                { enabled: crsEnabledNames },
                { headers: crsEtag ? { "If-Match": crsEtag } : {} },
            );
            if (!js.ok) {
                throw new Error(tx("Failed to save"));
            }
            setCrsEtag(js.etag ?? null);
            setServerCRSEnabled(new Set(crsEnabledNames));
            setCrsValid(null);
            setCrsMessages([]);
            await load(activeCurrentKey);
        } catch (error: unknown) {
            setError(getErrorMessage(error, tx("Save failed")));
        } finally {
            setSaving(false);
        }
    }, [activeCurrentKey, crsEnabledNames, crsEtag, load, tx]);

    const doDelete = useCallback(async () => {
        if (!active || !active.originalPath || !active.editable || !isEditableRuleAssetKind(active.kind)) {
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

    const toggleCRSAsset = useCallback((path: string, enabled: boolean) => {
        setEditors((prev) => {
            const key = assetKey("crs_asset", path);
            const cur = prev[key];
            if (!cur || !cur.toggleable) {
                return prev;
            }
            return {
                ...prev,
                [key]: { ...cur, enabled, runtimeLoaded: enabled },
            };
        });
    }, []);

    const toggleBaseAsset = useCallback((path: string, enabled: boolean) => {
        setEditors((prev) => {
            const key = assetKey("base", path);
            const cur = prev[key];
            if (!cur || !cur.toggleable) {
                return prev;
            }
            return {
                ...prev,
                [key]: { ...cur, enabled, runtimeLoaded: enabled },
            };
        });
    }, []);

    const setAllCRSAssets = useCallback((enabled: boolean) => {
        setEditors((prev) => {
            let changed = false;
            const next: Record<string, RuleEditor> = {};
            for (const [key, editor] of Object.entries(prev)) {
                if (editor.kind === "crs_asset" && editor.toggleable && editor.enabled !== enabled) {
                    next[key] = { ...editor, enabled, runtimeLoaded: enabled };
                    changed = true;
                } else {
                    next[key] = editor;
                }
            }
            return changed ? next : prev;
        });
    }, []);

    const doMove = useCallback(async (delta: number) => {
        if (!active || active.kind !== "base" || dirty) {
            return;
        }
        const index = baseEditors.findIndex((editor) => assetKey(editor.kind, editor.path) === activeCurrentKey);
        const nextIndex = index + delta;
        if (index < 0 || nextIndex < 0 || nextIndex >= baseEditors.length) {
            return;
        }
        const next = baseEditors.slice();
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
    }, [active, activeCurrentKey, baseEditors, dirty, load, tx]);

    const addDraft = useCallback((kind: RuleAssetKind, rawPath: string, enabled: boolean) => {
        const path = rawPath.trim();
        if (!path) {
            setError(tx("Path is empty"));
            return false;
        }
        const key = assetKey(kind, path);
        if (editors[key]) {
            setSelectedKey(key);
            return false;
        }
        const position = kind === "base" ? baseEditors.length : snippetEditors.length;
        setEditors((prev) => ({
            ...prev,
            [key]: {
                name: path.split("/").pop() ?? path,
                path,
                originalPath: "",
                kind,
                originalKind: kind,
                position,
                raw: defaultRuleTemplate(kind),
                serverRaw: "",
                etag: null,
                usage: "",
                orderGroup: kind === "base" ? "base_load_order" : "bypass_snippet",
                editable: true,
                toggleable: kind === "base",
                enabled: kind === "base" ? enabled : true,
                serverEnabled: kind === "base" ? enabled : true,
                runtimeLoaded: kind === "base" ? enabled : false,
                advanced: kind === "bypass_extra_rule",
                referenceCount: 0,
                referencedBy: [],
                loadError: null,
                valid: null,
                messages: [],
                lastSavedAt: null,
            },
        }));
        setSelectedKey(key);
        return true;
    }, [baseEditors.length, editors, snippetEditors.length, tx]);

    const addRuleDraft = useCallback(() => {
        if (addDraft(newKind, newPath, newEnabled)) {
            setNewPath("");
            setNewEnabled(false);
        }
    }, [addDraft, newEnabled, newKind, newPath]);

    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            const isSave = (e.key === "s" || e.key === "S") && (e.ctrlKey || e.metaKey);
            if (!isSave) {
                return;
            }
            e.preventDefault();
            if (saving || readOnly) {
                return;
            }
            if (crsDirty) {
                void doSaveCRS();
            } else if (activeDirty) {
                void doSave();
            }
        };

        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [activeDirty, crsDirty, doSave, doSaveCRS, readOnly, saving]);

    const activeRuleStatus = useMemo(() => {
        if (loading) {
            return <Badge color="gray">{tx("Loading")}</Badge>;
        }
        if (active?.kind === "crs_setup") {
            return <Badge color="green">{tx("Loaded")}</Badge>;
        }
        if (active?.kind === "crs_asset") {
            return active.enabled ? <Badge color="green">{tx("Enabled")}</Badge> : <Badge color="gray">{tx("Disabled")}</Badge>;
        }
        if (active?.kind === "base" && !active.enabled) {
            return <Badge color="gray">{tx("Disabled")}</Badge>;
        }
        if (!active || active.valid === null) {
            return <Badge color="gray">{tx("Unvalidated")}</Badge>;
        }
        return active.valid ? <Badge color="green">{tx("Valid")}</Badge> : <Badge color="red">{tx("Invalid")}</Badge>;
    }, [active, loading, tx]);
    const activePathLocked = !!active && (!active.editable || (active.kind === "bypass_extra_rule" && active.referenceCount > 0 && !!active.originalPath));
    const activeDeleteDisabled = readOnly || saving || !active?.originalPath || !active?.editable || (!!active && active.kind === "bypass_extra_rule" && active.referenceCount > 0);

    const renderRuleListItem = useCallback((editor: RuleEditor) => {
        const key = assetKey(editor.kind, editor.path);
        const selected = key === selectedKey;
        return (
            <div
                key={key}
                role="button"
                tabIndex={0}
                className={`w-full text-left px-3 py-2 border-b border-[#e5e7eb] last:border-b-0 cursor-pointer ${selected ? "bg-neutral-900 text-white" : "bg-white hover:bg-neutral-50"}`}
                onClick={() => setSelectedKey(key)}
                onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedKey(key);
                    }
                }}
            >
                <div className="flex items-center gap-2">
                    {(editor.kind === "base" || editor.kind === "crs_asset") && (
                        <input
                            type="checkbox"
                            checked={editor.enabled}
                            onClick={(event) => event.stopPropagation()}
                            onChange={(event) => {
                                if (editor.kind === "base") {
                                    setSelectedKey(key);
                                    toggleBaseAsset(editor.path, event.target.checked);
                                    return;
                                }
                                toggleCRSAsset(editor.path, event.target.checked);
                            }}
                            disabled={readOnly || saving || (editor.kind === "crs_asset" && !crsEnabled)}
                        />
                    )}
                    {editor.kind === "crs_setup" && (
                        <span className={`px-1.5 py-0.5 rounded text-[10px] ${selected ? "bg-white/15 text-neutral-100" : "bg-neutral-100 text-neutral-600"}`}>
                            {tx("setup")}
                        </span>
                    )}
                    <div className="min-w-0 flex-1 text-xs font-medium truncate">{editor.kind === "crs_asset" ? editor.name : editor.path}</div>
                </div>
            </div>
        );
    }, [crsEnabled, readOnly, saving, selectedKey, toggleBaseAsset, toggleCRSAsset, tx]);

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
                        <p className="text-xs text-neutral-500">{tx("Manage Coraza CRS and base WAF rule assets in runtime load order.")}</p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                        {activeRuleStatus}
                        {dirty && <Badge color="amber">{tx("Unsaved")}</Badge>}
                        {active?.etag && <MonoTag label="ETag" value={active.etag} />}
                    </div>
                </header>

                {error && <div className="border border-red-300 bg-red-50 rounded-xl p-3 text-xs text-red-700">{error}</div>}

                <div className="grid gap-3 xl:grid-cols-[minmax(260px,360px)_1fr]">
                    <aside className="space-y-3">
                        <div className="rounded-xl border border-[#e5e7eb] p-3 space-y-3">
                            <div className="grid gap-2">
                                <label className="text-xs text-neutral-500">{tx("New rule asset")}</label>
                                <select
                                    className="border border-[#e5e7eb] rounded px-2 py-1 text-xs bg-white"
                                    value={newKind}
                                    onChange={(e) => setNewKind(e.target.value as RuleAssetKind)}
                                    disabled={readOnly}
                                >
                                    {createKindOptions.map((option) => (
                                        <option key={option.value} value={option.value}>{tx(option.label)}</option>
                                    ))}
                                </select>
                                <input
                                    className="border border-[#e5e7eb] rounded px-2 py-1 text-xs"
                                    value={newPath}
                                    onChange={(e) => setNewPath(e.target.value)}
                                    placeholder={newKind === "base" ? "custom.conf" : "custom-extra.conf"}
                                    disabled={readOnly}
                                />
                                {newKind === "base" && (
                                    <label className="flex items-center gap-2 text-xs text-neutral-700">
                                        <input
                                            type="checkbox"
                                            checked={newEnabled}
                                            onChange={(event) => setNewEnabled(event.target.checked)}
                                            disabled={readOnly}
                                        />
                                        <span>{tx("Enable on save")}</span>
                                    </label>
                                )}
                                <button
                                    type="button"
                                    className="px-3 py-1.5 rounded-xl shadow text-xs bg-black text-white disabled:opacity-50"
                                    onClick={addRuleDraft}
                                    disabled={readOnly}
                                >
                                    {tx("Add")}
                                </button>
                            </div>
                        </div>

                        <details className="rounded-xl border border-[#e5e7eb] overflow-hidden" open>
                            <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-neutral-500 bg-neutral-50 border-b border-[#e5e7eb]">
                                {tx("Base WAF rules")} · {baseEditors.length}
                            </summary>
                            <div className="max-h-[520px] overflow-y-auto">
                                {baseEditors.length === 0 ? (
                                    <div className="p-3 text-xs text-neutral-500">{tx("No rule files configured.")}</div>
                                ) : baseEditors.map(renderRuleListItem)}
                            </div>
                        </details>

                        <details
                            className="rounded-xl border border-[#e5e7eb] overflow-hidden"
                            open={snippetEditors.length > 0 || active?.kind === "bypass_extra_rule"}
                        >
                            <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-neutral-500 bg-neutral-50 border-b border-[#e5e7eb]">
                                {tx("Advanced")} · {tx("Bypass snippets")} · {snippetEditors.length}
                            </summary>
                            {snippetEditors.length === 0 ? (
                                <div className="p-3 text-xs text-neutral-500">{tx("No bypass snippets configured.")}</div>
                            ) : snippetEditors.map((editor) => {
                                const key = assetKey(editor.kind, editor.path);
                                const selected = key === selectedKey;
                                return (
                                    <button
                                        key={key}
                                        type="button"
                                        className={`w-full text-left px-3 py-2 border-b border-[#e5e7eb] last:border-b-0 ${selected ? "bg-neutral-900 text-white" : "bg-white hover:bg-neutral-50"}`}
                                        onClick={() => setSelectedKey(key)}
                                    >
                                        <div className="flex items-center justify-between gap-2">
                                            <span className="text-xs font-medium truncate">{editor.path}</span>
                                            <span className={`text-xs shrink-0 ${selected ? "text-neutral-300" : "text-neutral-500"}`}>
                                                {tx("{count} refs", { count: editor.referenceCount })}
                                            </span>
                                        </div>
                                    </button>
                                );
                            })}
                        </details>

                        <details className="rounded-xl border border-[#e5e7eb] overflow-hidden" open={active?.kind === "crs_setup" || active?.kind === "crs_asset"}>
                            <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-neutral-500 bg-neutral-50 border-b border-[#e5e7eb]">
                                {tx("Coraza CRS rules")} · {corazaEditors.length}
                            </summary>
                            {corazaEditors.length > 0 && (
                                <div className="p-3 border-b border-[#e5e7eb] bg-white">
                                    <div className="flex flex-wrap items-center gap-2">
                                        <button
                                            type="button"
                                            className="px-3 py-1.5 rounded-xl shadow text-xs hover:bg-neutral-50 border border-[#e5e7eb]"
                                            onClick={() => setAllCRSAssets(true)}
                                            disabled={readOnly || saving || !crsEnabled}
                                        >
                                            {tx("Enable all CRS")}
                                        </button>
                                        <button
                                            type="button"
                                            className="px-3 py-1.5 rounded-xl shadow text-xs hover:bg-neutral-50 border border-[#e5e7eb]"
                                            onClick={() => setAllCRSAssets(false)}
                                            disabled={readOnly || saving || !crsEnabled}
                                        >
                                            {tx("Disable all CRS")}
                                        </button>
                                        <button
                                            type="button"
                                            className="px-3 py-1.5 rounded-xl shadow text-xs bg-black text-white disabled:opacity-50"
                                            onClick={() => void doSaveCRS()}
                                            disabled={readOnly || saving || !crsDirty || !crsEnabled}
                                        >
                                            {saving ? tx("Saving...") : tx("Save CRS")}
                                        </button>
                                    </div>
                                </div>
                            )}
                            <div className="max-h-[520px] overflow-y-auto">
                                {corazaEditors.length === 0 ? (
                                    <div className="p-3 text-xs text-neutral-500">{tx("No rule files configured.")}</div>
                                ) : corazaEditors.map(renderRuleListItem)}
                            </div>
                        </details>
                    </aside>

                    {active ? (
                        <main className="space-y-4">
                            <div className="grid gap-3 lg:grid-cols-[minmax(180px,220px)_minmax(220px,1fr)_auto] items-end">
                                <div className="grid gap-1 text-xs">
                                    <span className="text-neutral-600">{tx("Usage")}</span>
                                    <div className="min-h-8 border border-[#e5e7eb] rounded px-2 py-1 text-xs bg-neutral-50 flex items-center">
                                        {tx(wafRuleAssetKindLabel(active.kind))}
                                    </div>
                                </div>
                                <label className="grid gap-1 text-xs">
                                    <span className="text-neutral-600">{tx("Rule asset")}</span>
                                    <input
                                        className="border border-[#e5e7eb] rounded px-2 py-1 text-xs"
                                        value={active.path}
                                        onChange={(e) => setActive({ path: e.target.value })}
                                        disabled={readOnly || activePathLocked}
                                    />
                                </label>
                                {active.kind === "base" ? (
                                    <div className="flex flex-wrap items-center gap-2">
                                        <label className="flex items-center gap-2 text-xs h-8 mr-1">
                                            <input
                                                type="checkbox"
                                                checked={active.enabled}
                                                onChange={(event) => toggleBaseAsset(active.path, event.target.checked)}
                                                disabled={readOnly || saving}
                                            />
                                            <span>{tx("Enabled")}</span>
                                        </label>
                                        <button type="button" className="px-3 py-1.5 rounded-xl shadow text-xs hover:bg-neutral-50 border border-[#e5e7eb]" onClick={() => void doMove(-1)} disabled={readOnly || saving || dirty}>
                                            {tx("Move up")}
                                        </button>
                                        <button type="button" className="px-3 py-1.5 rounded-xl shadow text-xs hover:bg-neutral-50 border border-[#e5e7eb]" onClick={() => void doMove(1)} disabled={readOnly || saving || dirty}>
                                            {tx("Move down")}
                                        </button>
                                    </div>
                                ) : active.kind === "bypass_extra_rule" ? (
                                    <div className="flex flex-wrap items-end gap-2">
                                        <Badge color={active.referenceCount > 0 ? "green" : "gray"}>
                                            {active.referenceCount > 0 ? tx("{count} refs", { count: active.referenceCount }) : tx("Not referenced")}
                                        </Badge>
                                    </div>
                                ) : active.kind === "crs_asset" ? (
                                    <label className="flex items-center gap-2 text-xs h-8">
                                        <input
                                            type="checkbox"
                                            checked={active.enabled}
                                            onChange={(event) => toggleCRSAsset(active.path, event.target.checked)}
                                            disabled={readOnly || saving || !crsEnabled}
                                        />
                                        <span>{tx("Enabled")}</span>
                                    </label>
                                ) : (
                                    <div className="flex flex-wrap items-end gap-2">
                                        <Badge color="green">{tx("CRS setup")}</Badge>
                                    </div>
                                )}
                            </div>

                            {active.kind === "bypass_extra_rule" && active.referencedBy.length > 0 && (
                                <div className="rounded-xl border border-[#e5e7eb] p-3 text-xs">
                                    <div className="text-xs font-semibold text-neutral-500 mb-2">{tx("Referenced by")}</div>
                                    <div className="flex flex-wrap gap-2">
                                        {active.referencedBy.map((path) => (
                                            <code key={path} className="px-2 py-1 bg-neutral-100 rounded text-xs">{path}</code>
                                        ))}
                                    </div>
                                </div>
                            )}

                            <div className="flex flex-wrap items-center gap-2">
                                <button
                                    type="button"
                                    className="px-3 py-1.5 rounded-xl shadow text-xs hover:bg-neutral-50 border border-[#e5e7eb]"
                                    onClick={() => void load(activeCurrentKey)}
                                    disabled={loading}
                                >
                                    {tx("Refresh")}
                                </button>
                                <button
                                    type="button"
                                    className="px-3 py-1.5 rounded-xl shadow text-xs bg-black text-white disabled:opacity-50"
                                    onClick={() => {
                                        if (active.kind === "crs_asset") {
                                            void doSaveCRS();
                                            return;
                                        }
                                        void doSave();
                                    }}
                                    disabled={readOnly || saving || !!active.loadError || (active.kind === "crs_asset" ? !crsDirty || !crsEnabled : !activeDirty || !active.editable)}
                                    title="Ctrl/Cmd+S"
                                >
                                    {saving ? tx("Saving...") : active.kind === "base" || active.kind === "crs_asset" ? tx("Save & hot reload") : tx("Save")}
                                </button>
                                {active.editable && (
                                    <button
                                        type="button"
                                        className="px-3 py-1.5 rounded-xl shadow text-xs border border-red-200 text-red-700 hover:bg-red-50 disabled:opacity-50"
                                        onClick={() => void doDelete()}
                                        disabled={activeDeleteDisabled}
                                    >
                                        {tx("Delete")}
                                    </button>
                                )}
                            </div>

                            {active.loadError && (
                                <div className="border border-red-300 bg-red-50 rounded-xl p-3 text-xs">
                                    {tx("Load failed: {error}", { error: active.loadError })}
                                </div>
                            )}

                            <ActionResultNotice
                                tone={active.loadError ? "error" : active.kind === "crs_asset" && crsValid === false ? "error" : active.valid === false ? "error" : "success"}
                                messages={active.loadError ? [] : active.kind === "crs_asset" ? crsMessages : active.messages}
                            />

                            <textarea
                                className="w-full h-[500px] p-3 border border-[#e5e7eb] rounded-xl font-mono text-xs leading-5 outline-none focus:ring-2 focus:ring-black/20"
                                value={active.raw}
                                onChange={(e) => setActive({ raw: e.target.value })}
                                spellCheck={false}
                                disabled={readOnly || !active.editable || !!active.loadError}
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
                        <main className="text-xs text-neutral-500">{tx("No rule files configured.")}</main>
                    )}
                </div>
            </section>
        </div>
    );
}

function compareEditors(a: RuleEditor, b: RuleEditor) {
    const groupA = editorSortGroup(a.kind);
    const groupB = editorSortGroup(b.kind);
    if (groupA !== groupB) {
        return groupA - groupB;
    }
    if (a.position !== b.position) {
        return a.position - b.position;
    }
    return a.path.localeCompare(b.path);
}

function editorSortGroup(kind: RuleAssetKind) {
    if (kind === "base") {
        return 0;
    }
    if (kind === "bypass_extra_rule") {
        return 1;
    }
    return 2;
}

function wafRuleAssetKindLabel(kind: RuleAssetKind) {
    switch (kind) {
        case "crs_setup":
            return "Coraza CRS setup";
        case "crs_asset":
            return "Coraza CRS rule";
        case "bypass_extra_rule":
            return "Bypass rule snippet";
        default:
            return "Base WAF rule set";
    }
}

function normalizeRuleAssetKind(kind: RuleAssetKind | undefined): RuleAssetKind {
    switch (kind) {
        case "crs_setup":
        case "crs_asset":
        case "bypass_extra_rule":
            return kind;
        default:
            return "base";
    }
}

function defaultOrderGroup(kind: RuleAssetKind) {
    if (kind === "crs_setup" || kind === "crs_asset") {
        return "coraza_load_order";
    }
    if (kind === "bypass_extra_rule") {
        return "bypass_snippet";
    }
    return "base_load_order";
}

function isEditableRuleAssetKind(kind: RuleAssetKind) {
    return kind === "base" || kind === "bypass_extra_rule";
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
    const tag = revisionTagParts(label, value);
    return (
        <div className="hidden md:flex items-center gap-1 text-xs">
            <span className="text-neutral-500">{tag.label}:</span>
            <code className="px-2 py-0.5 bg-neutral-100 rounded max-w-[420px] truncate" title={tag.title}>
                {tag.value}
            </code>
        </div>
    );
}
