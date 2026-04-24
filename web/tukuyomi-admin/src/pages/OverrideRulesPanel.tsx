import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiDeleteJson, apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { ActionResultNotice } from "@/components/EditorChrome";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";
import { parseSavedAt } from "@/lib/savedAt";

type OverrideRuleDTO = {
    name: string;
    path: string;
    raw?: string;
    etag?: string;
    error?: string;
    saved_at?: string;
};

type OverrideRulesResp = {
    dir?: string;
    files?: OverrideRuleDTO[];
};

const OVERRIDE_RULE_STARTER = `SecRuleEngine On

SecRule REQUEST_URI "@beginsWith /api/example" "id:100001,phase:1,pass,nolog"
`;

export default function OverrideRulesPanel() {
    const { locale, tx } = useI18n();
    const { readOnly } = useAdminRuntime();
    const [overrideLoading, setOverrideLoading] = useState(true);
    const [overrideSaving, setOverrideSaving] = useState(false);
    const [overrideDeleting, setOverrideDeleting] = useState(false);
    const [overrideError, setOverrideError] = useState<string | null>(null);
    const [overrideDir, setOverrideDir] = useState("conf/rules");
    const [overrideFiles, setOverrideFiles] = useState<Record<string, OverrideRuleDTO>>({});
    const [selectedOverrideName, setSelectedOverrideName] = useState("");
    const [overrideName, setOverrideName] = useState("");
    const [overrideRaw, setOverrideRaw] = useState("");
    const [overrideServerName, setOverrideServerName] = useState("");
    const [overrideServerRaw, setOverrideServerRaw] = useState("");
    const [overrideETag, setOverrideETag] = useState<string | null>(null);
    const [overrideLoadError, setOverrideLoadError] = useState<string | null>(null);
    const [overrideValid, setOverrideValid] = useState<boolean | null>(null);
    const [overrideMessages, setOverrideMessages] = useState<string[]>([]);
    const [overrideLastSavedAt, setOverrideLastSavedAt] = useState<number | null>(null);
    const fileImportRef = useRef<HTMLInputElement | null>(null);
    const selectedOverrideNameRef = useRef("");

    const resetOverrideEditor = useCallback((name?: string, file?: OverrideRuleDTO) => {
        const nextName = (name || "").trim();
        const nextRaw = file?.raw ?? "";
        setSelectedOverrideName(nextName);
        setOverrideName(nextName);
        setOverrideRaw(nextRaw);
        setOverrideServerName(nextName);
        setOverrideServerRaw(nextRaw);
        setOverrideETag(file?.etag ?? null);
        setOverrideLoadError(file?.error ?? null);
        setOverrideValid(null);
        setOverrideMessages([]);
        setOverrideLastSavedAt(parseSavedAt(file?.saved_at));
    }, []);

    useEffect(() => {
        selectedOverrideNameRef.current = selectedOverrideName.trim();
    }, [selectedOverrideName]);

    const loadOverrides = useCallback(async (preferredName?: string) => {
        setOverrideLoading(true);
        setOverrideError(null);
        try {
            const data = await apiGetJson<OverrideRulesResp>("/override-rules");
            const files = Array.isArray(data.files) ? data.files : [];
            const next: Record<string, OverrideRuleDTO> = {};
            for (const file of files) {
                if (!file?.name) {
                    continue;
                }
                next[file.name] = file;
            }
            setOverrideFiles(next);
            setOverrideDir((data.dir || "conf/rules").trim() || "conf/rules");

            const preferred = (preferredName || "").trim();
            const current = selectedOverrideNameRef.current;
            const resolved = preferred && next[preferred]
                ? preferred
                : current && next[current]
                    ? current
                    : Object.keys(next)[0] || "";
            if (resolved) {
                resetOverrideEditor(resolved, next[resolved]);
            } else {
                resetOverrideEditor("", undefined);
            }
        } catch (error: unknown) {
            setOverrideError(getErrorMessage(error, tx("Failed to load")));
        } finally {
            setOverrideLoading(false);
        }
    }, [resetOverrideEditor, tx]);

    useEffect(() => {
        void loadOverrides();
    }, [loadOverrides]);

    const overrideNames = useMemo(() => Object.keys(overrideFiles).sort(), [overrideFiles]);
    const overrideDirty = useMemo(
        () => overrideName.trim() !== overrideServerName.trim() || overrideRaw !== overrideServerRaw,
        [overrideName, overrideServerName, overrideRaw, overrideServerRaw]
    );
    const overrideIsExisting = useMemo(() => !!overrideServerName.trim(), [overrideServerName]);

    const overrideDebounceRef = useRef<number | null>(null);
    useEffect(() => {
        if (overrideLoading) {
            return;
        }
        if (overrideDebounceRef.current) {
            window.clearTimeout(overrideDebounceRef.current);
        }
        const trimmedName = overrideName.trim();
        if (!trimmedName) {
            setOverrideValid(null);
            setOverrideMessages([]);
            return;
        }

        overrideDebounceRef.current = window.setTimeout(async () => {
            try {
                const js = await apiPostJson<{ ok: boolean; messages?: string[] }>(
                    "/override-rules:validate",
                    { name: trimmedName, raw: overrideRaw }
                );
                setOverrideValid(!!js.ok);
                setOverrideMessages(Array.isArray(js.messages) ? js.messages : []);
            } catch (error: unknown) {
                setOverrideValid(false);
                setOverrideMessages([getErrorMessage(error, tx("Validate failed"))]);
            }
        }, 300);

        return () => {
            if (overrideDebounceRef.current) {
                window.clearTimeout(overrideDebounceRef.current);
            }
        };
    }, [overrideLoading, overrideName, overrideRaw, tx]);

    const doSaveOverride = useCallback(async () => {
        const trimmedName = overrideName.trim();
        if (!trimmedName) {
            setOverrideError("override rule file name is required");
            return;
        }
        setOverrideSaving(true);
        setOverrideError(null);
        try {
            const js = await apiPutJson<{ ok: boolean; etag?: string; name?: string; saved_at?: string }>(
                "/override-rules",
                { name: trimmedName, raw: overrideRaw },
                { headers: overrideETag ? { "If-Match": overrideETag } : {} }
            );
            if (!js.ok) {
                throw new Error(tx("Failed to save"));
            }
            const nextSavedAt = parseSavedAt(js.saved_at);
            await loadOverrides(js.name || trimmedName);
            setOverrideLastSavedAt(nextSavedAt);
        } catch (error: unknown) {
            setOverrideError(getErrorMessage(error, tx("Save failed")));
        } finally {
            setOverrideSaving(false);
        }
    }, [loadOverrides, overrideETag, overrideName, overrideRaw, tx]);

    const doDeleteOverride = useCallback(async () => {
        const trimmedName = overrideServerName.trim() || overrideName.trim();
        if (!trimmedName) {
            return;
        }
        setOverrideDeleting(true);
        setOverrideError(null);
        try {
            await apiDeleteJson(`/override-rules?name=${encodeURIComponent(trimmedName)}`);
            await loadOverrides();
        } catch (error: unknown) {
            setOverrideError(getErrorMessage(error, tx("Delete failed")));
        } finally {
            setOverrideDeleting(false);
        }
    }, [loadOverrides, overrideName, overrideServerName, tx]);

    const handleImportOverride = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (!file) {
            return;
        }
        const text = await file.text();
        setOverrideRaw(text);
        if (!overrideName.trim()) {
            setOverrideName(file.name);
        }
        event.target.value = "";
    }, [overrideName]);

    const nextOverrideRuleName = useCallback(() => {
        let idx = 0;
        while (true) {
            const candidate = idx === 0 ? "new-override.conf" : `new-override-${idx + 1}.conf`;
            if (!overrideFiles[candidate]) {
                return candidate;
            }
            idx += 1;
        }
    }, [overrideFiles]);

    const beginNewOverride = useCallback(() => {
        const starterName = nextOverrideRuleName();
        setSelectedOverrideName("");
        setOverrideName(starterName);
        setOverrideRaw(OVERRIDE_RULE_STARTER);
        setOverrideServerName("");
        setOverrideServerRaw("");
        setOverrideETag(null);
        setOverrideLoadError(null);
        setOverrideValid(null);
        setOverrideMessages([]);
        setOverrideLastSavedAt(null);
        setOverrideError(null);
    }, [nextOverrideRuleName]);

    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            const isSave = (e.key === "s" || e.key === "S") && (e.ctrlKey || e.metaKey);
            if (!isSave) {
                return;
            }
            e.preventDefault();
            if (!overrideSaving && !readOnly && overrideDirty) {
                void doSaveOverride();
            }
        };

        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [doSaveOverride, overrideDirty, overrideSaving, readOnly]);

    const activeOverrideStatus = useMemo(() => {
        if (overrideLoading) {
            return <Badge color="gray">{tx("Loading")}</Badge>;
        }
        if (!overrideName.trim() || overrideValid === null) {
            return <Badge color="gray">{tx("Unvalidated")}</Badge>;
        }
        return overrideValid ? <Badge color="green">{tx("Valid")}</Badge> : <Badge color="red">{tx("Invalid")}</Badge>;
    }, [overrideLoading, overrideName, overrideValid, tx]);

    return (
        <div className="w-full p-4 space-y-6">
            <section className="space-y-4">
                <header className="flex items-center justify-between">
                    <div>
                        <h1 className="text-xl font-semibold">Override Rules</h1>
                        <p className="text-sm text-neutral-500">
                            Managed bypass `extra_rule` bodies are stored in DB. Accepted references are <code className="px-1 bg-neutral-100 rounded">name.conf</code> or <code className="px-1 bg-neutral-100 rounded">{overrideDir}/name.conf</code>.
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        {activeOverrideStatus}
                        {overrideDirty && <Badge color="amber">{tx("Unsaved")}</Badge>}
                        {overrideETag && <MonoTag label="ETag" value={overrideETag} />}
                    </div>
                </header>

                {overrideError && (
                    <div className="border border-red-300 bg-red-50 rounded-xl p-3 text-sm">
                        {overrideError}
                    </div>
                )}

                <div className="flex flex-wrap items-center gap-2">
                    <label className="text-sm text-neutral-600">{tx("Managed rule")}</label>
                    <select
                        className="border rounded px-2 py-1 text-sm min-w-[260px]"
                        value={selectedOverrideName}
                        onChange={(e) => {
                            const name = e.target.value;
                            const file = overrideFiles[name];
                            if (file) {
                                resetOverrideEditor(name, file);
                            } else {
                                beginNewOverride();
                            }
                        }}
                    >
                        <option value="">{tx("New override rule")}</option>
                        {overrideNames.map((name) => (
                            <option key={name} value={name}>{name}</option>
                        ))}
                    </select>
                    <button
                        type="button"
                        className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                        onClick={() => void loadOverrides()}
                        disabled={overrideLoading}
                    >
                        {tx("Refresh")}
                    </button>
                    <button
                        type="button"
                        className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                        onClick={beginNewOverride}
                        disabled={overrideSaving || overrideDeleting}
                    >
                        {tx("New")}
                    </button>
                    <button
                        type="button"
                        className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                        onClick={() => fileImportRef.current?.click()}
                        disabled={overrideSaving || overrideDeleting}
                    >
                        {tx("Import .conf")}
                    </button>
                    <input
                        ref={fileImportRef}
                        type="file"
                        accept=".conf,text/plain"
                        className="hidden"
                        onChange={handleImportOverride}
                    />
                    <button
                        type="button"
                        className="px-3 py-1.5 rounded-xl shadow text-sm bg-black text-white disabled:opacity-50"
                        onClick={() => void doSaveOverride()}
                        disabled={readOnly || overrideSaving || !overrideDirty || !overrideName.trim()}
                    >
                        {overrideSaving ? tx("Saving...") : tx("Save")}
                    </button>
                    <button
                        type="button"
                        className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border disabled:opacity-50"
                        onClick={() => void doDeleteOverride()}
                        disabled={readOnly || overrideDeleting || !overrideIsExisting}
                    >
                        {overrideDeleting ? tx("Deleting...") : tx("Delete")}
                    </button>
                </div>

                <ActionResultNotice
                    tone={overrideError ? "error" : overrideValid === false ? "error" : "success"}
                    messages={overrideError ? [overrideError] : overrideMessages}
                />

                <div className="grid gap-3 md:grid-cols-[280px_1fr]">
                    <div className="space-y-2">
                        <label className="text-sm font-medium text-neutral-700">File name</label>
                        <input
                            value={overrideName}
                            onChange={(e) => setOverrideName(e.target.value)}
                            placeholder="orders-preview.conf"
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono"
                        />
                        <div className="text-xs text-neutral-500">
                            DB asset reference: <code className="px-1 bg-neutral-100 rounded">{overrideName.trim() ? `${overrideDir}/${overrideName.trim()}` : `${overrideDir}/<name>.conf`}</code>
                        </div>
                        {overrideLoadError && (
                            <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900">
                                {tx("Load failed: {error}", { error: overrideLoadError })}
                            </div>
                        )}
                        <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs text-neutral-600">
                            `extra_rule` swaps the request onto this standalone DB-managed override rule instead of the base WAF rule set.
                        </div>
                    </div>
                    <textarea
                        className="w-full h-[320px] p-3 border rounded-xl font-mono text-sm leading-5 outline-none focus:ring-2 focus:ring-black/20"
                        value={overrideRaw}
                        onChange={(e) => setOverrideRaw(e.target.value)}
                        spellCheck={false}
                        placeholder={`SecRuleEngine On\n\nSecRule REQUEST_URI "@beginsWith /api/orders/preview" \\\n  "id:100001,phase:1,pass,nolog"`}
                    />
                </div>

                <div className="flex items-center justify-between text-xs text-neutral-500">
                    <div className="flex items-center gap-3">
                        <span>{tx("Lines")}: {overrideRaw ? overrideRaw.split(/\n/).length : 0}</span>
                        <span>{tx("Chars")}: {overrideRaw.length}</span>
                        {overrideLastSavedAt && <span>{tx("Last saved: {time}", { time: new Date(overrideLastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") })}</span>}
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
