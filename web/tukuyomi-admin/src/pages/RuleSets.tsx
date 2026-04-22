import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { ActionResultNotice } from "@/components/EditorChrome";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";
import { parseSavedAt } from "@/lib/savedAt";

type RuleItem = {
    name: string;
    path: string;
    enabled: boolean;
};

type RuleSetsResp = {
    crs_enabled?: boolean;
    disabled_file?: string;
    etag?: string;
    rules?: RuleItem[];
    saved_at?: string;
};

export default function RuleSets() {
    const { locale, tx } = useI18n();
    const { readOnly } = useAdminRuntime();
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [etag, setEtag] = useState<string | null>(null);
    const [disabledFile, setDisabledFile] = useState<string>("");
    const [crsEnabled, setCrsEnabled] = useState(true);
    const [rules, setRules] = useState<RuleItem[]>([]);
    const [serverEnabled, setServerEnabled] = useState<Set<string>>(new Set());
    const [valid, setValid] = useState<boolean | null>(null);
    const [messages, setMessages] = useState<string[]>([]);
    const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiGetJson<RuleSetsResp>("/crs-rule-sets");
            const list = Array.isArray(data.rules) ? data.rules : [];
            setRules(list);
            setCrsEnabled(data.crs_enabled !== false);
            setDisabledFile(data.disabled_file ?? "");
            setEtag(data.etag ?? null);

            const enabled = new Set<string>();
            for (const r of list) {
                if (r.enabled) {
                    enabled.add(r.name);
                }
            }
            setServerEnabled(enabled);
            setLastSavedAt(parseSavedAt(data.saved_at));
            setValid(null);
            setMessages([]);
        } catch (error: unknown) {
            setError(getErrorMessage(error, tx("Failed to load")));
        } finally {
            setLoading(false);
        }
    }, [tx]);

    useEffect(() => {
        void load();
    }, [load]);

    const enabledNames = useMemo(
        () => rules.filter((r) => r.enabled).map((r) => r.name).sort(),
        [rules]
    );
    const dirty = useMemo(() => {
        if (enabledNames.length !== serverEnabled.size) {
            return true;
        }
        for (const n of enabledNames) {
            if (!serverEnabled.has(n)) {
                return true;
            }
        }
        return false;
    }, [enabledNames, serverEnabled]);

    const debounceRef = useRef<number | null>(null);
    useEffect(() => {
        if (loading || !dirty) {
            return;
        }
        if (debounceRef.current) {
            window.clearTimeout(debounceRef.current);
        }

        debounceRef.current = window.setTimeout(async () => {
            try {
                const js = await apiPostJson<{ ok: boolean; messages?: string[] }>(
                    "/crs-rule-sets:validate",
                    { enabled: enabledNames }
                );
                setValid(!!js.ok);
                setMessages(Array.isArray(js.messages) ? js.messages : []);
            } catch (error: unknown) {
                setValid(false);
                setMessages([getErrorMessage(error, tx("Validate failed"))]);
            }
        }, 300);

        return () => {
            if (debounceRef.current) {
                window.clearTimeout(debounceRef.current);
            }
        };
    }, [dirty, enabledNames, loading, tx]);

    const toggle = useCallback((name: string, on: boolean) => {
        setRules((prev) => prev.map((r) => (r.name === name ? { ...r, enabled: on } : r)));
    }, []);

    const setAll = useCallback((on: boolean) => {
        setRules((prev) => prev.map((r) => ({ ...r, enabled: on })));
    }, []);

    const doSave = useCallback(async () => {
        setSaving(true);
        setError(null);
        try {
            const js = await apiPutJson<{ ok: boolean; etag?: string; saved_at?: string }>(
                "/crs-rule-sets",
                { enabled: enabledNames },
                { headers: etag ? { "If-Match": etag } : {} }
            );
            if (!js.ok) {
                throw new Error(tx("Failed to save"));
            }
            setEtag(js.etag ?? null);
            setServerEnabled(new Set(enabledNames));
            setLastSavedAt(parseSavedAt(js.saved_at));
        } catch (error: unknown) {
            setError(getErrorMessage(error, tx("Save failed")));
        } finally {
            setSaving(false);
        }
    }, [enabledNames, etag, tx]);

    if (loading) {
        return <div className="text-gray-500">{tx("Loading rule sets...")}</div>;
    }

    return (
        <div className="w-full p-4 space-y-4">
            <header className="flex items-center justify-between">
                <h1 className="text-xl font-semibold">{tx("Rule Sets")}</h1>
                <div className="flex items-center gap-2">
                    {!crsEnabled && <Badge color="amber">{tx("CRS Disabled")}</Badge>}
                    {valid === null ? <Badge color="gray">{tx("Unvalidated")}</Badge> : valid ? <Badge color="green">{tx("Valid")}</Badge> : <Badge color="red">{tx("Invalid")}</Badge>}
                    {dirty && <Badge color="amber">{tx("Unsaved")}</Badge>}
                    {etag && <MonoTag label="ETag" value={etag} />}
                </div>
            </header>
            <div className="text-sm text-neutral-600">
                {tx("Toggle CRS core rules on/off. WAF is hot-reloaded after save.")}
                {disabledFile && <span className="ml-2 text-neutral-500">{tx("Saved to: {path}", { path: disabledFile })}</span>}
            </div>

            <div className="flex items-center gap-2">
                <button
                    type="button"
                    className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                    onClick={() => setAll(true)}
                    disabled={readOnly || saving}
                >
                    {tx("Enable all")}
                </button>
                <button
                    type="button"
                    className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                    onClick={() => setAll(false)}
                    disabled={readOnly || saving}
                >
                    {tx("Disable all")}
                </button>
                <button
                    type="button"
                    className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border border-neutral-200"
                    onClick={() => void load()}
                    disabled={saving}
                >
                    {tx("Refresh")}
                </button>
                <button
                    type="button"
                    className="px-3 py-1.5 rounded-xl shadow text-sm bg-black text-white disabled:opacity-50"
                    onClick={() => void doSave()}
                    disabled={readOnly || saving || !dirty}
                >
                    {saving ? tx("Saving...") : tx("Save & hot reload")}
                </button>
            </div>

            <ActionResultNotice
                tone={error ? "error" : valid === false ? "error" : "success"}
                messages={error ? [`${tx("Error")}: ${error}`] : messages}
            />

            <div className="app-table-shell">
                <div className="app-table-head grid grid-cols-[100px_1fr_1fr] gap-0 text-xs font-semibold border-b border-neutral-200">
                    <div className="p-2">{tx("Enabled")}</div>
                    <div className="p-2">{tx("File")}</div>
                    <div className="p-2">{tx("Path")}</div>
                </div>
                <div className="max-h-[520px] overflow-auto">
                    {rules.map((r) => (
                        <label key={r.path} className="grid grid-cols-[100px_1fr_1fr] border-b border-neutral-200 last:border-b-0 text-sm items-center hover:bg-neutral-50/70">
                            <div className="p-2">
                                <input
                                    type="checkbox"
                                    checked={r.enabled}
                                    onChange={(e) => toggle(r.name, e.target.checked)}
                                    disabled={readOnly || saving}
                                />
                            </div>
                            <div className="p-2 font-mono">{r.name}</div>
                            <div className="p-2 font-mono text-xs text-neutral-600">{r.path}</div>
                        </label>
                    ))}
                    {rules.length === 0 && (
                        <div className="p-4 text-sm text-neutral-500">{tx("No CRS rule files found.")}</div>
                    )}
                </div>
            </div>

            <div className="flex items-center justify-between text-xs text-neutral-500">
                <div className="flex items-center gap-3">
                    <span>{tx("Total")}: {rules.length}</span>
                    <span>{tx("Enabled")}: {enabledNames.length}</span>
                    <span>{tx("Disabled")}: {rules.length - enabledNames.length}</span>
                    {lastSavedAt && <span>{tx("Last saved: {time}", { time: new Date(lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") })}</span>}
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
