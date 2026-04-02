import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";

type NotificationsDTO = {
    etag?: string;
    raw?: string;
    enabled?: boolean;
    sinks?: number;
    enabled_sinks?: number;
    active_alerts?: number;
};

export default function NotificationsPanel() {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [testing, setTesting] = useState(false);
    const [raw, setRaw] = useState("");
    const [serverRaw, setServerRaw] = useState("");
    const [etag, setEtag] = useState<string | null>(null);
    const [valid, setValid] = useState<boolean | null>(null);
    const [messages, setMessages] = useState<string[]>([]);
    const [enabled, setEnabled] = useState<boolean>(false);
    const [sinkCount, setSinkCount] = useState<number>(0);
    const [enabledSinkCount, setEnabledSinkCount] = useState<number>(0);
    const [activeAlerts, setActiveAlerts] = useState<number>(0);
    const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
    const [error, setError] = useState<string | null>(null);

    const dirty = useMemo(() => raw !== serverRaw, [raw, serverRaw]);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiGetJson<NotificationsDTO>("/notifications");
            setRaw(data.raw ?? "");
            setServerRaw(data.raw ?? "");
            setEtag(data.etag ?? null);
            setEnabled(!!data.enabled);
            setSinkCount(typeof data.sinks === "number" ? data.sinks : 0);
            setEnabledSinkCount(typeof data.enabled_sinks === "number" ? data.enabled_sinks : 0);
            setActiveAlerts(typeof data.active_alerts === "number" ? data.active_alerts : 0);
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
                const js = await apiPostJson<{ ok: boolean; messages?: string[]; enabled?: boolean; sinks?: number; enabled_sinks?: number }>(
                    "/notifications/validate",
                    { raw }
                );
                setValid(!!js.ok);
                setMessages(Array.isArray(js.messages) ? js.messages : []);
                setEnabled(!!js.enabled);
                setSinkCount(typeof js.sinks === "number" ? js.sinks : 0);
                setEnabledSinkCount(typeof js.enabled_sinks === "number" ? js.enabled_sinks : 0);
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
            const js = await apiPutJson<{ ok: boolean; etag?: string; enabled?: boolean; sinks?: number; enabled_sinks?: number }>(
                "/notifications",
                { raw },
                { headers: etag ? { "If-Match": etag } : {} }
            );
            if (!js.ok) {
                throw new Error("Failed to save");
            }
            setEtag(js.etag ?? null);
            setServerRaw(raw);
            setEnabled(!!js.enabled);
            setSinkCount(typeof js.sinks === "number" ? js.sinks : 0);
            setEnabledSinkCount(typeof js.enabled_sinks === "number" ? js.enabled_sinks : 0);
            setLastSavedAt(Date.now());
        } catch (e: any) {
            setError(e?.message || "Save failed");
        } finally {
            setSaving(false);
        }
    }, [raw, etag]);

    const doTest = useCallback(async () => {
        setTesting(true);
        setError(null);
        try {
            await apiPostJson<{ ok: boolean }>("/notifications/test", { note: "notifications panel test send" });
        } catch (e: any) {
            setError(e?.message || "Test send failed");
        } finally {
            setTesting(false);
        }
    }, []);

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
                <h1 className="text-xl font-semibold">Notifications</h1>
                <div className="flex items-center gap-2">
                    {statusBadge}
                    {enabled ? <Badge color="green">Enabled</Badge> : <Badge color="gray">Disabled</Badge>}
                    {dirty && <Badge color="amber">Unsaved</Badge>}
                    {etag && <MonoTag label="ETag" value={etag} />}
                </div>
            </header>

            {error && <Alert kind="error" title="Error" message={error} onClose={() => setError(null)} />}

            <div className="grid gap-3">
                <div className="flex items-center justify-between gap-2">
                    <div className="text-sm text-neutral-500">
                        Configure aggregate notifications for upstream and security state changes. Notifications are off by default.
                    </div>
                    <div className="flex items-center gap-2">
                        <button
                            type="button"
                            className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                            onClick={() => setRaw((prev) => (prev ? prev : defaultNotificationsExample))}
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
                            className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                            onClick={() => void doTest()}
                            disabled={loading || testing}
                        >
                            {testing ? "Sending..." : "Test send"}
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
                        <span>Sinks: {sinkCount}</span>
                        <span>Enabled sinks: {enabledSinkCount}</span>
                        <span>Active alerts: {activeAlerts}</span>
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

const defaultNotificationsExample = `{
  "enabled": false,
  "cooldown_seconds": 900,
  "sinks": [
    {
      "name": "primary-webhook",
      "type": "webhook",
      "enabled": false,
      "webhook_url": "https://hooks.example.invalid/tukuyomi",
      "timeout_seconds": 5,
      "headers": {
        "X-Tukuyomi-Token": "change-me"
      }
    },
    {
      "name": "ops-email",
      "type": "email",
      "enabled": false,
      "smtp_address": "smtp.example.invalid:587",
      "smtp_username": "alerts@example.invalid",
      "smtp_password": "change-me",
      "from": "alerts@example.invalid",
      "to": ["secops@example.invalid"],
      "subject_prefix": "[tukuyomi]"
    }
  ],
  "upstream": {
    "enabled": true,
    "window_seconds": 60,
    "active_threshold": 3,
    "escalated_threshold": 10
  },
  "security": {
    "enabled": true,
    "window_seconds": 300,
    "active_threshold": 20,
    "escalated_threshold": 100,
    "sources": ["waf_block", "rate_limited", "semantic_anomaly", "bot_challenge"]
  }
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

function Alert({ kind, title, message, onClose }: { kind: "error"; title: string; message: string; onClose: () => void }) {
    return (
        <div className={`rounded-xl border px-4 py-3 ${kind === "error" ? "border-red-200 bg-red-50 text-red-800" : ""}`}>
            <div className="flex items-start justify-between gap-4">
                <div>
                    <div className="font-medium">{title}</div>
                    <div className="text-sm whitespace-pre-wrap">{message}</div>
                </div>
                <button type="button" className="text-sm underline" onClick={onClose}>
                    close
                </button>
            </div>
        </div>
    );
}
