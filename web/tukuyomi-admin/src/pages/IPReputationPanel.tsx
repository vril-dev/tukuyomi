import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";

type IPReputationDTO = {
    etag?: string;
    raw?: string;
    config?: {
        enabled?: boolean;
        feed_urls?: string[];
        fail_open?: boolean;
        block_status_code?: number;
    };
    status?: {
        enabled?: boolean;
        feed_urls?: string[];
        last_refresh_at?: string;
        last_refresh_error?: string;
        effective_allow_count?: number;
        effective_block_count?: number;
        feed_allow_count?: number;
        feed_block_count?: number;
        block_status_code?: number;
        fail_open?: boolean;
    };
};

export default function IPReputationPanel() {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [raw, setRaw] = useState("");
    const [serverRaw, setServerRaw] = useState("");
    const [etag, setEtag] = useState<string | null>(null);
    const [valid, setValid] = useState<boolean | null>(null);
    const [messages, setMessages] = useState<string[]>([]);
    const [enabled, setEnabled] = useState(false);
    const [feedCount, setFeedCount] = useState(0);
    const [failOpen, setFailOpen] = useState(true);
    const [blockStatusCode, setBlockStatusCode] = useState(403);
    const [effectiveAllowCount, setEffectiveAllowCount] = useState(0);
    const [effectiveBlockCount, setEffectiveBlockCount] = useState(0);
    const [feedAllowCount, setFeedAllowCount] = useState(0);
    const [feedBlockCount, setFeedBlockCount] = useState(0);
    const [lastRefreshAt, setLastRefreshAt] = useState("");
    const [lastRefreshError, setLastRefreshError] = useState("");
    const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
    const [error, setError] = useState<string | null>(null);

    const dirty = useMemo(() => raw !== serverRaw, [raw, serverRaw]);

    const applyStatus = useCallback((data?: IPReputationDTO) => {
        const cfg = data?.config ?? {};
        const status = data?.status ?? {};
        setEnabled(!!(status.enabled ?? cfg.enabled));
        setFeedCount(Array.isArray(status.feed_urls ?? cfg.feed_urls) ? (status.feed_urls ?? cfg.feed_urls ?? []).length : 0);
        setFailOpen(!!(status.fail_open ?? cfg.fail_open));
        setBlockStatusCode(typeof (status.block_status_code ?? cfg.block_status_code) === "number" ? Number(status.block_status_code ?? cfg.block_status_code) : 403);
        setEffectiveAllowCount(typeof status.effective_allow_count === "number" ? status.effective_allow_count : 0);
        setEffectiveBlockCount(typeof status.effective_block_count === "number" ? status.effective_block_count : 0);
        setFeedAllowCount(typeof status.feed_allow_count === "number" ? status.feed_allow_count : 0);
        setFeedBlockCount(typeof status.feed_block_count === "number" ? status.feed_block_count : 0);
        setLastRefreshAt(status.last_refresh_at ?? "");
        setLastRefreshError(status.last_refresh_error ?? "");
    }, []);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiGetJson<IPReputationDTO>("/ip-reputation");
            setRaw(data.raw ?? "");
            setServerRaw(data.raw ?? "");
            setEtag(data.etag ?? null);
            applyStatus(data);
            setValid(null);
            setMessages([]);
        } catch (e: any) {
            setError(e?.message || String(e));
        } finally {
            setLoading(false);
        }
    }, [applyStatus]);

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
                const js = await apiPostJson<{ ok: boolean; messages?: string[]; config?: IPReputationDTO["config"] }>("/ip-reputation:validate", { raw });
                setValid(!!js.ok);
                setMessages(Array.isArray(js.messages) ? js.messages : []);
                applyStatus({ config: js.config });
            } catch (e: any) {
                setValid(false);
                setMessages([e?.message || "Validate failed"]);
            }
        }, 300);

        return () => {
            if (debounceRef.current) window.clearTimeout(debounceRef.current);
        };
    }, [raw, loading, applyStatus]);

    const doSave = useCallback(async () => {
        setSaving(true);
        setError(null);
        try {
            const js = await apiPutJson<{ ok: boolean; etag?: string; status?: IPReputationDTO["status"] }>(
                "/ip-reputation",
                { raw },
                { headers: etag ? { "If-Match": etag } : {} }
            );
            if (!js.ok) {
                throw new Error("Failed to save");
            }
            setEtag(js.etag ?? null);
            setServerRaw(raw);
            applyStatus({ status: js.status });
            setLastSavedAt(Date.now());
        } catch (e: any) {
            setError(e?.message || "Save failed");
        } finally {
            setSaving(false);
        }
    }, [applyStatus, etag, raw]);

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
                <h1 className="text-xl font-semibold">IP Reputation</h1>
                <div className="flex items-center gap-2">
                    {statusBadge}
                    {enabled ? <Badge color="green">Enabled</Badge> : <Badge color="gray">Disabled</Badge>}
                    {failOpen ? <Badge color="amber">Fail open</Badge> : <Badge color="red">Fail closed</Badge>}
                    {dirty && <Badge color="amber">Unsaved</Badge>}
                    {etag && <MonoTag label="ETag" value={etag} />}
                </div>
            </header>

            {error && <Alert kind="error" title="Error" message={error} onClose={() => setError(null)} />}

            <div className="grid gap-3">
                <div className="flex items-center justify-between gap-2">
                    <div className="text-sm text-neutral-500">
                        Manage static allow/block CIDRs and optional external feed refresh before bot, semantic, and WAF evaluation.
                    </div>
                    <div className="flex items-center gap-2">
                        <button
                            type="button"
                            className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border"
                            onClick={() => setRaw((prev) => (prev ? prev : defaultIPReputationExample))}
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
                    <div className="flex items-center gap-3 flex-wrap">
                        <span>Lines: {lineCount}</span>
                        <span>Feeds: {feedCount}</span>
                        <span>Block status: {blockStatusCode}</span>
                        <span>Effective allow: {effectiveAllowCount}</span>
                        <span>Effective block: {effectiveBlockCount}</span>
                        <span>Feed allow: {feedAllowCount}</span>
                        <span>Feed block: {feedBlockCount}</span>
                        {lastRefreshAt && <span>Last refresh: {new Date(lastRefreshAt).toLocaleString()}</span>}
                        {lastSavedAt && <span>Last saved: {new Date(lastSavedAt).toLocaleString()}</span>}
                    </div>
                    <div className="flex items-center gap-2 max-w-[40%] overflow-hidden">
                        {(lastRefreshError ? [lastRefreshError] : messages).slice(0, 2).map((m, i) => (
                            <span key={`msg-${i}`} className="px-2 py-0.5 bg-neutral-100 rounded truncate">
                                {m}
                            </span>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}

const defaultIPReputationExample = `{
  "enabled": false,
  "feed_urls": [
    "https://feeds.example.invalid/ip-reputation.txt"
  ],
  "allowlist": [
    "127.0.0.1/32",
    "::1/128"
  ],
  "blocklist": [
    "203.0.113.0/24",
    "2001:db8:dead:beef::/64"
  ],
  "refresh_interval_sec": 900,
  "request_timeout_sec": 5,
  "block_status_code": 403,
  "fail_open": true
}`;

function Badge({ color, children }: { color: "gray" | "green" | "red" | "amber"; children: React.ReactNode }) {
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
    const tone = kind === "error" ? "border-red-300 bg-red-50" : "border-blue-300 bg-blue-50";
    return (
        <div className={`border ${tone} rounded-xl p-3 text-sm flex items-start gap-3`}>
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
