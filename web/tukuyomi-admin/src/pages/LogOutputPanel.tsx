import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";

type LogOutputDTO = {
    etag?: string;
    raw?: string;
    path?: string;
    provider?: string;
    waf_mode?: string;
    waf_file_path?: string;
    interesting_mode?: string;
    interesting_file_path?: string;
    access_error_mode?: string;
    access_error_file_path?: string;
    stdout_streams?: number;
    file_streams?: number;
    local_read_compatible?: boolean;
};

export default function LogOutputPanel() {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [raw, setRaw] = useState("");
    const [serverRaw, setServerRaw] = useState("");
    const [etag, setEtag] = useState<string | null>(null);
    const [valid, setValid] = useState<boolean | null>(null);
    const [messages, setMessages] = useState<string[]>([]);
    const [provider, setProvider] = useState("custom");
    const [path, setPath] = useState("");
    const [stdoutStreams, setStdoutStreams] = useState(0);
    const [fileStreams, setFileStreams] = useState(0);
    const [localReadCompatible, setLocalReadCompatible] = useState(true);
    const [wafMode, setWafMode] = useState("");
    const [interestingMode, setInterestingMode] = useState("");
    const [accessErrorMode, setAccessErrorMode] = useState("");
    const [error, setError] = useState<string | null>(null);
    const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);

    const dirty = useMemo(() => raw !== serverRaw, [raw, serverRaw]);

    const applySummary = useCallback((data: LogOutputDTO) => {
        setProvider(data.provider ?? "custom");
        setPath(data.path ?? "");
        setStdoutStreams(typeof data.stdout_streams === "number" ? data.stdout_streams : 0);
        setFileStreams(typeof data.file_streams === "number" ? data.file_streams : 0);
        setLocalReadCompatible(data.local_read_compatible !== false);
        setWafMode(data.waf_mode ?? "");
        setInterestingMode(data.interesting_mode ?? "");
        setAccessErrorMode(data.access_error_mode ?? "");
    }, []);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiGetJson<LogOutputDTO>("/log-output");
            setRaw(data.raw ?? "");
            setServerRaw(data.raw ?? "");
            setEtag(data.etag ?? null);
            applySummary(data);
            setValid(null);
            setMessages([]);
        } catch (e: any) {
            setError(e?.message || String(e));
        } finally {
            setLoading(false);
        }
    }, [applySummary]);

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
                const js = await apiPostJson<LogOutputDTO & { ok: boolean; messages?: string[] }>("/log-output/validate", { raw });
                setValid(!!js.ok);
                setMessages(Array.isArray(js.messages) ? js.messages : []);
                applySummary(js);
            } catch (e: any) {
                setValid(false);
                setMessages([e?.message || "Validate failed"]);
            }
        }, 300);
        return () => {
            if (debounceRef.current) {
                window.clearTimeout(debounceRef.current);
            }
        };
    }, [raw, loading, applySummary]);

    const doSave = useCallback(async () => {
        setSaving(true);
        setError(null);
        try {
            const js = await apiPutJson<LogOutputDTO & { ok: boolean }>(
                "/log-output",
                { raw },
                { headers: etag ? { "If-Match": etag } : {} }
            );
            if (!js.ok) {
                throw new Error("Failed to save");
            }
            setEtag(js.etag ?? null);
            setServerRaw(raw);
            applySummary(js);
            setLastSavedAt(Date.now());
        } catch (e: any) {
            setError(e?.message || "Save failed");
        } finally {
            setSaving(false);
        }
    }, [raw, etag, applySummary]);

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
                <h1 className="text-xl font-semibold">Log Output</h1>
                <div className="flex items-center gap-2">
                    {statusBadge}
                    <Badge color={localReadCompatible ? "green" : "amber"}>
                        {localReadCompatible ? "File-backed Reads" : "Stdout-first"}
                    </Badge>
                    {dirty && <Badge color="amber">Unsaved</Badge>}
                    {etag && <MonoTag label="ETag" value={etag} />}
                </div>
            </header>

            {error && <Alert kind="error" title="Error" message={error} onClose={() => setError(null)} />}

            <div className="grid gap-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="text-sm text-neutral-500">
                        Choose how WAF, interesting, and access-error logs are emitted for cloud collectors or file-based operators.
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                        <button type="button" className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border" onClick={() => setRaw(awsPreset)} disabled={loading}>
                            AWS
                        </button>
                        <button type="button" className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border" onClick={() => setRaw(azurePreset)} disabled={loading}>
                            Azure
                        </button>
                        <button type="button" className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border" onClick={() => setRaw(gcpPreset)} disabled={loading}>
                            GCP
                        </button>
                        <button type="button" className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border" onClick={() => setRaw(onPremPreset)} disabled={loading}>
                            On-prem
                        </button>
                        <button type="button" className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border" onClick={() => void load()} disabled={loading}>
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

                <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4 text-xs">
                    <MetaCard label="Provider" value={provider} />
                    <MetaCard label="Profile Path" value={path || "-"} mono />
                    <MetaCard label="Stdout Streams" value={String(stdoutStreams)} />
                    <MetaCard label="File Streams" value={String(fileStreams)} />
                    <MetaCard label="WAF" value={wafMode || "-"} />
                    <MetaCard label="Interesting" value={interestingMode || "-"} />
                    <MetaCard label="Access Error" value={accessErrorMode || "-"} />
                    <MetaCard label="Local Reads" value={localReadCompatible ? "compatible" : "stdout-first only"} />
                </div>

                <textarea
                    className="w-full h-[420px] p-3 border rounded-xl font-mono text-sm leading-5 outline-none focus:ring-2 focus:ring-black/20"
                    value={raw}
                    onChange={(e) => setRaw(e.target.value)}
                    spellCheck={false}
                />

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

function MetaCard({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
    return (
        <div className="rounded-xl border bg-white px-3 py-2">
            <div className="text-xs text-neutral-500">{label}</div>
            <div className={`${mono ? "font-mono" : ""} mt-1 break-all`}>{value}</div>
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

const awsPreset = `{
  "provider": "aws",
  "waf": {
    "mode": "stdout-ndjson",
    "file_path": "logs/coraza/waf-events.ndjson"
  },
  "interesting": {
    "mode": "stdout-ndjson",
    "file_path": "logs/nginx/interesting.ndjson"
  },
  "access_error": {
    "mode": "stdout-ndjson",
    "file_path": "logs/nginx/access-error.ndjson"
  }
}`;

const azurePreset = `{
  "provider": "azure",
  "waf": {
    "mode": "stdout-ndjson",
    "file_path": "logs/coraza/waf-events.ndjson"
  },
  "interesting": {
    "mode": "stdout-ndjson",
    "file_path": "logs/nginx/interesting.ndjson"
  },
  "access_error": {
    "mode": "stdout-ndjson",
    "file_path": "logs/nginx/access-error.ndjson"
  }
}`;

const gcpPreset = `{
  "provider": "gcp",
  "waf": {
    "mode": "stdout-ndjson",
    "file_path": "logs/coraza/waf-events.ndjson"
  },
  "interesting": {
    "mode": "stdout-ndjson",
    "file_path": "logs/nginx/interesting.ndjson"
  },
  "access_error": {
    "mode": "stdout-ndjson",
    "file_path": "logs/nginx/access-error.ndjson"
  }
}`;

const onPremPreset = `{
  "provider": "onprem",
  "waf": {
    "mode": "dual",
    "file_path": "logs/coraza/waf-events.ndjson"
  },
  "interesting": {
    "mode": "file-ndjson",
    "file_path": "logs/nginx/interesting.ndjson"
  },
  "access_error": {
    "mode": "file-ndjson",
    "file_path": "logs/nginx/access-error.ndjson"
  }
}`;
