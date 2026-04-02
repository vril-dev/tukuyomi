import { useEffect, useMemo, useState } from 'react';
import { apiGetBinary, apiGetJson } from "@/lib/api";

type StatusResponse = Record<string, unknown>;

type StatsBucket = {
    key: string;
    count: number;
};

type StatsSeriesPoint = {
    bucket_start: string;
    count: number;
};

type LogsStatsResponse = {
    generated_at: string;
    scanned_lines: number;
    range_hours: number;
    oldest_scanned_ts?: string;
    newest_scanned_ts?: string;
    waf_block: {
        last_1h: number;
        last_24h: number;
        total_in_scan: number;
        top_rule_ids_24h: StatsBucket[];
        top_paths_24h: StatsBucket[];
        top_countries_24h: StatsBucket[];
        series_hourly: StatsSeriesPoint[];
    };
};

export default function Status() {
    const [data, setData] = useState<StatusResponse | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [manifestNotice, setManifestNotice] = useState<string | null>(null);
    const [manifestError, setManifestError] = useState<string | null>(null);
    const [manifestDownloading, setManifestDownloading] = useState(false);
    const [stats, setStats] = useState<LogsStatsResponse | null>(null);
    const [statsError, setStatsError] = useState<string | null>(null);
    const [statsLoading, setStatsLoading] = useState(false);
    const [rangeHours, setRangeHours] = useState<number>(24);

    useEffect(() => {
        let cancelled = false;

        apiGetJson<StatusResponse>("/status")
            .then((resp) => {
                if (cancelled) {
                    return;
                }
                setData(resp);
                setError(null);
            })
            .catch((err: unknown) => {
                if (cancelled) {
                    return;
                }
                const message = err instanceof Error ? err.message : String(err);
                setError(message);
            });

        return () => {
            cancelled = true;
        };
    }, []);

    useEffect(() => {
        let cancelled = false;

        setStatsLoading(true);
        apiGetJson<LogsStatsResponse>(`/logs/stats?hours=${rangeHours}`)
            .then((resp) => {
                if (cancelled) {
                    return;
                }
                setStats(resp);
                setStatsError(null);
            })
            .catch((err: unknown) => {
                if (cancelled) {
                    return;
                }
                const message = err instanceof Error ? err.message : String(err);
                setStatsError(message);
            })
            .finally(() => {
                if (cancelled) {
                    return;
                }
                setStatsLoading(false);
            });

        return () => {
            cancelled = true;
        };
    }, [rangeHours]);

    const running = useMemo(() => (data?.status === "running"), [data]);
    const wafBlock = stats?.waf_block;
    const dbSizeBytes = toNumber(data?.db_size_bytes);
    const dbRows = toNumber(data?.db_total_rows);
    const dbWAFBlockRows = toNumber(data?.db_waf_block_rows);

    async function downloadVerifyManifest() {
        setManifestDownloading(true);
        setManifestNotice(null);
        setManifestError(null);

        try {
            const { blob, filename } = await apiGetBinary("/verify-manifest");
            const objectUrl = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = objectUrl;
            a.download = filename || "tukuyomi-verify-manifest.json";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(objectUrl);
            setManifestNotice("Verify manifest downloaded.");
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : String(err);
            setManifestError(`Verify manifest download failed: ${message}`);
        } finally {
            setManifestDownloading(false);
        }
    }

    if (error) {
        return (
            <div className="w-full p-4">
                <div className="border border-red-300 bg-red-50 rounded-xl p-3 text-sm">Error: {error}</div>
            </div>
        );
    }

    if (!data) {
        return <div className="w-full p-4 text-gray-500">Loading status...</div>;
    }

    return (
        <div className="w-full p-4 space-y-4">
            <header className="flex items-center justify-between">
                <h1 className="text-xl font-semibold">Status</h1>
                <span
                    className={`px-2 py-0.5 text-xs rounded ${
                        running ? "bg-green-100 text-green-800" : "bg-amber-100 text-amber-800"
                    }`}
                >
                    {running ? "Running" : "Degraded"}
                </span>
            </header>

            <section className="rounded-xl border bg-white p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                        <h2 className="text-sm font-semibold">Verification Manifest</h2>
                        <p className="text-xs text-neutral-600">
                            Export the current admin-side verify manifest scaffold for external WAF test runners.
                        </p>
                    </div>
                    <button type="button" onClick={downloadVerifyManifest} disabled={manifestDownloading}>
                        {manifestDownloading ? "Downloading..." : "Download Verify Manifest"}
                    </button>
                </div>

                {manifestNotice ? (
                    <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{manifestNotice}</div>
                ) : null}
                {manifestError ? (
                    <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{manifestError}</div>
                ) : null}
            </section>

            {stats ? (
                <section className="rounded-xl border bg-white p-4 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                        <h2 className="text-sm font-semibold">WAF Block Overview ({stats.range_hours}h)</h2>
                        <div className="flex items-center gap-3 text-xs text-neutral-500">
                            <label className="inline-flex items-center gap-1">
                                Range
                                <select
                                    value={rangeHours}
                                    onChange={(e) => setRangeHours(Number(e.target.value))}
                                    className="rounded border px-1 py-0.5 text-xs bg-white text-neutral-700"
                                >
                                    <option value={24}>24h</option>
                                    <option value={72}>72h</option>
                                    <option value={168}>168h</option>
                                </select>
                            </label>
                            <span>
                                Scanned {formatCount(stats.scanned_lines)} lines · Updated {formatTime(stats.generated_at)}
                            </span>
                        </div>
                    </div>

                    <div className="grid gap-3 sm:grid-cols-3 text-sm">
                        <Metric label="Blocked (Last 1h)" value={formatCount(wafBlock?.last_1h)} />
                        <Metric label="Blocked (Last 24h)" value={formatCount(wafBlock?.last_24h)} />
                        <Metric label="Blocked (In Scan Window)" value={formatCount(wafBlock?.total_in_scan)} />
                    </div>

                    <HourlyBars points={wafBlock?.series_hourly ?? []} />

                    {stats.oldest_scanned_ts && stats.newest_scanned_ts ? (
                        <div className="text-xs text-neutral-500">
                            Scan coverage: {formatTime(stats.oldest_scanned_ts)} - {formatTime(stats.newest_scanned_ts)}
                        </div>
                    ) : null}

                    <div className="grid gap-3 lg:grid-cols-3">
                        <TopBuckets title="Top Rule IDs (24h)" items={wafBlock?.top_rule_ids_24h ?? []} />
                        <TopBuckets title="Top Paths (24h)" items={wafBlock?.top_paths_24h ?? []} />
                        <TopBuckets title="Top Countries (24h)" items={wafBlock?.top_countries_24h ?? []} />
                    </div>
                </section>
            ) : null}

            {statsLoading ? (
                <div className="text-xs text-neutral-500">Updating WAF block stats...</div>
            ) : null}

            {statsError ? (
                <div className="rounded-xl border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-800">
                    Failed to load WAF block stats: {statsError}
                </div>
            ) : null}

            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-sm">
                <Metric label="API Base" value={String(data.api_base ?? "-")} />
                <Metric label="Rules File" value={String(data.rules_file ?? "-")} />
                <Metric label="CRS Enabled" value={String(data.crs_enabled ?? "-")} />
                <Metric label="Rate Limit Enabled" value={String(data.rate_limit_enabled ?? "-")} />
                <Metric label="Bot Defense Enabled" value={String(data.bot_defense_enabled ?? "-")} />
                <Metric label="Semantic Mode" value={String(data.semantic_mode ?? "-")} />
                <Metric label="DB Enabled" value={String(data.db_enabled ?? "-")} />
                <Metric label="DB Retention Days" value={String(data.db_retention_days ?? "-")} />
                <Metric label="DB Rows (Total)" value={dbRows != null ? formatCount(dbRows) : "-"} />
                <Metric label="DB Rows (WAF Block)" value={dbWAFBlockRows != null ? formatCount(dbWAFBlockRows) : "-"} />
                <Metric label="DB Size" value={dbSizeBytes != null ? formatBytes(dbSizeBytes) : "-"} />
                <Metric label="DB Last Sync Scan Lines" value={String(data.db_last_sync_scanned_lines ?? "-")} />
            </div>

            <pre className="text-sm rounded-xl p-4 shadow-sm overflow-x-auto">
                {JSON.stringify(data, null, 2)}
            </pre>
        </div>
    );
}

function TopBuckets({ title, items }: { title: string; items: StatsBucket[] }) {
    return (
        <div className="rounded-xl border bg-white px-3 py-2">
            <div className="text-xs text-neutral-500">{title}</div>
            {items.length === 0 ? (
                <div className="mt-2 text-xs text-neutral-500">No data (last 24h)</div>
            ) : (
                <ul className="mt-2 space-y-1 text-xs font-mono">
                    {items.map((item) => (
                        <li key={`${title}:${item.key}`} className="flex items-center justify-between gap-2">
                            <span className="truncate">{item.key}</span>
                            <span className="text-neutral-500">{item.count.toLocaleString()}</span>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
}

function HourlyBars({ points }: { points: StatsSeriesPoint[] }) {
    const maxCount = points.reduce((max, point) => Math.max(max, point.count), 0);
    const start = points[0]?.bucket_start;
    const end = points[points.length - 1]?.bucket_start;

    return (
        <div className="rounded-xl border bg-white px-3 py-2">
            <div className="text-xs text-neutral-500">Blocked Requests by Hour</div>
            {points.length === 0 ? (
                <div className="mt-2 text-xs text-neutral-500">No data</div>
            ) : maxCount === 0 ? (
                <div className="mt-2 text-xs text-neutral-500">No blocked requests in selected range</div>
            ) : (
                <div className="mt-3">
                    <div className="h-28 flex items-end gap-1">
                        {points.map((point) => {
                            const height = Math.max(6, Math.round((point.count / maxCount) * 100));
                            return (
                                <div key={point.bucket_start} className="flex-1 min-w-0">
                                    <div
                                        className="w-full rounded-sm bg-red-400 hover:bg-red-500"
                                        style={{ height: `${height}%` }}
                                        title={`${formatTime(point.bucket_start)}: ${point.count}`}
                                    />
                                </div>
                            );
                        })}
                    </div>
                    <div className="mt-2 flex items-center justify-between text-[10px] text-neutral-500 font-mono">
                        <span>{formatShortTime(start)}</span>
                        <span>max {maxCount.toLocaleString()}</span>
                        <span>{formatShortTime(end)}</span>
                    </div>
                </div>
            )}
        </div>
    );
}

function Metric({ label, value }: { label: string; value: string }) {
    return (
        <div className="rounded-xl border bg-white px-3 py-2">
            <div className="text-xs text-neutral-500">{label}</div>
            <div className="font-mono text-xs mt-1 break-all">{value}</div>
        </div>
    );
}

function formatShortTime(value: string | undefined) {
    if (!value) {
        return "-";
    }
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) {
        return value;
    }
    return `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, "0")}:00`;
}

function formatCount(value: number | undefined) {
    if (typeof value !== "number" || Number.isNaN(value)) {
        return "-";
    }
    return value.toLocaleString();
}

function formatBytes(bytes: number) {
    if (!Number.isFinite(bytes) || bytes < 0) {
        return "-";
    }
    const units = ["B", "KB", "MB", "GB", "TB"];
    let value = bytes;
    let idx = 0;
    while (value >= 1024 && idx < units.length - 1) {
        value /= 1024;
        idx++;
    }
    const rounded = idx === 0 ? Math.round(value) : Math.round(value * 10) / 10;
    return `${rounded.toLocaleString()} ${units[idx]}`;
}

function toNumber(value: unknown): number | null {
    if (typeof value === "number" && Number.isFinite(value)) {
        return value;
    }
    if (typeof value === "string" && value.trim() !== "") {
        const n = Number(value);
        if (Number.isFinite(n)) {
            return n;
        }
    }
    return null;
}

function formatTime(value: string | undefined) {
    if (!value) {
        return "-";
    }
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) {
        return value;
    }
    return d.toLocaleString();
}
