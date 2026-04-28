import { useEffect, useMemo, useState } from 'react';
import { apiGetJson } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

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
    const { locale, tx } = useI18n();
    const [data, setData] = useState<StatusResponse | null>(null);
    const [error, setError] = useState<string | null>(null);
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
    const listenerMode = String(data?.listener_mode ?? "single");
    const adminListenerEnabled = data?.admin_listener_enabled === true;

    if (error) {
        return (
            <div className="w-full p-4">
                <div className="border border-red-300 bg-red-50 rounded-xl p-3 text-sm">{tx("Error")}: {error}</div>
            </div>
        );
    }

    if (!data) {
        return <div className="w-full p-4 text-gray-500">{tx("Loading status...")}</div>;
    }

    return (
        <div className="w-full p-4 space-y-4">
            <header className="flex items-center justify-between">
                <h1 className="text-xl font-semibold">{tx("Status")}</h1>
                <span
                    className={`px-2 py-0.5 text-xs rounded ${
                        running ? "bg-green-100 text-green-800" : "bg-amber-100 text-amber-800"
                    }`}
                >
                    {running ? tx("Running") : tx("Degraded")}
                </span>
            </header>

            <div className="rounded-xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-xs text-neutral-700">
                {listenerMode === "split"
                    ? tx("Split listener mode is active. Public proxy traffic stays on the public listener, while admin UI/API move to the admin listener over plain HTTP. Use a trusted network or front-proxy TLS termination for the admin port.")
                    : tx("Single listener mode is active. Public proxy traffic and admin UI/API share the same listener, and admin reachability is controlled by admin.external_mode and trusted CIDRs.")}
            </div>

            {stats ? (
      <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                        <h2 className="text-sm font-semibold">{tx("WAF Block Overview ({hours}h)", { hours: stats.range_hours })}</h2>
                        <div className="flex items-center gap-3 text-xs text-neutral-500">
                            <label className="inline-flex items-center gap-1">
                                {tx("Range")}
                                <select
                                    value={rangeHours}
                                    onChange={(e) => setRangeHours(Number(e.target.value))}
                className="rounded border border-neutral-200 px-1 py-0.5 text-xs bg-white text-neutral-700"
                                >
                                    <option value={24}>24h</option>
                                    <option value={72}>72h</option>
                                    <option value={168}>168h</option>
                                </select>
                            </label>
                            <span>
                                {tx("Scanned {lines} lines · Updated {time}", {
                                    lines: formatCount(stats.scanned_lines),
                                    time: formatTime(stats.generated_at, locale),
                                })}
                            </span>
                        </div>
                    </div>

                    <div className="grid gap-3 sm:grid-cols-3 text-sm">
                        <Metric label={tx("Blocked (Last 1h)")} value={formatCount(wafBlock?.last_1h)} />
                        <Metric label={tx("Blocked (Last 24h)")} value={formatCount(wafBlock?.last_24h)} />
                        <Metric label={tx("Blocked (In Scan Window)")} value={formatCount(wafBlock?.total_in_scan)} />
                    </div>

                    <HourlyBars points={wafBlock?.series_hourly ?? []} locale={locale} tx={tx} />

                    {stats.oldest_scanned_ts && stats.newest_scanned_ts ? (
                        <div className="text-xs text-neutral-500">
                            {tx("Scan coverage: {start} - {end}", {
                                start: formatTime(stats.oldest_scanned_ts, locale),
                                end: formatTime(stats.newest_scanned_ts, locale),
                            })}
                        </div>
                    ) : null}

                    <div className="grid gap-3 lg:grid-cols-3">
                        <TopBuckets title={tx("Top Rule IDs (24h)")} items={wafBlock?.top_rule_ids_24h ?? []} tx={tx} />
                        <TopBuckets title={tx("Top Paths (24h)")} items={wafBlock?.top_paths_24h ?? []} tx={tx} />
                        <TopBuckets title={tx("Top Countries (24h)")} items={wafBlock?.top_countries_24h ?? []} tx={tx} />
                    </div>
                </section>
            ) : null}

            {statsLoading ? (
                <div className="text-xs text-neutral-500">{tx("Updating WAF block stats...")}</div>
            ) : null}

            {statsError ? (
                <div className="rounded-xl border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-800">
                    {tx("Failed to load WAF block stats: {error}", { error: statsError })}
                </div>
            ) : null}

            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-sm">
                <Metric label={tx("Listener Mode")} value={listenerMode} />
                <Metric label={tx("Public Listener")} value={String(data.public_listener_addr ?? data.listen_addr ?? "-")} />
                <Metric label={tx("Admin Listener Enabled")} value={String(adminListenerEnabled)} />
                <Metric label={tx("Admin Listener")} value={String(data.admin_listener_addr ?? "-")} />
                <Metric label={tx("Admin Listener Transport")} value={String(data.admin_listener_transport ?? "-")} />
                <Metric label={tx("Public PROXY Protocol")} value={String(data.public_listener_proxy_protocol_enabled ?? "-")} />
                <Metric label={tx("Admin PROXY Protocol")} value={String(data.admin_listener_proxy_protocol_enabled ?? "-")} />
                <Metric label={tx("Public TLS Enabled")} value={String(data.public_listener_tls_enabled ?? data.server_tls_enabled ?? "-")} />
                <Metric label={tx("API Base")} value={String(data.api_base ?? "-")} />
                <Metric label={tx("Site Config Storage")} value={String(data.site_config_storage ?? "-")} />
                <Metric label={tx("Scheduled Task Config Storage")} value={String(data.scheduled_task_config_storage ?? "-")} />
                <Metric label={tx("Upstream Runtime Storage")} value={String(data.upstream_runtime_storage ?? "-")} />
                <Metric label={tx("Country Resolution Mode")} value={String(data.request_country_effective_mode ?? "-")} />
                <Metric label={tx("Country DB Loaded")} value={String(data.request_country_loaded ?? "-")} />
                <Metric label={tx("Country DB Path")} value={String(data.request_country_managed_path ?? "-")} />
                <Metric label={tx("Base Rule Asset")} value={String(data.rules_file ?? "-")} />
                <Metric label={tx("Proxy Upstream KeepAlive (sec)")} value={String(data.proxy_upstream_keepalive_sec ?? "-")} />
                <Metric label={tx("CRS Enabled")} value={String(data.crs_enabled ?? "-")} />
                <Metric label={tx("Rate Limit Enabled")} value={String(data.rate_limit_enabled ?? "-")} />
                <Metric label={tx("Bot Defense Enabled")} value={String(data.bot_defense_enabled ?? "-")} />
                <Metric label={tx("Semantic Mode")} value={String(data.semantic_mode ?? "-")} />
                <Metric label={tx("DB Retention Days")} value={String(data.db_retention_days ?? "-")} />
                <Metric label={tx("DB Rows (Total)")} value={dbRows != null ? formatCount(dbRows) : "-"} />
                <Metric label={tx("DB Rows (WAF Block)")} value={dbWAFBlockRows != null ? formatCount(dbWAFBlockRows) : "-"} />
                <Metric label={tx("DB Size")} value={dbSizeBytes != null ? formatBytes(dbSizeBytes) : "-"} />
                <Metric label={tx("DB Last Sync Scan Lines")} value={String(data.db_last_sync_scanned_lines ?? "-")} />
            </div>

      <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
                <div className="flex items-center justify-between gap-2">
                    <h2 className="text-sm font-semibold">{tx("Rendered JSON")}</h2>
                    <span className="text-xs text-neutral-500">{tx("Latest status payload")}</span>
                </div>
                <div className="app-code-shell">
                    <pre className="app-code-block">
                        {JSON.stringify(data, null, 2)}
                    </pre>
                </div>
            </section>
        </div>
    );
}

function TopBuckets({
    title,
    items,
    tx,
}: {
    title: string;
    items: StatsBucket[];
    tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
}) {
    return (
                  <div className="rounded-xl border border-neutral-200 bg-white px-3 py-2">
            <div className="text-xs text-neutral-500">{title}</div>
            {items.length === 0 ? (
                <div className="mt-2 text-xs text-neutral-500">{tx("No data (last 24h)")}</div>
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

function HourlyBars({
    points,
    locale,
    tx,
}: {
    points: StatsSeriesPoint[];
    locale: "en" | "ja";
    tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
}) {
    const maxCount = points.reduce((max, point) => Math.max(max, point.count), 0);
    const start = points[0]?.bucket_start;
    const end = points[points.length - 1]?.bucket_start;
    const chartHeightPx = 112;

    return (
                        <div className="rounded-xl border border-neutral-200 bg-white px-3 py-2">
            <div className="text-xs text-neutral-500">{tx("Blocked Requests by Hour")}</div>
            {points.length === 0 ? (
                <div className="mt-2 text-xs text-neutral-500">{tx("No data")}</div>
            ) : maxCount === 0 ? (
                <div className="mt-2 text-xs text-neutral-500">{tx("No blocked requests in selected range")}</div>
            ) : (
                <div className="mt-3">
                    <div className="h-28 flex items-end gap-1">
                        {points.map((point) => {
                            const height = point.count > 0
                                ? Math.max(6, Math.round((point.count / maxCount) * chartHeightPx))
                                : 0;
                            const tooltipLabel = `${formatHourTooltipTime(point.bucket_start, locale)} · ${formatCount(point.count)}`;
                            return (
                                <div key={point.bucket_start} className="group relative flex h-full flex-1 min-w-0 items-end">
                                    <div
                                        className="w-full rounded-sm bg-red-400 hover:bg-red-500"
                                        style={{ height: `${height}px` }}
                                        title={point.count > 0 ? tooltipLabel : undefined}
                                    />
                                    {point.count > 0 ? (
                                        <div className="pointer-events-none absolute bottom-full left-1/2 z-10 mb-2 hidden -translate-x-1/2 whitespace-nowrap rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-[10px] font-mono text-white shadow-lg group-hover:block">
                                            {tooltipLabel}
                                        </div>
                                    ) : null}
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
                        <div className="rounded-xl border border-neutral-200 bg-white px-3 py-2">
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

function formatHourTooltipTime(value: string | undefined, locale: "en" | "ja" = "en") {
    if (!value) {
        return "-";
    }
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) {
        return value;
    }
    return d.toLocaleString(locale === "ja" ? "ja-JP" : "en-US", {
        year: "numeric",
        month: "numeric",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    });
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

function formatTime(value: string | undefined, locale: "en" | "ja" = "en") {
    if (!value) {
        return "-";
    }
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) {
        return value;
    }
    return d.toLocaleString(locale === "ja" ? "ja-JP" : "en-US");
}
