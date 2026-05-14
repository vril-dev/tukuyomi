import { useEffect, useMemo, useState } from 'react';
import { apiGetBinary, apiGetJson } from "@/lib/api";
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

type SecurityFamilyKey =
    | "waf"
    | "rate_limit"
    | "country_block"
    | "route_access"
    | "bot_defense"
    | "semantic"
    | "ip_reputation";

type SecurityFamilyBucket = {
    family: SecurityFamilyKey;
    label: string;
    count: number;
};

type SecurityBlockBucket = {
    family: SecurityFamilyKey;
    event: string;
    key: string;
    label: string;
    count: number;
};

type SecuritySeriesPoint = {
    bucket_start: string;
    total: number;
    waf: number;
    rate_limit: number;
    country_block: number;
    route_access: number;
    bot_defense: number;
    semantic: number;
    ip_reputation: number;
};

type SecurityBlockStats = {
    last_1h: number;
    last_24h: number;
    total_in_scan: number;
    by_family_24h: SecurityFamilyBucket[];
    by_family_range?: SecurityFamilyBucket[];
    top_blocks_24h: SecurityBlockBucket[];
    top_blocks_range?: SecurityBlockBucket[];
    top_paths_24h: StatsBucket[];
    top_paths_range?: StatsBucket[];
    top_countries_24h: StatsBucket[];
    top_countries_range?: StatsBucket[];
    series_hourly: SecuritySeriesPoint[];
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
    security_blocks?: SecurityBlockStats;
};

const SECURITY_FAMILIES: Array<{
    key: SecurityFamilyKey;
    label: string;
    color: string;
    soft: string;
    text: string;
}> = [
    { key: "waf", label: "WAF", color: "#ef4444", soft: "#fee2e2", text: "#991b1b" },
    { key: "rate_limit", label: "Rate Limit", color: "#f97316", soft: "#ffedd5", text: "#9a3412" },
    { key: "country_block", label: "Country Block", color: "#0ea5e9", soft: "#e0f2fe", text: "#075985" },
    { key: "route_access", label: "Route Access", color: "#0f766e", soft: "#ccfbf1", text: "#134e4a" },
    { key: "bot_defense", label: "Bot Defense", color: "#8b5cf6", soft: "#ede9fe", text: "#5b21b6" },
    { key: "semantic", label: "Semantic Security", color: "#10b981", soft: "#d1fae5", text: "#065f46" },
    { key: "ip_reputation", label: "IP Reputation", color: "#64748b", soft: "#e2e8f0", text: "#334155" },
];

export default function Status() {
    const { locale, tx } = useI18n();
    const [data, setData] = useState<StatusResponse | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [stats, setStats] = useState<LogsStatsResponse | null>(null);
    const [statsError, setStatsError] = useState<string | null>(null);
    const [statsLoading, setStatsLoading] = useState(false);
    const [configDownloading, setConfigDownloading] = useState(false);
    const [configDownloadError, setConfigDownloadError] = useState<string | null>(null);
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
    const securityBlocks = stats?.security_blocks;
    const securityRangeFamilies = securityBlocks?.by_family_range ?? securityBlocks?.by_family_24h ?? [];
    const securityRangeTopBlocks = securityBlocks?.top_blocks_range ?? securityBlocks?.top_blocks_24h ?? [];
    const securityRangeTopPaths = securityBlocks?.top_paths_range ?? securityBlocks?.top_paths_24h ?? [];
    const securityRangeTopCountries = securityBlocks?.top_countries_range ?? securityBlocks?.top_countries_24h ?? [];
    const activeSecurityFamilies = securityRangeFamilies.filter((item) => item.count > 0).length;
    const dbSizeBytes = toNumber(data?.db_size_bytes);
    const dbRows = toNumber(data?.db_total_rows);
    const dbWAFBlockRows = toNumber(data?.db_waf_block_rows);
    const listenerMode = String(data?.listener_mode ?? "single");
    const adminListenerEnabled = data?.admin_listener_enabled === true;

    if (error) {
        return (
            <div className="w-full p-4">
                <div className="border border-red-300 bg-red-50 rounded-xl p-3 text-xs">{tx("Error")}: {error}</div>
            </div>
        );
    }

    if (!data) {
        return <div className="w-full p-4 text-gray-500">{tx("Loading status...")}</div>;
    }

    async function downloadConfigBundle() {
        setConfigDownloading(true);
        setConfigDownloadError(null);
        try {
            const { blob, filename } = await apiGetBinary("/status/config-bundle");
            const a = document.createElement("a");
            const url = URL.createObjectURL(blob);
            a.href = url;
            a.download = filename || "tukuyomi-config-bundle.json";
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : String(err);
            setConfigDownloadError(message);
        } finally {
            setConfigDownloading(false);
        }
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

            {stats && securityBlocks ? (
                <section className="overflow-hidden rounded-xl border border-neutral-200 bg-white">
                    <div className="border-b border-neutral-200 bg-neutral-50 px-4 py-3">
                        <div className="flex flex-wrap items-center justify-between gap-3">
                            <div>
                                <div className="inline-flex items-center gap-2 text-[10px] font-semibold uppercase text-neutral-500">
                                    <span className="h-2 w-2 rounded-full bg-emerald-500" />
                                    {tx("Security Controls")}
                                </div>
                                <h2 className="mt-1 text-sm font-semibold text-neutral-950">
                                    {tx("Security Control Overview ({hours}h)", { hours: stats.range_hours })}
                                </h2>
                            </div>
                            <div className="flex items-center gap-3 text-xs text-neutral-600">
                                <label className="inline-flex items-center gap-1">
                                    {tx("Range")}
                                    <select
                                        value={rangeHours}
                                        onChange={(e) => setRangeHours(Number(e.target.value))}
                                        className="rounded border border-neutral-300 bg-white px-2 py-1 text-xs text-neutral-900 shadow-sm"
                                    >
                                        <option value={24}>24h</option>
                                        <option value={72}>72h</option>
                                        <option value={168}>168h</option>
                                    </select>
                                </label>
                                <span className="text-neutral-500">
                                    {tx("Scanned {lines} lines · Updated {time}", {
                                        lines: formatCount(stats.scanned_lines),
                                        time: formatTime(stats.generated_at, locale),
                                    })}
                                </span>
                            </div>
                        </div>
                    </div>

                    <div className="space-y-4 p-4">
                        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-xs">
                            <Metric label={tx("Blocked (Last 1h)")} value={formatCount(securityBlocks.last_1h)} />
                            <Metric label={tx("Blocked (Last 24h)")} value={formatCount(securityBlocks.last_24h)} />
                            <Metric label={tx("Blocked (In Scan Window)")} value={formatCount(securityBlocks.total_in_scan)} />
                            <Metric label={tx("Active Controls ({hours}h)", { hours: stats.range_hours })} value={formatCount(activeSecurityFamilies)} />
                        </div>

                        <SecurityFamilyStrip items={securityRangeFamilies} tx={tx} />

                        <SecurityStackedBars points={securityBlocks.series_hourly ?? []} locale={locale} tx={tx} />

                        {stats.oldest_scanned_ts && stats.newest_scanned_ts ? (
                            <div className="text-xs text-neutral-500">
                                {tx("Scan coverage: {start} - {end}", {
                                    start: formatTime(stats.oldest_scanned_ts, locale),
                                    end: formatTime(stats.newest_scanned_ts, locale),
                                })}
                            </div>
                        ) : null}

                        <div className="grid gap-3 lg:grid-cols-3">
                            <TopSecurityBlocks title={tx("Top Blocks ({hours}h)", { hours: stats.range_hours })} items={securityRangeTopBlocks} tx={tx} />
                            <TopBuckets title={tx("Top Blocked Paths ({hours}h)", { hours: stats.range_hours })} items={securityRangeTopPaths} tx={tx} />
                            <TopBuckets title={tx("Top Blocked Countries ({hours}h)", { hours: stats.range_hours })} items={securityRangeTopCountries} tx={tx} />
                        </div>

                        <div className="grid gap-3 lg:grid-cols-3">
                            <TopBuckets title={tx("WAF Rule IDs (24h)")} items={wafBlock?.top_rule_ids_24h ?? []} tx={tx} />
                            <Metric label={tx("WAF Blocks (24h)")} value={formatCount(wafBlock?.last_24h)} />
                            <Metric label={tx("WAF Blocks (In Scan Window)")} value={formatCount(wafBlock?.total_in_scan)} />
                        </div>
                    </div>
                </section>
            ) : null}

            {statsLoading ? (
                <div className="text-xs text-neutral-500">{tx("Updating security stats...")}</div>
            ) : null}

            {statsError ? (
                <div className="rounded-xl border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-800">
                    {tx("Failed to load security stats: {error}", { error: statsError })}
                </div>
            ) : null}

            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-xs">
                <Metric label={tx("Listener Mode")} value={listenerMode} />
                <Metric label={tx("Public Listener")} value={String(data.public_listener_addr ?? data.listen_addr ?? "-")} />
                <Metric label={tx("Admin Listener Enabled")} value={String(adminListenerEnabled)} />
                <Metric label={tx("Admin Listener")} value={String(data.admin_listener_addr ?? "-")} />
                <Metric label={tx("Admin Listener Transport")} value={String(data.admin_listener_transport ?? "-")} />
                <Metric label={tx("Public PROXY Protocol")} value={String(data.public_listener_proxy_protocol_enabled ?? "-")} />
                <Metric label={tx("Admin PROXY Protocol")} value={String(data.admin_listener_proxy_protocol_enabled ?? "-")} />
                <Metric label={tx("Public TLS Enabled")} value={String(data.public_listener_tls_enabled ?? data.server_tls_enabled ?? "-")} />
                <Metric label={tx("Public HTTP/2 Advertised")} value={String(data.server_http2_advertised ?? "-")} />
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
                <Metric label={tx("Hot Log Retention Days")} value={String(data.hot_log_retention_days ?? "-")} />
                <Metric label={tx("DB Rows (Total)")} value={dbRows != null ? formatCount(dbRows) : "-"} />
                <Metric label={tx("DB Rows (WAF Block)")} value={dbWAFBlockRows != null ? formatCount(dbWAFBlockRows) : "-"} />
                <Metric label={tx("DB Size")} value={dbSizeBytes != null ? formatBytes(dbSizeBytes) : "-"} />
                <Metric label={tx("DB Last Sync Scan Lines")} value={String(data.db_last_sync_scanned_lines ?? "-")} />
            </div>

            <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                        <h2 className="text-sm font-semibold">{tx("Config bundle")}</h2>
                        <p className="mt-1 text-xs text-neutral-500">{tx("Download a redacted single-file config seed from the current DB-backed runtime config.")}</p>
                    </div>
                    <button
                        type="button"
                        className="rounded border border-neutral-300 bg-white px-3 py-2 text-xs font-semibold hover:bg-neutral-50 disabled:cursor-not-allowed disabled:text-neutral-400"
                        onClick={downloadConfigBundle}
                        disabled={configDownloading}
                    >
                        {configDownloading ? tx("Downloading...") : tx("Download config")}
                    </button>
                </div>
                {configDownloadError ? (
                    <div className="rounded border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">
                        {tx("Config download failed: {message}", { message: configDownloadError })}
                    </div>
                ) : null}
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

function TopSecurityBlocks({
    title,
    items,
    tx,
}: {
    title: string;
    items: SecurityBlockBucket[];
    tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
}) {
    return (
        <div className="rounded-xl border border-neutral-200 bg-white px-3 py-2">
            <div className="text-xs text-neutral-500">{title}</div>
            {items.length === 0 ? (
                <div className="mt-2 text-xs text-neutral-500">{tx("No data (last 24h)")}</div>
            ) : (
                <ul className="mt-2 space-y-2 text-xs">
                    {items.map((item) => {
                        const family = securityFamilyMeta(item.family);
                        return (
                            <li key={`${item.family}:${item.event}:${item.key}`} className="flex items-center justify-between gap-2">
                                <span className="min-w-0">
                                    <span
                                        className="mr-2 inline-block h-2.5 w-2.5 rounded-sm align-middle"
                                        style={{ backgroundColor: family.color }}
                                    />
                                    <span className="font-mono">{item.label}</span>
                                </span>
                                <span className="shrink-0 font-mono text-neutral-500">{item.count.toLocaleString()}</span>
                            </li>
                        );
                    })}
                </ul>
            )}
        </div>
    );
}

function SecurityFamilyStrip({
    items,
    tx,
}: {
    items: SecurityFamilyBucket[];
    tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
}) {
    const counts = new Map(items.map((item) => [item.family, item.count]));
    return (
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
            {SECURITY_FAMILIES.map((family) => {
                const count = counts.get(family.key) ?? 0;
                return (
                    <div
                        key={family.key}
                        className="rounded-xl border px-3 py-2"
                        style={{ borderColor: family.soft, backgroundColor: count > 0 ? family.soft : "#ffffff" }}
                    >
                        <div className="flex items-center gap-2">
                            <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: family.color }} />
                            <span className="truncate text-[11px] font-semibold" style={{ color: count > 0 ? family.text : "#525252" }}>
                                {tx(family.label)}
                            </span>
                        </div>
                        <div className="mt-2 font-mono text-sm" style={{ color: count > 0 ? family.text : "#737373" }}>
                            {formatCount(count)}
                        </div>
                    </div>
                );
            })}
        </div>
    );
}

function SecurityStackedBars({
    points,
    locale,
    tx,
}: {
    points: SecuritySeriesPoint[];
    locale: "en" | "ja";
    tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
}) {
    const maxCount = points.reduce((max, point) => Math.max(max, point.total), 0);
    const start = points[0]?.bucket_start;
    const end = points[points.length - 1]?.bucket_start;
    const chartHeightPx = 132;

    return (
        <div className="rounded-xl border border-neutral-200 bg-white px-3 py-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs text-neutral-500">{tx("Blocked Requests by Control")}</div>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-neutral-500">
                    {SECURITY_FAMILIES.map((family) => (
                        <span key={`legend-${family.key}`} className="inline-flex items-center gap-1">
                            <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: family.color }} />
                            {tx(family.label)}
                        </span>
                    ))}
                </div>
            </div>
            {points.length === 0 ? (
                <div className="mt-2 text-xs text-neutral-500">{tx("No data")}</div>
            ) : maxCount === 0 ? (
                <div className="mt-2 text-xs text-neutral-500">{tx("No blocked requests in selected range")}</div>
            ) : (
                <div className="mt-3">
                    <div className="flex h-32 items-end gap-1">
                        {points.map((point) => {
                            const totalHeight = point.total > 0
                                ? Math.max(6, Math.round((point.total / maxCount) * chartHeightPx))
                                : 0;
                            const tooltipLabel = securityPointTooltip(point, locale, tx);
                            return (
                                <div key={point.bucket_start} className="group relative flex h-full flex-1 min-w-0 items-end">
                                    <div
                                        className="flex w-full flex-col-reverse overflow-hidden rounded-sm bg-neutral-100"
                                        style={{ height: `${totalHeight}px` }}
                                        title={point.total > 0 ? tooltipLabel : undefined}
                                    >
                                        {SECURITY_FAMILIES.map((family) => {
                                            const count = point[family.key] ?? 0;
                                            const height = point.total > 0 ? Math.max(1, Math.round((count / point.total) * totalHeight)) : 0;
                                            return count > 0 ? (
                                                <div
                                                    key={`${point.bucket_start}:${family.key}`}
                                                    style={{ height: `${height}px`, backgroundColor: family.color }}
                                                />
                                            ) : null;
                                        })}
                                    </div>
                                    {point.total > 0 ? (
                                        <div className="pointer-events-none absolute bottom-full left-1/2 z-10 mb-2 hidden -translate-x-1/2 whitespace-pre rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-[10px] font-mono text-white shadow-lg group-hover:block">
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

function securityFamilyMeta(family: SecurityFamilyKey) {
    return SECURITY_FAMILIES.find((item) => item.key === family) ?? SECURITY_FAMILIES[0];
}

function securityPointTooltip(
    point: SecuritySeriesPoint,
    locale: "en" | "ja",
    tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string,
) {
    const lines = [`${formatHourTooltipTime(point.bucket_start, locale)} · ${formatCount(point.total)}`];
    for (const family of SECURITY_FAMILIES) {
        const count = point[family.key] ?? 0;
        if (count > 0) {
            lines.push(`${tx(family.label)}: ${formatCount(count)}`);
        }
    }
    return lines.join("\n");
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
