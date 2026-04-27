import { useCallback, useEffect, useMemo, useState } from "react";
import { apiDeleteJson, apiGetJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { useI18n } from "@/lib/i18n";

type BackendRecord = {
  key: string;
  name: string;
  url: string;
  provider_class?: string;
  managed_by_vhost?: string;
  runtime_ops_supported?: boolean;
  admin_state?: string;
  health_state?: string;
  configured_weight?: number;
  weight_override?: number;
  effective_weight?: number;
  effective_selectable?: boolean;
  inflight?: number;
  checked_at?: string;
  last_status_code?: number;
  last_latency_ms?: number;
  last_error?: string;
};

type BackendsResponse = {
  path?: string;
  storage?: string;
  etag?: string;
  strategy?: string;
  updated_at?: string;
  backends?: BackendRecord[];
};

export default function BackendsPanel() {
  const { tx, locale } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [data, setData] = useState<BackendsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busyKey, setBusyKey] = useState("");
  const [weightDrafts, setWeightDrafts] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const next = await apiGetJson<BackendsResponse>("/proxy-backends");
      setData(next);
      const drafts: Record<string, string> = {};
      for (const backend of Array.isArray(next.backends) ? next.backends : []) {
        drafts[backend.key] = backend.weight_override && backend.weight_override > 0 ? String(backend.weight_override) : "";
      }
      setWeightDrafts(drafts);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const backends = useMemo(() => (Array.isArray(data?.backends) ? data!.backends! : []), [data]);

  async function updateOverride(backend: BackendRecord, payload: Record<string, unknown>, successMessage: string) {
    if (!data?.etag) return;
    setBusyKey(backend.key);
    setError("");
    setNotice("");
    try {
      const next = await apiPutJson<BackendsResponse>(
        `/proxy-backends/${encodeURIComponent(backend.key)}/runtime-override`,
        payload,
        { headers: { "If-Match": data.etag } },
      );
      setData(next);
      setNotice(successMessage);
      const drafts: Record<string, string> = {};
      for (const entry of Array.isArray(next.backends) ? next.backends : []) {
        drafts[entry.key] = entry.weight_override && entry.weight_override > 0 ? String(entry.weight_override) : "";
      }
      setWeightDrafts(drafts);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
      try {
        await load();
      } catch {
        //
      }
    } finally {
      setBusyKey("");
    }
  }

  async function clearOverride(backend: BackendRecord) {
    if (!data?.etag) return;
    setBusyKey(backend.key);
    setError("");
    setNotice("");
    try {
      const next = await apiDeleteJson<BackendsResponse>(
        `/proxy-backends/${encodeURIComponent(backend.key)}/runtime-override`,
        { headers: { "If-Match": data.etag } },
      );
      setData(next);
      setNotice(tx("Runtime override cleared."));
      const drafts: Record<string, string> = {};
      for (const entry of Array.isArray(next.backends) ? next.backends : []) {
        drafts[entry.key] = entry.weight_override && entry.weight_override > 0 ? String(entry.weight_override) : "";
      }
      setWeightDrafts(drafts);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
      try {
        await load();
      } catch {
        //
      }
    } finally {
      setBusyKey("");
    }
  }

  async function saveWeightOverride(backend: BackendRecord) {
    const raw = String(weightDrafts[backend.key] ?? "").trim();
    if (raw === "") {
      setError(tx("Enter a positive weight override or clear the override."));
      return;
    }
    const weight = Number(raw);
    if (!Number.isInteger(weight) || weight <= 0) {
      setError(tx("Weight override must be a positive integer."));
      return;
    }
    await updateOverride(backend, { weight_override: weight }, tx("Runtime weight override saved."));
  }

  if (loading) {
    return <div className="w-full p-4 text-neutral-500">{tx("Loading backend runtime state...")}</div>;
  }

  if (error && !data) {
    return (
      <div className="w-full p-4">
        <div className="rounded-xl border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800">{error}</div>
      </div>
    );
  }

  return (
    <div className="w-full p-4 space-y-4">
      <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <h1 className="text-xl font-semibold">{tx("Backends")}</h1>
            <p className="text-sm text-neutral-600">
              {tx("Inspect direct upstream backends used by routing. Runtime enable/drain/disable and weight overrides apply here; Runtime App targets stay on the Runtime Apps surface.")}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs text-neutral-600">
            {data?.etag ? <MonoTag label="ETag" value={data.etag} /> : null}
            <button type="button" onClick={() => void load()} disabled={busyKey !== ""}>
              {tx("Reload")}
            </button>
          </div>
        </div>
        <div className="grid gap-3 sm:grid-cols-3 text-sm">
          <Metric label={tx("Default Strategy")} value={String(data?.strategy || "-")} />
          <Metric label={tx("Runtime Storage")} value={String(data?.storage || data?.path || "-")} mono />
          <Metric label={tx("Last Refresh")} value={formatTime(data?.updated_at, locale)} />
        </div>
        {notice ? <div className="rounded border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-800">{notice}</div> : null}
        {error ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800">{error}</div> : null}
      </section>

      <div className="app-table-shell">
        <table className="app-table min-w-full text-sm">
          <thead className="app-table-head">
            <tr>
              <th>{tx("Backend")}</th>
              <th>{tx("State")}</th>
              <th>{tx("Weight")}</th>
              <th>{tx("InFlight")}</th>
              <th>{tx("Last Check")}</th>
              <th>{tx("Last Result")}</th>
              <th>{tx("Actions")}</th>
            </tr>
          </thead>
          <tbody>
            {backends.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-2 py-1 text-center text-neutral-500">
                  <div className="space-y-1 py-2">
                    <div>{tx("No direct upstream backends are configured.")}</div>
                    <div className="text-xs text-neutral-400">
                      {tx("Add direct backends in Proxy Rules > Upstreams, then return here for status and runtime operations.")}
                    </div>
                  </div>
                </td>
              </tr>
            ) : (
              backends.map((backend) => {
                const rowBusy = busyKey === backend.key;
                const runtimeOpsSupported = backendRuntimeOpsSupported(backend);
                return (
                  <tr key={backend.key}>
                    <td className="px-2 py-1">
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <div className="font-semibold">{backend.name || tx("unnamed")}</div>
                          <ProviderChip providerClass={backend.provider_class} />
                        </div>
                        <code className="text-xs text-neutral-600">{backend.url}</code>
                        {backend.managed_by_vhost ? (
                          <div className="text-xs text-neutral-500">
                            {tx("runtime app")} <code>{backend.managed_by_vhost}</code>
                          </div>
                        ) : null}
                        <div className="text-xs text-neutral-500">
                          {tx("key")} <code>{backend.key}</code>
                        </div>
                      </div>
                    </td>
                    <td className="px-2 py-1">
                      <div className="space-y-1">
                        <StateChip kind="admin" value={backend.admin_state || "enabled"} />
                        <StateChip kind="health" value={backend.health_state || "unknown"} />
                        <div className="text-xs text-neutral-500">
                          {backend.effective_selectable ? tx("selectable") : tx("not selectable")}
                        </div>
                      </div>
                    </td>
                    <td className="px-2 py-1">
                      <div className="space-y-2">
                        <div className="text-xs text-neutral-600">
                          {tx("configured")} {backend.configured_weight ?? 1} / {tx("effective")} {backend.effective_weight ?? backend.configured_weight ?? 1}
                        </div>
                        {runtimeOpsSupported ? (
                          <div className="flex items-center gap-2">
                            <input
                              type="number"
                              min={1}
                              value={weightDrafts[backend.key] ?? ""}
                              onChange={(event) =>
                                setWeightDrafts((prev) => ({ ...prev, [backend.key]: event.target.value }))
                              }
                              className="w-24"
                              placeholder={tx("override")}
                              disabled={readOnly || rowBusy}
                            />
                            <button
                              type="button"
                              onClick={() => void saveWeightOverride(backend)}
                              disabled={readOnly || rowBusy}
                            >
                              {tx("Set weight")}
                            </button>
                          </div>
                        ) : (
                          <div className="text-xs text-neutral-500">
                            {tx("Runtime weight overrides are available only for direct named upstreams in this slice.")}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-2 py-1">{backend.inflight ?? 0}</td>
                    <td className="px-2 py-1">{formatTime(backend.checked_at, locale)}</td>
                    <td className="px-2 py-1">
                      <div className="space-y-1 text-xs">
                        <div>
                          {backend.last_status_code ? `${backend.last_status_code}` : "-"}
                          {backend.last_latency_ms ? ` / ${backend.last_latency_ms}ms` : ""}
                        </div>
                        {backend.last_error ? <div className="text-red-700">{backend.last_error}</div> : <div className="text-neutral-500">-</div>}
                      </div>
                    </td>
                    <td className="px-2 py-1">
                      {runtimeOpsSupported ? (
                        <div className="flex flex-wrap gap-2">
                          <button
                            type="button"
                            onClick={() => void updateOverride(backend, { admin_state: "enabled" }, tx("Backend enabled."))}
                            disabled={readOnly || rowBusy}
                          >
                            {tx("Enable")}
                          </button>
                          <button
                            type="button"
                            onClick={() => void updateOverride(backend, { admin_state: "draining" }, tx("Backend set to draining."))}
                            disabled={readOnly || rowBusy}
                          >
                            {tx("Drain")}
                          </button>
                          <button
                            type="button"
                            onClick={() => void updateOverride(backend, { admin_state: "disabled" }, tx("Backend disabled."))}
                            disabled={readOnly || rowBusy}
                          >
                            {tx("Disable")}
                          </button>
                          <button type="button" onClick={() => void clearOverride(backend)} disabled={readOnly || rowBusy}>
                            {tx("Clear override")}
                          </button>
                        </div>
                      ) : (
                        <div className="text-xs text-neutral-500">
                          {tx("Status only in this slice. Runtime enable/drain/disable stays on direct named upstreams.")}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function backendRuntimeOpsSupported(backend: BackendRecord) {
  if (typeof backend.runtime_ops_supported === "boolean") {
    return backend.runtime_ops_supported;
  }
  return String(backend.provider_class || "").trim().toLowerCase() !== "vhost_managed";
}

function ProviderChip({ providerClass }: { providerClass?: string }) {
  const normalized = String(providerClass || "").trim().toLowerCase();
  const label = normalized === "vhost_managed" ? "runtime-app" : "direct";
  const className =
    normalized === "vhost_managed"
      ? "inline-flex rounded px-2 py-0.5 text-xs font-semibold bg-sky-100 text-sky-800"
      : "inline-flex rounded px-2 py-0.5 text-xs font-semibold bg-neutral-100 text-neutral-700";
  return <span className={className}>{label}</span>;
}

function Metric({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2">
      <div className="text-xs uppercase tracking-wide text-neutral-500">{label}</div>
      <div className={mono ? "mt-1 font-mono text-xs break-all" : "mt-1"}>{value || "-"}</div>
    </div>
  );
}

function MonoTag({ label, value }: { label: string; value: string }) {
  return (
    <span className="rounded bg-neutral-100 px-2 py-1 font-mono text-xs text-neutral-700">
      {label} {value}
    </span>
  );
}

function StateChip({ kind, value }: { kind: "admin" | "health"; value: string }) {
  const normalized = String(value || "").trim().toLowerCase();
  let className = "inline-flex rounded px-2 py-0.5 text-xs font-semibold bg-neutral-100 text-neutral-800";
  if (normalized === "enabled" || normalized === "healthy") {
    className = "inline-flex rounded px-2 py-0.5 text-xs font-semibold bg-green-100 text-green-800";
  } else if (normalized === "draining" || normalized === "unknown") {
    className = "inline-flex rounded px-2 py-0.5 text-xs font-semibold bg-amber-100 text-amber-900";
  } else if (normalized === "disabled" || normalized === "unhealthy") {
    className = "inline-flex rounded px-2 py-0.5 text-xs font-semibold bg-red-100 text-red-800";
  }
  return <span className={className}>{kind === "admin" ? `admin:${normalized}` : `health:${normalized}`}</span>;
}

function formatTime(raw: string | undefined, locale: string) {
  const trimmed = String(raw || "").trim();
  if (!trimmed) {
    return "-";
  }
  const at = new Date(trimmed);
  if (Number.isNaN(at.getTime())) {
    return trimmed;
  }
  return at.toLocaleString(locale === "ja" ? "ja-JP" : "en-US");
}
