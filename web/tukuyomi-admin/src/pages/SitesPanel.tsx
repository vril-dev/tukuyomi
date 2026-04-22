import { useCallback, useEffect, useMemo, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";

type SiteTLSMode = "legacy" | "manual" | "acme";

type SiteEntry = {
  name: string;
  enabled: boolean;
  hosts: string[];
  default_upstream: string;
  tls: {
    mode: SiteTLSMode;
    cert_file?: string;
    key_file?: string;
  };
};

type SiteStatus = {
  name: string;
  enabled: boolean;
  hosts?: string[];
  default_upstream?: string;
  tls_mode?: string;
  tls_status?: string;
  tls_warning?: string;
  tls_cert_not_after?: string;
  generated_route?: string;
};

type SitesResponse = {
  etag?: string;
  raw?: string;
  sites?: {
    sites?: SiteEntry[];
  };
  site_statuses?: SiteStatus[];
  rollback_depth?: number;
};

function createEmptySite(index: number): SiteEntry {
  return {
    name: `site-${index}`,
    enabled: true,
    hosts: [],
    default_upstream: "http://app.internal:8080",
    tls: {
      mode: "legacy",
      cert_file: "",
      key_file: "",
    },
  };
}

function normalizeSites(sites: SiteEntry[]): SiteEntry[] {
  return sites.map((site) => ({
    name: site.name.trim(),
    enabled: !!site.enabled,
    hosts: site.hosts.map((host) => host.trim()).filter(Boolean),
    default_upstream: site.default_upstream.trim(),
    tls: {
      mode: site.tls.mode,
      cert_file: site.tls.cert_file?.trim() ?? "",
      key_file: site.tls.key_file?.trim() ?? "",
    },
  }));
}

function sitesToRaw(sites: SiteEntry[]) {
  const normalized = normalizeSites(sites).map((site) => ({
    name: site.name,
    enabled: site.enabled,
    hosts: site.hosts,
    default_upstream: site.default_upstream,
    tls: {
      mode: site.tls.mode,
      ...(site.tls.mode === "manual" && site.tls.cert_file ? { cert_file: site.tls.cert_file } : {}),
      ...(site.tls.mode === "manual" && site.tls.key_file ? { key_file: site.tls.key_file } : {}),
    },
  }));
  return JSON.stringify({ sites: normalized }, null, 2);
}

function parseSitesResponse(data?: SitesResponse): SiteEntry[] {
  if (data?.sites?.sites) {
    return data.sites.sites.map((site, index) => ({
      ...createEmptySite(index + 1),
      ...site,
      enabled: site.enabled !== false,
      hosts: Array.isArray(site.hosts) ? site.hosts : [],
      tls: {
        mode: (site.tls?.mode ?? "legacy") as SiteTLSMode,
        cert_file: site.tls?.cert_file ?? "",
        key_file: site.tls?.key_file ?? "",
      },
    }));
  }
  return [];
}

function stringListToMultiline(values: string[]) {
  return values.join("\n");
}

function multilineToStringList(value: string) {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function SitesPanel() {
  const { tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [etag, setETag] = useState("");
  const [sites, setSites] = useState<SiteEntry[]>([]);
  const [statuses, setStatuses] = useState<SiteStatus[]>([]);
  const [rollbackDepth, setRollbackDepth] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const rawPreview = useMemo(() => sitesToRaw(sites), [sites]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await apiGetJson<SitesResponse>("/sites");
      setETag(data.etag ?? "");
      setSites(parseSitesResponse(data));
      setStatuses(Array.isArray(data.site_statuses) ? data.site_statuses : []);
      setRollbackDepth(typeof data.rollback_depth === "number" ? data.rollback_depth : 0);
      setNotice("");
    } catch (error: unknown) {
      setError(getErrorMessage(error, tx("Failed to load")));
    } finally {
      setLoading(false);
    }
  }, [tx]);

  useEffect(() => {
    void load();
  }, [load]);

  const updateSite = useCallback((index: number, next: SiteEntry) => {
    setSites((current) => current.map((site, siteIndex) => (siteIndex === index ? next : site)));
  }, []);

  const runValidate = useCallback(async () => {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const out = await apiPostJson<{ ok: boolean; site_statuses?: SiteStatus[] }>("/sites/validate", { raw: rawPreview });
      setStatuses(Array.isArray(out.site_statuses) ? out.site_statuses : []);
      setNotice(tx("Validation passed."));
    } catch (error: unknown) {
      setError(getErrorMessage(error, tx("Validation failed.")));
    } finally {
      setSaving(false);
    }
  }, [rawPreview, tx]);

  const runApply = useCallback(async () => {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const out = await apiPutJson<{ etag?: string; site_statuses?: SiteStatus[]; sites?: { sites?: SiteEntry[] } }>(
        "/sites",
        { raw: rawPreview },
        { headers: { "If-Match": etag } },
      );
      setETag(out.etag ?? "");
      setSites(parseSitesResponse(out));
      setStatuses(Array.isArray(out.site_statuses) ? out.site_statuses : []);
      setNotice(tx("Saved. Site config applied."));
    } catch (error: unknown) {
      setError(getErrorMessage(error, tx("Save failed")));
    } finally {
      setSaving(false);
    }
  }, [etag, rawPreview, tx]);

  const runRollback = useCallback(async () => {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const out = await apiPostJson<{ etag?: string; site_statuses?: SiteStatus[]; sites?: { sites?: SiteEntry[] } }>("/sites/rollback", {});
      setETag(out.etag ?? "");
      setSites(parseSitesResponse(out));
      setStatuses(Array.isArray(out.site_statuses) ? out.site_statuses : []);
      setNotice(tx("Rollback applied."));
      setRollbackDepth((current) => Math.max(current - 1, 0));
    } catch (error: unknown) {
      setError(getErrorMessage(error, tx("rollback failed")));
    } finally {
      setSaving(false);
    }
  }, [tx]);

  if (loading) {
    return <div className="w-full p-4 text-neutral-500">{tx("Loading sites...")}</div>;
  }

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Sites")}</h1>
          <p className="text-sm text-neutral-500">{tx("Manage hostname ownership, default upstreams, and TLS binding as first-class protected sites.")}</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-neutral-500">
          <span className="rounded bg-neutral-100 px-2 py-1">ETag {etag || "-"}</span>
          <span className="rounded bg-neutral-100 px-2 py-1">{tx("Rollback depth")} {rollbackDepth}</span>
        </div>
      </header>

      <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={() => void load()} disabled={saving}>{tx("Load")}</button>
          <button type="button" onClick={() => void runValidate()} disabled={saving}>{saving ? tx("Working...") : tx("Validate")}</button>
          <button type="button" onClick={() => void runApply()} disabled={readOnly || saving || !etag}>{tx("Apply")}</button>
          <button type="button" onClick={() => void runRollback()} disabled={readOnly || saving || rollbackDepth === 0}>{tx("Rollback")}</button>
          <button
            type="button"
            onClick={() => setSites((current) => [...current, createEmptySite(current.length + 1)])}
            disabled={readOnly || saving}
          >
            {tx("Add Site")}
          </button>
        </div>

        {notice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{notice}</div> : null}
        {error ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{error}</div> : null}
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,2fr),minmax(320px,1fr)]">
        <div className="space-y-4">
          {sites.length === 0 ? (
            <div className="rounded-xl border border-dashed border-neutral-200 bg-white p-6 text-sm text-neutral-500">
              {tx("No sites configured. Existing `proxy.json` routing keeps working unchanged until you add a site.")}
            </div>
          ) : null}

          {sites.map((site, index) => (
            <article key={`${site.name}:${index}`} className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold">{site.name || `site-${index + 1}`}</h2>
                  <p className="text-xs text-neutral-500">{tx("Generated route")}: <code>site:{site.name || `site-${index + 1}`}</code></p>
                </div>
                <button
                  type="button"
                  className="text-sm underline"
                  onClick={() => setSites((current) => current.filter((_, siteIndex) => siteIndex !== index))}
                  disabled={readOnly || saving}
                >
                  {tx("Remove")}
                </button>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <label className="space-y-1 text-sm">
                  <span className="block text-xs text-neutral-600">{tx("Site name")}</span>
                  <input
                    value={site.name}
                    onChange={(e) => updateSite(index, { ...site, name: e.target.value })}
                    className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                  />
                </label>

                <label className="space-y-1 text-sm">
                  <span className="block text-xs text-neutral-600">{tx("Default upstream")}</span>
                  <input
                    value={site.default_upstream}
                    onChange={(e) => updateSite(index, { ...site, default_upstream: e.target.value })}
                    className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                    placeholder="http://app.internal:8080"
                  />
                </label>

                <label className="space-y-1 text-sm md:col-span-2">
                  <span className="block text-xs text-neutral-600">{tx("Hosts")}</span>
                  <textarea
                    value={stringListToMultiline(site.hosts)}
                    onChange={(e) => updateSite(index, { ...site, hosts: multilineToStringList(e.target.value) })}
                    className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-sm"
                    placeholder={"blog.example.com\n*.example.com"}
                  />
                </label>

                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={site.enabled}
                    onChange={(e) => updateSite(index, { ...site, enabled: e.target.checked })}
                  />
                  {tx("Enabled")}
                </label>

                <label className="space-y-1 text-sm">
                  <span className="block text-xs text-neutral-600">{tx("TLS mode")}</span>
                  <select
                    value={site.tls.mode}
                    onChange={(e) => updateSite(index, { ...site, tls: { ...site.tls, mode: e.target.value as SiteTLSMode } })}
                    className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                  >
                    <option value="legacy">legacy</option>
                    <option value="manual">manual</option>
                    <option value="acme">acme</option>
                  </select>
                </label>

                {site.tls.mode === "manual" ? (
                  <>
                    <label className="space-y-1 text-sm">
                      <span className="block text-xs text-neutral-600">{tx("cert_file")}</span>
                      <input
                        value={site.tls.cert_file ?? ""}
                        onChange={(e) => updateSite(index, { ...site, tls: { ...site.tls, cert_file: e.target.value } })}
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                        placeholder="/etc/tukuyomi/tls/fullchain.pem"
                      />
                    </label>
                    <label className="space-y-1 text-sm">
                      <span className="block text-xs text-neutral-600">{tx("key_file")}</span>
                      <input
                        value={site.tls.key_file ?? ""}
                        onChange={(e) => updateSite(index, { ...site, tls: { ...site.tls, key_file: e.target.value } })}
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                        placeholder="/etc/tukuyomi/tls/privkey.pem"
                      />
                    </label>
                  </>
                ) : null}
              </div>
            </article>
          ))}
        </div>

        <div className="space-y-4">
          <section className="rounded-xl border border-neutral-200 bg-white p-4">
            <h2 className="text-sm font-semibold">{tx("Validation Summary")}</h2>
            <div className="mt-3 space-y-2">
              {statuses.length === 0 ? (
                <div className="text-xs text-neutral-500">{tx("No site status yet. Use Validate or Load.")}</div>
              ) : (
                statuses.map((status) => (
                  <div key={status.name} className="rounded border border-neutral-200 px-3 py-2 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <strong>{status.name}</strong>
                      <span className="rounded bg-neutral-100 px-2 py-0.5">
                        {status.enabled ? `${status.tls_mode ?? "-"} / ${status.tls_status ?? "-"}` : tx("disabled")}
                      </span>
                    </div>
                    {status.hosts?.length ? <div className="mt-1 text-neutral-600">{status.hosts.join(", ")}</div> : null}
                    {status.generated_route ? <div className="mt-1 text-neutral-500">{tx("route")} {status.generated_route}</div> : null}
                    {status.tls_cert_not_after ? <div className="mt-1 text-neutral-500">{tx("cert not after")} {status.tls_cert_not_after}</div> : null}
                    {status.tls_warning ? <div className="mt-1 text-amber-700">{status.tls_warning}</div> : null}
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="rounded-xl border border-neutral-200 bg-white p-4">
            <h2 className="text-sm font-semibold">{tx("Rendered JSON")}</h2>
            <p className="mt-1 text-xs text-neutral-500">{tx("Apply and validate both use the generated JSON below.")}</p>
            <div className="app-code-shell mt-3">
              <pre className="app-code-block">{rawPreview}</pre>
            </div>
          </section>
        </div>
      </section>
    </div>
  );
}
