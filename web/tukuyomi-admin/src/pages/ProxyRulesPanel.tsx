import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { getErrorMessage } from "@/lib/errors";
import { getCurrentLocale, useI18n, translateCurrent } from "@/lib/i18n";
import {
  createEmptyBackendPool,
  createEmptyDefaultRoute,
  createEmptyRoute,
  createEmptyUpstream,
  defaultStickyCookieName,
  headerMapToMultiline,
  multilineToQueryMap,
  multilineToHeaderMap,
  multilineToStringList,
  parseProxyRulesEditor,
  queryMapToMultiline,
  serializeProxyRulesEditor,
  stringListToMultiline,
  type ProxyResponseHeaderSanitizeEditorState,
  type ProxyBackendPool,
  type ProxyRoute,
  type ProxyRouteAction,
  type ProxyRouteHeaderOperations,
  type ProxyRouteQueryOperations,
  type ProxyRulesRoutingEditorState,
  type ProxyUpstream,
} from "@/lib/proxyRulesEditor";
import {
  buildProxyRulesAuditPreview,
  buildProxyRulesDiffPreview,
  filterProxyRulesAuditEntries,
  formatProxyRulesAuditAction,
  formatProxyRulesAuditTransition,
  runProxyRulesAuditReload,
  serializeProxyRulesAuditEntries,
  type ProxyRulesAuditActionFilter,
  type ProxyRulesAuditEntry,
  type ProxyRulesDiffPreview,
} from "@/lib/proxyRulesAudit";

type HealthStatus = {
  status?: string;
  endpoint?: string;
  checked_at?: string;
  last_success_at?: string;
  last_failure_at?: string;
  consecutive_failures?: number;
  last_error?: string;
  last_status_code?: number;
  last_latency_ms?: number;
};

type ProxyRuntimeView = Record<string, unknown>;

type DryRunResult = {
  source?: string;
  route_name?: string;
  original_host?: string;
  original_path?: string;
  original_query?: string;
  rewritten_host?: string;
  rewritten_path?: string;
  rewritten_query?: string;
  selected_upstream?: string;
  selected_upstream_url?: string;
  final_url?: string;
};

type GetResponse = {
  etag?: string;
  raw?: string;
  proxy?: ProxyRuntimeView;
  health?: HealthStatus;
  rollback_depth?: number;
};

type RollbackPreviewResponse = {
  ok?: boolean;
  raw?: string;
  etag?: string;
};

type ProxyRulesAuditResponse = {
  entries?: ProxyRulesAuditEntry[];
};

type RoutePathType = "" | "exact" | "prefix" | "regex";
const defaultProxyRulesAuditLimit = 20 as const;

export default function ProxyRulesPanel() {
  const { tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [auditLimit, setAuditLimit] = useState<20 | 50 | 100>(defaultProxyRulesAuditLimit);
  const [auditActorFilter, setAuditActorFilter] = useState("");
  const [auditActionFilter, setAuditActionFilter] = useState<ProxyRulesAuditActionFilter>("all");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [dryRunning, setDryRunning] = useState(false);
  const [raw, setRaw] = useState("");
  const [serverRaw, setServerRaw] = useState("");
  const [etag, setEtag] = useState("");
  const [proxy, setProxy] = useState<ProxyRuntimeView | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [rollbackDepth, setRollbackDepth] = useState(0);
  const [messages, setMessages] = useState<string[]>([]);
  const [messagesTone, setMessagesTone] = useState<"success" | "error" | "warn">("success");
  const [upstreamProbeResult, setUpstreamProbeResult] = useState<{
    index: number;
    tone: "success" | "error" | "warn";
    message: string;
  } | null>(null);
  const [error, setError] = useState("");
  const [structuredError, setStructuredError] = useState("");
  const [auditEntries, setAuditEntries] = useState<ProxyRulesAuditEntry[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState("");
  const [auditNotice, setAuditNotice] = useState("");
  const [routingState, setRoutingState] = useState<ProxyRulesRoutingEditorState>({
    exposeWAFDebugHeaders: false,
    emitUpstreamNameRequestHeader: false,
    responseHeaderSanitize: {
      mode: "auto",
      customRemove: [],
      customKeep: [],
      debugLog: false,
    },
    upstreams: [],
    backendPools: [],
    routes: [],
    defaultRoute: null,
  });
  const [routingBase, setRoutingBase] = useState<Record<string, unknown>>({});
  const [dryRunHost, setDryRunHost] = useState("");
  const [dryRunPath, setDryRunPath] = useState("/servicea/users");
  const [dryRunResult, setDryRunResult] = useState<DryRunResult | null>(null);
  const [dryRunMessages, setDryRunMessages] = useState<string[]>([]);
  const [diffPreview, setDiffPreview] = useState<ProxyRulesDiffPreview | null>(null);
  const [routingTab, setRoutingTab] = useState<"routes" | "default">("routes");
  const auditInitialLoadDone = useRef(false);

  const dirty = useMemo(() => raw !== serverRaw, [raw, serverRaw]);
  const routeTargetOptions = useMemo(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const upstream of routingState.upstreams) {
      const name = upstream.name.trim();
      if (!name || seen.has(name)) {
        continue;
      }
      seen.add(name);
      out.push(name);
    }
    return out;
  }, [routingState.upstreams]);
  const backendPoolOptions = useMemo(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const pool of routingState.backendPools) {
      const name = pool.name.trim();
      if (!name || seen.has(name)) {
        continue;
      }
      seen.add(name);
      out.push(name);
    }
    return out;
  }, [routingState.backendPools]);

  const syncStructuredFromRaw = useCallback((nextRaw: string) => {
    try {
      const parsed = parseProxyRulesEditor(nextRaw);
      setRoutingBase(parsed.base);
      setRoutingState(parsed.state);
      setStructuredError("");
    } catch (error: unknown) {
      setStructuredError(getErrorMessage(error, tx("invalid raw JSON")));
    }
  }, [tx]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    setUpstreamProbeResult(null);
    setDryRunMessages([]);
    try {
      const data = await apiGetJson<GetResponse>("/proxy-rules");
      const nextRaw = data.raw || "";
      setRaw(nextRaw);
      setServerRaw(nextRaw);
      setEtag(data.etag || "");
      setProxy(data.proxy || null);
      setHealth(data.health || null);
      setRollbackDepth(typeof data.rollback_depth === "number" ? data.rollback_depth : 0);
      setMessages([]);
      syncStructuredFromRaw(nextRaw);
    } catch (error: unknown) {
      setError(getErrorMessage(error, tx("failed to load")));
    } finally {
      setLoading(false);
    }
  }, [syncStructuredFromRaw, tx]);

  const loadAuditForLimit = useCallback(async (limit: number) => {
    setAuditLoading(true);
    setAuditError("");
    setAuditNotice("");
    try {
      const data = await apiGetJson<ProxyRulesAuditResponse>(`/proxy-rules/audit?limit=${limit}`);
      setAuditEntries(Array.isArray(data.entries) ? data.entries : []);
    } catch (error: unknown) {
      setAuditEntries([]);
      setAuditError(getErrorMessage(error, tx("failed to load recent changes")));
    } finally {
      setAuditLoading(false);
    }
  }, [tx]);

  const loadAudit = useCallback(async () => {
    await loadAuditForLimit(auditLimit);
  }, [auditLimit, loadAuditForLimit]);

  const refreshAll = useCallback(async () => {
    await runProxyRulesAuditReload("manual", {
      loadConfig: load,
      loadAudit,
    });
  }, [load, loadAudit]);

  useEffect(() => {
    void runProxyRulesAuditReload("initial", {
      loadConfig: load,
      loadAudit: () => loadAuditForLimit(defaultProxyRulesAuditLimit),
    }).then(() => {
      auditInitialLoadDone.current = true;
    });
  }, [load, loadAuditForLimit]);

  useEffect(() => {
    if (!auditInitialLoadDone.current) {
      return;
    }
    void runProxyRulesAuditReload("limit_change", {
      loadConfig: load,
      loadAudit,
    });
  }, [auditLimit, load, loadAudit]);

  const visibleAuditEntries = useMemo(
    () => filterProxyRulesAuditEntries(auditEntries, auditActorFilter, auditActionFilter),
    [auditActionFilter, auditActorFilter, auditEntries]
  );

  const handleRawChange = useCallback(
    (nextRaw: string) => {
      setRaw(nextRaw);
      syncStructuredFromRaw(nextRaw);
    },
    [syncStructuredFromRaw]
  );

  const applyStructuredChange = useCallback(
    (updater: (current: ProxyRulesRoutingEditorState) => ProxyRulesRoutingEditorState) => {
      const nextState = updater(routingState);
      const nextRaw = serializeProxyRulesEditor(routingBase, nextState);
      setRaw(nextRaw);
      setRoutingState(nextState);
      setStructuredError("");
    },
    [routingBase, routingState]
  );

  const validate = useCallback(async () => {
    setMessages([]);
    setMessagesTone("success");
    setError("");
    try {
      const out = await apiPostJson<{ ok: boolean; messages?: string[]; proxy?: ProxyRuntimeView }>("/proxy-rules/validate", { raw });
      setMessages(out.messages && out.messages.length ? out.messages : [tx("Validation passed.")]);
      setMessagesTone("success");
      if (out.proxy) {
        setProxy(out.proxy);
      }
    } catch (error: unknown) {
      setMessages([getErrorMessage(error, tx("validate failed"))]);
      setMessagesTone("error");
    }
  }, [raw, tx]);

  const probeUpstream = useCallback(async (index: number, upstream: ProxyUpstream) => {
    const upstreamName = upstream.name.trim();
    if (!upstreamName) {
      setUpstreamProbeResult({ index, tone: "error", message: tx("upstream name is required for probe") });
      return;
    }
    setUpstreamProbeResult(null);
    setError("");
    try {
      const out = await apiPostJson<{ ok: boolean; probe?: { upstream_name?: string; address?: string; latency_ms?: number; timeout_ms?: number } }>(
        "/proxy-rules/probe",
        { raw, upstream_name: upstreamName, timeout_ms: 2000 }
      );
      if (out.probe) {
        setUpstreamProbeResult({
          index,
          tone: "success",
          message: tx("probe ok for {upstream}: {address} latency={latency}ms timeout={timeout}ms", {
          upstream: upstreamName,
          address: out.probe.address || "-",
          latency: out.probe.latency_ms ?? "-",
          timeout: out.probe.timeout_ms ?? "-",
        })});
      } else {
        setUpstreamProbeResult({ index, tone: "success", message: tx("probe ok for {upstream}", { upstream: upstreamName }) });
      }
    } catch (error: unknown) {
      setUpstreamProbeResult({
        index,
        tone: "error",
        message: tx("probe failed for {upstream}: {message}", {
          upstream: upstreamName,
          message: getErrorMessage(error, tx("probe failed")),
        }),
      });
    }
  }, [raw, tx]);

  const save = useCallback(async () => {
    setSaving(true);
    setError("");
    try {
      const out = await apiPutJson<{ ok: boolean; etag?: string; proxy?: ProxyRuntimeView }>(
        "/proxy-rules",
        { raw },
        { headers: etag ? { "If-Match": etag } : {} }
      );
      if (!out.ok) {
        throw new Error(tx("save failed"));
      }
      setServerRaw(raw);
      if (out.etag) {
        setEtag(out.etag);
      }
      if (out.proxy) {
        setProxy(out.proxy);
      }
      await refreshAll();
      return true;
    } catch (error: unknown) {
      setError(getErrorMessage(error, tx("save failed")));
      return false;
    } finally {
      setSaving(false);
    }
  }, [etag, raw, refreshAll, tx]);

  const rollback = useCallback(async () => {
    setSaving(true);
    setError("");
    try {
      await apiPostJson("/proxy-rules/rollback", {});
      await refreshAll();
      return true;
    } catch (error: unknown) {
      setError(getErrorMessage(error, tx("rollback failed")));
      return false;
    } finally {
      setSaving(false);
    }
  }, [refreshAll, tx]);

  const previewSave = useCallback(() => {
    setDiffPreview(
        buildProxyRulesDiffPreview({
          mode: "save",
          title: tx("Review changes before apply"),
          description: tx("Compare the current saved proxy rules with the JSON that will be applied."),
          currentRaw: serverRaw,
          nextRaw: raw,
          applyLabel: tx("Apply"),
        })
    );
  }, [raw, serverRaw, tx]);

  const previewRollback = useCallback(async () => {
    setPreviewing(true);
    setError("");
    try {
      const out = await apiGetJson<RollbackPreviewResponse>("/proxy-rules/rollback-preview");
      setDiffPreview(
        buildProxyRulesDiffPreview({
          mode: "rollback",
          title: tx("Review rollback target"),
          description: tx("Compare the current saved proxy rules with the snapshot that will be restored."),
          note: dirty ? tx("Unsaved editor changes are not part of rollback. Rollback restores the latest saved runtime snapshot.") : undefined,
          currentRaw: serverRaw,
          nextRaw: out.raw || "",
          applyLabel: tx("Apply rollback"),
        })
      );
    } catch (error: unknown) {
      setError(getErrorMessage(error, tx("rollback preview failed")));
    } finally {
      setPreviewing(false);
    }
  }, [dirty, serverRaw, tx]);

  const previewAuditEntry = useCallback((entry: ProxyRulesAuditEntry) => {
    setDiffPreview(buildProxyRulesAuditPreview(entry));
  }, []);

  const exportAuditEntries = useCallback(() => {
    const payload = serializeProxyRulesAuditEntries(visibleAuditEntries, "json");
    const blob = new Blob([payload], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `proxy-rules-audit-${auditLimit}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setAuditNotice(tx("Exported {count} audit entries as JSON.", { count: visibleAuditEntries.length }));
  }, [auditLimit, tx, visibleAuditEntries]);

  const copyAuditSummary = useCallback(async (text: string) => {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "true");
    area.style.position = "absolute";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }, []);

  const handleCopyAuditSummary = useCallback(async () => {
    if (!diffPreview?.copyText) {
      return;
    }
    try {
      await copyAuditSummary(diffPreview.copyText);
      setAuditNotice(tx("Copied selected audit summary."));
    } catch (error: unknown) {
      setAuditError(getErrorMessage(error, tx("failed to copy audit summary")));
    }
  }, [copyAuditSummary, diffPreview, tx]);

  const applyPreview = useCallback(async () => {
    if (readOnly) {
      setError(tx("This deployment is admin read-only."));
      return;
    }
    if (!diffPreview || diffPreview.parseError) {
      return;
    }
    const ok = diffPreview.mode === "save" ? await save() : await rollback();
    if (ok) {
      setDiffPreview(null);
    }
  }, [diffPreview, readOnly, rollback, save, tx]);

  const runDryRun = useCallback(async () => {
    setDryRunning(true);
    setDryRunMessages([]);
    try {
      const out = await apiPostJson<{ ok: boolean; dry_run?: DryRunResult; messages?: string[] }>("/proxy-rules/dry-run", {
        raw,
        host: dryRunHost,
        path: dryRunPath,
      });
      setDryRunResult(out.dry_run || null);
      setDryRunMessages(Array.isArray(out.messages) ? out.messages : []);
    } catch (error: unknown) {
      setDryRunResult(null);
      setDryRunMessages([getErrorMessage(error, tx("dry-run failed"))]);
    } finally {
      setDryRunning(false);
    }
  }, [dryRunHost, dryRunPath, raw, tx]);

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Proxy Rules")}</h1>
          <p className="text-sm text-neutral-500">{tx("Edit route-aware upstream selection, path/query rewrites, and header operations with a structured builder, then keep raw JSON for the rest of the proxy transport knobs.")}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <Badge color={structuredError ? "red" : "green"}>{structuredError ? tx("Raw JSON out of sync") : tx("Structured editor synced")}</Badge>
          {dirty ? <Badge color="amber">{tx("Unsaved")}</Badge> : <Badge color="gray">{tx("Saved")}</Badge>}
          <span className="px-2 py-0.5 rounded bg-neutral-100 text-neutral-700">{tx("rollback")}: {rollbackDepth}</span>
          {etag ? <MonoTag label={tx("ETag")} value={etag} /> : null}
        </div>
      </header>

      {error ? <NoticeBar tone="error">{error}</NoticeBar> : null}
      {structuredError ? (
        <NoticeBar tone="warn">
          {tx("Raw JSON is currently invalid. The structured editor is still showing the last valid routing snapshot. Any structured edit will regenerate raw JSON from that snapshot.")}
        </NoticeBar>
      ) : null}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]">
        <div className="space-y-4">
          <SectionCard
            title="Workflow"
            subtitle="Validate, save, and rollback stay on the same raw proxy-rules backend API. Structured edits only touch routing and rewrite fields."
            actions={
              <div className="flex flex-wrap items-center gap-2">
                <ActionButton onClick={() => void refreshAll()} disabled={loading || saving || auditLoading}>
                  {tx("Refresh")}
                </ActionButton>
                <ActionButton onClick={() => void validate()} disabled={loading || saving}>
                  {tx("Validate")}
                </ActionButton>
                <PrimaryButton onClick={previewSave} disabled={readOnly || loading || saving || previewing || !dirty}>
                  {saving ? tx("Saving...") : tx("Save")}
                </PrimaryButton>
                <ActionButton onClick={() => void previewRollback()} disabled={readOnly || loading || saving || previewing || rollbackDepth <= 0}>
                  {previewing ? tx("Preparing...") : tx("Rollback")}
                </ActionButton>
              </div>
            }
          >
            {messages.length > 0 ? (
              <NoticeBar tone={messagesTone}>
                {messages.map((m, idx) => (
                  <div key={`${m}-${idx}`}>{m}</div>
                ))}
              </NoticeBar>
            ) : null}

            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              <StatBox label="Upstreams" value={String(routingState.upstreams.length)} />
              <StatBox label="Backend pools" value={String(routingState.backendPools.length)} />
              <StatBox label="Routes" value={String(routingState.routes.length)} />
              <StatBox label="Default route" value={tx(routingState.defaultRoute ? "enabled" : "none")} />
            </div>
          </SectionCard>

          <SectionCard
            title="Upstreams"
            subtitle="Define named backend nodes first. Backend Pools and Routes refer to these names."
            actions={
              <ActionButton
                disabled={readOnly}
                onClick={() =>
                  applyStructuredChange((current) => ({
                    ...current,
                    upstreams: [...current.upstreams, createEmptyUpstream(current.upstreams.length + 1)],
                  }))
                }
              >
                {tx("Add upstream")}
              </ActionButton>
            }
          >
            <div className="space-y-3">
              {routingState.upstreams.length === 0 ? (
                <EmptyState>{tx("No named upstreams configured. Add upstreams before creating route targets.")}</EmptyState>
              ) : null}
              {routingState.upstreams.map((upstream, index) => (
                <div key={`upstream-${index}`} className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="font-medium">{tx("Upstream #{index}", { index: index + 1 })}</div>
                      <div className="text-xs text-neutral-500">{tx("Name is referenced from backend pools or route action.upstream.")}</div>
                    </div>
                    <div className="flex items-center gap-3">
                      <button
                        type="button"
                        className="text-sm text-neutral-700 underline"
                        disabled={loading || saving || upstream.discovery.enabled || !upstream.name.trim() || !upstream.url.trim()}
                        onClick={() => void probeUpstream(index, upstream)}
                      >
                        {tx("Probe")}
                      </button>
                      <button
                        type="button"
                        className="text-sm text-red-700 underline"
                        disabled={readOnly}
                        onClick={() => {
                          if (upstreamProbeResult?.index === index) {
                            setUpstreamProbeResult(null);
                          }
                          applyStructuredChange((current) => ({
                            ...current,
                            upstreams: current.upstreams.filter((_, candidateIndex) => candidateIndex !== index),
                          }));
                        }}
                      >
                        {tx("Remove")}
                      </button>
                    </div>
                  </div>
                  {upstreamProbeResult?.index === index ? <NoticeBar tone={upstreamProbeResult.tone}>{upstreamProbeResult.message}</NoticeBar> : null}
                  <div className="grid gap-3 md:grid-cols-4">
                    <Field label="Name">
                      <input
                        className={inputClass}
                        value={upstream.name}
                        onChange={(e) => updateUpstream(index, { ...upstream, name: e.target.value })}
                        placeholder="service-a"
                      />
                    </Field>
                    <Field label="URL">
                      <input
                        className={inputClass}
                        value={upstream.url}
                        disabled={upstream.discovery.enabled}
                        onChange={(e) => updateUpstream(index, { ...upstream, url: e.target.value })}
                        placeholder="http://service-a.internal:8080"
                      />
                    </Field>
                    <Field label="Weight">
                      <input
                        className={inputClass}
                        type="number"
                        min={1}
                        value={upstream.weight}
                        onChange={(e) => updateUpstream(index, { ...upstream, weight: Number(e.target.value || 1) })}
                      />
                    </Field>
                    <Field label="Enabled">
                      <label className="flex items-center gap-2 text-sm">
                        <input
                          type="checkbox"
                          checked={upstream.enabled}
                          onChange={(e) => updateUpstream(index, { ...upstream, enabled: e.target.checked })}
                        />
                        <span>{upstream.enabled ? tx("Enabled") : tx("Disabled")}</span>
                      </label>
                    </Field>
                  </div>
                  <div className="rounded-xl border border-neutral-200 bg-white p-3 space-y-3">
                    <label className="flex items-center gap-2 text-sm font-medium">
                      <input
                        type="checkbox"
                        checked={upstream.discovery.enabled}
                        onChange={(e) => {
                          const enabled = e.target.checked;
                          updateUpstream(index, {
                            ...upstream,
                            url: enabled ? "" : upstream.url,
                            discovery: {
                              ...upstream.discovery,
                              enabled,
                              type: enabled && !upstream.discovery.type ? "dns" : upstream.discovery.type,
                            },
                          });
                        }}
                      />
                      <span>{tx("Dynamic DNS discovery")}</span>
                    </label>
                    {upstream.discovery.enabled ? (
                      <>
                        <div className="grid gap-3 md:grid-cols-4">
                          <Field label="Discovery type">
                            <select
                              className={inputClass}
                              value={upstream.discovery.type}
                              onChange={(e) =>
                                updateUpstream(index, {
                                  ...upstream,
                                  discovery: { ...upstream.discovery, type: e.target.value as typeof upstream.discovery.type },
                                })
                              }
                            >
                              <option value="dns">dns A/AAAA</option>
                              <option value="dns_srv">dns_srv</option>
                            </select>
                          </Field>
                          <Field label="Scheme">
                            <select
                              className={inputClass}
                              value={upstream.discovery.scheme}
                              onChange={(e) =>
                                updateUpstream(index, {
                                  ...upstream,
                                  discovery: { ...upstream.discovery, scheme: e.target.value as typeof upstream.discovery.scheme },
                                })
                              }
                            >
                              <option value="http">http</option>
                              <option value="https">https</option>
                            </select>
                          </Field>
                          <Field label="Refresh sec">
                            <input
                              className={inputClass}
                              type="number"
                              min={1}
                              max={3600}
                              value={upstream.discovery.refreshIntervalSec}
                              onChange={(e) =>
                                updateUpstream(index, {
                                  ...upstream,
                                  discovery: { ...upstream.discovery, refreshIntervalSec: Number(e.target.value || 10) },
                                })
                              }
                            />
                          </Field>
                          <Field label="Timeout ms">
                            <input
                              className={inputClass}
                              type="number"
                              min={50}
                              max={10000}
                              value={upstream.discovery.timeoutMS}
                              onChange={(e) =>
                                updateUpstream(index, {
                                  ...upstream,
                                  discovery: { ...upstream.discovery, timeoutMS: Number(e.target.value || 1000) },
                                })
                              }
                            />
                          </Field>
                        </div>
                        {upstream.discovery.type === "dns" ? (
                          <div className="grid gap-3 md:grid-cols-3">
                            <Field label="Hostname">
                              <input
                                className={inputClass}
                                value={upstream.discovery.hostname}
                                onChange={(e) =>
                                  updateUpstream(index, {
                                    ...upstream,
                                    discovery: { ...upstream.discovery, hostname: e.target.value },
                                  })
                                }
                                placeholder="app.default.svc.cluster.local"
                              />
                            </Field>
                            <Field label="Port">
                              <input
                                className={inputClass}
                                type="number"
                                min={1}
                                max={65535}
                                value={upstream.discovery.port}
                                onChange={(e) =>
                                  updateUpstream(index, {
                                    ...upstream,
                                    discovery: { ...upstream.discovery, port: Number(e.target.value || 80) },
                                  })
                                }
                              />
                            </Field>
                            <Field label="Record types">
                              <input
                                className={inputClass}
                                value={upstream.discovery.recordTypes.join(",")}
                                onChange={(e) =>
                                  updateUpstream(index, {
                                    ...upstream,
                                    discovery: {
                                      ...upstream.discovery,
                                      recordTypes: e.target.value
                                        .split(",")
                                        .map((item) => item.trim())
                                        .filter(Boolean),
                                    },
                                  })
                                }
                                placeholder="A,AAAA"
                              />
                            </Field>
                          </div>
                        ) : (
                          <div className="grid gap-3 md:grid-cols-3">
                            <Field label="Service">
                              <input
                                className={inputClass}
                                value={upstream.discovery.service}
                                onChange={(e) =>
                                  updateUpstream(index, {
                                    ...upstream,
                                    discovery: { ...upstream.discovery, service: e.target.value },
                                  })
                                }
                                placeholder="http"
                              />
                            </Field>
                            <Field label="Proto">
                              <input
                                className={inputClass}
                                value={upstream.discovery.proto}
                                onChange={(e) =>
                                  updateUpstream(index, {
                                    ...upstream,
                                    discovery: { ...upstream.discovery, proto: e.target.value },
                                  })
                                }
                                placeholder="tcp"
                              />
                            </Field>
                            <Field label="Name">
                              <input
                                className={inputClass}
                                value={upstream.discovery.name}
                                onChange={(e) =>
                                  updateUpstream(index, {
                                    ...upstream,
                                    discovery: { ...upstream.discovery, name: e.target.value },
                                  })
                                }
                                placeholder="api.default.svc.cluster.local"
                              />
                            </Field>
                          </div>
                        )}
                        <Field label="Max targets">
                          <input
                            className={inputClass}
                            type="number"
                            min={1}
                            max={256}
                            value={upstream.discovery.maxTargets}
                            onChange={(e) =>
                              updateUpstream(index, {
                                ...upstream,
                                discovery: { ...upstream.discovery, maxTargets: Number(e.target.value || 32) },
                              })
                            }
                          />
                        </Field>
                      </>
                    ) : null}
                  </div>
                  <div className="grid gap-3 md:grid-cols-3">
                    <Field label="HTTP/2 Mode">
                      <select
                        className={inputClass}
                        value={upstream.http2Mode}
                        onChange={(e) => updateUpstream(index, { ...upstream, http2Mode: e.target.value as typeof upstream.http2Mode })}
                      >
                        <option value="">{tx("Default")}</option>
                        <option value="force_attempt">force_attempt</option>
                        <option value="h2c_prior_knowledge">h2c_prior_knowledge</option>
                      </select>
                    </Field>
                    <Field label="TLS Server Name">
                      <input
                        className={inputClass}
                        value={upstream.tlsServerName}
                        onChange={(e) => updateUpstream(index, { ...upstream, tlsServerName: e.target.value })}
                        placeholder="backend.internal"
                      />
                    </Field>
                    <Field label="TLS CA Bundle">
                      <input
                        className={inputClass}
                        value={upstream.tlsCABundle}
                        onChange={(e) => updateUpstream(index, { ...upstream, tlsCABundle: e.target.value })}
                        placeholder="/etc/tukuyomi/ca.pem"
                      />
                    </Field>
                    <Field label="TLS Min Version">
                      <select
                        className={inputClass}
                        value={upstream.tlsMinVersion}
                        onChange={(e) => updateUpstream(index, { ...upstream, tlsMinVersion: e.target.value })}
                      >
                        <option value="">{tx("Default")}</option>
                        <option value="tls1.2">tls1.2</option>
                        <option value="tls1.3">tls1.3</option>
                      </select>
                    </Field>
                    <Field label="TLS Max Version">
                      <select
                        className={inputClass}
                        value={upstream.tlsMaxVersion}
                        onChange={(e) => updateUpstream(index, { ...upstream, tlsMaxVersion: e.target.value })}
                      >
                        <option value="">{tx("Default")}</option>
                        <option value="tls1.2">tls1.2</option>
                        <option value="tls1.3">tls1.3</option>
                      </select>
                    </Field>
                    <Field label="Client Certificate File">
                      <input
                        className={inputClass}
                        value={upstream.tlsClientCert}
                        onChange={(e) => updateUpstream(index, { ...upstream, tlsClientCert: e.target.value })}
                        placeholder="/etc/tukuyomi/client.pem"
                      />
                    </Field>
                    <Field label="Client Key File">
                      <input
                        className={inputClass}
                        value={upstream.tlsClientKey}
                        onChange={(e) => updateUpstream(index, { ...upstream, tlsClientKey: e.target.value })}
                        placeholder="/etc/tukuyomi/client.key"
                      />
                    </Field>
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>

          <SectionCard
            title="Backend Pools"
            subtitle="Group named upstream nodes into route-scoped balancing sets. Use these pools from Routes."
            actions={
              <ActionButton
                disabled={readOnly}
                onClick={() =>
                  applyStructuredChange((current) => ({
                    ...current,
                    backendPools: [...current.backendPools, createEmptyBackendPool(current.backendPools.length + 1)],
                  }))
                }
              >
                {tx("Add backend pool")}
              </ActionButton>
            }
          >
            <div className="space-y-3">
              {routingState.backendPools.length === 0 ? (
                <EmptyState>{tx("No backend pools configured. Create a pool, assign named upstream members, then bind routes to that pool.")}</EmptyState>
              ) : null}
              {routingState.backendPools.map((pool, index) => (
                <BackendPoolEditorCard
                  key={`backend-pool-${index}`}
                  title={tx("Backend Pool #{index}", { index: index + 1 })}
                  pool={pool}
                  upstreamOptions={routingState.upstreams.map((item) => item.name)}
                  onChange={(next) => updateBackendPool(index, next)}
                  onRemove={readOnly ? undefined : () =>
                    applyStructuredChange((current) => ({
                      ...current,
                      backendPools: current.backendPools.filter((_, candidateIndex) => candidateIndex !== index),
                      routes: current.routes.map((route) =>
                        route.action.backendPool === pool.name
                          ? { ...route, action: { ...route.action, backendPool: "" } }
                          : route
                      ),
                      defaultRoute:
                        current.defaultRoute && current.defaultRoute.action.backendPool === pool.name
                          ? { ...current.defaultRoute, action: { ...current.defaultRoute.action, backendPool: "" } }
                          : current.defaultRoute,
                    }))
                  }
                />
              ))}
            </div>
          </SectionCard>

          <SectionCard
            title="Routing"
            subtitle="Routes are evaluated in ascending priority. The first match wins, then default_route, then upstreams."
            actions={
              routingTab === "routes" ? (
                <ActionButton
                  disabled={readOnly}
                  onClick={() =>
                    applyStructuredChange((current) => ({
                      ...current,
                      routes: [...current.routes, createEmptyRoute(current.routes.length + 1)],
                    }))
                  }
                >
                  {tx("Add route")}
                </ActionButton>
              ) : routingState.defaultRoute ? (
                <ActionButton
                  disabled={readOnly}
                  onClick={() =>
                    applyStructuredChange((current) => ({
                      ...current,
                      defaultRoute: null,
                    }))
                  }
                >
                  {tx("Remove default route")}
                </ActionButton>
              ) : (
                <ActionButton
                  disabled={readOnly}
                  onClick={() =>
                    applyStructuredChange((current) => ({
                      ...current,
                      defaultRoute: createEmptyDefaultRoute(),
                    }))
                  }
                >
                  {tx("Add default route")}
                </ActionButton>
              )
            }
          >
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                className={routingTab === "routes" ? "rounded-full bg-black px-3 py-1.5 text-xs font-medium text-white" : "rounded-full border border-neutral-200 bg-white px-3 py-1.5 text-xs font-medium text-neutral-700 hover:border-neutral-300"}
                onClick={() => setRoutingTab("routes")}
              >
                {tx("Routes")} ({routingState.routes.length})
              </button>
              <button
                type="button"
                className={routingTab === "default" ? "rounded-full bg-black px-3 py-1.5 text-xs font-medium text-white" : "rounded-full border border-neutral-200 bg-white px-3 py-1.5 text-xs font-medium text-neutral-700 hover:border-neutral-300"}
                onClick={() => setRoutingTab("default")}
              >
                {tx("Default route")} ({routingState.defaultRoute ? tx("enabled") : tx("none")})
              </button>
            </div>
            <div className="mt-4">
              {routingTab === "routes" ? (
                <div className="space-y-4">
                  {routingState.routes.length === 0 ? <EmptyState>{tx("No route rules configured. Traffic falls through to `default_route` or upstreams.")}</EmptyState> : null}
                  {routingState.routes.map((route, index) => (
                    <RouteEditorCard
                      key={`route-${index}`}
                      title={tx("Route #{index}", { index: index + 1 })}
                      route={route}
                      backendPoolOptions={backendPoolOptions}
                      routeTargetOptions={routeTargetOptions}
                      onChange={(next) => updateRoute(index, next)}
                      onRemove={readOnly ? undefined : () =>
                        applyStructuredChange((current) => ({
                          ...current,
                          routes: current.routes.filter((_, candidateIndex) => candidateIndex !== index),
                        }))
                      }
                      allowMatch
                    />
                  ))}
                </div>
              ) : null}
              {routingTab === "default" ? (
                routingState.defaultRoute ? (
                  <RouteEditorCard
                    title={tx("Default route")}
                    route={routingState.defaultRoute}
                    backendPoolOptions={backendPoolOptions}
                    routeTargetOptions={routeTargetOptions}
                    onChange={(next) =>
                      applyStructuredChange((current) => ({
                        ...current,
                        defaultRoute: next,
                      }))
                    }
                    allowMatch={false}
                  />
                ) : (
                  <EmptyState>{tx("Configure a default route when you want a distinct fallback before upstream selection.")}</EmptyState>
                )
              ) : null}
            </div>
          </SectionCard>

          <SectionCard
            title="Dry Run"
            subtitle="Confirm which route would win and which final upstream URL would be used without changing live traffic."
            actions={
              <PrimaryButton onClick={() => void runDryRun()} disabled={loading || dryRunning}>
                {dryRunning ? tx("Running...") : tx("Run dry-run")}
              </PrimaryButton>
            }
          >
            <div className="grid gap-3 md:grid-cols-2">
              <Field label="Host" hint="Optional. Leave empty to simulate host-agnostic routing.">
                <input className={inputClass} value={dryRunHost} onChange={(e) => setDryRunHost(e.target.value)} placeholder="api.example.com" />
              </Field>
              <Field label="Path" hint="Query strings are allowed here, for example `/servicea/users?lang=en&utm_source=ads`.">
                <input className={inputClass} value={dryRunPath} onChange={(e) => setDryRunPath(e.target.value)} placeholder="/servicea/users?lang=en" />
              </Field>
            </div>
            {dryRunMessages.length > 0 ? (
              <div className="rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
                {dryRunMessages.map((message, index) => (
                  <div key={`dry-run-message-${index}`}>{message}</div>
                ))}
              </div>
            ) : null}
            {dryRunResult ? (
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4 text-sm">
                <StatBox label="Source" value={dryRunResult.source || "-"} />
                <StatBox label="Route" value={dryRunResult.route_name || "-"} />
                <StatBox label="Upstream" value={dryRunResult.selected_upstream || "-"} />
                <StatBox label="Final URL" value={dryRunResult.final_url || "-"} />
              </div>
            ) : null}
          </SectionCard>

          <SectionCard
            title="WAF Debug Response Headers"
            subtitle="Keep these off in normal operation. Turn them on only when you need client-visible hit/rule diagnostics."
          >
            <div className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
              <Field
                label="Expose WAF Debug Headers"
                hint="Controls whether proxied responses include X-WAF-Hit and X-WAF-RuleIDs."
              >
                <label className="flex h-10 items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={routingState.exposeWAFDebugHeaders}
                    onChange={(e) =>
                      applyStructuredChange((current) => ({
                        ...current,
                        exposeWAFDebugHeaders: e.target.checked,
                      }))
                    }
                  />
                  <span>{routingState.exposeWAFDebugHeaders ? tx("Enabled") : tx("Disabled")}</span>
                </label>
              </Field>
              <p className="text-xs text-neutral-500">
                {tx("These headers are for troubleshooting only. Keep them off for normal client traffic and prefer logs or audit data for routine observability.")}
              </p>
            </div>
          </SectionCard>

          <SectionCard
            title="Named Upstream Observability Header"
            subtitle="Optionally tell backend applications which named upstream handled the request. This is observability-only and applies only to Proxy Rules > Upstreams targets."
          >
            <div className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
              <Field
                label="Emit X-Tukuyomi-Upstream-Name"
                hint="When enabled, named upstream requests carry X-Tukuyomi-Upstream-Name to the backend. Direct URLs and generated vhost targets do not receive it."
              >
                <label className="flex h-10 items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={routingState.emitUpstreamNameRequestHeader}
                    onChange={(e) =>
                      applyStructuredChange((current) => ({
                        ...current,
                        emitUpstreamNameRequestHeader: e.target.checked,
                      }))
                    }
                  />
                  <span>{routingState.emitUpstreamNameRequestHeader ? tx("Enabled") : tx("Disabled")}</span>
                </label>
              </Field>
              <p className="text-xs text-neutral-500">
                {tx("This header is internal observability data. It is stripped from inbound requests and re-added only when a named upstream is finally selected after WAF.")}
              </p>
            </div>
          </SectionCard>

          <SectionCard
            title="Response Header Sanitizer"
            subtitle="Proxy-level response header safety runs after route response_headers. Use this for product-wide removal policy rather than per-route cleanup."
          >
            <ResponseHeaderSanitizeEditor
              value={routingState.responseHeaderSanitize}
              onChange={(next) =>
                applyStructuredChange((current) => ({
                  ...current,
                  responseHeaderSanitize: next,
                }))
              }
            />
          </SectionCard>

          {dryRunResult ? (
            <SectionCard title="Dry Run Result">
              <div className="app-code-shell">
                <pre className="app-code-block">{JSON.stringify(dryRunResult, null, 2)}</pre>
              </div>
            </SectionCard>
          ) : null}

          <SectionCard title="Raw JSON" subtitle="Keep using the existing raw editor for transport and low-level fields that are not part of the structured routing editor.">
            <textarea
              className="w-full h-[420px] p-3 border rounded-xl font-mono text-sm leading-5 outline-none focus:ring-2 focus:ring-black/20"
              value={raw}
              onChange={(e) => handleRawChange(e.target.value)}
              spellCheck={false}
            />
          </SectionCard>

          <SectionCard title="Runtime Proxy">
            <div className="app-code-shell">
              <pre className="app-code-block">{JSON.stringify(proxy, null, 2)}</pre>
            </div>
          </SectionCard>

          <SectionCard title="Upstream Health">
            <div className="app-code-shell">
              <pre className="app-code-block">{JSON.stringify(health, null, 2)}</pre>
            </div>
          </SectionCard>

          <datalist id="proxy-route-target-options">
            {routeTargetOptions.map((value) => (
              <option key={value} value={value} />
            ))}
          </datalist>
        </div>

        <div className="space-y-4">
          <SectionCard title="Recent changes" subtitle="Successful proxy-rules apply and rollback operations are recorded here.">
            <div className="mb-3 grid gap-3 sm:grid-cols-2">
              <Field label="Limit">
                <select
                  className={inputClass}
                  value={auditLimit}
                  onChange={(e) => setAuditLimit(Number(e.target.value) as 20 | 50 | 100)}
                >
                  <option value={20}>20</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </Field>
              <Field label="Actor filter">
                <input
                  className={inputClass}
                  value={auditActorFilter}
                  onChange={(e) => setAuditActorFilter(e.target.value)}
                  placeholder="alice@example.com"
                />
              </Field>
              <div className="flex items-end sm:justify-end">
                <ActionButton onClick={exportAuditEntries} disabled={auditLoading || visibleAuditEntries.length === 0}>
                  {tx("Export JSON")}
                </ActionButton>
              </div>
              <Field label="Action filter">
                <select
                  className={inputClass}
                  value={auditActionFilter}
                  onChange={(e) => setAuditActionFilter(e.target.value as ProxyRulesAuditActionFilter)}
                >
                  <option value="all">{tx("all")}</option>
                  <option value="apply">{tx("apply")}</option>
                  <option value="rollback">{tx("rollback")}</option>
                </select>
              </Field>
            </div>
            {auditLoading ? <div className="text-sm text-neutral-500">{tx("Loading recent changes...")}</div> : null}
            {!auditLoading && auditError ? (
              <NoticeBar tone="error">{auditError}</NoticeBar>
            ) : null}
            {!auditLoading && !auditError && auditNotice ? (
              <NoticeBar tone="success">{auditNotice}</NoticeBar>
            ) : null}
            {!auditLoading && !auditError && auditEntries.length === 0 ? (
              <EmptyState>{tx("No config changes recorded yet.")}</EmptyState>
            ) : null}
            {!auditLoading && !auditError && auditEntries.length > 0 && visibleAuditEntries.length === 0 ? (
              <EmptyState>{tx("No changes match the current filters.")}</EmptyState>
            ) : null}
            {!auditLoading && !auditError && visibleAuditEntries.length > 0 ? (
              <div className="space-y-2">
                {visibleAuditEntries.map((entry, index) => (
                  <button
                    key={`${entry.ts || "audit"}-${index}`}
                    type="button"
                    className="min-w-0 w-full rounded-xl border border-neutral-200 bg-neutral-50 p-3 text-left transition hover:border-neutral-300 hover:bg-white"
                    onClick={() => previewAuditEntry(entry)}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="min-w-0 flex flex-wrap items-center gap-2">
                        <Badge color={entry.event === "proxy_rules_rollback" ? "amber" : "green"}>
                          {formatProxyRulesAuditAction(entry.event)}
                        </Badge>
                        {entry.restored_from?.etag ? (
                          <span className="max-w-full break-all whitespace-normal rounded bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800">
                            {tx("restored")} {entry.restored_from.etag}
                          </span>
                        ) : null}
                      </div>
                      <span className="shrink-0 text-xs text-neutral-500">{formatTimestamp(entry.ts)}</span>
                    </div>
                    <div className="mt-2 min-w-0 break-all text-sm font-medium text-neutral-900">
                      {entry.actor || tx("unknown")}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-neutral-500">
                      {entry.ip ? <span>{tx("IP")} {entry.ip}</span> : null}
                      {entry.restored_from?.timestamp ? <span>{tx("restored at")} {formatTimestamp(entry.restored_from.timestamp)}</span> : null}
                    </div>
                    <div className="mt-1 min-w-0 break-all font-mono text-xs text-neutral-600">
                      {formatProxyRulesAuditTransition(entry)}
                    </div>
                  </button>
                ))}
              </div>
            ) : null}
          </SectionCard>

        </div>
      </div>
      {diffPreview ? (
        <DiffPreviewModal
          preview={diffPreview}
          applying={saving}
          onCancel={() => setDiffPreview(null)}
          onApply={!readOnly && diffPreview.applyLabel ? () => void applyPreview() : undefined}
          onCopySummary={diffPreview.copyText ? () => void handleCopyAuditSummary() : undefined}
        />
      ) : null}
    </div>
  );

  function updateRoute(index: number, next: ProxyRoute) {
    applyStructuredChange((current) => ({
      ...current,
      routes: current.routes.map((route, routeIndex) => (routeIndex === index ? next : route)),
    }));
  }

  function updateUpstream(index: number, next: ProxyUpstream) {
    if (upstreamProbeResult?.index === index) {
      setUpstreamProbeResult(null);
    }
    applyStructuredChange((current) => ({
      ...current,
      upstreams: current.upstreams.map((upstream, upstreamIndex) => (upstreamIndex === index ? next : upstream)),
    }));
  }

  function updateBackendPool(index: number, next: ProxyBackendPool) {
    const previousName = routingState.backendPools[index]?.name ?? "";
    applyStructuredChange((current) => {
      const backendPools = current.backendPools.map((pool, poolIndex) => (poolIndex === index ? next : pool));
      if (!previousName || previousName === next.name) {
        return {
          ...current,
          backendPools,
        };
      }
      const rewriteRoute = (route: ProxyRoute): ProxyRoute =>
        route.action.backendPool === previousName
          ? { ...route, action: { ...route.action, backendPool: next.name } }
          : route;
      return {
        ...current,
        backendPools,
        routes: current.routes.map(rewriteRoute),
        defaultRoute: current.defaultRoute ? rewriteRoute(current.defaultRoute) : null,
      };
    });
  }
}

function RouteEditorCard({
  title,
  route,
  backendPoolOptions,
  routeTargetOptions,
  onChange,
  onRemove,
  allowMatch,
}: {
  title: string;
  route: ProxyRoute;
  backendPoolOptions: string[];
  routeTargetOptions: string[];
  onChange: (next: ProxyRoute) => void;
  onRemove?: () => void;
  allowMatch: boolean;
}) {
  const tx = translateCurrent;
  const pathType = route.path?.type || "";
  const pathValue = route.path?.value || "";

  const setAction = (nextAction: ProxyRouteAction) => onChange({ ...route, action: nextAction });

  return (
    <div className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="font-medium">{title}</div>
          <div className="text-xs text-neutral-500">{tx("Priority decides order. The first matching route wins.")}</div>
        </div>
        {onRemove ? (
          <button type="button" className="text-sm text-red-700 underline" onClick={onRemove}>
            {tx("Remove")}
          </button>
        ) : null}
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        <Field label="Name">
          <input className={inputClass} value={route.name} onChange={(e) => onChange({ ...route, name: e.target.value })} placeholder="service-a-prefix" />
        </Field>
        {allowMatch ? (
          <Field label="Priority">
            <input
              className={inputClass}
              type="number"
              value={route.priority}
              onChange={(e) => onChange({ ...route, priority: Number(e.target.value || 0) })}
            />
          </Field>
        ) : (
          <Field label="Priority">
            <div className="flex h-10 items-center rounded-xl border border-dashed border-neutral-300 px-3 text-sm text-neutral-500">{tx("Not used for default route")}</div>
          </Field>
        )}
        <Field label="Enabled">
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={route.enabled} onChange={(e) => onChange({ ...route, enabled: e.target.checked })} />
            <span>{route.enabled ? tx("Enabled") : tx("Disabled")}</span>
          </label>
        </Field>
      </div>

      {allowMatch ? (
        <div className="grid gap-3 md:grid-cols-2">
          <Field label="Hosts" hint="One host per line. Leave empty to match any host.">
            <MultilineTextArea
              className={textAreaClass}
              value={route.hosts}
              onValueChange={(next) => onChange({ ...route, hosts: next })}
              serialize={stringListToMultiline}
              parse={multilineToStringList}
              equals={stringListEqual}
              spellCheck={false}
              placeholder={"api.example.com\n*.example.net"}
            />
          </Field>
          <div className="grid gap-3">
            <Field label="Path match type">
              <select
                className={inputClass}
                value={pathType}
                onChange={(e) => {
                  const nextType = e.target.value as RoutePathType;
                  if (!nextType) {
                    onChange({
                      ...route,
                      path: null,
                      action: route.action.pathRewrite ? { ...route.action, pathRewrite: null } : route.action,
                    });
                    return;
                  }
                  onChange({
                    ...route,
                    path: { type: nextType, value: pathValue || "/" },
                    action: nextType === "regex" ? { ...route.action, pathRewrite: null } : route.action,
                  });
                }}
              >
                <option value="">{tx("any path")}</option>
                <option value="exact">exact</option>
                <option value="prefix">prefix</option>
                <option value="regex">regex</option>
              </select>
            </Field>
            <Field label="Path match value" hint={pathType === "regex" ? "Regex runs against request path only." : "Exact and prefix values should start with /."}>
              <input
                className={inputClass}
                value={pathValue}
                onChange={(e) => onChange({ ...route, path: route.path ? { ...route.path, value: e.target.value } : { type: "prefix", value: e.target.value } })}
                placeholder={pathType === "regex" ? "^/servicea/(users|orders)/[0-9]+$" : "/servicea/"}
                disabled={!pathType}
              />
            </Field>
          </div>
        </div>
      ) : null}

      <div className="grid gap-3 md:grid-cols-3">
        <Field label="Backend pool" hint="Standard balancing path. Select a named backend pool to scope target selection to that pool only.">
          <select
            className={inputClass}
            value={route.action.backendPool}
            onChange={(e) =>
              setAction({
                ...route.action,
                backendPool: e.target.value,
                upstream: e.target.value ? "" : route.action.upstream,
                canaryUpstream: e.target.value ? "" : route.action.canaryUpstream,
              })
            }
          >
            <option value="">{tx("none")}</option>
            {backendPoolOptions.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Action upstream" hint="Configured upstream name only. Route targets do not accept direct URLs or legacy generated targets.">
          <input
            className={inputClass}
            list={routeTargetOptions.length > 0 ? "proxy-route-target-options" : undefined}
            value={route.action.upstream}
            onChange={(e) => setAction({ ...route.action, upstream: e.target.value, backendPool: "" })}
            placeholder="service-a"
          />
        </Field>
        <Field label="Host rewrite" hint="Optional outbound Host header override.">
          <input
            className={inputClass}
            value={route.action.hostRewrite}
            onChange={(e) => setAction({ ...route.action, hostRewrite: e.target.value })}
            placeholder="service-a.internal"
          />
        </Field>
        <Field label="Path rewrite prefix" hint={pathType === "regex" ? "Disabled for regex path routes." : "Optional. Example: /service-a/"}>
          <input
            className={inputClass}
            value={route.action.pathRewrite?.prefix || ""}
            onChange={(e) =>
              setAction({
                ...route.action,
                pathRewrite: e.target.value ? { prefix: e.target.value } : null,
              })
            }
            placeholder="/service-a/"
            disabled={!allowMatch || pathType === "regex"}
          />
        </Field>
      </div>

      <QueryOperationsEditor
        title="Query rewrite"
        description="Applied after route matching. Operations run in remove, remove-prefixes, set, then add order. Route matching itself still ignores query strings."
        ops={route.action.queryRewrite}
        onChange={(next) => setAction({ ...route.action, queryRewrite: next })}
      />

      <div className="grid gap-3 md:grid-cols-4">
        <Field label="Canary upstream" hint="Optional secondary upstream name for weighted canary routing.">
          <input
            className={inputClass}
            list={routeTargetOptions.length > 0 ? "proxy-route-target-options" : undefined}
            value={route.action.canaryUpstream}
            onChange={(e) => setAction({ ...route.action, canaryUpstream: e.target.value })}
            placeholder="service-a-canary"
            disabled={!!route.action.backendPool.trim()}
          />
        </Field>
        <Field label="Canary %" hint="1-99 when canary is set.">
          <input
            className={inputClass}
            type="number"
            min={1}
            max={99}
            value={route.action.canaryWeightPercent}
            onChange={(e) => setAction({ ...route.action, canaryWeightPercent: Number(e.target.value || 10) })}
            disabled={!route.action.canaryUpstream.trim() || !!route.action.backendPool.trim()}
          />
        </Field>
        <Field label="Hash policy" hint="Optional sticky/hash routing policy for this route.">
          <select
            className={inputClass}
            value={route.action.hashPolicy}
            onChange={(e) =>
              setAction({
                ...route.action,
                hashPolicy: e.target.value as "" | "client_ip" | "header" | "cookie" | "jwt_sub",
                hashKey: e.target.value === "header" || e.target.value === "cookie" ? route.action.hashKey : "",
              })
            }
          >
            <option value="">none</option>
            <option value="client_ip">client_ip</option>
            <option value="header">header</option>
            <option value="cookie">cookie</option>
            <option value="jwt_sub">jwt_sub</option>
          </select>
        </Field>
        <Field label="Hash key" hint="Required only for header/cookie hash.">
          <input
            className={inputClass}
            value={route.action.hashKey}
            onChange={(e) => setAction({ ...route.action, hashKey: e.target.value })}
            placeholder={route.action.hashPolicy === "cookie" ? "session" : "X-User"}
            disabled={route.action.hashPolicy !== "header" && route.action.hashPolicy !== "cookie"}
          />
        </Field>
      </div>

      <div className="grid gap-3 xl:grid-cols-2">
        <HeaderOperationsEditor
          title="Request header operations"
          description="set/add/remove are applied after proxy forwarding headers are prepared. Restricted hop-by-hop, X-Forwarded-*, and X-Tukuyomi-Upstream-Name are still rejected by validation."
          ops={route.action.requestHeaders}
          onChange={(next) => setAction({ ...route.action, requestHeaders: next })}
        />
        <HeaderOperationsEditor
          title="Response header operations"
          description="set/add/remove are applied on the upstream response before it is returned to the client."
          ops={route.action.responseHeaders}
          onChange={(next) => setAction({ ...route.action, responseHeaders: next })}
        />
      </div>
    </div>
  );
}

function BackendPoolEditorCard({
  title,
  pool,
  upstreamOptions,
  onChange,
  onRemove,
}: {
  title: string;
  pool: ProxyBackendPool;
  upstreamOptions: string[];
  onChange: (next: ProxyBackendPool) => void;
  onRemove?: () => void;
}) {
  const tx = translateCurrent;
  return (
    <div className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="font-medium">{title}</div>
          <div className="text-xs text-neutral-500">{tx("Pools scope balancing to selected named upstream members. Routes bind to pools; Backends keeps runtime node controls.")}</div>
        </div>
        {onRemove ? (
          <button type="button" className="text-sm text-red-700 underline" onClick={onRemove}>
            {tx("Remove")}
          </button>
        ) : null}
      </div>

      <div className="grid gap-3 md:grid-cols-4">
        <Field label="Name">
          <input className={inputClass} value={pool.name} onChange={(e) => onChange({ ...pool, name: e.target.value })} placeholder="site-api" />
        </Field>
        <Field label="Strategy">
          <select
            className={inputClass}
            value={pool.strategy}
            onChange={(e) => onChange({ ...pool, strategy: e.target.value as ProxyBackendPool["strategy"] })}
          >
            <option value="">{tx("round_robin (default)")}</option>
            <option value="round_robin">round_robin</option>
            <option value="least_conn">least_conn</option>
          </select>
        </Field>
        <Field label="Hash policy" hint="Optional sticky/hash policy for members inside this pool.">
          <select
            className={inputClass}
            value={pool.hashPolicy}
            onChange={(e) =>
              onChange({
                ...pool,
                hashPolicy: e.target.value as ProxyBackendPool["hashPolicy"],
                hashKey: e.target.value === "header" || e.target.value === "cookie" ? pool.hashKey : "",
              })
            }
          >
            <option value="">none</option>
            <option value="client_ip">client_ip</option>
            <option value="header">header</option>
            <option value="cookie">cookie</option>
            <option value="jwt_sub">jwt_sub</option>
          </select>
        </Field>
        <Field label="Hash key" hint="Required only for header/cookie hash.">
          <input
            className={inputClass}
            value={pool.hashKey}
            onChange={(e) => onChange({ ...pool, hashKey: e.target.value })}
            placeholder={pool.hashPolicy === "cookie" ? "session" : "X-User"}
            disabled={pool.hashPolicy !== "header" && pool.hashPolicy !== "cookie"}
          />
        </Field>
      </div>

      <Field label="Members" hint="One named upstream per line. Only Proxy Rules > Upstreams entries are valid members.">
        <MultilineTextArea
          className={textAreaClass}
          value={pool.members}
          onValueChange={(next) => onChange({ ...pool, members: next })}
          serialize={stringListToMultiline}
          parse={multilineToStringList}
          equals={stringListEqual}
          spellCheck={false}
          placeholder={upstreamOptions.length > 0 ? upstreamOptions.join("\n") : "upstream-1\nupstream-2"}
        />
      </Field>

      <div className="rounded-xl border border-neutral-200 bg-white p-3 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-sm font-medium">{tx("Sticky session")}</div>
            <div className="text-xs text-neutral-500">{tx("Issue a signed affinity cookie so clients return to the same selectable backend in this pool.")}</div>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={pool.stickySession.enabled}
              onChange={(e) =>
                onChange({
                  ...pool,
                  stickySession: {
                    ...pool.stickySession,
                    enabled: e.target.checked,
                    cookieName: pool.stickySession.cookieName || defaultStickyCookieName(pool.name),
                  },
                })
              }
            />
            <span>{pool.stickySession.enabled ? tx("Enabled") : tx("Disabled")}</span>
          </label>
        </div>
        <div className="grid gap-3 md:grid-cols-4">
          <Field label="Cookie name">
            <input
              className={inputClass}
              value={pool.stickySession.cookieName}
              onChange={(e) => onChange({ ...pool, stickySession: { ...pool.stickySession, cookieName: e.target.value } })}
              placeholder={defaultStickyCookieName(pool.name)}
              disabled={!pool.stickySession.enabled}
            />
          </Field>
          <Field label="TTL seconds">
            <input
              className={inputClass}
              type="number"
              min={1}
              max={2592000}
              value={pool.stickySession.ttlSeconds}
              onChange={(e) => onChange({ ...pool, stickySession: { ...pool.stickySession, ttlSeconds: Number(e.target.value || 86400) } })}
              disabled={!pool.stickySession.enabled}
            />
          </Field>
          <Field label="Path">
            <input
              className={inputClass}
              value={pool.stickySession.path}
              onChange={(e) => onChange({ ...pool, stickySession: { ...pool.stickySession, path: e.target.value } })}
              placeholder="/"
              disabled={!pool.stickySession.enabled}
            />
          </Field>
          <Field label="Domain">
            <input
              className={inputClass}
              value={pool.stickySession.domain}
              onChange={(e) => onChange({ ...pool, stickySession: { ...pool.stickySession, domain: e.target.value } })}
              placeholder="optional"
              disabled={!pool.stickySession.enabled}
            />
          </Field>
        </div>
        <div className="grid gap-3 md:grid-cols-4">
          <Field label="SameSite">
            <select
              className={inputClass}
              value={pool.stickySession.sameSite}
              onChange={(e) => onChange({ ...pool, stickySession: { ...pool.stickySession, sameSite: e.target.value as ProxyBackendPool["stickySession"]["sameSite"] } })}
              disabled={!pool.stickySession.enabled}
            >
              <option value="lax">lax</option>
              <option value="strict">strict</option>
              <option value="none">none</option>
            </select>
          </Field>
          <Field label="Secure">
            <label className="flex h-10 items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={pool.stickySession.secure}
                onChange={(e) => onChange({ ...pool, stickySession: { ...pool.stickySession, secure: e.target.checked } })}
                disabled={!pool.stickySession.enabled}
              />
              <span>{tx("Secure cookie")}</span>
            </label>
          </Field>
          <Field label="HttpOnly">
            <label className="flex h-10 items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={pool.stickySession.httpOnly}
                onChange={(e) => onChange({ ...pool, stickySession: { ...pool.stickySession, httpOnly: e.target.checked } })}
                disabled={!pool.stickySession.enabled}
              />
              <span>{tx("HttpOnly cookie")}</span>
            </label>
          </Field>
          <Field label="Cookie contract">
            <div className="flex min-h-10 items-center rounded-xl border border-dashed border-neutral-300 px-3 text-xs text-neutral-500">
              {tx("Signed value stores upstream name and expiry only. Invalid cookies are ignored.")}
            </div>
          </Field>
        </div>
      </div>
    </div>
  );
}

function ResponseHeaderSanitizeEditor({
  value,
  onChange,
}: {
  value: ProxyResponseHeaderSanitizeEditorState;
  onChange: (next: ProxyResponseHeaderSanitizeEditorState) => void;
}) {
  const tx = translateCurrent;
  return (
    <div className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-4">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Field label="Mode" hint="auto uses the embedded OWASP list, manual removes only custom_remove, off disables the default list.">
          <select
            className={inputClass}
            value={value.mode}
            onChange={(e) =>
              onChange({
                ...value,
                mode: e.target.value as "auto" | "manual" | "off",
              })
            }
          >
            <option value="auto">auto</option>
            <option value="manual">manual</option>
            <option value="off">off</option>
          </select>
        </Field>
        <Field label="Debug log" hint="Logs removed header names only.">
          <label className="flex h-10 items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={value.debugLog}
              onChange={(e) =>
                onChange({
                  ...value,
                  debugLog: e.target.checked,
                })
              }
            />
            <span>{value.debugLog ? tx("Enabled") : tx("Disabled")}</span>
          </label>
        </Field>
        <StatBox label="Custom remove" value={String(value.customRemove.length)} />
        <StatBox label="Custom keep" value={String(value.customKeep.length)} />
      </div>
      <div className="grid gap-3 xl:grid-cols-2">
        <Field label="Custom remove" hint="One header name per line. Applies in auto, manual, and off.">
          <MultilineTextArea
            className={textAreaClass}
            value={value.customRemove}
            onValueChange={(next) =>
              onChange({
                ...value,
                customRemove: next,
              })
            }
            serialize={stringListToMultiline}
            parse={multilineToStringList}
            equals={stringListEqual}
            spellCheck={false}
            placeholder={"X-Internal-Leak\nX-My-Internal-Header"}
          />
        </Field>
        <Field label="Custom keep" hint="One header name per line. Used only to exempt headers from auto mode's embedded list.">
          <MultilineTextArea
            className={textAreaClass}
            value={value.customKeep}
            onValueChange={(next) =>
              onChange({
                ...value,
                customKeep: next,
              })
            }
            serialize={stringListToMultiline}
            parse={multilineToStringList}
            equals={stringListEqual}
            spellCheck={false}
            placeholder={"Server\nX-Envoy-Internal"}
            disabled={value.mode !== "auto"}
          />
        </Field>
      </div>
    </div>
  );
}

function QueryOperationsEditor({
  title,
  description,
  ops,
  onChange,
}: {
  title: string;
  description: string;
  ops: ProxyRouteQueryOperations;
  onChange: (next: ProxyRouteQueryOperations) => void;
}) {
  const tx = translateCurrent;
  return (
    <div className="rounded-xl border border-neutral-200 bg-white p-3 space-y-3">
      <div>
        <div className="font-medium text-sm">{tx(title)}</div>
        <div className="text-xs text-neutral-500">{tx(description)}</div>
      </div>
      <div className="grid gap-3 xl:grid-cols-2">
        <Field label="Set" hint="One `key=value` pair per line. Replaces existing values for that key.">
          <MultilineTextArea
            className={textAreaClass}
            value={ops.set}
            onValueChange={(next) =>
              onChange({
                ...ops,
                set: next,
              })
            }
            serialize={queryMapToMultiline}
            parse={multilineToQueryMap}
            equals={mapEqual}
            spellCheck={false}
            placeholder={"lang=ja\nmode=preview"}
          />
        </Field>
        <Field label="Add" hint="One `key=value` pair per line. Appends another value for that key.">
          <MultilineTextArea
            className={textAreaClass}
            value={ops.add}
            onValueChange={(next) =>
              onChange({
                ...ops,
                add: next,
              })
            }
            serialize={queryMapToMultiline}
            parse={multilineToQueryMap}
            equals={mapEqual}
            spellCheck={false}
            placeholder="preview=1"
          />
        </Field>
        <Field label="Remove" hint="One query key per line.">
          <MultilineTextArea
            className={textAreaClass}
            value={ops.remove}
            onValueChange={(next) =>
              onChange({
                ...ops,
                remove: next,
              })
            }
            serialize={stringListToMultiline}
            parse={multilineToStringList}
            equals={stringListEqual}
            spellCheck={false}
            placeholder={"debug\ntracking_id"}
          />
        </Field>
        <Field label="Remove prefixes" hint="One query-key prefix per line, for example `utm_`.">
          <MultilineTextArea
            className={textAreaClass}
            value={ops.removePrefixes}
            onValueChange={(next) =>
              onChange({
                ...ops,
                removePrefixes: next,
              })
            }
            serialize={stringListToMultiline}
            parse={multilineToStringList}
            equals={stringListEqual}
            spellCheck={false}
            placeholder={"utm_\nfbclid"}
          />
        </Field>
      </div>
    </div>
  );
}

function HeaderOperationsEditor({
  title,
  description,
  ops,
  onChange,
}: {
  title: string;
  description: string;
  ops: ProxyRouteHeaderOperations;
  onChange: (next: ProxyRouteHeaderOperations) => void;
}) {
  const tx = translateCurrent;
  return (
    <div className="rounded-xl border border-neutral-200 bg-white p-3 space-y-3">
      <div>
        <div className="font-medium text-sm">{tx(title)}</div>
        <div className="text-xs text-neutral-500">{tx(description)}</div>
      </div>
      <Field label="Set" hint="One `Header: value` pair per line.">
        <MultilineTextArea
          className={textAreaClass}
          value={ops.set}
          onValueChange={(next) =>
            onChange({
              ...ops,
              set: next,
            })
          }
          serialize={headerMapToMultiline}
          parse={multilineToHeaderMap}
          equals={mapEqual}
          spellCheck={false}
          placeholder={"X-Service: service-a\nCache-Control: no-store"}
        />
      </Field>
      <Field label="Add" hint="One `Header: value` pair per line.">
        <MultilineTextArea
          className={textAreaClass}
          value={ops.add}
          onValueChange={(next) =>
            onChange({
              ...ops,
              add: next,
            })
          }
          serialize={headerMapToMultiline}
          parse={multilineToHeaderMap}
          equals={mapEqual}
          spellCheck={false}
          placeholder="X-Route: service-a-prefix"
        />
      </Field>
      <Field label="Remove" hint="One header name per line.">
        <MultilineTextArea
          className={textAreaClass}
          value={ops.remove}
          onValueChange={(next) =>
            onChange({
              ...ops,
              remove: next,
            })
          }
          serialize={stringListToMultiline}
          parse={multilineToStringList}
          equals={stringListEqual}
          spellCheck={false}
          placeholder={"X-Debug\nX-Internal-Trace"}
        />
      </Field>
    </div>
  );
}

function SectionCard({
  title,
  subtitle,
  actions,
  children,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
}) {
  const tx = translateCurrent;
  return (
    <section className="rounded-2xl border border-neutral-200 bg-white p-4 shadow-sm space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">{tx(title)}</h2>
          {subtitle ? <p className="text-sm text-neutral-500">{tx(subtitle)}</p> : null}
        </div>
        {actions ? <div>{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  const tx = translateCurrent;
  return (
    <label className="grid gap-1">
      <span className="text-sm font-medium">{tx(label)}</span>
      {children}
      {hint ? <span className="text-xs text-neutral-500">{tx(hint)}</span> : null}
    </label>
  );
}

function StatBox({ label, value }: { label: string; value: string }) {
  const tx = translateCurrent;
  return (
    <div className="rounded-xl border border-neutral-200 bg-neutral-50 px-3 py-2">
      <div className="text-xs uppercase tracking-wide text-neutral-500">{tx(label)}</div>
      <div className="text-sm font-medium break-all">{value}</div>
    </div>
  );
}

function stringListEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function mapEqual(a: Record<string, string>, b: Record<string, string>): boolean {
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  if (aKeys.length !== bKeys.length) {
    return false;
  }
  for (const key of aKeys) {
    if (a[key] !== b[key]) {
      return false;
    }
  }
  return true;
}

function MultilineTextArea<T>({
  value,
  onValueChange,
  serialize,
  parse,
  equals,
  ...props
}: Omit<React.TextareaHTMLAttributes<HTMLTextAreaElement>, "value" | "onChange"> & {
  value: T;
  onValueChange: (next: T) => void;
  serialize: (value: T) => string;
  parse: (value: string) => T;
  equals: (a: T, b: T) => boolean;
}) {
  const serialized = useMemo(() => serialize(value), [serialize, value]);
  const [draft, setDraft] = useState(serialized);

  useEffect(() => {
    setDraft(serialized);
  }, [serialized]);

  return (
    <textarea
      {...props}
      value={draft}
      onChange={(event) => {
        const nextText = event.target.value;
        setDraft(nextText);
        const parsed = parse(nextText);
        if (!equals(parsed, value)) {
          onValueChange(parsed);
        }
      }}
    />
  );
}

function EmptyState({ children }: { children: React.ReactNode }) {
  return <div className="rounded-xl border border-dashed border-neutral-300 bg-neutral-50 px-4 py-6 text-sm text-neutral-500">{children}</div>;
}

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

function NoticeBar({
  tone,
  className = "",
  children,
}: {
  tone: "success" | "error" | "warn";
  className?: string;
  children: React.ReactNode;
}) {
  const cls =
    tone === "success"
      ? "border-green-300 bg-green-50 text-green-900"
      : tone === "error"
        ? "border-red-300 bg-red-50 text-red-900"
        : "border-amber-300 bg-amber-50 text-amber-900";
  return <div className={`rounded border px-3 py-2 text-xs whitespace-pre-wrap ${cls} ${className}`.trim()}>{children}</div>;
}

function MonoTag({ label, value }: { label: string; value: string }) {
  const tx = translateCurrent;
  return (
    <div className="hidden md:flex items-center gap-1 text-xs">
      <span className="text-neutral-500">{tx(label)}:</span>
      <code className="px-2 py-0.5 bg-neutral-100 rounded max-w-[420px] truncate">{value}</code>
    </div>
  );
}

function DiffPreviewModal({
  preview,
  applying,
  onCancel,
  onApply,
  onCopySummary,
}: {
  preview: ProxyRulesDiffPreview;
  applying: boolean;
  onCancel: () => void;
  onApply?: () => void;
  onCopySummary?: () => void;
}) {
  const tx = translateCurrent;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/45 px-4 py-6">
      <div className="w-full max-w-5xl rounded-2xl border border-neutral-200 bg-white shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-neutral-200 px-5 py-4">
          <div>
            <h2 className="text-lg font-semibold">{preview.title}</h2>
            <p className="text-sm text-neutral-500">{preview.description}</p>
            {preview.note ? <p className="mt-1 text-xs text-amber-700">{preview.note}</p> : null}
          </div>
          <button type="button" className="text-sm underline" onClick={onCancel} disabled={applying}>
            {tx("close")}
          </button>
        </div>
        <div className="space-y-3 px-5 py-4">
          {preview.metadata && preview.metadata.length > 0 ? (
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              {preview.metadata.map((item) => (
                <div key={`${item.label}-${item.value}`} className="rounded-xl border border-neutral-200 bg-neutral-50 px-3 py-2">
                  <div className="text-[11px] font-medium uppercase tracking-wide text-neutral-500">{item.label}</div>
                  <div className="mt-1 break-all text-sm text-neutral-900">{item.value}</div>
                </div>
              ))}
            </div>
          ) : null}
          {preview.parseError ? (
            <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800 whitespace-pre-wrap">{preview.parseError}</div>
          ) : null}
          {!preview.parseError && preview.lines.length === 0 ? (
            <div className="rounded-xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm text-neutral-600">{tx("No visible diff.")}</div>
          ) : null}
          {!preview.parseError ? (
            <div className="max-h-[60vh] overflow-auto rounded-xl border border-neutral-200 bg-neutral-950">
              <pre className="min-w-full p-4 font-mono text-xs leading-5 text-neutral-100">
                {preview.lines.map((line, index) => (
                  <div
                    key={`${line.kind}-${index}-${line.text}`}
                    className={
                      line.kind === "add"
                        ? "bg-green-950/70 text-green-300"
                        : line.kind === "remove"
                          ? "bg-red-950/70 text-red-300"
                          : "text-neutral-300"
                    }
                  >
                    <span className="mr-3 inline-block w-4 select-none text-center">{line.kind === "add" ? "+" : line.kind === "remove" ? "-" : " "}</span>
                    <span>{line.text || " "}</span>
                  </div>
                ))}
              </pre>
            </div>
          ) : null}
        </div>
        <div className="flex justify-end gap-2 border-t border-neutral-200 px-5 py-4">
          {onCopySummary ? (
            <ActionButton onClick={onCopySummary} disabled={applying}>
              {tx("Copy summary")}
            </ActionButton>
          ) : null}
          <ActionButton onClick={onCancel} disabled={applying}>
            {onApply ? tx("Cancel") : tx("Close")}
          </ActionButton>
          {onApply && preview.applyLabel ? (
            <PrimaryButton onClick={onApply} disabled={applying || !!preview.parseError}>
              {applying ? tx("Applying...") : preview.applyLabel}
            </PrimaryButton>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function ActionButton({
  children,
  disabled,
  onClick,
}: {
  children: React.ReactNode;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border disabled:opacity-50" onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}

function formatTimestamp(ts?: string) {
  if (!ts) {
    return "-";
  }
  return new Date(ts).toLocaleString(getCurrentLocale() === "ja" ? "ja-JP" : "en-US");
}

function PrimaryButton({
  children,
  disabled,
  onClick,
}: {
  children: React.ReactNode;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" className="px-3 py-1.5 rounded-xl shadow text-sm bg-black text-white disabled:opacity-50" onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}

const inputClass = "w-full rounded-xl border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-black/20";
const textAreaClass = "w-full min-h-24 rounded-xl border px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-black/20";
