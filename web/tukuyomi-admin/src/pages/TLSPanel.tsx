import { useCallback, useEffect, useMemo, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { ParsedTextArea, stringListEqual } from "@/components/EditorChrome";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";
import { formatRevision } from "@/lib/revision";
import {
  createEmptyTLSBinding,
  parseTLSBindingsResponse,
  tlsBindingsToRaw,
  type TLSBindingACMEEnvironment,
  type TLSBindingEntry,
  type TLSBindingMode,
  type TLSBindingStatus,
  type TLSBindingsResponse,
} from "@/lib/tlsBindingsConfig";
import {
  multilineToStringList,
  stringListToMultiline,
} from "@/lib/sitesConfig";

export default function TLSPanel() {
  const { tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [etag, setETag] = useState("");
  const [bindings, setBindings] = useState<TLSBindingEntry[]>([]);
  const [statuses, setStatuses] = useState<TLSBindingStatus[]>([]);
  const [rollbackDepth, setRollbackDepth] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const rawPreview = useMemo(() => tlsBindingsToRaw(bindings), [bindings]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await apiGetJson<TLSBindingsResponse>("/tls-bindings");
      setETag(data.etag ?? "");
      setBindings(parseTLSBindingsResponse(data));
      setStatuses(Array.isArray(data.tls_binding_statuses) ? data.tls_binding_statuses : []);
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

  const updateBinding = useCallback((index: number, next: TLSBindingEntry) => {
    setBindings((current) => current.map((binding, bindingIndex) => (bindingIndex === index ? next : binding)));
  }, []);

  const runValidate = useCallback(async () => {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const out = await apiPostJson<{ ok: boolean; tls_binding_statuses?: TLSBindingStatus[] }>("/tls-bindings/validate", { raw: rawPreview });
      setStatuses(Array.isArray(out.tls_binding_statuses) ? out.tls_binding_statuses : []);
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
      const out = await apiPutJson<TLSBindingsResponse>(
        "/tls-bindings",
        { raw: rawPreview },
        { headers: { "If-Match": etag } },
      );
      setETag(out.etag ?? "");
      setBindings(parseTLSBindingsResponse(out));
      setStatuses(Array.isArray(out.tls_binding_statuses) ? out.tls_binding_statuses : []);
      setNotice(tx("Saved. TLS config applied."));
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
      const out = await apiPostJson<TLSBindingsResponse>("/tls-bindings/rollback", {});
      setETag(out.etag ?? "");
      setBindings(parseTLSBindingsResponse(out));
      setStatuses(Array.isArray(out.tls_binding_statuses) ? out.tls_binding_statuses : []);
      setNotice(tx("Rollback applied."));
      setRollbackDepth((current) => Math.max(current - 1, 0));
    } catch (error: unknown) {
      setError(getErrorMessage(error, tx("rollback failed")));
    } finally {
      setSaving(false);
    }
  }, [tx]);

  if (loading) {
    return <div className="w-full p-4 text-neutral-500">{tx("Loading TLS bindings...")}</div>;
  }

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("TLS")}</h1>
          <p className="text-xs text-neutral-500">{tx("Manage TLS bindings, ACME certificates, and SNI hostnames.")}</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-neutral-500">
          <span className="rounded bg-neutral-100 px-2 py-1" title={etag || undefined}>{formatRevision(etag)}</span>
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
            onClick={() => setBindings((current) => [...current, createEmptyTLSBinding(current.length + 1)])}
            disabled={readOnly || saving}
          >
            {tx("Add TLS Binding")}
          </button>
        </div>

        {notice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{notice}</div> : null}
        {error ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{error}</div> : null}
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,2fr),minmax(320px,1fr)]">
        <div className="space-y-4">
          {bindings.length === 0 ? (
            <div className="rounded-xl border border-dashed border-neutral-200 bg-white p-6 text-xs text-neutral-500">
              {tx("No TLS bindings configured. Add a binding before enabling per-host certificates.")}
            </div>
          ) : null}

          {bindings.map((binding, index) => (
            <article key={`${binding.name}:${index}`} className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold">{binding.name || `tls-${index + 1}`}</h2>
                  <p className="text-xs text-neutral-500">{tx("SNI hostnames and certificate mode")}</p>
                </div>
                <button
                  type="button"
                  className="text-xs"
                  onClick={() => setBindings((current) => current.filter((_, bindingIndex) => bindingIndex !== index))}
                  disabled={readOnly || saving}
                >
                  {tx("Remove")}
                </button>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <label className="space-y-1 text-xs">
                  <span className="block text-xs text-neutral-600">{tx("Label")}</span>
                  <input
                    value={binding.name}
                    onChange={(e) => updateBinding(index, { ...binding, name: e.target.value })}
                    className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                  />
                </label>

                <label className="space-y-1 text-xs">
                  <span className="block text-xs text-neutral-600">{tx("TLS mode")}</span>
                  <select
                    value={binding.mode}
                    onChange={(e) => updateBinding(index, { ...binding, mode: e.target.value as TLSBindingMode })}
                    className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                  >
                    <option value="legacy">legacy</option>
                    <option value="manual">manual</option>
                    <option value="acme">acme</option>
                  </select>
                </label>

                <label className="space-y-1 text-xs md:col-span-2">
                  <span className="block text-xs text-neutral-600">{tx("Hosts")}</span>
                  <ParsedTextArea
                    value={binding.hosts}
                    onValueChange={(next) => updateBinding(index, { ...binding, hosts: next })}
                    serialize={stringListToMultiline}
                    parse={multilineToStringList}
                    equals={stringListEqual}
                    className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                    placeholder={"www.example.com\napi.example.com"}
                  />
                </label>

                <label className="flex items-center gap-2 text-xs">
                  <input
                    type="checkbox"
                    checked={binding.enabled}
                    onChange={(e) => updateBinding(index, { ...binding, enabled: e.target.checked })}
                  />
                  {tx("Enabled")}
                </label>

                <div className="text-xs text-neutral-500">
                  {tx("TLS bindings are selected by Host/SNI and do not require a Site record.")}
                </div>

                {binding.mode === "manual" ? (
                  <>
                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">{tx("cert_file")}</span>
                      <input
                        value={binding.cert_file ?? ""}
                        onChange={(e) => updateBinding(index, { ...binding, cert_file: e.target.value })}
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                        placeholder="/etc/tukuyomi/tls/fullchain.pem"
                      />
                    </label>
                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">{tx("key_file")}</span>
                      <input
                        value={binding.key_file ?? ""}
                        onChange={(e) => updateBinding(index, { ...binding, key_file: e.target.value })}
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                        placeholder="/etc/tukuyomi/tls/privkey.pem"
                      />
                    </label>
                  </>
                ) : null}

                {binding.mode === "acme" ? (
                  <>
                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">{tx("ACME environment")}</span>
                      <select
                        value={binding.acme?.environment ?? "production"}
                        onChange={(e) => updateBinding(index, {
                          ...binding,
                          acme: {
                            ...(binding.acme ?? {}),
                            environment: e.target.value as TLSBindingACMEEnvironment,
                          },
                        })}
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                      >
                        <option value="production">production</option>
                        <option value="staging">staging</option>
                      </select>
                    </label>
                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">{tx("ACME account email")}</span>
                      <input
                        value={binding.acme?.email ?? ""}
                        onChange={(e) => updateBinding(index, {
                          ...binding,
                          acme: {
                            ...(binding.acme ?? {}),
                            email: e.target.value,
                          },
                        })}
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                        placeholder="ops@example.com"
                      />
                    </label>
                    <div className="text-xs text-neutral-500 md:col-span-2">
                      {tx("ACME here supports DNS hostnames only. IP address certificates are not managed by TLS bindings.")}
                    </div>
                  </>
                ) : null}
              </div>
            </article>
          ))}
        </div>

        <div className="space-y-4">
          <section className="rounded-xl border border-neutral-200 bg-white p-4">
            <h2 className="text-sm font-semibold">{tx("TLS Status")}</h2>
            <div className="mt-3 space-y-2">
              {statuses.length === 0 ? (
                <div className="text-xs text-neutral-500">{tx("No TLS status yet. Use Validate or Load.")}</div>
              ) : (
                statuses.map((status) => (
                  <div key={status.name} className="rounded border border-neutral-200 px-3 py-2 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <strong>{status.name}</strong>
                      <span className="rounded bg-neutral-100 px-2 py-0.5">
                        {status.enabled ? `${status.mode ?? "-"} / ${status.status ?? "-"}` : tx("disabled")}
                      </span>
                    </div>
                    {status.hosts?.length ? <div className="mt-1 text-neutral-600">{status.hosts.join(", ")}</div> : null}
                    {status.acme_environment ? <div className="mt-1 text-neutral-500">{tx("ACME environment")} {status.acme_environment}</div> : null}
                    {status.cert_not_after ? <div className="mt-1 text-neutral-500">{tx("cert not after")} {status.cert_not_after}</div> : null}
                    {status.warning ? <div className="mt-1 text-amber-700">{status.warning}</div> : null}
                  </div>
                ))
              )}
            </div>
          </section>
        </div>
      </section>
    </div>
  );
}
