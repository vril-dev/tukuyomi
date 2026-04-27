import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { useI18n } from "@/lib/i18n";

type VhostMode = "static" | "php-fpm";
type RewriteFlag = "break" | "last" | "redirect" | "permanent";

type BasicAuthUser = {
  username: string;
  password_hash: string;
};

type BasicAuthConfig = {
  realm?: string;
  users?: BasicAuthUser[];
} | null;

type VhostRewriteRule = {
  pattern: string;
  replacement: string;
  flag: RewriteFlag;
  preserve_query?: boolean;
};

type VhostAccessRule = {
  path_pattern: string;
  action: "allow" | "deny";
  cidrs?: string[];
  basic_auth?: BasicAuthConfig;
};

type VhostEntry = {
  name: string;
  mode: VhostMode;
  hostname: string;
  listen_port: number;
  document_root: string;
  linked_upstream_name?: string;
  runtime_id?: string;
  try_files?: string[];
  rewrite_rules?: VhostRewriteRule[];
  access_rules?: VhostAccessRule[];
  basic_auth?: BasicAuthConfig;
  php_value?: Record<string, string>;
  php_admin_value?: Record<string, string>;
};

type VhostsResponse = {
  etag?: string;
  raw?: string;
  vhosts?: {
    vhosts?: VhostEntry[];
  };
  rollback_depth?: number;
};

type PHPRuntimeRecord = {
  runtime_id: string;
  display_name: string;
  detected_version?: string;
  available?: boolean;
};

type PHPRuntimeMaterializedStatus = {
  runtime_id: string;
  generated_targets?: string[];
  document_roots?: string[];
};

type PHPRuntimeProcessStatus = {
  runtime_id: string;
  running: boolean;
  pid?: number;
  last_action?: string;
  last_error?: string;
  generated_targets?: string[];
};

type PHPRuntimesResponse = {
  runtimes?: {
    runtimes?: PHPRuntimeRecord[];
  };
  materialized?: PHPRuntimeMaterializedStatus[];
  processes?: PHPRuntimeProcessStatus[];
};

type VhostFormState = {
  name: string;
  mode: VhostMode;
  hostname: string;
  listenPort: string;
  documentRoot: string;
  runtimeID: string;
  tryFilesText: string;
  rewriteRules: Array<{
    pattern: string;
    replacement: string;
    flag: RewriteFlag;
    preserveQuery: boolean;
  }>;
  accessRules: Array<{
    pathPattern: string;
    action: "allow" | "deny";
    cidrsText: string;
    authRealm: string;
    authUsersText: string;
  }>;
  basicAuthRealm: string;
  basicAuthUsersText: string;
  phpValueText: string;
  phpAdminValueText: string;
};

function createEmptyVhost(index: number): VhostFormState {
  return {
    name: `vhost-${index}`,
    mode: "php-fpm",
    hostname: "",
    listenPort: String(9400 + index),
    documentRoot: "",
    runtimeID: "",
    tryFilesText: "",
    rewriteRules: [],
    accessRules: [],
    basicAuthRealm: "",
    basicAuthUsersText: "",
    phpValueText: "",
    phpAdminValueText: "",
  };
}

function runtimeLabel(runtime: PHPRuntimeRecord) {
  return runtime.display_name || runtime.detected_version || runtime.runtime_id;
}

function runtimeStateLabel(process: PHPRuntimeProcessStatus | undefined, materialized: boolean) {
  if (process?.last_action) {
    return process.last_action;
  }
  if (process?.running) {
    return "running";
  }
  return materialized ? "stopped" : "not_materialized";
}

function runtimeStateClass(process: PHPRuntimeProcessStatus | undefined, materialized: boolean) {
  const state = runtimeStateLabel(process, materialized);
  if (process?.last_error || ["exited", "start_failed", "restart_failed", "identity_error", "preflight_failed", "reconcile_error"].includes(state)) {
    return "bg-red-100 text-red-800";
  }
  if (process?.running) {
    return "bg-green-100 text-green-800";
  }
  if (state === "manual_stopped") {
    return "bg-amber-100 text-amber-900";
  }
  return "bg-neutral-100 text-neutral-700";
}

function stringListToText(values?: string[]) {
  return Array.isArray(values) ? values.join("\n") : "";
}

function textToStringList(value: string) {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function authUsersToText(auth?: BasicAuthConfig) {
  if (!auth?.users?.length) {
    return "";
  }
  return auth.users.map((user) => `${user.username}:${user.password_hash}`).join("\n");
}

function textToAuthUsers(value: string) {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const idx = line.indexOf(":");
      if (idx < 0) {
        return { username: line.trim(), password_hash: "" };
      }
      return {
        username: line.slice(0, idx).trim(),
        password_hash: line.slice(idx + 1).trim(),
      };
    })
    .filter((entry) => entry.username || entry.password_hash);
}

function iniMapToText(values?: Record<string, string>) {
  if (!values) {
    return "";
  }
  return Object.entries(values)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");
}

function textToIniMap(value: string) {
  const out: Record<string, string> = {};
  for (const line of value.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const idx = trimmed.indexOf("=");
    if (idx < 0) {
      out[trimmed] = "";
      continue;
    }
    out[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
  }
  return out;
}

function parseVhostsResponse(data?: VhostsResponse): VhostFormState[] {
  if (!Array.isArray(data?.vhosts?.vhosts)) {
    return [];
  }
  return data.vhosts.vhosts.map((vhost, index) => ({
    name: vhost.name || `vhost-${index + 1}`,
    mode: (vhost.mode || "static") as VhostMode,
    hostname: vhost.hostname || "",
    listenPort: String(vhost.listen_port || 0),
    documentRoot: vhost.document_root || "",
    runtimeID: vhost.runtime_id || "",
    tryFilesText: stringListToText(vhost.try_files),
    rewriteRules: Array.isArray(vhost.rewrite_rules)
      ? vhost.rewrite_rules.map((rule) => ({
          pattern: rule.pattern || "",
          replacement: rule.replacement || "",
          flag: (rule.flag || "break") as RewriteFlag,
          preserveQuery: rule.preserve_query === true,
        }))
      : [],
    accessRules: Array.isArray(vhost.access_rules)
      ? vhost.access_rules.map((rule) => ({
          pathPattern: rule.path_pattern || "",
          action: (rule.action || "allow") as "allow" | "deny",
          cidrsText: stringListToText(rule.cidrs),
          authRealm: rule.basic_auth?.realm || "",
          authUsersText: authUsersToText(rule.basic_auth),
        }))
      : [],
    basicAuthRealm: vhost.basic_auth?.realm || "",
    basicAuthUsersText: authUsersToText(vhost.basic_auth),
    phpValueText: iniMapToText(vhost.php_value),
    phpAdminValueText: iniMapToText(vhost.php_admin_value),
  }));
}

function vhostsToRaw(vhosts: VhostFormState[]) {
  const normalized = vhosts.map((vhost) => {
    const basicAuthUsers = textToAuthUsers(vhost.basicAuthUsersText).filter((entry) => entry.username && entry.password_hash);
    const basicAuth = basicAuthUsers.length > 0
      ? {
          realm: vhost.basicAuthRealm.trim() || "Restricted",
          users: basicAuthUsers,
        }
      : undefined;

    return {
      name: vhost.name.trim(),
      mode: vhost.mode,
      hostname: vhost.hostname.trim(),
      listen_port: Number(vhost.listenPort) || 0,
      document_root: vhost.documentRoot.trim(),
      ...(vhost.mode === "php-fpm" ? { runtime_id: vhost.runtimeID.trim() } : {}),
      ...(textToStringList(vhost.tryFilesText).length > 0 ? { try_files: textToStringList(vhost.tryFilesText) } : {}),
      ...(vhost.rewriteRules.length > 0
        ? {
            rewrite_rules: vhost.rewriteRules.map((rule) => ({
              pattern: rule.pattern.trim(),
              replacement: rule.replacement.trim(),
              flag: rule.flag,
              preserve_query: rule.preserveQuery,
            })),
          }
        : {}),
      ...(vhost.accessRules.length > 0
        ? {
            access_rules: vhost.accessRules.map((rule) => {
              const authUsers = textToAuthUsers(rule.authUsersText).filter((entry) => entry.username && entry.password_hash);
              return {
                path_pattern: rule.pathPattern.trim(),
                action: rule.action,
                ...(textToStringList(rule.cidrsText).length > 0 ? { cidrs: textToStringList(rule.cidrsText) } : {}),
                ...(authUsers.length > 0
                  ? {
                      basic_auth: {
                        realm: rule.authRealm.trim() || "Restricted",
                        users: authUsers,
                      },
                    }
                  : {}),
              };
            }),
          }
        : {}),
      ...(basicAuth ? { basic_auth: basicAuth } : {}),
      ...(vhost.mode === "php-fpm" && Object.keys(textToIniMap(vhost.phpValueText)).length > 0 ? { php_value: textToIniMap(vhost.phpValueText) } : {}),
      ...(vhost.mode === "php-fpm" && Object.keys(textToIniMap(vhost.phpAdminValueText)).length > 0 ? { php_admin_value: textToIniMap(vhost.phpAdminValueText) } : {}),
    };
  });
  return JSON.stringify({ vhosts: normalized }, null, 2);
}

function validateVhostsForUI(vhosts: VhostFormState[], hasBuiltRuntime: boolean) {
  if (!hasBuiltRuntime) {
    return "build a runtime from Options before editing Vhosts";
  }
  for (const [index, vhost] of vhosts.entries()) {
    const label = vhost.name.trim() || `vhost-${index + 1}`;
    if (!label) {
      return `vhost ${index + 1}: name is required`;
    }
    if (vhost.mode === "static") {
      return `${label}: legacy static vhost is no longer supported; remove it`;
    }
    if (!vhost.hostname.trim()) {
      return `${label}: hostname is required`;
    }
    if (!vhost.listenPort.trim() || Number(vhost.listenPort) < 1) {
      return `${label}: listen port must be > 0`;
    }
    if (!vhost.documentRoot.trim()) {
      return `${label}: document root is required`;
    }
    if (vhost.mode === "php-fpm" && !vhost.runtimeID.trim()) {
      return `${label}: runtime selection is required for php-fpm`;
    }
  }
  return "";
}

export default function VhostsPanel() {
  const { tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [etag, setETag] = useState("");
  const [vhosts, setVhosts] = useState<VhostFormState[]>([]);
  const [runtimeOptions, setRuntimeOptions] = useState<PHPRuntimeRecord[]>([]);
  const [runtimeMaterialized, setRuntimeMaterialized] = useState<PHPRuntimeMaterializedStatus[]>([]);
  const [runtimeProcesses, setRuntimeProcesses] = useState<PHPRuntimeProcessStatus[]>([]);
  const [rollbackDepth, setRollbackDepth] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const rawPreview = useMemo(() => vhostsToRaw(vhosts), [vhosts]);
  const legacyStaticCount = useMemo(() => vhosts.filter((entry) => entry.mode === "static").length, [vhosts]);
  const builtRuntimeOptions = useMemo(
    () => runtimeOptions.filter((runtime) => runtime.available === true),
    [runtimeOptions],
  );
  const runtimeMap = useMemo(
    () => new Map(runtimeOptions.map((runtime) => [runtime.runtime_id, runtime])),
    [runtimeOptions],
  );
  const materializedMap = useMemo(
    () => new Map(runtimeMaterialized.map((runtime) => [runtime.runtime_id, runtime])),
    [runtimeMaterialized],
  );
  const processMap = useMemo(
    () => new Map(runtimeProcesses.map((process) => [process.runtime_id, process])),
    [runtimeProcesses],
  );
  const hasBuiltRuntime = builtRuntimeOptions.length > 0;

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [vhostData, runtimeData] = await Promise.all([
        apiGetJson<VhostsResponse>("/vhosts"),
        apiGetJson<PHPRuntimesResponse>("/php-runtimes"),
      ]);
      setETag(vhostData.etag ?? "");
      setVhosts(parseVhostsResponse(vhostData));
      setRollbackDepth(typeof vhostData.rollback_depth === "number" ? vhostData.rollback_depth : 0);
      setRuntimeOptions(Array.isArray(runtimeData.runtimes?.runtimes) ? runtimeData.runtimes.runtimes : []);
      setRuntimeMaterialized(Array.isArray(runtimeData.materialized) ? runtimeData.materialized : []);
      setRuntimeProcesses(Array.isArray(runtimeData.processes) ? runtimeData.processes : []);
      setNotice("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const updateVhost = useCallback((index: number, next: VhostFormState) => {
    setVhosts((current) => current.map((entry, currentIndex) => (currentIndex === index ? next : entry)));
  }, []);

  const runValidate = useCallback(async () => {
    const localError = validateVhostsForUI(vhosts, hasBuiltRuntime);
    if (localError) {
      setError(localError);
      setNotice("");
      return;
    }
    setSaving(true);
    setError("");
    setNotice("");
    try {
      await apiPostJson<VhostsResponse>("/vhosts/validate", { raw: rawPreview });
      setNotice(tx("Validation passed."));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }, [hasBuiltRuntime, rawPreview, tx, vhosts]);

  const runApply = useCallback(async () => {
    const localError = validateVhostsForUI(vhosts, hasBuiltRuntime);
    if (localError) {
      setError(localError);
      setNotice("");
      return;
    }
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const out = await apiPutJson<VhostsResponse>("/vhosts", { raw: rawPreview }, { headers: { "If-Match": etag } });
      setETag(out.etag ?? "");
      setVhosts(parseVhostsResponse(out));
      setRollbackDepth(typeof out.rollback_depth === "number" ? out.rollback_depth : rollbackDepth);
      setNotice(tx("Saved. Vhost config applied."));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }, [etag, hasBuiltRuntime, rawPreview, rollbackDepth, tx, vhosts]);

  const runRollback = useCallback(async () => {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const out = await apiPostJson<VhostsResponse>("/vhosts/rollback", {});
      setETag(out.etag ?? "");
      setVhosts(parseVhostsResponse(out));
      setRollbackDepth((current) => Math.max(current - 1, 0));
      setNotice(tx("Rollback applied."));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }, [tx]);

  if (loading) {
    return <div className="w-full p-4 text-neutral-500">{tx("Loading vhosts...")}</div>;
  }
  if (!hasBuiltRuntime) {
    return <Navigate to="/options" replace />;
  }

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Vhosts")}</h1>
          <p className="text-sm text-neutral-500">{tx("Define PHP-FPM vhosts here instead of creating proxy upstream rows. Each vhost owns its hostname, FastCGI port, docroot, and runtime binding.")}</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-neutral-500">
          <span className="rounded bg-neutral-100 px-2 py-1">ETag {etag || "-"}</span>
          <span className="rounded bg-neutral-100 px-2 py-1">{tx("Rollback depth")} {rollbackDepth}</span>
        </div>
      </header>

      <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={() => void load()} disabled={saving}>{tx("Load")}</button>
          <button type="button" onClick={() => void runValidate()} disabled={saving}>{tx("Validate")}</button>
          <button type="button" onClick={() => void runApply()} disabled={readOnly || saving || !etag}>{tx("Apply")}</button>
          <button type="button" onClick={() => void runRollback()} disabled={readOnly || saving || rollbackDepth === 0}>{tx("Rollback")}</button>
          <button
            type="button"
            onClick={() =>
              setVhosts((current) => {
                const next = createEmptyVhost(current.length + 1);
                next.runtimeID = builtRuntimeOptions[0]?.runtime_id ?? "";
                return [...current, next];
              })
            }
            disabled={readOnly || saving}
          >
            {tx("Add vhost")}
          </button>
        </div>

        {notice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{notice}</div> : null}
        {error ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{error}</div> : null}
        {legacyStaticCount > 0 ? (
          <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
            {tx("Legacy static vhosts are still present in local config. Static mode is no longer supported here; remove those entries before applying changes.")}
          </div>
        ) : null}
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,2fr),minmax(360px,1fr)]">
        <div className="space-y-4">
          {vhosts.length === 0 ? (
            <div className="rounded-xl border border-dashed border-neutral-200 bg-white p-6 text-sm text-neutral-500">
              {tx("No PHP-FPM vhosts configured. Add one to publish a host-backed PHP-FPM runtime.")}
            </div>
          ) : null}

          {vhosts.map((vhost, index) => (
            <article key={`${vhost.name}:${index}`} className="rounded-xl border border-neutral-200 bg-white p-4 space-y-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold">{vhost.name || `vhost-${index + 1}`}</h2>
                  <p className="text-xs text-neutral-500">{tx("Hostname")}: <code>{vhost.hostname || "-"}</code></p>
                </div>
                <button type="button" className="text-sm underline" onClick={() => setVhosts((current) => current.filter((_, currentIndex) => currentIndex !== index))} disabled={readOnly || saving}>
                  {tx("Remove")}
                </button>
              </div>

              {vhost.mode === "static" ? (
                <section className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 space-y-2">
                  <div className="font-semibold">{tx("Legacy static vhost")}</div>
                  <p>{tx("Static mode is no longer supported from this page. Remove this entry, or replace it with a PHP-FPM vhost that has an explicit runtime binding.")}</p>
                  <div className="grid gap-2 md:grid-cols-2 text-neutral-800">
                    <div>{tx("Hostname")}: <code>{vhost.hostname || "-"}</code></div>
                    <div>{tx("Listen Port")}: <code>{vhost.listenPort || "-"}</code></div>
                    <div className="md:col-span-2">{tx("Document Root")}: <code>{vhost.documentRoot || "-"}</code></div>
                  </div>
                </section>
              ) : null}

              {vhost.mode === "static" ? null : (
                <>
                  <div className="grid gap-3 md:grid-cols-2">
                    <label className="space-y-1 text-sm">
                      <span className="block text-xs text-neutral-600">{tx("Name")}</span>
                      <input value={vhost.name} onChange={(e) => updateVhost(index, { ...vhost, name: e.target.value })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" />
                    </label>
                    <label className="space-y-1 text-sm">
                      <span className="block text-xs text-neutral-600">{tx("Mode")}</span>
                      <select value="php-fpm" className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" disabled>
                        <option value="php-fpm">php-fpm</option>
                      </select>
                    </label>
                    <label className="space-y-1 text-sm">
                      <span className="block text-xs text-neutral-600">{tx("Runtime")}</span>
                      <select value={vhost.runtimeID} onChange={(e) => updateVhost(index, { ...vhost, runtimeID: e.target.value })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" disabled={builtRuntimeOptions.length === 0}>
                        <option value="">{tx("Select runtime")}</option>
                        {builtRuntimeOptions.map((runtime) => (
                          <option key={runtime.runtime_id} value={runtime.runtime_id}>{runtimeLabel(runtime)}</option>
                        ))}
                      </select>
                    </label>
                    <RuntimeStateSummary
                      tx={tx}
                      runtimeID={vhost.runtimeID}
                      runtime={runtimeMap.get(vhost.runtimeID)}
                      materialized={materializedMap.get(vhost.runtimeID)}
                      process={processMap.get(vhost.runtimeID)}
                    />
                    <label className="space-y-1 text-sm">
                      <span className="block text-xs text-neutral-600">{tx("Hostname")}</span>
                      <input value={vhost.hostname} onChange={(e) => updateVhost(index, { ...vhost, hostname: e.target.value })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" placeholder="app.example.com" />
                    </label>
                    <label className="space-y-1 text-sm">
                      <span className="block text-xs text-neutral-600">{tx("Listen Port")}</span>
                      <input value={vhost.listenPort} onChange={(e) => updateVhost(index, { ...vhost, listenPort: e.target.value })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" />
                    </label>
                    <label className="space-y-1 text-sm md:col-span-2">
                      <span className="block text-xs text-neutral-600">{tx("Document Root")}</span>
                      <input
                        value={vhost.documentRoot}
                        onChange={(e) => updateVhost(index, { ...vhost, documentRoot: e.target.value })}
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                        placeholder="./data/vhosts/<app>/public"
                      />
                    </label>
                    <label className="space-y-1 text-sm md:col-span-2">
                      <span className="block text-xs text-neutral-600">{tx("try_files")}</span>
                      <textarea value={vhost.tryFilesText} onChange={(e) => updateVhost(index, { ...vhost, tryFilesText: e.target.value })} className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-sm" placeholder={"$uri\n$uri/\n/index.php?$query_string"} />
                    </label>
                  </div>

                  <section className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="text-sm font-semibold">{tx("Rewrite Rules")}</h3>
                      <button type="button" onClick={() => updateVhost(index, { ...vhost, rewriteRules: [...vhost.rewriteRules, { pattern: "", replacement: "", flag: "break", preserveQuery: false }] })} disabled={readOnly || saving}>
                        {tx("Add rule")}
                      </button>
                    </div>
                    <div className="space-y-3">
                      {vhost.rewriteRules.map((rule, ruleIndex) => (
                        <div key={`${rule.pattern}:${ruleIndex}`} className="rounded-lg border border-neutral-200 p-3 grid gap-3 md:grid-cols-2">
                          <label className="space-y-1 text-sm">
                            <span className="block text-xs text-neutral-600">{tx("Pattern")}</span>
                            <input value={rule.pattern} onChange={(e) => updateVhost(index, { ...vhost, rewriteRules: vhost.rewriteRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, pattern: e.target.value } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-sm" />
                          </label>
                          <label className="space-y-1 text-sm">
                            <span className="block text-xs text-neutral-600">{tx("Replacement")}</span>
                            <input value={rule.replacement} onChange={(e) => updateVhost(index, { ...vhost, rewriteRules: vhost.rewriteRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, replacement: e.target.value } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-sm" />
                          </label>
                          <label className="space-y-1 text-sm">
                            <span className="block text-xs text-neutral-600">{tx("Flag")}</span>
                            <select value={rule.flag} onChange={(e) => updateVhost(index, { ...vhost, rewriteRules: vhost.rewriteRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, flag: e.target.value as RewriteFlag } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white">
                              <option value="break">break</option>
                              <option value="last">last</option>
                              <option value="redirect">redirect</option>
                              <option value="permanent">permanent</option>
                            </select>
                          </label>
                          <label className="flex items-center gap-2 text-sm">
                            <input type="checkbox" checked={rule.preserveQuery} onChange={(e) => updateVhost(index, { ...vhost, rewriteRules: vhost.rewriteRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, preserveQuery: e.target.checked } : entry) })} />
                            {tx("Preserve query string")}
                          </label>
                          <button type="button" className="text-sm underline text-left" onClick={() => updateVhost(index, { ...vhost, rewriteRules: vhost.rewriteRules.filter((_, currentIndex) => currentIndex !== ruleIndex) })} disabled={readOnly || saving}>
                            {tx("Remove")}
                          </button>
                        </div>
                      ))}
                    </div>
                  </section>

                  <section className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="text-sm font-semibold">{tx("Access Rules")}</h3>
                      <button type="button" onClick={() => updateVhost(index, { ...vhost, accessRules: [...vhost.accessRules, { pathPattern: "/", action: "allow", cidrsText: "", authRealm: "", authUsersText: "" }] })} disabled={readOnly || saving}>
                        {tx("Add rule")}
                      </button>
                    </div>
                    <div className="space-y-3">
                      {vhost.accessRules.map((rule, ruleIndex) => (
                        <div key={`${rule.pathPattern}:${ruleIndex}`} className="rounded-lg border border-neutral-200 p-3 grid gap-3 md:grid-cols-2">
                          <label className="space-y-1 text-sm">
                            <span className="block text-xs text-neutral-600">{tx("Path pattern")}</span>
                            <input value={rule.pathPattern} onChange={(e) => updateVhost(index, { ...vhost, accessRules: vhost.accessRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, pathPattern: e.target.value } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" />
                          </label>
                          <label className="space-y-1 text-sm">
                            <span className="block text-xs text-neutral-600">{tx("Action")}</span>
                            <select value={rule.action} onChange={(e) => updateVhost(index, { ...vhost, accessRules: vhost.accessRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, action: e.target.value as "allow" | "deny" } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white">
                              <option value="allow">allow</option>
                              <option value="deny">deny</option>
                            </select>
                          </label>
                          <label className="space-y-1 text-sm">
                            <span className="block text-xs text-neutral-600">{tx("CIDRs")}</span>
                            <textarea value={rule.cidrsText} onChange={(e) => updateVhost(index, { ...vhost, accessRules: vhost.accessRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, cidrsText: e.target.value } : entry) })} className="min-h-20 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-sm" placeholder={"127.0.0.1/32\n10.0.0.0/8"} />
                          </label>
                          <div className="space-y-3">
                            <label className="space-y-1 text-sm block">
                              <span className="block text-xs text-neutral-600">{tx("Basic Auth Realm")}</span>
                              <input value={rule.authRealm} onChange={(e) => updateVhost(index, { ...vhost, accessRules: vhost.accessRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, authRealm: e.target.value } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" />
                            </label>
                            <label className="space-y-1 text-sm block">
                              <span className="block text-xs text-neutral-600">{tx("Users (`username:bcrypt-hash`)")}</span>
                              <textarea value={rule.authUsersText} onChange={(e) => updateVhost(index, { ...vhost, accessRules: vhost.accessRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, authUsersText: e.target.value } : entry) })} className="min-h-20 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-sm" placeholder={"alice:$2a$..."} />
                            </label>
                          </div>
                          <button type="button" className="text-sm underline text-left" onClick={() => updateVhost(index, { ...vhost, accessRules: vhost.accessRules.filter((_, currentIndex) => currentIndex !== ruleIndex) })} disabled={readOnly || saving}>
                            {tx("Remove")}
                          </button>
                        </div>
                      ))}
                    </div>
                  </section>

                  <section className="grid gap-3 md:grid-cols-2">
                    <label className="space-y-1 text-sm">
                      <span className="block text-xs text-neutral-600">{tx("Vhost Basic Auth Realm")}</span>
                      <input value={vhost.basicAuthRealm} onChange={(e) => updateVhost(index, { ...vhost, basicAuthRealm: e.target.value })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" />
                    </label>
                    <label className="space-y-1 text-sm md:col-span-2">
                      <span className="block text-xs text-neutral-600">{tx("Users (`username:bcrypt-hash`)")}</span>
                      <textarea value={vhost.basicAuthUsersText} onChange={(e) => updateVhost(index, { ...vhost, basicAuthUsersText: e.target.value })} className="min-h-20 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-sm" placeholder={"alice:$2a$..."} />
                    </label>
                    <label className="space-y-1 text-sm">
                      <span className="block text-xs text-neutral-600">{tx("php_value (`key=value`)")}</span>
                      <textarea value={vhost.phpValueText} onChange={(e) => updateVhost(index, { ...vhost, phpValueText: e.target.value })} className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-sm" placeholder={"memory_limit=512M"} />
                    </label>
                    <label className="space-y-1 text-sm">
                      <span className="block text-xs text-neutral-600">{tx("php_admin_value (`key=value`)")}</span>
                      <textarea value={vhost.phpAdminValueText} onChange={(e) => updateVhost(index, { ...vhost, phpAdminValueText: e.target.value })} className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-sm" placeholder={"open_basedir=/srv/app"} />
                    </label>
                  </section>
                </>
              )}
            </article>
          ))}
        </div>

        <aside className="space-y-4">
          <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-2">
            <h2 className="text-sm font-semibold">{tx("Runtime options")}</h2>
            {builtRuntimeOptions.length === 0 ? (
              <div className="text-sm text-neutral-500">{tx("No built PHP runtimes are available.")}</div>
            ) : (
              <ul className="flex flex-wrap gap-2 text-sm">
                {builtRuntimeOptions.map((runtime) => (
                  <li
                    key={runtime.runtime_id}
                    className="inline-flex items-center gap-2 rounded-full border border-neutral-200 bg-neutral-50 px-3 py-1.5"
                    title={runtime.runtime_id}
                  >
                    <span className="font-medium">{runtimeLabel(runtime)}</span>
                    <code className="text-[11px] text-neutral-500">{runtime.runtime_id}</code>
                  </li>
                ))}
              </ul>
            )}
          </section>

        </aside>
      </section>
    </div>
  );
}

function RuntimeStateSummary({
  tx,
  runtimeID,
  runtime,
  materialized,
  process,
}: {
  tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
  runtimeID: string;
  runtime?: PHPRuntimeRecord;
  materialized?: PHPRuntimeMaterializedStatus;
  process?: PHPRuntimeProcessStatus;
}) {
  if (!runtimeID.trim()) {
    return (
      <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-sm">
        <div className="text-xs text-neutral-500">{tx("Runtime State")}</div>
        <div className="text-neutral-600">{tx("Select runtime")}</div>
      </div>
    );
  }
  const targets = process?.generated_targets?.length ? process.generated_targets : (materialized?.generated_targets ?? []);
  const materializedRuntime = !!materialized;
  return (
    <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-sm space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-xs text-neutral-500">{tx("Runtime State")}</div>
          <div className="font-medium">{runtime ? runtimeLabel(runtime) : runtimeID}</div>
        </div>
        <span className={`rounded px-2 py-1 text-xs ${runtimeStateClass(process, materializedRuntime)}`}>
          {tx(runtimeStateLabel(process, materializedRuntime))}
        </span>
      </div>
      <div className="grid gap-1 text-xs text-neutral-600">
        <div>{tx("PID")}: <code>{process?.pid || "-"}</code></div>
        <div>{tx("Generated Targets")}: <code className="break-all">{targets.length > 0 ? targets.join(", ") : "-"}</code></div>
        {process?.last_error ? <div className="text-red-700">{process.last_error}</div> : null}
      </div>
      <Link to="/options#runtime-inventory" className="inline-flex text-xs underline">
        {tx("Open Runtime")}
      </Link>
    </div>
  );
}
