import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { useI18n } from "@/lib/i18n";
import { formatRevision } from "@/lib/revision";

type RuntimeAppMode = "static" | "php-fpm" | "psgi";
type RewriteFlag = "break" | "last" | "redirect" | "permanent";

type BasicAuthUser = {
  username: string;
  password_hash: string;
};

type BasicAuthConfig = {
  realm?: string;
  users?: BasicAuthUser[];
} | null;

type RuntimeAppRewriteRule = {
  pattern: string;
  replacement: string;
  flag: RewriteFlag;
  preserve_query?: boolean;
};

type RuntimeAppAccessRule = {
  path_pattern: string;
  action: "allow" | "deny";
  cidrs?: string[];
  basic_auth?: BasicAuthConfig;
};

type RuntimeAppEntry = {
  name: string;
  mode: RuntimeAppMode;
  hostname: string;
  listen_port: number;
  document_root: string;
  linked_upstream_name?: string;
  runtime_id?: string;
  try_files?: string[];
  rewrite_rules?: RuntimeAppRewriteRule[];
  access_rules?: RuntimeAppAccessRule[];
  basic_auth?: BasicAuthConfig;
  php_value?: Record<string, string>;
  php_admin_value?: Record<string, string>;
  app_root?: string;
  psgi_file?: string;
  workers?: number;
  max_requests?: number;
  include_extlib?: boolean;
  env?: Record<string, string>;
};

type RuntimeAppsResponse = {
  etag?: string;
  raw?: string;
  runtime_apps?: {
    vhosts?: RuntimeAppEntry[];
  };
  materialized?: PHPRuntimeMaterializedStatus[];
  psgi_materialized?: PSGIRuntimeMaterializedStatus[];
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

type PSGIRuntimeRecord = {
  runtime_id: string;
  display_name: string;
  detected_version?: string;
  available?: boolean;
};

type PSGIRuntimeMaterializedStatus = {
  process_id: string;
  vhost_name: string;
  runtime_id: string;
  generated_target?: string;
};

type PSGIRuntimeProcessStatus = {
  process_id: string;
  vhost_name: string;
  runtime_id: string;
  running: boolean;
  pid?: number;
  last_action?: string;
  last_error?: string;
  generated_target?: string;
};

type PSGIRuntimesResponse = {
  runtimes?: {
    runtimes?: PSGIRuntimeRecord[];
  };
  materialized?: PSGIRuntimeMaterializedStatus[];
  processes?: PSGIRuntimeProcessStatus[];
};

let runtimeAppFormIDSequence = 0;

function nextRuntimeAppFormID(prefix: string) {
  runtimeAppFormIDSequence += 1;
  return `${prefix}-${runtimeAppFormIDSequence}`;
}

type RuntimeAppRewriteRuleFormState = {
  formID: string;
  pattern: string;
  replacement: string;
  flag: RewriteFlag;
  preserveQuery: boolean;
};

type RuntimeAppAccessRuleFormState = {
  formID: string;
  pathPattern: string;
  action: "allow" | "deny";
  cidrsText: string;
  authRealm: string;
  authUsersText: string;
};

type RuntimeAppFormState = {
  formID: string;
  name: string;
  mode: RuntimeAppMode;
  hostname: string;
  listenPort: string;
  documentRoot: string;
  runtimeID: string;
  tryFilesText: string;
  rewriteRules: RuntimeAppRewriteRuleFormState[];
  accessRules: RuntimeAppAccessRuleFormState[];
  basicAuthRealm: string;
  basicAuthUsersText: string;
  phpValueText: string;
  phpAdminValueText: string;
  appRoot: string;
  psgiFile: string;
  workers: string;
  maxRequests: string;
  includeExtlib: boolean;
  envText: string;
};

function createEmptyRewriteRule(): RuntimeAppRewriteRuleFormState {
  return {
    formID: nextRuntimeAppFormID("rewrite-rule"),
    pattern: "",
    replacement: "",
    flag: "break",
    preserveQuery: false,
  };
}

function createEmptyAccessRule(): RuntimeAppAccessRuleFormState {
  return {
    formID: nextRuntimeAppFormID("access-rule"),
    pathPattern: "/",
    action: "allow",
    cidrsText: "",
    authRealm: "",
    authUsersText: "",
  };
}

function createEmptyRuntimeApp(index: number): RuntimeAppFormState {
  return {
    formID: nextRuntimeAppFormID("runtime-app"),
    name: `app-${index}`,
    mode: "php-fpm",
    hostname: "127.0.0.1",
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
    appRoot: "",
    psgiFile: "mt.psgi",
    workers: "2",
    maxRequests: "200",
    includeExtlib: true,
    envText: "",
  };
}

function runtimeLabel(runtime: PHPRuntimeRecord) {
  return runtime.display_name || runtime.detected_version || runtime.runtime_id;
}

function psgiRuntimeLabel(runtime: PSGIRuntimeRecord) {
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

function parseRuntimeAppsResponse(data?: RuntimeAppsResponse): RuntimeAppFormState[] {
  const entries = data?.runtime_apps?.vhosts;
  if (!Array.isArray(entries)) {
    return [];
  }
  return entries.map((app, index) => ({
    formID: nextRuntimeAppFormID("runtime-app"),
    name: app.name || `app-${index + 1}`,
    mode: (app.mode || "static") as RuntimeAppMode,
    hostname: app.hostname || "",
    listenPort: String(app.listen_port || 0),
    documentRoot: app.document_root || "",
    runtimeID: app.runtime_id || "",
    tryFilesText: stringListToText(app.try_files),
    rewriteRules: Array.isArray(app.rewrite_rules)
      ? app.rewrite_rules.map((rule) => ({
          formID: nextRuntimeAppFormID("rewrite-rule"),
          pattern: rule.pattern || "",
          replacement: rule.replacement || "",
          flag: (rule.flag || "break") as RewriteFlag,
          preserveQuery: rule.preserve_query === true,
        }))
      : [],
    accessRules: Array.isArray(app.access_rules)
      ? app.access_rules.map((rule) => ({
          formID: nextRuntimeAppFormID("access-rule"),
          pathPattern: rule.path_pattern || "",
          action: (rule.action || "allow") as "allow" | "deny",
          cidrsText: stringListToText(rule.cidrs),
          authRealm: rule.basic_auth?.realm || "",
          authUsersText: authUsersToText(rule.basic_auth),
        }))
      : [],
    basicAuthRealm: app.basic_auth?.realm || "",
    basicAuthUsersText: authUsersToText(app.basic_auth),
    phpValueText: iniMapToText(app.php_value),
    phpAdminValueText: iniMapToText(app.php_admin_value),
    appRoot: app.app_root || "",
    psgiFile: app.psgi_file || "mt.psgi",
    workers: String(app.workers || 2),
    maxRequests: String(app.max_requests || 200),
    includeExtlib: app.include_extlib !== false,
    envText: iniMapToText(app.env),
  }));
}

function runtimeAppsToRaw(vhosts: RuntimeAppFormState[]) {
  const normalized = vhosts.map((app) => {
    const basicAuthUsers = textToAuthUsers(app.basicAuthUsersText).filter((entry) => entry.username && entry.password_hash);
    const basicAuth = basicAuthUsers.length > 0
      ? {
          realm: app.basicAuthRealm.trim() || "Restricted",
          users: basicAuthUsers,
        }
      : undefined;

    return {
      name: app.name.trim(),
      mode: app.mode,
      hostname: app.hostname.trim(),
      listen_port: Number(app.listenPort) || 0,
      document_root: app.documentRoot.trim(),
      ...(app.mode === "php-fpm" ? { runtime_id: app.runtimeID.trim() } : {}),
      ...(app.mode === "psgi"
        ? {
            runtime_id: app.runtimeID.trim(),
            app_root: app.appRoot.trim(),
            psgi_file: app.psgiFile.trim(),
            workers: Number(app.workers) || 0,
            max_requests: Number(app.maxRequests) || 0,
            include_extlib: app.includeExtlib,
          }
        : {}),
      ...(textToStringList(app.tryFilesText).length > 0 ? { try_files: textToStringList(app.tryFilesText) } : {}),
      ...(app.rewriteRules.length > 0
        ? {
            rewrite_rules: app.rewriteRules.map((rule) => ({
              pattern: rule.pattern.trim(),
              replacement: rule.replacement.trim(),
              flag: rule.flag,
              preserve_query: rule.preserveQuery,
            })),
          }
        : {}),
      ...(app.accessRules.length > 0
        ? {
            access_rules: app.accessRules.map((rule) => {
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
      ...(app.mode === "php-fpm" && Object.keys(textToIniMap(app.phpValueText)).length > 0 ? { php_value: textToIniMap(app.phpValueText) } : {}),
      ...(app.mode === "php-fpm" && Object.keys(textToIniMap(app.phpAdminValueText)).length > 0 ? { php_admin_value: textToIniMap(app.phpAdminValueText) } : {}),
      ...(app.mode === "psgi" && Object.keys(textToIniMap(app.envText)).length > 0 ? { env: textToIniMap(app.envText) } : {}),
    };
  });
  return JSON.stringify({ vhosts: normalized }, null, 2);
}

function comparableRuntimeAppRaw(raw: string) {
  const trimmed = raw.trim();
  if (!trimmed) {
    return "";
  }
  try {
    return JSON.stringify(JSON.parse(trimmed));
  } catch {
    return trimmed;
  }
}

function validateRuntimeAppsForUI(vhosts: RuntimeAppFormState[], hasBuiltPHPRuntime: boolean, hasBuiltPSGIRuntime: boolean) {
  if (!hasBuiltPHPRuntime && !hasBuiltPSGIRuntime) {
    return "build a runtime from Options before editing Runtime Apps";
  }
  for (const [index, app] of vhosts.entries()) {
    const label = app.name.trim() || `app-${index + 1}`;
    if (!label) {
      return `runtime app ${index + 1}: name is required`;
    }
    if (app.mode === "static") {
      return `${label}: legacy static runtime app is no longer supported; remove it`;
    }
    if (!app.hostname.trim()) {
      return `${label}: listen host is required`;
    }
    if (!app.listenPort.trim() || Number(app.listenPort) < 1) {
      return `${label}: listen port must be > 0`;
    }
    if (!app.documentRoot.trim()) {
      return `${label}: document root is required`;
    }
    if (app.mode === "php-fpm") {
      if (!hasBuiltPHPRuntime) {
        return `${label}: build a PHP runtime before using php-fpm mode`;
      }
      if (!app.runtimeID.trim()) {
        return `${label}: runtime selection is required for php-fpm`;
      }
    }
    if (app.mode === "psgi") {
      if (!hasBuiltPSGIRuntime) {
        return `${label}: build a PSGI runtime before using psgi mode`;
      }
      if (!app.runtimeID.trim()) {
        return `${label}: runtime selection is required for psgi`;
      }
      if (!app.appRoot.trim()) {
        return `${label}: app root is required for psgi`;
      }
      if (!app.psgiFile.trim()) {
        return `${label}: psgi file is required`;
      }
    }
  }
  return "";
}

export default function RuntimeAppsPanel() {
  const { tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [etag, setETag] = useState("");
  const [loadedRaw, setLoadedRaw] = useState("");
  const [vhosts, setRuntimeApps] = useState<RuntimeAppFormState[]>([]);
  const [runtimeOptions, setRuntimeOptions] = useState<PHPRuntimeRecord[]>([]);
  const [runtimeMaterialized, setRuntimeMaterialized] = useState<PHPRuntimeMaterializedStatus[]>([]);
  const [runtimeProcesses, setRuntimeProcesses] = useState<PHPRuntimeProcessStatus[]>([]);
  const [psgiRuntimeOptions, setPSGIRuntimeOptions] = useState<PSGIRuntimeRecord[]>([]);
  const [psgiMaterialized, setPSGIMaterialized] = useState<PSGIRuntimeMaterializedStatus[]>([]);
  const [psgiProcesses, setPSGIProcesses] = useState<PSGIRuntimeProcessStatus[]>([]);
  const [rollbackDepth, setRollbackDepth] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const rawPreview = useMemo(() => runtimeAppsToRaw(vhosts), [vhosts]);
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
  const builtPSGIOptions = useMemo(
    () => psgiRuntimeOptions.filter((runtime) => runtime.available === true),
    [psgiRuntimeOptions],
  );
  const psgiRuntimeMap = useMemo(
    () => new Map(psgiRuntimeOptions.map((runtime) => [runtime.runtime_id, runtime])),
    [psgiRuntimeOptions],
  );
  const psgiMaterializedMap = useMemo(
    () => new Map(psgiMaterialized.map((entry) => [entry.vhost_name, entry])),
    [psgiMaterialized],
  );
  const psgiProcessMap = useMemo(
    () => new Map(psgiProcesses.map((entry) => [entry.vhost_name, entry])),
    [psgiProcesses],
  );
  const hasBuiltPHPRuntime = builtRuntimeOptions.length > 0;
  const hasBuiltPSGIRuntime = builtPSGIOptions.length > 0;
  const hasBuiltRuntime = hasBuiltPHPRuntime || hasBuiltPSGIRuntime;

  const applyRuntimeState = useCallback((runtimeData: PHPRuntimesResponse, psgiRuntimeData: PSGIRuntimesResponse) => {
    setRuntimeOptions(Array.isArray(runtimeData.runtimes?.runtimes) ? runtimeData.runtimes.runtimes : []);
    setRuntimeMaterialized(Array.isArray(runtimeData.materialized) ? runtimeData.materialized : []);
    setRuntimeProcesses(Array.isArray(runtimeData.processes) ? runtimeData.processes : []);
    setPSGIRuntimeOptions(Array.isArray(psgiRuntimeData.runtimes?.runtimes) ? psgiRuntimeData.runtimes.runtimes : []);
    setPSGIMaterialized(Array.isArray(psgiRuntimeData.materialized) ? psgiRuntimeData.materialized : []);
    setPSGIProcesses(Array.isArray(psgiRuntimeData.processes) ? psgiRuntimeData.processes : []);
  }, []);

  const refreshRuntimeState = useCallback(async () => {
    const [runtimeData, psgiRuntimeData] = await Promise.all([
      apiGetJson<PHPRuntimesResponse>("/php-runtimes"),
      apiGetJson<PSGIRuntimesResponse>("/psgi-runtimes"),
    ]);
    applyRuntimeState(runtimeData, psgiRuntimeData);
  }, [applyRuntimeState]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [runtimeAppsData, runtimeData, psgiRuntimeData] = await Promise.all([
        apiGetJson<RuntimeAppsResponse>("/runtime-apps"),
        apiGetJson<PHPRuntimesResponse>("/php-runtimes"),
        apiGetJson<PSGIRuntimesResponse>("/psgi-runtimes"),
      ]);
      const parsedRuntimeApps = parseRuntimeAppsResponse(runtimeAppsData);
      setETag(runtimeAppsData.etag ?? "");
      setLoadedRaw(runtimeAppsData.raw ?? runtimeAppsToRaw(parsedRuntimeApps));
      setRuntimeApps(parsedRuntimeApps);
      setRollbackDepth(typeof runtimeAppsData.rollback_depth === "number" ? runtimeAppsData.rollback_depth : 0);
      applyRuntimeState(runtimeData, psgiRuntimeData);
      setNotice("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [applyRuntimeState]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const sync = () => {
      void refreshRuntimeState().catch(() => {
        //
      });
    };
    const interval = window.setInterval(sync, 5000);
    window.addEventListener("focus", sync);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener("focus", sync);
    };
  }, [refreshRuntimeState]);

  const updateRuntimeApp = useCallback((index: number, next: RuntimeAppFormState) => {
    setRuntimeApps((current) => current.map((entry, currentIndex) => (currentIndex === index ? next : entry)));
  }, []);

  const runValidate = useCallback(async () => {
    const localError = validateRuntimeAppsForUI(vhosts, hasBuiltPHPRuntime, hasBuiltPSGIRuntime);
    if (localError) {
      setError(localError);
      setNotice("");
      return;
    }
    setSaving(true);
    setError("");
    setNotice("");
    try {
      await apiPostJson<RuntimeAppsResponse>("/runtime-apps/validate", { raw: rawPreview });
      setNotice(tx("Validation passed."));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }, [hasBuiltPHPRuntime, hasBuiltPSGIRuntime, rawPreview, tx, vhosts]);

  const runApply = useCallback(async () => {
    const localError = validateRuntimeAppsForUI(vhosts, hasBuiltPHPRuntime, hasBuiltPSGIRuntime);
    if (localError) {
      setError(localError);
      setNotice("");
      return;
    }
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const out = await apiPutJson<RuntimeAppsResponse>("/runtime-apps", { raw: rawPreview }, { headers: { "If-Match": etag } });
      const parsedRuntimeApps = parseRuntimeAppsResponse(out);
      setETag(out.etag ?? "");
      setLoadedRaw(out.raw ?? rawPreview);
      setRuntimeApps(parsedRuntimeApps);
      setRollbackDepth(typeof out.rollback_depth === "number" ? out.rollback_depth : rollbackDepth);
      await refreshRuntimeState();
      setNotice(tx("Saved. Runtime Apps config applied."));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      try {
        const latest = await apiGetJson<RuntimeAppsResponse>("/runtime-apps");
        const latestRuntimeApps = parseRuntimeAppsResponse(latest);
        const latestRaw = latest.raw ?? runtimeAppsToRaw(latestRuntimeApps);
        const sameLoadedConfig = comparableRuntimeAppRaw(latestRaw) === comparableRuntimeAppRaw(loadedRaw);
        setETag(sameLoadedConfig ? latest.etag ?? "" : "");
        setLoadedRaw(latestRaw);
        setRollbackDepth(typeof latest.rollback_depth === "number" ? latest.rollback_depth : rollbackDepth);
        if (Array.isArray(latest.materialized)) {
          setRuntimeMaterialized(latest.materialized);
        }
        if (Array.isArray(latest.psgi_materialized)) {
          setPSGIMaterialized(latest.psgi_materialized);
        }
        const suffix = sameLoadedConfig
          ? tx("Server-side Runtime Apps revision was refreshed; the editor values were kept. Review the error and apply again.")
          : tx("Server-side Runtime Apps config changed; load before applying to avoid overwriting another change.");
        setError(`${message}; ${suffix}`);
      } catch {
        setError(message);
      }
    } finally {
      setSaving(false);
    }
  }, [etag, hasBuiltPHPRuntime, hasBuiltPSGIRuntime, loadedRaw, rawPreview, refreshRuntimeState, rollbackDepth, tx, vhosts]);

  const runRollback = useCallback(async () => {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const out = await apiPostJson<RuntimeAppsResponse>("/runtime-apps/rollback", {});
      const parsedRuntimeApps = parseRuntimeAppsResponse(out);
      setETag(out.etag ?? "");
      setLoadedRaw(out.raw ?? runtimeAppsToRaw(parsedRuntimeApps));
      setRuntimeApps(parsedRuntimeApps);
      setRollbackDepth((current) => Math.max(current - 1, 0));
      await refreshRuntimeState();
      setNotice(tx("Rollback applied."));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }, [refreshRuntimeState, tx]);

  if (loading) {
    return <div className="w-full p-4 text-neutral-500">{tx("Loading Runtime Apps...")}</div>;
  }
  if (!hasBuiltRuntime) {
    return <Navigate to="/options" replace />;
  }

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Runtime Apps")}</h1>
          <p className="text-xs text-neutral-500">{tx("Define runtime-backed application listeners here. Proxy Rules routes traffic to the generated upstream target.")}</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-neutral-500">
          <span className="rounded bg-neutral-100 px-2 py-1" title={etag || undefined}>{formatRevision(etag)}</span>
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
              setRuntimeApps((current) => {
                const next = createEmptyRuntimeApp(current.length + 1);
                if (builtRuntimeOptions[0]) {
                  next.mode = "php-fpm";
                  next.runtimeID = builtRuntimeOptions[0].runtime_id;
                } else if (builtPSGIOptions[0]) {
                  next.mode = "psgi";
                  next.runtimeID = builtPSGIOptions[0].runtime_id;
                }
                return [...current, next];
              })
            }
            disabled={readOnly || saving}
          >
            {tx("Add app")}
          </button>
        </div>

        {notice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{notice}</div> : null}
        {error ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{error}</div> : null}
        {legacyStaticCount > 0 ? (
          <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
            {tx("Legacy static runtime apps are still present in local config. Static mode is no longer supported here; remove those entries before applying changes.")}
          </div>
        ) : null}
      </section>

      <section className="space-y-4">
        <div className="space-y-4">
          {vhosts.length === 0 ? (
            <div className="rounded-xl border border-dashed border-neutral-200 bg-white p-6 text-xs text-neutral-500">
              {tx("No runtime-backed apps configured. Add one to publish a managed application listener.")}
            </div>
          ) : null}

          {vhosts.map((app, index) => (
            <article key={app.formID} className="rounded-xl border border-neutral-200 bg-white p-4 space-y-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold">{app.name || `app-${index + 1}`}</h2>
                  <p className="text-xs text-neutral-500">{tx("Listen Host")}: <code>{app.hostname || "-"}</code></p>
                </div>
                <button type="button" className="text-xs underline" onClick={() => setRuntimeApps((current) => current.filter((_, currentIndex) => currentIndex !== index))} disabled={readOnly || saving}>
                  {tx("Remove")}
                </button>
              </div>

              {app.mode === "static" ? (
                <section className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 space-y-2">
                  <div className="font-semibold">{tx("Legacy static runtime app")}</div>
                  <p>{tx("Static mode is no longer supported from this page. Remove this entry, or replace it with a PHP-FPM runtime app that has an explicit runtime binding.")}</p>
                  <div className="grid gap-2 md:grid-cols-2 text-neutral-800">
                    <div>{tx("Listen Host")}: <code>{app.hostname || "-"}</code></div>
                    <div>{tx("Listen Port")}: <code>{app.listenPort || "-"}</code></div>
                    <div className="md:col-span-2">{tx("Document Root")}: <code>{app.documentRoot || "-"}</code></div>
                  </div>
                </section>
              ) : null}

              {app.mode === "static" ? null : (
                <>
                  <div className="grid gap-3 md:grid-cols-2">
                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">{tx("Name")}</span>
                      <input value={app.name} onChange={(e) => updateRuntimeApp(index, { ...app, name: e.target.value })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" />
                    </label>
                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">{tx("Mode")}</span>
                      <select
                        value={app.mode}
                        onChange={(e) => {
                          const mode = e.target.value as RuntimeAppMode;
                          updateRuntimeApp(index, {
                            ...app,
                            mode,
                            runtimeID: mode === "psgi" ? (builtPSGIOptions[0]?.runtime_id ?? "") : (builtRuntimeOptions[0]?.runtime_id ?? ""),
                            tryFilesText: mode === "psgi" && !app.tryFilesText.trim() ? "$uri\n$uri/\n@psgi" : app.tryFilesText,
                          });
                        }}
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                      >
                        <option value="php-fpm">php-fpm</option>
                        <option value="psgi">psgi</option>
                      </select>
                    </label>
                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">{tx("Runtime")}</span>
                      <select
                        value={app.runtimeID}
                        onChange={(e) => updateRuntimeApp(index, { ...app, runtimeID: e.target.value })}
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                        disabled={app.mode === "psgi" ? builtPSGIOptions.length === 0 : builtRuntimeOptions.length === 0}
                      >
                        <option value="">{tx("Select runtime")}</option>
                        {app.mode === "psgi"
                          ? builtPSGIOptions.map((runtime) => (
                              <option key={runtime.runtime_id} value={runtime.runtime_id}>{psgiRuntimeLabel(runtime)}</option>
                            ))
                          : builtRuntimeOptions.map((runtime) => (
                              <option key={runtime.runtime_id} value={runtime.runtime_id}>{runtimeLabel(runtime)}</option>
                            ))}
                      </select>
                    </label>
                    {app.mode === "psgi" ? (
                      <PSGIStateSummary
                        tx={tx}
                        runtimeID={app.runtimeID}
                        runtime={psgiRuntimeMap.get(app.runtimeID)}
                        materialized={psgiMaterializedMap.get(app.name)}
                        process={psgiProcessMap.get(app.name)}
                      />
                    ) : (
                      <RuntimeStateSummary
                        tx={tx}
                        runtimeID={app.runtimeID}
                        runtime={runtimeMap.get(app.runtimeID)}
                        materialized={materializedMap.get(app.runtimeID)}
                        process={processMap.get(app.runtimeID)}
                      />
                    )}
                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">{tx("Listen Host")}</span>
                      <input value={app.hostname} onChange={(e) => updateRuntimeApp(index, { ...app, hostname: e.target.value })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" placeholder="127.0.0.1" />
                    </label>
                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">{tx("Listen Port")}</span>
                      <input value={app.listenPort} onChange={(e) => updateRuntimeApp(index, { ...app, listenPort: e.target.value })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" />
                    </label>
                    <label className="space-y-1 text-xs md:col-span-2">
                      <span className="block text-xs text-neutral-600">{tx("Document Root")}</span>
                      <input
                        value={app.documentRoot}
                        onChange={(e) => updateRuntimeApp(index, { ...app, documentRoot: e.target.value })}
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                        placeholder={app.mode === "psgi" ? "./data/mt/mt-static" : "./data/vhosts/<app>/public"}
                      />
                    </label>
                    {app.mode === "psgi" ? (
                      <>
                        <label className="space-y-1 text-xs md:col-span-2">
                          <span className="block text-xs text-neutral-600">{tx("App Root")}</span>
                          <input
                            value={app.appRoot}
                            onChange={(e) => updateRuntimeApp(index, { ...app, appRoot: e.target.value })}
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                            placeholder="./data/mt/MT-9.0.7"
                          />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">{tx("PSGI File")}</span>
                          <input
                            value={app.psgiFile}
                            onChange={(e) => updateRuntimeApp(index, { ...app, psgiFile: e.target.value })}
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                            placeholder="mt.psgi"
                          />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">{tx("Workers")}</span>
                          <input
                            value={app.workers}
                            onChange={(e) => updateRuntimeApp(index, { ...app, workers: e.target.value })}
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                          />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">{tx("Max Requests")}</span>
                          <input
                            value={app.maxRequests}
                            onChange={(e) => updateRuntimeApp(index, { ...app, maxRequests: e.target.value })}
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                          />
                        </label>
                        <label className="flex items-center gap-2 text-xs">
                          <input
                            type="checkbox"
                            checked={app.includeExtlib}
                            onChange={(e) => updateRuntimeApp(index, { ...app, includeExtlib: e.target.checked })}
                          />
                          {tx("Include app extlib")}
                        </label>
                      </>
                    ) : null}
                    <label className="space-y-1 text-xs md:col-span-2">
                      <span className="block text-xs text-neutral-600">{tx("try_files")}</span>
                      <textarea
                        value={app.tryFilesText}
                        onChange={(e) => updateRuntimeApp(index, { ...app, tryFilesText: e.target.value })}
                        className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                        placeholder={app.mode === "psgi" ? "$uri\n$uri/\n@psgi" : "$uri\n$uri/\n/index.php?$query_string"}
                      />
                    </label>
                  </div>

                  <section className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="text-sm font-semibold">{tx("Rewrite Rules")}</h3>
                      <button type="button" onClick={() => updateRuntimeApp(index, { ...app, rewriteRules: [...app.rewriteRules, createEmptyRewriteRule()] })} disabled={readOnly || saving}>
                        {tx("Add rule")}
                      </button>
                    </div>
                    <div className="space-y-3">
                      {app.rewriteRules.map((rule, ruleIndex) => (
                        <div key={rule.formID} className="rounded-lg border border-neutral-200 p-3 grid gap-3 md:grid-cols-2">
                          <label className="space-y-1 text-xs">
                            <span className="block text-xs text-neutral-600">{tx("Pattern")}</span>
                            <input value={rule.pattern} onChange={(e) => updateRuntimeApp(index, { ...app, rewriteRules: app.rewriteRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, pattern: e.target.value } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs" />
                          </label>
                          <label className="space-y-1 text-xs">
                            <span className="block text-xs text-neutral-600">{tx("Replacement")}</span>
                            <input value={rule.replacement} onChange={(e) => updateRuntimeApp(index, { ...app, rewriteRules: app.rewriteRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, replacement: e.target.value } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs" />
                          </label>
                          <label className="space-y-1 text-xs">
                            <span className="block text-xs text-neutral-600">{tx("Flag")}</span>
                            <select value={rule.flag} onChange={(e) => updateRuntimeApp(index, { ...app, rewriteRules: app.rewriteRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, flag: e.target.value as RewriteFlag } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white">
                              <option value="break">break</option>
                              <option value="last">last</option>
                              <option value="redirect">redirect</option>
                              <option value="permanent">permanent</option>
                            </select>
                          </label>
                          <label className="flex items-center gap-2 text-xs">
                            <input type="checkbox" checked={rule.preserveQuery} onChange={(e) => updateRuntimeApp(index, { ...app, rewriteRules: app.rewriteRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, preserveQuery: e.target.checked } : entry) })} />
                            {tx("Preserve query string")}
                          </label>
                          <button type="button" className="text-xs underline text-left" onClick={() => updateRuntimeApp(index, { ...app, rewriteRules: app.rewriteRules.filter((_, currentIndex) => currentIndex !== ruleIndex) })} disabled={readOnly || saving}>
                            {tx("Remove")}
                          </button>
                        </div>
                      ))}
                    </div>
                  </section>

                  <section className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="text-sm font-semibold">{tx("Access Rules")}</h3>
                      <button type="button" onClick={() => updateRuntimeApp(index, { ...app, accessRules: [...app.accessRules, createEmptyAccessRule()] })} disabled={readOnly || saving}>
                        {tx("Add rule")}
                      </button>
                    </div>
                    <div className="space-y-3">
                      {app.accessRules.map((rule, ruleIndex) => (
                        <div key={rule.formID} className="rounded-lg border border-neutral-200 p-3 grid gap-3 md:grid-cols-2">
                          <label className="space-y-1 text-xs">
                            <span className="block text-xs text-neutral-600">{tx("Path pattern")}</span>
                            <input value={rule.pathPattern} onChange={(e) => updateRuntimeApp(index, { ...app, accessRules: app.accessRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, pathPattern: e.target.value } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" />
                          </label>
                          <label className="space-y-1 text-xs">
                            <span className="block text-xs text-neutral-600">{tx("Action")}</span>
                            <select value={rule.action} onChange={(e) => updateRuntimeApp(index, { ...app, accessRules: app.accessRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, action: e.target.value as "allow" | "deny" } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white">
                              <option value="allow">allow</option>
                              <option value="deny">deny</option>
                            </select>
                          </label>
                          <label className="space-y-1 text-xs">
                            <span className="block text-xs text-neutral-600">{tx("CIDRs")}</span>
                            <textarea value={rule.cidrsText} onChange={(e) => updateRuntimeApp(index, { ...app, accessRules: app.accessRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, cidrsText: e.target.value } : entry) })} className="min-h-20 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs" placeholder={"127.0.0.1/32\n10.0.0.0/8"} />
                          </label>
                          <div className="space-y-3">
                            <label className="space-y-1 text-xs block">
                              <span className="block text-xs text-neutral-600">{tx("Basic Auth Realm")}</span>
                              <input value={rule.authRealm} onChange={(e) => updateRuntimeApp(index, { ...app, accessRules: app.accessRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, authRealm: e.target.value } : entry) })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" />
                            </label>
                            <label className="space-y-1 text-xs block">
                              <span className="block text-xs text-neutral-600">{tx("Users (`username:bcrypt-hash`)")}</span>
                              <textarea value={rule.authUsersText} onChange={(e) => updateRuntimeApp(index, { ...app, accessRules: app.accessRules.map((entry, currentIndex) => currentIndex === ruleIndex ? { ...entry, authUsersText: e.target.value } : entry) })} className="min-h-20 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs" placeholder={"alice:$2a$..."} />
                            </label>
                          </div>
                          <button type="button" className="text-xs underline text-left" onClick={() => updateRuntimeApp(index, { ...app, accessRules: app.accessRules.filter((_, currentIndex) => currentIndex !== ruleIndex) })} disabled={readOnly || saving}>
                            {tx("Remove")}
                          </button>
                        </div>
                      ))}
                    </div>
                  </section>

                  <section className="grid gap-3 md:grid-cols-2">
                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">{tx("Runtime App Basic Auth Realm")}</span>
                      <input value={app.basicAuthRealm} onChange={(e) => updateRuntimeApp(index, { ...app, basicAuthRealm: e.target.value })} className="w-full rounded border border-neutral-200 px-3 py-2 bg-white" />
                    </label>
                    <label className="space-y-1 text-xs md:col-span-2">
                      <span className="block text-xs text-neutral-600">{tx("Users (`username:bcrypt-hash`)")}</span>
                      <textarea value={app.basicAuthUsersText} onChange={(e) => updateRuntimeApp(index, { ...app, basicAuthUsersText: e.target.value })} className="min-h-20 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs" placeholder={"alice:$2a$..."} />
                    </label>
                    {app.mode === "php-fpm" ? (
                      <>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">{tx("php_value (`key=value`)")}</span>
                          <textarea value={app.phpValueText} onChange={(e) => updateRuntimeApp(index, { ...app, phpValueText: e.target.value })} className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs" placeholder={"memory_limit=512M"} />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">{tx("php_admin_value (`key=value`)")}</span>
                          <textarea value={app.phpAdminValueText} onChange={(e) => updateRuntimeApp(index, { ...app, phpAdminValueText: e.target.value })} className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs" placeholder={"open_basedir=/srv/app"} />
                        </label>
                      </>
                    ) : (
                      <label className="space-y-1 text-xs md:col-span-2">
                        <span className="block text-xs text-neutral-600">{tx("Environment (`KEY=value`)")}</span>
                        <textarea value={app.envText} onChange={(e) => updateRuntimeApp(index, { ...app, envText: e.target.value })} className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs" placeholder={"MT_HOME=/srv/mt"} />
                      </label>
                    )}
                  </section>
                </>
              )}
            </article>
          ))}
        </div>

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
      <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs">
        <div className="text-xs text-neutral-500">{tx("Runtime State")}</div>
        <div className="text-neutral-600">{tx("Select runtime")}</div>
      </div>
    );
  }
  const targets = process?.generated_targets?.length ? process.generated_targets : (materialized?.generated_targets ?? []);
  const materializedRuntime = !!materialized;
  return (
    <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs space-y-2">
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

function PSGIStateSummary({
  tx,
  runtimeID,
  runtime,
  materialized,
  process,
}: {
  tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
  runtimeID: string;
  runtime?: PSGIRuntimeRecord;
  materialized?: PSGIRuntimeMaterializedStatus;
  process?: PSGIRuntimeProcessStatus;
}) {
  if (!runtimeID.trim()) {
    return (
      <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs">
        <div className="text-xs text-neutral-500">{tx("Runtime State")}</div>
        <div className="text-neutral-600">{tx("Select runtime")}</div>
      </div>
    );
  }
  const state = process?.last_action || (process?.running ? "running" : materialized ? "stopped" : "not_materialized");
  const stateClass = process?.last_error || ["exited", "start_failed", "restart_failed", "identity_error", "preflight_failed", "reconcile_error"].includes(state)
    ? "bg-red-100 text-red-800"
    : process?.running
      ? "bg-green-100 text-green-800"
      : "bg-neutral-100 text-neutral-700";
  return (
    <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-xs text-neutral-500">{tx("PSGI State")}</div>
          <div className="font-medium">{runtime ? psgiRuntimeLabel(runtime) : runtimeID}</div>
        </div>
        <span className={`rounded px-2 py-1 text-xs ${stateClass}`}>{tx(state)}</span>
      </div>
      <div className="grid gap-1 text-xs text-neutral-600">
        <div>{tx("PID")}: <code>{process?.pid || "-"}</code></div>
        <div>{tx("Generated Target")}: <code className="break-all">{process?.generated_target || materialized?.generated_target || "-"}</code></div>
        {process?.last_error ? <div className="text-red-700">{process.last_error}</div> : null}
      </div>
      <Link to="/options#psgi-runtime-inventory" className="inline-flex text-xs underline">
        {tx("Open Runtime")}
      </Link>
    </div>
  );
}
