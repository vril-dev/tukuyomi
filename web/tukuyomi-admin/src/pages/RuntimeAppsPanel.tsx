import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { useI18n } from "@/lib/i18n";
import { formatRevision } from "@/lib/revision";

type RuntimeAppMode = "static" | "php-fpm" | "psgi" | "daemon";
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
  max_request_body_bytes?: number;
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
  enabled?: boolean;
  command?: string;
  args?: string[];
  working_dir?: string;
  run_user?: string;
  run_group?: string;
  restart_policy?: string;
  graceful_stop_sec?: number;
  persistent_paths?: string[];
};

type RuntimeAppsResponse = {
  etag?: string;
  raw?: string;
  runtime_apps?: {
    vhosts?: RuntimeAppEntry[];
  };
  materialized?: PHPRuntimeMaterializedStatus[];
  psgi_materialized?: PSGIRuntimeMaterializedStatus[];
  daemon_processes?: DaemonRuntimeProcessStatus[];
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

type DaemonRuntimeProcessStatus = {
  app_id: string;
  process_id: string;
  enabled?: boolean;
  running?: boolean;
  pid?: number;
  command?: string;
  args?: string[];
  app_root?: string;
  working_dir?: string;
  configured_user?: string;
  configured_group?: string;
  effective_user?: string;
  effective_group?: string;
  restart_policy?: string;
  started_at?: string;
  stopped_at?: string;
  last_action?: string;
  last_error?: string;
  log_file?: string;
};

type DaemonRuntimeProcessLog = {
  app_id: string;
  process_id: string;
  log_file: string;
  tail: string;
  truncated: boolean;
  max_bytes: number;
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
  maxRequestBodyBytes: string;
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
  enabled: boolean;
  command: string;
  argsText: string;
  workingDir: string;
  runUser: string;
  runGroup: string;
  restartPolicy: string;
  gracefulStopSec: string;
  persistentPathsText: string;
};

const DEFAULT_RUNTIME_APP_MAX_REQUEST_BODY_BYTES = "67108864";
const MAX_RUNTIME_APP_MAX_REQUEST_BODY_BYTES = 2147483648;

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
    maxRequestBodyBytes: DEFAULT_RUNTIME_APP_MAX_REQUEST_BODY_BYTES,
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
    enabled: false,
    command: "./bin/server",
    argsText: "",
    workingDir: "",
    runUser: "",
    runGroup: "",
    restartPolicy: "on-failure",
    gracefulStopSec: "5",
    persistentPathsText: "",
  };
}

function runtimeLabel(runtime: PHPRuntimeRecord) {
  return runtime.display_name || runtime.detected_version || runtime.runtime_id;
}

function psgiRuntimeLabel(runtime: PSGIRuntimeRecord) {
  return runtime.display_name || runtime.detected_version || runtime.runtime_id;
}

function runtimeStateLabel(
  process: PHPRuntimeProcessStatus | undefined,
  materialized: boolean,
) {
  if (process?.last_action) {
    return process.last_action;
  }
  if (process?.running) {
    return "running";
  }
  return materialized ? "stopped" : "not_materialized";
}

function runtimeStateClass(
  process: PHPRuntimeProcessStatus | undefined,
  materialized: boolean,
) {
  const state = runtimeStateLabel(process, materialized);
  if (
    process?.last_error ||
    [
      "exited",
      "start_failed",
      "restart_failed",
      "identity_error",
      "preflight_failed",
      "reconcile_error",
    ].includes(state)
  ) {
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
  return auth.users
    .map((user) => `${user.username}:${user.password_hash}`)
    .join("\n");
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

function parseRuntimeAppsResponse(
  data?: RuntimeAppsResponse,
): RuntimeAppFormState[] {
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
    maxRequestBodyBytes: String(
      app.max_request_body_bytes || DEFAULT_RUNTIME_APP_MAX_REQUEST_BODY_BYTES,
    ),
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
    enabled: app.enabled === true,
    command: app.command || "",
    argsText: stringListToText(app.args),
    workingDir: app.working_dir || "",
    runUser: app.run_user || "",
    runGroup: app.run_group || "",
    restartPolicy: app.restart_policy || "on-failure",
    gracefulStopSec: String(app.graceful_stop_sec || 5),
    persistentPathsText: stringListToText(app.persistent_paths),
  }));
}

function runtimeAppsToRaw(vhosts: RuntimeAppFormState[]) {
  const normalized = vhosts.map((app) => {
    if (app.mode === "daemon") {
      return {
        name: app.name.trim(),
        mode: app.mode,
        enabled: app.enabled,
        app_root: app.appRoot.trim(),
        command: app.command.trim(),
        ...(textToStringList(app.argsText).length > 0
          ? { args: textToStringList(app.argsText) }
          : {}),
        ...(app.workingDir.trim()
          ? { working_dir: app.workingDir.trim() }
          : {}),
        ...(app.runUser.trim() ? { run_user: app.runUser.trim() } : {}),
        ...(app.runGroup.trim() ? { run_group: app.runGroup.trim() } : {}),
        restart_policy: app.restartPolicy,
        graceful_stop_sec: Number(app.gracefulStopSec) || 0,
        ...(textToStringList(app.persistentPathsText).length > 0
          ? { persistent_paths: textToStringList(app.persistentPathsText) }
          : {}),
        ...(Object.keys(textToIniMap(app.envText)).length > 0
          ? { env: textToIniMap(app.envText) }
          : {}),
      };
    }
    const basicAuthUsers = textToAuthUsers(app.basicAuthUsersText).filter(
      (entry) => entry.username && entry.password_hash,
    );
    const basicAuth =
      basicAuthUsers.length > 0
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
      max_request_body_bytes: Number(app.maxRequestBodyBytes) || 0,
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
      ...(textToStringList(app.tryFilesText).length > 0
        ? { try_files: textToStringList(app.tryFilesText) }
        : {}),
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
              const authUsers = textToAuthUsers(rule.authUsersText).filter(
                (entry) => entry.username && entry.password_hash,
              );
              return {
                path_pattern: rule.pathPattern.trim(),
                action: rule.action,
                ...(textToStringList(rule.cidrsText).length > 0
                  ? { cidrs: textToStringList(rule.cidrsText) }
                  : {}),
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
      ...(app.mode === "php-fpm" &&
      Object.keys(textToIniMap(app.phpValueText)).length > 0
        ? { php_value: textToIniMap(app.phpValueText) }
        : {}),
      ...(app.mode === "php-fpm" &&
      Object.keys(textToIniMap(app.phpAdminValueText)).length > 0
        ? { php_admin_value: textToIniMap(app.phpAdminValueText) }
        : {}),
      ...(app.mode === "psgi" &&
      Object.keys(textToIniMap(app.envText)).length > 0
        ? { env: textToIniMap(app.envText) }
        : {}),
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

function validateRuntimeAppsForUI(
  vhosts: RuntimeAppFormState[],
  hasBuiltPHPRuntime: boolean,
  hasBuiltPSGIRuntime: boolean,
) {
  for (const [index, app] of vhosts.entries()) {
    const label = app.name.trim() || `app-${index + 1}`;
    if (!label) {
      return `runtime app ${index + 1}: name is required`;
    }
    if (app.mode === "static") {
      return `${label}: legacy static runtime app is no longer supported; remove it`;
    }
    if (app.mode === "daemon") {
      if (!app.appRoot.trim()) {
        return `${label}: app root is required for daemon`;
      }
      if (!app.command.trim()) {
        return `${label}: command is required for daemon`;
      }
      if (!["none", "on-failure", "always"].includes(app.restartPolicy)) {
        return `${label}: restart policy is invalid`;
      }
      const gracefulStopSec = Number(app.gracefulStopSec);
      if (
        !Number.isInteger(gracefulStopSec) ||
        gracefulStopSec < 0 ||
        gracefulStopSec > 60
      ) {
        return `${label}: graceful stop seconds must be between 0 and 60`;
      }
      continue;
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
    const maxRequestBodyBytes = Number(app.maxRequestBodyBytes);
    if (
      !Number.isInteger(maxRequestBodyBytes) ||
      maxRequestBodyBytes < 0 ||
      maxRequestBodyBytes > MAX_RUNTIME_APP_MAX_REQUEST_BODY_BYTES
    ) {
      return `${label}: max request body bytes must be between 0 and ${MAX_RUNTIME_APP_MAX_REQUEST_BODY_BYTES}`;
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
  const [runtimeMaterialized, setRuntimeMaterialized] = useState<
    PHPRuntimeMaterializedStatus[]
  >([]);
  const [runtimeProcesses, setRuntimeProcesses] = useState<
    PHPRuntimeProcessStatus[]
  >([]);
  const [psgiRuntimeOptions, setPSGIRuntimeOptions] = useState<
    PSGIRuntimeRecord[]
  >([]);
  const [psgiMaterialized, setPSGIMaterialized] = useState<
    PSGIRuntimeMaterializedStatus[]
  >([]);
  const [psgiProcesses, setPSGIProcesses] = useState<
    PSGIRuntimeProcessStatus[]
  >([]);
  const [daemonProcesses, setDaemonProcesses] = useState<
    DaemonRuntimeProcessStatus[]
  >([]);
  const [rollbackDepth, setRollbackDepth] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [daemonLog, setDaemonLog] = useState<DaemonRuntimeProcessLog | null>(
    null,
  );
  const [daemonLogLoading, setDaemonLogLoading] = useState(false);

  const rawPreview = useMemo(() => runtimeAppsToRaw(vhosts), [vhosts]);
  const legacyStaticCount = useMemo(
    () => vhosts.filter((entry) => entry.mode === "static").length,
    [vhosts],
  );
  const builtRuntimeOptions = useMemo(
    () => runtimeOptions.filter((runtime) => runtime.available === true),
    [runtimeOptions],
  );
  const runtimeMap = useMemo(
    () =>
      new Map(runtimeOptions.map((runtime) => [runtime.runtime_id, runtime])),
    [runtimeOptions],
  );
  const materializedMap = useMemo(
    () =>
      new Map(
        runtimeMaterialized.map((runtime) => [runtime.runtime_id, runtime]),
      ),
    [runtimeMaterialized],
  );
  const processMap = useMemo(
    () =>
      new Map(runtimeProcesses.map((process) => [process.runtime_id, process])),
    [runtimeProcesses],
  );
  const builtPSGIOptions = useMemo(
    () => psgiRuntimeOptions.filter((runtime) => runtime.available === true),
    [psgiRuntimeOptions],
  );
  const psgiRuntimeMap = useMemo(
    () =>
      new Map(
        psgiRuntimeOptions.map((runtime) => [runtime.runtime_id, runtime]),
      ),
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
  const daemonProcessMap = useMemo(() => {
    const out = new Map<string, DaemonRuntimeProcessStatus>();
    for (const process of daemonProcesses) {
      out.set(process.app_id, process);
      out.set(process.process_id, process);
    }
    return out;
  }, [daemonProcesses]);
  const hasBuiltPHPRuntime = builtRuntimeOptions.length > 0;
  const hasBuiltPSGIRuntime = builtPSGIOptions.length > 0;

  const applyRuntimeState = useCallback(
    (
      runtimeData: PHPRuntimesResponse,
      psgiRuntimeData: PSGIRuntimesResponse,
    ) => {
      setRuntimeOptions(
        Array.isArray(runtimeData.runtimes?.runtimes)
          ? runtimeData.runtimes.runtimes
          : [],
      );
      setRuntimeMaterialized(
        Array.isArray(runtimeData.materialized) ? runtimeData.materialized : [],
      );
      setRuntimeProcesses(
        Array.isArray(runtimeData.processes) ? runtimeData.processes : [],
      );
      setPSGIRuntimeOptions(
        Array.isArray(psgiRuntimeData.runtimes?.runtimes)
          ? psgiRuntimeData.runtimes.runtimes
          : [],
      );
      setPSGIMaterialized(
        Array.isArray(psgiRuntimeData.materialized)
          ? psgiRuntimeData.materialized
          : [],
      );
      setPSGIProcesses(
        Array.isArray(psgiRuntimeData.processes)
          ? psgiRuntimeData.processes
          : [],
      );
    },
    [],
  );

  const refreshRuntimeState = useCallback(async () => {
    const [runtimeData, psgiRuntimeData, runtimeAppsData] = await Promise.all([
      apiGetJson<PHPRuntimesResponse>("/php-runtimes"),
      apiGetJson<PSGIRuntimesResponse>("/psgi-runtimes"),
      apiGetJson<RuntimeAppsResponse>("/runtime-apps"),
    ]);
    applyRuntimeState(runtimeData, psgiRuntimeData);
    setDaemonProcesses(
      Array.isArray(runtimeAppsData.daemon_processes)
        ? runtimeAppsData.daemon_processes
        : [],
    );
  }, [applyRuntimeState]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [runtimeAppsData, runtimeData, psgiRuntimeData] = await Promise.all(
        [
          apiGetJson<RuntimeAppsResponse>("/runtime-apps"),
          apiGetJson<PHPRuntimesResponse>("/php-runtimes"),
          apiGetJson<PSGIRuntimesResponse>("/psgi-runtimes"),
        ],
      );
      const parsedRuntimeApps = parseRuntimeAppsResponse(runtimeAppsData);
      setETag(runtimeAppsData.etag ?? "");
      setLoadedRaw(runtimeAppsData.raw ?? runtimeAppsToRaw(parsedRuntimeApps));
      setRuntimeApps(parsedRuntimeApps);
      setDaemonProcesses(
        Array.isArray(runtimeAppsData.daemon_processes)
          ? runtimeAppsData.daemon_processes
          : [],
      );
      setRollbackDepth(
        typeof runtimeAppsData.rollback_depth === "number"
          ? runtimeAppsData.rollback_depth
          : 0,
      );
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

  const updateRuntimeApp = useCallback(
    (index: number, next: RuntimeAppFormState) => {
      setRuntimeApps((current) =>
        current.map((entry, currentIndex) =>
          currentIndex === index ? next : entry,
        ),
      );
    },
    [],
  );

  const runValidate = useCallback(async () => {
    const localError = validateRuntimeAppsForUI(
      vhosts,
      hasBuiltPHPRuntime,
      hasBuiltPSGIRuntime,
    );
    if (localError) {
      setError(localError);
      setNotice("");
      return;
    }
    setSaving(true);
    setError("");
    setNotice("");
    try {
      await apiPostJson<RuntimeAppsResponse>("/runtime-apps/validate", {
        raw: rawPreview,
      });
      setNotice(tx("Validation passed."));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }, [hasBuiltPHPRuntime, hasBuiltPSGIRuntime, rawPreview, tx, vhosts]);

  const runApply = useCallback(async () => {
    const localError = validateRuntimeAppsForUI(
      vhosts,
      hasBuiltPHPRuntime,
      hasBuiltPSGIRuntime,
    );
    if (localError) {
      setError(localError);
      setNotice("");
      return;
    }
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const out = await apiPutJson<RuntimeAppsResponse>(
        "/runtime-apps",
        { raw: rawPreview },
        { headers: { "If-Match": etag } },
      );
      const parsedRuntimeApps = parseRuntimeAppsResponse(out);
      setETag(out.etag ?? "");
      setLoadedRaw(out.raw ?? rawPreview);
      setRuntimeApps(parsedRuntimeApps);
      setRollbackDepth(
        typeof out.rollback_depth === "number"
          ? out.rollback_depth
          : rollbackDepth,
      );
      await refreshRuntimeState();
      setNotice(tx("Saved. Runtime Apps config applied."));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      try {
        const latest = await apiGetJson<RuntimeAppsResponse>("/runtime-apps");
        const latestRuntimeApps = parseRuntimeAppsResponse(latest);
        const latestRaw = latest.raw ?? runtimeAppsToRaw(latestRuntimeApps);
        const sameLoadedConfig =
          comparableRuntimeAppRaw(latestRaw) ===
          comparableRuntimeAppRaw(loadedRaw);
        setETag(sameLoadedConfig ? (latest.etag ?? "") : "");
        setLoadedRaw(latestRaw);
        setRollbackDepth(
          typeof latest.rollback_depth === "number"
            ? latest.rollback_depth
            : rollbackDepth,
        );
        if (Array.isArray(latest.materialized)) {
          setRuntimeMaterialized(latest.materialized);
        }
        if (Array.isArray(latest.psgi_materialized)) {
          setPSGIMaterialized(latest.psgi_materialized);
        }
        if (Array.isArray(latest.daemon_processes)) {
          setDaemonProcesses(latest.daemon_processes);
        }
        const suffix = sameLoadedConfig
          ? tx(
              "Server-side Runtime Apps revision was refreshed; the editor values were kept. Review the error and apply again.",
            )
          : tx(
              "Server-side Runtime Apps config changed; load before applying to avoid overwriting another change.",
            );
        setError(`${message}; ${suffix}`);
      } catch {
        setError(message);
      }
    } finally {
      setSaving(false);
    }
  }, [
    etag,
    hasBuiltPHPRuntime,
    hasBuiltPSGIRuntime,
    loadedRaw,
    rawPreview,
    refreshRuntimeState,
    rollbackDepth,
    tx,
    vhosts,
  ]);

  const runRollback = useCallback(async () => {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const out = await apiPostJson<RuntimeAppsResponse>(
        "/runtime-apps/rollback",
        {},
      );
      const parsedRuntimeApps = parseRuntimeAppsResponse(out);
      setETag(out.etag ?? "");
      setLoadedRaw(out.raw ?? runtimeAppsToRaw(parsedRuntimeApps));
      setRuntimeApps(parsedRuntimeApps);
      setDaemonProcesses(
        Array.isArray(out.daemon_processes) ? out.daemon_processes : [],
      );
      setRollbackDepth((current) => Math.max(current - 1, 0));
      await refreshRuntimeState();
      setNotice(tx("Rollback applied."));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }, [refreshRuntimeState, tx]);

  const runDaemonAction = useCallback(
    async (appID: string, action: "up" | "down" | "reload") => {
      setSaving(true);
      setError("");
      setNotice("");
      try {
        const out = await apiPostJson<RuntimeAppsResponse>(
          `/daemon-processes/${encodeURIComponent(appID)}/${action}`,
          {},
        );
        setDaemonProcesses(
          Array.isArray(out.daemon_processes) ? out.daemon_processes : [],
        );
        await refreshRuntimeState();
        setNotice(tx("Daemon action completed."));
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setSaving(false);
      }
    },
    [refreshRuntimeState, tx],
  );

  const openDaemonLog = useCallback(
    async (appID: string) => {
      setDaemonLogLoading(true);
      setError("");
      try {
        const out = await apiGetJson<DaemonRuntimeProcessLog>(
          `/daemon-processes/${encodeURIComponent(appID)}/log?max_bytes=32768`,
        );
        setDaemonLog(out);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setDaemonLogLoading(false);
      }
    },
    [],
  );

  if (loading) {
    return (
      <div className="w-full p-4 text-neutral-500">
        {tx("Loading Runtime Apps...")}
      </div>
    );
  }

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Runtime Apps")}</h1>
          <p className="text-xs text-neutral-500">
            {tx(
              "Define runtime-backed application listeners here. Publish traffic only through explicit Proxy Rules upstreams and routes.",
            )}
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-neutral-500">
          <span
            className="rounded bg-neutral-100 px-2 py-1"
            title={etag || undefined}
          >
            {formatRevision(etag)}
          </span>
          <span className="rounded bg-neutral-100 px-2 py-1">
            {tx("Rollback depth")} {rollbackDepth}
          </span>
        </div>
      </header>

      <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={() => void load()} disabled={saving}>
            {tx("Load")}
          </button>
          <button
            type="button"
            onClick={() => void runValidate()}
            disabled={saving}
          >
            {tx("Validate")}
          </button>
          <button
            type="button"
            onClick={() => void runApply()}
            disabled={readOnly || saving || !etag}
          >
            {tx("Apply")}
          </button>
          <button
            type="button"
            onClick={() => void runRollback()}
            disabled={readOnly || saving || rollbackDepth === 0}
          >
            {tx("Rollback")}
          </button>
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

        {notice ? (
          <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">
            {notice}
          </div>
        ) : null}
        {error ? (
          <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">
            {error}
          </div>
        ) : null}
        {legacyStaticCount > 0 ? (
          <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
            {tx(
              "Legacy static runtime apps are still present in local config. Static mode is no longer supported here; remove those entries before applying changes.",
            )}
          </div>
        ) : null}
      </section>

      <section className="space-y-4">
        <div className="space-y-4">
          {vhosts.length === 0 ? (
            <div className="rounded-xl border border-dashed border-neutral-200 bg-white p-6 text-xs text-neutral-500">
              {tx(
                "No runtime-backed apps configured. Add one to publish a managed application listener.",
              )}
            </div>
          ) : null}

          {vhosts.map((app, index) => (
            <article
              key={app.formID}
              className="rounded-xl border border-neutral-200 bg-white p-4 space-y-4"
            >
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold">
                    {app.name || `app-${index + 1}`}
                  </h2>
                  <p className="text-xs text-neutral-500">
                    {app.mode === "daemon" ? tx("App Root") : tx("Listen Host")}
                    :{" "}
                    <code>
                      {app.mode === "daemon"
                        ? app.appRoot || "-"
                        : app.hostname || "-"}
                    </code>
                  </p>
                </div>
                <button
                  type="button"
                  className="text-xs"
                  onClick={() =>
                    setRuntimeApps((current) =>
                      current.filter(
                        (_, currentIndex) => currentIndex !== index,
                      ),
                    )
                  }
                  disabled={readOnly || saving}
                >
                  {tx("Remove")}
                </button>
              </div>

              {app.mode === "static" ? (
                <section className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 space-y-2">
                  <div className="font-semibold">
                    {tx("Legacy static runtime app")}
                  </div>
                  <p>
                    {tx(
                      "Static mode is no longer supported from this page. Remove this entry, or replace it with a PHP-FPM runtime app that has an explicit runtime binding.",
                    )}
                  </p>
                  <div className="grid gap-2 md:grid-cols-2 text-neutral-800">
                    <div>
                      {tx("Listen Host")}: <code>{app.hostname || "-"}</code>
                    </div>
                    <div>
                      {tx("Listen Port")}: <code>{app.listenPort || "-"}</code>
                    </div>
                    <div className="md:col-span-2">
                      {tx("Document Root")}:{" "}
                      <code>{app.documentRoot || "-"}</code>
                    </div>
                  </div>
                </section>
              ) : null}

              {app.mode === "static" ? null : (
                <>
                  <div className="grid gap-3 md:grid-cols-2">
                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">
                        {tx("Name")}
                      </span>
                      <input
                        value={app.name}
                        onChange={(e) =>
                          updateRuntimeApp(index, {
                            ...app,
                            name: e.target.value,
                          })
                        }
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                      />
                    </label>

                    <label className="space-y-1 text-xs">
                      <span className="block text-xs text-neutral-600">
                        {tx("Mode")}
                      </span>
                      <select
                        value={app.mode}
                        onChange={(e) => {
                          const mode = e.target.value as RuntimeAppMode;
                          updateRuntimeApp(index, {
                            ...app,
                            mode,
                            runtimeID:
                              mode === "daemon"
                                ? ""
                                : mode === "psgi"
                                  ? (builtPSGIOptions[0]?.runtime_id ?? "")
                                  : (builtRuntimeOptions[0]?.runtime_id ?? ""),
                            tryFilesText:
                              mode === "psgi" && !app.tryFilesText.trim()
                                ? "$uri\n$uri/\n@psgi"
                                : app.tryFilesText,
                            appRoot:
                              mode === "daemon" && !app.appRoot.trim()
                                ? `./data/runtime-sites/${app.name || `app-${index + 1}`}/app`
                                : app.appRoot,
                          });
                        }}
                        className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                      >
                        <option value="php-fpm" disabled={!hasBuiltPHPRuntime}>
                          php-fpm
                        </option>
                        <option value="psgi" disabled={!hasBuiltPSGIRuntime}>
                          psgi
                        </option>
                        <option value="daemon">daemon</option>
                      </select>
                    </label>

                    {app.mode !== "daemon" ? (
                      <label className="space-y-1 text-xs">
                        <span className="block text-xs text-neutral-600">
                          {tx("Runtime")}
                        </span>
                        <select
                          value={app.runtimeID}
                          onChange={(e) =>
                            updateRuntimeApp(index, {
                              ...app,
                              runtimeID: e.target.value,
                            })
                          }
                          className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                          disabled={
                            app.mode === "psgi"
                              ? builtPSGIOptions.length === 0
                              : builtRuntimeOptions.length === 0
                          }
                        >
                          <option value="">{tx("Select runtime")}</option>
                          {app.mode === "psgi"
                            ? builtPSGIOptions.map((runtime) => (
                                <option
                                  key={runtime.runtime_id}
                                  value={runtime.runtime_id}
                                >
                                  {psgiRuntimeLabel(runtime)}
                                </option>
                              ))
                            : builtRuntimeOptions.map((runtime) => (
                                <option
                                  key={runtime.runtime_id}
                                  value={runtime.runtime_id}
                                >
                                  {runtimeLabel(runtime)}
                                </option>
                              ))}
                        </select>
                      </label>
                    ) : null}

                    {app.mode === "daemon" ? (
                      <DaemonStateSummary
                        tx={tx}
                        app={app}
                        process={daemonProcessMap.get(app.name)}
                        readOnly={readOnly}
                        saving={saving}
                        onAction={(action) =>
                          void runDaemonAction(app.name, action)
                        }
                        onViewLog={() => void openDaemonLog(app.name)}
                        logLoading={daemonLogLoading}
                      />
                    ) : app.mode === "psgi" ? (
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

                    {app.mode === "daemon" ? (
                      <>
                        <label className="flex items-center gap-2 text-xs">
                          <input
                            type="checkbox"
                            checked={app.enabled}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                enabled: e.target.checked,
                              })
                            }
                          />
                          {tx("Enable daemon")}
                        </label>
                        <label className="space-y-1 text-xs md:col-span-2">
                          <span className="block text-xs text-neutral-600">
                            {tx("App Root")}
                          </span>
                          <input
                            value={app.appRoot}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                appRoot: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                            placeholder={`./data/runtime-sites/${app.name || `app-${index + 1}`}/app`}
                          />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("Command")}
                          </span>
                          <input
                            value={app.command}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                command: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                            placeholder="./bin/server"
                          />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("Working dir")}
                          </span>
                          <input
                            value={app.workingDir}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                workingDir: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                            placeholder="."
                          />
                        </label>
                        <label className="space-y-1 text-xs md:col-span-2">
                          <span className="block text-xs text-neutral-600">
                            {tx("Args")}
                          </span>
                          <textarea
                            value={app.argsText}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                argsText: e.target.value,
                              })
                            }
                            className="min-h-20 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                            placeholder={"--config\nconfig/mqtt-broker.yml"}
                          />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("Run user")}
                          </span>
                          <input
                            value={app.runUser}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                runUser: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                            placeholder="tukuyomi"
                          />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("Run group")}
                          </span>
                          <input
                            value={app.runGroup}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                runGroup: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                          />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("Restart policy")}
                          </span>
                          <select
                            value={app.restartPolicy}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                restartPolicy: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                          >
                            <option value="on-failure">on-failure</option>
                            <option value="always">always</option>
                            <option value="none">none</option>
                          </select>
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("Graceful stop seconds")}
                          </span>
                          <input
                            type="number"
                            min="0"
                            max="60"
                            value={app.gracefulStopSec}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                gracefulStopSec: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                          />
                        </label>
                        <label className="space-y-1 text-xs md:col-span-2">
                          <span className="block text-xs text-neutral-600">
                            {tx("Persistent paths")}
                          </span>
                          <textarea
                            value={app.persistentPathsText}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                persistentPathsText: e.target.value,
                              })
                            }
                            className="min-h-20 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                            placeholder={"data\nstate"}
                          />
                        </label>
                      </>
                    ) : (
                      <>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("Listen Host")}
                          </span>
                          <input
                            value={app.hostname}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                hostname: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                            placeholder="127.0.0.1"
                          />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("Listen Port")}
                          </span>
                          <input
                            value={app.listenPort}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                listenPort: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                          />
                        </label>
                        <label className="space-y-1 text-xs md:col-span-2">
                          <span className="block text-xs text-neutral-600">
                            {tx("Document Root")}
                          </span>
                          <input
                            value={app.documentRoot}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                documentRoot: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                            placeholder={
                              app.mode === "psgi"
                                ? "./data/runtime-sites/<app-id>/static"
                                : "./data/runtime-sites/<app-id>/public"
                            }
                          />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("Max request body bytes")}
                          </span>
                          <input
                            type="number"
                            min="0"
                            max={MAX_RUNTIME_APP_MAX_REQUEST_BODY_BYTES}
                            value={app.maxRequestBodyBytes}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                maxRequestBodyBytes: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                            placeholder={
                              DEFAULT_RUNTIME_APP_MAX_REQUEST_BODY_BYTES
                            }
                          />
                          <span className="block text-[11px] text-neutral-500">
                            {tx("0 uses the 64 MiB default. Maximum: 2 GiB.")}
                          </span>
                        </label>
                        {app.mode === "psgi" ? (
                          <>
                            <label className="space-y-1 text-xs md:col-span-2">
                              <span className="block text-xs text-neutral-600">
                                {tx("App Root")}
                              </span>
                              <input
                                value={app.appRoot}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    appRoot: e.target.value,
                                  })
                                }
                                className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                                placeholder="./data/runtime-sites/<app-id>/app"
                              />
                            </label>
                            <label className="space-y-1 text-xs">
                              <span className="block text-xs text-neutral-600">
                                {tx("PSGI File")}
                              </span>
                              <input
                                value={app.psgiFile}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    psgiFile: e.target.value,
                                  })
                                }
                                className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                                placeholder="mt.psgi"
                              />
                            </label>
                            <label className="space-y-1 text-xs">
                              <span className="block text-xs text-neutral-600">
                                {tx("Workers")}
                              </span>
                              <input
                                value={app.workers}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    workers: e.target.value,
                                  })
                                }
                                className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                              />
                            </label>
                            <label className="space-y-1 text-xs">
                              <span className="block text-xs text-neutral-600">
                                {tx("Max Requests")}
                              </span>
                              <input
                                value={app.maxRequests}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    maxRequests: e.target.value,
                                  })
                                }
                                className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                              />
                            </label>
                            <label className="flex items-center gap-2 text-xs">
                              <input
                                type="checkbox"
                                checked={app.includeExtlib}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    includeExtlib: e.target.checked,
                                  })
                                }
                              />
                              {tx("Include app extlib")}
                            </label>
                          </>
                        ) : null}
                        <label className="space-y-1 text-xs md:col-span-2">
                          <span className="block text-xs text-neutral-600">
                            {tx("try_files")}
                          </span>
                          <textarea
                            value={app.tryFilesText}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                tryFilesText: e.target.value,
                              })
                            }
                            className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                            placeholder={
                              app.mode === "psgi"
                                ? "$uri\n$uri/\n@psgi"
                                : "$uri\n$uri/\n/index.php?$query_string"
                            }
                          />
                        </label>
                      </>
                    )}
                  </div>

                  {app.mode !== "daemon" ? (
                    <section className="space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <h3 className="text-sm font-semibold">
                          {tx("Rewrite Rules")}
                        </h3>
                        <button
                          type="button"
                          onClick={() =>
                            updateRuntimeApp(index, {
                              ...app,
                              rewriteRules: [
                                ...app.rewriteRules,
                                createEmptyRewriteRule(),
                              ],
                            })
                          }
                          disabled={readOnly || saving}
                        >
                          {tx("Add rule")}
                        </button>
                      </div>
                      <div className="space-y-3">
                        {app.rewriteRules.map((rule, ruleIndex) => (
                          <div
                            key={rule.formID}
                            className="rounded-lg border border-neutral-200 p-3 grid gap-3 md:grid-cols-2"
                          >
                            <label className="space-y-1 text-xs">
                              <span className="block text-xs text-neutral-600">
                                {tx("Pattern")}
                              </span>
                              <input
                                value={rule.pattern}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    rewriteRules: app.rewriteRules.map(
                                      (entry, currentIndex) =>
                                        currentIndex === ruleIndex
                                          ? {
                                              ...entry,
                                              pattern: e.target.value,
                                            }
                                          : entry,
                                    ),
                                  })
                                }
                                className="w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                              />
                            </label>
                            <label className="space-y-1 text-xs">
                              <span className="block text-xs text-neutral-600">
                                {tx("Replacement")}
                              </span>
                              <input
                                value={rule.replacement}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    rewriteRules: app.rewriteRules.map(
                                      (entry, currentIndex) =>
                                        currentIndex === ruleIndex
                                          ? {
                                              ...entry,
                                              replacement: e.target.value,
                                            }
                                          : entry,
                                    ),
                                  })
                                }
                                className="w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                              />
                            </label>
                            <label className="space-y-1 text-xs">
                              <span className="block text-xs text-neutral-600">
                                {tx("Flag")}
                              </span>
                              <select
                                value={rule.flag}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    rewriteRules: app.rewriteRules.map(
                                      (entry, currentIndex) =>
                                        currentIndex === ruleIndex
                                          ? {
                                              ...entry,
                                              flag: e.target
                                                .value as RewriteFlag,
                                            }
                                          : entry,
                                    ),
                                  })
                                }
                                className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                              >
                                <option value="break">break</option>
                                <option value="last">last</option>
                                <option value="redirect">redirect</option>
                                <option value="permanent">permanent</option>
                              </select>
                            </label>
                            <label className="flex items-center gap-2 text-xs">
                              <input
                                type="checkbox"
                                checked={rule.preserveQuery}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    rewriteRules: app.rewriteRules.map(
                                      (entry, currentIndex) =>
                                        currentIndex === ruleIndex
                                          ? {
                                              ...entry,
                                              preserveQuery: e.target.checked,
                                            }
                                          : entry,
                                    ),
                                  })
                                }
                              />
                              {tx("Preserve query string")}
                            </label>
                            <button
                              type="button"
                              className="text-xs text-left"
                              onClick={() =>
                                updateRuntimeApp(index, {
                                  ...app,
                                  rewriteRules: app.rewriteRules.filter(
                                    (_, currentIndex) =>
                                      currentIndex !== ruleIndex,
                                  ),
                                })
                              }
                              disabled={readOnly || saving}
                            >
                              {tx("Remove")}
                            </button>
                          </div>
                        ))}
                      </div>
                    </section>
                  ) : null}

                  {app.mode !== "daemon" ? (
                    <section className="space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <h3 className="text-sm font-semibold">
                          {tx("Access Rules")}
                        </h3>
                        <button
                          type="button"
                          onClick={() =>
                            updateRuntimeApp(index, {
                              ...app,
                              accessRules: [
                                ...app.accessRules,
                                createEmptyAccessRule(),
                              ],
                            })
                          }
                          disabled={readOnly || saving}
                        >
                          {tx("Add rule")}
                        </button>
                      </div>
                      <div className="space-y-3">
                        {app.accessRules.map((rule, ruleIndex) => (
                          <div
                            key={rule.formID}
                            className="rounded-lg border border-neutral-200 p-3 grid gap-3 md:grid-cols-2"
                          >
                            <label className="space-y-1 text-xs">
                              <span className="block text-xs text-neutral-600">
                                {tx("Path pattern")}
                              </span>
                              <input
                                value={rule.pathPattern}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    accessRules: app.accessRules.map(
                                      (entry, currentIndex) =>
                                        currentIndex === ruleIndex
                                          ? {
                                              ...entry,
                                              pathPattern: e.target.value,
                                            }
                                          : entry,
                                    ),
                                  })
                                }
                                className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                              />
                            </label>
                            <label className="space-y-1 text-xs">
                              <span className="block text-xs text-neutral-600">
                                {tx("Action")}
                              </span>
                              <select
                                value={rule.action}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    accessRules: app.accessRules.map(
                                      (entry, currentIndex) =>
                                        currentIndex === ruleIndex
                                          ? {
                                              ...entry,
                                              action: e.target.value as
                                                | "allow"
                                                | "deny",
                                            }
                                          : entry,
                                    ),
                                  })
                                }
                                className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                              >
                                <option value="allow">allow</option>
                                <option value="deny">deny</option>
                              </select>
                            </label>
                            <label className="space-y-1 text-xs">
                              <span className="block text-xs text-neutral-600">
                                {tx("CIDRs")}
                              </span>
                              <textarea
                                value={rule.cidrsText}
                                onChange={(e) =>
                                  updateRuntimeApp(index, {
                                    ...app,
                                    accessRules: app.accessRules.map(
                                      (entry, currentIndex) =>
                                        currentIndex === ruleIndex
                                          ? {
                                              ...entry,
                                              cidrsText: e.target.value,
                                            }
                                          : entry,
                                    ),
                                  })
                                }
                                className="min-h-20 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                                placeholder={"127.0.0.1/32\n10.0.0.0/8"}
                              />
                            </label>
                            <div className="space-y-3">
                              <label className="space-y-1 text-xs block">
                                <span className="block text-xs text-neutral-600">
                                  {tx("Basic Auth Realm")}
                                </span>
                                <input
                                  value={rule.authRealm}
                                  onChange={(e) =>
                                    updateRuntimeApp(index, {
                                      ...app,
                                      accessRules: app.accessRules.map(
                                        (entry, currentIndex) =>
                                          currentIndex === ruleIndex
                                            ? {
                                                ...entry,
                                                authRealm: e.target.value,
                                              }
                                            : entry,
                                      ),
                                    })
                                  }
                                  className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                                />
                              </label>
                              <label className="space-y-1 text-xs block">
                                <span className="block text-xs text-neutral-600">
                                  {tx("Users (`username:bcrypt-hash`)")}
                                </span>
                                <textarea
                                  value={rule.authUsersText}
                                  onChange={(e) =>
                                    updateRuntimeApp(index, {
                                      ...app,
                                      accessRules: app.accessRules.map(
                                        (entry, currentIndex) =>
                                          currentIndex === ruleIndex
                                            ? {
                                                ...entry,
                                                authUsersText: e.target.value,
                                              }
                                            : entry,
                                      ),
                                    })
                                  }
                                  className="min-h-20 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                                  placeholder={"alice:$2a$..."}
                                />
                              </label>
                            </div>
                            <button
                              type="button"
                              className="text-xs text-left"
                              onClick={() =>
                                updateRuntimeApp(index, {
                                  ...app,
                                  accessRules: app.accessRules.filter(
                                    (_, currentIndex) =>
                                      currentIndex !== ruleIndex,
                                  ),
                                })
                              }
                              disabled={readOnly || saving}
                            >
                              {tx("Remove")}
                            </button>
                          </div>
                        ))}
                      </div>
                    </section>
                  ) : null}

                  <section className="grid gap-3 md:grid-cols-2">
                    {app.mode !== "daemon" ? (
                      <>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("Runtime App Basic Auth Realm")}
                          </span>
                          <input
                            value={app.basicAuthRealm}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                basicAuthRealm: e.target.value,
                              })
                            }
                            className="w-full rounded border border-neutral-200 px-3 py-2 bg-white"
                          />
                        </label>
                        <label className="space-y-1 text-xs md:col-span-2">
                          <span className="block text-xs text-neutral-600">
                            {tx("Users (`username:bcrypt-hash`)")}
                          </span>
                          <textarea
                            value={app.basicAuthUsersText}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                basicAuthUsersText: e.target.value,
                              })
                            }
                            className="min-h-20 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                            placeholder={"alice:$2a$..."}
                          />
                        </label>
                      </>
                    ) : null}
                    {app.mode === "php-fpm" ? (
                      <>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("php_value (`key=value`)")}
                          </span>
                          <textarea
                            value={app.phpValueText}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                phpValueText: e.target.value,
                              })
                            }
                            className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                            placeholder={"memory_limit=512M"}
                          />
                        </label>
                        <label className="space-y-1 text-xs">
                          <span className="block text-xs text-neutral-600">
                            {tx("php_admin_value (`key=value`)")}
                          </span>
                          <textarea
                            value={app.phpAdminValueText}
                            onChange={(e) =>
                              updateRuntimeApp(index, {
                                ...app,
                                phpAdminValueText: e.target.value,
                              })
                            }
                            className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                            placeholder={"open_basedir=/srv/app"}
                          />
                        </label>
                      </>
                    ) : (
                      <label className="space-y-1 text-xs md:col-span-2">
                        <span className="block text-xs text-neutral-600">
                          {tx("Environment (`KEY=value`)")}
                        </span>
                        <textarea
                          value={app.envText}
                          onChange={(e) =>
                            updateRuntimeApp(index, {
                              ...app,
                              envText: e.target.value,
                            })
                          }
                          className="min-h-24 w-full rounded border border-neutral-200 px-3 py-2 bg-white font-mono text-xs"
                          placeholder={"MT_HOME=/srv/mt"}
                        />
                      </label>
                    )}
                  </section>
                </>
              )}
            </article>
          ))}
        </div>
      </section>
      {daemonLog ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/35 px-4 py-6">
          <div className="w-full max-w-5xl rounded-lg border border-neutral-200 bg-white shadow-lg">
            <div className="flex items-start justify-between gap-3 border-b border-neutral-200 px-4 py-3">
              <div>
                <h2 className="text-sm">{tx("Daemon log")}</h2>
                <p className="text-xs text-neutral-500">
                  {daemonLog.app_id} / {daemonLog.log_file}
                </p>
              </div>
              <button type="button" onClick={() => setDaemonLog(null)}>
                {tx("Close")}
              </button>
            </div>
            <div className="p-4">
              {daemonLog.truncated ? (
                <p className="form-message info">
                  {tx("Showing the latest bounded log output.")}
                </p>
              ) : null}
              <pre className="max-h-[60vh] overflow-auto rounded border border-neutral-200 bg-white p-3 font-mono text-xs leading-5 text-neutral-900">
                {daemonLog.tail || tx("No daemon log output.")}
              </pre>
            </div>
          </div>
        </div>
      ) : null}
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
  tx: (
    key: string,
    vars?: Record<string, string | number | boolean | null | undefined>,
  ) => string;
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
  const targets = process?.generated_targets?.length
    ? process.generated_targets
    : (materialized?.generated_targets ?? []);
  const materializedRuntime = !!materialized;
  return (
    <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-xs text-neutral-500">{tx("Runtime State")}</div>
          <div className="font-medium">
            {runtime ? runtimeLabel(runtime) : runtimeID}
          </div>
        </div>
        <span
          className={`rounded px-2 py-1 text-xs ${runtimeStateClass(process, materializedRuntime)}`}
        >
          {tx(runtimeStateLabel(process, materializedRuntime))}
        </span>
      </div>
      <div className="grid gap-1 text-xs text-neutral-600">
        <div>
          {tx("PID")}: <code>{process?.pid || "-"}</code>
        </div>
        <div>
          {tx("Generated Targets")}:{" "}
          <code className="break-all">
            {targets.length > 0 ? targets.join(", ") : "-"}
          </code>
        </div>
        {process?.last_error ? (
          <div className="text-red-700">{process.last_error}</div>
        ) : null}
      </div>
      <Link
        to="/options#runtime-inventory"
        className="inline-flex text-xs underline"
      >
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
  tx: (
    key: string,
    vars?: Record<string, string | number | boolean | null | undefined>,
  ) => string;
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
  const state =
    process?.last_action ||
    (process?.running
      ? "running"
      : materialized
        ? "stopped"
        : "not_materialized");
  const stateClass =
    process?.last_error ||
    [
      "exited",
      "start_failed",
      "restart_failed",
      "identity_error",
      "preflight_failed",
      "reconcile_error",
    ].includes(state)
      ? "bg-red-100 text-red-800"
      : process?.running
        ? "bg-green-100 text-green-800"
        : "bg-neutral-100 text-neutral-700";
  return (
    <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-xs text-neutral-500">{tx("PSGI State")}</div>
          <div className="font-medium">
            {runtime ? psgiRuntimeLabel(runtime) : runtimeID}
          </div>
        </div>
        <span className={`rounded px-2 py-1 text-xs ${stateClass}`}>
          {tx(state)}
        </span>
      </div>
      <div className="grid gap-1 text-xs text-neutral-600">
        <div>
          {tx("PID")}: <code>{process?.pid || "-"}</code>
        </div>
        <div>
          {tx("Generated Target")}:{" "}
          <code className="break-all">
            {process?.generated_target || materialized?.generated_target || "-"}
          </code>
        </div>
        {process?.last_error ? (
          <div className="text-red-700">{process.last_error}</div>
        ) : null}
      </div>
      <Link
        to="/options#psgi-runtime-inventory"
        className="inline-flex text-xs underline"
      >
        {tx("Open Runtime")}
      </Link>
    </div>
  );
}

function DaemonStateSummary({
  tx,
  app,
  process,
  readOnly,
  saving,
  onAction,
  onViewLog,
  logLoading,
}: {
  tx: (
    key: string,
    vars?: Record<string, string | number | boolean | null | undefined>,
  ) => string;
  app: RuntimeAppFormState;
  process?: DaemonRuntimeProcessStatus;
  readOnly: boolean;
  saving: boolean;
  onAction: (action: "up" | "down" | "reload") => void;
  onViewLog: () => void;
  logLoading: boolean;
}) {
  const state =
    process?.last_action ||
    (process?.running ? "running" : app.enabled ? "stopped" : "disabled");
  const stateClass =
    process?.last_error ||
    [
      "exited",
      "start_failed",
      "restart_failed",
      "identity_error",
      "preflight_failed",
      "restart_limited",
    ].includes(state)
      ? "bg-red-100 text-red-800"
      : process?.running
        ? "bg-green-100 text-green-800"
        : state === "disabled"
          ? "bg-neutral-100 text-neutral-700"
          : "bg-amber-100 text-amber-900";

  return (
    <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-xs text-neutral-500">{tx("Daemon State")}</div>
          <div className="font-mono text-xs">{app.command || "-"}</div>
        </div>
        <span className={`rounded px-2 py-1 text-xs ${stateClass}`}>
          {tx(state)}
        </span>
      </div>
      <div className="grid gap-1 text-xs text-neutral-600">
        <div>
          {tx("PID")}: <code>{process?.pid || "-"}</code>
        </div>
        <div>
          {tx("Process ID")}:{" "}
          <code>{process?.process_id || app.name || "-"}</code>
        </div>
        <div>
          {tx("Log file")}:{" "}
          <code className="break-all">{process?.log_file || "-"}</code>
        </div>
        {process?.last_error ? (
          <div className="text-red-700">{process.last_error}</div>
        ) : null}
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => onAction("up")}
          disabled={readOnly || saving || process?.running === true}
        >
          {tx("Start")}
        </button>
        <button
          type="button"
          onClick={() => onAction("reload")}
          disabled={readOnly || saving}
        >
          {tx("Restart")}
        </button>
        <button
          type="button"
          onClick={() => onAction("down")}
          disabled={readOnly || saving || process?.running !== true}
        >
          {tx("Stop")}
        </button>
        <button
          type="button"
          onClick={onViewLog}
          disabled={saving || logLoading || !process?.log_file}
        >
          {logLoading ? tx("Loading...") : tx("View log")}
        </button>
      </div>
    </div>
  );
}
