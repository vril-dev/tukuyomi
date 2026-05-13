export type RuntimeAppMode = "static" | "php-fpm" | "psgi" | "daemon";
export type RewriteFlag = "break" | "last" | "redirect" | "permanent";

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

export type RuntimeAppEntry = {
  name: string;
  mode: RuntimeAppMode;
  hostname: string;
  listen_port: number;
  document_root: string;
  max_request_body_bytes?: number;
  php_fpm_pool_settings?: string;
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

type RuntimeAppsConfigResponse = {
  runtime_apps?: {
    vhosts?: RuntimeAppEntry[];
  };
};

let runtimeAppFormIDSequence = 0;

function nextRuntimeAppFormID(prefix: string) {
  runtimeAppFormIDSequence += 1;
  return `${prefix}-${runtimeAppFormIDSequence}`;
}

export type RuntimeAppRewriteRuleFormState = {
  formID: string;
  pattern: string;
  replacement: string;
  flag: RewriteFlag;
  preserveQuery: boolean;
};

export type RuntimeAppAccessRuleFormState = {
  formID: string;
  pathPattern: string;
  action: "allow" | "deny";
  cidrsText: string;
  authRealm: string;
  authUsersText: string;
};

export type RuntimeAppFormState = {
  formID: string;
  name: string;
  mode: RuntimeAppMode;
  hostname: string;
  listenPort: string;
  documentRoot: string;
  maxRequestBodyBytes: string;
  phpPoolSettingsText: string;
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

export const DEFAULT_RUNTIME_APP_MAX_REQUEST_BODY_BYTES = "67108864";
export const MAX_RUNTIME_APP_MAX_REQUEST_BODY_BYTES = 2147483648;

export function createEmptyRewriteRule(): RuntimeAppRewriteRuleFormState {
  return {
    formID: nextRuntimeAppFormID("rewrite-rule"),
    pattern: "",
    replacement: "",
    flag: "break",
    preserveQuery: false,
  };
}

export function createEmptyAccessRule(): RuntimeAppAccessRuleFormState {
  return {
    formID: nextRuntimeAppFormID("access-rule"),
    pathPattern: "/",
    action: "allow",
    cidrsText: "",
    authRealm: "",
    authUsersText: "",
  };
}

export function createEmptyRuntimeApp(index: number): RuntimeAppFormState {
  return {
    formID: nextRuntimeAppFormID("runtime-app"),
    name: `app-${index}`,
    mode: "php-fpm",
    hostname: "127.0.0.1",
    listenPort: String(9400 + index),
    documentRoot: "",
    maxRequestBodyBytes: DEFAULT_RUNTIME_APP_MAX_REQUEST_BODY_BYTES,
    phpPoolSettingsText: "",
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

export function parseRuntimeAppsResponse(
  data?: RuntimeAppsConfigResponse,
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
    phpPoolSettingsText:
      app.mode === "php-fpm" ? app.php_fpm_pool_settings || "" : "",
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

export function runtimeAppsToRaw(vhosts: RuntimeAppFormState[]) {
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
      ...(app.mode === "php-fpm" && app.phpPoolSettingsText.trim()
        ? { php_fpm_pool_settings: app.phpPoolSettingsText.trim() }
        : {}),
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

export function comparableRuntimeAppRaw(raw: string) {
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

export function validateRuntimeAppsForUI(
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
