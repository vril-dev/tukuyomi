import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { apiDeleteJson, apiGetJson, apiPostFormData, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";

type PHPRuntimeRecord = {
  runtime_id: string;
  display_name: string;
  detected_version?: string;
  binary_path: string;
  cli_binary_path?: string;
  modules?: string[];
  default_disabled_modules?: string[];
  available?: boolean;
  availability_message?: string;
  run_user?: string;
  run_group?: string;
};

type PHPRuntimeInventory = {
  runtimes?: PHPRuntimeRecord[];
};

type PHPRuntimeMaterializedStatus = {
  runtime_id: string;
  generated_targets?: string[];
  document_roots?: string[];
  config_file?: string;
  pool_files?: string[];
  runtime_dir?: string;
};

type PHPRuntimeProcessStatus = {
  runtime_id: string;
  running: boolean;
  pid?: number;
  last_error?: string;
  last_action?: string;
  started_at?: string;
  stopped_at?: string;
  configured_user?: string;
  configured_group?: string;
  effective_user?: string;
  effective_group?: string;
  effective_uid?: number;
  effective_gid?: number;
  config_file?: string;
  generated_targets?: string[];
};

type PHPRuntimesResponse = {
  etag?: string;
  runtimes?: PHPRuntimeInventory;
  materialized?: PHPRuntimeMaterializedStatus[];
  processes?: PHPRuntimeProcessStatus[];
};

type PHPRuntimeActionResponse = {
  ok?: boolean;
  runtime_id?: string;
  processes?: PHPRuntimeProcessStatus[];
};

type PSGIRuntimeRecord = {
  runtime_id: string;
  display_name: string;
  detected_version?: string;
  perl_path: string;
  starman_path: string;
  modules?: string[];
  available?: boolean;
  availability_message?: string;
  run_user?: string;
  run_group?: string;
};

type PSGIRuntimeInventory = {
  runtimes?: PSGIRuntimeRecord[];
};

type PSGIRuntimeMaterializedStatus = {
  process_id: string;
  vhost_name: string;
  runtime_id: string;
  app_root?: string;
  psgi_file?: string;
  listen_port?: number;
  workers?: number;
  max_requests?: number;
  generated_target?: string;
};

type PSGIRuntimeProcessStatus = {
  process_id: string;
  vhost_name: string;
  runtime_id: string;
  running: boolean;
  pid?: number;
  last_error?: string;
  last_action?: string;
  started_at?: string;
  stopped_at?: string;
  effective_user?: string;
  effective_group?: string;
  generated_target?: string;
};

type PSGIRuntimesResponse = {
  etag?: string;
  runtimes?: PSGIRuntimeInventory;
  materialized?: PSGIRuntimeMaterializedStatus[];
  processes?: PSGIRuntimeProcessStatus[];
};

type PSGIProcessActionResponse = {
  ok?: boolean;
  vhost_name?: string;
  processes?: PSGIRuntimeProcessStatus[];
};

type RequestCountryDBStatus = {
  managed_path?: string;
  config_etag?: string;
  configured_mode?: string;
  effective_mode?: string;
  installed?: boolean;
  loaded?: boolean;
  size_bytes?: number;
  mod_time?: string;
  last_error?: string;
};

type RequestCountryUpdateStatus = {
  managed_config_path?: string;
  config_installed?: boolean;
  config_size_bytes?: number;
  config_mod_time?: string;
  edition_ids?: string[];
  supported_country_edition?: string;
  updater_available?: boolean;
  updater_path?: string;
  last_attempt?: string;
  last_success?: string;
  last_result?: string;
  last_error?: string;
};

type EdgeModeConfig = {
  enabled?: boolean;
  require_device_approval?: boolean;
  device_auth?: {
    enabled?: boolean;
    status_refresh_interval_sec?: number;
  };
};

type RemoteSSHCenterConfig = {
  enabled?: boolean;
  max_ttl_sec?: number;
  idle_timeout_sec?: number;
  max_sessions_total?: number;
  max_sessions_per_device?: number;
};

type RemoteSSHGatewayConfig = {
  enabled?: boolean;
  center_signing_public_key?: string;
  center_tls_ca_bundle_file?: string;
  center_tls_server_name?: string;
  embedded_server?: {
    enabled?: boolean;
    shell?: string;
    working_dir?: string;
    run_as_user?: string;
  };
};

type RemoteSSHConfig = {
  center?: RemoteSSHCenterConfig;
  gateway?: RemoteSSHGatewayConfig;
};

type EdgeSettingsConfig = Record<string, unknown> & {
  edge?: EdgeModeConfig;
  remote_ssh?: RemoteSSHConfig;
};

type EdgeSettingsResponse = {
  etag?: string;
  restart_required?: boolean;
  config?: EdgeSettingsConfig;
  runtime?: {
    edge_enabled?: boolean;
    edge_device_auth_enabled?: boolean;
    edge_device_status_refresh_interval_sec?: number;
    remote_ssh_center_enabled?: boolean;
    remote_ssh_gateway_enabled?: boolean;
    remote_ssh_gateway_embedded_enabled?: boolean;
  };
};

type RemoteSSHGatewaySigningKeyRefreshResponse = {
  center_signing_public_key?: string;
  algorithm?: string;
};

type EdgeDeviceAuthStatus = {
  store_available?: boolean;
  edge_enabled?: boolean;
  device_auth_enabled?: boolean;
  require_device_approval?: boolean;
  proxy_locked?: boolean;
  proxy_lock_reason?: string;
  identity_configured?: boolean;
  device_id?: string;
  key_id?: string;
  public_key_fingerprint_sha256?: string;
  enrollment_status?: string;
  center_url?: string;
  center_product_id?: string;
  center_status_checked_at_unix?: number;
  center_status_error?: string;
  last_enrollment_at_unix?: number;
  last_enrollment_error?: string;
};

function runtimeDisplayName(runtime: PHPRuntimeRecord) {
  return runtime.display_name || runtime.detected_version || runtime.runtime_id;
}

function psgiRuntimeDisplayName(runtime: PSGIRuntimeRecord) {
  return runtime.display_name || runtime.detected_version || runtime.runtime_id;
}

function formatUnixTimestamp(value: number | undefined, locale: "en" | "ja") {
  if (!value) {
    return "-";
  }
  const date = new Date(value * 1000);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return date.toLocaleString(locale === "ja" ? "ja-JP" : "en-US");
}

function edgeStatusRefreshIntervalFromConfig(config: EdgeSettingsConfig | null | undefined) {
  const raw = config?.edge?.device_auth?.status_refresh_interval_sec;
  return Number.isFinite(raw) && raw !== undefined && raw >= 0 ? String(Math.trunc(raw)) : "30";
}

function normalizeEdgeStatusRefreshInterval(value: string) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return 30;
  }
  return Math.min(parsed, 3600);
}

type RemoteSSHGatewayForm = {
  enabled: boolean;
  centerSigningPublicKey: string;
  centerTLSCABundleFile: string;
  centerTLSServerName: string;
  shell: string;
  workingDir: string;
  runAsUser: string;
};

function defaultRemoteSSHGatewayForm(): RemoteSSHGatewayForm {
  return {
    enabled: false,
    centerSigningPublicKey: "",
    centerTLSCABundleFile: "",
    centerTLSServerName: "",
    shell: "/bin/sh",
    workingDir: "/",
    runAsUser: "",
  };
}

function remoteSSHGatewayFormFromConfig(config: EdgeSettingsConfig | null | undefined): RemoteSSHGatewayForm {
  const gateway = config?.remote_ssh?.gateway;
  const embedded = gateway?.embedded_server;
  return {
    enabled: gateway?.enabled === true && embedded?.enabled === true,
    centerSigningPublicKey: gateway?.center_signing_public_key ?? "",
    centerTLSCABundleFile: gateway?.center_tls_ca_bundle_file ?? "",
    centerTLSServerName: gateway?.center_tls_server_name ?? "",
    shell: embedded?.shell || "/bin/sh",
    workingDir: embedded?.working_dir || "/",
    runAsUser: embedded?.run_as_user ?? "",
  };
}

function trimRemoteSSHGatewayForm(form: RemoteSSHGatewayForm): RemoteSSHGatewayForm {
  return {
    enabled: form.enabled,
    centerSigningPublicKey: form.centerSigningPublicKey.trim(),
    centerTLSCABundleFile: form.centerTLSCABundleFile.trim(),
    centerTLSServerName: form.centerTLSServerName.trim(),
    shell: form.shell.trim() || "/bin/sh",
    workingDir: form.workingDir.trim() || "/",
    runAsUser: form.runAsUser.trim(),
  };
}

function remoteSSHGatewayFormChanged(config: EdgeSettingsConfig | null | undefined, form: RemoteSSHGatewayForm) {
  const current = trimRemoteSSHGatewayForm(remoteSSHGatewayFormFromConfig(config));
  const next = trimRemoteSSHGatewayForm(form);
  return JSON.stringify(current) !== JSON.stringify(next);
}

function buildRemoteSSHConfig(current: RemoteSSHConfig | undefined, form: RemoteSSHGatewayForm): RemoteSSHConfig {
  const normalized = trimRemoteSSHGatewayForm(form);
  return {
    center: {
      enabled: current?.center?.enabled === true,
      max_ttl_sec: current?.center?.max_ttl_sec ?? 900,
      idle_timeout_sec: current?.center?.idle_timeout_sec ?? 300,
      max_sessions_total: current?.center?.max_sessions_total ?? 16,
      max_sessions_per_device: current?.center?.max_sessions_per_device ?? 1,
    },
    gateway: {
      ...(current?.gateway ?? {}),
      enabled: normalized.enabled,
      center_signing_public_key: normalized.centerSigningPublicKey,
      center_tls_ca_bundle_file: normalized.centerTLSCABundleFile,
      center_tls_server_name: normalized.centerTLSServerName,
      embedded_server: {
        ...(current?.gateway?.embedded_server ?? {}),
        enabled: normalized.enabled,
        shell: normalized.shell,
        working_dir: normalized.workingDir,
        run_as_user: normalized.runAsUser,
      },
    },
  };
}

function remoteSSHGatewayFormValidationError(form: RemoteSSHGatewayForm, edgeEnabled: boolean) {
  const normalized = trimRemoteSSHGatewayForm(form);
  if (normalized.enabled && !edgeEnabled) {
    return "Enable IoT / Edge mode first, save, and restart before enabling Remote SSH.";
  }
  if (normalized.enabled && (!normalized.shell.startsWith("/") || normalized.shell === "/")) {
    return "Shell path must be an absolute executable path such as /bin/sh.";
  }
  if (normalized.enabled && !normalized.workingDir.startsWith("/")) {
    return "Working directory must be an absolute path.";
  }
  return "";
}

function processActionLabel(process: PHPRuntimeProcessStatus | undefined, materialized: boolean) {
  if (process?.last_action) {
    return process.last_action;
  }
  if (process?.running) {
    return "running";
  }
  return materialized ? "stopped" : "not_materialized";
}

function processBadgeClass(process: PHPRuntimeProcessStatus | undefined, materialized: boolean) {
  const action = processActionLabel(process, materialized);
  if (process?.last_error || ["exited", "start_failed", "restart_failed", "identity_error", "preflight_failed", "reconcile_error"].includes(action)) {
    return "bg-red-100 text-red-800";
  }
  if (process?.running) {
    return "bg-green-100 text-green-800";
  }
  if (action === "manual_stopped") {
    return "bg-amber-100 text-amber-900";
  }
  return "bg-neutral-100 text-neutral-700";
}

function runtimeIdentity(process: PHPRuntimeProcessStatus | undefined, runtime: PHPRuntimeRecord) {
  return [process?.effective_user || runtime.run_user, process?.effective_group || runtime.run_group].filter(Boolean).join(":") || "-";
}

type RuntimeModuleListProps = {
  modules?: string[];
  defaultDisabledModules?: string[];
  availabilityMessage?: string;
  tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
};

function RuntimeModuleList({ modules = [], defaultDisabledModules = [], availabilityMessage, tx }: RuntimeModuleListProps) {
  const defaultDisabled = useMemo(() => new Set(defaultDisabledModules), [defaultDisabledModules]);
  const defaultOffCount = modules.filter((module) => defaultDisabled.has(module)).length;

  if (modules.length === 0) {
    return (
      <div className="space-y-2">
        <div className="text-xs text-neutral-500">{tx("Modules")}</div>
        <div className="rounded border border-dashed border-neutral-200 px-3 py-2 text-xs text-neutral-500">
          {availabilityMessage || tx("No built modules detected.")}
        </div>
      </div>
    );
  }

  return (
    <details className="rounded border border-neutral-200 bg-neutral-50/40">
      <summary className="cursor-pointer select-none px-3 py-2 text-xs text-neutral-600">
        <span className="font-semibold text-neutral-700">{tx("Modules")}</span>
        <span className="ml-2">{tx("{count} installed", { count: modules.length })}</span>
        {defaultOffCount > 0 ? <span className="ml-2 text-amber-800">{tx("{count} default off", { count: defaultOffCount })}</span> : null}
      </summary>
      <div className="border-t border-neutral-200 p-3">
        <div className="max-h-52 overflow-y-auto pr-1">
          <div className="flex flex-wrap gap-2">
            {modules.map((module) => {
              const defaultOff = defaultDisabled.has(module);
              return (
                <span
                  key={module}
                  className={`rounded-full border px-2 py-1 text-xs ${defaultOff ? "border-amber-200 bg-amber-50 text-amber-900" : "bg-white text-neutral-700"}`}
                >
                  {module}
                  {defaultOff ? ` · ${tx("default off")}` : ""}
                </span>
              );
            })}
          </div>
        </div>
      </div>
    </details>
  );
}

export default function OptionsPanel() {
  const { locale, tx } = useI18n();
  const [runtimes, setRuntimes] = useState<PHPRuntimeRecord[]>([]);
  const [materialized, setMaterialized] = useState<PHPRuntimeMaterializedStatus[]>([]);
  const [processes, setProcesses] = useState<PHPRuntimeProcessStatus[]>([]);
  const [psgiRuntimes, setPSGIRuntimes] = useState<PSGIRuntimeRecord[]>([]);
  const [psgiMaterialized, setPSGIMaterialized] = useState<PSGIRuntimeMaterializedStatus[]>([]);
  const [psgiProcesses, setPSGIProcesses] = useState<PSGIRuntimeProcessStatus[]>([]);
  const [requestCountryDB, setRequestCountryDB] = useState<RequestCountryDBStatus | null>(null);
  const [requestCountryUpdate, setRequestCountryUpdate] = useState<RequestCountryUpdateStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [dbNotice, setDBNotice] = useState("");
  const [dbError, setDBError] = useState("");
  const [dbUploading, setDBUploading] = useState(false);
  const [dbRemoving, setDBRemoving] = useState(false);
  const [selectedCountryDB, setSelectedCountryDB] = useState<File | null>(null);
  const [countryMode, setCountryMode] = useState("header");
  const [modeSaving, setModeSaving] = useState(false);
  const [modeNotice, setModeNotice] = useState("");
  const [modeError, setModeError] = useState("");
  const [updateNotice, setUpdateNotice] = useState("");
  const [updateError, setUpdateError] = useState("");
  const [configUploading, setConfigUploading] = useState(false);
  const [configRemoving, setConfigRemoving] = useState(false);
  const [updatingNow, setUpdatingNow] = useState(false);
  const [selectedCountryConfig, setSelectedCountryConfig] = useState<File | null>(null);
  const [runtimeNotice, setRuntimeNotice] = useState("");
  const [runtimeError, setRuntimeError] = useState("");
  const [runtimeAction, setRuntimeAction] = useState<{ runtimeID: string; action: "up" | "down" | "reload" } | null>(null);
  const [psgiAction, setPSGIAction] = useState<{ appName: string; action: "up" | "down" | "reload" } | null>(null);
  const [edgeSettings, setEdgeSettings] = useState<EdgeSettingsConfig | null>(null);
  const [edgeETag, setEdgeETag] = useState("");
  const [edgeEnabled, setEdgeEnabled] = useState(false);
  const [edgeRuntimeEnabled, setEdgeRuntimeEnabled] = useState(false);
  const [edgeStatusRefreshIntervalSec, setEdgeStatusRefreshIntervalSec] = useState("30");
  const [edgeSaving, setEdgeSaving] = useState(false);
  const [edgeNotice, setEdgeNotice] = useState("");
  const [edgeError, setEdgeError] = useState("");
  const [remoteSSHGatewayForm, setRemoteSSHGatewayForm] = useState<RemoteSSHGatewayForm>(() => defaultRemoteSSHGatewayForm());
  const [remoteSSHRuntimeEmbeddedEnabled, setRemoteSSHRuntimeEmbeddedEnabled] = useState(false);
  const [remoteSSHSaving, setRemoteSSHSaving] = useState(false);
  const [remoteSSHSigningKeyRefreshing, setRemoteSSHSigningKeyRefreshing] = useState(false);
  const [remoteSSHNotice, setRemoteSSHNotice] = useState("");
  const [remoteSSHError, setRemoteSSHError] = useState("");
  const [edgeDeviceStatus, setEdgeDeviceStatus] = useState<EdgeDeviceAuthStatus | null>(null);
  const [edgeEnrollForm, setEdgeEnrollForm] = useState({
    centerURL: "",
    enrollmentToken: "",
    deviceID: "",
    keyID: "default",
  });
  const [edgeEnrollSaving, setEdgeEnrollSaving] = useState(false);
  const [edgeStatusRefreshSaving, setEdgeStatusRefreshSaving] = useState(false);
  const [edgeEnrollNotice, setEdgeEnrollNotice] = useState("");
  const [edgeEnrollError, setEdgeEnrollError] = useState("");
  const { readOnly } = useAdminRuntime();

  const availableRuntimeCount = useMemo(
    () => runtimes.filter((runtime) => runtime.available === true).length,
    [runtimes],
  );
  const materializedMap = useMemo(
    () => new Map(materialized.map((entry) => [entry.runtime_id, entry])),
    [materialized],
  );
  const processMap = useMemo(
    () => new Map(processes.map((entry) => [entry.runtime_id, entry])),
    [processes],
  );
  const psgiAvailableRuntimeCount = useMemo(
    () => psgiRuntimes.filter((runtime) => runtime.available === true).length,
    [psgiRuntimes],
  );
  const psgiProcessMap = useMemo(
    () => new Map(psgiProcesses.map((entry) => [entry.vhost_name, entry])),
    [psgiProcesses],
  );

  const applyRuntimeState = useCallback((data: PHPRuntimesResponse, psgiData: PSGIRuntimesResponse) => {
    setRuntimes(Array.isArray(data.runtimes?.runtimes) ? data.runtimes.runtimes : []);
    setMaterialized(Array.isArray(data.materialized) ? data.materialized : []);
    setProcesses(Array.isArray(data.processes) ? data.processes : []);
    setPSGIRuntimes(Array.isArray(psgiData.runtimes?.runtimes) ? psgiData.runtimes.runtimes : []);
    setPSGIMaterialized(Array.isArray(psgiData.materialized) ? psgiData.materialized : []);
    setPSGIProcesses(Array.isArray(psgiData.processes) ? psgiData.processes : []);
  }, []);

  const refreshRuntimeState = useCallback(async () => {
    const [data, psgiData, edgeAuthStatus] = await Promise.all([
      apiGetJson<PHPRuntimesResponse>("/php-runtimes"),
      apiGetJson<PSGIRuntimesResponse>("/psgi-runtimes"),
      apiGetJson<EdgeDeviceAuthStatus>("/edge/device-auth"),
    ]);
    applyRuntimeState(data, psgiData);
    setEdgeDeviceStatus(edgeAuthStatus);
  }, [applyRuntimeState]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [data, psgiData, countryDB, countryUpdate, settings, edgeAuthStatus] = await Promise.all([
        apiGetJson<PHPRuntimesResponse>("/php-runtimes"),
        apiGetJson<PSGIRuntimesResponse>("/psgi-runtimes"),
        apiGetJson<RequestCountryDBStatus>("/request-country-db"),
        apiGetJson<RequestCountryUpdateStatus>("/request-country-update"),
        apiGetJson<EdgeSettingsResponse>("/settings/listener-admin"),
        apiGetJson<EdgeDeviceAuthStatus>("/edge/device-auth"),
      ]);
      applyRuntimeState(data, psgiData);
      setRequestCountryDB(countryDB);
      setRequestCountryUpdate(countryUpdate);
      setEdgeSettings(settings.config ?? null);
      setEdgeETag(settings.etag ?? "");
      setEdgeEnabled(settings.config?.edge?.enabled === true);
      setEdgeRuntimeEnabled(settings.runtime?.edge_enabled === true);
      setEdgeStatusRefreshIntervalSec(edgeStatusRefreshIntervalFromConfig(settings.config));
      setRemoteSSHGatewayForm(remoteSSHGatewayFormFromConfig(settings.config));
      setRemoteSSHRuntimeEmbeddedEnabled(settings.runtime?.remote_ssh_gateway_embedded_enabled === true);
      setEdgeDeviceStatus(edgeAuthStatus);
      setEdgeEnrollForm((current) => ({
        centerURL: current.centerURL || edgeAuthStatus.center_url || "",
        enrollmentToken: "",
        deviceID: current.deviceID || edgeAuthStatus.device_id || "",
        keyID: current.keyID || edgeAuthStatus.key_id || "default",
      }));
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

  useEffect(() => {
    setCountryMode(requestCountryDB?.configured_mode || "header");
  }, [requestCountryDB?.configured_mode]);

  async function onUploadCountryDB() {
    if (!selectedCountryDB) return;
    setDBUploading(true);
    setDBError("");
    setDBNotice("");
    try {
      const form = new FormData();
      form.append("file", selectedCountryDB);
      const next = await apiPostFormData<RequestCountryDBStatus>("/request-country-db/upload", form);
      setRequestCountryDB(next);
      setSelectedCountryDB(null);
      setDBNotice(tx("Country DB uploaded."));
    } catch (err: unknown) {
      setDBError(err instanceof Error ? err.message : String(err));
    } finally {
      setDBUploading(false);
    }
  }

  async function onRemoveCountryDB() {
    setDBRemoving(true);
    setDBError("");
    setDBNotice("");
    try {
      const next = await apiDeleteJson<RequestCountryDBStatus>("/request-country-db");
      setRequestCountryDB(next);
      setDBNotice(tx("Country DB removed."));
    } catch (err: unknown) {
      setDBError(err instanceof Error ? err.message : String(err));
    } finally {
      setDBRemoving(false);
    }
  }

  async function onUploadCountryConfig() {
    if (!selectedCountryConfig) return;
    setConfigUploading(true);
    setUpdateError("");
    setUpdateNotice("");
    try {
      const form = new FormData();
      form.append("file", selectedCountryConfig);
      const next = await apiPostFormData<RequestCountryUpdateStatus>("/request-country-update/config/upload", form);
      setRequestCountryUpdate(next);
      setSelectedCountryConfig(null);
      setUpdateNotice(tx("GeoIP.conf uploaded."));
    } catch (err: unknown) {
      setUpdateError(err instanceof Error ? err.message : String(err));
    } finally {
      setConfigUploading(false);
    }
  }

  async function onRemoveCountryConfig() {
    setConfigRemoving(true);
    setUpdateError("");
    setUpdateNotice("");
    try {
      const next = await apiDeleteJson<RequestCountryUpdateStatus>("/request-country-update/config");
      setRequestCountryUpdate(next);
      setUpdateNotice(tx("GeoIP.conf removed."));
    } catch (err: unknown) {
      setUpdateError(err instanceof Error ? err.message : String(err));
    } finally {
      setConfigRemoving(false);
    }
  }

  async function onRunCountryUpdate() {
    const previousAttempt = requestCountryUpdate?.last_attempt || "";
    setUpdatingNow(true);
    setUpdateError("");
    setUpdateNotice("");
    try {
      const next = await apiPostJson<RequestCountryUpdateStatus>("/request-country-update/run", {});
      setRequestCountryUpdate(next);
      const db = await apiGetJson<RequestCountryDBStatus>("/request-country-db");
      setRequestCountryDB(db);
      setUpdateNotice(tx("Country DB update completed."));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      try {
        const next = await apiGetJson<RequestCountryUpdateStatus>("/request-country-update");
        setRequestCountryUpdate(next);
        if (next.last_result === "success" && next.last_attempt && next.last_attempt !== previousAttempt && !next.last_error) {
          try {
            const db = await apiGetJson<RequestCountryDBStatus>("/request-country-db");
            setRequestCountryDB(db);
          } catch {
            //
          }
          setUpdateNotice(tx("Country DB update completed."));
          setUpdateError("");
          return;
        }
        setUpdateError(next.last_error || message);
      } catch {
        setUpdateError(message);
      }
    } finally {
      setUpdatingNow(false);
    }
  }

  async function onSaveCountryMode() {
    if (!requestCountryDB?.config_etag) return;
    setModeSaving(true);
    setModeNotice("");
    setModeError("");
    try {
      const next = await apiPutJson<RequestCountryDBStatus>(
        "/request-country-mode",
        { mode: countryMode },
        { headers: { "If-Match": requestCountryDB.config_etag } },
      );
      setRequestCountryDB(next);
      setModeNotice(tx("Country resolution mode saved. Restart the process to apply the new mode."));
    } catch (err: unknown) {
      setModeError(err instanceof Error ? err.message : String(err));
      try {
        const next = await apiGetJson<RequestCountryDBStatus>("/request-country-db");
        setRequestCountryDB(next);
      } catch {
        //
      }
    } finally {
      setModeSaving(false);
    }
  }

  async function onSaveEdgeMode() {
    if (!edgeSettings || !edgeETag) return;
    setEdgeSaving(true);
    setEdgeNotice("");
    setEdgeError("");
    try {
      const nextConfig: EdgeSettingsConfig = {
        ...edgeSettings,
        edge: {
          ...(edgeSettings.edge ?? {}),
          enabled: edgeEnabled,
          require_device_approval: edgeSettings.edge?.require_device_approval !== false,
          device_auth: {
            enabled: edgeSettings.edge?.device_auth?.enabled !== false,
            status_refresh_interval_sec: normalizeEdgeStatusRefreshInterval(edgeStatusRefreshIntervalSec),
          },
        },
      };
      const next = await apiPutJson<EdgeSettingsResponse>(
        "/settings/listener-admin",
        { config: nextConfig },
        { headers: { "If-Match": edgeETag } },
      );
      setEdgeSettings(next.config ?? nextConfig);
      setEdgeETag(next.etag ?? "");
      setEdgeEnabled(next.config?.edge?.enabled === true);
      setEdgeRuntimeEnabled(next.runtime?.edge_enabled === true);
      setEdgeStatusRefreshIntervalSec(edgeStatusRefreshIntervalFromConfig(next.config ?? nextConfig));
      setRemoteSSHGatewayForm(remoteSSHGatewayFormFromConfig(next.config ?? nextConfig));
      setRemoteSSHRuntimeEmbeddedEnabled(next.runtime?.remote_ssh_gateway_embedded_enabled === true);
      setEdgeNotice(tx("IoT / Edge mode saved. Restart the process to apply the new mode and polling interval."));
    } catch (err: unknown) {
      setEdgeError(err instanceof Error ? err.message : String(err));
      try {
        const current = await apiGetJson<EdgeSettingsResponse>("/settings/listener-admin");
        setEdgeSettings(current.config ?? null);
        setEdgeETag(current.etag ?? "");
        setEdgeEnabled(current.config?.edge?.enabled === true);
        setEdgeRuntimeEnabled(current.runtime?.edge_enabled === true);
        setEdgeStatusRefreshIntervalSec(edgeStatusRefreshIntervalFromConfig(current.config));
        setRemoteSSHGatewayForm(remoteSSHGatewayFormFromConfig(current.config));
        setRemoteSSHRuntimeEmbeddedEnabled(current.runtime?.remote_ssh_gateway_embedded_enabled === true);
      } catch {
        //
      }
    } finally {
      setEdgeSaving(false);
    }
  }

  async function onSaveRemoteSSHGateway() {
    if (!edgeSettings || !edgeETag) return;
    const validationError = remoteSSHGatewayFormValidationError(remoteSSHGatewayForm, edgeSettings.edge?.enabled === true);
    if (validationError) {
      setRemoteSSHError(tx(validationError));
      return;
    }
    setRemoteSSHSaving(true);
    setRemoteSSHNotice("");
    setRemoteSSHError("");
    try {
      const nextConfig: EdgeSettingsConfig = {
        ...edgeSettings,
        remote_ssh: buildRemoteSSHConfig(edgeSettings.remote_ssh, remoteSSHGatewayForm),
      };
      const next = await apiPutJson<EdgeSettingsResponse>(
        "/settings/listener-admin",
        { config: nextConfig },
        { headers: { "If-Match": edgeETag } },
      );
      setEdgeSettings(next.config ?? nextConfig);
      setEdgeETag(next.etag ?? "");
      setEdgeEnabled(next.config?.edge?.enabled === true);
      setEdgeRuntimeEnabled(next.runtime?.edge_enabled === true);
      setEdgeStatusRefreshIntervalSec(edgeStatusRefreshIntervalFromConfig(next.config ?? nextConfig));
      setRemoteSSHGatewayForm(remoteSSHGatewayFormFromConfig(next.config ?? nextConfig));
      setRemoteSSHRuntimeEmbeddedEnabled(next.runtime?.remote_ssh_gateway_embedded_enabled === true);
      setRemoteSSHNotice(tx("Remote SSH Gateway settings saved. Restart tukuyomi to apply them."));
    } catch (err: unknown) {
      setRemoteSSHError(err instanceof Error ? err.message : String(err));
      try {
        const current = await apiGetJson<EdgeSettingsResponse>("/settings/listener-admin");
        setEdgeSettings(current.config ?? null);
        setEdgeETag(current.etag ?? "");
        setEdgeEnabled(current.config?.edge?.enabled === true);
        setEdgeRuntimeEnabled(current.runtime?.edge_enabled === true);
        setEdgeStatusRefreshIntervalSec(edgeStatusRefreshIntervalFromConfig(current.config));
        setRemoteSSHGatewayForm(remoteSSHGatewayFormFromConfig(current.config));
        setRemoteSSHRuntimeEmbeddedEnabled(current.runtime?.remote_ssh_gateway_embedded_enabled === true);
      } catch {
        //
      }
    } finally {
      setRemoteSSHSaving(false);
    }
  }

  async function onRefreshRemoteSSHGatewaySigningKey() {
    setRemoteSSHSigningKeyRefreshing(true);
    setRemoteSSHNotice("");
    setRemoteSSHError("");
    try {
      await apiPostJson<RemoteSSHGatewaySigningKeyRefreshResponse>("/edge/device-auth/remote-ssh/signing-key/refresh", { confirm: true });
      const current = await apiGetJson<EdgeSettingsResponse>("/settings/listener-admin");
      setEdgeSettings(current.config ?? null);
      setEdgeETag(current.etag ?? "");
      setEdgeEnabled(current.config?.edge?.enabled === true);
      setEdgeRuntimeEnabled(current.runtime?.edge_enabled === true);
      setEdgeStatusRefreshIntervalSec(edgeStatusRefreshIntervalFromConfig(current.config));
      setRemoteSSHGatewayForm(remoteSSHGatewayFormFromConfig(current.config));
      setRemoteSSHRuntimeEmbeddedEnabled(current.runtime?.remote_ssh_gateway_embedded_enabled === true);
      setRemoteSSHNotice(tx("Center signing public key refreshed from approved Center."));
    } catch (err: unknown) {
      setRemoteSSHError(err instanceof Error ? err.message : String(err));
    } finally {
      setRemoteSSHSigningKeyRefreshing(false);
    }
  }

  async function onEnrollEdgeDevice() {
    setEdgeEnrollSaving(true);
    setEdgeEnrollNotice("");
    setEdgeEnrollError("");
    try {
      const centerURL = edgeEnrollForm.centerURL.trim();
      const enrollmentToken = edgeEnrollForm.enrollmentToken.trim();
      if (!centerURL) {
        throw new Error(tx("Center URL is required."));
      }
      if (!enrollmentToken) {
        throw new Error(tx("Enrollment token is required."));
      }
      const next = await apiPostJson<EdgeDeviceAuthStatus>("/edge/device-auth/enroll", {
        center_url: centerURL,
        enrollment_token: enrollmentToken,
        device_id: edgeEnrollForm.deviceID.trim(),
        key_id: edgeEnrollForm.keyID.trim(),
      });
      setEdgeDeviceStatus(next);
      setEdgeEnrollForm((current) => ({
        ...current,
        centerURL: next.center_url || centerURL,
        enrollmentToken: "",
        deviceID: next.device_id || current.deviceID,
        keyID: next.key_id || current.keyID || "default",
      }));
      setEdgeEnrollNotice(tx("Center enrollment request sent. Approve the pending device in Center."));
    } catch (err: unknown) {
      setEdgeEnrollError(getErrorMessage(err, tx("Center enrollment request failed.")));
      try {
        const current = await apiGetJson<EdgeDeviceAuthStatus>("/edge/device-auth");
        setEdgeDeviceStatus(current);
      } catch {
        //
      }
    } finally {
      setEdgeEnrollSaving(false);
    }
  }

  async function onRefreshEdgeDeviceStatus() {
    setEdgeStatusRefreshSaving(true);
    setEdgeEnrollNotice("");
    setEdgeEnrollError("");
    try {
      const next = await apiPostJson<EdgeDeviceAuthStatus>("/edge/device-auth/refresh", {});
      setEdgeDeviceStatus(next);
      setEdgeEnrollNotice(tx("Center device status refreshed."));
    } catch (err: unknown) {
      setEdgeEnrollError(getErrorMessage(err, tx("Center device status refresh failed.")));
      try {
        const current = await apiGetJson<EdgeDeviceAuthStatus>("/edge/device-auth");
        setEdgeDeviceStatus(current);
      } catch {
        //
      }
    } finally {
      setEdgeStatusRefreshSaving(false);
    }
  }

  async function onRuntimeAction(runtimeID: string, action: "up" | "down" | "reload") {
    setRuntimeAction({ runtimeID, action });
    setRuntimeNotice("");
    setRuntimeError("");
    try {
      const next = await apiPostJson<PHPRuntimeActionResponse>(`/php-runtimes/${encodeURIComponent(runtimeID)}/${action}`, {});
      if (Array.isArray(next.processes)) {
        setProcesses(next.processes);
      } else {
        const data = await apiGetJson<PHPRuntimesResponse>("/php-runtimes");
        setProcesses(Array.isArray(data.processes) ? data.processes : []);
        setMaterialized(Array.isArray(data.materialized) ? data.materialized : []);
      }
      if (action === "up") {
        setRuntimeNotice(tx("PHP runtime {runtime} started.", { runtime: runtimeID }));
      } else if (action === "down") {
        setRuntimeNotice(tx("PHP runtime {runtime} stopped.", { runtime: runtimeID }));
      } else {
        setRuntimeNotice(tx("PHP runtime {runtime} reloaded.", { runtime: runtimeID }));
      }
    } catch (err: unknown) {
      setRuntimeError(getErrorMessage(err, tx("PHP runtime action failed.")));
      try {
        const data = await apiGetJson<PHPRuntimesResponse>("/php-runtimes");
        setProcesses(Array.isArray(data.processes) ? data.processes : []);
        setMaterialized(Array.isArray(data.materialized) ? data.materialized : []);
      } catch {
        //
      }
    } finally {
      setRuntimeAction(null);
    }
  }

  async function onPSGIAction(appName: string, action: "up" | "down" | "reload") {
    setPSGIAction({ appName, action });
    setRuntimeNotice("");
    setRuntimeError("");
    try {
      const next = await apiPostJson<PSGIProcessActionResponse>(`/psgi-processes/${encodeURIComponent(appName)}/${action}`, {});
      if (Array.isArray(next.processes)) {
        setPSGIProcesses(next.processes);
      } else {
        const data = await apiGetJson<PSGIRuntimesResponse>("/psgi-runtimes");
        setPSGIProcesses(Array.isArray(data.processes) ? data.processes : []);
        setPSGIMaterialized(Array.isArray(data.materialized) ? data.materialized : []);
      }
      if (action === "up") {
        setRuntimeNotice(tx("PSGI process {runtime} started.", { runtime: appName }));
      } else if (action === "down") {
        setRuntimeNotice(tx("PSGI process {runtime} stopped.", { runtime: appName }));
      } else {
        setRuntimeNotice(tx("PSGI process {runtime} reloaded.", { runtime: appName }));
      }
    } catch (err: unknown) {
      setRuntimeError(getErrorMessage(err, tx("PSGI process action failed.")));
      try {
        const data = await apiGetJson<PSGIRuntimesResponse>("/psgi-runtimes");
        setPSGIProcesses(Array.isArray(data.processes) ? data.processes : []);
        setPSGIMaterialized(Array.isArray(data.materialized) ? data.materialized : []);
      } catch {
        //
      }
    } finally {
      setPSGIAction(null);
    }
  }

  if (loading) {
    return <div className="w-full p-4 text-neutral-500">{tx("Loading options...")}</div>;
  }

  const edgeEnrollmentStatus = (edgeDeviceStatus?.enrollment_status || "").toLowerCase();
  const edgeReapprovalStatuses = new Set(["revoked", "archived", "failed", "product_changed"]);
  const edgeRequestableStatuses = new Set(["", "unconfigured", "local", "failed", "revoked", "archived", "product_changed"]);
  const edgeNeedsReapproval = edgeDeviceStatus?.identity_configured === true && edgeReapprovalStatuses.has(edgeEnrollmentStatus);
  const edgeCanRequestApproval =
    edgeDeviceStatus?.identity_configured === true ? edgeRequestableStatuses.has(edgeEnrollmentStatus) : edgeDeviceStatus?.identity_configured !== undefined;
  const edgeEnrollButtonText = edgeNeedsReapproval ? tx("Request re-approval") : tx("Request Center approval");
  const remoteSSHGatewayBusy = remoteSSHSaving || remoteSSHSigningKeyRefreshing;
  const remoteSSHValidationError = remoteSSHGatewayFormValidationError(remoteSSHGatewayForm, edgeSettings?.edge?.enabled === true);
  const remoteSSHSaveDisabled =
    readOnly ||
    remoteSSHGatewayBusy ||
    !edgeSettings ||
    !edgeETag ||
    !remoteSSHGatewayFormChanged(edgeSettings, remoteSSHGatewayForm) ||
    remoteSSHValidationError !== "";

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Options")}</h1>
          <p className="text-xs text-neutral-500">{tx("Review built runtime inventory, module baselines, readiness, and process state from one place.")}</p>
        </div>
      </header>

      <div className="rounded-xl border border-neutral-200 p-4 space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold">{tx("IoT / Edge Mode")}</h2>
            <p className="text-xs text-neutral-500">
              {tx("Use this parent switch only for IoT deployments. Web/VPS deployments should leave edge mode off.")}
            </p>
          </div>
          <span className={`rounded px-2 py-1 text-xs ${edgeRuntimeEnabled ? "bg-green-100 text-green-800" : "bg-neutral-100 text-neutral-700"}`}>
            {edgeRuntimeEnabled ? tx("IoT ON") : tx("IoT OFF")}
          </span>
        </div>
        <div className="grid gap-3 md:grid-cols-[minmax(220px,260px)_minmax(220px,260px)_auto]">
          <div className="grid grid-rows-[16px_36px_16px] gap-1">
            <span aria-hidden="true" />
            <label className="flex h-9 items-center gap-2 rounded border border-neutral-200 bg-white px-3 text-xs text-neutral-700">
              <input
                type="checkbox"
                checked={edgeEnabled}
                onChange={(e) => setEdgeEnabled(e.target.checked)}
                disabled={readOnly || edgeSaving || !edgeSettings || !edgeETag}
              />
              {tx("Enable IoT / Edge mode")}
            </label>
            <span aria-hidden="true" />
          </div>
          <label className="grid grid-rows-[16px_36px_16px] gap-1 text-xs">
            <span className="text-xs font-semibold leading-4">{tx("Center status poll interval seconds")}</span>
            <input
              className="h-9"
              type="number"
              min={0}
              max={3600}
              value={edgeStatusRefreshIntervalSec}
              onChange={(e) => setEdgeStatusRefreshIntervalSec(e.target.value)}
              disabled={readOnly || edgeSaving || !edgeSettings || !edgeETag}
            />
            <span className="text-xs leading-4 text-neutral-500">{tx("0 disables automatic Center status polling.")}</span>
          </label>
          <div className="grid grid-rows-[16px_36px_16px] gap-1 md:w-28">
            <span aria-hidden="true" />
            <button
              className="h-9"
              type="button"
              onClick={() => void onSaveEdgeMode()}
              disabled={
                readOnly ||
                edgeSaving ||
                !edgeSettings ||
                !edgeETag ||
                (edgeEnabled === (edgeSettings.edge?.enabled === true) &&
                  normalizeEdgeStatusRefreshInterval(edgeStatusRefreshIntervalSec) ===
                    normalizeEdgeStatusRefreshInterval(edgeStatusRefreshIntervalFromConfig(edgeSettings)))
              }
            >
              {edgeSaving ? tx("Working...") : tx("Save mode")}
            </button>
            <span aria-hidden="true" />
          </div>
        </div>
        <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
          {tx("Saving updates DB app_config. Restart tukuyomi before relying on the menu IoT state or request-path edge controls.")}
        </div>
        {edgeNotice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{edgeNotice}</div> : null}
        {edgeError ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{edgeError}</div> : null}

        <div className="border-t border-neutral-200 pt-4 space-y-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold">{tx("Center Enrollment")}</h3>
              <p className="text-xs text-neutral-500">
                {tx("Request Center approval for this Gateway. The enrollment token is sent once and is not stored locally.")}
              </p>
              {edgeNeedsReapproval ? (
                <p className="mt-1 text-xs text-amber-800">
                {tx("This Gateway is no longer approved. Enter a new enrollment token to request re-approval with the same device identity.")}
                </p>
              ) : null}
              {edgeEnrollmentStatus === "approved" ? (
                <p className="mt-1 text-xs text-green-800">{tx("This Gateway is approved. New enrollment requests are disabled until Center removes approval.")}</p>
              ) : null}
              {edgeEnrollmentStatus === "pending" ? (
                <p className="mt-1 text-xs text-amber-800">{tx("Approval is pending in Center. Use Check Center status after approving it.")}</p>
              ) : null}
            </div>
            <span
              className={`rounded px-2 py-1 text-xs ${
                edgeDeviceStatus?.proxy_locked
                  ? "bg-red-100 text-red-800"
                  : edgeDeviceStatus?.identity_configured
                    ? "bg-green-100 text-green-800"
                    : "bg-neutral-100 text-neutral-700"
              }`}
            >
              {edgeDeviceStatus?.proxy_locked ? tx("Proxy locked") : edgeDeviceStatus?.identity_configured ? tx("Identity ready") : tx("No identity")}
            </span>
          </div>

          <div className="grid gap-3 md:grid-cols-4 text-xs">
            <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2">
              <div className="text-xs text-neutral-500">{tx("Runtime")}</div>
              <div>{edgeDeviceStatus?.edge_enabled && edgeDeviceStatus?.device_auth_enabled ? tx("enabled") : tx("disabled")}</div>
            </div>
            <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2">
              <div className="text-xs text-neutral-500">{tx("Proxy")}</div>
              <div>{edgeDeviceStatus?.proxy_locked ? tx("locked") : tx("available")}</div>
            </div>
            <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2">
              <div className="text-xs text-neutral-500">{tx("Enrollment status")}</div>
              <div>{edgeDeviceStatus?.enrollment_status || "-"}</div>
            </div>
            <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2">
              <div className="text-xs text-neutral-500">{tx("DB store")}</div>
              <div>{edgeDeviceStatus?.store_available ? tx("available") : tx("unavailable")}</div>
            </div>
            <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2">
              <div className="text-xs text-neutral-500">{tx("Last request")}</div>
              <div>{formatUnixTimestamp(edgeDeviceStatus?.last_enrollment_at_unix, locale)}</div>
            </div>
            <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2">
              <div className="text-xs text-neutral-500">{tx("Last Center check")}</div>
              <div>{formatUnixTimestamp(edgeDeviceStatus?.center_status_checked_at_unix, locale)}</div>
            </div>
            <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2 md:col-span-2">
              <div className="text-xs text-neutral-500">{tx("Product ID")}</div>
              <div className="break-all">{edgeDeviceStatus?.center_product_id || "-"}</div>
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-2 text-xs">
            <label className="grid gap-1">
              <span className="text-xs font-semibold">{tx("Center URL")}</span>
              <input
                value={edgeEnrollForm.centerURL}
                onChange={(e) => setEdgeEnrollForm((current) => ({ ...current, centerURL: e.target.value }))}
                placeholder="https://center.example.com"
                disabled={readOnly || edgeEnrollSaving || !edgeCanRequestApproval}
              />
            </label>
            <label className="grid gap-1">
              <span className="text-xs font-semibold">{tx("Enrollment token")}</span>
              <input
                type="password"
                value={edgeEnrollForm.enrollmentToken}
                onChange={(e) => setEdgeEnrollForm((current) => ({ ...current, enrollmentToken: e.target.value }))}
                placeholder={tx("one-time token")}
                autoComplete="off"
                disabled={readOnly || edgeEnrollSaving || !edgeCanRequestApproval}
              />
            </label>
            <label className="grid gap-1">
              <span className="text-xs font-semibold">{tx("Device ID")}</span>
              <input
                value={edgeEnrollForm.deviceID}
                onChange={(e) => setEdgeEnrollForm((current) => ({ ...current, deviceID: e.target.value }))}
                placeholder={tx("auto generated")}
                disabled={readOnly || edgeEnrollSaving || edgeDeviceStatus?.identity_configured}
              />
            </label>
            <label className="grid gap-1">
              <span className="text-xs font-semibold">{tx("Key ID")}</span>
              <input
                value={edgeEnrollForm.keyID}
                onChange={(e) => setEdgeEnrollForm((current) => ({ ...current, keyID: e.target.value }))}
                placeholder="default"
                disabled={readOnly || edgeEnrollSaving || edgeDeviceStatus?.identity_configured}
              />
            </label>
          </div>

          {edgeDeviceStatus?.device_id || edgeDeviceStatus?.public_key_fingerprint_sha256 ? (
            <div className="grid gap-3 md:grid-cols-2 text-xs">
              <div>
                <div className="text-xs text-neutral-500">{tx("Device ID")}</div>
                <code className="break-all">{edgeDeviceStatus.device_id || "-"}</code>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("Public key fingerprint")}</div>
                <code className="break-all">{edgeDeviceStatus.public_key_fingerprint_sha256 || "-"}</code>
              </div>
            </div>
          ) : null}

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void onEnrollEdgeDevice()}
              disabled={
                readOnly ||
                edgeEnrollSaving ||
                edgeStatusRefreshSaving ||
                !edgeCanRequestApproval ||
                !edgeDeviceStatus?.store_available ||
                !edgeDeviceStatus?.edge_enabled ||
                !edgeDeviceStatus?.device_auth_enabled
              }
            >
              {edgeEnrollSaving ? tx("Working...") : edgeEnrollButtonText}
            </button>
            <button
              type="button"
              onClick={() => void onRefreshEdgeDeviceStatus()}
              disabled={
                readOnly ||
                edgeEnrollSaving ||
                edgeStatusRefreshSaving ||
                !edgeDeviceStatus?.store_available ||
                !edgeDeviceStatus?.edge_enabled ||
                !edgeDeviceStatus?.device_auth_enabled ||
                !edgeDeviceStatus?.identity_configured
              }
            >
              {edgeStatusRefreshSaving ? tx("Working...") : tx("Check Center status")}
            </button>
            {edgeDeviceStatus?.edge_enabled && edgeDeviceStatus?.device_auth_enabled ? null : (
              <span className="text-xs text-neutral-500">{tx("Enable IoT / Edge mode and restart before requesting Center approval.")}</span>
            )}
          </div>
          {edgeEnrollNotice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{edgeEnrollNotice}</div> : null}
          {edgeEnrollError || edgeDeviceStatus?.last_enrollment_error || edgeDeviceStatus?.center_status_error ? (
            <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">
              {edgeEnrollError || edgeDeviceStatus?.last_enrollment_error || edgeDeviceStatus?.center_status_error}
            </div>
          ) : null}
        </div>

        <div className="border-t border-neutral-200 pt-4 space-y-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold">{tx("Remote SSH Gateway")}</h3>
              <p className="text-xs text-neutral-500">
                {tx("Allow this Gateway to attach short-lived embedded SSH sessions requested from Center. This is startup config and requires restart.")}
              </p>
            </div>
            <span className={`rounded px-2 py-1 text-xs ${remoteSSHRuntimeEmbeddedEnabled ? "bg-green-100 text-green-800" : "bg-neutral-100 text-neutral-700"}`}>
              {remoteSSHRuntimeEmbeddedEnabled ? tx("Remote SSH runtime ON") : tx("Remote SSH runtime OFF")}
            </span>
          </div>

          <div className="grid gap-3 md:grid-cols-2 text-xs">
            <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2">
              <div className="text-xs text-neutral-500">{tx("Configured")}</div>
              <div>{remoteSSHGatewayForm.enabled ? tx("enabled") : tx("disabled")}</div>
            </div>
            <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2">
              <div className="text-xs text-neutral-500">{tx("Running process")}</div>
              <div>{remoteSSHRuntimeEmbeddedEnabled ? tx("enabled") : tx("disabled")}</div>
            </div>
          </div>

          <div className="grid gap-3 text-xs">
            <label className="flex items-center gap-2 rounded border border-neutral-200 bg-white px-3 py-2 text-xs text-neutral-700">
              <input
                type="checkbox"
                checked={remoteSSHGatewayForm.enabled}
                onChange={(e) => setRemoteSSHGatewayForm((current) => ({ ...current, enabled: e.target.checked }))}
                disabled={readOnly || remoteSSHGatewayBusy || !edgeSettings || !edgeETag}
              />
              {tx("Enable Remote SSH on this Gateway")}
            </label>
          </div>

          <details className="rounded border border-neutral-200 bg-neutral-50/40 text-xs">
            <summary className="cursor-pointer select-none px-3 py-2 font-semibold text-neutral-700">{tx("Advanced Remote SSH Gateway trust and shell")}</summary>
            <div className="grid gap-3 border-t border-neutral-200 p-3 md:grid-cols-2">
            <label className="grid gap-1 md:col-span-2">
              <span className="text-xs font-semibold">{tx("Center signing public key")}</span>
              <textarea
                className="min-h-20 font-mono text-xs"
                value={remoteSSHGatewayForm.centerSigningPublicKey}
                onChange={(e) => setRemoteSSHGatewayForm((current) => ({ ...current, centerSigningPublicKey: e.target.value }))}
                placeholder={tx("auto fetched from enrolled Center on save")}
                disabled={readOnly || remoteSSHGatewayBusy || !edgeSettings || !edgeETag}
              />
              <span className="text-xs text-neutral-500">{tx("Gateway auto-fetches and pins this Center key when Remote SSH is enabled and the field is empty.")}</span>
              <button
                type="button"
                onClick={() => void onRefreshRemoteSSHGatewaySigningKey()}
                disabled={readOnly || remoteSSHGatewayBusy || !edgeSettings || !edgeETag}
              >
                {remoteSSHSigningKeyRefreshing ? tx("Refreshing...") : tx("Refresh key from approved Center")}
              </button>
            </label>
            <label className="grid gap-1">
              <span className="text-xs font-semibold">{tx("Center CA bundle file")}</span>
              <input
                value={remoteSSHGatewayForm.centerTLSCABundleFile}
                onChange={(e) => setRemoteSSHGatewayForm((current) => ({ ...current, centerTLSCABundleFile: e.target.value }))}
                placeholder="conf/center-ca.pem"
                disabled={readOnly || remoteSSHGatewayBusy || !edgeSettings || !edgeETag}
              />
              <span className="text-xs text-neutral-500">{tx("Optional when Center uses a public CA certificate.")}</span>
            </label>
            <label className="grid gap-1">
              <span className="text-xs font-semibold">{tx("Center TLS server name")}</span>
              <input
                value={remoteSSHGatewayForm.centerTLSServerName}
                onChange={(e) => setRemoteSSHGatewayForm((current) => ({ ...current, centerTLSServerName: e.target.value }))}
                placeholder="center.example.local"
                disabled={readOnly || remoteSSHGatewayBusy || !edgeSettings || !edgeETag}
              />
              <span className="text-xs text-neutral-500">{tx("Use this when Gateway reaches Center by IP but the certificate uses a DNS name.")}</span>
            </label>
            <label className="grid gap-1">
              <span className="text-xs font-semibold">{tx("Shell")}</span>
              <input
                value={remoteSSHGatewayForm.shell}
                onChange={(e) => setRemoteSSHGatewayForm((current) => ({ ...current, shell: e.target.value }))}
                placeholder="/bin/sh"
                disabled={readOnly || remoteSSHGatewayBusy || !edgeSettings || !edgeETag}
              />
            </label>
            <label className="grid gap-1">
              <span className="text-xs font-semibold">{tx("Working directory")}</span>
              <input
                value={remoteSSHGatewayForm.workingDir}
                onChange={(e) => setRemoteSSHGatewayForm((current) => ({ ...current, workingDir: e.target.value }))}
                placeholder="/"
                disabled={readOnly || remoteSSHGatewayBusy || !edgeSettings || !edgeETag}
              />
            </label>
            <label className="grid gap-1">
              <span className="text-xs font-semibold">{tx("Run as user")}</span>
              <input
                value={remoteSSHGatewayForm.runAsUser}
                onChange={(e) => setRemoteSSHGatewayForm((current) => ({ ...current, runAsUser: e.target.value }))}
                placeholder="tukuyomi"
                disabled={readOnly || remoteSSHGatewayBusy || !edgeSettings || !edgeETag}
              />
              <span className="text-xs text-neutral-500">{tx("Required when the tukuyomi process runs as root.")}</span>
            </label>
            </div>
          </details>

          {remoteSSHValidationError ? (
            <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">{tx(remoteSSHValidationError)}</div>
          ) : null}
          <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
            {tx("Use Center device Remote SSH ON and this Gateway ON. Center service must be enabled in Center Settings. Restart tukuyomi after saving Gateway config.")}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={() => void onSaveRemoteSSHGateway()} disabled={remoteSSHSaveDisabled}>
              {remoteSSHGatewayBusy ? tx("Working...") : tx("Save Remote SSH")}
            </button>
          </div>
          {remoteSSHNotice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{remoteSSHNotice}</div> : null}
          {remoteSSHError ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{remoteSSHError}</div> : null}
        </div>
      </div>

      <div className="rounded-xl border border-neutral-200 p-4 space-y-4">
        <div>
          <h2 className="text-sm font-semibold">{tx("Country Block Support")}</h2>
          <p className="text-xs text-neutral-500">{tx("Manage the country database artifact and the optional MaxMind updater workflow used by Country Block and country-aware policy.")}</p>
        </div>

          <div className="space-y-3">
            <div>
              <h3 className="text-sm font-semibold">{tx("Country DB")}</h3>
              <p className="text-xs text-neutral-500">{tx("Upload the managed .mmdb country database here. In DB mode the artifact is stored in runtime DB authority, not as a persistent file.")}</p>
            </div>
            <div className="grid gap-3 md:grid-cols-2 text-xs">
              <div>
                <div className="text-xs text-neutral-500">{tx("Storage")}</div>
                <code className="break-all">{requestCountryDB?.managed_path || "db:request_country_mmdb_asset"}</code>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("Installed")}</div>
                <div>{String(requestCountryDB?.installed ?? false)}</div>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("Loaded")}</div>
                <div>{String(requestCountryDB?.loaded ?? false)}</div>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("Size Bytes")}</div>
                <div>{requestCountryDB?.size_bytes ?? 0}</div>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("MTime")}</div>
                <div>{requestCountryDB?.mod_time || "-"}</div>
              </div>
            </div>
            <div className="space-y-2">
              <input
                type="file"
                accept=".mmdb,application/octet-stream"
                onChange={(e) => setSelectedCountryDB(e.target.files?.[0] ?? null)}
                disabled={readOnly || dbUploading || dbRemoving}
              />
              <div className="flex flex-wrap items-center gap-2">
                <button type="button" onClick={() => void onUploadCountryDB()} disabled={readOnly || dbUploading || dbRemoving || !selectedCountryDB}>
                  {dbUploading ? tx("Working...") : tx("Upload Country DB")}
                </button>
                <button type="button" onClick={() => void onRemoveCountryDB()} disabled={readOnly || dbUploading || dbRemoving || !requestCountryDB?.installed}>
                  {dbRemoving ? tx("Working...") : tx("Remove Country DB")}
                </button>
              </div>
              {dbNotice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{dbNotice}</div> : null}
              {dbError ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{dbError}</div> : null}
              {requestCountryDB?.last_error ? (
                <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">{requestCountryDB.last_error}</div>
              ) : null}
            </div>
          </div>

          <div className="border-t border-neutral-200 pt-4 space-y-3">
            <div>
              <h3 className="text-sm font-semibold">{tx("GeoIP Update")}</h3>
              <p className="text-xs text-neutral-500">{tx("Upload the managed GeoIP.conf here, then run Update now manually or from Scheduled Tasks. In DB mode the config and update state are stored in DB authority.")}</p>
            </div>
            <div className="grid gap-3 md:grid-cols-2 text-xs">
              <div>
                <div className="text-xs text-neutral-500">{tx("Config Storage")}</div>
                <code className="break-all">{requestCountryUpdate?.managed_config_path || "db:request_country_geoip_config"}</code>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("Updater Available")}</div>
                <div>{String(requestCountryUpdate?.updater_available ?? false)}</div>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("Config Installed")}</div>
                <div>{String(requestCountryUpdate?.config_installed ?? false)}</div>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("Config MTime")}</div>
                <div>{requestCountryUpdate?.config_mod_time || "-"}</div>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("Edition IDs")}</div>
                <div>{requestCountryUpdate?.edition_ids?.join(", ") || "-"}</div>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("Supported Country Edition")}</div>
                <div>{requestCountryUpdate?.supported_country_edition || "-"}</div>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("Last Attempt")}</div>
                <div>{requestCountryUpdate?.last_attempt || "-"}</div>
              </div>
              <div>
                <div className="text-xs text-neutral-500">{tx("Last Success")}</div>
                <div>{requestCountryUpdate?.last_success || "-"}</div>
              </div>
            </div>
            <div className="space-y-2">
              <input
                type="file"
                accept=".conf,text/plain"
                onChange={(e) => setSelectedCountryConfig(e.target.files?.[0] ?? null)}
                disabled={readOnly || configUploading || configRemoving || updatingNow}
              />
              <div className="flex flex-wrap items-center gap-2">
                <button type="button" onClick={() => void onUploadCountryConfig()} disabled={readOnly || configUploading || configRemoving || updatingNow || !selectedCountryConfig}>
                  {configUploading ? tx("Working...") : tx("Upload GeoIP.conf")}
                </button>
                <button type="button" onClick={() => void onRemoveCountryConfig()} disabled={readOnly || configUploading || configRemoving || updatingNow || !requestCountryUpdate?.config_installed}>
                  {configRemoving ? tx("Working...") : tx("Remove GeoIP.conf")}
                </button>
                <button
                  type="button"
                  onClick={() => void onRunCountryUpdate()}
                  disabled={readOnly || configUploading || configRemoving || updatingNow || !requestCountryUpdate?.config_installed || !requestCountryUpdate?.updater_available}
                >
                  {updatingNow ? tx("Working...") : tx("Update now")}
                </button>
              </div>
              <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs text-neutral-700">
                <div>{tx("Scheduled Tasks command example:")}</div>
                <code className="break-all">./scripts/update_country_db.sh</code>
              </div>
              {updateNotice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{updateNotice}</div> : null}
              {updateError ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{updateError}</div> : null}
              {requestCountryUpdate?.last_error ? (
                <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">{requestCountryUpdate.last_error}</div>
              ) : null}
            </div>
          </div>

          <div className="border-t border-neutral-200 pt-4 space-y-3">
            <div>
              <h3 className="text-sm font-semibold">{tx("Country Resolution Mode")}</h3>
              <p className="text-xs text-neutral-500">
                {tx("Choose whether request country comes from a trusted frontend header or from the installed local country database artifact. This updates DB app_config and takes effect after restart.")}
              </p>
            </div>
            <div className="grid gap-3 text-xs">
              <div>
                <div className="text-xs text-neutral-500">{tx("Configured / Effective Mode")}</div>
                <div>{[requestCountryDB?.configured_mode || "-", requestCountryDB?.effective_mode || "-"].join(" / ")}</div>
              </div>
            </div>
            <div className="flex flex-wrap items-end gap-3">
              <div className="space-y-1">
                <div className="text-xs text-neutral-500">{tx("Mode")}</div>
                <select
                  value={countryMode}
                  onChange={(e) => setCountryMode(e.target.value)}
                  disabled={readOnly || modeSaving}
                  className="min-w-48"
                >
                  <option value="header">header</option>
                  <option value="mmdb">mmdb</option>
                </select>
              </div>
              <button
                type="button"
                onClick={() => void onSaveCountryMode()}
                disabled={readOnly || modeSaving || !requestCountryDB?.config_etag || countryMode === (requestCountryDB?.configured_mode || "header")}
              >
                {modeSaving ? tx("Working...") : tx("Save mode")}
              </button>
            </div>
            <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
              {tx("Saving updates DB app_config. Restart the process after switching modes.")}
            </div>
            {modeNotice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{modeNotice}</div> : null}
            {modeError ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{modeError}</div> : null}
          </div>
      </div>

      <div id="runtime-inventory" className="rounded-xl border border-neutral-200 p-4 space-y-3">
        <h2 className="text-sm font-semibold">{tx("Runtime Inventory")}</h2>
        <p className="text-xs text-neutral-500">{tx("Runtime entries are managed here for visibility, readiness, and PHP-FPM process controls.")}</p>
        {runtimeNotice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{runtimeNotice}</div> : null}
        {runtimeError ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{runtimeError}</div> : null}
        {availableRuntimeCount === 0 ? (
          <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
            {tx("No built runtimes are available yet. Build a runtime bundle first, then return here to confirm readiness.")}
          </div>
        ) : (
          <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900 flex flex-wrap items-center justify-between gap-2">
            <span>{tx("Built runtimes are available. Manage PHP-FPM host, port, and docroot bindings from Runtime Apps.")}</span>
            <Link to="/runtime-apps" className="underline">
              {tx("Open Runtime Apps")}
            </Link>
          </div>
        )}
        {runtimes.length === 0 ? (
          <div className="rounded border border-dashed border-neutral-200 px-3 py-6 text-xs text-neutral-500">{tx("No built runtimes detected.")}</div>
        ) : (
          <div className="space-y-3">
            {runtimes.map((runtime) => {
              const materializedEntry = materializedMap.get(runtime.runtime_id);
              const process = processMap.get(runtime.runtime_id);
              const usageCount = materializedEntry?.generated_targets?.length ?? 0;
              const materializedRuntime = !!materializedEntry;
              const generatedTargets = process?.generated_targets?.length ? process.generated_targets : (materializedEntry?.generated_targets ?? []);
              const isBusy = runtimeAction?.runtimeID === runtime.runtime_id;
              const canStart = materializedRuntime && !process?.running;
              const canStop = materializedRuntime && process?.running === true;
              return (
                <article key={runtime.runtime_id} className="rounded-xl border border-neutral-200 p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h3 className="text-sm font-semibold">{runtimeDisplayName(runtime)}</h3>
                      <p className="text-xs text-neutral-500">
                        <code>{runtime.runtime_id}</code> · {tx("bundled")}
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="rounded bg-neutral-100 px-2 py-1">{usageCount} {tx("app(s)")}</span>
                      <span className={`rounded px-2 py-1 ${runtime.available ? "bg-green-100 text-green-800" : "bg-amber-100 text-amber-900"}`}>
                        {runtime.available ? tx("ready") : tx("not built")}
                      </span>
                      <span className={`rounded px-2 py-1 ${processBadgeClass(process, materializedRuntime)}`}>
                        {tx(processActionLabel(process, materializedRuntime))}
                      </span>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => void onRuntimeAction(runtime.runtime_id, "up")}
                      disabled={readOnly || !!runtimeAction || !canStart}
                    >
                      {isBusy && runtimeAction?.action === "up" ? tx("Working...") : tx("Start")}
                    </button>
                    <button
                      type="button"
                      onClick={() => void onRuntimeAction(runtime.runtime_id, "down")}
                      disabled={readOnly || !!runtimeAction || !canStop}
                    >
                      {isBusy && runtimeAction?.action === "down" ? tx("Working...") : tx("Stop")}
                    </button>
                    <button
                      type="button"
                      onClick={() => void onRuntimeAction(runtime.runtime_id, "reload")}
                      disabled={readOnly || !!runtimeAction || !canStop}
                    >
                      {isBusy && runtimeAction?.action === "reload" ? tx("Working...") : tx("Reload")}
                    </button>
                    {!materializedRuntime ? (
                      <span className="text-xs text-neutral-500">{tx("Bind this runtime from Runtime Apps before process controls become available.")}</span>
                    ) : null}
                  </div>

                  <div className="grid gap-3 md:grid-cols-2 text-xs">
                    <div>
                      <div className="text-xs text-neutral-500">{tx("Binary Path")}</div>
                      <code className="break-all">{runtime.binary_path}</code>
                    </div>
                    <div>
                      <div className="text-xs text-neutral-500">{tx("CLI Binary Path")}</div>
                      <code className="break-all">{runtime.cli_binary_path || "-"}</code>
                    </div>
                    <div>
                      <div className="text-xs text-neutral-500">{tx("Detected Version")}</div>
                      <div>{runtime.detected_version || "-"}</div>
                    </div>
                    <div>
                      <div className="text-xs text-neutral-500">{tx("Run User")}</div>
                      <div>{[runtime.run_user, runtime.run_group].filter(Boolean).join(":") || "-"}</div>
                    </div>
                    <div>
                      <div className="text-xs text-neutral-500">{tx("PID")}</div>
                      <div>{process?.pid || "-"}</div>
                    </div>
                    <div>
                      <div className="text-xs text-neutral-500">{tx("Effective User")}</div>
                      <div>{runtimeIdentity(process, runtime)}</div>
                    </div>
                    <div>
                      <div className="text-xs text-neutral-500">{tx("Started At")}</div>
                      <div>{process?.started_at || "-"}</div>
                    </div>
                    <div>
                      <div className="text-xs text-neutral-500">{tx("Stopped At")}</div>
                      <div>{process?.stopped_at || "-"}</div>
                    </div>
                    <div>
                      <div className="text-xs text-neutral-500">{tx("Generated Targets")}</div>
                      <code className="break-all">{generatedTargets.length > 0 ? generatedTargets.join(", ") : "-"}</code>
                    </div>
                    <div>
                      <div className="text-xs text-neutral-500">{tx("Config File")}</div>
                      <code className="break-all">{process?.config_file || materializedEntry?.config_file || "-"}</code>
                    </div>
                  </div>

                  <RuntimeModuleList
                    modules={runtime.modules}
                    defaultDisabledModules={runtime.default_disabled_modules}
                    availabilityMessage={runtime.availability_message}
                    tx={tx}
                  />

                  {process?.last_error ? (
                    <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                      {process.last_error}
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>
        )}
      </div>

      <div id="psgi-runtime-inventory" className="rounded-xl border border-neutral-200 p-4 space-y-3">
        <h2 className="text-sm font-semibold">{tx("PSGI Runtime Inventory")}</h2>
        <p className="text-xs text-neutral-500">{tx("Perl/Starman runtime entries are managed here for PSGI Runtime Apps and per-app process controls.")}</p>
        {psgiAvailableRuntimeCount === 0 ? (
          <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
            {tx("No built PSGI runtimes are available yet. Build a PSGI runtime bundle first, then bind it from Runtime Apps.")}
          </div>
        ) : (
          <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900 flex flex-wrap items-center justify-between gap-2">
            <span>{tx("Built PSGI runtimes are available. Bind each PSGI app from Runtime Apps.")}</span>
            <Link to="/runtime-apps" className="underline">
              {tx("Open Runtime Apps")}
            </Link>
          </div>
        )}
        {psgiRuntimes.length === 0 ? (
          <div className="rounded border border-dashed border-neutral-200 px-3 py-6 text-xs text-neutral-500">{tx("No built PSGI runtimes detected.")}</div>
        ) : (
          <div className="space-y-3">
            {psgiRuntimes.map((runtime) => (
              <article key={runtime.runtime_id} className="rounded-xl border border-neutral-200 p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-semibold">{psgiRuntimeDisplayName(runtime)}</h3>
                    <p className="text-xs text-neutral-500">
                      <code>{runtime.runtime_id}</code> · {tx("bundled")}
                    </p>
                  </div>
                  <span className={`rounded px-2 py-1 text-xs ${runtime.available ? "bg-green-100 text-green-800" : "bg-amber-100 text-amber-900"}`}>
                    {runtime.available ? tx("ready") : tx("not built")}
                  </span>
                </div>
                <div className="grid gap-3 md:grid-cols-2 text-xs">
                  <div>
                    <div className="text-xs text-neutral-500">{tx("Perl Path")}</div>
                    <code className="break-all">{runtime.perl_path}</code>
                  </div>
                  <div>
                    <div className="text-xs text-neutral-500">{tx("Starman Path")}</div>
                    <code className="break-all">{runtime.starman_path}</code>
                  </div>
                  <div>
                    <div className="text-xs text-neutral-500">{tx("Detected Version")}</div>
                    <div>{runtime.detected_version || "-"}</div>
                  </div>
                  <div>
                    <div className="text-xs text-neutral-500">{tx("Run User")}</div>
                    <div>{[runtime.run_user, runtime.run_group].filter(Boolean).join(":") || "-"}</div>
                  </div>
                </div>
                <RuntimeModuleList modules={runtime.modules} availabilityMessage={runtime.availability_message} tx={tx} />
              </article>
            ))}
          </div>
        )}

        <div className="space-y-3">
          <h3 className="text-xs font-semibold">{tx("PSGI Processes")}</h3>
          {psgiMaterialized.length === 0 ? (
            <div className="rounded border border-dashed border-neutral-200 px-3 py-6 text-xs text-neutral-500">{tx("No PSGI Runtime Apps are materialized.")}</div>
          ) : (
            psgiMaterialized.map((entry) => {
              const process = psgiProcessMap.get(entry.vhost_name);
              const running = process?.running === true;
              const busy = psgiAction?.appName === entry.vhost_name;
              const state = process?.last_action || (running ? "running" : "stopped");
              return (
                <article key={entry.process_id} className="rounded-xl border border-neutral-200 p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h4 className="text-sm font-semibold">{entry.vhost_name}</h4>
                      <p className="text-xs text-neutral-500"><code>{entry.runtime_id}</code> · <code>{entry.generated_target || "-"}</code></p>
                    </div>
                    <span className={`rounded px-2 py-1 text-xs ${process?.last_error ? "bg-red-100 text-red-800" : running ? "bg-green-100 text-green-800" : "bg-neutral-100 text-neutral-700"}`}>
                      {tx(state)}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <button type="button" onClick={() => void onPSGIAction(entry.vhost_name, "up")} disabled={readOnly || !!psgiAction || running}>
                      {busy && psgiAction?.action === "up" ? tx("Working...") : tx("Start")}
                    </button>
                    <button type="button" onClick={() => void onPSGIAction(entry.vhost_name, "down")} disabled={readOnly || !!psgiAction || !running}>
                      {busy && psgiAction?.action === "down" ? tx("Working...") : tx("Stop")}
                    </button>
                    <button type="button" onClick={() => void onPSGIAction(entry.vhost_name, "reload")} disabled={readOnly || !!psgiAction || !running}>
                      {busy && psgiAction?.action === "reload" ? tx("Working...") : tx("Reload")}
                    </button>
                  </div>
                  <div className="grid gap-3 md:grid-cols-2 text-xs">
                    <div><div className="text-xs text-neutral-500">{tx("PID")}</div><div>{process?.pid || "-"}</div></div>
                    <div><div className="text-xs text-neutral-500">{tx("Listen Port")}</div><div>{entry.listen_port || "-"}</div></div>
                    <div><div className="text-xs text-neutral-500">{tx("App Root")}</div><code className="break-all">{entry.app_root || "-"}</code></div>
                    <div><div className="text-xs text-neutral-500">{tx("PSGI File")}</div><code className="break-all">{entry.psgi_file || "-"}</code></div>
                  </div>
                  {process?.last_error ? <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">{process.last_error}</div> : null}
                </article>
              );
            })
          )}
        </div>
      </div>

      {error ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{error}</div> : null}

    </div>
  );
}
