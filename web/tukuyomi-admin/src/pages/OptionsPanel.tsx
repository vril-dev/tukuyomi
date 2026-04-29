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
  device_auth?: {
    enabled?: boolean;
  };
};

type EdgeSettingsConfig = Record<string, unknown> & {
  edge?: EdgeModeConfig;
};

type EdgeSettingsResponse = {
  etag?: string;
  restart_required?: boolean;
  config?: EdgeSettingsConfig;
  runtime?: {
    edge_enabled?: boolean;
    edge_device_auth_enabled?: boolean;
  };
};

function runtimeDisplayName(runtime: PHPRuntimeRecord) {
  return runtime.display_name || runtime.detected_version || runtime.runtime_id;
}

function psgiRuntimeDisplayName(runtime: PSGIRuntimeRecord) {
  return runtime.display_name || runtime.detected_version || runtime.runtime_id;
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
  const { tx } = useI18n();
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
  const [edgeSaving, setEdgeSaving] = useState(false);
  const [edgeNotice, setEdgeNotice] = useState("");
  const [edgeError, setEdgeError] = useState("");
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
    const [data, psgiData] = await Promise.all([
      apiGetJson<PHPRuntimesResponse>("/php-runtimes"),
      apiGetJson<PSGIRuntimesResponse>("/psgi-runtimes"),
    ]);
    applyRuntimeState(data, psgiData);
  }, [applyRuntimeState]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [data, psgiData, countryDB, countryUpdate, settings] = await Promise.all([
        apiGetJson<PHPRuntimesResponse>("/php-runtimes"),
        apiGetJson<PSGIRuntimesResponse>("/psgi-runtimes"),
        apiGetJson<RequestCountryDBStatus>("/request-country-db"),
        apiGetJson<RequestCountryUpdateStatus>("/request-country-update"),
        apiGetJson<EdgeSettingsResponse>("/settings/listener-admin"),
      ]);
      applyRuntimeState(data, psgiData);
      setRequestCountryDB(countryDB);
      setRequestCountryUpdate(countryUpdate);
      setEdgeSettings(settings.config ?? null);
      setEdgeETag(settings.etag ?? "");
      setEdgeEnabled(settings.config?.edge?.enabled === true);
      setEdgeRuntimeEnabled(settings.runtime?.edge_enabled === true);
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
          device_auth: {
            enabled: edgeSettings.edge?.device_auth?.enabled !== false,
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
      setEdgeNotice(tx("IoT / Edge mode saved. Restart the process to apply the new mode."));
    } catch (err: unknown) {
      setEdgeError(err instanceof Error ? err.message : String(err));
      try {
        const current = await apiGetJson<EdgeSettingsResponse>("/settings/listener-admin");
        setEdgeSettings(current.config ?? null);
        setEdgeETag(current.etag ?? "");
        setEdgeEnabled(current.config?.edge?.enabled === true);
        setEdgeRuntimeEnabled(current.runtime?.edge_enabled === true);
      } catch {
        //
      }
    } finally {
      setEdgeSaving(false);
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
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex min-h-10 items-center gap-2 rounded border border-neutral-200 bg-white px-3 py-2 text-xs text-neutral-700">
            <input
              type="checkbox"
              checked={edgeEnabled}
              onChange={(e) => setEdgeEnabled(e.target.checked)}
              disabled={readOnly || edgeSaving || !edgeSettings || !edgeETag}
            />
            {tx("Enable IoT / Edge mode")}
          </label>
          <button
            type="button"
            onClick={() => void onSaveEdgeMode()}
            disabled={readOnly || edgeSaving || !edgeSettings || !edgeETag || edgeEnabled === (edgeSettings.edge?.enabled === true)}
          >
            {edgeSaving ? tx("Working...") : tx("Save mode")}
          </button>
        </div>
        <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
          {tx("Saving updates DB app_config. Restart tukuyomi before relying on the menu IoT state or request-path edge controls.")}
        </div>
        {edgeNotice ? <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{edgeNotice}</div> : null}
        {edgeError ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{edgeError}</div> : null}
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
                    <div className="md:col-span-2">
                      <div className="text-xs text-neutral-500">{tx("Generated Targets")}</div>
                      <code className="break-all">{generatedTargets.length > 0 ? generatedTargets.join(", ") : "-"}</code>
                    </div>
                    <div className="md:col-span-2">
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
