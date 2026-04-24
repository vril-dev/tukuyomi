import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { apiDeleteJson, apiGetJson, apiPostFormData, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
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
  runtime_dir?: string;
};

type PHPRuntimeProcessStatus = {
  runtime_id: string;
  running: boolean;
  pid?: number;
  last_error?: string;
  effective_user?: string;
  effective_group?: string;
};

type PHPRuntimesResponse = {
  etag?: string;
  runtimes?: PHPRuntimeInventory;
  materialized?: PHPRuntimeMaterializedStatus[];
  processes?: PHPRuntimeProcessStatus[];
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

function runtimeDisplayName(runtime: PHPRuntimeRecord) {
  return runtime.display_name || runtime.detected_version || runtime.runtime_id;
}

export default function OptionsPanel() {
  const { tx } = useI18n();
  const [runtimes, setRuntimes] = useState<PHPRuntimeRecord[]>([]);
  const [materialized, setMaterialized] = useState<PHPRuntimeMaterializedStatus[]>([]);
  const [processes, setProcesses] = useState<PHPRuntimeProcessStatus[]>([]);
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

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [data, countryDB, countryUpdate] = await Promise.all([
        apiGetJson<PHPRuntimesResponse>("/php-runtimes"),
        apiGetJson<RequestCountryDBStatus>("/request-country-db"),
        apiGetJson<RequestCountryUpdateStatus>("/request-country-update"),
      ]);
      setRuntimes(Array.isArray(data.runtimes?.runtimes) ? data.runtimes.runtimes : []);
      setMaterialized(Array.isArray(data.materialized) ? data.materialized : []);
      setProcesses(Array.isArray(data.processes) ? data.processes : []);
      setRequestCountryDB(countryDB);
      setRequestCountryUpdate(countryUpdate);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

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

  if (loading) {
    return <div className="w-full p-4 text-neutral-500">{tx("Loading options...")}</div>;
  }

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Options")}</h1>
          <p className="text-sm text-neutral-500">{tx("Review built runtime inventory, module baselines, readiness, and process state from one place.")}</p>
        </div>
      </header>

      <div className="rounded-xl border border-neutral-200 p-4 space-y-4">
        <div>
          <h2 className="text-sm font-semibold">{tx("Country Block Support")}</h2>
          <p className="text-sm text-neutral-500">{tx("Manage the country database artifact and the optional MaxMind updater workflow used by Country Block and country-aware policy.")}</p>
        </div>

          <div className="space-y-3">
            <div>
              <h3 className="text-sm font-semibold">{tx("Country DB")}</h3>
              <p className="text-sm text-neutral-500">{tx("Upload the managed .mmdb country database here. In DB mode the artifact is stored in runtime DB authority, not as a persistent file.")}</p>
            </div>
            <div className="grid gap-3 md:grid-cols-2 text-sm">
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
              <p className="text-sm text-neutral-500">{tx("Upload the managed GeoIP.conf here, then run Update now manually or from Scheduled Tasks. In DB mode the config and update state are stored in DB authority.")}</p>
            </div>
            <div className="grid gap-3 md:grid-cols-2 text-sm">
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
              <p className="text-sm text-neutral-500">
                {tx("Choose whether request country comes from a trusted frontend header or from the installed local country database artifact. This updates DB app_config and takes effect after restart.")}
              </p>
            </div>
            <div className="grid gap-3 text-sm">
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

      <div className="rounded-xl border border-neutral-200 p-4 space-y-3">
        <h2 className="text-sm font-semibold">{tx("Runtime Inventory")}</h2>
        <p className="text-sm text-neutral-500">{tx("Runtime entries are read-only here. This panel is for visibility, readiness, and process status.")}</p>
        {availableRuntimeCount === 0 ? (
          <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
            {tx("No built runtimes are available yet. Build a runtime bundle first, then return here to confirm readiness.")}
          </div>
        ) : (
          <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900 flex flex-wrap items-center justify-between gap-2">
            <span>{tx("Built runtimes are available. Manage PHP-FPM host, port, and docroot bindings from Vhosts.")}</span>
            <Link to="/vhosts" className="underline">
              {tx("Open Vhosts")}
            </Link>
          </div>
        )}
        {runtimes.length === 0 ? (
          <div className="rounded border border-dashed border-neutral-200 px-3 py-6 text-sm text-neutral-500">{tx("No built runtimes detected.")}</div>
        ) : (
          <div className="space-y-3">
            {runtimes.map((runtime) => {
              const materializedEntry = materializedMap.get(runtime.runtime_id);
              const process = processMap.get(runtime.runtime_id);
              const usageCount = materializedEntry?.generated_targets?.length ?? 0;
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
                      <span className="rounded bg-neutral-100 px-2 py-1">{usageCount} {tx("vhost(s)")}</span>
                      <span className={`rounded px-2 py-1 ${runtime.available ? "bg-green-100 text-green-800" : "bg-amber-100 text-amber-900"}`}>
                        {runtime.available ? tx("ready") : tx("not built")}
                      </span>
                      <span className={`rounded px-2 py-1 ${process?.running ? "bg-green-100 text-green-800" : "bg-neutral-100 text-neutral-700"}`}>
                        {process?.running ? tx("running") : tx("stopped")}
                      </span>
                    </div>
                  </div>

                  <div className="grid gap-3 md:grid-cols-2 text-sm">
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
                  </div>

                  <div className="space-y-2">
                    <div className="text-xs text-neutral-500">{tx("Modules")}</div>
                    {(runtime.modules ?? []).length === 0 ? (
                      <div className="rounded border border-dashed border-neutral-200 px-3 py-2 text-xs text-neutral-500">
                        {runtime.availability_message || tx("No built modules detected.")}
                      </div>
                    ) : (
                      <div className="flex flex-wrap gap-2">
                        {(runtime.modules ?? []).map((module) => {
                          const defaultOff = (runtime.default_disabled_modules ?? []).includes(module);
                          return (
                            <span
                              key={module}
                              className={`rounded-full border px-2 py-1 text-xs ${defaultOff ? "border-amber-200 bg-amber-50 text-amber-900" : "bg-neutral-50 text-neutral-700"}`}
                            >
                              {module}
                              {defaultOff ? ` · ${tx("default off")}` : ""}
                            </span>
                          );
                        })}
                      </div>
                    )}
                  </div>

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

      {error ? <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{error}</div> : null}

    </div>
  );
}
