import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  apiGetBinary,
  apiGetJson,
  apiPostJson,
  apiPutJson,
  getOperatorIdentity,
  setOperatorIdentity,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { useI18n } from "@/lib/i18n";
import { computeSettingsRuntimeDrift } from "@/lib/settingsConfig";

type ListenerAdminConfig = {
  server: {
    listen_addr: string;
    read_timeout_sec: number;
    read_header_timeout_sec: number;
    write_timeout_sec: number;
    idle_timeout_sec: number;
    graceful_shutdown_timeout_sec: number;
    max_header_bytes: number;
    max_concurrent_requests: number;
    max_queued_requests: number;
    queued_request_timeout_ms: number;
    max_concurrent_proxy_requests: number;
    max_queued_proxy_requests: number;
    queued_proxy_request_timeout_ms: number;
    proxy_protocol: {
      enabled: boolean;
      trusted_cidrs: string[];
    };
    tls: {
      enabled: boolean;
      cert_file: string;
      key_file: string;
      min_version: string;
      redirect_http: boolean;
      http_redirect_addr: string;
    };
    http3: {
      enabled: boolean;
      alt_svc_max_age_sec: number;
    };
  };
  runtime: {
    gomaxprocs: number;
    memory_limit_mb: number;
  };
  request_metadata: {
    country: {
      mode: string;
    };
  };
  admin: {
    api_base_path: string;
    ui_base_path: string;
    listen_addr: string;
    external_mode: string;
    trusted_cidrs: string[];
    trust_forwarded_for: boolean;
    proxy_protocol: {
      enabled: boolean;
      trusted_cidrs: string[];
    };
    read_only: boolean;
    cors_allowed_origins: string[];
    rate_limit: {
      enabled: boolean;
      rps: number;
      burst: number;
      status_code: number;
      retry_after_seconds: number;
    };
  };
  storage: {
    db_driver: string;
    db_path: string;
    db_retention_days: number;
    db_sync_interval_sec: number;
    file_rotate_bytes: number;
    file_max_bytes: number;
    file_retention_days: number;
  };
    paths: {
      proxy_config_file: string;
      site_config_file: string;
      php_runtime_inventory_file: string;
      vhost_config_file: string;
      scheduled_task_config_file: string;
      security_audit_file: string;
      security_audit_blob_dir: string;
      cache_rules_file: string;
      cache_store_file: string;
      rules_file: string;
      override_rules_dir: string;
      upstream_runtime_file: string;
      bypass_file: string;
    country_block_file: string;
    rate_limit_file: string;
    bot_defense_file: string;
    semantic_file: string;
    notification_file: string;
    ip_reputation_file: string;
    log_file: string;
    crs_setup_file: string;
    crs_rules_dir: string;
    crs_disabled_file: string;
  };
  proxy: {
    rollback_history_size: number;
    engine: {
      mode: string;
    };
  };
  crs: {
    enable: boolean;
  };
  fp_tuner: {
    endpoint: string;
    model: string;
    timeout_sec: number;
    require_approval: boolean;
    approval_ttl_sec: number;
    audit_file: string;
  };
  observability: {
    tracing: {
      enabled: boolean;
      service_name: string;
      otlp_endpoint: string;
      insecure: boolean;
      sample_ratio: number;
    };
  };
};

type ListenerAdminRuntime = {
  request_country_configured_mode?: string;
  request_country_effective_mode?: string;
  request_country_managed_path?: string;
  request_country_loaded?: boolean;
  request_country_db_size_bytes?: number;
  request_country_db_mod_time?: string;
  request_country_last_error?: string;
  listen_addr?: string;
  api_base_path?: string;
  ui_base_path?: string;
  admin_listen_addr?: string;
  server_tls_enabled?: boolean;
  server_tls_source?: string;
  server_tls_min_version?: string;
  server_tls_redirect_http?: boolean;
  server_tls_http_redirect_addr?: string;
  server_http3_enabled?: boolean;
  server_http3_advertised?: boolean;
  server_http3_alt_svc?: string;
  server_proxy_protocol_enabled?: boolean;
  server_proxy_protocol_trusted_cidrs?: string[];
  admin_external_mode?: string;
  admin_trusted_cidrs?: string[];
  admin_trust_forwarded_for?: boolean;
  admin_proxy_protocol_enabled?: boolean;
  admin_proxy_protocol_trusted_cidrs?: string[];
  admin_read_only?: boolean;
  admin_rate_limit_enabled?: boolean;
  admin_rate_limit_rps?: number;
  admin_rate_limit_burst?: number;
  admin_rate_limit_status_code?: number;
  admin_rate_limit_retry_after_seconds?: number;
  runtime_gomaxprocs?: number;
  runtime_memory_limit_mb?: number;
  server_graceful_shutdown_timeout_sec?: number;
  server_max_concurrent_requests?: number;
  server_max_queued_requests?: number;
  server_queued_request_timeout_ms?: number;
  server_max_concurrent_proxy_requests?: number;
  server_max_queued_proxy_requests?: number;
  server_queued_proxy_request_timeout_ms?: number;
  proxy_engine_mode?: string;
  storage_db_driver?: string;
  storage_db_path?: string;
  storage_db_retention_days?: number;
  storage_db_sync_interval_sec?: number;
  storage_file_rotate_bytes?: number;
  storage_file_max_bytes?: number;
  storage_file_retention_days?: number;
  tracing_enabled?: boolean;
  tracing_service_name?: string;
  tracing_otlp_endpoint?: string;
  tracing_insecure?: boolean;
  tracing_sample_ratio?: number;
};

type ListenerAdminResponse = {
  etag?: string;
  config_file?: string;
  restart_required?: boolean;
  config?: ListenerAdminConfig;
  secrets?: SecretStatus;
  runtime?: ListenerAdminRuntime;
};

type SecretStatus = {
  admin_api_key_primary_configured?: boolean;
  admin_api_key_secondary_configured?: boolean;
  admin_session_secret_configured?: boolean;
  storage_db_dsn_configured?: boolean;
  security_audit_key_source?: string;
  security_audit_encryption_key_id?: string;
  security_audit_encryption_key_configured?: boolean;
  security_audit_hmac_key_id?: string;
  security_audit_hmac_key_configured?: boolean;
  fp_tuner_api_key_configured?: boolean;
};

function createEmptyListenerAdminConfig(): ListenerAdminConfig {
  return {
    server: {
      listen_addr: ":9090",
      read_timeout_sec: 30,
      read_header_timeout_sec: 5,
      write_timeout_sec: 0,
      idle_timeout_sec: 120,
      graceful_shutdown_timeout_sec: 30,
      max_header_bytes: 1048576,
      max_concurrent_requests: 0,
      max_queued_requests: 0,
      queued_request_timeout_ms: 0,
      max_concurrent_proxy_requests: 0,
      max_queued_proxy_requests: 32,
      queued_proxy_request_timeout_ms: 100,
      proxy_protocol: {
        enabled: false,
        trusted_cidrs: [],
      },
      tls: {
        enabled: false,
        cert_file: "",
        key_file: "",
        min_version: "tls1.2",
        redirect_http: false,
        http_redirect_addr: "",
      },
      http3: {
        enabled: false,
        alt_svc_max_age_sec: 86400,
      },
    },
    runtime: {
      gomaxprocs: 0,
      memory_limit_mb: 0,
    },
    request_metadata: {
      country: {
        mode: "header",
      },
    },
    admin: {
      api_base_path: "/tukuyomi-api",
      ui_base_path: "/tukuyomi-ui",
      listen_addr: "",
      external_mode: "api_only_external",
      trusted_cidrs: [],
      trust_forwarded_for: false,
      proxy_protocol: {
        enabled: false,
        trusted_cidrs: [],
      },
      read_only: false,
      cors_allowed_origins: [],
      rate_limit: {
        enabled: false,
        rps: 5,
        burst: 10,
        status_code: 429,
        retry_after_seconds: 1,
      },
    },
    storage: {
      db_driver: "sqlite",
      db_path: "db/tukuyomi.db",
      db_retention_days: 30,
      db_sync_interval_sec: 0,
      file_rotate_bytes: 8 * 1024 * 1024,
      file_max_bytes: 256 * 1024 * 1024,
      file_retention_days: 7,
    },
    paths: {
      proxy_config_file: "conf/proxy.json",
      site_config_file: "conf/sites.json",
      php_runtime_inventory_file: "data/php-fpm/inventory.json",
      vhost_config_file: "data/php-fpm/vhosts.json",
      scheduled_task_config_file: "conf/scheduled-tasks.json",
      security_audit_file: "audit/security-audit.ndjson",
      security_audit_blob_dir: "audit/security-audit-blobs",
      cache_rules_file: "conf/cache-rules.json",
      cache_store_file: "conf/cache-store.json",
      rules_file: "rules/tukuyomi.conf",
      override_rules_dir: "conf/rules",
      upstream_runtime_file: "conf/upstream-runtime.json",
      bypass_file: "conf/waf-bypass.json",
      country_block_file: "conf/country-block.json",
      rate_limit_file: "conf/rate-limit.json",
      bot_defense_file: "conf/bot-defense.json",
      semantic_file: "conf/semantic.json",
      notification_file: "conf/notifications.json",
      ip_reputation_file: "conf/ip-reputation.json",
      log_file: "",
      crs_setup_file: "rules/crs/crs-setup.conf",
      crs_rules_dir: "rules/crs/rules",
      crs_disabled_file: "conf/crs-disabled.conf",
    },
    proxy: {
      rollback_history_size: 8,
      engine: {
        mode: "tukuyomi_proxy",
      },
    },
    crs: {
      enable: true,
    },
    fp_tuner: {
      endpoint: "",
      model: "",
      timeout_sec: 15,
      require_approval: true,
      approval_ttl_sec: 600,
      audit_file: "audit/fp-tuner-audit.ndjson",
    },
    observability: {
      tracing: {
        enabled: false,
        service_name: "tukuyomi",
        otlp_endpoint: "",
        insecure: false,
        sample_ratio: 1,
      },
    },
  };
}

function cloneListenerAdminConfig(value: ListenerAdminConfig): ListenerAdminConfig {
  return JSON.parse(JSON.stringify(value)) as ListenerAdminConfig;
}

function normalizeListenerAdminConfig(value: Partial<ListenerAdminConfig> | null | undefined): ListenerAdminConfig {
  const base = createEmptyListenerAdminConfig();
  if (!value) return base;
  return {
    ...base,
    ...value,
    server: {
      ...base.server,
      ...value.server,
      proxy_protocol: {
        ...base.server.proxy_protocol,
        ...value.server?.proxy_protocol,
        trusted_cidrs: Array.isArray(value.server?.proxy_protocol?.trusted_cidrs) ? [...value.server.proxy_protocol.trusted_cidrs] : [],
      },
      tls: {
        ...base.server.tls,
        ...value.server?.tls,
      },
      http3: {
        ...base.server.http3,
        ...value.server?.http3,
      },
    },
    runtime: {
      ...base.runtime,
      ...value.runtime,
    },
    request_metadata: {
      ...base.request_metadata,
      ...value.request_metadata,
      country: {
        ...base.request_metadata.country,
        ...value.request_metadata?.country,
      },
    },
    admin: {
      ...base.admin,
      ...value.admin,
      trusted_cidrs: Array.isArray(value.admin?.trusted_cidrs) ? [...value.admin.trusted_cidrs] : [],
      cors_allowed_origins: Array.isArray(value.admin?.cors_allowed_origins) ? [...value.admin.cors_allowed_origins] : [],
      proxy_protocol: {
        ...base.admin.proxy_protocol,
        ...value.admin?.proxy_protocol,
        trusted_cidrs: Array.isArray(value.admin?.proxy_protocol?.trusted_cidrs) ? [...value.admin.proxy_protocol.trusted_cidrs] : [],
      },
      rate_limit: {
        ...base.admin.rate_limit,
        ...value.admin?.rate_limit,
      },
    },
    storage: {
      ...base.storage,
      ...value.storage,
    },
    paths: {
      ...base.paths,
      ...value.paths,
    },
    proxy: {
      ...base.proxy,
      ...value.proxy,
      engine: {
        ...base.proxy.engine,
        ...value.proxy?.engine,
      },
    },
    crs: {
      ...base.crs,
      ...value.crs,
    },
    fp_tuner: {
      ...base.fp_tuner,
      ...value.fp_tuner,
    },
    observability: {
      ...base.observability,
      ...value.observability,
      tracing: {
        ...base.observability.tracing,
        ...value.observability?.tracing,
      },
    },
  };
}

function stringListToMultiline(values: string[] | null | undefined) {
  return Array.isArray(values) ? values.join("\n") : "";
}

function multilineToStringList(value: string) {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function createEmptySecretStatus(): SecretStatus {
  return {
    admin_api_key_primary_configured: false,
    admin_api_key_secondary_configured: false,
    admin_session_secret_configured: false,
    storage_db_dsn_configured: false,
    security_audit_key_source: "config",
    security_audit_encryption_key_id: "",
    security_audit_encryption_key_configured: false,
    security_audit_hmac_key_id: "",
    security_audit_hmac_key_configured: false,
    fp_tuner_api_key_configured: false,
  };
}

export default function SettingsPanel() {
  const { tx } = useI18n();
  const [operatorIdentityInput, setOperatorIdentityInput] = useState(() => getOperatorIdentity());
  const [helperNotice, setHelperNotice] = useState("");
  const [helperError, setHelperError] = useState("");
  const [checking, setChecking] = useState(false);
  const [manifestDownloading, setManifestDownloading] = useState(false);
  const [configLoading, setConfigLoading] = useState(true);
  const [configSaving, setConfigSaving] = useState(false);
  const [etag, setETag] = useState("");
  const [configFile, setConfigFile] = useState("");
  const [restartRequired, setRestartRequired] = useState(true);
  const [listenerAdminConfig, setListenerAdminConfig] = useState<ListenerAdminConfig>(createEmptyListenerAdminConfig());
  const [serverConfig, setServerConfig] = useState<ListenerAdminConfig>(createEmptyListenerAdminConfig());
  const [secretStatus, setSecretStatus] = useState<SecretStatus>(createEmptySecretStatus());
  const [runtime, setRuntime] = useState<ListenerAdminRuntime | null>(null);
  const [configNotice, setConfigNotice] = useState("");
  const [configError, setConfigError] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const { session, refresh } = useAuth();
  const { readOnly } = useAdminRuntime();

  const hasOperatorIdentity = useMemo(
    () => operatorIdentityInput.trim().length > 0,
    [operatorIdentityInput],
  );

  const dirty = useMemo(
    () => JSON.stringify(listenerAdminConfig) !== JSON.stringify(serverConfig),
    [listenerAdminConfig, serverConfig],
  );

  const driftItems = useMemo(() => {
    return computeSettingsRuntimeDrift(listenerAdminConfig, runtime, tx);
  }, [listenerAdminConfig, runtime, tx]);

  const loadSettingsConfig = useCallback(async () => {
    setConfigLoading(true);
    setConfigError("");
    try {
      const data = await apiGetJson<ListenerAdminResponse>("/settings/listener-admin");
      const next = cloneListenerAdminConfig(normalizeListenerAdminConfig(data.config));
      setListenerAdminConfig(next);
      setServerConfig(cloneListenerAdminConfig(next));
      setSecretStatus(data.secrets ?? createEmptySecretStatus());
      setETag(data.etag ?? "");
      setConfigFile(data.config_file ?? "");
      setRestartRequired(data.restart_required !== false);
      setRuntime(data.runtime ?? null);
      setConfigNotice("");
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setConfigError(message);
    } finally {
      setConfigLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSettingsConfig();
  }, [loadSettingsConfig]);

  function onSaveOperatorIdentity(e: FormEvent) {
    e.preventDefault();
    setOperatorIdentity(operatorIdentityInput);
    setHelperError("");
    setHelperNotice(tx("Saved. This browser now sends the configured operator identity on /tukuyomi-api requests."));
  }

  function onClearOperatorIdentity() {
    setOperatorIdentityInput("");
    setOperatorIdentity("");
    setHelperError("");
    setHelperNotice(tx("Operator identity cleared."));
  }

  async function onVerify() {
    setChecking(true);
    setHelperError("");
    setHelperNotice("");

    try {
      await apiGetJson("/status");
      await refresh();
      setHelperNotice(tx("Verified. Current admin session is valid."));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setHelperError(tx("Verification failed: {message}", { message }));
    } finally {
      setChecking(false);
    }
  }

  async function onDownloadManifest() {
    setManifestDownloading(true);
    setHelperError("");
    setHelperNotice("");

    try {
      const { blob, filename } = await apiGetBinary("/verify-manifest");
      const objectUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = objectUrl;
      a.download = filename || "tukuyomi-verify-manifest.json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(objectUrl);
      setHelperNotice(tx("Verify manifest downloaded."));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setHelperError(tx("Verify manifest download failed: {message}", { message }));
    } finally {
      setManifestDownloading(false);
    }
  }

  async function onValidateConfig() {
    setConfigSaving(true);
    setConfigError("");
    setConfigNotice("");
    try {
      const data = await apiPostJson<ListenerAdminResponse>("/settings/listener-admin/validate", {
        config: listenerAdminConfig,
      });
      const next = cloneListenerAdminConfig(normalizeListenerAdminConfig(data.config ?? listenerAdminConfig));
      setListenerAdminConfig(next);
      setSecretStatus(data.secrets ?? createEmptySecretStatus());
      setConfigNotice(tx("Validation passed. Global config changes here still require restart after save."));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setConfigError(message);
    } finally {
      setConfigSaving(false);
    }
  }

  async function onSaveConfig() {
    setConfigSaving(true);
    setConfigError("");
    setConfigNotice("");
    try {
      const data = await apiPutJson<ListenerAdminResponse>(
        "/settings/listener-admin",
        { config: listenerAdminConfig },
        { headers: { "If-Match": etag } },
      );
      const next = cloneListenerAdminConfig(normalizeListenerAdminConfig(data.config ?? listenerAdminConfig));
      setListenerAdminConfig(next);
      setServerConfig(cloneListenerAdminConfig(next));
      setSecretStatus(data.secrets ?? createEmptySecretStatus());
      setETag(data.etag ?? "");
      setRestartRequired(data.restart_required !== false);
      setRuntime(data.runtime ?? null);
      setConfigNotice(tx("Saved to DB app_config. Restart tukuyomi to apply global config changes from this panel."));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setConfigError(message);
    } finally {
      setConfigSaving(false);
    }
  }

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">{tx("Settings")}</h1>
        <div className="flex items-center gap-2">
          <span className={`px-2 py-0.5 text-xs rounded ${session.authenticated ? "bg-green-100 text-green-800" : "bg-amber-100 text-amber-800"}`}>
            {tx("session")} {session.authenticated ? tx("active") : tx("missing")}
          </span>
          <span className={`px-2 py-0.5 text-xs rounded ${hasOperatorIdentity ? "bg-green-100 text-green-800" : "bg-gray-100 text-gray-700"}`}>
            {tx("actor")} {hasOperatorIdentity ? tx("configured") : tx("not set")}
          </span>
        </div>
      </header>

      <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-sm font-medium">{tx("Global Product Config")}</div>
              <p className="text-xs text-neutral-500">
              {tx("Edit listener, runtime, storage policy, and observability settings stored in DB app_config. DB connection fields still come from the bootstrap config file.")}
              </p>
            </div>
          <div className="flex flex-wrap items-center gap-2 text-xs text-neutral-500">
            <span className="rounded bg-neutral-100 px-2 py-1">ETag {etag || "-"}</span>
            <span className="rounded bg-neutral-100 px-2 py-1">{tx("Bootstrap Config")}: {configFile || "-"}</span>
            <span className={`rounded px-2 py-1 ${restartRequired ? "bg-amber-100 text-amber-900" : "bg-green-100 text-green-800"}`}>
              {restartRequired ? tx("Restart required") : tx("No restart required")}
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={() => void loadSettingsConfig()} disabled={configLoading || configSaving}>
            {tx("Load")}
          </button>
          <button type="button" onClick={() => void onValidateConfig()} disabled={configLoading || configSaving}>
            {configSaving ? tx("Working...") : tx("Validate")}
          </button>
          <button type="button" onClick={() => void onSaveConfig()} disabled={readOnly || configLoading || configSaving || !etag || !dirty}>
            {tx("Save config only")}
          </button>
        </div>

        {configNotice ? (
          <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{configNotice}</div>
        ) : null}
        {configError ? (
          <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{configError}</div>
        ) : null}

        <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
          {tx("Listener, runtime, storage policy, and observability settings here are restart-required startup config. Saving updates DB app_config; db_driver, db_path, and db_dsn stay bootstrap-only in config.json.")}
        </div>

        {configLoading ? (
          <div className="text-xs text-neutral-500">{tx("Loading settings config...")}</div>
        ) : (
          <>
            <div className="grid gap-4 xl:grid-cols-2">
              <section className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
                <div>
                  <div className="text-sm font-medium">{tx("Listener & Network")}</div>
                  <p className="text-xs text-neutral-500">
                    {tx("Public listener, TLS, HTTP redirect, HTTP/3, and overload controls for the main proxy listener.")}
                  </p>
                </div>

                <Field label={tx("Public Listen Address")}>
                  <input
                    value={listenerAdminConfig.server.listen_addr}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, listen_addr: e.target.value },
                    }))}
                    className="w-full rounded border border-neutral-200 bg-white"
                    placeholder=":9090"
                  />
                </Field>

                <label className="flex items-center gap-2 text-xs text-neutral-700">
                  <input
                    type="checkbox"
                    checked={listenerAdminConfig.server.proxy_protocol.enabled}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: {
                        ...current.server,
                        proxy_protocol: { ...current.server.proxy_protocol, enabled: e.target.checked },
                      },
                    }))}
                  />
                  {tx("Enable PROXY Protocol on the public listener")}
                </label>

                <Field label={tx("Trusted PROXY Peers CIDRs (one per line)")}>
                  <textarea
                    value={stringListToMultiline(listenerAdminConfig.server.proxy_protocol.trusted_cidrs)}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: {
                        ...current.server,
                        proxy_protocol: {
                          ...current.server.proxy_protocol,
                          trusted_cidrs: multilineToStringList(e.target.value),
                        },
                      },
                    }))}
                    className="w-full rounded border border-neutral-200 bg-white"
                    rows={4}
                  />
                  <div className="mt-1 text-xs text-neutral-500">
                    {tx("Trusted peers may supply HAProxy PROXY headers. The public HTTP redirect listener follows this same trust list.")}
                  </div>
                </Field>

                <div className="grid gap-3 sm:grid-cols-2">
                  <NumberField
                    label={tx("Read Timeout Seconds")}
                    value={listenerAdminConfig.server.read_timeout_sec}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, read_timeout_sec: value },
                    }))}
                    hint={tx("Total inbound read budget for the request line, headers, and request body. Use this to bound slow body uploads.")}
                  />
                  <NumberField
                    label={tx("Read Header Timeout Seconds")}
                    value={listenerAdminConfig.server.read_header_timeout_sec}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, read_header_timeout_sec: value },
                    }))}
                    hint={tx("Header-only budget before the body starts. This does not replace the total read timeout above.")}
                  />
                  <NumberField
                    label={tx("Write Timeout Seconds")}
                    value={listenerAdminConfig.server.write_timeout_sec}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, write_timeout_sec: value },
                    }))}
                  />
                  <NumberField
                    label={tx("Idle Timeout Seconds")}
                    value={listenerAdminConfig.server.idle_timeout_sec}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, idle_timeout_sec: value },
                    }))}
                  />
                  <NumberField
                    label={tx("Graceful Shutdown Timeout Seconds")}
                    value={listenerAdminConfig.server.graceful_shutdown_timeout_sec}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, graceful_shutdown_timeout_sec: value },
                    }))}
                    hint={tx("Maximum drain time for SIGTERM, SIGINT, SIGHUP, and socket-activated service replacement before force close.")}
                  />
                  <NumberField
                    label={tx("Max Header Bytes")}
                    value={listenerAdminConfig.server.max_header_bytes}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, max_header_bytes: value },
                    }))}
                  />
                </div>

                <label className="flex items-center gap-2 text-xs text-neutral-700">
                  <input
                    type="checkbox"
                    checked={listenerAdminConfig.server.tls.enabled}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: {
                        ...current.server,
                        tls: { ...current.server.tls, enabled: e.target.checked },
                      },
                    }))}
                  />
                  {tx("Enable built-in TLS on the public listener")}
                </label>

                <div className="grid gap-3 sm:grid-cols-2">
                  <Field label={tx("TLS Certificate File")}>
                    <input
                      value={listenerAdminConfig.server.tls.cert_file}
                      onChange={(e) => setListenerAdminConfig((current) => ({
                        ...current,
                        server: {
                          ...current.server,
                          tls: { ...current.server.tls, cert_file: e.target.value },
                        },
                      }))}
                      className="w-full rounded border border-neutral-200 bg-white"
                      placeholder="/etc/tukuyomi/tls/fullchain.pem"
                    />
                  </Field>
                  <Field label={tx("TLS Key File")}>
                    <input
                      value={listenerAdminConfig.server.tls.key_file}
                      onChange={(e) => setListenerAdminConfig((current) => ({
                        ...current,
                        server: {
                          ...current.server,
                          tls: { ...current.server.tls, key_file: e.target.value },
                        },
                      }))}
                      className="w-full rounded border border-neutral-200 bg-white"
                      placeholder="/etc/tukuyomi/tls/privkey.pem"
                    />
                  </Field>
                  <Field label={tx("TLS Min Version")}>
                    <select
                      value={listenerAdminConfig.server.tls.min_version}
                      onChange={(e) => setListenerAdminConfig((current) => ({
                        ...current,
                        server: {
                          ...current.server,
                          tls: { ...current.server.tls, min_version: e.target.value },
                        },
                      }))}
                      className="w-full rounded border border-neutral-200 bg-white"
                    >
                      <option value="tls1.2">tls1.2</option>
                      <option value="tls1.3">tls1.3</option>
                    </select>
                  </Field>
                  <Field label={tx("HTTP Redirect Address")}>
                    <input
                      value={listenerAdminConfig.server.tls.http_redirect_addr}
                      onChange={(e) => setListenerAdminConfig((current) => ({
                        ...current,
                        server: {
                          ...current.server,
                          tls: { ...current.server.tls, http_redirect_addr: e.target.value },
                        },
                      }))}
                      className="w-full rounded border border-neutral-200 bg-white"
                      placeholder=":80"
                    />
                  </Field>
                </div>

                <label className="flex items-center gap-2 text-xs text-neutral-700">
                  <input
                    type="checkbox"
                    checked={listenerAdminConfig.server.tls.redirect_http}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: {
                        ...current.server,
                        tls: { ...current.server.tls, redirect_http: e.target.checked },
                      },
                    }))}
                  />
                  {tx("Redirect plain HTTP to HTTPS")}
                </label>

                <label className="flex items-center gap-2 text-xs text-neutral-700">
                  <input
                    type="checkbox"
                    checked={listenerAdminConfig.server.http3.enabled}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: {
                        ...current.server,
                        http3: { ...current.server.http3, enabled: e.target.checked },
                      },
                    }))}
                  />
                  {tx("Enable HTTP/3 on the public listener")}
                </label>

                <NumberField
                  label={tx("HTTP/3 Alt-Svc Max Age Seconds")}
                  value={listenerAdminConfig.server.http3.alt_svc_max_age_sec}
                  onChange={(value) => setListenerAdminConfig((current) => ({
                    ...current,
                    server: {
                      ...current.server,
                      http3: { ...current.server.http3, alt_svc_max_age_sec: value },
                    },
                  }))}
                />
              </section>

              <section className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
                <div>
                  <div className="text-sm font-medium">{tx("Admin")}</div>
                  <p className="text-xs text-neutral-500">
                    {tx("Admin path layout, optional split listener address, external exposure policy, trusted CIDRs, read-only mode, and admin rate limits. Built-in admin TLS is not provided in this slice; use a trusted network or front-proxy TLS termination when admin.listen_addr is set.")}
                  </p>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <Field label={tx("API Base Path")}>
                    <input
                      value={listenerAdminConfig.admin.api_base_path}
                      onChange={(e) => setListenerAdminConfig((current) => ({
                        ...current,
                        admin: { ...current.admin, api_base_path: e.target.value },
                      }))}
                      className="w-full rounded border border-neutral-200 bg-white"
                      placeholder="/tukuyomi-api"
                    />
                  </Field>
                  <Field label={tx("UI Base Path")}>
                    <input
                      value={listenerAdminConfig.admin.ui_base_path}
                      onChange={(e) => setListenerAdminConfig((current) => ({
                        ...current,
                        admin: { ...current.admin, ui_base_path: e.target.value },
                      }))}
                      className="w-full rounded border border-neutral-200 bg-white"
                      placeholder="/tukuyomi-ui"
                    />
                  </Field>
                  <Field label={tx("Admin Listen Address")}>
                    <input
                      value={listenerAdminConfig.admin.listen_addr}
                      onChange={(e) => setListenerAdminConfig((current) => ({
                        ...current,
                        admin: { ...current.admin, listen_addr: e.target.value },
                      }))}
                      className="w-full rounded border border-neutral-200 bg-white"
                      placeholder=":9091"
                    />
                    <div className="mt-1 text-xs text-neutral-500">
                      {tx("Leave empty to share the public listener. When set, admin UI/API move to a separate plain-HTTP listener and no longer ride on the public proxy listener.")}
                    </div>
                  </Field>
                </div>

                <label className="flex items-center gap-2 text-xs text-neutral-700">
                  <input
                    type="checkbox"
                    checked={listenerAdminConfig.admin.proxy_protocol.enabled}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      admin: {
                        ...current.admin,
                        proxy_protocol: { ...current.admin.proxy_protocol, enabled: e.target.checked },
                      },
                    }))}
                  />
                  {tx("Enable PROXY Protocol on the admin listener")}
                </label>

                <Field label={tx("Admin Trusted PROXY Peers CIDRs (one per line)")}>
                  <textarea
                    value={stringListToMultiline(listenerAdminConfig.admin.proxy_protocol.trusted_cidrs)}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      admin: {
                        ...current.admin,
                        proxy_protocol: {
                          ...current.admin.proxy_protocol,
                          trusted_cidrs: multilineToStringList(e.target.value),
                        },
                      },
                    }))}
                    className="w-full rounded border border-neutral-200 bg-white"
                    rows={4}
                  />
                  <div className="mt-1 text-xs text-neutral-500">
                    {tx("Only available when Admin Listen Address is set. Trusted peers may supply HAProxy PROXY headers to the split admin listener.")}
                  </div>
                </Field>

                <Field label={tx("External Mode")}>
                  <select
                    value={listenerAdminConfig.admin.external_mode}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      admin: { ...current.admin, external_mode: e.target.value },
                    }))}
                    className="w-full rounded border border-neutral-200 bg-white"
                  >
                    <option value="deny_external">deny_external</option>
                    <option value="api_only_external">api_only_external</option>
                    <option value="full_external">full_external</option>
                  </select>
                </Field>

                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="flex items-center gap-2 text-xs text-neutral-700">
                    <input
                      type="checkbox"
                      checked={listenerAdminConfig.admin.trust_forwarded_for}
                      onChange={(e) => setListenerAdminConfig((current) => ({
                        ...current,
                        admin: { ...current.admin, trust_forwarded_for: e.target.checked },
                      }))}
                    />
                    {tx("Trust Forwarded For")}
                  </label>
                  <label className="flex items-center gap-2 text-xs text-neutral-700">
                    <input
                      type="checkbox"
                      checked={listenerAdminConfig.admin.read_only}
                      onChange={(e) => setListenerAdminConfig((current) => ({
                        ...current,
                        admin: { ...current.admin, read_only: e.target.checked },
                      }))}
                    />
                    {tx("Admin read only")}
                  </label>
                </div>

                <Field label={tx("Trusted CIDRs (one per line)")}>
                  <textarea
                    value={stringListToMultiline(listenerAdminConfig.admin.trusted_cidrs)}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      admin: { ...current.admin, trusted_cidrs: multilineToStringList(e.target.value) },
                    }))}
                    className="w-full rounded border border-neutral-200 bg-white"
                    rows={5}
                  />
                </Field>

                <Field label={tx("CORS Allowed Origins (one per line)")}>
                  <textarea
                    value={stringListToMultiline(listenerAdminConfig.admin.cors_allowed_origins)}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      admin: { ...current.admin, cors_allowed_origins: multilineToStringList(e.target.value) },
                    }))}
                    className="w-full rounded border border-neutral-200 bg-white"
                    rows={4}
                  />
                </Field>

                <label className="flex items-center gap-2 text-xs text-neutral-700">
                  <input
                    type="checkbox"
                    checked={listenerAdminConfig.admin.rate_limit.enabled}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      admin: {
                        ...current.admin,
                        rate_limit: { ...current.admin.rate_limit, enabled: e.target.checked },
                      },
                    }))}
                  />
                  {tx("Enable admin rate limit")}
                </label>

                <div className="grid gap-3 sm:grid-cols-2">
                  <NumberField
                    label={tx("Rate Limit RPS")}
                    value={listenerAdminConfig.admin.rate_limit.rps}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      admin: {
                        ...current.admin,
                        rate_limit: { ...current.admin.rate_limit, rps: value },
                      },
                    }))}
                  />
                  <NumberField
                    label={tx("Rate Limit Burst")}
                    value={listenerAdminConfig.admin.rate_limit.burst}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      admin: {
                        ...current.admin,
                        rate_limit: { ...current.admin.rate_limit, burst: value },
                      },
                    }))}
                  />
                  <NumberField
                    label={tx("Rate Limit Status Code")}
                    value={listenerAdminConfig.admin.rate_limit.status_code}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      admin: {
                        ...current.admin,
                        rate_limit: { ...current.admin.rate_limit, status_code: value },
                      },
                    }))}
                  />
                  <NumberField
                    label={tx("Retry After Seconds")}
                    value={listenerAdminConfig.admin.rate_limit.retry_after_seconds}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      admin: {
                        ...current.admin,
                        rate_limit: { ...current.admin.rate_limit, retry_after_seconds: value },
                      },
                    }))}
                  />
                </div>
              </section>
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              <section className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
                <div>
                  <div className="text-sm font-medium">{tx("Runtime")}</div>
                  <p className="text-xs text-neutral-500">
                    {tx("Process resource limits plus request queue and overload controls loaded at startup.")}
                  </p>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <NumberField
                    label={tx("GOMAXPROCS")}
                    value={listenerAdminConfig.runtime.gomaxprocs}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      runtime: { ...current.runtime, gomaxprocs: value },
                    }))}
                  />
                  <NumberField
                    label={tx("Memory Limit MB")}
                    value={listenerAdminConfig.runtime.memory_limit_mb}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      runtime: { ...current.runtime, memory_limit_mb: value },
                    }))}
                  />
                  <NumberField
                    label={tx("Max Concurrent Requests")}
                    value={listenerAdminConfig.server.max_concurrent_requests}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, max_concurrent_requests: value },
                    }))}
                  />
                  <NumberField
                    label={tx("Max Queued Requests")}
                    value={listenerAdminConfig.server.max_queued_requests}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, max_queued_requests: value },
                    }))}
                  />
                  <NumberField
                    label={tx("Queued Request Timeout MS")}
                    value={listenerAdminConfig.server.queued_request_timeout_ms}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, queued_request_timeout_ms: value },
                    }))}
                  />
                  <NumberField
                    label={tx("Max Concurrent Proxy Requests")}
                    value={listenerAdminConfig.server.max_concurrent_proxy_requests}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, max_concurrent_proxy_requests: value },
                    }))}
                  />
                  <NumberField
                    label={tx("Max Queued Proxy Requests")}
                    value={listenerAdminConfig.server.max_queued_proxy_requests}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, max_queued_proxy_requests: value },
                    }))}
                  />
                  <NumberField
                    label={tx("Queued Proxy Request Timeout MS")}
                    value={listenerAdminConfig.server.queued_proxy_request_timeout_ms}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      server: { ...current.server, queued_proxy_request_timeout_ms: value },
                    }))}
                  />
                </div>
              </section>

              <section className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
                <div>
                  <div className="text-sm font-medium">{tx("Storage")}</div>
                  <p className="text-xs text-neutral-500">
                    {tx("Database storage policy and bootstrap connection status. Driver, path, and DSN are read from the bootstrap config file before DB is opened.")}
                  </p>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <Field label={tx("DB Driver")}>
	                    <select
	                      value={listenerAdminConfig.storage.db_driver}
	                      disabled
	                      className="w-full rounded border border-neutral-200 bg-neutral-100 text-neutral-600"
	                    >
                      <option value="sqlite">sqlite</option>
                      <option value="mysql">mysql</option>
                      <option value="pgsql">pgsql</option>
                    </select>
                  </Field>
                  <Field label={tx("DB Path")}>
	                    <input
	                      value={listenerAdminConfig.storage.db_path}
	                      readOnly
	                      className="w-full rounded border border-neutral-200 bg-neutral-100 text-neutral-600"
	                      placeholder="db/tukuyomi.db"
	                    />
                  </Field>
                  <NumberField
                    label={tx("DB Retention Days")}
                    value={listenerAdminConfig.storage.db_retention_days}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      storage: { ...current.storage, db_retention_days: value },
                    }))}
                  />
                  <NumberField
                    label={tx("DB Sync Interval Seconds")}
                    value={listenerAdminConfig.storage.db_sync_interval_sec}
                    onChange={(value) => setListenerAdminConfig((current) => ({
                      ...current,
                      storage: { ...current.storage, db_sync_interval_sec: value },
                    }))}
                  />
                </div>

                <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
	                  {tx("DB connection is bootstrap-only. Current DSN status: {state}. Change db_driver, db_path, or db_dsn in the bootstrap config file, run migrations/import as needed, then restart.", {
	                    state: secretStatus.storage_db_dsn_configured ? tx("configured") : tx("not configured"),
	                  })}
                </div>
              </section>
            </div>

            <section className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
              <div>
                <div className="text-sm font-medium">{tx("Observability")}</div>
                <p className="text-xs text-neutral-500">
                  {tx("Tracing exporter settings loaded at startup. When tracing is enabled, service name and OTLP endpoint are required.")}
                </p>
              </div>

              <label className="flex items-center gap-2 text-xs text-neutral-700">
                <input
                  type="checkbox"
                  checked={listenerAdminConfig.observability.tracing.enabled}
                  onChange={(e) => setListenerAdminConfig((current) => ({
                    ...current,
                    observability: {
                      ...current.observability,
                      tracing: { ...current.observability.tracing, enabled: e.target.checked },
                    },
                  }))}
                />
                {tx("Enable tracing")}
              </label>

              <div className="grid gap-3 sm:grid-cols-2">
                <Field label={tx("Tracing Service Name")}>
                  <input
                    value={listenerAdminConfig.observability.tracing.service_name}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      observability: {
                        ...current.observability,
                        tracing: { ...current.observability.tracing, service_name: e.target.value },
                      },
                    }))}
                    className="w-full rounded border border-neutral-200 bg-white"
                    placeholder="tukuyomi"
                  />
                </Field>
                <Field label={tx("OTLP Endpoint")}>
                  <input
                    value={listenerAdminConfig.observability.tracing.otlp_endpoint}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      observability: {
                        ...current.observability,
                        tracing: { ...current.observability.tracing, otlp_endpoint: e.target.value },
                      },
                    }))}
                    className="w-full rounded border border-neutral-200 bg-white"
                    placeholder="http://otel-collector:4318"
                  />
                </Field>
                <FloatField
                  label={tx("Tracing Sample Ratio")}
                  value={listenerAdminConfig.observability.tracing.sample_ratio}
                  onChange={(value) => setListenerAdminConfig((current) => ({
                    ...current,
                    observability: {
                      ...current.observability,
                      tracing: { ...current.observability.tracing, sample_ratio: value },
                    },
                  }))}
                />
                <label className="flex items-center gap-2 text-xs text-neutral-700">
                  <input
                    type="checkbox"
                    checked={listenerAdminConfig.observability.tracing.insecure}
                    onChange={(e) => setListenerAdminConfig((current) => ({
                      ...current,
                      observability: {
                        ...current.observability,
                        tracing: { ...current.observability.tracing, insecure: e.target.checked },
                      },
                    }))}
                  />
                  {tx("Use insecure OTLP transport")}
                </label>
              </div>
            </section>

            <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
              <div>
                <div className="text-sm font-medium">{tx("Secret-backed Values")}</div>
                <p className="text-xs text-neutral-500">
                  {tx("Sensitive fields are not exposed here as plain text. This panel shows whether they are configured and any safe key identifiers we can disclose.")}
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 text-sm">
                <SecretMetric label={tx("Admin API Key Primary")} configured={secretStatus.admin_api_key_primary_configured} />
                <SecretMetric label={tx("Admin API Key Secondary")} configured={secretStatus.admin_api_key_secondary_configured} />
                <SecretMetric label={tx("Admin Session Secret")} configured={secretStatus.admin_session_secret_configured} />
                <SecretMetric label={tx("Storage DB DSN")} configured={secretStatus.storage_db_dsn_configured} />
                <SecretMetric label={tx("FP Tuner API Key")} configured={secretStatus.fp_tuner_api_key_configured} />
                <RuntimeMetric label={tx("Security Audit Key Source")} value={secretStatus.security_audit_key_source} />
                <RuntimeMetric label={tx("Security Audit Encryption Key ID")} value={secretStatus.security_audit_encryption_key_id} />
                <SecretMetric label={tx("Security Audit Encryption Key")} configured={secretStatus.security_audit_encryption_key_configured} />
                <RuntimeMetric label={tx("Security Audit HMAC Key ID")} value={secretStatus.security_audit_hmac_key_id} />
                <SecretMetric label={tx("Security Audit HMAC Key")} configured={secretStatus.security_audit_hmac_key_configured} />
              </div>
            </section>

            <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="text-sm font-medium">{tx("Advanced Config")}</div>
                  <p className="text-xs text-neutral-500">
                    {tx("Paths, fp-tuner, rollback history, and CRS defaults are advanced operator settings. Expand only when you intend to edit dangerous product-wide values.")}
                  </p>
                </div>
                <button type="button" onClick={() => setShowAdvanced((current) => !current)}>
                  {showAdvanced ? tx("Hide advanced config") : tx("Show advanced config")}
                </button>
              </div>

              {showAdvanced ? (
                <div className="space-y-4">
                  <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
	                    {tx("Advanced paths and global support files affect the whole product. Runtime-owned JSON paths are seed/import/export locations after DB bootstrap. Validate before save and restart after changes.")}
                  </div>

                  <div className="grid gap-4 xl:grid-cols-2">
                    <section className="rounded border border-neutral-200 bg-neutral-50 p-4 space-y-3">
                      <div className="text-sm font-medium">{tx("Advanced Paths")}</div>
                      <div className="grid gap-3 sm:grid-cols-2">
	                        <Field label={tx("Proxy Seed File")}><input value={listenerAdminConfig.paths.proxy_config_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, proxy_config_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Site Seed File")}><input value={listenerAdminConfig.paths.site_config_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, site_config_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("PHP Runtime Inventory File")}><input value={listenerAdminConfig.paths.php_runtime_inventory_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, php_runtime_inventory_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Vhost Config File")}><input value={listenerAdminConfig.paths.vhost_config_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, vhost_config_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Scheduled Task Seed File")}><input value={listenerAdminConfig.paths.scheduled_task_config_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, scheduled_task_config_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Security Audit File")}><input value={listenerAdminConfig.paths.security_audit_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, security_audit_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Security Audit Blob Dir")}><input value={listenerAdminConfig.paths.security_audit_blob_dir} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, security_audit_blob_dir: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Cache Rules File")}><input value={listenerAdminConfig.paths.cache_rules_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, cache_rules_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Cache Store File")}><input value={listenerAdminConfig.paths.cache_store_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, cache_store_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Base Rule Asset")}><input value={listenerAdminConfig.paths.rules_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, rules_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Override Rule Reference Prefix")}><input value={listenerAdminConfig.paths.override_rules_dir} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, override_rules_dir: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Upstream Runtime Seed File")}><input value={listenerAdminConfig.paths.upstream_runtime_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, upstream_runtime_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Bypass File")}><input value={listenerAdminConfig.paths.bypass_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, bypass_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Country Block File")}><input value={listenerAdminConfig.paths.country_block_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, country_block_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Rate Limit File")}><input value={listenerAdminConfig.paths.rate_limit_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, rate_limit_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Bot Defense File")}><input value={listenerAdminConfig.paths.bot_defense_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, bot_defense_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Semantic File")}><input value={listenerAdminConfig.paths.semantic_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, semantic_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Notification File")}><input value={listenerAdminConfig.paths.notification_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, notification_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("IP Reputation File")}><input value={listenerAdminConfig.paths.ip_reputation_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, ip_reputation_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("Legacy WAF Log Import File")}><input value={listenerAdminConfig.paths.log_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, log_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("CRS Setup File")}><input value={listenerAdminConfig.paths.crs_setup_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, crs_setup_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("CRS Rules Dir")}><input value={listenerAdminConfig.paths.crs_rules_dir} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, crs_rules_dir: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("CRS Disabled File")}><input value={listenerAdminConfig.paths.crs_disabled_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, paths: { ...current.paths, crs_disabled_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                      </div>
                    </section>

                    <section className="rounded border border-neutral-200 bg-neutral-50 p-4 space-y-3">
                      <div className="text-sm font-medium">{tx("Proxy Engine, CRS, Rollback, and FP Tuner")}</div>
                      <div className="grid gap-3 sm:grid-cols-2">
                        <Field label={tx("Proxy Engine")}>
                          <input
                            value={listenerAdminConfig.proxy.engine.mode || "tukuyomi_proxy"}
                            readOnly
                            className="w-full rounded border border-neutral-200 bg-neutral-100 text-neutral-700"
                          />
                          <p className="mt-1 text-[11px] text-neutral-500">
                            {tx("tukuyomi_proxy is the built-in proxy engine. The legacy net_http bridge has been removed. Restart required after config file changes.")}
                          </p>
                        </Field>
                        <NumberField label={tx("Proxy Rollback History Size")} value={listenerAdminConfig.proxy.rollback_history_size} onChange={(value) => setListenerAdminConfig((current) => ({ ...current, proxy: { ...current.proxy, rollback_history_size: value } }))} />
                        <label className="flex items-center gap-2 text-xs text-neutral-700">
                          <input type="checkbox" checked={listenerAdminConfig.crs.enable} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, crs: { ...current.crs, enable: e.target.checked } }))} />
                          {tx("Enable CRS by default")}
                        </label>
                        <Field label={tx("FP Tuner Endpoint")}><input value={listenerAdminConfig.fp_tuner.endpoint} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, fp_tuner: { ...current.fp_tuner, endpoint: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <Field label={tx("FP Tuner Model")}><input value={listenerAdminConfig.fp_tuner.model} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, fp_tuner: { ...current.fp_tuner, model: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <NumberField label={tx("FP Tuner Timeout Seconds")} value={listenerAdminConfig.fp_tuner.timeout_sec} onChange={(value) => setListenerAdminConfig((current) => ({ ...current, fp_tuner: { ...current.fp_tuner, timeout_sec: value } }))} />
                        <Field label={tx("FP Tuner Audit File")}><input value={listenerAdminConfig.fp_tuner.audit_file} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, fp_tuner: { ...current.fp_tuner, audit_file: e.target.value } }))} className="w-full rounded border border-neutral-200 bg-white" /></Field>
                        <NumberField label={tx("FP Tuner Approval TTL Seconds")} value={listenerAdminConfig.fp_tuner.approval_ttl_sec} onChange={(value) => setListenerAdminConfig((current) => ({ ...current, fp_tuner: { ...current.fp_tuner, approval_ttl_sec: value } }))} />
                        <label className="flex items-center gap-2 text-xs text-neutral-700">
                          <input type="checkbox" checked={listenerAdminConfig.fp_tuner.require_approval} onChange={(e) => setListenerAdminConfig((current) => ({ ...current, fp_tuner: { ...current.fp_tuner, require_approval: e.target.checked } }))} />
                          {tx("Require FP Tuner approval")}
                        </label>
                      </div>
                      <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                        {tx("FP Tuner API key is currently {state}. Manage the literal key outside this panel.", {
                          state: secretStatus.fp_tuner_api_key_configured ? tx("configured") : tx("not configured"),
                        })}
                      </div>
                    </section>
                  </div>
                </div>
              ) : null}
            </section>

            {runtime ? (
              <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm font-medium">{tx("Current Runtime Snapshot")}</div>
                  <span className="text-xs text-neutral-500">{tx("Loaded by the running process before restart")}</span>
                </div>
                {driftItems.length > 0 ? (
                  <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                    {tx("Configured values differ from the current runtime until restart: {items}", {
                      items: driftItems.join(", "),
                    })}
                  </div>
                ) : null}
                <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 text-sm">
                  <RuntimeMetric label={tx("Current Listen Address")} value={runtime.listen_addr} />
                  <RuntimeMetric label={tx("Current API Base Path")} value={runtime.api_base_path} />
                  <RuntimeMetric label={tx("Current UI Base Path")} value={runtime.ui_base_path} />
                  <RuntimeMetric label={tx("Current Admin Listen Address")} value={runtime.admin_listen_addr} />
                  <RuntimeMetric label={tx("Current Public PROXY Protocol")} value={String(runtime.server_proxy_protocol_enabled ?? "-")} />
                  <RuntimeMetric label={tx("Current Admin PROXY Protocol")} value={String(runtime.admin_proxy_protocol_enabled ?? "-")} />
                  <RuntimeMetric label={tx("Current TLS")} value={String(runtime.server_tls_enabled ?? "-")} />
                  <RuntimeMetric label={tx("Current TLS Source")} value={runtime.server_tls_source} />
                  <RuntimeMetric label={tx("Current HTTP/3 Advertised")} value={String(runtime.server_http3_advertised ?? "-")} />
                  <RuntimeMetric label={tx("Current GOMAXPROCS")} value={runtime.runtime_gomaxprocs} />
                  <RuntimeMetric label={tx("Current Memory Limit MB")} value={runtime.runtime_memory_limit_mb} />
                  <RuntimeMetric label={tx("Current Graceful Shutdown Timeout Seconds")} value={runtime.server_graceful_shutdown_timeout_sec} />
                  <RuntimeMetric label={tx("Current Max Concurrent Requests")} value={runtime.server_max_concurrent_requests} />
                  <RuntimeMetric label={tx("Current Max Queued Requests")} value={runtime.server_max_queued_requests} />
                  <RuntimeMetric label={tx("Current Max Concurrent Proxy")} value={runtime.server_max_concurrent_proxy_requests} />
                  <RuntimeMetric label={tx("Current Max Queued Proxy")} value={runtime.server_max_queued_proxy_requests} />
                  <RuntimeMetric label={tx("Current Proxy Engine")} value={runtime.proxy_engine_mode} />
                  <RuntimeMetric label={tx("Current External Mode")} value={runtime.admin_external_mode} />
                  <RuntimeMetric label={tx("Current Read Only")} value={String(runtime.admin_read_only ?? "-")} />
                  <RuntimeMetric label={tx("Current Admin Rate Limit")} value={String(runtime.admin_rate_limit_enabled ?? "-")} />
                  <RuntimeMetric label={tx("Current DB Driver")} value={runtime.storage_db_driver} />
                  <RuntimeMetric label={tx("Current DB Path")} value={runtime.storage_db_path} />
                  <RuntimeMetric label={tx("Current Tracing")} value={String(runtime.tracing_enabled ?? "-")} />
                  <RuntimeMetric label={tx("Current Tracing Service")} value={runtime.tracing_service_name} />
                  <RuntimeMetric label={tx("Current OTLP Endpoint")} value={runtime.tracing_otlp_endpoint} />
                </div>
              </section>
            ) : null}
          </>
        )}
      </section>

      <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-3">
        <div className="space-y-2">
          <div className="text-sm font-medium">{tx("Verification Manifest")}</div>
          <p className="text-sm text-neutral-600">
            {tx("Export the current verify manifest scaffold for external WAF test runners before running browser and attack scenarios.")}
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={onDownloadManifest} disabled={manifestDownloading}>
              {manifestDownloading ? tx("Downloading...") : tx("Download Verify Manifest")}
            </button>
          </div>
        </div>

        <hr className="border-neutral-200" />

        <p className="text-sm text-neutral-600">
          {tx("Browser access now uses a signed admin session cookie. Sign in once on the login page, then use this panel to manage optional operator identity metadata and verify the current session.")}
        </p>

        <form onSubmit={onSaveOperatorIdentity} className="space-y-3">
          <div className="space-y-1">
            <label className="block text-xs text-neutral-600" htmlFor="operator-identity-input">
              {tx("Audit operator identity")}
            </label>
            <input
              id="operator-identity-input"
              type="text"
              value={operatorIdentityInput}
              onChange={(e) => setOperatorIdentityInput(e.target.value)}
              className="w-full rounded border border-neutral-200 bg-white"
              placeholder={tx("alice@example.com")}
            />
            <p className="text-xs text-neutral-500">
              {tx("Stored in localStorage and sent as")} <code>X-Tukuyomi-Actor</code> {tx("on admin API requests when set.")}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button type="submit">{tx("Save")}</button>
            <button type="button" onClick={onVerify} disabled={checking || !session.authenticated}>
              {checking ? tx("Verifying...") : tx("Verify Session")}
            </button>
            <button type="button" onClick={onClearOperatorIdentity}>
              {tx("Clear operator identity")}
            </button>
          </div>
        </form>

        {helperNotice ? (
          <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900">{helperNotice}</div>
        ) : null}
        {helperError ? (
          <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{helperError}</div>
        ) : null}
      </section>
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-1">
      <span className="block text-xs text-neutral-600">{label}</span>
      {children}
    </label>
  );
}

function NumberField({
  label,
  value,
  onChange,
  hint,
}: {
  label: string;
  value: number;
  onChange: (value: number) => void;
  hint?: string;
}) {
  return (
    <Field label={label}>
      <input
        type="number"
        value={Number.isFinite(value) ? value : 0}
        onChange={(e) => onChange(Number(e.target.value || "0"))}
        className="w-full rounded border border-neutral-200 bg-white"
      />
      {hint ? <div className="mt-1 text-xs text-neutral-500">{hint}</div> : null}
    </Field>
  );
}

function FloatField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (value: number) => void;
}) {
  return (
    <Field label={label}>
      <input
        type="number"
        step="0.1"
        min="0"
        max="1"
        value={Number.isFinite(value) ? value : 0}
        onChange={(e) => onChange(Number(e.target.value || "0"))}
        className="w-full rounded border border-neutral-200 bg-white"
      />
    </Field>
  );
}

function SecretMetric({ label, configured }: { label: string; configured: boolean | undefined }) {
  return (
    <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2">
      <div className="text-xs text-neutral-500">{label}</div>
      <div className="mt-1 font-mono text-sm">{configured ? "configured" : "not configured"}</div>
    </div>
  );
}

function RuntimeMetric({ label, value }: { label: string; value: unknown }) {
  return (
    <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2">
      <div className="text-xs text-neutral-500">{label}</div>
      <div className="mt-1 font-mono text-sm">{String(value ?? "-")}</div>
    </div>
  );
}
