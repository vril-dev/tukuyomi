type DriftConfig = {
  server: {
    listen_addr: string;
    graceful_shutdown_timeout_sec: number;
    proxy_protocol: { enabled: boolean; trusted_cidrs: string[] };
    tls: { enabled: boolean };
  };
  admin: {
    api_base_path: string;
    ui_base_path: string;
    listen_addr: string;
    proxy_protocol: { enabled: boolean; trusted_cidrs: string[] };
    read_only: boolean;
  };
  runtime: {
    gomaxprocs: number;
    memory_limit_mb: number;
  };
  storage: {
    backend: string;
    db_driver: string;
    db_path: string;
  };
  observability: {
    tracing: {
      enabled: boolean;
      service_name: string;
      otlp_endpoint: string;
    };
  };
  proxy: {
    engine: {
      mode: string;
    };
  };
};

type DriftRuntime = {
  listen_addr?: string;
  api_base_path?: string;
  ui_base_path?: string;
  admin_listen_addr?: string;
  server_proxy_protocol_enabled?: boolean;
  server_proxy_protocol_trusted_cidrs?: string[];
  server_tls_enabled?: boolean;
  server_graceful_shutdown_timeout_sec?: number;
  admin_proxy_protocol_enabled?: boolean;
  admin_proxy_protocol_trusted_cidrs?: string[];
  admin_read_only?: boolean;
  runtime_gomaxprocs?: number;
  runtime_memory_limit_mb?: number;
  request_country_effective_mode?: string;
  storage_backend?: string;
  storage_db_driver?: string;
  storage_db_path?: string;
  tracing_enabled?: boolean;
  tracing_service_name?: string;
  tracing_otlp_endpoint?: string;
  proxy_engine_mode?: string;
};

export function computeSettingsRuntimeDrift(
  config: DriftConfig,
  runtime: DriftRuntime | null | undefined,
  label: (key: string) => string = (value) => value,
): string[] {
  if (!runtime) return [];
  const drift: string[] = [];
  if ((runtime.listen_addr ?? "") !== config.server.listen_addr) drift.push(label("Listen Address"));
  if ((runtime.server_graceful_shutdown_timeout_sec ?? 30) !== config.server.graceful_shutdown_timeout_sec) drift.push(label("Graceful Shutdown Timeout"));
  if ((runtime.server_proxy_protocol_enabled ?? false) !== config.server.proxy_protocol.enabled) drift.push(label("Public PROXY Protocol"));
  if (JSON.stringify(runtime.server_proxy_protocol_trusted_cidrs ?? []) !== JSON.stringify(config.server.proxy_protocol.trusted_cidrs)) drift.push(label("Public PROXY Protocol Trusted CIDRs"));
  if ((runtime.api_base_path ?? "") !== config.admin.api_base_path) drift.push(label("API Base Path"));
  if ((runtime.ui_base_path ?? "") !== config.admin.ui_base_path) drift.push(label("UI Base Path"));
  if ((runtime.admin_listen_addr ?? "") !== config.admin.listen_addr) drift.push(label("Admin Listen Address"));
  if ((runtime.admin_proxy_protocol_enabled ?? false) !== config.admin.proxy_protocol.enabled) drift.push(label("Admin PROXY Protocol"));
  if (JSON.stringify(runtime.admin_proxy_protocol_trusted_cidrs ?? []) !== JSON.stringify(config.admin.proxy_protocol.trusted_cidrs)) drift.push(label("Admin PROXY Protocol Trusted CIDRs"));
  if ((runtime.server_tls_enabled ?? false) !== config.server.tls.enabled) drift.push(label("TLS Enabled"));
  if ((runtime.admin_read_only ?? false) !== config.admin.read_only) drift.push(label("Admin Read Only"));
  if ((runtime.runtime_gomaxprocs ?? 0) !== config.runtime.gomaxprocs) drift.push(label("GOMAXPROCS"));
  if ((runtime.runtime_memory_limit_mb ?? 0) !== config.runtime.memory_limit_mb) drift.push(label("Memory Limit MB"));
  if ((runtime.storage_backend ?? "") !== config.storage.backend) drift.push(label("Storage Backend"));
  if ((runtime.storage_db_driver ?? "") !== config.storage.db_driver) drift.push(label("DB Driver"));
  if ((runtime.storage_db_path ?? "") !== config.storage.db_path) drift.push(label("DB Path"));
  if ((runtime.tracing_enabled ?? false) !== config.observability.tracing.enabled) drift.push(label("Tracing Enabled"));
  if ((runtime.tracing_service_name ?? "") !== config.observability.tracing.service_name) drift.push(label("Tracing Service Name"));
  if ((runtime.tracing_otlp_endpoint ?? "") !== config.observability.tracing.otlp_endpoint) drift.push(label("OTLP Endpoint"));
  if ((runtime.proxy_engine_mode ?? "tukuyomi_proxy") !== (config.proxy.engine.mode || "tukuyomi_proxy")) drift.push(label("Proxy Engine"));
  return drift;
}
