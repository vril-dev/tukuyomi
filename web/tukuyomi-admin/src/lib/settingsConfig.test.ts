import assert from "node:assert/strict";
import test from "node:test";
import { computeSettingsRuntimeDrift } from "./settingsConfig.js";

test("computeSettingsRuntimeDrift returns empty when runtime matches configured values", () => {
  const config = {
    server: { listen_addr: ":9090", graceful_shutdown_timeout_sec: 30, proxy_protocol: { enabled: false, trusted_cidrs: [] }, tls: { enabled: false } },
    admin: { api_base_path: "/tukuyomi-api", ui_base_path: "/tukuyomi-ui", listen_addr: "", proxy_protocol: { enabled: false, trusted_cidrs: [] }, read_only: false },
    runtime: { gomaxprocs: 0, memory_limit_mb: 0 },
    storage: { db_driver: "sqlite", db_path: "db/tukuyomi.db" },
    persistent_storage: { backend: "local", local: { base_dir: "data/persistent" } },
    observability: { tracing: { enabled: false, service_name: "tukuyomi", otlp_endpoint: "" } },
    proxy: { engine: { mode: "tukuyomi_proxy" } },
    waf: { engine: { mode: "coraza" } },
  };
  const runtime = {
    listen_addr: ":9090",
    server_graceful_shutdown_timeout_sec: 30,
    server_proxy_protocol_enabled: false,
    server_proxy_protocol_trusted_cidrs: [],
    api_base_path: "/tukuyomi-api",
    ui_base_path: "/tukuyomi-ui",
    admin_listen_addr: "",
    admin_proxy_protocol_enabled: false,
    admin_proxy_protocol_trusted_cidrs: [],
    server_tls_enabled: false,
    admin_read_only: false,
    runtime_gomaxprocs: 0,
    runtime_memory_limit_mb: 0,
    storage_db_driver: "sqlite",
    storage_db_path: "db/tukuyomi.db",
    persistent_storage_backend: "local",
    persistent_storage_local_base_dir: "data/persistent",
    tracing_enabled: false,
    tracing_service_name: "tukuyomi",
    tracing_otlp_endpoint: "",
    proxy_engine_mode: "tukuyomi_proxy",
    waf_engine_mode: "coraza",
  };

  assert.deepEqual(computeSettingsRuntimeDrift(config, runtime), []);
});

test("computeSettingsRuntimeDrift returns labeled mismatches when restart is pending", () => {
  const config = {
    server: { listen_addr: ":443", graceful_shutdown_timeout_sec: 45, proxy_protocol: { enabled: true, trusted_cidrs: ["10.0.0.0/8"] }, tls: { enabled: true } },
    admin: { api_base_path: "/admin-api", ui_base_path: "/admin-ui", listen_addr: ":9091", proxy_protocol: { enabled: true, trusted_cidrs: ["127.0.0.1/32"] }, read_only: true },
    runtime: { gomaxprocs: 4, memory_limit_mb: 512 },
    storage: { db_driver: "pgsql", db_path: "db/custom.db" },
    persistent_storage: { backend: "local", local: { base_dir: "data/shared-persistent" } },
    observability: { tracing: { enabled: true, service_name: "proxy-prod", otlp_endpoint: "http://otel:4318" } },
    proxy: { engine: { mode: "tukuyomi_proxy" } },
    waf: { engine: { mode: "coraza" } },
  };
  const runtime = {
    listen_addr: ":9090",
    server_graceful_shutdown_timeout_sec: 30,
    server_proxy_protocol_enabled: false,
    server_proxy_protocol_trusted_cidrs: [],
    api_base_path: "/tukuyomi-api",
    ui_base_path: "/tukuyomi-ui",
    admin_listen_addr: "",
    admin_proxy_protocol_enabled: false,
    admin_proxy_protocol_trusted_cidrs: [],
    server_tls_enabled: false,
    admin_read_only: false,
    runtime_gomaxprocs: 0,
    runtime_memory_limit_mb: 0,
    storage_db_driver: "sqlite",
    storage_db_path: "db/tukuyomi.db",
    persistent_storage_backend: "local",
    persistent_storage_local_base_dir: "data/persistent",
    tracing_enabled: false,
    tracing_service_name: "tukuyomi",
    tracing_otlp_endpoint: "",
    proxy_engine_mode: "legacy_bridge",
    waf_engine_mode: "open_appsec",
  };

  assert.deepEqual(computeSettingsRuntimeDrift(config, runtime), [
    "Listen Address",
    "Graceful Shutdown Timeout",
    "Public PROXY Protocol",
    "Public PROXY Protocol Trusted CIDRs",
    "API Base Path",
    "UI Base Path",
    "Admin Listen Address",
    "Admin PROXY Protocol",
    "Admin PROXY Protocol Trusted CIDRs",
    "TLS Enabled",
    "Admin Read Only",
    "GOMAXPROCS",
    "Memory Limit MB",
    "DB Driver",
    "DB Path",
    "Persistent Storage Local Base Directory",
    "Tracing Enabled",
    "Tracing Service Name",
    "OTLP Endpoint",
    "Proxy Engine",
    "WAF Engine",
  ]);
});

test("computeSettingsRuntimeDrift includes S3 persistent storage placement", () => {
  const config = {
    server: { listen_addr: ":9090", graceful_shutdown_timeout_sec: 30, proxy_protocol: { enabled: false, trusted_cidrs: [] }, tls: { enabled: false } },
    admin: { api_base_path: "/tukuyomi-api", ui_base_path: "/tukuyomi-ui", listen_addr: "", proxy_protocol: { enabled: false, trusted_cidrs: [] }, read_only: false },
    runtime: { gomaxprocs: 0, memory_limit_mb: 0 },
    storage: { db_driver: "sqlite", db_path: "db/tukuyomi.db" },
    persistent_storage: {
      backend: "s3",
      local: { base_dir: "data/persistent" },
      s3: { bucket: "runtime", region: "us-east-1", endpoint: "http://minio:9000", prefix: "prod", force_path_style: true },
    },
    observability: { tracing: { enabled: false, service_name: "tukuyomi", otlp_endpoint: "" } },
    proxy: { engine: { mode: "tukuyomi_proxy" } },
    waf: { engine: { mode: "coraza" } },
  };
  const runtime = {
    listen_addr: ":9090",
    server_graceful_shutdown_timeout_sec: 30,
    server_proxy_protocol_enabled: false,
    server_proxy_protocol_trusted_cidrs: [],
    api_base_path: "/tukuyomi-api",
    ui_base_path: "/tukuyomi-ui",
    admin_listen_addr: "",
    admin_proxy_protocol_enabled: false,
    admin_proxy_protocol_trusted_cidrs: [],
    server_tls_enabled: false,
    admin_read_only: false,
    runtime_gomaxprocs: 0,
    runtime_memory_limit_mb: 0,
    storage_db_driver: "sqlite",
    storage_db_path: "db/tukuyomi.db",
    persistent_storage_backend: "s3",
    persistent_storage_local_base_dir: "data/persistent",
    persistent_storage_s3_bucket: "old-runtime",
    persistent_storage_s3_region: "us-east-1",
    persistent_storage_s3_endpoint: "",
    persistent_storage_s3_prefix: "old-prod",
    persistent_storage_s3_force_path_style: false,
    tracing_enabled: false,
    tracing_service_name: "tukuyomi",
    tracing_otlp_endpoint: "",
    proxy_engine_mode: "tukuyomi_proxy",
    waf_engine_mode: "coraza",
  };

  assert.deepEqual(computeSettingsRuntimeDrift(config, runtime), [
    "Persistent Storage S3 Bucket",
    "Persistent Storage S3 Endpoint",
    "Persistent Storage S3 Prefix",
    "Persistent Storage S3 Path Style",
  ]);
});
