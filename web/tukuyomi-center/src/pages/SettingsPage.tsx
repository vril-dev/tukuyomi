import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

type SettingsConfig = {
  enrollment_token_default_max_uses?: number;
  enrollment_token_default_ttl_seconds?: number;
  admin_session_ttl_seconds?: number;
  listen_addr?: string;
  api_base_path?: string;
  gateway_api_base_path?: string;
  ui_base_path?: string;
  tls_mode?: string;
  tls_cert_file?: string;
  tls_key_file?: string;
  tls_min_version?: string;
  client_allow_cidrs?: string[];
  manage_api_allow_cidrs?: string[];
  center_api_allow_cidrs?: string[];
  remote_ssh?: {
    center?: {
      enabled?: boolean;
      max_ttl_sec?: number;
      idle_timeout_sec?: number;
      max_sessions_total?: number;
      max_sessions_per_device?: number;
    };
  };
};

type CenterSettings = {
  etag?: string;
  restart_required?: boolean;
  storage?: {
    db_driver?: string;
    db_path?: string;
    db_retention_days?: number;
    file_retention_days?: number;
  };
  access?: {
    read_only?: boolean;
  };
  config?: SettingsConfig;
};

type RemoteSSHSigningKeyResponse = {
  public_key?: string;
  algorithm?: string;
};

type Tx = (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;

const DEFAULT_TOKEN_MAX_USES = 10;
const SECONDS_PER_DAY = 24 * 60 * 60;
const DEFAULT_SESSION_TTL_MINUTES = 8 * 60;
const MIN_SESSION_TTL_MINUTES = 5;
const MAX_SESSION_TTL_MINUTES = 7 * 24 * 60;
const DEFAULT_CENTER_LISTEN_ADDR = "127.0.0.1:9092";
const DEFAULT_CENTER_API_BASE_PATH = "/center-api";
const DEFAULT_CENTER_GATEWAY_API_BASE_PATH = "/center-api";
const DEFAULT_CENTER_UI_BASE_PATH = "/center-ui";
const DEFAULT_MANAGE_API_ALLOW_CIDRS = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"];
const DEFAULT_REMOTE_SSH_MAX_TTL_SEC = 900;
const DEFAULT_REMOTE_SSH_IDLE_TIMEOUT_SEC = 300;
const DEFAULT_REMOTE_SSH_MAX_SESSIONS_TOTAL = 16;
const DEFAULT_REMOTE_SSH_MAX_SESSIONS_PER_DEVICE = 1;

function boolLabel(value: boolean | undefined, tx: Tx) {
  if (typeof value !== "boolean") {
    return "-";
  }
  return value ? tx("enabled") : tx("disabled");
}

function daysLabel(value: number | undefined, tx: Tx) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "-";
  }
  return tx("{count} days", { count: value });
}

function allowCIDRText(value: string[] | undefined, fallback: string[] = []) {
  const list = Array.isArray(value) ? value : fallback;
  return list.join("\n");
}

function normalizeForm(config: SettingsConfig | undefined) {
  const maxUses = Number.isFinite(config?.enrollment_token_default_max_uses)
    ? Number(config?.enrollment_token_default_max_uses)
    : DEFAULT_TOKEN_MAX_USES;
  const ttlSeconds = Number.isFinite(config?.enrollment_token_default_ttl_seconds)
    ? Number(config?.enrollment_token_default_ttl_seconds)
    : 0;
  const sessionTTLSeconds = Number.isFinite(config?.admin_session_ttl_seconds)
    ? Number(config?.admin_session_ttl_seconds)
    : DEFAULT_SESSION_TTL_MINUTES * 60;
  const remoteSSHCenter = config?.remote_ssh?.center;
  return {
    defaultMaxUses: String(Math.max(1, Math.min(maxUses, 1000000))),
    defaultTTLDays: ttlSeconds > 0 ? String(Math.floor(ttlSeconds / SECONDS_PER_DAY)) : "0",
    sessionTTLMinutes: String(Math.max(MIN_SESSION_TTL_MINUTES, Math.min(Math.floor(sessionTTLSeconds / 60), MAX_SESSION_TTL_MINUTES))),
    listenAddr: config?.listen_addr || DEFAULT_CENTER_LISTEN_ADDR,
    apiBasePath: config?.api_base_path || DEFAULT_CENTER_API_BASE_PATH,
    gatewayApiBasePath: config?.gateway_api_base_path || DEFAULT_CENTER_GATEWAY_API_BASE_PATH,
    uiBasePath: config?.ui_base_path || DEFAULT_CENTER_UI_BASE_PATH,
    tlsMode: config?.tls_mode === "manual" ? "manual" : "off",
    tlsCertFile: config?.tls_cert_file || "",
    tlsKeyFile: config?.tls_key_file || "",
    tlsMinVersion: config?.tls_min_version === "tls1.3" ? "tls1.3" : "tls1.2",
    clientAllowCIDRs: allowCIDRText(config?.client_allow_cidrs),
    manageApiAllowCIDRs: allowCIDRText(config?.manage_api_allow_cidrs, DEFAULT_MANAGE_API_ALLOW_CIDRS),
    centerApiAllowCIDRs: allowCIDRText(config?.center_api_allow_cidrs),
    remoteSSHCenterEnabled: remoteSSHCenter?.enabled === true,
    remoteSSHMaxTTLSec: String(
      Number.isFinite(remoteSSHCenter?.max_ttl_sec) ? Number(remoteSSHCenter?.max_ttl_sec) : DEFAULT_REMOTE_SSH_MAX_TTL_SEC,
    ),
    remoteSSHIdleTimeoutSec: String(
      Number.isFinite(remoteSSHCenter?.idle_timeout_sec) ? Number(remoteSSHCenter?.idle_timeout_sec) : DEFAULT_REMOTE_SSH_IDLE_TIMEOUT_SEC,
    ),
    remoteSSHMaxSessionsTotal: String(
      Number.isFinite(remoteSSHCenter?.max_sessions_total) ? Number(remoteSSHCenter?.max_sessions_total) : DEFAULT_REMOTE_SSH_MAX_SESSIONS_TOTAL,
    ),
    remoteSSHMaxSessionsPerDevice: String(
      Number.isFinite(remoteSSHCenter?.max_sessions_per_device)
        ? Number(remoteSSHCenter?.max_sessions_per_device)
        : DEFAULT_REMOTE_SSH_MAX_SESSIONS_PER_DEVICE,
    ),
  };
}

function parsePositiveInt(value: string, fallback: number) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return parsed;
}

function parseCIDRList(value: string) {
  return value
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export default function SettingsPage() {
  const { tx } = useI18n();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [rotatingSigningKey, setRotatingSigningKey] = useState(false);
  const [message, setMessage] = useState("");
  const [messageTone, setMessageTone] = useState<"success" | "error">("success");
  const [settings, setSettings] = useState<CenterSettings>({});
  const [remoteSSHSigningPublicKey, setRemoteSSHSigningPublicKey] = useState("");
  const [form, setForm] = useState(() => normalizeForm(undefined));

  const load = useCallback(async () => {
    setLoading(true);
    setMessage("");
    try {
      const [data, signingKey] = await Promise.all([
        apiGetJson<CenterSettings>("/settings"),
        apiGetJson<RemoteSSHSigningKeyResponse>("/remote-ssh/signing-key"),
      ]);
      setSettings(data);
      setRemoteSSHSigningPublicKey(signingKey.public_key || "");
      setForm(normalizeForm(data.config));
    } catch (err) {
      const fallback = tx("Failed to load Center settings");
      setMessageTone("error");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setLoading(false);
    }
  }, [tx]);

  useEffect(() => {
    void load();
  }, [load]);

  const currentForm = useMemo(() => normalizeForm(settings.config), [settings.config]);
  const dirty =
    form.defaultMaxUses !== currentForm.defaultMaxUses ||
    form.defaultTTLDays !== currentForm.defaultTTLDays ||
    form.sessionTTLMinutes !== currentForm.sessionTTLMinutes ||
    form.listenAddr !== currentForm.listenAddr ||
    form.apiBasePath !== currentForm.apiBasePath ||
    form.gatewayApiBasePath !== currentForm.gatewayApiBasePath ||
    form.uiBasePath !== currentForm.uiBasePath ||
    form.tlsMode !== currentForm.tlsMode ||
    form.tlsCertFile !== currentForm.tlsCertFile ||
    form.tlsKeyFile !== currentForm.tlsKeyFile ||
    form.tlsMinVersion !== currentForm.tlsMinVersion ||
    form.clientAllowCIDRs !== currentForm.clientAllowCIDRs ||
    form.manageApiAllowCIDRs !== currentForm.manageApiAllowCIDRs ||
    form.centerApiAllowCIDRs !== currentForm.centerApiAllowCIDRs ||
    form.remoteSSHCenterEnabled !== currentForm.remoteSSHCenterEnabled ||
    form.remoteSSHMaxTTLSec !== currentForm.remoteSSHMaxTTLSec ||
    form.remoteSSHIdleTimeoutSec !== currentForm.remoteSSHIdleTimeoutSec ||
    form.remoteSSHMaxSessionsTotal !== currentForm.remoteSSHMaxSessionsTotal ||
    form.remoteSSHMaxSessionsPerDevice !== currentForm.remoteSSHMaxSessionsPerDevice;
  const readOnly = settings.access?.read_only === true;

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    setMessageTone("success");
    const defaultMaxUses = parsePositiveInt(form.defaultMaxUses, DEFAULT_TOKEN_MAX_USES);
    const defaultTTLDays = parsePositiveInt(form.defaultTTLDays, 0);
    const sessionTTLMinutes = parsePositiveInt(form.sessionTTLMinutes, DEFAULT_SESSION_TTL_MINUTES);
    const remoteSSHMaxTTLSec = parsePositiveInt(form.remoteSSHMaxTTLSec, DEFAULT_REMOTE_SSH_MAX_TTL_SEC);
    const remoteSSHIdleTimeoutSec = parsePositiveInt(form.remoteSSHIdleTimeoutSec, DEFAULT_REMOTE_SSH_IDLE_TIMEOUT_SEC);
    const remoteSSHMaxSessionsTotal = parsePositiveInt(form.remoteSSHMaxSessionsTotal, DEFAULT_REMOTE_SSH_MAX_SESSIONS_TOTAL);
    const remoteSSHMaxSessionsPerDevice = parsePositiveInt(form.remoteSSHMaxSessionsPerDevice, DEFAULT_REMOTE_SSH_MAX_SESSIONS_PER_DEVICE);
    if (defaultMaxUses < 1 || defaultMaxUses > 1000000) {
      setMessageTone("error");
      setMessage(tx("Default max uses must be between 1 and 1000000."));
      return;
    }
    if (defaultTTLDays < 0 || defaultTTLDays > 3650) {
      setMessageTone("error");
      setMessage(tx("Default token TTL must be between 0 and 3650 days."));
      return;
    }
    if (sessionTTLMinutes < MIN_SESSION_TTL_MINUTES || sessionTTLMinutes > MAX_SESSION_TTL_MINUTES) {
      setMessageTone("error");
      setMessage(tx("Session TTL must be between 5 minutes and 7 days."));
      return;
    }
    if (remoteSSHMaxTTLSec < 60 || remoteSSHMaxTTLSec > 86400) {
      setMessageTone("error");
      setMessage(tx("Remote SSH max TTL must be between 60 and 86400 seconds."));
      return;
    }
    if (remoteSSHIdleTimeoutSec < 30 || remoteSSHIdleTimeoutSec > 3600 || remoteSSHIdleTimeoutSec > remoteSSHMaxTTLSec) {
      setMessageTone("error");
      setMessage(tx("Remote SSH idle timeout must be between 30 and 3600 seconds and not exceed max TTL."));
      return;
    }
    if (remoteSSHMaxSessionsTotal < 1 || remoteSSHMaxSessionsTotal > 128) {
      setMessageTone("error");
      setMessage(tx("Remote SSH max sessions total must be between 1 and 128."));
      return;
    }
    if (remoteSSHMaxSessionsPerDevice < 1 || remoteSSHMaxSessionsPerDevice > 8) {
      setMessageTone("error");
      setMessage(tx("Remote SSH max sessions per Gateway must be between 1 and 8."));
      return;
    }
    const listenAddr = form.listenAddr.trim();
    const apiBasePath = form.apiBasePath.trim();
    const gatewayApiBasePath = form.gatewayApiBasePath.trim();
    const uiBasePath = form.uiBasePath.trim();
    const tlsCertFile = form.tlsCertFile.trim();
    const tlsKeyFile = form.tlsKeyFile.trim();
    const clientAllowCIDRs = parseCIDRList(form.clientAllowCIDRs);
    const manageApiAllowCIDRs = parseCIDRList(form.manageApiAllowCIDRs);
    const centerApiAllowCIDRs = parseCIDRList(form.centerApiAllowCIDRs);
    if (!listenAddr || !listenAddr.includes(":")) {
      setMessageTone("error");
      setMessage(tx("Listen address must include a host and port."));
      return;
    }
    if (
      !apiBasePath.startsWith("/") ||
      !gatewayApiBasePath.startsWith("/") ||
      !uiBasePath.startsWith("/") ||
      apiBasePath === uiBasePath ||
      gatewayApiBasePath === uiBasePath
    ) {
      setMessageTone("error");
      setMessage(tx("API paths and UI base path must be different absolute paths."));
      return;
    }
    if (form.tlsMode === "manual" && (!tlsCertFile || !tlsKeyFile)) {
      setMessageTone("error");
      setMessage(tx("Manual TLS requires both certificate and key files."));
      return;
    }
    const etag = settings.etag || "";
    if (!etag) {
      setMessageTone("error");
      setMessage(tx("Settings revision is missing. Refresh and try again."));
      return;
    }
    setSaving(true);
    try {
      const next = await apiPutJson<CenterSettings>(
        "/settings",
        {
          config: {
            enrollment_token_default_max_uses: defaultMaxUses,
            enrollment_token_default_ttl_seconds: defaultTTLDays * SECONDS_PER_DAY,
            admin_session_ttl_seconds: sessionTTLMinutes * 60,
            listen_addr: listenAddr,
            api_base_path: apiBasePath,
            gateway_api_base_path: gatewayApiBasePath,
            ui_base_path: uiBasePath,
            tls_mode: form.tlsMode,
            tls_cert_file: tlsCertFile,
            tls_key_file: tlsKeyFile,
            tls_min_version: form.tlsMinVersion,
            client_allow_cidrs: clientAllowCIDRs,
            manage_api_allow_cidrs: manageApiAllowCIDRs,
            center_api_allow_cidrs: centerApiAllowCIDRs,
            remote_ssh: {
              center: {
                enabled: form.remoteSSHCenterEnabled,
                max_ttl_sec: remoteSSHMaxTTLSec,
                idle_timeout_sec: remoteSSHIdleTimeoutSec,
                max_sessions_total: remoteSSHMaxSessionsTotal,
                max_sessions_per_device: remoteSSHMaxSessionsPerDevice,
              },
            },
          },
        },
        { headers: { "If-Match": etag } },
      );
      setSettings(next);
      setForm(normalizeForm(next.config));
      setMessageTone("success");
      setMessage(next.restart_required ? tx("Center settings saved. Restart Center to apply runtime changes.") : tx("Center settings saved."));
    } catch (err) {
      const fallback = tx("Failed to save Center settings");
      setMessageTone("error");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setSaving(false);
    }
  }

  async function rotateRemoteSSHSigningKey() {
    setMessage("");
    setMessageTone("success");
    if (readOnly) {
      setMessageTone("error");
      setMessage(tx("Admin read-only mode disables settings changes."));
      return;
    }
    if (typeof window !== "undefined" && !window.confirm(tx("Rotate Remote SSH Center signing key? Gateways must refresh their pinned key before new sessions work."))) {
      return;
    }
    setRotatingSigningKey(true);
    try {
      const next = await apiPostJson<RemoteSSHSigningKeyResponse>("/remote-ssh/signing-key/rotate", { confirm: true });
      setRemoteSSHSigningPublicKey(next.public_key || "");
      setMessageTone("success");
      setMessage(tx("Remote SSH Center signing key rotated. Refresh each approved Gateway key pin before opening new sessions."));
    } catch (err) {
      const fallback = tx("Failed to rotate Remote SSH Center signing key");
      setMessageTone("error");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setRotatingSigningKey(false);
    }
  }

  return (
    <div className="content-panel">
      <section className="content-section">
        <form onSubmit={save}>
          <div className="section-header">
            <div>
              <h2 className="section-title">{tx("Center settings")}</h2>
              {loading ? <p className="section-note">{tx("Loading Center settings...")}</p> : null}
            </div>
            <button type="button" onClick={() => void load()} disabled={loading || saving}>
              {tx("Refresh")}
            </button>
          </div>
          <div className="summary-grid">
            <SettingItem label={tx("Read only")} value={boolLabel(settings.access?.read_only, tx)} />
            <SettingItem label={tx("DB driver")} value={settings.storage?.db_driver || "-"} />
            <SettingItem label={tx("DB path")} value={settings.storage?.db_path || "-"} />
            <SettingItem label={tx("DB retention")} value={daysLabel(settings.storage?.db_retention_days, tx)} />
            <SettingItem label={tx("File retention")} value={daysLabel(settings.storage?.file_retention_days, tx)} />
          </div>
          <h3 className="section-subtitle">{tx("Remote SSH service")}</h3>
          <div className="form-grid">
            <label className="checkbox-line remote-ssh-checkbox">
              <input
                type="checkbox"
                checked={form.remoteSSHCenterEnabled}
                onChange={(event) => setForm((current) => ({ ...current, remoteSSHCenterEnabled: event.target.checked }))}
                disabled={loading || saving || readOnly}
              />
              <span>{tx("Enable Remote SSH on this Center")}</span>
            </label>
            <label>
              <span>{tx("Max TTL seconds")}</span>
              <input
                type="number"
                min={60}
                max={86400}
                value={form.remoteSSHMaxTTLSec}
                onChange={(event) => setForm((current) => ({ ...current, remoteSSHMaxTTLSec: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
            </label>
            <label>
              <span>{tx("Idle timeout seconds")}</span>
              <input
                type="number"
                min={30}
                max={3600}
                value={form.remoteSSHIdleTimeoutSec}
                onChange={(event) => setForm((current) => ({ ...current, remoteSSHIdleTimeoutSec: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
            </label>
            <label>
              <span>{tx("Max sessions total")}</span>
              <input
                type="number"
                min={1}
                max={128}
                value={form.remoteSSHMaxSessionsTotal}
                onChange={(event) => setForm((current) => ({ ...current, remoteSSHMaxSessionsTotal: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
            </label>
            <label>
              <span>{tx("Max sessions per Gateway")}</span>
              <input
                type="number"
                min={1}
                max={8}
                value={form.remoteSSHMaxSessionsPerDevice}
                onChange={(event) => setForm((current) => ({ ...current, remoteSSHMaxSessionsPerDevice: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
            </label>
          </div>
          <p className="section-note">{tx("This Center service setting is applied immediately after saving.")}</p>
          <h3 className="section-subtitle">{tx("Remote SSH trust")}</h3>
          <div className="form-grid">
            <label>
              <span>{tx("Center signing public key")}</span>
              <textarea className="mono" rows={3} value={remoteSSHSigningPublicKey || "-"} readOnly />
              <span className="field-hint">{tx("Gateways pin this key after approved enrollment. Rotate only when the fleet can refresh the pin.")}</span>
            </label>
            <label>
              <span>{tx("Signing key rotation")}</span>
              <button type="button" onClick={() => void rotateRemoteSSHSigningKey()} disabled={loading || saving || rotatingSigningKey || readOnly}>
                {rotatingSigningKey ? tx("Rotating...") : tx("Rotate signing key")}
              </button>
              <span className="field-hint">{tx("Existing Gateway pins are not silently overwritten. Refresh them from Gateway Options after rotation.")}</span>
            </label>
          </div>
          <h3 className="section-subtitle">{tx("Standalone listener")}</h3>
          <div className="form-grid">
            <label>
              <span>{tx("Listen address")}</span>
              <input
                value={form.listenAddr}
                onChange={(event) => setForm((current) => ({ ...current, listenAddr: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
              <span className="field-hint">{tx("Applied after Center restart.")}</span>
            </label>
            <label>
              <span>{tx("API base path")}</span>
              <input
                value={form.apiBasePath}
                onChange={(event) => setForm((current) => ({ ...current, apiBasePath: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
              <span className="field-hint">{tx("Applied after Center restart.")}</span>
            </label>
            <label>
              <span>{tx("Gateway API base path")}</span>
              <input
                value={form.gatewayApiBasePath}
                onChange={(event) => setForm((current) => ({ ...current, gatewayApiBasePath: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
              <span className="field-hint">{tx("Public API path used when Center UI is accessed through Gateway.")}</span>
            </label>
            <label>
              <span>{tx("UI base path")}</span>
              <input
                value={form.uiBasePath}
                onChange={(event) => setForm((current) => ({ ...current, uiBasePath: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
              <span className="field-hint">{tx("Applied after Center restart.")}</span>
            </label>
            <label>
              <span>{tx("TLS mode")}</span>
              <select
                value={form.tlsMode}
                onChange={(event) => setForm((current) => ({ ...current, tlsMode: event.target.value }))}
                disabled={loading || saving || readOnly}
              >
                <option value="off">{tx("Off")}</option>
                <option value="manual">{tx("Manual certificate")}</option>
              </select>
              <span className="field-hint">{tx("Manual TLS is applied after Center restart.")}</span>
            </label>
            <label>
              <span>{tx("TLS certificate file")}</span>
              <input
                value={form.tlsCertFile}
                onChange={(event) => setForm((current) => ({ ...current, tlsCertFile: event.target.value }))}
                disabled={loading || saving || readOnly || form.tlsMode !== "manual"}
              />
            </label>
            <label>
              <span>{tx("TLS key file")}</span>
              <input
                value={form.tlsKeyFile}
                onChange={(event) => setForm((current) => ({ ...current, tlsKeyFile: event.target.value }))}
                disabled={loading || saving || readOnly || form.tlsMode !== "manual"}
              />
            </label>
            <label>
              <span>{tx("TLS minimum version")}</span>
              <select
                value={form.tlsMinVersion}
                onChange={(event) => setForm((current) => ({ ...current, tlsMinVersion: event.target.value }))}
                disabled={loading || saving || readOnly || form.tlsMode !== "manual"}
              >
                <option value="tls1.2">TLS 1.2</option>
                <option value="tls1.3">TLS 1.3</option>
              </select>
            </label>
          </div>
          {settings.restart_required ? <p className="form-message warning">{tx("Center restart required for saved listener settings.")}</p> : null}
          <h3 className="section-subtitle">{tx("Source IP allowlists")}</h3>
          <div className="form-grid">
            <label>
              <span>{tx("Client to Center")}</span>
              <textarea
                rows={4}
                value={form.clientAllowCIDRs}
                onChange={(event) => setForm((current) => ({ ...current, clientAllowCIDRs: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
              <span className="field-hint">{tx("Empty allows any source. Applies to Center UI access.")}</span>
            </label>
            <label>
              <span>{tx("Center manage API")}</span>
              <textarea
                rows={4}
                value={form.manageApiAllowCIDRs}
                onChange={(event) => setForm((current) => ({ ...current, manageApiAllowCIDRs: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
              <span className="field-hint">{tx("Default allows loopback and private/local CIDRs.")}</span>
            </label>
            <label>
              <span>{tx("Center API")}</span>
              <textarea
                rows={4}
                value={form.centerApiAllowCIDRs}
                onChange={(event) => setForm((current) => ({ ...current, centerApiAllowCIDRs: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
              <span className="field-hint">{tx("Empty allows any source. Applies to Gateway device API calls.")}</span>
            </label>
          </div>
          <h3 className="section-subtitle">{tx("Admin session")}</h3>
          <div className="form-grid">
            <label>
              <span>{tx("Session TTL minutes")}</span>
              <input
                type="number"
                min={MIN_SESSION_TTL_MINUTES}
                max={MAX_SESSION_TTL_MINUTES}
                value={form.sessionTTLMinutes}
                onChange={(event) => setForm((current) => ({ ...current, sessionTTLMinutes: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
              <span className="field-hint">{tx("5 minutes to 7 days. New sessions use the saved value.")}</span>
            </label>
          </div>
          <h3 className="section-subtitle">{tx("Enrollment token defaults")}</h3>
          <div className="form-grid">
            <label>
              <span>{tx("Default max uses")}</span>
              <input
                type="number"
                min={1}
                max={1000000}
                value={form.defaultMaxUses}
                onChange={(event) => setForm((current) => ({ ...current, defaultMaxUses: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
              <span className="field-hint">{tx("Used when an enrollment token is created without an explicit max use count.")}</span>
            </label>
            <label>
              <span>{tx("Default token TTL days")}</span>
              <input
                type="number"
                min={0}
                max={3650}
                value={form.defaultTTLDays}
                onChange={(event) => setForm((current) => ({ ...current, defaultTTLDays: event.target.value }))}
                disabled={loading || saving || readOnly}
              />
              <span className="field-hint">{tx("0 keeps newly-created enrollment tokens non-expiring by default.")}</span>
            </label>
          </div>
          <div className="form-footer">
            <button type="submit" disabled={loading || saving || readOnly || !dirty}>
              {saving ? tx("Saving...") : tx("Save settings")}
            </button>
            {readOnly ? <span className="form-message error">{tx("Admin read-only mode disables settings changes.")}</span> : null}
            {message ? (
              <span className={`form-message ${messageTone}`} role={messageTone === "error" ? "alert" : "status"}>
                {message}
              </span>
            ) : null}
          </div>
        </form>
      </section>

    </div>
  );
}

function SettingItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span>{label}</span>
      <strong title={value}>{value}</strong>
    </div>
  );
}
