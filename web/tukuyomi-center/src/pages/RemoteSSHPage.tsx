import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { useParams } from "react-router-dom";

import { apiGetJson, apiPutJson } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import { getAPIBasePath } from "@/lib/runtime";

type RemoteSSHDevice = {
  device_id: string;
  status: string;
  product_id?: string;
  last_seen_at_unix: number;
};

type RemoteSSHPolicy = {
  device_id: string;
  enabled: boolean;
  max_ttl_sec: number;
  allowed_run_as_user: string;
  require_reason: boolean;
  updated_by_username?: string;
  updated_at_unix: number;
};

type RemoteSSHSession = {
  session_id: string;
  device_id: string;
  status: string;
  reason: string;
  requested_by_username?: string;
  operator_public_key_fingerprint_sha256?: string;
  gateway_host_key_fingerprint_sha256?: string;
  gateway_host_public_key?: string;
  ttl_sec: number;
  expires_at_unix: number;
  created_at_unix: number;
  gateway_connected_at_unix: number;
  operator_connected_at_unix: number;
  started_at_unix: number;
  ended_at_unix: number;
  close_reason?: string;
  operator_ip?: string;
};

type RemoteSSHViewResponse = {
  center_enabled?: boolean;
  device?: RemoteSSHDevice;
  policy?: RemoteSSHPolicy;
  sessions?: RemoteSSHSession[];
};

type RemoteSSHPolicyResponse = {
  policy?: RemoteSSHPolicy;
};

type CenterSettingsConfig = {
  enrollment_token_default_max_uses?: number;
  enrollment_token_default_ttl_seconds?: number;
  admin_session_ttl_seconds?: number;
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

type CenterSettingsResponse = {
  etag?: string;
  config?: CenterSettingsConfig;
};

type PolicyForm = {
  enabled: boolean;
  maxTTLSec: string;
  allowedRunAsUser: string;
  requireReason: boolean;
};

type CommandForm = {
  reason: string;
  ttlSec: string;
  localAddr: string;
  centerURL: string;
  centerCABundle: string;
  centerServerName: string;
};

const DEFAULT_REMOTE_SSH_TTL = 900;
const DEFAULT_REMOTE_SSH_IDLE_TIMEOUT = 300;
const DEFAULT_REMOTE_SSH_MAX_SESSIONS_TOTAL = 16;
const DEFAULT_REMOTE_SSH_MAX_SESSIONS_PER_DEVICE = 1;
const DEFAULT_REMOTE_SSH_LOCAL_ADDR = "127.0.0.1:0";

function formatUnixTime(value: number, locale: string) {
  if (!value) {
    return "-";
  }
  const date = new Date(value * 1000);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return date.toLocaleString(locale === "ja" ? "ja-JP" : "en-US", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function shortHash(value?: string) {
  const trimmed = (value || "").trim();
  return trimmed.length > 12 ? trimmed.slice(0, 12) : trimmed || "-";
}

function policyToForm(policy?: RemoteSSHPolicy): PolicyForm {
  return {
    enabled: Boolean(policy?.enabled),
    maxTTLSec: String(policy?.max_ttl_sec || DEFAULT_REMOTE_SSH_TTL),
    allowedRunAsUser: policy?.allowed_run_as_user || "",
    requireReason: typeof policy?.require_reason === "boolean" ? policy.require_reason : true,
  };
}

function boundedTTL(value: string, fallback: number, max = 86400) {
  const trimmed = value.trim();
  const parsed = /^\d+$/.test(trimmed) ? Number.parseInt(trimmed, 10) : NaN;
  const upper = Math.min(Math.max(max, 60), 86400);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return Math.min(Math.max(fallback, 60), upper);
  }
  return Math.min(Math.max(parsed, 60), upper);
}

function shellQuote(value: string) {
  const singleLine = value.replace(/[\r\n]+/g, " ").trim();
  return `'${singleLine.replaceAll("'", "'\\''")}'`;
}

function defaultCenterURL() {
  if (typeof window === "undefined" || !window.location?.origin) {
    return "https://center.example.local";
  }
  return window.location.origin;
}

function shouldAllowLocalHTTP(centerURL: string) {
  try {
    const parsed = new URL(centerURL);
    if (parsed.protocol !== "http:") {
      return false;
    }
    return parsed.hostname === "127.0.0.1" || parsed.hostname === "::1" || parsed.hostname === "[::1]" || parsed.hostname === "localhost";
  } catch {
    return false;
  }
}

function remoteSSHCommand(deviceID: string, form: CommandForm, policy?: RemoteSSHPolicy) {
  const reason = form.reason.trim() || "maintenance";
  const ttl = boundedTTL(form.ttlSec, policy?.max_ttl_sec || DEFAULT_REMOTE_SSH_TTL, policy?.max_ttl_sec || 86400);
  const localAddr = form.localAddr.trim() || DEFAULT_REMOTE_SSH_LOCAL_ADDR;
  const centerURL = form.centerURL.trim() || defaultCenterURL();
  const args = [
    `--center ${shellQuote(centerURL)}`,
    `--api-base ${shellQuote(getAPIBasePath())}`,
    `--device ${shellQuote(deviceID)}`,
    `--local ${shellQuote(localAddr)}`,
    `--ttl ${ttl}`,
    `--reason ${shellQuote(reason)}`,
  ];
  if (form.centerCABundle.trim()) {
    args.push(`--center-ca-bundle ${shellQuote(form.centerCABundle.trim())}`);
  }
  if (form.centerServerName.trim()) {
    args.push(`--center-server-name ${shellQuote(form.centerServerName.trim())}`);
  }
  if (shouldAllowLocalHTTP(centerURL)) {
    args.push("--allow-insecure-http");
  }
  return [
    "export TUKUYOMI_ADMIN_TOKEN='<paste-personal-access-token>'",
    `tukuyomi remote-ssh \\\n  ${args.join(" \\\n  ")}`,
  ].join("\n");
}

export default function RemoteSSHPage() {
  const { locale, tx } = useI18n();
  const { deviceID: routeDeviceID = "" } = useParams();
  const deviceID = routeDeviceID || "";
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [enablingCenterService, setEnablingCenterService] = useState(false);
  const [copying, setCopying] = useState(false);
  const [message, setMessage] = useState("");
  const [messageTone, setMessageTone] = useState<"success" | "error">("success");
  const [view, setView] = useState<RemoteSSHViewResponse | null>(null);
  const [policyForm, setPolicyForm] = useState<PolicyForm>(() => policyToForm());
  const [commandForm, setCommandForm] = useState<CommandForm>({
    reason: "maintenance",
    ttlSec: String(DEFAULT_REMOTE_SSH_TTL),
    localAddr: DEFAULT_REMOTE_SSH_LOCAL_ADDR,
    centerURL: defaultCenterURL(),
    centerCABundle: "",
    centerServerName: "",
  });

  const policy = view?.policy;
  const device = view?.device;
  const sessions = Array.isArray(view?.sessions) ? view.sessions : [];
  const centerEnabled = view?.center_enabled === true;
  const canStart = Boolean(centerEnabled && device?.device_id && device.status === "approved" && policy?.enabled);
  const command = useMemo(() => remoteSSHCommand(deviceID, commandForm, policy), [commandForm, deviceID, policy]);

  const load = useCallback(async () => {
    if (!deviceID) {
      return;
    }
    setLoading(true);
    setMessage("");
    try {
      const data = await apiGetJson<RemoteSSHViewResponse>(`/devices/${encodeURIComponent(deviceID)}/remote-ssh?limit=50`);
      setView(data);
      setPolicyForm(policyToForm(data.policy));
      const ttl = String(data.policy?.max_ttl_sec || DEFAULT_REMOTE_SSH_TTL);
      setCommandForm((current) => ({
        ...current,
        ttlSec: current.ttlSec || ttl,
      }));
    } catch (err) {
      const fallback = tx("Failed to load Remote SSH");
      setView(null);
      setMessageTone("error");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setLoading(false);
    }
  }, [deviceID, tx]);

  useEffect(() => {
    void load();
  }, [load]);

  async function enableCenterService() {
    setEnablingCenterService(true);
    setMessage("");
    setMessageTone("success");
    try {
      const settings = await apiGetJson<CenterSettingsResponse>("/settings");
      const etag = settings.etag || "";
      if (!etag) {
        throw new Error(tx("Settings revision is missing. Refresh and try again."));
      }
      const currentConfig = settings.config || {};
      const currentRemoteSSH = currentConfig.remote_ssh || {};
      const currentCenter = currentRemoteSSH.center || {};
      const nextConfig: CenterSettingsConfig = {
        ...currentConfig,
        remote_ssh: {
          ...currentRemoteSSH,
          center: {
            ...currentCenter,
            enabled: true,
            max_ttl_sec: currentCenter.max_ttl_sec || DEFAULT_REMOTE_SSH_TTL,
            idle_timeout_sec: currentCenter.idle_timeout_sec || DEFAULT_REMOTE_SSH_IDLE_TIMEOUT,
            max_sessions_total: currentCenter.max_sessions_total || DEFAULT_REMOTE_SSH_MAX_SESSIONS_TOTAL,
            max_sessions_per_device: currentCenter.max_sessions_per_device || DEFAULT_REMOTE_SSH_MAX_SESSIONS_PER_DEVICE,
          },
        },
      };
      await apiPutJson<CenterSettingsResponse>("/settings", { config: nextConfig }, { headers: { "If-Match": etag } });
      setMessageTone("success");
      setMessage(tx("Remote SSH Center service enabled."));
      await load();
    } catch (err) {
      const fallback = tx("Failed to enable Remote SSH Center service");
      setMessageTone("error");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setEnablingCenterService(false);
    }
  }

  async function savePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!deviceID) {
      return;
    }
    setSaving(true);
    setMessage("");
    setMessageTone("success");
    try {
      const payload = {
        enabled: policyForm.enabled,
        max_ttl_sec: boundedTTL(policyForm.maxTTLSec, DEFAULT_REMOTE_SSH_TTL),
        allowed_run_as_user: policyForm.allowedRunAsUser.trim(),
        require_reason: policyForm.requireReason,
      };
      const data = await apiPutJson<RemoteSSHPolicyResponse>(`/devices/${encodeURIComponent(deviceID)}/remote-ssh/policy`, payload);
      setView((current) => ({ ...(current || {}), policy: data.policy || current?.policy }));
      if (data.policy) {
        setPolicyForm(policyToForm(data.policy));
      }
      setMessageTone("success");
      setMessage(tx("Remote SSH policy saved."));
    } catch (err) {
      const fallback = tx("Failed to save Remote SSH policy");
      setMessageTone("error");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setSaving(false);
    }
  }

  async function copyCommand() {
    setCopying(true);
    setMessage("");
    try {
      await navigator.clipboard.writeText(command);
      setMessageTone("success");
      setMessage(tx("Remote SSH command copied."));
    } catch (err) {
      const fallback = tx("Failed to copy Remote SSH command");
      setMessageTone("error");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setCopying(false);
    }
  }

  return (
    <div className="content-section rules-page remote-ssh-page">
      <div className="section-header">
        <div>
          <h2>{tx("Remote SSH")}</h2>
          <p className="section-note device-detail-id">{deviceID}</p>
          {loading ? <p className="section-note">{tx("Loading Remote SSH...")}</p> : null}
        </div>
      </div>

      {message ? (
        <p className={`form-message ${messageTone}`} role={messageTone === "error" ? "alert" : "status"}>
          {message}
        </p>
      ) : null}

      {!loading && !device ? <div className="empty">{tx("Device not found.")}</div> : null}

      {device ? (
        <>
          <section className="device-detail-section">
            <h3>{tx("Remote SSH overview")}</h3>
            <div className="summary-grid rules-summary-grid">
              <div>
                <span>{tx("Device status")}</span>
                <strong>{tx(device.status || "-")}</strong>
              </div>
              <div>
                <span>{tx("Policy")}</span>
                <strong>{policy?.enabled ? tx("Enabled") : tx("Disabled")}</strong>
              </div>
              <div>
                <span>{tx("Center service")}</span>
                <strong>{centerEnabled ? tx("Enabled") : tx("Disabled")}</strong>
              </div>
              <div>
                <span>{tx("Last seen")}</span>
                <strong>{formatUnixTime(device.last_seen_at_unix, locale)}</strong>
              </div>
            </div>
          </section>

          <section className="device-detail-section">
            <div className="device-detail-section-header">
              <div>
                <h3>{tx("Policy")}</h3>
                <p className="section-note">{tx("Remote SSH stays unavailable until this per-device policy is enabled.")}</p>
              </div>
            </div>
            <form onSubmit={savePolicy}>
              {!centerEnabled ? (
                <div className="form-message error remote-ssh-center-service-warning">
                  <span>{tx("Remote SSH Center service is OFF. Enable the Center service before enabling a Gateway policy.")}</span>
                  <button type="button" className="secondary" onClick={() => void enableCenterService()} disabled={enablingCenterService}>
                    {enablingCenterService ? tx("Working...") : tx("Enable Center service")}
                  </button>
                </div>
              ) : null}
              <div className="waf-upload-row remote-ssh-policy-row">
                <label className="toggle-row">
                  <input
                    type="checkbox"
                    checked={policyForm.enabled}
                    onChange={(event) => setPolicyForm((current) => ({ ...current, enabled: event.target.checked }))}
                    disabled={saving || enablingCenterService}
                  />
                  <span>{tx("Enable Remote SSH for this Gateway")}</span>
                </label>
                <label className="toggle-row">
                  <input
                    type="checkbox"
                    checked={policyForm.requireReason}
                    onChange={(event) => setPolicyForm((current) => ({ ...current, requireReason: event.target.checked }))}
                    disabled={saving || enablingCenterService}
                  />
                  <span>{tx("Require reason")}</span>
                </label>
                <label className="remote-ssh-policy-field">
                  <span>{tx("Max TTL seconds")}</span>
                  <input
                    type="number"
                    min={60}
                    max={86400}
                    value={policyForm.maxTTLSec}
                    onChange={(event) => setPolicyForm((current) => ({ ...current, maxTTLSec: event.target.value }))}
                    disabled={saving || enablingCenterService}
                  />
                </label>
                <label className="remote-ssh-policy-field remote-ssh-policy-user-field">
                  <span>{tx("Run as user")}</span>
                  <input
                    value={policyForm.allowedRunAsUser}
                    onChange={(event) => setPolicyForm((current) => ({ ...current, allowedRunAsUser: event.target.value }))}
                    placeholder="tukuyomi"
                    disabled={saving || enablingCenterService}
                  />
                  <span className="field-hint">{tx("Leave blank to use the Gateway config default.")}</span>
                </label>
                <button type="submit" disabled={saving || enablingCenterService}>
                  {saving ? tx("Saving...") : tx("Save policy")}
                </button>
              </div>
              <div className="form-footer remote-ssh-policy-meta">
                {policy?.updated_at_unix ? (
                  <span className="section-note">
                    {tx("Updated {time}", { time: formatUnixTime(policy.updated_at_unix, locale) })}
                    {policy.updated_by_username ? ` / ${policy.updated_by_username}` : ""}
                  </span>
                ) : null}
              </div>
            </form>
          </section>

          <section className="device-detail-section">
            <div className="device-detail-section-header">
              <div>
                <h3>{tx("CLI handoff")}</h3>
                <p className="section-note">{tx("The browser never generates SSH private keys. Run this command from the operator machine.")}</p>
              </div>
              <button type="button" onClick={() => void copyCommand()} disabled={!canStart || copying}>
                {copying ? tx("Copying...") : tx("Copy command")}
              </button>
            </div>
            {!canStart ? <p className="form-message error">{tx("Remote SSH requires Center service ON, an approved device, and an enabled policy.")}</p> : null}
            <div className="form-grid remote-ssh-command-grid">
              <label>
                <span>{tx("Reason")}</span>
                <input
                  value={commandForm.reason}
                  onChange={(event) => setCommandForm((current) => ({ ...current, reason: event.target.value }))}
                  placeholder="maintenance"
                />
              </label>
              <label>
                <span>{tx("TTL seconds")}</span>
                <input
                  type="number"
                  min={60}
                  max={policy?.max_ttl_sec || 86400}
                  value={commandForm.ttlSec}
                  onChange={(event) => setCommandForm((current) => ({ ...current, ttlSec: event.target.value }))}
                />
              </label>
              <label>
                <span>{tx("Local listen")}</span>
                <input
                  value={commandForm.localAddr}
                  onChange={(event) => setCommandForm((current) => ({ ...current, localAddr: event.target.value }))}
                  placeholder={DEFAULT_REMOTE_SSH_LOCAL_ADDR}
                />
              </label>
              <label>
                <span>{tx("Center URL")}</span>
                <input
                  value={commandForm.centerURL}
                  onChange={(event) => setCommandForm((current) => ({ ...current, centerURL: event.target.value }))}
                />
              </label>
              <label>
                <span>{tx("Center CA bundle")}</span>
                <input
                  value={commandForm.centerCABundle}
                  onChange={(event) => setCommandForm((current) => ({ ...current, centerCABundle: event.target.value }))}
                  placeholder="conf/center-ca.pem"
                />
              </label>
              <label>
                <span>{tx("Center server name")}</span>
                <input
                  value={commandForm.centerServerName}
                  onChange={(event) => setCommandForm((current) => ({ ...current, centerServerName: event.target.value }))}
                  placeholder="center.example.local"
                />
              </label>
            </div>
            <textarea className="rules-json-editor remote-ssh-command" value={command} readOnly spellCheck={false} aria-label={tx("Remote SSH command")} />
          </section>

          <section className="device-detail-section">
            <div className="device-detail-section-header">
              <div>
                <h3>{tx("Sessions")}</h3>
                <p className="section-note">{tx("Recent Remote SSH sessions for this Gateway.")}</p>
              </div>
            </div>
            <div className="table-wrap remote-ssh-session-table">
              <table>
                <thead>
                  <tr>
                    <th>{tx("Status")}</th>
                    <th>{tx("Reason")}</th>
                    <th>{tx("Requested by")}</th>
                    <th>{tx("Created")}</th>
                    <th>{tx("Expires")}</th>
                    <th>{tx("Gateway")}</th>
                    <th>{tx("Operator")}</th>
                    <th>{tx("Close reason")}</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((session) => (
                    <tr key={session.session_id}>
                      <td>
                        <span className={`token-status token-status-${session.status || "unknown"}`}>{tx(session.status || "-")}</span>
                      </td>
                      <td title={session.reason}>{session.reason || "-"}</td>
                      <td title={session.operator_ip || undefined}>{session.requested_by_username || "-"}</td>
                      <td title={session.session_id}>{formatUnixTime(session.created_at_unix, locale)}</td>
                      <td>{formatUnixTime(session.expires_at_unix, locale)}</td>
                      <td title={session.gateway_host_key_fingerprint_sha256 || undefined}>
                        {session.gateway_connected_at_unix ? formatUnixTime(session.gateway_connected_at_unix, locale) : "-"}
                        {session.gateway_host_key_fingerprint_sha256 ? (
                          <span className="table-subvalue">H: {shortHash(session.gateway_host_key_fingerprint_sha256)}</span>
                        ) : null}
                      </td>
                      <td title={session.operator_public_key_fingerprint_sha256 || undefined}>
                        {session.operator_connected_at_unix ? formatUnixTime(session.operator_connected_at_unix, locale) : "-"}
                        {session.operator_public_key_fingerprint_sha256 ? (
                          <span className="table-subvalue">K: {shortHash(session.operator_public_key_fingerprint_sha256)}</span>
                        ) : null}
                      </td>
                      <td title={session.close_reason || undefined}>{session.close_reason || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {sessions.length === 0 ? <div className="empty">{tx("No Remote SSH sessions.")}</div> : null}
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}
