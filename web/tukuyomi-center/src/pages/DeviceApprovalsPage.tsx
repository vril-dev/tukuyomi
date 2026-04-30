import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";

import { apiGetJson, apiPostJson } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import { getAPIBasePath } from "@/lib/runtime";

type EnrollmentRecord = {
  enrollment_id: number;
  device_id: string;
  key_id: string;
  public_key_fingerprint_sha256: string;
  requested_at_unix: number;
  remote_addr?: string;
  user_agent?: string;
};

type EnrollmentListResponse = {
  enrollments?: EnrollmentRecord[];
};

type DeviceRecord = {
  device_id: string;
  key_id: string;
  public_key_fingerprint_sha256: string;
  status: string;
  product_id?: string;
  runtime_role?: string;
  build_version?: string;
  go_version?: string;
  enrollment_token_prefix?: string;
  enrollment_token_label?: string;
  enrollment_token_status?: string;
  approved_at_unix: number;
  approved_by: string;
  last_seen_at_unix: number;
  updated_at_unix: number;
  revoked_at_unix: number;
  revoked_by: string;
  archived_at_unix: number;
  archived_by: string;
  config_snapshot_revision?: string;
  config_snapshot_at_unix: number;
  config_snapshot_bytes: number;
};

type DeviceListResponse = {
  devices?: DeviceRecord[];
};

type DeviceRevokeResponse = {
  device?: DeviceRecord;
};

type DeviceArchiveResponse = {
  device?: DeviceRecord;
};

type EnrollmentTokenRecord = {
  token_id: number;
  token_prefix: string;
  label: string;
  status: string;
  max_uses: number;
  use_count: number;
  expires_at_unix: number;
  created_at_unix: number;
  created_by: string;
  revoked_at_unix: number;
  revoked_by: string;
  last_used_at_unix: number;
  last_used_by_device: string;
};

type EnrollmentTokenListResponse = {
  tokens?: EnrollmentTokenRecord[];
};

type EnrollmentTokenCreateResponse = {
  token?: string;
  record?: EnrollmentTokenRecord;
};

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

function datetimeLocalToUnix(value: string) {
  const trimmed = value.trim();
  if (!trimmed) {
    return 0;
  }
  const millis = new Date(trimmed).getTime();
  if (!Number.isFinite(millis) || millis <= 0) {
    return 0;
  }
  return Math.floor(millis / 1000);
}

function boundedMaxUses(value: string) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 1;
  }
  return Math.min(parsed, 1000000);
}

function tokenEffectiveStatus(token: EnrollmentTokenRecord) {
  const now = Math.floor(Date.now() / 1000);
  if (token.status === "active" && token.expires_at_unix > 0 && token.expires_at_unix < now) {
    return "expired";
  }
  if (token.status === "active" && token.max_uses > 0 && token.use_count >= token.max_uses) {
    return "exhausted";
  }
  return token.status || "-";
}

function tokenCanEnroll(token: EnrollmentTokenRecord) {
  return tokenEffectiveStatus(token) === "active";
}

function deviceProxyAllowed(device: DeviceRecord) {
  return device.status === "approved";
}

function shortRevision(value?: string) {
  const trimmed = (value || "").trim();
  return trimmed ? trimmed.slice(0, 8) : "-";
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) {
    return "-";
  }
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function configSnapshotDownloadPath(device: DeviceRecord) {
  return `${getAPIBasePath()}/devices/${encodeURIComponent(device.device_id)}/config-snapshot`;
}

export default function DeviceApprovalsPage({ focusApprovals = false }: { focusApprovals?: boolean }) {
  const { locale, tx } = useI18n();
  const approvalRef = useRef<HTMLElement | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [enrollments, setEnrollments] = useState<EnrollmentRecord[]>([]);
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [tokens, setTokens] = useState<EnrollmentTokenRecord[]>([]);
  const [decidingID, setDecidingID] = useState<number | null>(null);
  const [tokenSaving, setTokenSaving] = useState(false);
  const [revokingTokenID, setRevokingTokenID] = useState<number | null>(null);
  const [revokingDeviceID, setRevokingDeviceID] = useState<string | null>(null);
  const [archivingDeviceID, setArchivingDeviceID] = useState<string | null>(null);
  const [createdToken, setCreatedToken] = useState("");
  const [tokenMessage, setTokenMessage] = useState("");
  const [tokenMessageTone, setTokenMessageTone] = useState<"success" | "error">("success");
  const [showInactiveTokens, setShowInactiveTokens] = useState(false);
  const [showArchivedDevices, setShowArchivedDevices] = useState(false);
  const [managedDevice, setManagedDevice] = useState<DeviceRecord | null>(null);
  const [tokenForm, setTokenForm] = useState({
    label: "",
    maxUses: "1",
    expiresAt: "",
  });

  const load = useCallback(async () => {
    setLoading(true);
    setMessage("");
    try {
      const [enrollmentData, tokenData, deviceData] = await Promise.all([
        apiGetJson<EnrollmentListResponse>("/devices/enrollments?status=pending&limit=50"),
        apiGetJson<EnrollmentTokenListResponse>("/enrollment-tokens?limit=50"),
        apiGetJson<DeviceListResponse>(showArchivedDevices ? "/devices?include_archived=1" : "/devices"),
      ]);
      setEnrollments(Array.isArray(enrollmentData.enrollments) ? enrollmentData.enrollments : []);
      setTokens(Array.isArray(tokenData.tokens) ? tokenData.tokens : []);
      setDevices(Array.isArray(deviceData.devices) ? deviceData.devices : []);
    } catch (err) {
      const fallback = tx("Failed to load device approvals");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setLoading(false);
    }
  }, [showArchivedDevices, tx]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!focusApprovals) {
      return;
    }
    approvalRef.current?.scrollIntoView({ block: "start" });
  }, [focusApprovals, enrollments.length]);

  async function decide(enrollmentID: number, action: "approve" | "reject") {
    setDecidingID(enrollmentID);
    setMessage("");
    try {
      await apiPostJson(`/devices/enrollments/${enrollmentID}/${action}`, action === "reject" ? { reason: "rejected from center ui" } : {});
      await load();
    } catch (err) {
      const fallback = tx(action === "approve" ? "Failed to approve enrollment" : "Failed to reject enrollment");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setDecidingID(null);
    }
  }

  async function createToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setTokenSaving(true);
    setTokenMessage("");
    setTokenMessageTone("success");
    setCreatedToken("");
    try {
      const data = await apiPostJson<EnrollmentTokenCreateResponse>("/enrollment-tokens", {
        label: tokenForm.label.trim(),
        max_uses: boundedMaxUses(tokenForm.maxUses),
        expires_at_unix: datetimeLocalToUnix(tokenForm.expiresAt),
      });
      if (data.token) {
        setCreatedToken(data.token);
      }
      if (data.record) {
        setTokens((current) => [data.record as EnrollmentTokenRecord, ...current]);
      } else {
        await load();
      }
      setTokenForm((current) => ({ ...current, label: "" }));
      setTokenMessageTone("success");
      setTokenMessage(tx("Enrollment token created."));
    } catch (err) {
      const fallback = tx("Failed to create enrollment token");
      setTokenMessageTone("error");
      setTokenMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setTokenSaving(false);
    }
  }

  async function revokeToken(tokenID: number) {
    setRevokingTokenID(tokenID);
    setTokenMessage("");
    setTokenMessageTone("success");
    try {
      await apiPostJson(`/enrollment-tokens/${tokenID}/revoke`, {});
      await load();
    } catch (err) {
      const fallback = tx("Failed to revoke enrollment token");
      setTokenMessageTone("error");
      setTokenMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setRevokingTokenID(null);
    }
  }

  async function revokeDevice(deviceID: string) {
    setRevokingDeviceID(deviceID);
    setMessage("");
    try {
      await apiPostJson<DeviceRevokeResponse>(`/devices/${encodeURIComponent(deviceID)}/revoke`, {});
      await load();
      setManagedDevice(null);
    } catch (err) {
      const fallback = tx("Failed to revoke device approval");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setRevokingDeviceID(null);
    }
  }

  async function archiveDevice(deviceID: string) {
    setArchivingDeviceID(deviceID);
    setMessage("");
    try {
      await apiPostJson<DeviceArchiveResponse>(`/devices/${encodeURIComponent(deviceID)}/archive`, {});
      await load();
      setManagedDevice(null);
    } catch (err) {
      const fallback = tx("Failed to archive device");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setArchivingDeviceID(null);
    }
  }

  const activeTokens = tokens.filter(tokenCanEnroll);
  const inactiveTokenCount = tokens.length - activeTokens.length;
  const visibleTokens = showInactiveTokens ? tokens : activeTokens;

  return (
    <div className="content-panel">
      <section className="content-section">
        <div className="section-header">
          <div>
            <h2 className="section-title">{tx("Enrollment tokens")}</h2>
            <p className="section-note">{tx("Issue a registration token before a Gateway can request device approval.")}</p>
            {loading ? <p className="section-note">{tx("Loading device approvals...")}</p> : null}
          </div>
        </div>
        <div className="section-toolbar">
          <label className="toggle-row">
            <input type="checkbox" checked={showInactiveTokens} onChange={(event) => setShowInactiveTokens(event.target.checked)} />
            <span>{tx("Show inactive token history")}</span>
          </label>
          {inactiveTokenCount > 0 ? <span className="section-note">{tx("{count} inactive token(s) hidden", { count: inactiveTokenCount })}</span> : null}
        </div>
        <form onSubmit={createToken}>
          <div className="form-grid">
            <label>
              <span>{tx("Label")}</span>
              <input
                value={tokenForm.label}
                onChange={(event) => setTokenForm((current) => ({ ...current, label: event.target.value }))}
                placeholder={tx("factory batch")}
                disabled={tokenSaving}
              />
            </label>
            <label>
              <span>{tx("Max uses")}</span>
              <input
                type="number"
                min={1}
                max={1000000}
                value={tokenForm.maxUses}
                onChange={(event) => setTokenForm((current) => ({ ...current, maxUses: event.target.value }))}
                disabled={tokenSaving}
              />
            </label>
            <label>
              <span>{tx("Expires at")}</span>
              <input
                type="datetime-local"
                value={tokenForm.expiresAt}
                onChange={(event) => setTokenForm((current) => ({ ...current, expiresAt: event.target.value }))}
                disabled={tokenSaving}
              />
              <span className="field-hint">{tx("Leave blank for no expiration.")}</span>
            </label>
          </div>
          <div className="form-footer">
            <button type="submit" disabled={tokenSaving}>
              {tokenSaving ? tx("Creating enrollment token...") : tx("Create enrollment token")}
            </button>
            {tokenMessage ? (
              <span className={`form-message ${tokenMessageTone}`} role={tokenMessageTone === "error" ? "alert" : "status"}>
                {tokenMessage}
              </span>
            ) : null}
          </div>
        </form>

        {createdToken ? (
          <div className="token-created">
            <label>
              <span>{tx("Generated token")}</span>
              <input value={createdToken} readOnly onFocus={(event) => event.currentTarget.select()} />
            </label>
            <p>{tx("Copy and store this token now. It will not be shown again.")}</p>
          </div>
        ) : null}

        <div className="table-wrap token-table">
          <table>
            <thead>
              <tr>
                <th>{tx("Token prefix")}</th>
                <th>{tx("Label")}</th>
                <th>{tx("Status")}</th>
                <th>{tx("Usable")}</th>
                <th>{tx("Uses")}</th>
                <th>{tx("Expires")}</th>
                <th>{tx("Last used")}</th>
                <th>{tx("Actions")}</th>
              </tr>
            </thead>
            <tbody>
              {visibleTokens.map((token) => {
                const effectiveStatus = tokenEffectiveStatus(token);
                const canEnroll = effectiveStatus === "active";
                return (
                  <tr key={token.token_id}>
                    <td title={token.token_prefix}>{token.token_prefix || "-"}</td>
                    <td title={token.label}>{token.label || "-"}</td>
                    <td>
                      <span className={`token-status token-status-${effectiveStatus}`}>{tx(effectiveStatus)}</span>
                    </td>
                    <td>
                      <span className={`token-status ${canEnroll ? "token-status-active" : "token-status-blocked"}`}>
                        {canEnroll ? tx("Can enroll") : tx("Cannot enroll")}
                      </span>
                    </td>
                    <td>
                      {token.use_count}/{token.max_uses || "-"}
                    </td>
                    <td>{formatUnixTime(token.expires_at_unix, locale)}</td>
                    <td title={token.last_used_by_device || undefined}>{formatUnixTime(token.last_used_at_unix, locale)}</td>
                    <td className="actions-cell">
                      {token.status === "active" ? (
                        <button
                          type="button"
                          className="danger"
                          onClick={() => void revokeToken(token.token_id)}
                          disabled={revokingTokenID === token.token_id}
                        >
                          {revokingTokenID === token.token_id ? tx("Revoking...") : tx("Revoke")}
                        </button>
                      ) : (
                        "-"
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {visibleTokens.length === 0 ? (
            <div className="empty">{showInactiveTokens ? tx("No enrollment tokens.") : tx("No active enrollment tokens.")}</div>
          ) : null}
        </div>
        <p className="section-note">{tx("Revoked, expired, or exhausted tokens are kept as audit history and cannot enroll devices.")}</p>
        {message ? <p className="form-message error">{message}</p> : null}
      </section>

      <section id="device-approvals" ref={approvalRef} className="content-section">
        <h2 className="section-title">{tx("Device enrollment approvals")}</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{tx("Device")}</th>
                <th>{tx("Key")}</th>
                <th>{tx("Fingerprint")}</th>
                <th>{tx("Requested")}</th>
                <th>{tx("Actions")}</th>
              </tr>
            </thead>
            <tbody>
              {enrollments.map((enrollment) => (
                <tr key={enrollment.enrollment_id}>
                  <td title={enrollment.device_id}>{enrollment.device_id}</td>
                  <td title={enrollment.key_id}>{enrollment.key_id}</td>
                  <td title={enrollment.public_key_fingerprint_sha256}>{enrollment.public_key_fingerprint_sha256}</td>
                  <td>{formatUnixTime(enrollment.requested_at_unix, locale)}</td>
                  <td className="actions-cell">
                    <div className="inline-actions">
                      <button
                        type="button"
                        onClick={() => void decide(enrollment.enrollment_id, "approve")}
                        disabled={decidingID === enrollment.enrollment_id}
                      >
                        {tx("Approve")}
                      </button>
                      <button
                        type="button"
                        className="danger"
                        onClick={() => void decide(enrollment.enrollment_id, "reject")}
                        disabled={decidingID === enrollment.enrollment_id}
                      >
                        {tx("Reject")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {enrollments.length === 0 ? <div className="empty">{tx("No pending enrollments.")}</div> : null}
        </div>
      </section>

      <section className="content-section">
        <div className="section-header">
          <div>
            <h2 className="section-title">{tx("Registered devices")}</h2>
          </div>
        </div>
        <div className="section-toolbar">
          <label className="toggle-row">
            <input type="checkbox" checked={showArchivedDevices} onChange={(event) => setShowArchivedDevices(event.target.checked)} />
            <span>{tx("Show archived devices")}</span>
          </label>
        </div>
        <div className="table-wrap registered-device-table">
          <table>
            <thead>
              <tr>
                <th>{tx("Device")}</th>
                <th>{tx("Key")}</th>
                <th>{tx("Fingerprint")}</th>
                <th>{tx("Product ID")}</th>
                <th>{tx("Runtime")}</th>
                <th>{tx("Version")}</th>
                <th>{tx("Config")}</th>
                <th>{tx("Enrollment token")}</th>
                <th>{tx("Token status")}</th>
                <th>{tx("Status")}</th>
                <th>{tx("Proxy access")}</th>
                <th>{tx("Approved")}</th>
                <th>{tx("Last seen")}</th>
                <th>{tx("Actions")}</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => (
                <tr key={`${device.device_id}:${device.key_id}`}>
                  <td title={device.device_id}>{device.device_id}</td>
                  <td title={device.key_id}>{device.key_id}</td>
                  <td title={device.public_key_fingerprint_sha256}>{device.public_key_fingerprint_sha256}</td>
                  <td title={device.product_id || undefined}>{device.product_id || "-"}</td>
                  <td title={device.runtime_role || undefined}>{device.runtime_role || "-"}</td>
                  <td title={[device.build_version, device.go_version].filter(Boolean).join(" / ") || undefined}>
                    {device.build_version || "-"}
                    {device.go_version ? <span className="table-subvalue">{device.go_version}</span> : null}
                  </td>
                  <td title={device.config_snapshot_revision || undefined}>
                    {device.config_snapshot_revision ? (
                      <>
                        <span>R: {shortRevision(device.config_snapshot_revision)}</span>
                        <span className="table-subvalue">{formatUnixTime(device.config_snapshot_at_unix, locale)}</span>
                      </>
                    ) : (
                      "-"
                    )}
                  </td>
                  <td title={device.enrollment_token_label || device.enrollment_token_prefix || undefined}>
                    {device.enrollment_token_label || device.enrollment_token_prefix || "-"}
                  </td>
                  <td>
                    {device.enrollment_token_status ? (
                      <span className={`token-status token-status-${device.enrollment_token_status}`}>{tx(device.enrollment_token_status)}</span>
                    ) : (
                      "-"
                    )}
                  </td>
                  <td>
                    <span className={`token-status token-status-${device.status || "unknown"}`}>{tx(device.status || "-")}</span>
                  </td>
                  <td>
                    <span className={`token-status ${deviceProxyAllowed(device) ? "token-status-approved" : "token-status-blocked"}`}>
                      {deviceProxyAllowed(device) ? tx("Proxy allowed") : tx("Proxy locked")}
                    </span>
                  </td>
                  <td title={device.approved_by || undefined}>{formatUnixTime(device.approved_at_unix, locale)}</td>
                  <td>{formatUnixTime(device.last_seen_at_unix, locale)}</td>
                  <td className="actions-cell">
                    <button type="button" onClick={() => setManagedDevice(device)}>
                      {tx("Manage")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {devices.length === 0 ? <div className="empty">{tx("No registered devices.")}</div> : null}
        </div>
      </section>

      {managedDevice ? (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setManagedDevice(null)}>
          <div className="modal-panel device-action-modal" role="dialog" aria-modal="true" onMouseDown={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h2 className="section-title">{tx("Device actions")}</h2>
                <p className="section-note">{managedDevice.device_id}</p>
              </div>
              <button type="button" className="secondary" onClick={() => setManagedDevice(null)}>
                {tx("Close")}
              </button>
            </div>
            <div className="summary-grid">
              <div>
                <span>{tx("Status")}</span>
                <strong>{tx(managedDevice.status || "-")}</strong>
              </div>
              <div>
                <span>{tx("Proxy access")}</span>
                <strong>{deviceProxyAllowed(managedDevice) ? tx("Proxy allowed") : tx("Proxy locked")}</strong>
              </div>
              <div>
                <span>{tx("Config revision")}</span>
                <strong>{shortRevision(managedDevice.config_snapshot_revision)}</strong>
              </div>
              <div>
                <span>{tx("Config size")}</span>
                <strong>{formatBytes(managedDevice.config_snapshot_bytes)}</strong>
              </div>
              <div>
                <span>{tx("Config received")}</span>
                <strong>{formatUnixTime(managedDevice.config_snapshot_at_unix, locale)}</strong>
              </div>
              <div>
                <span>{tx("Last seen")}</span>
                <strong>{formatUnixTime(managedDevice.last_seen_at_unix, locale)}</strong>
              </div>
            </div>
            <div className="modal-actions">
              {managedDevice.config_snapshot_revision ? (
                <a className="button-link" href={configSnapshotDownloadPath(managedDevice)}>
                  {tx("Config download")}
                </a>
              ) : (
                <span className="section-note">{tx("No config snapshot received.")}</span>
              )}
              {managedDevice.status === "approved" ? (
                <button
                  type="button"
                  className="danger"
                  onClick={() => void revokeDevice(managedDevice.device_id)}
                  disabled={revokingDeviceID === managedDevice.device_id}
                >
                  {revokingDeviceID === managedDevice.device_id ? tx("Revoking...") : tx("Revoke approval")}
                </button>
              ) : null}
              {managedDevice.status === "revoked" ? (
                <button
                  type="button"
                  onClick={() => void archiveDevice(managedDevice.device_id)}
                  disabled={archivingDeviceID === managedDevice.device_id}
                >
                  {archivingDeviceID === managedDevice.device_id ? tx("Archiving...") : tx("Archive")}
                </button>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
