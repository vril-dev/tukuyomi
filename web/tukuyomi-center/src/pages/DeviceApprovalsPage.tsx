import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { apiGetJson, apiPostJson } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import { getAPIBasePath } from "@/lib/runtime";

type EnrollmentRecord = {
  enrollment_id: number;
  device_id: string;
  key_id: string;
  public_key_fingerprint_sha256: string;
  enrollment_token_id?: number;
  enrollment_token_prefix?: string;
  enrollment_token_label?: string;
  enrollment_token_status?: string;
  requested_at_unix: number;
  remote_addr?: string;
  user_agent?: string;
};

type EnrollmentListResponse = {
  enrollments?: EnrollmentRecord[];
};

type DeviceRuntimeSummary = {
  runtime_family: string;
  runtime_id: string;
  display_name?: string;
  detected_version?: string;
  source?: string;
  available: boolean;
  availability_message?: string;
  module_count: number;
  usage_reported: boolean;
  app_count: number;
  generated_targets?: string[];
  process_running: boolean;
  artifact_revision?: string;
  artifact_hash?: string;
  apply_state?: string;
  apply_error?: string;
  updated_at_unix: number;
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
  os?: string;
  arch?: string;
  kernel_version?: string;
  distro_id?: string;
  distro_id_like?: string;
  distro_version?: string;
  runtime_deployment_supported?: boolean;
  runtime_inventory?: DeviceRuntimeSummary[];
  enrollment_token_id?: number;
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

type DeviceConfigSnapshotRecord = {
  device_id: string;
  revision: string;
  payload_hash: string;
  size_bytes: number;
  created_at_unix: number;
  created_at: string;
};

type DeviceConfigSnapshotListResponse = {
  snapshots?: DeviceConfigSnapshotRecord[];
  limit: number;
  offset: number;
  next_offset: number;
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

type CenterSettingsResponse = {
  config?: {
    enrollment_token_default_max_uses?: number;
    enrollment_token_default_ttl_seconds?: number;
  };
};

const DEFAULT_ENROLLMENT_TOKEN_MAX_USES = 10;
const SECONDS_PER_DAY = 24 * 60 * 60;
const CONFIG_SNAPSHOT_PAGE_SIZE = 6;

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
  if (!value.trim()) {
    return 0;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 0;
  }
  return Math.min(parsed, 1000000);
}

function normalizeTokenDefaults(settings: CenterSettingsResponse) {
  const maxUses = Number(settings.config?.enrollment_token_default_max_uses);
  const ttlSeconds = Number(settings.config?.enrollment_token_default_ttl_seconds);
  return {
    maxUses: Number.isFinite(maxUses) && maxUses > 0 ? Math.min(maxUses, 1000000) : DEFAULT_ENROLLMENT_TOKEN_MAX_USES,
    ttlSeconds: Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? ttlSeconds : 0,
  };
}

function tokenDefaultTTLLabel(seconds: number, tx: (key: string, vars?: Record<string, string | number>) => string) {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return tx("no expiration");
  }
  return tx("{count} days", { count: Math.ceil(seconds / SECONDS_PER_DAY) });
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

function normalizeTokenID(value?: number) {
  const numeric = typeof value === "number" ? value : 0;
  return Number.isFinite(numeric) && numeric > 0 ? numeric : 0;
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

function platformLabel(device: DeviceRecord) {
  const distro = [device.distro_id, device.distro_version].filter(Boolean).join(" ");
  const os = distro || device.os || "";
  return [os, device.arch].filter(Boolean).join(" / ") || "-";
}

function platformTitle(device: DeviceRecord) {
  return [
    [device.os, device.arch].filter(Boolean).join("/"),
    [device.distro_id, device.distro_version].filter(Boolean).join(" "),
    device.distro_id_like ? `like: ${device.distro_id_like}` : "",
    device.kernel_version ? `kernel: ${device.kernel_version}` : "",
  ]
    .filter(Boolean)
    .join(" | ");
}

function configSnapshotDownloadPath(device: DeviceRecord) {
  return `${getAPIBasePath()}/devices/${encodeURIComponent(device.device_id)}/config-snapshot`;
}

function configSnapshotRevisionPath(deviceID: string, revision: string, download = false) {
  const suffix = download ? "?download=1" : "";
  return `${getAPIBasePath()}/devices/${encodeURIComponent(deviceID)}/config-snapshots/${encodeURIComponent(revision)}${suffix}`;
}

function deviceDetailPath(deviceID: string) {
  return `/device-approvals/devices/${encodeURIComponent(deviceID)}`;
}

export default function DeviceApprovalsPage({ focusApprovals = false }: { focusApprovals?: boolean }) {
  const { locale, tx } = useI18n();
  const navigate = useNavigate();
  const { deviceID: routeDeviceID = "" } = useParams();
  const selectedDeviceID = routeDeviceID || "";
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
  const [showHiddenTokens, setShowHiddenTokens] = useState(false);
  const [showArchivedDevices, setShowArchivedDevices] = useState(false);
  const [tokenDefaults, setTokenDefaults] = useState({ maxUses: DEFAULT_ENROLLMENT_TOKEN_MAX_USES, ttlSeconds: 0 });
  const [configSnapshots, setConfigSnapshots] = useState<DeviceConfigSnapshotRecord[]>([]);
  const [configSnapshotOffset, setConfigSnapshotOffset] = useState(0);
  const [configSnapshotNextOffset, setConfigSnapshotNextOffset] = useState(0);
  const [configSnapshotLoading, setConfigSnapshotLoading] = useState(false);
  const [configSnapshotMessage, setConfigSnapshotMessage] = useState("");
  const [configSnapshotViewer, setConfigSnapshotViewer] = useState<{ revision: string; payload: string } | null>(null);
  const [tokenForm, setTokenForm] = useState({
    label: "",
    maxUses: "",
    expiresAt: "",
  });

  const load = useCallback(async () => {
    setLoading(true);
    setMessage("");
    try {
      const deviceListPath = showArchivedDevices || selectedDeviceID ? "/devices?include_archived=1" : "/devices";
      const [enrollmentData, tokenData, deviceData, settingsData] = await Promise.all([
        apiGetJson<EnrollmentListResponse>("/devices/enrollments?status=pending&limit=50"),
        apiGetJson<EnrollmentTokenListResponse>("/enrollment-tokens?limit=500"),
        apiGetJson<DeviceListResponse>(deviceListPath),
        apiGetJson<CenterSettingsResponse>("/settings"),
      ]);
      setEnrollments(Array.isArray(enrollmentData.enrollments) ? enrollmentData.enrollments : []);
      setTokens(Array.isArray(tokenData.tokens) ? tokenData.tokens : []);
      setDevices(Array.isArray(deviceData.devices) ? deviceData.devices : []);
      setTokenDefaults(normalizeTokenDefaults(settingsData));
    } catch (err) {
      const fallback = tx("Failed to load device approvals");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setLoading(false);
    }
  }, [selectedDeviceID, showArchivedDevices, tx]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!focusApprovals) {
      return;
    }
    approvalRef.current?.scrollIntoView({ block: "start" });
  }, [focusApprovals, enrollments.length]);

  const loadConfigSnapshots = useCallback(
    async (deviceID: string, offset: number) => {
      setConfigSnapshotLoading(true);
      setConfigSnapshotMessage("");
      setConfigSnapshotViewer(null);
      try {
        const data = await apiGetJson<DeviceConfigSnapshotListResponse>(
          `/devices/${encodeURIComponent(deviceID)}/config-snapshots?limit=${CONFIG_SNAPSHOT_PAGE_SIZE}&offset=${offset}`,
        );
        setConfigSnapshots(Array.isArray(data.snapshots) ? data.snapshots : []);
        setConfigSnapshotNextOffset(Number.isFinite(data.next_offset) && data.next_offset > 0 ? data.next_offset : 0);
      } catch (err) {
        const fallback = tx("Failed to load config snapshots");
        setConfigSnapshots([]);
        setConfigSnapshotNextOffset(0);
        setConfigSnapshotMessage(err instanceof Error ? err.message || fallback : fallback);
      } finally {
        setConfigSnapshotLoading(false);
      }
    },
    [tx],
  );

  const managedDevice = useMemo(() => {
    if (!selectedDeviceID) {
      return null;
    }
    return devices.find((device) => device.device_id === selectedDeviceID) || null;
  }, [devices, selectedDeviceID]);
  const managedDeviceID = managedDevice?.device_id || "";

  useEffect(() => {
    if (!managedDeviceID) {
      setConfigSnapshots([]);
      setConfigSnapshotOffset(0);
      setConfigSnapshotNextOffset(0);
      setConfigSnapshotMessage("");
      setConfigSnapshotViewer(null);
      return;
    }
    void loadConfigSnapshots(managedDeviceID, configSnapshotOffset);
  }, [managedDeviceID, configSnapshotOffset, loadConfigSnapshots]);

  useEffect(() => {
    if (!configSnapshotViewer) {
      return;
    }
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setConfigSnapshotViewer(null);
      }
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", closeOnEscape);
    };
  }, [configSnapshotViewer]);

  async function viewConfigSnapshot(deviceID: string, revision: string) {
    setConfigSnapshotMessage("");
    setConfigSnapshotViewer(null);
    try {
      const data = await apiGetJson<unknown>(`/devices/${encodeURIComponent(deviceID)}/config-snapshots/${encodeURIComponent(revision)}`);
      const payload = JSON.stringify(data, null, 2);
      setConfigSnapshotViewer({ revision, payload: payload || "" });
    } catch (err) {
      const fallback = tx("Failed to load config snapshot");
      setConfigSnapshotMessage(err instanceof Error ? err.message || fallback : fallback);
    }
  }

  function resetDeviceActionState() {
    setConfigSnapshotOffset(0);
    setConfigSnapshotNextOffset(0);
    setConfigSnapshots([]);
    setConfigSnapshotMessage("");
    setConfigSnapshotViewer(null);
  }

  function openDeviceActions(device: DeviceRecord) {
    resetDeviceActionState();
    navigate(deviceDetailPath(device.device_id));
  }

  function closeDeviceActions() {
    resetDeviceActionState();
    navigate("/device-approvals");
  }

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
      closeDeviceActions();
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
      closeDeviceActions();
    } catch (err) {
      const fallback = tx("Failed to archive device");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setArchivingDeviceID(null);
    }
  }

  const linkedTokenRefs = useMemo(() => {
    const ids = new Set<number>();
    const prefixes = new Set<string>();
    for (const device of devices) {
      if (device.status === "archived" || device.enrollment_token_status === "revoked") {
        continue;
      }
      const tokenID = normalizeTokenID(device.enrollment_token_id);
      if (tokenID > 0) {
        ids.add(tokenID);
      }
      if (device.enrollment_token_prefix) {
        prefixes.add(device.enrollment_token_prefix);
      }
    }
    for (const enrollment of enrollments) {
      if (enrollment.enrollment_token_status === "revoked") {
        continue;
      }
      const tokenID = normalizeTokenID(enrollment.enrollment_token_id);
      if (tokenID > 0) {
        ids.add(tokenID);
      }
      if (enrollment.enrollment_token_prefix) {
        prefixes.add(enrollment.enrollment_token_prefix);
      }
    }
    return { ids, prefixes };
  }, [devices, enrollments]);

  const visibleByDefaultTokens = tokens.filter((token) => {
    if (tokenCanEnroll(token)) {
      return true;
    }
    if (token.status === "revoked") {
      return false;
    }
    return linkedTokenRefs.ids.has(token.token_id) || linkedTokenRefs.prefixes.has(token.token_prefix);
  });
  const hiddenTokenCount = tokens.length - visibleByDefaultTokens.length;
  const visibleTokens = showHiddenTokens ? tokens : visibleByDefaultTokens;

  if (selectedDeviceID) {
    return (
      <div className="content-panel">
        <section className="content-section device-detail-page">
          <div className="section-header">
            <div>
              <h2 className="section-title">{tx("Device actions")}</h2>
              <p className="section-note device-detail-id">{selectedDeviceID}</p>
              {loading ? <p className="section-note">{tx("Loading device details...")}</p> : null}
            </div>
            <button type="button" className="secondary" onClick={closeDeviceActions}>
              {tx("Back to registered devices")}
            </button>
          </div>
          {message ? <p className="form-message error">{message}</p> : null}
          {!loading && !managedDevice ? <div className="empty">{tx("Device not found.")}</div> : null}
          {managedDevice ? (
            <>
              <div className="summary-grid">
                <div>
                  <span>{tx("Status")}</span>
                  <strong>{tx(managedDevice.status || "-")}</strong>
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
              <div className="device-actions">
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
              <div className="device-detail-section">
                <div className="device-detail-section-header">
                  <div>
                    <h3>{tx("Platform details")}</h3>
                  </div>
                </div>
                <div className="summary-grid platform-detail-grid">
                  <div>
                    <span>{tx("OS")}</span>
                    <strong title={managedDevice.os || undefined}>{managedDevice.os || "-"}</strong>
                  </div>
                  <div>
                    <span>{tx("Architecture")}</span>
                    <strong title={managedDevice.arch || undefined}>{managedDevice.arch || "-"}</strong>
                  </div>
                  <div>
                    <span>{tx("Distro ID")}</span>
                    <strong title={managedDevice.distro_id || undefined}>{managedDevice.distro_id || "-"}</strong>
                  </div>
                  <div>
                    <span>{tx("Distro version")}</span>
                    <strong title={managedDevice.distro_version || undefined}>{managedDevice.distro_version || "-"}</strong>
                  </div>
                  <div>
                    <span>{tx("Distro ID like")}</span>
                    <strong title={managedDevice.distro_id_like || undefined}>{managedDevice.distro_id_like || "-"}</strong>
                  </div>
                  <div>
                    <span>{tx("Kernel version")}</span>
                    <strong title={managedDevice.kernel_version || undefined}>{managedDevice.kernel_version || "-"}</strong>
                  </div>
                </div>
              </div>
              <div className="device-detail-section">
                <div className="device-detail-section-header">
                  <div>
                    <h3>{tx("Config snapshots")}</h3>
                    <p className="section-note">{tx("Latest 6 snapshots are shown per page. History rows do not include JSON payloads until opened.")}</p>
                  </div>
                  {configSnapshotLoading ? <span className="section-note">{tx("Loading config snapshots...")}</span> : null}
                </div>
                <div className="table-wrap config-snapshot-table">
                  <table>
                    <thead>
                      <tr>
                        <th>{tx("Actions")}</th>
                        <th>{tx("Revision")}</th>
                        <th>{tx("Received")}</th>
                        <th>{tx("Size")}</th>
                        <th>{tx("Payload hash")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {configSnapshots.map((snapshot) => (
                        <tr key={snapshot.revision}>
                          <td className="actions-cell">
                            <div className="inline-actions">
                              <button type="button" onClick={() => void viewConfigSnapshot(snapshot.device_id, snapshot.revision)}>
                                {tx("View JSON")}
                              </button>
                              <a className="button-link" href={configSnapshotRevisionPath(snapshot.device_id, snapshot.revision, true)}>
                                {tx("Download JSON")}
                              </a>
                            </div>
                          </td>
                          <td title={snapshot.revision}>R: {shortRevision(snapshot.revision)}</td>
                          <td>{formatUnixTime(snapshot.created_at_unix, locale)}</td>
                          <td>{formatBytes(snapshot.size_bytes)}</td>
                          <td title={snapshot.payload_hash}>H: {shortRevision(snapshot.payload_hash)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {configSnapshots.length === 0 && !configSnapshotLoading ? <div className="empty">{tx("No config snapshots.")}</div> : null}
                </div>
                <div className="snapshot-pager">
                  <span className="section-note">
                    {tx("Showing {start}-{end}", {
                      start: configSnapshots.length ? configSnapshotOffset + 1 : 0,
                      end: configSnapshotOffset + configSnapshots.length,
                    })}
                  </span>
                  <div className="inline-actions">
                    <button
                      type="button"
                      onClick={() => setConfigSnapshotOffset(Math.max(0, configSnapshotOffset - CONFIG_SNAPSHOT_PAGE_SIZE))}
                      disabled={configSnapshotLoading || configSnapshotOffset <= 0}
                    >
                      {tx("Previous")}
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfigSnapshotOffset(configSnapshotNextOffset)}
                      disabled={configSnapshotLoading || configSnapshotNextOffset <= 0}
                    >
                      {tx("Next")}
                    </button>
                  </div>
                </div>
                {configSnapshotMessage ? <p className="form-message error">{configSnapshotMessage}</p> : null}
              </div>
            </>
          ) : null}
        </section>
        {configSnapshotViewer ? (
          <div
            className="config-snapshot-modal-backdrop"
            role="presentation"
            onMouseDown={() => setConfigSnapshotViewer(null)}
          >
            <div
              className="config-snapshot-modal"
              role="dialog"
              aria-modal="true"
              aria-labelledby="config-snapshot-modal-title"
              onMouseDown={(event) => event.stopPropagation()}
            >
              <div className="device-detail-section-header">
                <div>
                  <h3 id="config-snapshot-modal-title">{tx("Config JSON")}</h3>
                  <p className="section-note">R: {shortRevision(configSnapshotViewer.revision)}</p>
                </div>
                <button type="button" className="secondary" onClick={() => setConfigSnapshotViewer(null)}>
                  {tx("Close")}
                </button>
              </div>
              <textarea
                className="rules-json-editor config-snapshot-json"
                value={configSnapshotViewer.payload}
                readOnly
                spellCheck={false}
                aria-label={tx("Config JSON")}
              />
            </div>
          </div>
        ) : null}
      </div>
    );
  }

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
            <input type="checkbox" checked={showHiddenTokens} onChange={(event) => setShowHiddenTokens(event.target.checked)} />
            <span>{tx("Show hidden token history")}</span>
          </label>
          {hiddenTokenCount > 0 ? <span className="section-note">{tx("{count} hidden token(s)", { count: hiddenTokenCount })}</span> : null}
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
                placeholder={String(tokenDefaults.maxUses)}
                disabled={tokenSaving}
              />
              <span className="field-hint">{tx("Settings default: {value}", { value: tokenDefaults.maxUses })}</span>
            </label>
            <label>
              <span>{tx("Expires at")}</span>
              <input
                type="datetime-local"
                value={tokenForm.expiresAt}
                onChange={(event) => setTokenForm((current) => ({ ...current, expiresAt: event.target.value }))}
                disabled={tokenSaving}
              />
              <span className="field-hint">
                {tx("Settings default: {value}", { value: tokenDefaultTTLLabel(tokenDefaults.ttlSeconds, tx) })}
              </span>
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
            <div className="empty">{showHiddenTokens ? tx("No enrollment tokens.") : tx("No visible enrollment tokens.")}</div>
          ) : null}
        </div>
        <p className="section-note">{tx("Tokens that cannot enroll new devices are kept as audit history. Linked tokens stay visible while their devices are registered or awaiting approval.")}</p>
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
                <th>{tx("Actions")}</th>
                <th>{tx("Device")}</th>
                <th>{tx("Key")}</th>
                <th>{tx("Fingerprint")}</th>
                <th>{tx("Product ID")}</th>
                <th>{tx("Runtime")}</th>
                <th>{tx("Version")}</th>
                <th>{tx("Platform")}</th>
                <th>{tx("Config")}</th>
                <th>{tx("Enrollment token")}</th>
                <th>{tx("Token status")}</th>
                <th>{tx("Status")}</th>
                <th>{tx("Proxy access")}</th>
                <th>{tx("Approved")}</th>
                <th>{tx("Last seen")}</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => (
                <tr key={`${device.device_id}:${device.key_id}`}>
                  <td className="actions-cell">
                    <button type="button" onClick={() => openDeviceActions(device)}>
                      {tx("Manage")}
                    </button>
                  </td>
                  <td title={device.device_id}>{device.device_id}</td>
                  <td title={device.key_id}>{device.key_id}</td>
                  <td title={device.public_key_fingerprint_sha256}>{device.public_key_fingerprint_sha256}</td>
                  <td title={device.product_id || undefined}>{device.product_id || "-"}</td>
                  <td title={device.runtime_role || undefined}>{device.runtime_role || "-"}</td>
                  <td title={[device.build_version, device.go_version].filter(Boolean).join(" / ") || undefined}>
                    {device.build_version || "-"}
                    {device.go_version ? <span className="table-subvalue">{device.go_version}</span> : null}
                  </td>
                  <td title={platformTitle(device) || undefined}>{platformLabel(device)}</td>
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
                </tr>
              ))}
            </tbody>
          </table>
          {devices.length === 0 ? <div className="empty">{tx("No registered devices.")}</div> : null}
        </div>
      </section>
    </div>
  );
}
