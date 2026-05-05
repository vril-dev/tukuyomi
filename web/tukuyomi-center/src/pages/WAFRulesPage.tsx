import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { apiGetJson, apiPostForm, apiPostJson } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import { getAPIBasePath } from "@/lib/runtime";

type DeviceRecord = {
  device_id: string;
  status: string;
  last_seen_at_unix?: number;
};

type WAFRuleAsset = {
  path: string;
  kind: string;
  etag?: string;
  disabled: boolean;
  size_bytes: number;
};

type WAFRuleSnapshot = {
  config_revision: string;
  domain_etag: string;
  bundle_revision: string;
  assets?: WAFRuleAsset[];
  error?: string;
  snapshot_created_at_unix?: number;
};

type WAFRuleBundle = {
  bundle_revision: string;
  bundle_hash: string;
  compressed_size: number;
  uncompressed_size: number;
  file_count: number;
  created_at_unix: number;
  local_bundle_revision?: string;
  apply_state?: string;
  apply_error?: string;
  last_attempt_at_unix?: number;
  applied_at_unix?: number;
  apply_updated_at_unix?: number;
};

type WAFRuleAssignment = {
  bundle_revision: string;
  base_bundle_revision: string;
  reason: string;
  assigned_by: string;
  assigned_at_unix: number;
  updated_at_unix: number;
  dispatched_at_unix?: number;
  compressed_size: number;
  uncompressed_size: number;
  file_count: number;
};

type WAFRuleApplyStatus = {
  desired_bundle_revision: string;
  local_bundle_revision: string;
  apply_state: string;
  apply_error: string;
  last_attempt_at_unix: number;
  updated_at_unix: number;
};

type WAFRulesView = {
  device: DeviceRecord;
  current?: WAFRuleSnapshot | null;
  bundles?: WAFRuleBundle[];
  assignment?: WAFRuleAssignment | null;
  apply_status?: WAFRuleApplyStatus | null;
};

type WAFRuleBundleFile = {
  path: string;
  archive_path: string;
  kind: string;
  etag?: string;
  disabled: boolean;
  sha256: string;
  size_bytes: number;
};

type WAFRuleBundleDetail = {
  bundle: WAFRuleBundle;
  files: WAFRuleBundleFile[];
};

type WAFRuleFileDetail = {
  file: WAFRuleBundleFile;
  raw: string;
};

type WAFRuleBundleImportResult = {
  bundle: WAFRuleBundle;
  stored: boolean;
  assignment?: WAFRuleAssignment;
  stripped_root_prefixes?: string[];
};

type PageMessage = { kind: "info" | "success" | "error"; text: string };

const wafRuleDispatchLeaseSeconds = 60;

function compactRevision(value: string | undefined) {
  if (!value) {
    return "-";
  }
  return value.length > 14 ? `R: ${value.slice(0, 12)}` : value;
}

function compactETag(value: string | undefined) {
  if (!value) {
    return "-";
  }
  return value.length > 34 ? `${value.slice(0, 31)}...` : value;
}

function formatUnix(value: number | undefined, locale: string) {
  if (!value) {
    return "-";
  }
  return new Date(value * 1000).toLocaleString(locale === "ja" ? "ja-JP" : "en-US");
}

function formatSize(bytes: number | undefined) {
  if (!bytes || !Number.isFinite(bytes)) {
    return "-";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function dispatchActive(dispatchedAtUnix: number | undefined) {
  if (!dispatchedAtUnix) {
    return false;
  }
  return Math.floor(Date.now() / 1000) - dispatchedAtUnix < wafRuleDispatchLeaseSeconds;
}

function bundleApplyState(bundle: WAFRuleBundle, assignment: WAFRuleAssignment | null) {
  if (assignment?.bundle_revision === bundle.bundle_revision) {
    return assignment.dispatched_at_unix ? "picked_up" : "pending";
  }
  return (bundle.apply_state || "").trim();
}

function applyStateClass(state: string) {
  switch (state) {
    case "applied":
      return "status-pill apply-applied";
    case "failed":
    case "blocked":
      return "status-pill apply-failed";
    case "applying":
    case "pending":
    case "picked_up":
      return "status-pill apply-applying";
    default:
      return "";
  }
}

function wafRuleBundleDownloadPath(deviceID: string, revision: string) {
  return `${getAPIBasePath()}/devices/${encodeURIComponent(deviceID)}/waf-rules/bundles/${encodeURIComponent(revision)}/download`;
}

export default function WAFRulesPage() {
  const { deviceID = "" } = useParams();
  const navigate = useNavigate();
  const { locale, tx } = useI18n();
  const [view, setView] = useState<WAFRulesView | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState("");
  const [loadMessage, setLoadMessage] = useState<PageMessage | null>(null);
  const [uploadMessage, setUploadMessage] = useState<PageMessage | null>(null);
  const [pendingMessage, setPendingMessage] = useState<PageMessage | null>(null);
  const [bundleMessage, setBundleMessage] = useState<PageMessage | null>(null);
  const [modalMessage, setModalMessage] = useState<PageMessage | null>(null);
  const [selectedBundle, setSelectedBundle] = useState<WAFRuleBundleDetail | null>(null);
  const [selectedFile, setSelectedFile] = useState<WAFRuleFileDetail | null>(null);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadAssign, setUploadAssign] = useState(false);
  const [uploadInputKey, setUploadInputKey] = useState(0);

  const current = view?.current || null;
  const assignment = view?.assignment || null;
  const assignmentDispatchActive = dispatchActive(assignment?.dispatched_at_unix);
  const bundles = useMemo(() => [...(view?.bundles || [])], [view?.bundles]);

  const loadRules = useCallback(async () => {
    if (!deviceID) {
      navigate("/device-approvals", { replace: true });
      return;
    }
    setLoading(true);
    try {
      const data = await apiGetJson<WAFRulesView>(`/devices/${encodeURIComponent(deviceID)}/waf-rules`);
      setView(data);
      setLoadMessage(null);
    } catch (err) {
      setLoadMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to load WAF rules") });
    } finally {
      setLoading(false);
    }
  }, [deviceID, navigate, tx]);

  useEffect(() => {
    void loadRules();
  }, [loadRules]);

  useEffect(() => {
    if (!assignment && !assignmentDispatchActive) {
      return;
    }
    const timer = window.setInterval(() => {
      void loadRules();
    }, 4000);
    return () => window.clearInterval(timer);
  }, [assignment, assignmentDispatchActive, loadRules]);

  const assignBundle = async (bundle: WAFRuleBundle) => {
    if (!deviceID || assignmentDispatchActive) {
      return;
    }
    setBusy(`assign:${bundle.bundle_revision}`);
    setBundleMessage(null);
    try {
      await apiPostJson(`/devices/${encodeURIComponent(deviceID)}/waf-rules/assignments`, {
        bundle_revision: bundle.bundle_revision,
        reason: "center WAF rule bundle assignment",
      });
      await loadRules();
      setBundleMessage({ kind: "success", text: tx("WAF rule request queued") });
    } catch (err) {
      setBundleMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to assign WAF rules") });
    } finally {
      setBusy("");
    }
  };

  const cancelAssignment = async () => {
    if (!deviceID || assignmentDispatchActive) {
      return;
    }
    setBusy("cancel");
    setPendingMessage(null);
    try {
      await apiPostJson(`/devices/${encodeURIComponent(deviceID)}/waf-rules/assignments/clear`, {});
      await loadRules();
      setPendingMessage({ kind: "success", text: tx("WAF rule request canceled") });
    } catch (err) {
      setPendingMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to cancel WAF request") });
    } finally {
      setBusy("");
    }
  };

  const uploadBundle = async () => {
    if (!deviceID || !uploadFile || busy === "upload") {
      return;
    }
    setBusy("upload");
    setUploadMessage(null);
    try {
      const form = new FormData();
      form.append("bundle", uploadFile);
      form.append("assign", uploadAssign ? "1" : "0");
      form.append("reason", uploadAssign ? "center WAF rule bundle upload and assign" : "center WAF rule bundle upload");
      const result = await apiPostForm<WAFRuleBundleImportResult>(`/devices/${encodeURIComponent(deviceID)}/waf-rules/bundles/import`, form);
      setUploadFile(null);
      setUploadInputKey((value) => value + 1);
      await loadRules();
      const baseMessage = uploadAssign
        ? result.stored
          ? tx("WAF rule bundle uploaded and assigned.")
          : tx("WAF rule bundle already exists and was assigned.")
        : result.stored
          ? tx("WAF rule bundle uploaded.")
          : tx("WAF rule bundle already exists. Same content was not added again.");
      const strippedMessage = result.stripped_root_prefixes?.length
        ? ` ${tx("Removed wrapper folder")}: ${result.stripped_root_prefixes.join("/")}`
        : "";
      setUploadMessage({
        kind: result.stored || uploadAssign ? "success" : "info",
        text: `${baseMessage}${strippedMessage}`,
      });
    } catch (err) {
      setUploadMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to upload WAF bundle") });
    } finally {
      setBusy("");
    }
  };

  const openBundle = async (bundle: WAFRuleBundle) => {
    if (!deviceID) {
      return;
    }
    setBusy(`bundle:${bundle.bundle_revision}`);
    setBundleMessage(null);
    try {
      const data = await apiGetJson<WAFRuleBundleDetail>(
        `/devices/${encodeURIComponent(deviceID)}/waf-rules/bundles/${encodeURIComponent(bundle.bundle_revision)}`,
      );
      setSelectedBundle(data);
      setModalMessage(null);
    } catch (err) {
      setBundleMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to load WAF bundle") });
    } finally {
      setBusy("");
    }
  };

  const openFile = async (file: WAFRuleBundleFile) => {
    if (!deviceID || !selectedBundle) {
      return;
    }
    setBusy(`file:${file.path}`);
    setModalMessage(null);
    try {
      const data = await apiGetJson<WAFRuleFileDetail>(
        `/devices/${encodeURIComponent(deviceID)}/waf-rules/bundles/${encodeURIComponent(
          selectedBundle.bundle.bundle_revision,
        )}/files?path=${encodeURIComponent(file.path)}`,
      );
      setSelectedFile(data);
    } catch (err) {
      setModalMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to load WAF rule file") });
    } finally {
      setBusy("");
    }
  };

  if (!deviceID) {
    return null;
  }

  return (
    <div className="content-section rules-page">
      <div className="section-header">
        <div>
          <h2>{tx("WAF Rules")}</h2>
          <p>{tx("Upload and assign Center-managed WAF rule bundles.")}</p>
        </div>
      </div>

      {loadMessage ? <p className={`form-message ${loadMessage.kind}`}>{loadMessage.text}</p> : null}

      <section className="device-detail-section">
        <h3>{tx("Current WAF bundle")}</h3>
        <div className="summary-grid rules-summary-grid">
          <div>
            <span>{tx("Bundle")}</span>
            <strong title={current?.bundle_revision || ""}>{compactRevision(current?.bundle_revision)}</strong>
          </div>
          <div>
            <span>{tx("Assets")}</span>
            <strong>{current?.assets?.length ?? 0}</strong>
          </div>
          <div>
            <span>{tx("Snapshot")}</span>
            <strong>{formatUnix(current?.snapshot_created_at_unix, locale)}</strong>
          </div>
        </div>
        {current?.error ? <p className="runtime-build-error">{current.error}</p> : null}
      </section>

      <section className="device-detail-section">
        <h3>{tx("Upload WAF bundle")}</h3>
        <p className="section-subtitle">{tx("Upload a ZIP archive using the same folder paths shown in View files.")}</p>
        <div className="waf-upload-row">
          <input
            key={uploadInputKey}
            type="file"
            accept=".zip,application/zip"
            onChange={(event) => setUploadFile(event.currentTarget.files?.[0] || null)}
          />
          <label className="checkbox-line">
            <input type="checkbox" checked={uploadAssign} onChange={(event) => setUploadAssign(event.currentTarget.checked)} />
            <span>{tx("Assign after upload")}</span>
          </label>
          <button type="button" className="secondary-btn" disabled={!uploadFile || busy === "upload"} onClick={() => void uploadBundle()}>
            {busy === "upload" ? tx("Uploading...") : tx("Upload bundle")}
          </button>
        </div>
        {uploadMessage ? <p className={`form-message ${uploadMessage.kind}`}>{uploadMessage.text}</p> : null}
      </section>

      <section className="device-detail-section">
        <h3>{tx("Pending WAF rule requests")}</h3>
        <p className="section-subtitle">{tx("Requests waiting for the Gateway to pick them up.")}</p>
        <div className="table-wrap rules-request-table waf-request-table">
          <table>
            <colgroup>
              <col className="rules-request-col-actions" />
              <col className="rules-request-col-revision" />
              <col className="rules-request-col-revision" />
              <col className="rules-request-col-size" />
              <col className="rules-request-col-time" />
            </colgroup>
            <thead>
              <tr>
                <th>{tx("Actions")}</th>
                <th>{tx("Bundle")}</th>
                <th>{tx("Base bundle")}</th>
                <th>{tx("Files")}</th>
                <th>{tx("Dispatched")}</th>
              </tr>
            </thead>
            <tbody>
              {assignment ? (
                <tr>
                  <td className="actions-cell">
                    <div className="inline-actions">
                      {assignmentDispatchActive ? (
                        <button type="button" className="secondary-btn" disabled>
                          {tx("Picked up")}
                        </button>
                      ) : (
                        <button type="button" className="secondary-btn" disabled={busy === "cancel"} onClick={() => void cancelAssignment()}>
                          {tx("Cancel request")}
                        </button>
                      )}
                    </div>
                  </td>
                  <td title={assignment.bundle_revision}>{compactRevision(assignment.bundle_revision)}</td>
                  <td title={assignment.base_bundle_revision}>{compactRevision(assignment.base_bundle_revision)}</td>
                  <td>{assignment.file_count}</td>
                  <td>{formatUnix(assignment.dispatched_at_unix, locale)}</td>
                </tr>
              ) : (
                <tr>
                  <td colSpan={5}>{tx("No pending WAF rule requests.")}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {pendingMessage ? <p className={`form-message ${pendingMessage.kind}`}>{pendingMessage.text}</p> : null}
      </section>

      <section className="device-detail-section">
        <h3>{tx("Saved WAF rule bundles")}</h3>
        <p className="section-subtitle">{tx("Latest 20 saved or Gateway-reported bundles. Use Assign to redeploy a saved bundle.")}</p>
        <div className="table-wrap rules-bundle-table waf-bundle-table">
          <table>
            <colgroup>
              <col className="rules-bundle-col-actions" />
              <col className="rules-bundle-col-revision" />
              <col className="rules-bundle-col-state" />
              <col className="rules-bundle-col-time" />
              <col className="rules-bundle-col-time" />
              <col className="rules-bundle-col-etag" />
              <col className="rules-bundle-col-size" />
              <col className="rules-bundle-col-size" />
            </colgroup>
            <thead>
              <tr>
                <th>{tx("Actions")}</th>
                <th>{tx("Bundle")}</th>
                <th>{tx("Apply state")}</th>
                <th>{tx("Applied at")}</th>
                <th>{tx("Created")}</th>
                <th>{tx("Bundle hash")}</th>
                <th>{tx("Files")}</th>
                <th>{tx("Size")}</th>
              </tr>
            </thead>
            <tbody>
              {bundles.length > 0 ? (
                bundles.map((bundle) => {
                  const state = bundleApplyState(bundle, assignment);
                  const isCurrent = current?.bundle_revision === bundle.bundle_revision;
                  return (
                    <tr key={bundle.bundle_revision}>
                      <td className="actions-cell">
                        <div className="inline-actions">
                          <button
                            type="button"
                            className="secondary-btn"
                            disabled={busy === `bundle:${bundle.bundle_revision}`}
                            onClick={() => void openBundle(bundle)}
                          >
                            {tx("View files")}
                          </button>
                          <a className="button-link" href={wafRuleBundleDownloadPath(deviceID, bundle.bundle_revision)}>
                            {tx("Download")}
                          </a>
                          {!isCurrent ? (
                            <button
                              type="button"
                              className="secondary-btn"
                              disabled={Boolean(assignment) || busy === `assign:${bundle.bundle_revision}`}
                              onClick={() => void assignBundle(bundle)}
                            >
                              {tx("Assign")}
                            </button>
                          ) : null}
                        </div>
                      </td>
                      <td title={bundle.bundle_revision}>{compactRevision(bundle.bundle_revision)}</td>
                      <td>
                        {state ? <span className={applyStateClass(state)}>{state === "picked_up" ? tx("picked up") : tx(state)}</span> : "-"}
                        {bundle.apply_error ? <span className="table-subvalue">{bundle.apply_error}</span> : null}
                      </td>
                      <td>{formatUnix(bundle.applied_at_unix, locale)}</td>
                      <td>{formatUnix(bundle.created_at_unix, locale)}</td>
                      <td title={bundle.bundle_hash}>{compactETag(bundle.bundle_hash)}</td>
                      <td>{bundle.file_count}</td>
                      <td>{formatSize(bundle.compressed_size)}</td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={8}>{tx("No WAF rule bundles reported.")}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {bundleMessage ? <p className={`form-message ${bundleMessage.kind}`}>{bundleMessage.text}</p> : null}
      </section>

      {selectedBundle ? (
        <div className="rules-bundle-modal-backdrop" role="dialog" aria-modal="true">
          <div className="rules-bundle-modal">
            <div className="section-header">
              <div>
                <h3>{tx("WAF bundle files")}</h3>
                <p className="section-subtitle" title={selectedBundle.bundle.bundle_revision}>
                  {compactRevision(selectedBundle.bundle.bundle_revision)}
                </p>
              </div>
              <button
                type="button"
                className="secondary-btn"
                onClick={() => {
                  setSelectedBundle(null);
                  setModalMessage(null);
                }}
              >
                {tx("Close")}
              </button>
            </div>
            <div className="summary-grid rules-bundle-modal-facts">
              <div>
                <span>{tx("Files")}</span>
                <strong>{selectedBundle.bundle.file_count}</strong>
              </div>
              <div>
                <span>{tx("Compressed")}</span>
                <strong>{formatSize(selectedBundle.bundle.compressed_size)}</strong>
              </div>
              <div>
                <span>{tx("Uncompressed")}</span>
                <strong>{formatSize(selectedBundle.bundle.uncompressed_size)}</strong>
              </div>
              <div>
                <span>{tx("Created")}</span>
                <strong>{formatUnix(selectedBundle.bundle.created_at_unix, locale)}</strong>
              </div>
            </div>
            <div className="table-wrap rules-file-table">
              <table>
                <colgroup>
                  <col className="rules-file-col-actions" />
                  <col className="rules-file-col-path" />
                  <col className="rules-file-col-kind" />
                  <col className="rules-file-col-state" />
                  <col className="rules-file-col-size" />
                  <col className="rules-file-col-sha" />
                </colgroup>
                <thead>
                  <tr>
                    <th>{tx("Actions")}</th>
                    <th>{tx("Path")}</th>
                    <th>{tx("Kind")}</th>
                    <th>{tx("State")}</th>
                    <th>{tx("Size")}</th>
                    <th>{tx("SHA256")}</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedBundle.files.map((file) => (
                    <tr key={file.path}>
                      <td className="actions-cell">
                        <div className="inline-actions">
                          <button type="button" className="secondary-btn" disabled={busy === `file:${file.path}`} onClick={() => void openFile(file)}>
                            {tx("View")}
                          </button>
                        </div>
                      </td>
                      <td title={file.path}>{file.path}</td>
                      <td>{file.kind}</td>
                      <td>{file.disabled ? tx("disabled") : tx("enabled")}</td>
                      <td>{formatSize(file.size_bytes)}</td>
                      <td title={file.sha256}>{compactETag(file.sha256)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {modalMessage ? <p className={`form-message ${modalMessage.kind}`}>{modalMessage.text}</p> : null}
          </div>
        </div>
      ) : null}

      {selectedFile ? (
        <div className="rules-bundle-modal-backdrop" role="dialog" aria-modal="true">
          <div className="rules-bundle-modal">
            <div className="section-header">
              <div>
                <h3>{tx("WAF rule file")}</h3>
                <p className="section-subtitle" title={selectedFile.file.path}>
                  {selectedFile.file.path}
                </p>
              </div>
              <button type="button" className="secondary-btn" onClick={() => setSelectedFile(null)}>
                {tx("Close")}
              </button>
            </div>
            <textarea className="rules-json-editor rules-bundle-json" readOnly value={selectedFile.raw} />
          </div>
        </div>
      ) : null}
    </div>
  );
}
