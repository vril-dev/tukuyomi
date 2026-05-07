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

type AppDeployPackageRecord = {
  package_revision: string;
  package_hash: string;
  device_id: string;
  app_id: string;
  runtime_family: string;
  runtime_id: string;
  profile_revision: string;
  roots?: AppDeployRootRecord[];
  label: string;
  note?: string;
  source_type: string;
  compressed_size: number;
  uncompressed_size: number;
  file_count: number;
  uploaded_by: string;
  uploaded_at_unix: number;
  uploaded_at: string;
};

type AppDeployRootRecord = {
  root_id: string;
  runtime_field: string;
  source_path?: string;
  package_prefix: string;
  target_subpath: string;
  runtime_subpath?: string;
  required: boolean;
};

type AppDeployCandidateRecord = {
  device_id: string;
  app_id: string;
  runtime_family: string;
  runtime_id: string;
  roots?: AppDeployRootRecord[];
  managed: boolean;
  detected_at_unix: number;
};

type AppDeployProfileRecord = {
  profile_id: number;
  device_id: string;
  app_id: string;
  runtime_family: string;
  runtime_id: string;
  profile_revision: string;
  roots?: AppDeployRootRecord[];
  updated_at_unix: number;
};

type AppDeployRequestRecord = {
  request_id: number;
  device_id: string;
  app_id: string;
  operation: string;
  package_revision: string;
  package_hash: string;
  base_package_revision: string;
  profile_revision: string;
  roots?: AppDeployRootRecord[];
  restart_behavior: string;
  script_timeout_sec: number;
  reason: string;
  requested_by: string;
  requested_at_unix: number;
  updated_at_unix: number;
  dispatched_at_unix?: number;
  compressed_size?: number;
  uncompressed_size?: number;
  file_count?: number;
  runtime_family?: string;
  runtime_id?: string;
};

type AppDeployApplyStatusRecord = {
  device_id: string;
  app_id: string;
  desired_package_revision: string;
  local_package_revision: string;
  local_package_hash: string;
  apply_state: string;
  apply_error: string;
  output_tail?: string;
  last_attempt_at_unix: number;
  updated_at_unix: number;
};

type AppDeployHistoryRecord = {
  history_id: number;
  device_id: string;
  app_id: string;
  operation: string;
  package_revision: string;
  package_hash: string;
  apply_state: string;
  apply_error: string;
  output_tail?: string;
  requested_by: string;
  requested_at_unix: number;
  applied_at_unix: number;
  updated_at_unix: number;
};

type AppDeployView = {
  device: DeviceRecord;
  candidates?: AppDeployCandidateRecord[];
  profiles?: AppDeployProfileRecord[];
  packages?: AppDeployPackageRecord[];
  request?: AppDeployRequestRecord | null;
  status?: AppDeployApplyStatusRecord[];
  history?: AppDeployHistoryRecord[];
};

type AppDeployPackageFileRecord = {
  path: string;
  sha256: string;
  size_bytes: number;
  mode: number;
};

type AppDeployPackageDetail = {
  package: AppDeployPackageRecord;
  files: AppDeployPackageFileRecord[];
};

type AppDeployPackageFileDetail = {
  file: AppDeployPackageFileRecord;
  raw?: string;
};

type AppDeployPackageImportResult = {
  package: AppDeployPackageRecord;
  request?: AppDeployRequestRecord;
};

type AppDeployPackageDiff = {
  base_package_revision: string;
  target_package_revision: string;
  base_known: boolean;
  added_files?: AppDeployPackageFileRecord[];
  updated_files?: AppDeployPackageFileRecord[];
  removed_files?: AppDeployPackageFileRecord[];
  added_directories?: string[];
  removed_directories?: string[];
  truncated?: boolean;
};

type PageMessage = { kind: "info" | "success" | "error"; text: string };
type PendingDiff = { pkg: AppDeployPackageRecord; operation: string; diff: AppDeployPackageDiff };

const defaultScriptTimeoutSec = 60;

function compactRevision(value: string | undefined) {
  if (!value) {
    return "-";
  }
  return value.length > 14 ? `R: ${value.slice(0, 12)}` : value;
}

function compactHash(value: string | undefined) {
  if (!value) {
    return "-";
  }
  return value.length > 34 ? `${value.slice(0, 31)}...` : value;
}

function formatUnix(value: number | undefined, locale: string) {
  if (!value) {
    return "-";
  }
  const date = new Date(value * 1000);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return date.toLocaleString(locale === "ja" ? "ja-JP" : "en-US");
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

function applyStateClass(state: string) {
  switch (state) {
    case "applied":
      return "status-pill apply-applied";
    case "failed":
    case "failed_after_switch":
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

function appDeployPackageDownloadPath(deviceID: string, revision: string) {
  return `${getAPIBasePath()}/devices/${encodeURIComponent(deviceID)}/app-deployments/packages/${encodeURIComponent(
    revision,
  )}/download`;
}

function packageRuntimeLabel(pkg: Pick<AppDeployPackageRecord, "runtime_family" | "runtime_id">) {
  return [pkg.runtime_family, pkg.runtime_id].filter(Boolean).join(" / ") || "-";
}

function defaultRootsForFamily(runtimeFamily: string): AppDeployRootRecord[] {
  if (runtimeFamily === "psgi") {
    return [
      {
        root_id: "app_root",
        runtime_field: "app_root",
        source_path: "",
        package_prefix: "app",
        target_subpath: "app",
        runtime_subpath: "app",
        required: true,
      },
      {
        root_id: "document_root",
        runtime_field: "document_root",
        source_path: "",
        package_prefix: "static",
        target_subpath: "static",
        runtime_subpath: "static",
        required: true,
      },
    ];
  }
  return [
    {
      root_id: "source_root",
      runtime_field: "document_root",
      source_path: "",
      package_prefix: "",
      target_subpath: "",
      runtime_subpath: "public",
      required: true,
    },
  ];
}

function rootsForEditor(roots: AppDeployRootRecord[] | undefined, runtimeFamily: string): AppDeployRootRecord[] {
  return (roots && roots.length > 0 ? roots : defaultRootsForFamily(runtimeFamily)).map((root) => ({
    ...root,
    source_path: root.source_path || "",
  }));
}

function packagesWithUploadedPackage(packages: AppDeployPackageRecord[] | undefined, pkg: AppDeployPackageRecord) {
  const out = [pkg, ...(packages || []).filter((item) => item.package_revision !== pkg.package_revision)];
  out.sort((a, b) => {
    if (a.uploaded_at_unix !== b.uploaded_at_unix) {
      return b.uploaded_at_unix - a.uploaded_at_unix;
    }
    return b.package_revision.localeCompare(a.package_revision);
  });
  return out.slice(0, 50);
}

function prettyRoots(roots: AppDeployRootRecord[] | undefined) {
  if (!roots || roots.length === 0) {
    return "-";
  }
  return roots.map((root) => {
    const prefix = root.package_prefix || ".";
    const target = root.target_subpath || ".";
    const runtime = root.runtime_subpath || root.target_subpath || ".";
    const source = root.source_path ? `${root.source_path} -> ` : "";
    return `${root.runtime_field}: ${source}${prefix} -> current/${target} (runtime current/${runtime})`;
  }).join(", ");
}

function normalizePositiveInt(value: string, fallback: number) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.min(parsed, 900);
}

export default function AppDeployPage() {
  const { deviceID = "" } = useParams();
  const navigate = useNavigate();
  const { locale, tx } = useI18n();
  const [view, setView] = useState<AppDeployView | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState("");
  const [loadMessage, setLoadMessage] = useState<PageMessage | null>(null);
  const [uploadMessage, setUploadMessage] = useState<PageMessage | null>(null);
  const [candidateMessage, setCandidateMessage] = useState<PageMessage | null>(null);
  const [pendingMessage, setPendingMessage] = useState<PageMessage | null>(null);
  const [packageMessage, setPackageMessage] = useState<PageMessage | null>(null);
  const [modalMessage, setModalMessage] = useState<PageMessage | null>(null);
  const [selectedPackage, setSelectedPackage] = useState<AppDeployPackageDetail | null>(null);
  const [selectedFile, setSelectedFile] = useState<AppDeployPackageFileDetail | null>(null);
  const [pendingDiff, setPendingDiff] = useState<PendingDiff | null>(null);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadInputKey, setUploadInputKey] = useState(0);
  const [appID, setAppID] = useState("app-1");
  const [runtimeFamily, setRuntimeFamily] = useState("php-fpm");
  const [runtimeID, setRuntimeID] = useState("php85");
  const [rootsJSON, setRootsJSON] = useState(() => JSON.stringify(defaultRootsForFamily("php-fpm"), null, 2));
  const [label, setLabel] = useState("");
  const [note, setNote] = useState("");
  const [restartBehavior, setRestartBehavior] = useState("restart-runtime");
  const [scriptTimeoutSec, setScriptTimeoutSec] = useState(String(defaultScriptTimeoutSec));
  const [preSwitchScript, setPreSwitchScript] = useState("");
  const [postSwitchScript, setPostSwitchScript] = useState("");
  const [reason, setReason] = useState("runtime app deploy");

  const request = view?.request || null;
  const candidates = useMemo(() => [...(view?.candidates || [])], [view?.candidates]);
  const profiles = useMemo(() => [...(view?.profiles || [])], [view?.profiles]);
  const packages = useMemo(() => [...(view?.packages || [])], [view?.packages]);
  const statuses = useMemo(() => [...(view?.status || [])], [view?.status]);
  const history = useMemo(() => [...(view?.history || [])], [view?.history]);

  const statusByApp = useMemo(() => {
    const out = new Map<string, AppDeployApplyStatusRecord>();
    for (const status of statuses) {
      out.set(status.app_id, status);
    }
    return out;
  }, [statuses]);

  const packageByRevision = useMemo(() => {
    const out = new Map<string, AppDeployPackageRecord>();
    for (const pkg of packages) {
      out.set(pkg.package_revision, pkg);
    }
    return out;
  }, [packages]);

  const profileByApp = useMemo(() => {
    const out = new Map<string, AppDeployProfileRecord>();
    for (const profile of profiles) {
      out.set(profile.app_id, profile);
    }
    return out;
  }, [profiles]);

  const candidateByApp = useMemo(() => {
    const out = new Map<string, AppDeployCandidateRecord>();
    for (const candidate of candidates) {
      out.set(candidate.app_id, candidate);
    }
    return out;
  }, [candidates]);

  const latestHistoryByPackage = useMemo(() => {
    const out = new Map<string, AppDeployHistoryRecord>();
    for (const item of history) {
      const key = `${item.app_id}:${item.package_revision}`;
      if (!out.has(key)) {
        out.set(key, item);
      }
    }
    return out;
  }, [history]);

  const loadDeployments = useCallback(async () => {
    if (!deviceID) {
      navigate("/device-approvals", { replace: true });
      return;
    }
    setLoading(true);
    try {
      const data = await apiGetJson<AppDeployView>(`/devices/${encodeURIComponent(deviceID)}/app-deployments`);
      setView(data);
      setLoadMessage(null);
    } catch (err) {
      setLoadMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to load Runtime App Deploy") });
    } finally {
      setLoading(false);
    }
  }, [deviceID, navigate, tx]);

  useEffect(() => {
    void loadDeployments();
  }, [loadDeployments]);

  useEffect(() => {
    if (!request) {
      return;
    }
    const timer = window.setInterval(() => {
      void loadDeployments();
    }, 4000);
    return () => window.clearInterval(timer);
  }, [request, loadDeployments]);

  useEffect(() => {
    if (candidates.length === 0 || candidateByApp.has(appID.trim())) {
      return;
    }
    const candidate = candidates[0];
    setAppID(candidate.app_id);
    setRuntimeFamily(candidate.runtime_family);
    setRuntimeID(candidate.runtime_id || "");
    setRootsJSON(JSON.stringify(rootsForEditor(candidate.roots, candidate.runtime_family), null, 2));
  }, [appID, candidateByApp, candidates]);

  const selectedCandidate = candidateByApp.get(appID.trim());
  const uploadTargetReady =
    Boolean(selectedCandidate) &&
    selectedCandidate?.runtime_family === runtimeFamily &&
    (selectedCandidate?.runtime_id || "") === runtimeID;
  const uploadTargetMessage =
    candidates.length === 0
      ? tx("No deployable Runtime App is reported. Install a runtime and bind a Runtime App first.")
      : !uploadTargetReady
        ? tx("Choose a Runtime App candidate before uploading a package.")
        : "";

  const uploadPackage = async () => {
    if (!deviceID || !uploadFile || busy === "upload") {
      return;
    }
    setBusy("upload");
    setUploadMessage(null);
    try {
      const form = new FormData();
      form.append("package", uploadFile);
      form.append("app_id", appID);
      form.append("runtime_family", runtimeFamily);
      form.append("runtime_id", runtimeID);
      form.append("roots_json", rootsJSON);
      form.append("label", label);
      form.append("note", note);
      form.append("assign", "0");
      form.append("restart_behavior", restartBehavior);
      form.append("script_timeout_sec", String(normalizePositiveInt(scriptTimeoutSec, defaultScriptTimeoutSec)));
      form.append("pre_switch_script", preSwitchScript);
      form.append("post_switch_script", postSwitchScript);
      form.append("reason", reason || "runtime app deploy");
      const result = await apiPostForm<AppDeployPackageImportResult>(
        `/devices/${encodeURIComponent(deviceID)}/app-deployments/packages/import`,
        form,
      );
      setUploadFile(null);
      setUploadInputKey((value) => value + 1);
      if (result.package) {
        setView((current) =>
          current ? { ...current, packages: packagesWithUploadedPackage(current.packages, result.package) } : current,
        );
      }
      await loadDeployments();
      if (result.package) {
        setView((current) =>
          current ? { ...current, packages: packagesWithUploadedPackage(current.packages, result.package) } : current,
        );
      }
      setUploadMessage({
        kind: "success",
        text: result.request
          ? tx("App package uploaded and deployment request queued.")
          : tx("App package uploaded. Use Deploy in Saved app packages to apply it."),
      });
    } catch (err) {
      setUploadMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to upload app package") });
    } finally {
      setBusy("");
    }
  };

  const useCandidateRoots = (candidate: AppDeployCandidateRecord) => {
    setAppID(candidate.app_id);
    setRuntimeFamily(candidate.runtime_family);
    setRuntimeID(candidate.runtime_id || "");
    setRootsJSON(JSON.stringify(rootsForEditor(candidate.roots, candidate.runtime_family), null, 2));
  };

  const createAdoptionRequest = async (candidate: AppDeployCandidateRecord) => {
    if (!deviceID || request) {
      return;
    }
    setBusy(`adopt:${candidate.app_id}`);
    setCandidateMessage(null);
    try {
      await apiPostJson(`/devices/${encodeURIComponent(deviceID)}/app-deployments/requests`, {
        app_id: candidate.app_id,
        operation: "adopt",
        runtime_family: candidate.runtime_family,
        runtime_id: candidate.runtime_id,
        roots: candidate.roots || [],
        reason: "adopt current source",
      });
      await loadDeployments();
      setCandidateMessage({ kind: "success", text: tx("Baseline adoption request queued.") });
    } catch (err) {
      setCandidateMessage({
        kind: "error",
        text: err instanceof Error ? err.message : tx("Failed to queue baseline adoption request"),
      });
    } finally {
      setBusy("");
    }
  };

  const openDiff = async (pkg: AppDeployPackageRecord) => {
    if (!deviceID || request) {
      return;
    }
    const currentStatus = statusByApp.get(pkg.app_id);
    const currentPackage = currentStatus?.local_package_revision
      ? packageByRevision.get(currentStatus.local_package_revision)
      : undefined;
    const operation =
      currentPackage && pkg.uploaded_at_unix < currentPackage.uploaded_at_unix ? "rollback" : "deploy";
    setBusy(`diff:${pkg.package_revision}`);
    setPackageMessage(null);
    try {
      const data = await apiGetJson<{ diff: AppDeployPackageDiff }>(
        `/devices/${encodeURIComponent(deviceID)}/app-deployments/packages/${encodeURIComponent(
          pkg.package_revision,
        )}/diff?base_revision=${encodeURIComponent(currentStatus?.local_package_revision || "")}`,
      );
      setPendingDiff({ pkg, operation, diff: data.diff });
    } catch (err) {
      setPackageMessage({
        kind: "error",
        text: err instanceof Error ? err.message : tx("Failed to load app deployment diff"),
      });
    } finally {
      setBusy("");
    }
  };

  const confirmDiffRequest = async () => {
    if (!deviceID || !pendingDiff || request) {
      return;
    }
    const { pkg, operation, diff } = pendingDiff;
    setBusy(`request:${pkg.package_revision}`);
    setPackageMessage(null);
    try {
      await apiPostJson(`/devices/${encodeURIComponent(deviceID)}/app-deployments/requests`, {
        app_id: pkg.app_id,
        operation,
        package_revision: pkg.package_revision,
        base_package_revision: diff.base_known ? diff.base_package_revision : "",
        restart_behavior: restartBehavior,
        script_timeout_sec: normalizePositiveInt(scriptTimeoutSec, defaultScriptTimeoutSec),
        pre_switch_script: preSwitchScript,
        post_switch_script: postSwitchScript,
        reason: reason || "runtime app deploy",
      });
      setPendingDiff(null);
      await loadDeployments();
      setPackageMessage({ kind: "success", text: tx("App deployment request queued.") });
    } catch (err) {
      setPackageMessage({
        kind: "error",
        text: err instanceof Error ? err.message : tx("Failed to queue app deployment request"),
      });
    } finally {
      setBusy("");
    }
  };

  const cancelRequest = async () => {
    if (!deviceID || !request || request.dispatched_at_unix) {
      return;
    }
    setBusy("cancel");
    setPendingMessage(null);
    try {
      await apiPostJson(`/devices/${encodeURIComponent(deviceID)}/app-deployments/requests/clear`, {
        app_id: request.app_id,
      });
      await loadDeployments();
      setPendingMessage({ kind: "success", text: tx("App deployment request canceled.") });
    } catch (err) {
      setPendingMessage({
        kind: "error",
        text: err instanceof Error ? err.message : tx("Failed to cancel app deployment request"),
      });
    } finally {
      setBusy("");
    }
  };

  const openPackage = async (pkg: AppDeployPackageRecord) => {
    if (!deviceID) {
      return;
    }
    setBusy(`package:${pkg.package_revision}`);
    setPackageMessage(null);
    try {
      const data = await apiGetJson<AppDeployPackageDetail>(
        `/devices/${encodeURIComponent(deviceID)}/app-deployments/packages/${encodeURIComponent(pkg.package_revision)}`,
      );
      setSelectedPackage(data);
      setModalMessage(null);
    } catch (err) {
      setPackageMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to load app package") });
    } finally {
      setBusy("");
    }
  };

  const openFile = async (file: AppDeployPackageFileRecord) => {
    if (!deviceID || !selectedPackage) {
      return;
    }
    setBusy(`file:${file.path}`);
    setModalMessage(null);
    try {
      const data = await apiGetJson<AppDeployPackageFileDetail>(
        `/devices/${encodeURIComponent(deviceID)}/app-deployments/packages/${encodeURIComponent(
          selectedPackage.package.package_revision,
        )}/files?path=${encodeURIComponent(file.path)}`,
      );
      setSelectedFile(data);
    } catch (err) {
      setModalMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to load app package file") });
    } finally {
      setBusy("");
    }
  };

  if (!deviceID) {
    return null;
  }

  return (
    <div className="content-section rules-page app-deploy-page">
      <div className="section-header">
        <div>
          <h2>{tx("Runtime App Deploy")}</h2>
          <p>{tx("Upload app packages to Center and deploy them through the Gateway polling flow.")}</p>
        </div>
        {loading ? <span className="status-pill apply-applying">{tx("Loading")}</span> : null}
      </div>

      {loadMessage ? <p className={`form-message ${loadMessage.kind}`}>{loadMessage.text}</p> : null}

      <section className="device-detail-section">
        <h3>{tx("Current app deploy status")}</h3>
        <div className="table-wrap app-deploy-status-table">
          <table>
            <colgroup>
              <col className="app-deploy-col-app" />
              <col className="app-deploy-col-revision" />
              <col className="app-deploy-col-state" />
              <col className="app-deploy-col-time" />
              <col className="app-deploy-col-message" />
            </colgroup>
            <thead>
              <tr>
                <th>{tx("App ID")}</th>
                <th>{tx("Local package")}</th>
                <th>{tx("Apply state")}</th>
                <th>{tx("Last attempt")}</th>
                <th>{tx("Message")}</th>
              </tr>
            </thead>
            <tbody>
              {statuses.length > 0 ? (
                statuses.map((status) => (
                  <tr key={status.app_id}>
                    <td>{status.app_id}</td>
                    <td title={status.local_package_revision}>{compactRevision(status.local_package_revision)}</td>
                    <td>
                      <span className={applyStateClass(status.apply_state)}>{tx(status.apply_state || "-")}</span>
                    </td>
                    <td>{formatUnix(status.last_attempt_at_unix, locale)}</td>
                    <td title={status.apply_error || status.output_tail || ""}>
                      {status.apply_error || status.output_tail || "-"}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5}>{tx("No app deployment status reported.")}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="device-detail-section">
        <h3>{tx("Runtime App candidates")}</h3>
        <p className="section-subtitle">{tx("Runtime Apps reported by this Gateway that can be tied to deployment profiles.")}</p>
        <div className="table-wrap app-deploy-status-table">
          <table>
            <colgroup>
              <col className="app-deploy-col-actions-wide" />
              <col className="app-deploy-col-app" />
              <col className="app-deploy-col-runtime" />
              <col className="app-deploy-col-state" />
              <col className="app-deploy-col-message" />
            </colgroup>
            <thead>
              <tr>
                <th>{tx("Actions")}</th>
                <th>{tx("App ID")}</th>
                <th>{tx("Runtime")}</th>
                <th>{tx("Profile")}</th>
                <th>{tx("Roots")}</th>
              </tr>
            </thead>
            <tbody>
              {candidates.length > 0 ? (
                candidates.map((candidate) => {
                  const profile = profileByApp.get(candidate.app_id);
                  return (
                    <tr key={candidate.app_id}>
                      <td className="actions-cell">
                        <div className="inline-actions">
                          <button type="button" className="secondary-btn" onClick={() => useCandidateRoots(candidate)}>
                            {tx("Use roots")}
                          </button>
                          <button
                            type="button"
                            className="secondary-btn"
                            disabled={Boolean(request) || busy === `adopt:${candidate.app_id}`}
                            onClick={() => void createAdoptionRequest(candidate)}
                          >
                            {tx("Adopt current source")}
                          </button>
                        </div>
                      </td>
                      <td>{candidate.app_id}</td>
                      <td>{packageRuntimeLabel(candidate)}</td>
                      <td>
                        <span className={profile ? "status-pill apply-applied" : "status-pill apply-applying"}>
                          {profile ? tx("profile saved") : tx("unadopted")}
                        </span>
                      </td>
                      <td title={prettyRoots(candidate.roots)}>{prettyRoots(candidate.roots)}</td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={5}>{tx("No Runtime App deploy candidates reported.")}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {candidateMessage ? <p className={`form-message ${candidateMessage.kind}`}>{candidateMessage.text}</p> : null}
      </section>

      <section className="device-detail-section">
        <h3>{tx("Upload app package")}</h3>
        <p className="section-subtitle">
          {tx("Upload a ZIP archive. The Gateway deploys it only for a Runtime App bound to data/app-deployments/<app-id>/current.")}
        </p>
        <div className="form-grid app-deploy-upload-grid">
          <label>
            <span>{tx("App ID")}</span>
            <select
              value={appID}
              disabled={candidates.length === 0}
              onChange={(event) => {
                const candidate = candidateByApp.get(event.currentTarget.value);
                if (candidate) {
                  useCandidateRoots(candidate);
                }
              }}
            >
              {candidates.length === 0 ? (
                <option value={appID}>{tx("No Runtime App candidates")}</option>
              ) : (
                candidates.map((candidate) => (
                  <option key={candidate.app_id} value={candidate.app_id}>
                    {candidate.app_id}
                  </option>
                ))
              )}
            </select>
          </label>
          <label>
            <span>{tx("Runtime family")}</span>
            <select
              value={runtimeFamily}
              disabled
              onChange={(event) => {
                const next = event.currentTarget.value;
                setRuntimeFamily(next);
                setRootsJSON(JSON.stringify(defaultRootsForFamily(next), null, 2));
              }}
            >
              <option value="php-fpm">php-fpm</option>
              <option value="psgi">psgi</option>
            </select>
          </label>
          <label>
            <span>{tx("Runtime ID")}</span>
            <input value={runtimeID} readOnly placeholder="php85" />
          </label>
          <label>
            <span>{tx("Label")}</span>
            <input value={label} onChange={(event) => setLabel(event.currentTarget.value)} placeholder="release label" />
          </label>
          <label className="app-deploy-wide">
            <span>{tx("Note")}</span>
            <input value={note} onChange={(event) => setNote(event.currentTarget.value)} placeholder="operator note" />
          </label>
          <label>
            <span>{tx("Restart behavior")}</span>
            <select value={restartBehavior} onChange={(event) => setRestartBehavior(event.currentTarget.value)}>
              <option value="restart-runtime">{tx("Restart runtime")}</option>
              <option value="reload-runtime">{tx("Reload runtime")}</option>
              <option value="none">{tx("No runtime control")}</option>
            </select>
          </label>
          <label>
            <span>{tx("Script timeout seconds")}</span>
            <input
              type="number"
              min={1}
              max={900}
              value={scriptTimeoutSec}
              onChange={(event) => setScriptTimeoutSec(event.currentTarget.value)}
            />
          </label>
          <label className="app-deploy-wide">
            <span>{tx("Reason")}</span>
            <input value={reason} onChange={(event) => setReason(event.currentTarget.value)} />
          </label>
          <label className="app-deploy-wide app-deploy-roots">
            <span>{tx("Deployment roots JSON")}</span>
            <textarea value={rootsJSON} onChange={(event) => setRootsJSON(event.currentTarget.value)} />
          </label>
          <label className="app-deploy-script">
            <span>{tx("Pre-switch script")}</span>
            <textarea value={preSwitchScript} onChange={(event) => setPreSwitchScript(event.currentTarget.value)} />
          </label>
          <label className="app-deploy-script">
            <span>{tx("Post-switch script")}</span>
            <textarea value={postSwitchScript} onChange={(event) => setPostSwitchScript(event.currentTarget.value)} />
          </label>
        </div>
        <div className="waf-upload-row">
          <input
            key={uploadInputKey}
            type="file"
            accept=".zip,application/zip"
            onChange={(event) => setUploadFile(event.currentTarget.files?.[0] || null)}
          />
          <button
            type="button"
            className="secondary-btn"
            disabled={!uploadFile || !appID.trim() || !runtimeFamily.trim() || !uploadTargetReady || busy === "upload"}
            onClick={() => void uploadPackage()}
          >
            {busy === "upload" ? tx("Uploading...") : tx("Upload package")}
          </button>
        </div>
        {uploadTargetMessage ? <p className="form-message error">{uploadTargetMessage}</p> : null}
        {uploadMessage ? <p className={`form-message ${uploadMessage.kind}`}>{uploadMessage.text}</p> : null}
      </section>

      <section className="device-detail-section">
        <h3>{tx("Pending app deploy request")}</h3>
        <p className="section-subtitle">{tx("Requests waiting for the Gateway to pick them up.")}</p>
        <div className="table-wrap app-deploy-request-table">
          <table>
            <colgroup>
              <col className="app-deploy-col-actions" />
              <col className="app-deploy-col-app" />
              <col className="app-deploy-col-state" />
              <col className="app-deploy-col-revision" />
              <col className="app-deploy-col-time" />
              <col className="app-deploy-col-time" />
            </colgroup>
            <thead>
              <tr>
                <th>{tx("Actions")}</th>
                <th>{tx("App ID")}</th>
                <th>{tx("Operation")}</th>
                <th>{tx("Package")}</th>
                <th>{tx("Requested")}</th>
                <th>{tx("Dispatched")}</th>
              </tr>
            </thead>
            <tbody>
              {request ? (
                <tr>
                  <td className="actions-cell">
                    <div className="inline-actions">
                      {request.dispatched_at_unix ? (
                        <button type="button" className="secondary-btn" disabled>
                          {tx("Picked up")}
                        </button>
                      ) : (
                        <button type="button" className="secondary-btn" disabled={busy === "cancel"} onClick={() => void cancelRequest()}>
                          {tx("Cancel request")}
                        </button>
                      )}
                    </div>
                  </td>
                  <td>{request.app_id}</td>
                  <td>{tx(request.operation)}</td>
                  <td title={request.package_revision}>{compactRevision(request.package_revision)}</td>
                  <td>{formatUnix(request.requested_at_unix, locale)}</td>
                  <td>{formatUnix(request.dispatched_at_unix, locale)}</td>
                </tr>
              ) : (
                <tr>
                  <td colSpan={6}>{tx("No pending app deployment request.")}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {pendingMessage ? <p className={`form-message ${pendingMessage.kind}`}>{pendingMessage.text}</p> : null}
      </section>

      <section className="device-detail-section">
        <h3>{tx("Saved app packages")}</h3>
        <p className="section-subtitle">{tx("Latest uploaded packages. Deploy an older package to perform a manual rollback.")}</p>
        <div className="table-wrap app-deploy-package-table">
          <table>
            <colgroup>
              <col className="app-deploy-col-actions-wide" />
              <col className="app-deploy-col-app" />
              <col className="app-deploy-col-revision" />
              <col className="app-deploy-col-state" />
              <col className="app-deploy-col-runtime" />
              <col className="app-deploy-col-time" />
              <col className="app-deploy-col-hash" />
              <col className="app-deploy-col-size" />
              <col className="app-deploy-col-size" />
            </colgroup>
            <thead>
              <tr>
                <th>{tx("Actions")}</th>
                <th>{tx("App ID")}</th>
                <th>{tx("Package")}</th>
                <th>{tx("Apply state")}</th>
                <th>{tx("Runtime")}</th>
                <th>{tx("Uploaded")}</th>
                <th>{tx("Package hash")}</th>
                <th>{tx("Files")}</th>
                <th>{tx("Size")}</th>
              </tr>
            </thead>
            <tbody>
              {packages.length > 0 ? (
                packages.map((pkg) => {
                  const currentStatus = statusByApp.get(pkg.app_id);
                  const currentPackage = currentStatus?.local_package_revision
                    ? packageByRevision.get(currentStatus.local_package_revision)
                    : undefined;
                  const isCurrent = currentStatus?.local_package_revision === pkg.package_revision;
                  const requested = request?.app_id === pkg.app_id && request.package_revision === pkg.package_revision;
                  const latestHistory = latestHistoryByPackage.get(`${pkg.app_id}:${pkg.package_revision}`);
                  const deployTargetReady = candidateByApp.has(pkg.app_id);
                  const state = requested
                    ? request?.dispatched_at_unix
                      ? "picked_up"
                      : "pending"
                    : isCurrent
                      ? currentStatus?.apply_state || "applied"
                      : latestHistory?.apply_state || "";
                  const operationLabel =
                    currentPackage && pkg.uploaded_at_unix < currentPackage.uploaded_at_unix ? tx("Rollback") : tx("Deploy");
                  return (
                    <tr key={pkg.package_revision}>
                      <td className="actions-cell">
                        <div className="inline-actions">
                          <button
                            type="button"
                            className="secondary-btn"
                            disabled={busy === `package:${pkg.package_revision}`}
                            onClick={() => void openPackage(pkg)}
                          >
                            {tx("View files")}
                          </button>
                          <a className="button-link" href={appDeployPackageDownloadPath(deviceID, pkg.package_revision)}>
                            {tx("Download")}
                          </a>
                          {!isCurrent ? (
                            <button
                              type="button"
                              className="secondary-btn"
                              disabled={
                                !deployTargetReady ||
                                Boolean(request) ||
                                busy === `diff:${pkg.package_revision}` ||
                                busy === `request:${pkg.package_revision}`
                              }
                              onClick={() => void openDiff(pkg)}
                            >
                              {operationLabel}
                            </button>
                          ) : null}
                        </div>
                      </td>
                      <td>{pkg.app_id}</td>
                      <td title={pkg.package_revision}>{compactRevision(pkg.package_revision)}</td>
                      <td>
                        {state ? <span className={applyStateClass(state)}>{state === "picked_up" ? tx("picked up") : tx(state)}</span> : "-"}
                      </td>
                      <td title={packageRuntimeLabel(pkg)}>{packageRuntimeLabel(pkg)}</td>
                      <td>{formatUnix(pkg.uploaded_at_unix, locale)}</td>
                      <td title={pkg.package_hash}>{compactHash(pkg.package_hash)}</td>
                      <td>{pkg.file_count}</td>
                      <td>{formatSize(pkg.compressed_size)}</td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={9}>{tx("No app packages uploaded.")}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {packageMessage ? <p className={`form-message ${packageMessage.kind}`}>{packageMessage.text}</p> : null}
      </section>

      <section className="device-detail-section">
        <h3>{tx("App deploy history")}</h3>
        <p className="section-subtitle">{tx("Recent completed deployment attempts reported by this Gateway.")}</p>
        <div className="table-wrap app-deploy-history-table">
          <table>
            <colgroup>
              <col className="app-deploy-col-app" />
              <col className="app-deploy-col-state" />
              <col className="app-deploy-col-revision" />
              <col className="app-deploy-col-state" />
              <col className="app-deploy-col-time" />
              <col className="app-deploy-col-time" />
              <col className="app-deploy-col-message" />
            </colgroup>
            <thead>
              <tr>
                <th>{tx("App ID")}</th>
                <th>{tx("Operation")}</th>
                <th>{tx("Package")}</th>
                <th>{tx("Apply state")}</th>
                <th>{tx("Requested")}</th>
                <th>{tx("Applied at")}</th>
                <th>{tx("Message")}</th>
              </tr>
            </thead>
            <tbody>
              {history.length > 0 ? (
                history.map((item) => (
                  <tr key={item.history_id}>
                    <td>{item.app_id}</td>
                    <td>{tx(item.operation)}</td>
                    <td title={item.package_revision}>{compactRevision(item.package_revision)}</td>
                    <td>
                      <span className={applyStateClass(item.apply_state)}>{tx(item.apply_state || "-")}</span>
                    </td>
                    <td>{formatUnix(item.requested_at_unix, locale)}</td>
                    <td>{formatUnix(item.applied_at_unix, locale)}</td>
                    <td title={item.apply_error || item.output_tail || ""}>{item.apply_error || item.output_tail || "-"}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7}>{tx("No app deployment history reported.")}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {pendingDiff ? (
        <div className="rules-bundle-modal-backdrop" role="dialog" aria-modal="true">
          <div className="rules-bundle-modal">
            <div className="section-header">
              <div>
                <h3>{pendingDiff.operation === "rollback" ? tx("Confirm rollback") : tx("Confirm deploy")}</h3>
                <p className="section-subtitle">
                  {compactRevision(pendingDiff.diff.base_package_revision)}
                  {" -> "}
                  {compactRevision(pendingDiff.diff.target_package_revision)}
                </p>
              </div>
              <button type="button" className="secondary-btn" onClick={() => setPendingDiff(null)}>
                {tx("Close")}
              </button>
            </div>
            <div className="summary-grid rules-bundle-modal-facts">
              <div>
                <span>{tx("Base known")}</span>
                <strong>{pendingDiff.diff.base_known ? tx("yes") : tx("no")}</strong>
              </div>
              <div>
                <span>{tx("Added files")}</span>
                <strong>{pendingDiff.diff.added_files?.length || 0}</strong>
              </div>
              <div>
                <span>{tx("Updated files")}</span>
                <strong>{pendingDiff.diff.updated_files?.length || 0}</strong>
              </div>
              <div>
                <span>{tx("Removed files")}</span>
                <strong>{pendingDiff.diff.removed_files?.length || 0}</strong>
              </div>
            </div>
            {!pendingDiff.diff.base_known ? (
              <p className="form-message error">
                {tx("Center does not know the current base package. Removed files cannot be computed from Center history.")}
              </p>
            ) : null}
            <div className="table-wrap rules-file-table app-deploy-file-table">
              <table>
                <colgroup>
                  <col className="app-deploy-col-state" />
                  <col className="rules-file-col-path" />
                  <col className="rules-file-col-size" />
                </colgroup>
                <thead>
                  <tr>
                    <th>{tx("Change")}</th>
                    <th>{tx("Path")}</th>
                    <th>{tx("Size")}</th>
                  </tr>
                </thead>
                <tbody>
                  {[...(pendingDiff.diff.added_files || []).map((file) => ({ change: tx("add"), file })),
                    ...(pendingDiff.diff.updated_files || []).map((file) => ({ change: tx("update"), file })),
                    ...(pendingDiff.diff.removed_files || []).map((file) => ({ change: tx("remove"), file }))].map((item) => (
                    <tr key={`${item.change}:${item.file.path}`}>
                      <td>{item.change}</td>
                      <td title={item.file.path}>{item.file.path}</td>
                      <td>{formatSize(item.file.size_bytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="form-actions">
              <button
                type="button"
                className="secondary-btn"
                disabled={busy === `request:${pendingDiff.pkg.package_revision}`}
                onClick={() => void confirmDiffRequest()}
              >
                {pendingDiff.operation === "rollback" ? tx("Confirm rollback") : tx("Confirm deploy")}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {selectedPackage ? (
        <div className="rules-bundle-modal-backdrop" role="dialog" aria-modal="true">
          <div className="rules-bundle-modal">
            <div className="section-header">
              <div>
                <h3>{tx("App package files")}</h3>
                <p className="section-subtitle" title={selectedPackage.package.package_revision}>
                  {selectedPackage.package.app_id} / {compactRevision(selectedPackage.package.package_revision)}
                </p>
              </div>
              <button
                type="button"
                className="secondary-btn"
                onClick={() => {
                  setSelectedPackage(null);
                  setModalMessage(null);
                }}
              >
                {tx("Close")}
              </button>
            </div>
            <div className="summary-grid rules-bundle-modal-facts">
              <div>
                <span>{tx("Files")}</span>
                <strong>{selectedPackage.package.file_count}</strong>
              </div>
              <div>
                <span>{tx("Compressed")}</span>
                <strong>{formatSize(selectedPackage.package.compressed_size)}</strong>
              </div>
              <div>
                <span>{tx("Uncompressed")}</span>
                <strong>{formatSize(selectedPackage.package.uncompressed_size)}</strong>
              </div>
              <div>
                <span>{tx("Uploaded")}</span>
                <strong>{formatUnix(selectedPackage.package.uploaded_at_unix, locale)}</strong>
              </div>
            </div>
            <div className="table-wrap rules-file-table app-deploy-file-table">
              <table>
                <colgroup>
                  <col className="rules-file-col-actions" />
                  <col className="rules-file-col-path" />
                  <col className="rules-file-col-size" />
                  <col className="rules-file-col-sha" />
                </colgroup>
                <thead>
                  <tr>
                    <th>{tx("Actions")}</th>
                    <th>{tx("Path")}</th>
                    <th>{tx("Size")}</th>
                    <th>{tx("SHA256")}</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedPackage.files.map((file) => (
                    <tr key={file.path}>
                      <td className="actions-cell">
                        <div className="inline-actions">
                          <button type="button" className="secondary-btn" disabled={busy === `file:${file.path}`} onClick={() => void openFile(file)}>
                            {tx("View")}
                          </button>
                        </div>
                      </td>
                      <td title={file.path}>{file.path}</td>
                      <td>{formatSize(file.size_bytes)}</td>
                      <td title={file.sha256}>{compactHash(file.sha256)}</td>
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
                <h3>{tx("App package file")}</h3>
                <p className="section-subtitle" title={selectedFile.file.path}>
                  {selectedFile.file.path}
                </p>
              </div>
              <button type="button" className="secondary-btn" onClick={() => setSelectedFile(null)}>
                {tx("Close")}
              </button>
            </div>
            <textarea className="rules-json-editor rules-bundle-json" readOnly value={selectedFile.raw || ""} />
          </div>
        </div>
      ) : null}
    </div>
  );
}
