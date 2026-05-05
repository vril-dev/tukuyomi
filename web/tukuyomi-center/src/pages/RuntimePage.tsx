import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { apiGetJson, apiPostJson } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

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
  status: string;
  os?: string;
  arch?: string;
  kernel_version?: string;
  distro_id?: string;
  distro_id_like?: string;
  distro_version?: string;
  runtime_deployment_supported?: boolean;
  runtime_inventory?: DeviceRuntimeSummary[];
  last_seen_at_unix: number;
};

type DeviceListResponse = {
  devices?: DeviceRecord[];
};

type RuntimeTargetKey = {
  os?: string;
  arch?: string;
  kernel_version?: string;
  distro_id?: string;
  distro_id_like?: string;
  distro_version?: string;
};

type RuntimeArtifactRecord = {
  artifact_revision: string;
  artifact_hash: string;
  runtime_family: string;
  runtime_id: string;
  detected_version?: string;
  target?: RuntimeTargetKey;
  compressed_size: number;
  uncompressed_size: number;
  file_count: number;
  storage_state: string;
  builder_version?: string;
  builder_profile?: string;
  created_by?: string;
  created_at_unix: number;
};

type RuntimeAssignmentRecord = {
  assignment_id: number;
  device_id: string;
  runtime_family: string;
  runtime_id: string;
  desired_artifact_revision: string;
  desired_state: string;
  reason?: string;
  assigned_by?: string;
  assigned_at_unix: number;
  updated_at_unix: number;
  artifact_hash: string;
  compressed_size: number;
  uncompressed_size: number;
  file_count: number;
  detected_version?: string;
  storage_state: string;
  target?: RuntimeTargetKey;
};

type RuntimeApplyStatusRecord = {
  device_id: string;
  runtime_family: string;
  runtime_id: string;
  desired_artifact_revision?: string;
  local_artifact_revision?: string;
  local_artifact_hash?: string;
  apply_state?: string;
  apply_error?: string;
  last_attempt_at_unix: number;
  updated_at_unix: number;
};

type RuntimeDeploymentResponse = {
  device?: DeviceRecord;
  artifacts?: RuntimeArtifactRecord[];
  assignments?: RuntimeAssignmentRecord[];
  apply_status?: RuntimeApplyStatusRecord[];
};

type RuntimeBuilderCapabilities = {
  available: boolean;
  docker_available: boolean;
  php_fpm_supported: boolean;
  psgi_supported: boolean;
  message?: string;
  runtimes?: RuntimeBuildRuntimeState[];
};

type RuntimeBuildRuntimeState = {
  runtime_family: string;
  runtime_id: string;
  supported: boolean;
  message?: string;
};

type RuntimeBuildJob = {
  job_id: string;
  status: string;
  device_id: string;
  runtime_family: string;
  runtime_id: string;
  artifact?: RuntimeArtifactRecord;
  assignment?: RuntimeAssignmentRecord;
  error?: string;
  queued_at_unix: number;
  started_at_unix: number;
  finished_at_unix: number;
  updated_at_unix: number;
};

type RuntimeBuildJobResponse = {
  job?: RuntimeBuildJob;
};

type RuntimeBuildJobsResponse = {
  jobs?: RuntimeBuildJob[];
};

const RUNTIME_BUILD_OPTIONS = [
  { runtime_family: "php-fpm", runtime_id: "php83", label: "PHP 8.3" },
  { runtime_family: "php-fpm", runtime_id: "php84", label: "PHP 8.4" },
  { runtime_family: "php-fpm", runtime_id: "php85", label: "PHP 8.5" },
  { runtime_family: "psgi", runtime_id: "perl536", label: "Perl 5.36" },
  { runtime_family: "psgi", runtime_id: "perl538", label: "Perl 5.38" },
  { runtime_family: "psgi", runtime_id: "perl540", label: "Perl 5.40" },
];

function shortRevision(value?: string) {
  const trimmed = (value || "").trim();
  return trimmed.length > 12 ? trimmed.slice(0, 12) : trimmed || "-";
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
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

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

function runtimeTargetLabel(target?: RuntimeTargetKey) {
  if (!target) {
    return "-";
  }
  return [target.os, target.arch, target.distro_id, target.distro_version].filter(Boolean).join(" / ") || "-";
}

function deviceRuntimeTarget(device?: DeviceRecord) {
  if (!device) {
    return "-";
  }
  return [device.os, device.arch, device.distro_id, device.distro_version].filter(Boolean).join(" / ") || "-";
}

function runtimePageDevicePath(deviceID: string) {
  return `/device-approvals/devices/${encodeURIComponent(deviceID)}/runtime`;
}

function compareRuntimeIdentity(
  left: { runtime_family?: string; runtime_id?: string },
  right: { runtime_family?: string; runtime_id?: string },
) {
  const family = (left.runtime_family || "").localeCompare(right.runtime_family || "");
  if (family !== 0) {
    return family;
  }
  return (left.runtime_id || "").localeCompare(right.runtime_id || "", undefined, { numeric: true });
}

function isRuntimeBuildActive(job?: RuntimeBuildJob | null) {
  return job?.status === "queued" || job?.status === "running";
}

function runtimeBuildJobKey(job: Pick<RuntimeBuildJob, "runtime_family" | "runtime_id">) {
  return `${job.runtime_family}:${job.runtime_id}`;
}

function mergeRuntimeBuildJobs(current: RuntimeBuildJob[], incoming: RuntimeBuildJob[]) {
  const byID = new Map<string, RuntimeBuildJob>();
  for (const job of current) {
    if (job.job_id) {
      byID.set(job.job_id, job);
    }
  }
  for (const job of incoming) {
    if (job.job_id) {
      byID.set(job.job_id, job);
    }
  }
  return [...byID.values()]
    .sort((left, right) => {
      if (left.updated_at_unix !== right.updated_at_unix) {
        return right.updated_at_unix - left.updated_at_unix;
      }
      if (left.queued_at_unix !== right.queued_at_unix) {
        return right.queued_at_unix - left.queued_at_unix;
      }
      return right.job_id.localeCompare(left.job_id);
    })
    .slice(0, 20);
}

export default function RuntimePage() {
  const { locale, tx } = useI18n();
  const navigate = useNavigate();
  const { deviceID: routeDeviceID = "" } = useParams();
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [deployment, setDeployment] = useState<RuntimeDeploymentResponse | null>(null);
  const [deploymentLoading, setDeploymentLoading] = useState(false);
  const [builder, setBuilder] = useState<RuntimeBuilderCapabilities | null>(null);
  const [buildRuntimeID, setBuildRuntimeID] = useState("php83");
  const [buildingKey, setBuildingKey] = useState("");
  const [buildJobs, setBuildJobs] = useState<RuntimeBuildJob[]>([]);
  const [assigningKey, setAssigningKey] = useState("");
  const [clearingKey, setClearingKey] = useState("");
  const [removingKey, setRemovingKey] = useState("");

  const loadDevices = useCallback(async () => {
    setLoading(true);
    setMessage("");
    try {
      const data = await apiGetJson<DeviceListResponse>("/devices?include_archived=1");
      setDevices(Array.isArray(data.devices) ? data.devices : []);
    } catch (err) {
      const fallback = tx("Failed to load runtime devices");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setLoading(false);
    }
  }, [tx]);

  const loadBuilder = useCallback(async () => {
    try {
      const data = await apiGetJson<RuntimeBuilderCapabilities>("/runtime-builder/capabilities");
      setBuilder(data);
    } catch (err) {
      setBuilder({
        available: false,
        docker_available: false,
        php_fpm_supported: false,
        psgi_supported: false,
        message: err instanceof Error ? err.message : tx("Failed to load runtime builder capability"),
      });
    }
  }, [tx]);

  const approvedDevices = useMemo(() => devices.filter((device) => device.status === "approved"), [devices]);
  const selectedDevice = useMemo(() => {
    if (routeDeviceID) {
      const routed = approvedDevices.find((device) => device.device_id === routeDeviceID);
      if (routed) {
        return routed;
      }
    }
    return approvedDevices[0] || null;
  }, [approvedDevices, routeDeviceID]);
  const selectedDeviceID = selectedDevice?.device_id || "";

  const loadDeployment = useCallback(
    async (deviceID: string) => {
      setDeploymentLoading(true);
      setMessage("");
      try {
        const data = await apiGetJson<RuntimeDeploymentResponse>(`/devices/${encodeURIComponent(deviceID)}/runtime-deployment`);
        setDeployment({
          device: data.device,
          artifacts: Array.isArray(data.artifacts) ? data.artifacts : [],
          assignments: Array.isArray(data.assignments) ? data.assignments : [],
          apply_status: Array.isArray(data.apply_status) ? data.apply_status : [],
        });
      } catch (err) {
        const fallback = tx("Failed to load runtime deployment");
        setDeployment(null);
        setMessage(err instanceof Error ? err.message || fallback : fallback);
      } finally {
        setDeploymentLoading(false);
      }
    },
    [tx],
  );

  const loadBuildJobs = useCallback(
    async (deviceID: string) => {
      try {
        const data = await apiGetJson<RuntimeBuildJobsResponse>(`/devices/${encodeURIComponent(deviceID)}/runtime-builds?limit=20`);
        setBuildJobs(Array.isArray(data.jobs) ? data.jobs : []);
        return Array.isArray(data.jobs) ? data.jobs : [];
      } catch (err) {
        const fallback = tx("Failed to load runtime build status");
        setMessage(err instanceof Error ? err.message || fallback : fallback);
        setBuildJobs([]);
        return [];
      }
    },
    [tx],
  );

  useEffect(() => {
    void loadDevices();
    void loadBuilder();
  }, [loadBuilder, loadDevices]);

  useEffect(() => {
    if (!selectedDeviceID) {
      setDeployment(null);
      setBuildJobs([]);
      return;
    }
    void loadDeployment(selectedDeviceID);
    void loadBuildJobs(selectedDeviceID);
  }, [loadBuildJobs, loadDeployment, selectedDeviceID]);

  useEffect(() => {
    if (loading || !selectedDeviceID) {
      return;
    }
    if (routeDeviceID !== selectedDeviceID) {
      navigate(runtimePageDevicePath(selectedDeviceID), { replace: true });
    }
  }, [loading, navigate, routeDeviceID, selectedDeviceID]);

  const hasActiveBuildJob = buildJobs.some(isRuntimeBuildActive);

  useEffect(() => {
    if (!selectedDeviceID || !hasActiveBuildJob) {
      return;
    }
    const timer = window.setInterval(async () => {
      const jobs = await loadBuildJobs(selectedDeviceID);
      if (!jobs.some(isRuntimeBuildActive)) {
        setBuildingKey("");
        await loadDevices();
        await loadDeployment(selectedDeviceID);
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [hasActiveBuildJob, loadBuildJobs, loadDeployment, loadDevices, selectedDeviceID]);

  const assignments = useMemo(() => [...(deployment?.assignments || [])].sort(compareRuntimeIdentity), [deployment?.assignments]);
  const artifacts = useMemo(() => [...(deployment?.artifacts || [])].sort(compareRuntimeIdentity), [deployment?.artifacts]);
  const applyStatus = deployment?.apply_status || [];
  const inventory = useMemo(() => [...(deployment?.device?.runtime_inventory || selectedDevice?.runtime_inventory || [])].sort(compareRuntimeIdentity), [deployment?.device?.runtime_inventory, selectedDevice?.runtime_inventory]);
  const recentBuildJobs = useMemo(() => [...buildJobs].sort((left, right) => right.updated_at_unix - left.updated_at_unix || right.queued_at_unix - left.queued_at_unix), [buildJobs]);
  const latestBuildJob = recentBuildJobs[0] || null;
  const activeBuildByKey = new Map<string, RuntimeBuildJob>();
  for (const job of recentBuildJobs) {
    if (isRuntimeBuildActive(job)) {
      activeBuildByKey.set(runtimeBuildJobKey(job), job);
    }
  }
  const runtimeBuildCapabilityByKey = new Map<string, RuntimeBuildRuntimeState>((builder?.runtimes || []).map((item) => [`${item.runtime_family}:${item.runtime_id}`, item] as const));
  const runtimeBuildSupported = (runtimeFamily: string, runtimeID: string) => {
    if (!builder?.available) {
      return false;
    }
    const key = `${runtimeFamily}:${runtimeID}`;
    const listed = runtimeBuildCapabilityByKey.get(key);
    if (listed) {
      return listed.supported;
    }
    if (runtimeFamily === "php-fpm") {
      return builder.php_fpm_supported;
    }
    if (runtimeFamily === "psgi") {
      return builder.psgi_supported;
    }
    return false;
  };
  const runtimeBuildMessage = (runtimeFamily: string, runtimeID: string) => runtimeBuildCapabilityByKey.get(`${runtimeFamily}:${runtimeID}`)?.message || builder?.message || undefined;
  const assignmentByKey = new Map<string, RuntimeAssignmentRecord>(assignments.map((item) => [`${item.runtime_family}:${item.runtime_id}`, item] as const));
  const assignedRevisionByKey = new Map<string, string>(assignments.map((item) => [`${item.runtime_family}:${item.runtime_id}`, item.desired_artifact_revision] as const));
  const statusByKey = new Map<string, RuntimeApplyStatusRecord>(applyStatus.map((item) => [`${item.runtime_family}:${item.runtime_id}`, item] as const));
  const builtArtifactKeySet = new Set<string>();
  for (const item of artifacts) {
    if ((item.storage_state || "").trim() === "stored") {
      builtArtifactKeySet.add(`${item.runtime_family}:${item.runtime_id}`);
    }
  }
  const builtRuntimeKeySet = new Set<string>(builtArtifactKeySet);
  const installedRevisionByKey = new Map<string, string>();
  for (const item of inventory) {
    const revision = (item.artifact_revision || "").trim();
    const key = `${item.runtime_family}:${item.runtime_id}`;
    const source = (item.source || "").trim();
    const state = (item.apply_state || "").trim();
    if (source === "center" || (state === "installed" && revision)) {
      builtRuntimeKeySet.add(key);
    }
    if (state === "installed" || (item.available && source === "center")) {
      if (revision) {
        installedRevisionByKey.set(key, revision);
      }
    }
  }
  for (const item of applyStatus) {
    const revision = (item.local_artifact_revision || "").trim();
    if (item.apply_state === "installed") {
      const key = `${item.runtime_family}:${item.runtime_id}`;
      if (revision) {
        builtRuntimeKeySet.add(key);
      }
      if (revision) {
        installedRevisionByKey.set(key, revision);
      }
    }
  }
  const buildOptions = RUNTIME_BUILD_OPTIONS.map((option) => {
    const key = `${option.runtime_family}:${option.runtime_id}`;
    const supported = runtimeBuildSupported(option.runtime_family, option.runtime_id);
    const busy = buildingKey === key || activeBuildByKey.has(key);
    const built = builtRuntimeKeySet.has(key);
    const pending = assignedRevisionByKey.has(key);
    let stateLabel = "";
    let disabledTitle = "";
    if (busy) {
      stateLabel = tx("Building...");
      disabledTitle = tx("Runtime build is already running.");
    } else if (pending) {
      stateLabel = tx("Request pending");
      disabledTitle = tx("Request pending");
    } else if (built) {
      stateLabel = tx("Built");
      disabledTitle = tx("Built");
    } else if (!supported) {
      stateLabel = tx("unsupported");
      disabledTitle = runtimeBuildMessage(option.runtime_family, option.runtime_id) || tx("Build is not supported for this runtime family yet.");
    }
    return {
      ...option,
      key,
      busy,
      disabled: Boolean(built || pending || busy || !supported),
      disabledTitle,
      selectLabel: stateLabel ? `${option.label} (${stateLabel})` : option.label,
    };
  });
  const selectedBuildOption = buildOptions.find((item) => item.runtime_id === buildRuntimeID) || buildOptions.find((item) => !item.disabled) || buildOptions[0];
  const selectedBuildBusy = selectedBuildOption.busy;
  const canStartSelectedBuild = Boolean(selectedDevice?.runtime_deployment_supported && selectedDeviceID && !selectedBuildOption.disabled);
  const selectedBuildTitle = selectedBuildOption.disabledTitle || runtimeBuildMessage(selectedBuildOption.runtime_family, selectedBuildOption.runtime_id);
  const buildOptionStateKey = buildOptions.map((option) => `${option.key}:${option.disabled ? "1" : "0"}`).join("|");

  useEffect(() => {
    const current = buildOptions.find((option) => option.runtime_id === buildRuntimeID);
    if (!current || !current.disabled) {
      return;
    }
    const next = buildOptions.find((option) => !option.disabled);
    if (next && next.runtime_id !== buildRuntimeID) {
      setBuildRuntimeID(next.runtime_id);
    }
  }, [buildOptionStateKey, buildRuntimeID]);

  async function startBuild(runtimeFamily: string, runtimeID: string) {
    if (!selectedDeviceID) {
      return;
    }
    const key = `${runtimeFamily}:${runtimeID}`;
    setBuildingKey(key);
    setMessage("");
    try {
      const data = await apiPostJson<RuntimeBuildJobResponse>(`/devices/${encodeURIComponent(selectedDeviceID)}/runtime-builds`, {
        runtime_family: runtimeFamily,
        runtime_id: runtimeID,
        assign: true,
        reason: "runtime build requested from runtime page",
      });
      if (data.job) {
        setBuildJobs((current) => mergeRuntimeBuildJobs(current, [data.job as RuntimeBuildJob]));
      }
      setBuildingKey("");
    } catch (err) {
      const fallback = tx("Failed to start runtime build");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
      setBuildingKey("");
    }
  }

  async function assignArtifact(artifact: RuntimeArtifactRecord) {
    if (!selectedDeviceID) {
      return;
    }
    const key = `${artifact.runtime_family}:${artifact.runtime_id}:${artifact.artifact_revision}`;
    setAssigningKey(key);
    setMessage("");
    try {
      await apiPostJson(`/devices/${encodeURIComponent(selectedDeviceID)}/runtime-assignments`, {
        runtime_family: artifact.runtime_family,
        runtime_id: artifact.runtime_id,
        artifact_revision: artifact.artifact_revision,
        reason: "assigned from runtime page",
      });
      await loadDeployment(selectedDeviceID);
    } catch (err) {
      const fallback = tx("Failed to assign runtime artifact");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setAssigningKey("");
    }
  }

  async function clearAssignment(assignment: RuntimeAssignmentRecord) {
    if (!selectedDeviceID) {
      return;
    }
    const key = `${assignment.runtime_family}:${assignment.runtime_id}`;
    setClearingKey(key);
    setMessage("");
    try {
      await apiPostJson(`/devices/${encodeURIComponent(selectedDeviceID)}/runtime-assignments/clear`, {
        runtime_family: assignment.runtime_family,
        runtime_id: assignment.runtime_id,
      });
      await loadDeployment(selectedDeviceID);
    } catch (err) {
      const fallback = tx("Failed to cancel runtime request");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setClearingKey("");
    }
  }

  async function requestRemoval(runtime: DeviceRuntimeSummary) {
    if (!selectedDeviceID) {
      return;
    }
    const key = `${runtime.runtime_family}:${runtime.runtime_id}`;
    setRemovingKey(key);
    setMessage("");
    try {
      await apiPostJson(`/devices/${encodeURIComponent(selectedDeviceID)}/runtime-assignments/remove`, {
        runtime_family: runtime.runtime_family,
        runtime_id: runtime.runtime_id,
        reason: "removal requested from runtime page",
      });
      await loadDevices();
      await loadDeployment(selectedDeviceID);
    } catch (err) {
      const fallback = tx("Failed to request runtime removal");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setRemovingKey("");
    }
  }

  return (
    <div className="content-section rules-page runtime-page">
      <div className="section-header">
        <div>
          <h2>{tx("Runtime")}</h2>
        </div>
      </div>
      {message ? <p className="form-message error">{message}</p> : null}

      {selectedDevice ? (
        <>
          <section className="device-detail-section">
            <h3>{tx("Gateway target")}</h3>
            <div className="summary-grid rules-summary-grid runtime-platform-grid">
              <div>
                <span>{tx("Target")}</span>
                <strong title={deviceRuntimeTarget(selectedDevice)}>{deviceRuntimeTarget(selectedDevice)}</strong>
              </div>
              <div>
                <span>{tx("Last seen")}</span>
                <strong>{formatUnixTime(selectedDevice.last_seen_at_unix, locale)}</strong>
              </div>
              <div>
                <span>{tx("Runtime deployment")}</span>
                <strong>{selectedDevice.runtime_deployment_supported ? tx("supported") : tx("unsupported")}</strong>
              </div>
            </div>
          </section>

            <section className="device-detail-section">
              <div className="device-detail-section-header">
                <div>
                  <h3>{tx("Runtime build")}</h3>
                  <p className="section-note">{builder?.message || tx("Builds use the selected Gateway platform target.")}</p>
                </div>
                {latestBuildJob ? (
                  <span className={`token-status ${latestBuildJob.status === "failed" ? "token-status-blocked" : "token-status-active"}`}>{tx(latestBuildJob.status)}</span>
                ) : null}
              </div>
              <div className="runtime-build-controls">
                <label>
                  <span>{tx("Runtime")}</span>
                  <select value={buildRuntimeID} onChange={(event) => setBuildRuntimeID(event.target.value)}>
                    {buildOptions.map((option) => (
                      <option key={option.key} value={option.runtime_id} disabled={option.disabled} title={option.disabledTitle || undefined}>
                        {option.selectLabel}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  type="button"
                  onClick={() => void startBuild(selectedBuildOption.runtime_family, selectedBuildOption.runtime_id)}
                  disabled={!canStartSelectedBuild}
                  title={selectedBuildTitle}
                >
                  {selectedBuildBusy ? tx("Building...") : tx("Build & assign")}
                </button>
                {latestBuildJob?.artifact?.artifact_revision ? (
                  <p className="section-note runtime-build-message" title={latestBuildJob.artifact.artifact_revision}>
                    R: {shortRevision(latestBuildJob.artifact.artifact_revision)}
                  </p>
                ) : null}
              </div>
              {latestBuildJob?.error ? <p className="form-message error">{latestBuildJob.error}</p> : null}
              {recentBuildJobs.length > 0 ? (
                <div className="table-wrap runtime-build-job-table">
                  <table>
                    <thead>
                      <tr>
                        <th>{tx("Status")}</th>
                        <th>{tx("Family")}</th>
                        <th>{tx("Runtime ID")}</th>
                        <th>{tx("Queued")}</th>
                        <th>{tx("Finished")}</th>
                        <th>{tx("Error")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentBuildJobs.slice(0, 5).map((job) => (
                        <tr key={job.job_id}>
                          <td>
                            <span className={`token-status ${job.status === "failed" ? "token-status-blocked" : "token-status-active"}`}>{tx(job.status)}</span>
                          </td>
                          <td>{job.runtime_family || "-"}</td>
                          <td>{job.runtime_id || "-"}</td>
                          <td>{formatUnixTime(job.queued_at_unix, locale)}</td>
                          <td>{formatUnixTime(job.finished_at_unix, locale)}</td>
                          <td title={job.error || undefined}>{job.error || "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </section>

            <section className="device-detail-section">
              <div className="device-detail-section-header">
                <div>
                  <h3>{tx("Runtime inventory")}</h3>
                  <p className="section-note">{deploymentLoading ? tx("Loading runtime deployment...") : tx("Latest runtime summary reported by this Gateway.")}</p>
                </div>
              </div>
              <div className="table-wrap runtime-summary-table">
                <table>
                  <thead>
                    <tr>
                      <th>{tx("Actions")}</th>
                      <th>{tx("Family")}</th>
                      <th>{tx("Runtime ID")}</th>
                      <th>{tx("Detected version")}</th>
                      <th>{tx("Source")}</th>
                      <th>{tx("Available")}</th>
                      <th>{tx("Modules")}</th>
                      <th>{tx("Apps")}</th>
                      <th>{tx("Process")}</th>
                      <th>{tx("Apply state")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {inventory.map((runtime) => {
                      const runtimeKey = `${runtime.runtime_family}:${runtime.runtime_id}`;
                      const assignment = assignmentByKey.get(runtimeKey);
                      const appCount = Number.isFinite(runtime.app_count) ? runtime.app_count : 0;
                      const removalRequested = assignment?.desired_state === "removed";
                      const removalSupported = runtime.runtime_family === "php-fpm" || runtime.runtime_family === "psgi";
                      const buildSupported = runtimeBuildSupported(runtime.runtime_family, runtime.runtime_id);
                      const runtimeBuildActive = activeBuildByKey.has(runtimeKey);
                      const runtimeBuildBusy = buildingKey === runtimeKey || runtimeBuildActive;
                      const canBuild =
                        buildSupported &&
                        Boolean(selectedDevice.runtime_deployment_supported) &&
                        !runtime.process_running &&
                        !removalRequested &&
                        !runtimeBuildBusy;
                      const buildTitle = !buildSupported
                        ? tx("Build is not supported for this runtime family yet.")
                        : runtime.process_running
                            ? tx("Runtime process is running.")
                            : removalRequested
                              ? tx("Removal already requested.")
                              : runtimeBuildActive
                                ? tx("Runtime build is already running.")
                              : runtimeBuildMessage(runtime.runtime_family, runtime.runtime_id);
                      const canRemove =
                        removalSupported &&
                        runtime.available &&
                        runtime.usage_reported &&
                        appCount === 0 &&
                        !runtime.process_running &&
                        !removalRequested;
                      const removalTitle = !runtime.usage_reported
                        ? tx("Usage state is not reported yet.")
                        : !removalSupported
                          ? tx("Removal is not supported for this runtime family.")
                          : appCount > 0
                            ? tx("Runtime is used by apps.")
                            : runtime.process_running
                              ? tx("Runtime process is running.")
                              : removalRequested
                                ? tx("Removal already requested.")
                                : undefined;
                      return (
                        <tr key={runtimeKey}>
                          <td className="actions-cell">
                            <div className="inline-actions">
                              <button
                                type="button"
                                title={buildTitle}
                                onClick={() => void startBuild(runtime.runtime_family, runtime.runtime_id)}
                                disabled={!canBuild}
                              >
                                {runtimeBuildBusy ? tx("Building...") : runtime.available ? tx("Rebuild") : tx("Build")}
                              </button>
                              <button
                                type="button"
                                className="danger"
                                title={removalTitle}
                                onClick={() => void requestRemoval(runtime)}
                                disabled={!canRemove || removingKey === runtimeKey}
                              >
                                {removingKey === runtimeKey ? tx("Removing...") : removalRequested ? tx("Removal requested") : tx("Remove")}
                              </button>
                            </div>
                          </td>
                          <td>{runtime.runtime_family || "-"}</td>
                          <td title={runtime.display_name || runtime.runtime_id}>{runtime.runtime_id || "-"}</td>
                          <td title={runtime.detected_version || undefined}>{runtime.detected_version || "-"}</td>
                          <td>{runtime.source || "-"}</td>
                          <td>
                            <span className={`token-status ${runtime.available ? "token-status-approved" : "token-status-blocked"}`}>
                              {runtime.available ? tx("available") : tx("unavailable")}
                            </span>
                          </td>
                          <td>{Number.isFinite(runtime.module_count) ? runtime.module_count : "-"}</td>
                          <td title={(runtime.generated_targets || []).join(", ") || undefined}>
                            {runtime.usage_reported ? appCount : "-"}
                            {runtime.generated_targets && runtime.generated_targets.length > 0 ? <span className="table-subvalue">{runtime.generated_targets.join(", ")}</span> : null}
                          </td>
                          <td>
                            {runtime.usage_reported ? (
                              <span className={`token-status ${runtime.process_running ? "token-status-active" : "token-status-approved"}`}>
                                {runtime.process_running ? tx("running") : tx("stopped")}
                              </span>
                            ) : (
                              "-"
                            )}
                          </td>
                          <td title={runtime.apply_error || undefined}>
                            {runtime.apply_state || "-"}
                            {runtime.apply_error ? <span className="table-subvalue">{runtime.apply_error}</span> : null}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                {inventory.length === 0 && !deploymentLoading ? <div className="empty">{tx("No runtime inventory reported.")}</div> : null}
              </div>
            </section>

            <section className="device-detail-section">
              <div className="device-detail-section-header">
                <div>
                  <h3>{tx("Pending runtime requests")}</h3>
                  <p className="section-note">{tx("Requests waiting for the Gateway to pick them up.")}</p>
                </div>
              </div>
              <div className="table-wrap runtime-assignment-table">
                <table>
                  <thead>
                    <tr>
                      <th>{tx("Actions")}</th>
                      <th>{tx("Family")}</th>
                      <th>{tx("Runtime ID")}</th>
                      <th>{tx("Requested artifact")}</th>
                      <th>{tx("Local artifact")}</th>
                      <th>{tx("Apply state")}</th>
                      <th>{tx("Assigned")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assignments.map((assignment) => {
                      const key = `${assignment.runtime_family}:${assignment.runtime_id}`;
                      const status = statusByKey.get(key);
                      return (
                        <tr key={key}>
                          <td className="actions-cell">
                            <button type="button" className="secondary" onClick={() => void clearAssignment(assignment)} disabled={clearingKey === key}>
                              {clearingKey === key ? tx("Canceling...") : tx("Cancel request")}
                            </button>
                          </td>
                          <td>{assignment.runtime_family || "-"}</td>
                          <td>{assignment.runtime_id || "-"}</td>
                          <td title={assignment.desired_artifact_revision}>R: {shortRevision(assignment.desired_artifact_revision)}</td>
                          <td title={status?.local_artifact_revision || undefined}>{status?.local_artifact_revision ? `R: ${shortRevision(status.local_artifact_revision)}` : "-"}</td>
                          <td title={status?.apply_error || undefined}>
                            {status?.apply_state || "-"}
                            {status?.apply_error ? <span className="table-subvalue">{status.apply_error}</span> : null}
                          </td>
                          <td title={assignment.assigned_by || undefined}>{formatUnixTime(assignment.assigned_at_unix, locale)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                {assignments.length === 0 && !deploymentLoading ? <div className="empty">{tx("No pending runtime requests.")}</div> : null}
              </div>
            </section>

            <section className="device-detail-section">
              <div className="device-detail-section-header">
                <div>
                  <h3>{tx("Built artifacts")}</h3>
                  <p className="section-note">{tx("Stored artifacts matching this Gateway platform.")}</p>
                </div>
              </div>
              <div className="table-wrap runtime-artifact-table">
                <table>
                  <thead>
                    <tr>
                      <th>{tx("Actions")}</th>
                      <th>{tx("Family")}</th>
                      <th>{tx("Runtime ID")}</th>
                      <th>{tx("Revision")}</th>
                      <th>{tx("Version")}</th>
                      <th>{tx("Target")}</th>
                      <th>{tx("Size")}</th>
                      <th>{tx("State")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {artifacts.map((artifact) => {
                      const assignKey = `${artifact.runtime_family}:${artifact.runtime_id}:${artifact.artifact_revision}`;
                      const runtimeKey = `${artifact.runtime_family}:${artifact.runtime_id}`;
                      const pendingRevision = assignedRevisionByKey.get(runtimeKey);
                      const alreadyRequested = pendingRevision === artifact.artifact_revision;
                      const alreadyInstalled = installedRevisionByKey.get(runtimeKey) === artifact.artifact_revision;
                      const canAssign = artifact.storage_state === "stored" && !pendingRevision && !alreadyInstalled;
                      const assignLabel = alreadyInstalled
                        ? tx("Current")
                        : pendingRevision
                          ? tx(alreadyRequested ? "Assigned" : "Request pending")
                          : assigningKey === assignKey
                            ? tx("Assigning...")
                            : tx("Assign");
                      return (
                        <tr key={assignKey}>
                          <td className="actions-cell">
                            <button type="button" onClick={() => void assignArtifact(artifact)} disabled={!canAssign || assigningKey === assignKey}>
                              {assignLabel}
                            </button>
                          </td>
                          <td>{artifact.runtime_family || "-"}</td>
                          <td>{artifact.runtime_id || "-"}</td>
                          <td title={artifact.artifact_revision}>R: {shortRevision(artifact.artifact_revision)}</td>
                          <td title={artifact.detected_version || undefined}>{artifact.detected_version || "-"}</td>
                          <td title={artifact.builder_profile || undefined}>{runtimeTargetLabel(artifact.target)}</td>
                          <td>{formatBytes(artifact.compressed_size)}</td>
                          <td>{artifact.storage_state || "-"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                {artifacts.length === 0 && !deploymentLoading ? <div className="empty">{tx("No built artifacts.")}</div> : null}
              </div>
            </section>
          </>
        ) : (
          <div className="empty">{loading ? tx("Loading runtime devices...") : tx("No approved devices.")}</div>
        )}
    </div>
  );
}
