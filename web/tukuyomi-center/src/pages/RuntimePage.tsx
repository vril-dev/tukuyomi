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
  dispatched_at_unix?: number;
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

type RuntimeAssignmentResponse = {
  assignment?: RuntimeAssignmentRecord;
};

type RuntimeDeploymentFollowUp = {
  device_id: string;
  runtime_family: string;
  runtime_id: string;
  desired_artifact_revision: string;
  desired_state: string;
  assigned_at_unix: number;
  expires_at_unix: number;
};

type RuntimePendingRequest = {
  key: string;
  runtime_family: string;
  runtime_id: string;
  desired_artifact_revision: string;
  desired_state: string;
  assigned_at_unix: number;
  assignment?: RuntimeAssignmentRecord;
};

const RUNTIME_BUILD_OPTIONS = [
  { runtime_family: "php-fpm", runtime_id: "php83", label: "PHP 8.3" },
  { runtime_family: "php-fpm", runtime_id: "php84", label: "PHP 8.4" },
  { runtime_family: "php-fpm", runtime_id: "php85", label: "PHP 8.5" },
  { runtime_family: "psgi", runtime_id: "perl536", label: "Perl 5.36" },
  { runtime_family: "psgi", runtime_id: "perl538", label: "Perl 5.38" },
  { runtime_family: "psgi", runtime_id: "perl540", label: "Perl 5.40" },
];

const RUNTIME_DEPLOYMENT_FOLLOW_UP_SECONDS = 30 * 60;

function shortRevision(value?: string) {
  const trimmed = (value || "").trim();
  return trimmed.length > 12 ? trimmed.slice(0, 12) : trimmed || "-";
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

function runtimeAssignmentRequestLabel(desiredState?: string) {
  switch ((desiredState || "").trim()) {
    case "installed":
      return "Install";
    case "removed":
      return "Remove";
    default:
      return desiredState || "-";
  }
}

function runtimeAssignmentRequestClass(desiredState?: string) {
  switch ((desiredState || "").trim()) {
    case "installed":
      return "token-status-approved";
    case "removed":
      return "token-status-blocked";
    default:
      return "";
  }
}

function runtimePendingCurrentState(status?: RuntimeApplyStatusRecord) {
  const state = (status?.apply_state || "").trim();
  const localRevision = (status?.local_artifact_revision || "").trim();
  if (!localRevision && (state === "" || state === "removed")) {
    return "not installed";
  }
  return state || "-";
}

function runtimeFollowUpFromAssignment(deviceID: string, assignment: RuntimeAssignmentRecord, nowUnix: number): RuntimeDeploymentFollowUp {
  const assignedAt = assignment.assigned_at_unix > 0 ? assignment.assigned_at_unix : nowUnix;
  return {
    device_id: assignment.device_id || deviceID,
    runtime_family: assignment.runtime_family,
    runtime_id: assignment.runtime_id,
    desired_artifact_revision: assignment.desired_artifact_revision || "",
    desired_state: assignment.desired_state || "installed",
    assigned_at_unix: assignedAt,
    expires_at_unix: nowUnix + RUNTIME_DEPLOYMENT_FOLLOW_UP_SECONDS,
  };
}

function runtimeFollowUpFromBuildJob(job: RuntimeBuildJob, nowUnix: number): RuntimeDeploymentFollowUp | null {
  if (job.status !== "succeeded" || !job.assignment) {
    return null;
  }
  const followUp = runtimeFollowUpFromAssignment(job.device_id, job.assignment, nowUnix);
  const baseUnix = job.finished_at_unix || job.updated_at_unix || job.queued_at_unix || nowUnix;
  followUp.expires_at_unix = baseUnix + RUNTIME_DEPLOYMENT_FOLLOW_UP_SECONDS;
  return followUp;
}

function runtimeFollowUpSettled(followUp: RuntimeDeploymentFollowUp, status?: RuntimeApplyStatusRecord, runtime?: DeviceRuntimeSummary) {
  if (!status) {
    return false;
  }
  const state = (status.apply_state || "").trim();
  const statusUpdatedAfterRequest = status.updated_at_unix >= followUp.assigned_at_unix || status.last_attempt_at_unix >= followUp.assigned_at_unix;
  if (followUp.desired_state === "removed") {
    if ((state === "failed" || state === "blocked") && statusUpdatedAfterRequest) {
      return true;
    }
    return !runtime && state === "removed" && statusUpdatedAfterRequest;
  }
  const localRevision = (status.local_artifact_revision || "").trim();
  const runtimeRevision = (runtime?.artifact_revision || "").trim();
  if (state === "installed") {
    if (runtime && runtimeRevision === followUp.desired_artifact_revision) {
      return true;
    }
    return Boolean(runtime && localRevision && statusUpdatedAfterRequest);
  }
  if (state === "removed" && statusUpdatedAfterRequest) {
    return true;
  }
  if ((state === "failed" || state === "blocked") && status.desired_artifact_revision === followUp.desired_artifact_revision) {
    return true;
  }
  return false;
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
  const [clearingKey, setClearingKey] = useState("");
  const [removingKeys, setRemovingKeys] = useState<Set<string>>(() => new Set());
  const [runtimeFollowUps, setRuntimeFollowUps] = useState<RuntimeDeploymentFollowUp[]>([]);

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
    async (deviceID: string, options?: { silent?: boolean }) => {
      const silent = options?.silent === true;
      if (!silent) {
        setDeploymentLoading(true);
        setMessage("");
      }
      try {
        const data = await apiGetJson<RuntimeDeploymentResponse>(`/devices/${encodeURIComponent(deviceID)}/runtime-deployment`);
        setDeployment({
          device: data.device,
          assignments: Array.isArray(data.assignments) ? data.assignments : [],
          apply_status: Array.isArray(data.apply_status) ? data.apply_status : [],
        });
      } catch (err) {
        const fallback = tx("Failed to load runtime deployment");
        if (!silent) {
          setDeployment(null);
        }
        setMessage(err instanceof Error ? err.message || fallback : fallback);
      } finally {
        if (!silent) {
          setDeploymentLoading(false);
        }
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

  useEffect(() => {
    setRuntimeFollowUps([]);
  }, [selectedDeviceID]);

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
  const applyStatus = deployment?.apply_status || [];
  const displayDevice = deployment?.device || selectedDevice;
  const inventory = useMemo(() => {
    const source = deployment?.device ? deployment.device.runtime_inventory || [] : selectedDevice?.runtime_inventory || [];
    return [...source].sort(compareRuntimeIdentity);
  }, [deployment?.device, selectedDevice?.runtime_inventory]);
  const recentBuildJobs = useMemo(() => [...buildJobs].sort((left, right) => right.updated_at_unix - left.updated_at_unix || right.queued_at_unix - left.queued_at_unix), [buildJobs]);
  const activeBuildJobs = useMemo(() => recentBuildJobs.filter(isRuntimeBuildActive), [recentBuildJobs]);

  const latestBuildJob = recentBuildJobs[0] || null;
  const visibleBuildStatusJob = activeBuildJobs[0] || (latestBuildJob?.status === "failed" ? latestBuildJob : null);
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
  const inventoryByKey = new Map<string, DeviceRuntimeSummary>(inventory.map((item) => [`${item.runtime_family}:${item.runtime_id}`, item] as const));
  const installedRuntimeKeySet = new Set<string>();
  for (const item of inventory) {
    const revision = (item.artifact_revision || "").trim();
    const key = `${item.runtime_family}:${item.runtime_id}`;
    const source = (item.source || "").trim();
    const state = (item.apply_state || "").trim();
    if (source === "center" || (state === "installed" && revision)) {
      installedRuntimeKeySet.add(key);
      continue;
    }
    if (state === "installed" || (item.available && source === "center")) {
      installedRuntimeKeySet.add(key);
    }
  }
  for (const item of applyStatus) {
    const revision = (item.local_artifact_revision || "").trim();
    if (item.apply_state === "installed") {
      const key = `${item.runtime_family}:${item.runtime_id}`;
      if (revision) {
        installedRuntimeKeySet.add(key);
      }
    }
  }
  const nowUnix = Math.floor(Date.now() / 1000);
  const buildJobFollowUps = recentBuildJobs
    .map((job) => runtimeFollowUpFromBuildJob(job, nowUnix))
    .filter((item): item is RuntimeDeploymentFollowUp => Boolean(item));
  const unresolvedRuntimeFollowUps = [...runtimeFollowUps, ...buildJobFollowUps].filter((item) => {
    if (item.device_id !== selectedDeviceID || item.expires_at_unix <= nowUnix) {
      return false;
    }
    const key = `${item.runtime_family}:${item.runtime_id}`;
    return !runtimeFollowUpSettled(item, statusByKey.get(key), inventoryByKey.get(key));
  });
  const runtimeFollowUpByRuntimeKey = new Map<string, RuntimeDeploymentFollowUp>();
  for (const item of unresolvedRuntimeFollowUps) {
    runtimeFollowUpByRuntimeKey.set(`${item.runtime_family}:${item.runtime_id}`, item);
  }
  const pendingRuntimeRequests = useMemo(() => {
    const rows: RuntimePendingRequest[] = assignments.map((assignment) => ({
      key: `${assignment.runtime_family}:${assignment.runtime_id}`,
      runtime_family: assignment.runtime_family,
      runtime_id: assignment.runtime_id,
      desired_artifact_revision: assignment.desired_artifact_revision,
      desired_state: assignment.desired_state,
      assigned_at_unix: assignment.assigned_at_unix,
      assignment,
    }));
    const seen = new Set(rows.map((row) => row.key));
    for (const followUp of unresolvedRuntimeFollowUps) {
      const key = `${followUp.runtime_family}:${followUp.runtime_id}`;
      if (seen.has(key)) {
        continue;
      }
      rows.push({
        key,
        runtime_family: followUp.runtime_family,
        runtime_id: followUp.runtime_id,
        desired_artifact_revision: followUp.desired_artifact_revision,
        desired_state: followUp.desired_state,
        assigned_at_unix: followUp.assigned_at_unix,
      });
    }
    return rows.sort(compareRuntimeIdentity);
  }, [assignments, unresolvedRuntimeFollowUps]);

  useEffect(() => {
    if (!selectedDeviceID || hasActiveBuildJob || (assignments.length === 0 && unresolvedRuntimeFollowUps.length === 0)) {
      return;
    }
    let inFlight = false;
    const timer = window.setInterval(() => {
      if (inFlight) {
        return;
      }
      inFlight = true;
      void loadDeployment(selectedDeviceID, { silent: true }).finally(() => {
        inFlight = false;
      });
    }, 5000);
    return () => window.clearInterval(timer);
  }, [assignments.length, hasActiveBuildJob, loadDeployment, selectedDeviceID, unresolvedRuntimeFollowUps.length]);

  const buildOptions = RUNTIME_BUILD_OPTIONS.map((option) => {
    const key = `${option.runtime_family}:${option.runtime_id}`;
    const supported = runtimeBuildSupported(option.runtime_family, option.runtime_id);
    const busy = buildingKey === key || activeBuildByKey.has(key);
    const built = installedRuntimeKeySet.has(key);
    const pending = assignedRevisionByKey.has(key) || runtimeFollowUpByRuntimeKey.has(key);
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
  const canStartSelectedBuild = Boolean(displayDevice?.runtime_deployment_supported && selectedDeviceID && !selectedBuildOption.disabled);
  const selectedBuildTitle = selectedBuildOption.disabledTitle || runtimeBuildMessage(selectedBuildOption.runtime_family, selectedBuildOption.runtime_id);
  const buildOptionStateKey = buildOptions.map((option) => `${option.key}:${option.disabled ? "1" : "0"}`).join("|");

  const renderBuildJobTable = (jobs: RuntimeBuildJob[], className = "runtime-build-job-table") => (
    <div className={`table-wrap ${className}`}>
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
          {jobs.map((job) => (
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
  );

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

  function recordRuntimeFollowUp(assignment?: RuntimeAssignmentRecord) {
    if (!selectedDeviceID || !assignment) {
      return;
    }
    const nowUnix = Math.floor(Date.now() / 1000);
    const followUp = runtimeFollowUpFromAssignment(selectedDeviceID, assignment, nowUnix);
    const key = `${followUp.device_id}:${followUp.runtime_family}:${followUp.runtime_id}`;
    setRuntimeFollowUps((current) => {
      const next = current.filter((item) => `${item.device_id}:${item.runtime_family}:${item.runtime_id}` !== key && item.expires_at_unix > nowUnix);
      return [...next, followUp];
    });
  }

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
      setRuntimeFollowUps((current) => current.filter((item) => !(item.device_id === selectedDeviceID && item.runtime_family === assignment.runtime_family && item.runtime_id === assignment.runtime_id)));
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
    setRemovingKeys((current) => new Set(current).add(key));
    setMessage("");
    try {
      const data = await apiPostJson<RuntimeAssignmentResponse>(`/devices/${encodeURIComponent(selectedDeviceID)}/runtime-assignments/remove`, {
        runtime_family: runtime.runtime_family,
        runtime_id: runtime.runtime_id,
        reason: "removal requested from runtime page",
      });
      recordRuntimeFollowUp(data.assignment);
      await loadDevices();
      await loadDeployment(selectedDeviceID);
    } catch (err) {
      const fallback = tx("Failed to request runtime removal");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setRemovingKeys((current) => {
        const next = new Set(current);
        next.delete(key);
        return next;
      });
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
                <strong title={deviceRuntimeTarget(displayDevice || undefined)}>{deviceRuntimeTarget(displayDevice || undefined)}</strong>
              </div>
              <div>
                <span>{tx("Last seen")}</span>
                <strong>{formatUnixTime(displayDevice?.last_seen_at_unix || 0, locale)}</strong>
              </div>
              <div>
                <span>{tx("Runtime deployment")}</span>
                <strong>{displayDevice?.runtime_deployment_supported ? tx("supported") : tx("unsupported")}</strong>
              </div>
            </div>
          </section>

            <section className="device-detail-section">
              <div className="device-detail-section-header">
                <div>
                  <h3>{tx("Runtime build")}</h3>
                  <p className="section-note">{builder?.message || tx("Builds use the selected Gateway platform target.")}</p>
                </div>
                {visibleBuildStatusJob ? (
                  <span className={`token-status ${visibleBuildStatusJob.status === "failed" ? "token-status-blocked" : "token-status-active"}`}>{tx(visibleBuildStatusJob.status)}</span>
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
              {activeBuildJobs.length > 0 ? renderBuildJobTable(activeBuildJobs, "runtime-build-active-table") : null}
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
                      const followUp = runtimeFollowUpByRuntimeKey.get(runtimeKey);
                      const appCount = Number.isFinite(runtime.app_count) ? runtime.app_count : 0;
                      const removalRequested = assignment?.desired_state === "removed" || followUp?.desired_state === "removed";
                      const removalSupported = runtime.runtime_family === "php-fpm" || runtime.runtime_family === "psgi";
                      const buildSupported = runtimeBuildSupported(runtime.runtime_family, runtime.runtime_id);
                      const runtimeBuildActive = activeBuildByKey.has(runtimeKey);
                      const runtimeBuildBusy = buildingKey === runtimeKey || runtimeBuildActive;
                      const removalSubmitting = removingKeys.has(runtimeKey);
                      const canBuild =
                        buildSupported &&
                        Boolean(displayDevice?.runtime_deployment_supported) &&
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
                                disabled={!canRemove || removalSubmitting}
                              >
                                {removalSubmitting || removalRequested ? tx("Removing...") : tx("Remove")}
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
                  <p className="section-note">{tx("Requests queued for Gateway pickup or waiting for the next apply report.")}</p>
                </div>
              </div>
              <div className="table-wrap runtime-assignment-table">
                <table>
                  <thead>
                    <tr>
                      <th>{tx("Actions")}</th>
                      <th>{tx("Request")}</th>
                      <th>{tx("Family")}</th>
                      <th>{tx("Runtime ID")}</th>
                      <th>{tx("Requested artifact")}</th>
                      <th>{tx("Local artifact")}</th>
                      <th>{tx("Current state")}</th>
                      <th>{tx("Requested at")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pendingRuntimeRequests.map((request) => {
                      const key = request.key;
                      const status = statusByKey.get(key);
                      const requestLabel = runtimeAssignmentRequestLabel(request.desired_state);
                      const requestedArtifact = request.desired_state === "removed" ? "-" : `R: ${shortRevision(request.desired_artifact_revision)}`;
                      const currentState = runtimePendingCurrentState(status);
                      const canCancel = Boolean(request.assignment);
                      return (
                        <tr key={key}>
                          <td className="actions-cell">
                            <button
                              type="button"
                              className="secondary"
                              onClick={() => {
                                if (request.assignment) {
                                  void clearAssignment(request.assignment);
                                }
                              }}
                              disabled={!canCancel || clearingKey === key}
                            >
                              {!canCancel ? tx("Picked up") : clearingKey === key ? tx("Canceling...") : tx("Cancel request")}
                            </button>
                          </td>
                          <td>
                            <span className={`token-status ${runtimeAssignmentRequestClass(request.desired_state)}`}>{tx(requestLabel)}</span>
                          </td>
                          <td>{request.runtime_family || "-"}</td>
                          <td>{request.runtime_id || "-"}</td>
                          <td title={request.desired_artifact_revision || undefined}>{requestedArtifact}</td>
                          <td title={status?.local_artifact_revision || undefined}>{status?.local_artifact_revision ? `R: ${shortRevision(status.local_artifact_revision)}` : "-"}</td>
                          <td title={status?.apply_error || undefined}>
                            {tx(currentState)}
                            {status?.apply_error ? <span className="table-subvalue">{status.apply_error}</span> : null}
                          </td>
                          <td title={request.assignment?.assigned_by || undefined}>{formatUnixTime(request.assigned_at_unix, locale)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                {pendingRuntimeRequests.length === 0 && !deploymentLoading ? <div className="empty">{tx("No pending runtime requests.")}</div> : null}
              </div>
            </section>

            {recentBuildJobs.length > 0 ? (
              <section className="device-detail-section runtime-build-history-section">
                <details>
                  <summary>
                    <span>{tx("Runtime build history")}</span>
                    <span className="section-note">{tx("Latest 20 build jobs kept by this Center process.")}</span>
                  </summary>
                  {renderBuildJobTable(recentBuildJobs)}
                </details>
              </section>
            ) : null}

          </>
        ) : (
          <div className="empty">{loading ? tx("Loading runtime devices...") : tx("No approved devices.")}</div>
        )}
    </div>
  );
}
