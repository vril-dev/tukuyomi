import { useEffect, useMemo, useState } from "react";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { useI18n } from "@/lib/i18n";

type ScheduledTaskRecord = {
  name: string;
  display_name?: string;
  enabled?: boolean;
  schedule: string;
  timezone?: string;
  command: string;
  env?: Record<string, string>;
  timeout_sec?: number;
};

type ScheduledTaskStatus = {
  name: string;
  running?: boolean;
  pid?: number;
  last_schedule_minute?: string;
  last_started_at?: string;
  last_finished_at?: string;
  last_result?: string;
  last_error?: string;
  last_exit_code?: number;
  last_duration_ms?: number;
  log_file?: string;
  resolved_command?: string;
};

type ScheduledTaskRuntimePaths = {
  config_file?: string;
  runtime_dir?: string;
  state_file?: string;
  log_dir?: string;
};

type ScheduledTasksResponse = {
  etag?: string;
  tasks?: {
    tasks?: ScheduledTaskRecord[];
  };
  statuses?: ScheduledTaskStatus[];
  runtime_paths?: ScheduledTaskRuntimePaths;
  rollback_depth?: number;
};

type TaskDraft = {
  draftID: string;
  name: string;
  enabled: boolean;
  schedule: string;
  timezone: string;
  command: string;
  envText: string;
  timeoutSec: string;
};

let nextDraftID = 1;

function makeDraftID() {
  const draftID = `scheduled-task-${nextDraftID}`;
  nextDraftID += 1;
  return draftID;
}

function draftFromRecord(task: ScheduledTaskRecord): TaskDraft {
  return {
    draftID: makeDraftID(),
    name: task.name || "",
    enabled: task.enabled !== false,
    schedule: task.schedule || "* * * * *",
    timezone: task.timezone || "",
    command: task.command || "",
    envText: Object.entries(task.env || {})
      .map(([key, value]) => `${key}=${value}`)
      .join("\n"),
    timeoutSec: String(task.timeout_sec || 300),
  };
}

function emptyDraft(): TaskDraft {
  return {
    draftID: makeDraftID(),
    name: "",
    enabled: true,
    schedule: "* * * * *",
    timezone: "",
    command: "",
    envText: "",
    timeoutSec: "300",
  };
}

function parseEnv(raw: string) {
  const out: Record<string, string> = {};
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const idx = trimmed.indexOf("=");
    if (idx <= 0) {
      continue;
    }
    out[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1);
  }
  return out;
}

function recordFromDraft(task: TaskDraft): ScheduledTaskRecord {
  const timeout = Number.parseInt(task.timeoutSec.trim(), 10);
  return {
    name: task.name.trim(),
    enabled: task.enabled,
    schedule: task.schedule.trim(),
    timezone: task.timezone.trim() || undefined,
    command: task.command.trim(),
    env: parseEnv(task.envText),
    timeout_sec: Number.isFinite(timeout) ? timeout : 300,
  };
}

function statusBadgeClass(status?: string, running?: boolean) {
  if (running) {
    return "bg-green-100 text-green-800";
  }
  switch (status) {
    case "success":
      return "bg-green-100 text-green-800";
    case "failed":
    case "timeout":
    case "invalid":
      return "bg-red-100 text-red-800";
    case "abandoned":
      return "bg-amber-100 text-amber-900";
    default:
      return "bg-neutral-100 text-neutral-700";
  }
}

function statusHasExecution(status?: ScheduledTaskStatus) {
  if (!status) {
    return false;
  }
  return Boolean(
    status.running ||
      status.last_schedule_minute ||
      status.last_started_at ||
      status.last_finished_at ||
      status.last_result ||
      status.last_error ||
      status.log_file ||
      status.resolved_command,
  );
}

export default function ScheduledTasksPanel() {
  const { tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [etag, setEtag] = useState("");
  const [tasks, setTasks] = useState<TaskDraft[]>([]);
  const [statuses, setStatuses] = useState<ScheduledTaskStatus[]>([]);
  const [runtimePaths, setRuntimePaths] = useState<ScheduledTaskRuntimePaths>({});
  const [rollbackDepth, setRollbackDepth] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [messages, setMessages] = useState<string[]>([]);
  const [busy, setBusy] = useState<"" | "validate" | "apply" | "rollback">("");

  const statusMap = useMemo(
    () => new Map(statuses.map((status) => [status.name, status])),
    [statuses],
  );

  function updateTask(index: number, patch: Partial<TaskDraft>) {
    setTasks((prev) => prev.map((entry, taskIndex) => (
      taskIndex === index ? { ...entry, ...patch } : entry
    )));
  }

  async function load() {
    setLoading(true);
    setError("");
    try {
      const data = await apiGetJson<ScheduledTasksResponse>("/scheduled-tasks");
      setEtag(data.etag || "");
      setTasks(
        Array.isArray(data.tasks?.tasks) && data.tasks?.tasks?.length
          ? data.tasks.tasks.map(draftFromRecord)
          : [],
      );
      setStatuses(Array.isArray(data.statuses) ? data.statuses : []);
      setRuntimePaths(data.runtime_paths || {});
      setRollbackDepth(Number(data.rollback_depth || 0));
      setMessages([]);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const raw = useMemo(
    () => JSON.stringify({ tasks: tasks.map(recordFromDraft) }, null, 2),
    [tasks],
  );

  async function validate() {
    setBusy("validate");
    setError("");
    try {
      const data = await apiPostJson<{ messages?: string[] }>("/scheduled-tasks/validate", { raw });
      setMessages(data.messages && data.messages.length ? data.messages : [tx("Validation passed.")]);
    } catch (err: unknown) {
      setMessages([]);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy("");
    }
  }

  async function apply() {
    setBusy("apply");
    setError("");
    try {
      const data = await apiPutJson<ScheduledTasksResponse>("/scheduled-tasks", { raw }, {
        headers: {
          "If-Match": etag,
        },
      });
      setEtag(data.etag || "");
      setStatuses(Array.isArray(data.statuses) ? data.statuses : []);
      setRuntimePaths(data.runtime_paths || {});
      setMessages([tx("Scheduled tasks updated.")]);
      await load();
    } catch (err: unknown) {
      setMessages([]);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy("");
    }
  }

  async function rollback() {
    setBusy("rollback");
    setError("");
    try {
      await apiPostJson("/scheduled-tasks/rollback", {});
      setMessages([tx("Rollback applied.")]);
      await load();
    } catch (err: unknown) {
      setMessages([]);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy("");
    }
  }

  function expectedLogFile(task: TaskDraft) {
    const taskName = task.name.trim();
    if (!taskName || !runtimePaths.log_dir) {
      return "-";
    }
    return `${runtimePaths.log_dir}/${taskName}.log`;
  }

  if (loading) {
    return <div className="w-full p-4 text-neutral-500">{tx("Loading scheduled tasks...")}</div>;
  }

  return (
    <div className="w-full p-4 space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{tx("Scheduled Tasks")}</h1>
        <p className="text-sm text-neutral-500">
          {tx("Store cron-style command lines here, then execute them from cron, a Docker sidecar, or a systemd timer outside the request path.")}
        </p>
      </header>

      <section className="rounded-xl border border-neutral-200 bg-white p-4 space-y-4">
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => void load()}>{tx("Load")}</button>
          <button type="button" disabled={readOnly} onClick={() => setTasks((prev) => [...prev, emptyDraft()])}>{tx("Add Task")}</button>
          <button type="button" disabled={busy !== ""} onClick={() => void validate()}>
            {busy === "validate" ? tx("Validating...") : tx("Validate")}
          </button>
          <button type="button" disabled={readOnly || !etag || busy !== ""} onClick={() => void apply()}>
            {busy === "apply" ? tx("Applying...") : tx("Apply")}
          </button>
          <button type="button" disabled={readOnly || rollbackDepth === 0 || busy !== ""} onClick={() => void rollback()}>
            {busy === "rollback" ? tx("Rolling back...") : tx("Rollback")}
          </button>
        </div>

        {messages.length ? (
          <div className="rounded border border-green-300 bg-green-50 px-3 py-2 text-xs text-green-900 whitespace-pre-wrap">
            {messages.join("\n")}
          </div>
        ) : null}
        {error ? (
          <div className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900 whitespace-pre-wrap">
            {error}
          </div>
        ) : null}

        <div className="rounded border border-blue-200 bg-blue-50 px-3 py-2 text-xs text-blue-900">
          {tx("Enter the full command line you would normally put into cron. Example: date >> /app/logs/scheduled-task.log")}
        </div>

        <div className="grid gap-3 md:grid-cols-2">
          <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs text-neutral-700 space-y-1">
            <div>{tx("Saving a task does not execute it.")}</div>
            <div>{tx("Binary deployments need a systemd timer.")}</div>
            <div>{tx("Docker deployments need the scheduled-task-runner sidecar.")}</div>
            <div>{tx("ui-preview-up starts its own preview scheduler sidecar and resets preview tasks to empty.")}</div>
          </div>
          <div className="rounded border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs text-neutral-700 space-y-1">
            <div>{tx("Config File")}: <code>{runtimePaths.config_file || "-"}</code></div>
            <div>{tx("State File")}: <code>{runtimePaths.state_file || "-"}</code></div>
            <div>{tx("Log Directory")}: <code>{runtimePaths.log_dir || "-"}</code></div>
          </div>
        </div>

        {tasks.length === 0 ? (
          <div className="rounded border border-dashed border-neutral-200 px-3 py-6 text-sm text-neutral-500">
            {tx("No scheduled tasks configured yet.")}
          </div>
        ) : (
          <div className="space-y-4">
            {tasks.map((task, index) => {
              const status = statusMap.get(task.name.trim());
              const ranBefore = statusHasExecution(status);
              return (
                <article key={task.draftID} className="rounded-xl border border-neutral-200 p-4 space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h2 className="text-sm font-semibold">{task.name.trim() || tx("New Task")}</h2>
                      <p className="text-xs text-neutral-500">{tx("Cron match and execution status are evaluated by the external scheduler runner.")}</p>
                    </div>
                    <div className="flex flex-wrap gap-2 text-xs">
                      <span className={`rounded px-2 py-1 ${statusBadgeClass(status?.last_result, status?.running)}`}>
                        {status?.running ? tx("running") : tx(ranBefore ? (status?.last_result || "idle") : "never-run")}
                      </span>
                      <button
                        type="button"
                        className="text-red-700"
                        onClick={() => setTasks((prev) => prev.filter((_, taskIndex) => taskIndex !== index))}
                        disabled={readOnly}
                      >
                        {tx("Remove")}
                      </button>
                    </div>
                  </div>

                  <div className="grid gap-3 md:grid-cols-2">
                    <label className="space-y-1 text-sm">
                      <span>{tx("Name")}</span>
                      <input
                        className="w-full"
                        placeholder="app-schedule"
                        value={task.name}
                        onChange={(event) => updateTask(index, { name: event.target.value })}
                      />
                    </label>
                    <div className="space-y-1 text-sm">
                      <span>{tx("Enabled")}</span>
                      <div className="flex min-h-[34px] items-center">
                        <label className="inline-flex items-center gap-2 text-sm">
                          <input
                            type="checkbox"
                            checked={task.enabled}
                            onChange={(event) => updateTask(index, { enabled: event.target.checked })}
                          />
                          <span>{tx("Enabled")}</span>
                        </label>
                      </div>
                    </div>
                    <label className="space-y-1 text-sm">
                      <span>{tx("Schedule")}</span>
                      <input
                        className="w-full"
                        value={task.schedule}
                        onChange={(event) => updateTask(index, { schedule: event.target.value })}
                      />
                    </label>
                    <label className="space-y-1 text-sm">
                      <span>{tx("Timezone")}</span>
                      <input
                        className="w-full"
                        placeholder="Asia/Tokyo"
                        value={task.timezone}
                        onChange={(event) => updateTask(index, { timezone: event.target.value })}
                      />
                    </label>
                    <label className="space-y-1 text-sm md:col-span-2">
                      <span>{tx("Command")}</span>
                      <p className="text-xs text-neutral-500">
                        {tx("Full command line. Use absolute paths for predictable execution. App jobs inside Docker need the app tree mounted into both coraza and scheduled-task-runner.")}
                      </p>
                      <input
                        className="w-full"
                        placeholder="date >> /app/logs/scheduled-task.log"
                        value={task.command}
                        onChange={(event) => updateTask(index, { command: event.target.value })}
                      />
                    </label>
                    <label className="space-y-1 text-sm">
                      <span>{tx("Timeout Seconds")}</span>
                      <input
                        className="w-full"
                        value={task.timeoutSec}
                        onChange={(event) => updateTask(index, { timeoutSec: event.target.value })}
                      />
                    </label>
                    <label className="space-y-1 text-sm md:col-span-2">
                      <span>{tx("Environment (KEY=value per line)")}</span>
                      <textarea className="w-full" rows={3} value={task.envText} onChange={(event) => updateTask(index, { envText: event.target.value })} />
                    </label>
                  </div>

                  {status ? (
                    <div className="rounded border border-neutral-200 bg-neutral-50 p-3 text-xs space-y-1">
                      {ranBefore ? (
                        <>
                          <div>{tx("Last Schedule Minute")}: {status.last_schedule_minute || "-"}</div>
                          <div>{tx("Last Started")}: {status.last_started_at || "-"}</div>
                          <div>{tx("Last Finished")}: {status.last_finished_at || "-"}</div>
                          <div>{tx("Exit Code")}: {typeof status.last_exit_code === "number" ? String(status.last_exit_code) : "-"}</div>
                          <div>{tx("Duration")}: {typeof status.last_duration_ms === "number" ? `${status.last_duration_ms}ms` : "-"}</div>
                          <div>{tx("Executed Command")}: <code>{status.resolved_command || task.command || "-"}</code></div>
                          <div>{tx("Log File")}: <code>{status.log_file || expectedLogFile(task)}</code></div>
                          {status.last_error ? <div className="text-red-700">{status.last_error}</div> : null}
                        </>
                      ) : (
                        <>
                          <div>{tx("This task has never run yet. Saving only updates config.")}</div>
                          <div>{tx("Configured Command")}: <code>{task.command || "-"}</code></div>
                          <div>{tx("Expected Log File")}: <code>{expectedLogFile(task)}</code></div>
                          <div>{tx("State File")}: <code>{runtimePaths.state_file || "-"}</code></div>
                        </>
                      )}
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>
        )}

        <div className="rounded border border-neutral-200 p-3 bg-neutral-50">
          <div className="text-xs text-neutral-500 mb-2">{tx("Rendered JSON")}</div>
          <pre className="overflow-x-auto text-xs whitespace-pre-wrap">{raw}</pre>
        </div>
      </section>
    </div>
  );
}
