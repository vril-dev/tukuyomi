import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useParams } from "react-router-dom";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";

import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
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
  operator_mode?: string;
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

type RemoteSSHWebTerminalResponse = {
  terminal_id?: string;
  websocket_path?: string;
  expires_at_unix?: number;
  session?: RemoteSSHSession;
};

type RemoteSSHSessionActionResponse = {
  status?: string;
  session?: RemoteSSHSession;
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

type WebTerminalForm = {
  reason: string;
  ttlSec: string;
  scrollbackRows: string;
};

const DEFAULT_REMOTE_SSH_TTL = 900;
const DEFAULT_REMOTE_SSH_IDLE_TIMEOUT = 300;
const DEFAULT_REMOTE_SSH_MAX_SESSIONS_TOTAL = 16;
const DEFAULT_REMOTE_SSH_MAX_SESSIONS_PER_DEVICE = 1;
const DEFAULT_REMOTE_SSH_LOCAL_ADDR = "127.0.0.1:0";
const DEFAULT_REMOTE_SSH_TERMINAL_SCROLLBACK = 2000;
const MIN_REMOTE_SSH_TERMINAL_SCROLLBACK = 100;
const MAX_REMOTE_SSH_TERMINAL_SCROLLBACK = 10000;
const REMOTE_SSH_WEB_TERMINAL_PROTOCOL = "tukuyomi.remote-ssh.web-terminal.v1";
const REMOTE_SSH_SESSION_PAGE_SIZE = 10;
const REMOTE_SSH_ATTACHABLE_STATUSES = new Set(["pending", "gateway_attached", "operator_attached", "active"]);

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

function boundedScrollbackRows(value: string) {
  const trimmed = value.trim();
  const parsed = /^\d+$/.test(trimmed) ? Number.parseInt(trimmed, 10) : NaN;
  if (!Number.isFinite(parsed)) {
    return DEFAULT_REMOTE_SSH_TERMINAL_SCROLLBACK;
  }
  return Math.min(Math.max(parsed, MIN_REMOTE_SSH_TERMINAL_SCROLLBACK), MAX_REMOTE_SSH_TERMINAL_SCROLLBACK);
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

function webSocketURL(path: string) {
  const raw = path.trim();
  if (raw.startsWith("ws://") || raw.startsWith("wss://")) {
    return raw;
  }
  const fullPath = raw.startsWith("/") ? raw : `${getAPIBasePath()}/${raw.replace(/^\/+/, "")}`;
  if (typeof window === "undefined" || !window.location) {
    return fullPath;
  }
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}${fullPath}`;
}

function sendTerminalMessage(ws: WebSocket | null, payload: unknown) {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }
  ws.send(JSON.stringify(payload));
}

function closeRemoteSSHSession(sessionID: string) {
  const trimmed = sessionID.trim();
  if (!trimmed) {
    return;
  }
  void apiPostJson(`/remote-ssh/sessions/${encodeURIComponent(trimmed)}/close`, {}).catch(() => undefined);
}

function canTerminateRemoteSSHSession(session: RemoteSSHSession) {
  return REMOTE_SSH_ATTACHABLE_STATUSES.has((session.status || "").trim());
}

export default function RemoteSSHPage() {
  const { locale, tx } = useI18n();
  const { deviceID: routeDeviceID = "" } = useParams();
  const deviceID = routeDeviceID || "";
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [enablingCenterService, setEnablingCenterService] = useState(false);
  const [copying, setCopying] = useState(false);
  const [webConnecting, setWebConnecting] = useState(false);
  const [webTerminalOpen, setWebTerminalOpen] = useState(false);
  const [webTerminalMessage, setWebTerminalMessage] = useState("");
  const [webTerminalTone, setWebTerminalTone] = useState<"success" | "error">("success");
  const [webTerminalSessionID, setWebTerminalSessionID] = useState("");
  const [terminatingSessionID, setTerminatingSessionID] = useState("");
  const [sessionActionMessage, setSessionActionMessage] = useState("");
  const [sessionActionTone, setSessionActionTone] = useState<"success" | "error">("success");
  const [message, setMessage] = useState("");
  const [messageTone, setMessageTone] = useState<"success" | "error">("success");
  const [view, setView] = useState<RemoteSSHViewResponse | null>(null);
  const [sessionPage, setSessionPage] = useState(1);
  const [policyForm, setPolicyForm] = useState<PolicyForm>(() => policyToForm());
  const [commandForm, setCommandForm] = useState<CommandForm>({
    reason: "maintenance",
    ttlSec: String(DEFAULT_REMOTE_SSH_TTL),
    localAddr: DEFAULT_REMOTE_SSH_LOCAL_ADDR,
    centerURL: defaultCenterURL(),
    centerCABundle: "",
    centerServerName: "",
  });
  const [webTerminalForm, setWebTerminalForm] = useState<WebTerminalForm>({
    reason: "maintenance",
    ttlSec: String(DEFAULT_REMOTE_SSH_TTL),
    scrollbackRows: String(DEFAULT_REMOTE_SSH_TERMINAL_SCROLLBACK),
  });
  const terminalContainerRef = useRef<HTMLDivElement | null>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const webSocketRef = useRef<WebSocket | null>(null);
  const webTerminalSessionIDRef = useRef("");
  const intentionalWebTerminalCloseRef = useRef("");
  const resizeObserverRef = useRef<ResizeObserver | null>(null);

  const policy = view?.policy;
  const device = view?.device;
  const sessions = Array.isArray(view?.sessions) ? view.sessions : [];
  const centerEnabled = view?.center_enabled === true;
  const canStart = Boolean(centerEnabled && device?.device_id && device.status === "approved" && policy?.enabled);
  const command = useMemo(() => remoteSSHCommand(deviceID, commandForm, policy), [commandForm, deviceID, policy]);
  const sessionPageCount = Math.max(1, Math.ceil(sessions.length / REMOTE_SSH_SESSION_PAGE_SIZE));
  const currentSessionPage = Math.min(sessionPage, sessionPageCount);
  const sessionPageStart = sessions.length ? (currentSessionPage - 1) * REMOTE_SSH_SESSION_PAGE_SIZE : 0;
  const sessionPageEnd = Math.min(sessionPageStart + REMOTE_SSH_SESSION_PAGE_SIZE, sessions.length);
  const pagedSessions = sessions.slice(sessionPageStart, sessionPageEnd);

  useEffect(() => {
    setSessionPage((current) => Math.min(Math.max(current, 1), sessionPageCount));
  }, [sessionPageCount]);

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
      setWebTerminalForm((current) => ({
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

  const closeWebTerminal = useCallback((showMessage = true) => {
    const sessionID = webTerminalSessionIDRef.current;
    const ws = webSocketRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      sendTerminalMessage(ws, { type: "close" });
      ws.close(1000, "closed");
    } else if (ws && ws.readyState === WebSocket.CONNECTING) {
      ws.close();
    }
    closeRemoteSSHSession(sessionID);
    webSocketRef.current = null;
    webTerminalSessionIDRef.current = "";
    resizeObserverRef.current?.disconnect();
    resizeObserverRef.current = null;
    terminalRef.current?.dispose();
    terminalRef.current = null;
    fitAddonRef.current = null;
    if (terminalContainerRef.current) {
      terminalContainerRef.current.textContent = "";
    }
    setWebTerminalOpen(false);
    setWebConnecting(false);
    setWebTerminalSessionID("");
    if (showMessage) {
      setWebTerminalTone("success");
      setWebTerminalMessage("Terminal closed.");
    }
  }, []);

  useEffect(() => () => closeWebTerminal(false), [closeWebTerminal]);

  useEffect(() => {
    if (!terminalRef.current) {
      return;
    }
    terminalRef.current.options.scrollback = boundedScrollbackRows(webTerminalForm.scrollbackRows);
  }, [webTerminalForm.scrollbackRows]);

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

  async function openWebTerminal() {
    if (!deviceID || !canStart) {
      return;
    }
    closeWebTerminal(false);
    setWebConnecting(true);
    setWebTerminalMessage("");
    setWebTerminalTone("success");
    try {
      const ttl = boundedTTL(webTerminalForm.ttlSec, policy?.max_ttl_sec || DEFAULT_REMOTE_SSH_TTL, policy?.max_ttl_sec || 86400);
      const data = await apiPostJson<RemoteSSHWebTerminalResponse>(`/devices/${encodeURIComponent(deviceID)}/remote-ssh/web-terminal`, {
        reason: webTerminalForm.reason.trim() || "maintenance",
        ttl_sec: ttl,
        rows: 24,
        cols: 80,
      });
      if (!data.websocket_path || !data.terminal_id) {
        throw new Error(tx("Remote SSH web terminal response is incomplete."));
      }
      if (data.session) {
        webTerminalSessionIDRef.current = data.session.session_id;
        intentionalWebTerminalCloseRef.current = "";
        setView((current) => ({
          ...(current || {}),
          sessions: [data.session as RemoteSSHSession, ...(current?.sessions || [])].slice(0, 50),
        }));
        setSessionPage(1);
        setWebTerminalSessionID(data.session.session_id);
      }
      const container = terminalContainerRef.current;
      if (!container) {
        throw new Error(tx("Remote SSH terminal container is unavailable."));
      }
      container.textContent = "";
      const terminal = new Terminal({
        cursorBlink: true,
        convertEol: true,
        fontFamily: "'SFMono-Regular', Consolas, 'Liberation Mono', monospace",
        fontSize: 12,
        lineHeight: 1.2,
        scrollback: boundedScrollbackRows(webTerminalForm.scrollbackRows),
        theme: {
          background: "#0f172a",
          foreground: "#e5edf7",
          cursor: "#e5edf7",
          selectionBackground: "#334155",
        },
      });
      const fitAddon = new FitAddon();
      terminal.loadAddon(fitAddon);
      terminal.open(container);
      terminalRef.current = terminal;
      fitAddonRef.current = fitAddon;
      setWebTerminalOpen(true);
      requestAnimationFrame(() => fitAddon.fit());

      const ws = new WebSocket(webSocketURL(data.websocket_path), REMOTE_SSH_WEB_TERMINAL_PROTOCOL);
      ws.binaryType = "arraybuffer";
      webSocketRef.current = ws;
      const isCurrentSocket = () => webSocketRef.current === ws;
      const decoder = new TextDecoder();
      let heartbeatTimer = 0;
      const outputQueue: string[] = [];
      let outputWriting = false;
      const pumpOutputQueue = () => {
        if (outputWriting || terminalRef.current !== terminal) {
          return;
        }
        const next = outputQueue.shift();
        if (typeof next === "undefined") {
          return;
        }
        outputWriting = true;
        terminal.write(next, () => {
          outputWriting = false;
          pumpOutputQueue();
        });
      };
      const enqueueOutput = (value: string) => {
        if (!value) {
          return;
        }
        outputQueue.push(value);
        pumpOutputQueue();
      };
      let resizeFrame = 0;
      let lastRows = 0;
      let lastCols = 0;
      const sendResize = (force = false) => {
        fitAddon.fit();
        if (!force && terminal.rows === lastRows && terminal.cols === lastCols) {
          return;
        }
        lastRows = terminal.rows;
        lastCols = terminal.cols;
        sendTerminalMessage(ws, { type: "resize", rows: terminal.rows, cols: terminal.cols });
      };
      const scheduleResize = (force = false) => {
        if (resizeFrame) {
          return;
        }
        resizeFrame = window.requestAnimationFrame(() => {
          resizeFrame = 0;
          if (webSocketRef.current === ws && terminalRef.current === terminal) {
            sendResize(force);
          }
        });
      };
      terminal.onData((input) => {
        sendTerminalMessage(ws, { type: "input", data: input });
      });
      terminal.onResize(({ rows, cols }) => {
        if (rows !== lastRows || cols !== lastCols) {
          lastRows = rows;
          lastCols = cols;
          sendTerminalMessage(ws, { type: "resize", rows, cols });
        }
      });
      if (typeof ResizeObserver !== "undefined") {
        const observer = new ResizeObserver(() => scheduleResize());
        observer.observe(container);
        resizeObserverRef.current = observer;
      }
      ws.onopen = () => {
        setWebConnecting(false);
        setWebTerminalTone("success");
        setWebTerminalMessage(tx("Terminal relay opened. Waiting for Gateway..."));
        heartbeatTimer = window.setInterval(() => {
          sendTerminalMessage(ws, { type: "ping" });
        }, 20000);
        scheduleResize(true);
        terminal.focus();
      };
      ws.onmessage = async (event) => {
        if (typeof event.data === "string") {
          try {
            const msg = JSON.parse(event.data) as { type?: string; message?: string };
            if (msg.type === "error") {
              setWebTerminalTone("error");
              setWebTerminalMessage(msg.message || tx("Terminal connection failed."));
            } else if (msg.type === "status") {
              setWebTerminalTone("success");
              setWebTerminalMessage(msg.message === "connected" ? tx("Terminal connected.") : msg.message || tx("Opening..."));
              if (msg.message === "connected") {
                void load();
              }
            } else if (msg.type === "closed") {
              setWebTerminalTone("success");
              setWebTerminalMessage(msg.message ? `${tx("Terminal closed.")} ${msg.message}` : tx("Terminal closed."));
            }
          } catch {
            enqueueOutput(event.data);
          }
          return;
        }
        if (event.data instanceof ArrayBuffer) {
          enqueueOutput(decoder.decode(event.data, { stream: true }));
          return;
        }
        if (event.data instanceof Blob) {
          enqueueOutput(decoder.decode(await event.data.arrayBuffer(), { stream: true }));
        }
      };
      ws.onerror = () => {
        if (!isCurrentSocket() || intentionalWebTerminalCloseRef.current === webTerminalSessionIDRef.current) {
          return;
        }
        setWebConnecting(false);
        setWebTerminalTone("error");
        setWebTerminalMessage(tx("Terminal connection failed."));
      };
      ws.onclose = () => {
        if (heartbeatTimer) {
          window.clearInterval(heartbeatTimer);
        }
        if (resizeFrame) {
          window.cancelAnimationFrame(resizeFrame);
        }
        if (!isCurrentSocket()) {
          return;
        }
        const sessionID = webTerminalSessionIDRef.current;
        const intentionalClose = intentionalWebTerminalCloseRef.current === sessionID;
        if (!intentionalClose) {
          closeRemoteSSHSession(sessionID);
        }
        intentionalWebTerminalCloseRef.current = "";
        webTerminalSessionIDRef.current = "";
        setWebTerminalSessionID("");
        setWebConnecting(false);
        setWebTerminalOpen(false);
        resizeObserverRef.current?.disconnect();
        resizeObserverRef.current = null;
        void load();
      };
    } catch (err) {
      const fallback = tx("Failed to open Remote SSH web terminal");
      closeWebTerminal(false);
      setWebTerminalTone("error");
      setWebTerminalMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setWebConnecting(false);
    }
  }

  async function terminateSession(session: RemoteSSHSession) {
    const sessionID = (session.session_id || "").trim();
    if (!sessionID || terminatingSessionID) {
      return;
    }
    if (!window.confirm(tx("Terminate this Remote SSH session?"))) {
      return;
    }
    setTerminatingSessionID(sessionID);
    setSessionActionMessage("");
    setSessionActionTone("success");
    try {
      if (sessionID === webTerminalSessionIDRef.current) {
        intentionalWebTerminalCloseRef.current = sessionID;
      }
      const data = await apiPostJson<RemoteSSHSessionActionResponse>(`/remote-ssh/sessions/${encodeURIComponent(sessionID)}/terminate`, {});
      if (data.session) {
        setView((current) => ({
          ...(current || {}),
          sessions: (current?.sessions || []).map((item) => (item.session_id === sessionID ? (data.session as RemoteSSHSession) : item)),
        }));
      }
      setSessionActionTone("success");
      setSessionActionMessage(tx("Remote SSH session terminated."));
      await load();
    } catch (err) {
      if (intentionalWebTerminalCloseRef.current === sessionID) {
        intentionalWebTerminalCloseRef.current = "";
      }
      const fallback = tx("Failed to terminate Remote SSH session");
      setSessionActionTone("error");
      setSessionActionMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setTerminatingSessionID("");
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
                <h3>{tx("Web terminal")}</h3>
                <p className="section-note">{tx("Open an interactive browser terminal through the existing Remote SSH relay.")}</p>
              </div>
            </div>
            {!canStart ? <p className="form-message error">{tx("Remote SSH requires Center service ON, an approved device, and an enabled policy.")}</p> : null}
            <div className="waf-upload-row remote-ssh-terminal-toolbar">
              <label className="remote-ssh-policy-field">
                <span>{tx("Reason")}</span>
                <input
                  value={webTerminalForm.reason}
                  onChange={(event) => setWebTerminalForm((current) => ({ ...current, reason: event.target.value }))}
                  placeholder="maintenance"
                  disabled={webConnecting || webTerminalOpen}
                />
              </label>
              <label className="remote-ssh-policy-field">
                <span>{tx("TTL seconds")}</span>
                <input
                  type="number"
                  min={60}
                  max={policy?.max_ttl_sec || 86400}
                  value={webTerminalForm.ttlSec}
                  onChange={(event) => setWebTerminalForm((current) => ({ ...current, ttlSec: event.target.value }))}
                  disabled={webConnecting || webTerminalOpen}
                />
              </label>
              <label className="remote-ssh-policy-field">
                <span>{tx("Scrollback rows")}</span>
                <input
                  type="number"
                  min={MIN_REMOTE_SSH_TERMINAL_SCROLLBACK}
                  max={MAX_REMOTE_SSH_TERMINAL_SCROLLBACK}
                  step={100}
                  inputMode="numeric"
                  value={webTerminalForm.scrollbackRows}
                  onChange={(event) => setWebTerminalForm((current) => ({ ...current, scrollbackRows: event.target.value }))}
                  onBlur={() =>
                    setWebTerminalForm((current) => ({
                      ...current,
                      scrollbackRows: String(boundedScrollbackRows(current.scrollbackRows)),
                    }))
                  }
                />
              </label>
              <button type="button" onClick={() => void openWebTerminal()} disabled={!canStart || webConnecting || webTerminalOpen}>
                {webConnecting ? tx("Opening...") : tx("Open terminal")}
              </button>
              <button type="button" className="secondary" onClick={() => closeWebTerminal()} disabled={!webConnecting && !webTerminalOpen && !webTerminalSessionID}>
                {tx("Close terminal")}
              </button>
            </div>
            {webTerminalMessage ? (
              <p className={`form-message ${webTerminalTone}`} role={webTerminalTone === "error" ? "alert" : "status"}>
                {tx(webTerminalMessage)}
              </p>
            ) : null}
            <div className={`remote-ssh-terminal-shell${webTerminalOpen || webConnecting ? " is-active" : ""}`} ref={terminalContainerRef} />
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
                    <th>{tx("Mode")}</th>
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
                  {pagedSessions.map((session) => (
                    <tr key={session.session_id}>
                      <td>
                        <div className="remote-ssh-status-cell">
                          <span className={`token-status token-status-${session.status || "unknown"}`}>{tx(session.status || "-")}</span>
                          {canTerminateRemoteSSHSession(session) ? (
                            <button
                              type="button"
                              className="remote-ssh-terminate-button"
                              onClick={() => void terminateSession(session)}
                              disabled={Boolean(terminatingSessionID)}
                              aria-label={tx("Terminate")}
                              title={terminatingSessionID === session.session_id ? tx("Terminating...") : tx("Terminate")}
                            >
                              <span className="visually-hidden">{terminatingSessionID === session.session_id ? tx("Terminating...") : tx("Terminate")}</span>
                            </button>
                          ) : null}
                        </div>
                      </td>
                      <td>{tx(session.operator_mode || "cli")}</td>
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
            {sessionActionMessage ? (
              <p className={`form-message ${sessionActionTone}`} role={sessionActionTone === "error" ? "alert" : "status"}>
                {sessionActionMessage}
              </p>
            ) : null}
            {sessions.length > REMOTE_SSH_SESSION_PAGE_SIZE ? (
              <div className="table-pager remote-ssh-session-pager">
                <span className="section-note">
                  {tx("Showing {start}-{end} of {total}", {
                    start: sessionPageStart + 1,
                    end: sessionPageEnd,
                    total: sessions.length,
                  })}
                </span>
                <div className="inline-actions">
                  <button type="button" onClick={() => setSessionPage((current) => Math.max(1, current - 1))} disabled={currentSessionPage <= 1}>
                    {tx("Previous")}
                  </button>
                  <span className="section-note">
                    {tx("Page {current} of {total}", {
                      current: currentSessionPage,
                      total: sessionPageCount,
                    })}
                  </span>
                  <button
                    type="button"
                    onClick={() => setSessionPage((current) => Math.min(sessionPageCount, current + 1))}
                    disabled={currentSessionPage >= sessionPageCount}
                  >
                    {tx("Next")}
                  </button>
                </div>
              </div>
            ) : null}
          </section>
        </>
      ) : null}
    </div>
  );
}
