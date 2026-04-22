export type NotificationSinkType = "webhook" | "email";

export type NotificationHeaderDraft = {
  key: string;
  value: string;
};

export type NotificationTriggerDraft = {
  enabled: boolean;
  windowSeconds: number;
  activeThreshold: number;
  escalatedThreshold: number;
};

export type NotificationSecurityTriggerDraft = NotificationTriggerDraft & {
  sources: string[];
};

export type NotificationSinkDraft = {
  name: string;
  type: NotificationSinkType;
  enabled: boolean;
  timeoutSeconds: number;
  webhookURL: string;
  headers: NotificationHeaderDraft[];
  smtpAddress: string;
  smtpUsername: string;
  smtpPassword: string;
  from: string;
  to: string[];
  subjectPrefix: string;
};

export type NotificationEditorState = {
  enabled: boolean;
  cooldownSeconds: number;
  upstream: NotificationTriggerDraft;
  security: NotificationSecurityTriggerDraft;
  sinks: NotificationSinkDraft[];
};

type JSONRecord = Record<string, unknown>;

export type ParsedNotificationEditor = {
  base: JSONRecord;
  sinkBases: JSONRecord[];
  state: NotificationEditorState;
};

export const DEFAULT_NOTIFICATION_SECURITY_SOURCES = [
  "waf_block",
  "rate_limited",
  "semantic_anomaly",
  "bot_challenge",
  "ip_reputation",
];

export function createDefaultNotificationTrigger(): NotificationTriggerDraft {
  return {
    enabled: false,
    windowSeconds: 60,
    activeThreshold: 3,
    escalatedThreshold: 10,
  };
}

export function createDefaultNotificationSecurityTrigger(): NotificationSecurityTriggerDraft {
  return {
    enabled: false,
    windowSeconds: 300,
    activeThreshold: 20,
    escalatedThreshold: 100,
    sources: [...DEFAULT_NOTIFICATION_SECURITY_SOURCES],
  };
}

export function createDefaultNotificationEditorState(): NotificationEditorState {
  return {
    enabled: false,
    cooldownSeconds: 900,
    upstream: createDefaultNotificationTrigger(),
    security: createDefaultNotificationSecurityTrigger(),
    sinks: [],
  };
}

export function createWebhookNotificationSink(seed = 1): NotificationSinkDraft {
  return {
    name: seed === 1 ? "primary-webhook" : `webhook-${seed}`,
    type: "webhook",
    enabled: false,
    timeoutSeconds: 5,
    webhookURL: "https://hooks.example.invalid/tukuyomi",
    headers: [],
    smtpAddress: "",
    smtpUsername: "",
    smtpPassword: "",
    from: "",
    to: [],
    subjectPrefix: "[tukuyomi]",
  };
}

export function createEmailNotificationSink(seed = 1): NotificationSinkDraft {
  return {
    name: seed === 1 ? "ops-email" : `email-${seed}`,
    type: "email",
    enabled: false,
    timeoutSeconds: 5,
    webhookURL: "",
    headers: [],
    smtpAddress: "smtp.example.invalid:587",
    smtpUsername: "alerts@example.invalid",
    smtpPassword: "",
    from: "alerts@example.invalid",
    to: ["secops@example.invalid"],
    subjectPrefix: "[tukuyomi]",
  };
}

export function parseNotificationEditorDocument(raw: string): ParsedNotificationEditor {
  const trimmed = raw.trim();
  if (!trimmed) {
    return {
      base: {},
      sinkBases: [],
      state: createDefaultNotificationEditorState(),
    };
  }

  const parsed = JSON.parse(trimmed) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("notification config must be a JSON object");
  }

  const base = deepCloneRecord(parsed);
  const sinkDrafts = readSinks(base.sinks);
  return {
    base,
    sinkBases: sinkDrafts.sinkBases,
    state: {
      enabled: readBoolean(base.enabled, false),
      cooldownSeconds: readFiniteInt(base.cooldown_seconds, 900),
      upstream: readTrigger(base.upstream, createDefaultNotificationTrigger()),
      security: readSecurityTrigger(base.security, createDefaultNotificationSecurityTrigger()),
      sinks: sinkDrafts.sinks,
    },
  };
}

export function parseNotificationEditor(raw: string): NotificationEditorState {
  return parseNotificationEditorDocument(raw).state;
}

export function serializeNotificationEditor(state: NotificationEditorState): string;
export function serializeNotificationEditor(base: JSONRecord, state: NotificationEditorState, sinkBases?: JSONRecord[]): string;
export function serializeNotificationEditor(
  baseOrState: JSONRecord | NotificationEditorState,
  maybeState?: NotificationEditorState,
  maybeSinkBases?: JSONRecord[],
): string {
  const state = maybeState ?? (baseOrState as NotificationEditorState);
  const next = maybeState ? deepCloneRecord(baseOrState as JSONRecord) : {};

  next.enabled = state.enabled;
  next.cooldown_seconds = writeFiniteInt(state.cooldownSeconds, 900);
  next.sinks = state.sinks.map((sink, index) => writeSink(maybeSinkBases?.[index] ?? null, sink));
  next.upstream = writeTrigger(isRecord(next.upstream) ? next.upstream : null, state.upstream);
  next.security = writeSecurityTrigger(isRecord(next.security) ? next.security : null, state.security);

  return `${JSON.stringify(next, null, 2)}\n`;
}

export function countEnabledNotificationSinkDrafts(state: NotificationEditorState): number {
  return state.sinks.filter((sink) => sink.enabled).length;
}

function readTrigger(value: unknown, defaults: NotificationTriggerDraft): NotificationTriggerDraft {
  const base = isRecord(value) ? value : {};
  return {
    enabled: readBoolean(base.enabled, defaults.enabled),
    windowSeconds: readFiniteInt(base.window_seconds, defaults.windowSeconds),
    activeThreshold: readFiniteInt(base.active_threshold, defaults.activeThreshold),
    escalatedThreshold: readFiniteInt(base.escalated_threshold, defaults.escalatedThreshold),
  };
}

function readSecurityTrigger(value: unknown, defaults: NotificationSecurityTriggerDraft): NotificationSecurityTriggerDraft {
  const base = isRecord(value) ? value : {};
  return {
    ...readTrigger(base, defaults),
    sources: normalizeSourceList(readStringList(base.sources), defaults.sources),
  };
}

function readSinks(value: unknown): { sinkBases: JSONRecord[]; sinks: NotificationSinkDraft[] } {
  if (!Array.isArray(value)) {
    return {
      sinkBases: [],
      sinks: [],
    };
  }

  const entries = value.map((entry, index) => {
    const fallback = createWebhookNotificationSink(index + 1);
    if (!isRecord(entry)) {
      return {
        base: {},
        sink: fallback,
      };
    }
    const type = readSinkType(entry.type, entry);
    return {
      base: deepCloneRecord(entry),
      sink: {
        name: readString(entry.name, fallback.name).trim(),
        type,
        enabled: readBoolean(entry.enabled, false),
        timeoutSeconds: readFiniteInt(entry.timeout_seconds, 5),
        webhookURL: readString(entry.webhook_url, "").trim(),
        headers: readHeaders(entry.headers),
        smtpAddress: readString(entry.smtp_address, "").trim(),
        smtpUsername: readString(entry.smtp_username, "").trim(),
        smtpPassword: readString(entry.smtp_password, ""),
        from: readString(entry.from, "").trim(),
        to: readStringList(entry.to),
        subjectPrefix: readString(entry.subject_prefix, "[tukuyomi]").trim() || "[tukuyomi]",
      },
    };
  });

  return {
    sinkBases: entries.map((entry) => entry.base),
    sinks: entries.map((entry) => entry.sink),
  };
}

function readSinkType(value: unknown, entry: JSONRecord): NotificationSinkType {
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "email") {
      return "email";
    }
    if (normalized === "webhook") {
      return "webhook";
    }
  }
  if (typeof entry.smtp_address === "string" || typeof entry.from === "string" || Array.isArray(entry.to)) {
    return "email";
  }
  return "webhook";
}

function readHeaders(value: unknown): NotificationHeaderDraft[] {
  if (!isRecord(value)) {
    return [];
  }
  return Object.entries(value)
    .map(([key, item]) => ({
      key: key.trim(),
      value: typeof item === "string" ? item.trim() : "",
    }))
    .filter((entry) => entry.key);
}

function writeTrigger(base: JSONRecord | null, trigger: NotificationTriggerDraft): JSONRecord {
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = trigger.enabled;
  out.window_seconds = writeFiniteInt(trigger.windowSeconds, 60);
  out.active_threshold = writeFiniteInt(trigger.activeThreshold, 1);
  out.escalated_threshold = writeFiniteInt(trigger.escalatedThreshold, out.active_threshold);
  return out;
}

function writeSecurityTrigger(base: JSONRecord | null, trigger: NotificationSecurityTriggerDraft): JSONRecord {
  const out = writeTrigger(base, trigger);
  out.sources = normalizeSourceList(trigger.sources, DEFAULT_NOTIFICATION_SECURITY_SOURCES);
  return out;
}

function writeSink(base: JSONRecord | null, sink: NotificationSinkDraft): JSONRecord {
  const out = base ? deepCloneRecord(base) : {};
  out.name = sink.name.trim();
  out.type = sink.type;
  out.enabled = sink.enabled;

  if (sink.type === "webhook") {
    out.webhook_url = sink.webhookURL.trim();
    out.timeout_seconds = writeFiniteInt(sink.timeoutSeconds, 5);
    const headers = writeHeaders(sink.headers);
    if (Object.keys(headers).length > 0) {
      out.headers = headers;
    } else {
      delete out.headers;
    }
    delete out.smtp_address;
    delete out.smtp_username;
    delete out.smtp_password;
    delete out.from;
    delete out.to;
    delete out.subject_prefix;
  } else {
    out.smtp_address = sink.smtpAddress.trim();
    out.smtp_username = sink.smtpUsername.trim();
    out.smtp_password = sink.smtpPassword.trim();
    out.from = sink.from.trim();
    out.to = normalizeStringList(sink.to);
    out.subject_prefix = sink.subjectPrefix.trim() || "[tukuyomi]";
    delete out.webhook_url;
    delete out.timeout_seconds;
    delete out.headers;
  }

  return out;
}

function writeHeaders(headers: NotificationHeaderDraft[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const header of headers) {
    const key = header.key.trim();
    if (!key) {
      continue;
    }
    out[key] = header.value.trim();
  }
  return out;
}

function normalizeSourceList(values: string[], fallback: string[]): string[] {
  const normalized = normalizeStringList(values.map((value) => value.toLowerCase()));
  return normalized.length > 0 ? normalized : [...fallback];
}

function normalizeStringList(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) {
      continue;
    }
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

function readStringList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => (typeof item === "string" ? item.trim() : "")).filter(Boolean);
}

function readBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function readString(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

function readFiniteInt(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.trunc(value) : fallback;
}

function writeFiniteInt(value: number, fallback: number | unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.trunc(value) : Number(fallback) || 0;
}

function isRecord(value: unknown): value is JSONRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepCloneRecord(value: JSONRecord): JSONRecord {
  return JSON.parse(JSON.stringify(value)) as JSONRecord;
}
