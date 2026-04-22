import { serializePolicyHostKey } from "./policyHost.js";

export const RATE_LIMIT_KEY_BY_OPTIONS = [
  "ip",
  "country",
  "ip_country",
  "session",
  "ip_session",
  "jwt_sub",
  "ip_jwt_sub",
] as const;

export type RateLimitKeyBy = (typeof RATE_LIMIT_KEY_BY_OPTIONS)[number];

export type RateLimitActionDraft = {
  status: number;
  retryAfterSeconds: number;
};

export type RateLimitPolicyDraft = {
  enabled: boolean;
  limit: number;
  windowSeconds: number;
  burst: number;
  keyBy: RateLimitKeyBy;
  action: RateLimitActionDraft;
};

export type RateLimitRuleDraft = {
  name: string;
  matchType: "exact" | "prefix" | "regex";
  matchValue: string;
  methods: string[];
  policy: RateLimitPolicyDraft;
};

export type RateLimitFeedbackDraft = {
  enabled: boolean;
  strikesRequired: number;
  strikeWindowSeconds: number;
  adaptiveOnly: boolean;
  dryRun: boolean;
};

export type RateLimitScopeDraft = {
  enabled: boolean;
  allowlistIPs: string[];
  allowlistCountries: string[];
  sessionCookieNames: string[];
  jwtHeaderNames: string[];
  jwtCookieNames: string[];
  adaptiveEnabled: boolean;
  adaptiveScoreThreshold: number;
  adaptiveLimitFactorPercent: number;
  adaptiveBurstFactorPercent: number;
  feedback: RateLimitFeedbackDraft;
  defaultPolicy: RateLimitPolicyDraft;
  rules: RateLimitRuleDraft[];
};

export type RateLimitHostScopeDraft = RateLimitScopeDraft & {
  host: string;
};

export type RateLimitEditorState = RateLimitScopeDraft & {
  hosts: RateLimitHostScopeDraft[];
};

type JSONRecord = Record<string, unknown>;

export type ParsedRateLimitEditor = {
  base: JSONRecord;
  defaultBase: JSONRecord;
  defaultRuleBases: JSONRecord[];
  hostBases: JSONRecord[];
  hostRuleBases: JSONRecord[][];
  state: RateLimitEditorState;
};

const DEFAULT_SESSION_COOKIE_NAMES = ["session", "sid", "connect.sid", "_session"];
const DEFAULT_JWT_HEADER_NAMES = ["Authorization", "X-Auth-Token"];
const DEFAULT_JWT_COOKIE_NAMES = ["token", "access_token", "jwt"];

export function createDefaultRateLimitPolicy(): RateLimitPolicyDraft {
  return {
    enabled: true,
    limit: 120,
    windowSeconds: 60,
    burst: 20,
    keyBy: "ip",
    action: {
      status: 429,
      retryAfterSeconds: 60,
    },
  };
}

export function createEmptyRateLimitRule(seed = 1): RateLimitRuleDraft {
  return {
    name: `rule-${seed}`,
    matchType: "prefix",
    matchValue: "/",
    methods: [],
    policy: createDefaultRateLimitPolicy(),
  };
}

export function createDefaultRateLimitScopeDraft(): RateLimitScopeDraft {
  return {
    enabled: true,
    allowlistIPs: [],
    allowlistCountries: [],
    sessionCookieNames: [...DEFAULT_SESSION_COOKIE_NAMES],
    jwtHeaderNames: [...DEFAULT_JWT_HEADER_NAMES],
    jwtCookieNames: [...DEFAULT_JWT_COOKIE_NAMES],
    adaptiveEnabled: false,
    adaptiveScoreThreshold: 6,
    adaptiveLimitFactorPercent: 50,
    adaptiveBurstFactorPercent: 50,
    feedback: {
      enabled: false,
      strikesRequired: 3,
      strikeWindowSeconds: 300,
      adaptiveOnly: true,
      dryRun: false,
    },
    defaultPolicy: createDefaultRateLimitPolicy(),
    rules: [],
  };
}

export function createEmptyRateLimitHostScope(seed = 1): RateLimitHostScopeDraft {
  return {
    host: `example-${seed}.com`,
    ...createDefaultRateLimitScopeDraft(),
  };
}

export function createDefaultRateLimitEditorState(): RateLimitEditorState {
  return {
    ...createDefaultRateLimitScopeDraft(),
    hosts: [],
  };
}

export function parseRateLimitEditorDocument(raw: string): ParsedRateLimitEditor {
  const trimmed = raw.trim();
  const defaults = createDefaultRateLimitScopeDraft();
  if (!trimmed) {
    return {
      base: {},
      defaultBase: {},
      defaultRuleBases: [],
      hostBases: [],
      hostRuleBases: [],
      state: createDefaultRateLimitEditorState(),
    };
  }

  const parsed = JSON.parse(trimmed) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("rate limit config must be a JSON object");
  }

  if (!("default" in parsed) && !("hosts" in parsed)) {
    const legacyBase = deepCloneRecord(parsed);
    const legacyScope = readScopeDraft(legacyBase, defaults);
    return {
      base: {},
      defaultBase: legacyBase,
      defaultRuleBases: legacyScope.ruleBases,
      hostBases: [],
      hostRuleBases: [],
      state: {
        ...legacyScope.scope,
        hosts: [],
      },
    };
  }

  const base = deepCloneRecord(parsed);
  const defaultBase = isRecord(base.default) ? deepCloneRecord(base.default) : {};
  const defaultScope = readScopeDraft(defaultBase, defaults);
  const hostScopes = readHostScopes(base.hosts, defaultBase, defaults);
  return {
    base,
    defaultBase,
    defaultRuleBases: defaultScope.ruleBases,
    hostBases: hostScopes.hostBases,
    hostRuleBases: hostScopes.hostRuleBases,
    state: {
      ...defaultScope.scope,
      hosts: hostScopes.hosts,
    },
  };
}

export function parseRateLimitEditor(raw: string): RateLimitEditorState {
  return parseRateLimitEditorDocument(raw).state;
}

export function serializeRateLimitEditor(state: RateLimitEditorState): string;
export function serializeRateLimitEditor(
  base: JSONRecord,
  state: RateLimitEditorState,
  defaultBase?: JSONRecord,
  defaultRuleBases?: JSONRecord[],
  hostBases?: JSONRecord[],
  hostRuleBases?: JSONRecord[][],
): string;
export function serializeRateLimitEditor(
  baseOrState: JSONRecord | RateLimitEditorState,
  maybeState?: RateLimitEditorState,
  maybeDefaultBase?: JSONRecord,
  maybeDefaultRuleBases?: JSONRecord[],
  maybeHostBases?: JSONRecord[],
  maybeHostRuleBases?: JSONRecord[][],
): string {
  const state = maybeState ?? (baseOrState as RateLimitEditorState);
  const next = maybeState ? deepCloneRecord(baseOrState as JSONRecord) : {};
  deleteLegacyRateLimitRootKeys(next);

  next.default = writeScopeDraft(
    maybeDefaultBase ?? (isRecord(next.default) ? next.default : null),
    state,
    maybeDefaultRuleBases,
  );

  const nextHosts = state.hosts
    .map((scope, index) => ({
      index,
      host: serializePolicyHostKey(scope.host),
      scope,
    }))
    .filter((scope) => scope.host)
    .sort((a, b) => a.host.localeCompare(b.host));

  if (nextHosts.length > 0) {
    const outHosts: Record<string, JSONRecord> = {};
    for (const scope of nextHosts) {
      if (scope.host in outHosts) {
        throw new Error(`duplicate host scope: ${scope.host}`);
      }
      outHosts[scope.host] = writeScopeDraft(
        maybeHostBases?.[scope.index] ?? null,
        scope.scope,
        maybeHostRuleBases?.[scope.index],
      );
    }
    next.hosts = outHosts;
  } else {
    delete next.hosts;
  }

  return `${JSON.stringify(next, null, 2)}\n`;
}

function readHostScopes(
  value: unknown,
  defaultBase: JSONRecord,
  defaults: RateLimitScopeDraft,
): { hostBases: JSONRecord[]; hostRuleBases: JSONRecord[][]; hosts: RateLimitHostScopeDraft[] } {
  if (!isRecord(value)) {
    return {
      hostBases: [],
      hostRuleBases: [],
      hosts: [],
    };
  }

  const entries = Object.entries(value)
    .map(([host, scope]) => {
      const normalizedHost = serializePolicyHostKey(host);
      const rawScope = isRecord(scope) ? deepCloneRecord(scope) : {};
      const mergedScope = mergeJSONRecords(defaultBase, rawScope);
      const parsed = readScopeDraft(mergedScope, defaults);
      return {
        host: normalizedHost,
        base: mergedScope,
        ruleBases: parsed.ruleBases,
        scope: {
          host: normalizedHost,
          ...parsed.scope,
        },
      };
    })
    .filter((scope) => scope.host)
    .sort((a, b) => a.host.localeCompare(b.host));

  return {
    hostBases: entries.map((entry) => entry.base),
    hostRuleBases: entries.map((entry) => entry.ruleBases),
    hosts: entries.map((entry) => entry.scope),
  };
}

function readScopeDraft(value: JSONRecord | null, defaults: RateLimitScopeDraft): { scope: RateLimitScopeDraft; ruleBases: JSONRecord[] } {
  const base = value ?? {};
  const rules = readRuleDrafts(base.rules);
  return {
    ruleBases: rules.ruleBases,
    scope: {
      enabled: readBoolean(base.enabled, defaults.enabled),
      allowlistIPs: readList(base.allowlist_ips),
      allowlistCountries: normalizeCountryCodes(readList(base.allowlist_countries)),
      sessionCookieNames: normalizeNames(readList(base.session_cookie_names), DEFAULT_SESSION_COOKIE_NAMES),
      jwtHeaderNames: normalizeNames(readList(base.jwt_header_names), DEFAULT_JWT_HEADER_NAMES),
      jwtCookieNames: normalizeNames(readList(base.jwt_cookie_names), DEFAULT_JWT_COOKIE_NAMES),
      adaptiveEnabled: readBoolean(base.adaptive_enabled, defaults.adaptiveEnabled),
      adaptiveScoreThreshold: readPositiveInt(base.adaptive_score_threshold, defaults.adaptiveScoreThreshold),
      adaptiveLimitFactorPercent: readPositiveInt(base.adaptive_limit_factor_percent, defaults.adaptiveLimitFactorPercent),
      adaptiveBurstFactorPercent: readPositiveInt(base.adaptive_burst_factor_percent, defaults.adaptiveBurstFactorPercent),
      feedback: readFeedbackDraft(base.feedback, defaults.feedback),
      defaultPolicy: readPolicyDraft(base.default_policy, defaults.defaultPolicy),
      rules: rules.rules,
    },
  };
}

function writeScopeDraft(base: JSONRecord | null, scope: RateLimitScopeDraft, ruleBases?: JSONRecord[]): JSONRecord {
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = scope.enabled;
  out.allowlist_ips = normalizeNames(scope.allowlistIPs);
  out.allowlist_countries = normalizeCountryCodes(scope.allowlistCountries);
  out.session_cookie_names = normalizeNames(scope.sessionCookieNames);
  out.jwt_header_names = normalizeNames(scope.jwtHeaderNames);
  out.jwt_cookie_names = normalizeNames(scope.jwtCookieNames);
  out.adaptive_enabled = scope.adaptiveEnabled;
  out.adaptive_score_threshold = readPositiveInt(scope.adaptiveScoreThreshold, 6);
  out.adaptive_limit_factor_percent = readPositiveInt(scope.adaptiveLimitFactorPercent, 50);
  out.adaptive_burst_factor_percent = readPositiveInt(scope.adaptiveBurstFactorPercent, 50);
  out.feedback = writeFeedbackDraftWithBase(isRecord(out.feedback) ? out.feedback : null, scope.feedback);
  out.default_policy = writePolicyDraftWithBase(isRecord(out.default_policy) ? out.default_policy : null, scope.defaultPolicy);
  out.rules = scope.rules.map((rule, index) => writeRuleDraft(ruleBases?.[index] ?? null, rule));
  return out;
}

function writePolicyDraftWithBase(base: JSONRecord | null, policy: RateLimitPolicyDraft): JSONRecord {
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = policy.enabled;
  out.limit = readNonNegativeInt(policy.limit, 0);
  out.window_seconds = readNonNegativeInt(policy.windowSeconds, 0);
  out.burst = readNonNegativeInt(policy.burst, 0);
  out.key_by = readKeyBy(policy.keyBy, "ip");
  const action = isRecord(out.action) ? deepCloneRecord(out.action) : {};
  action.status = readPositiveInt(policy.action.status, 429);
  action.retry_after_seconds = readNonNegativeInt(policy.action.retryAfterSeconds, 0);
  out.action = action;
  return out;
}

function writeFeedbackDraftWithBase(base: JSONRecord | null, feedback: RateLimitFeedbackDraft): JSONRecord {
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = feedback.enabled;
  out.strikes_required = readPositiveInt(feedback.strikesRequired, 3);
  out.strike_window_seconds = readPositiveInt(feedback.strikeWindowSeconds, 300);
  out.adaptive_only = feedback.adaptiveOnly;
  out.dry_run = feedback.dryRun;
  return out;
}

function writeRuleDraft(base: JSONRecord | null, rule: RateLimitRuleDraft): JSONRecord {
  const out = base ? deepCloneRecord(base) : {};
  out.name = rule.name.trim();
  out.match_type = rule.matchType;
  out.match_value = rule.matchValue.trim();
  out.methods = normalizeMethods(rule.methods);
  out.policy = writePolicyDraftWithBase(isRecord(out.policy) ? out.policy : null, rule.policy);
  return out;
}

function readFeedbackDraft(value: unknown, fallback: RateLimitFeedbackDraft): RateLimitFeedbackDraft {
  if (!isRecord(value)) {
    return { ...fallback };
  }
  const enabled = readBoolean(value.enabled, fallback.enabled);
  return {
    enabled,
    strikesRequired: readPositiveInt(value.strikes_required, enabled ? fallback.strikesRequired : 0),
    strikeWindowSeconds: readPositiveInt(value.strike_window_seconds, enabled ? fallback.strikeWindowSeconds : 0),
    adaptiveOnly: readBoolean(value.adaptive_only, fallback.adaptiveOnly),
    dryRun: readBoolean(value.dry_run, fallback.dryRun),
  };
}

function readPolicyDraft(value: unknown, fallback: RateLimitPolicyDraft): RateLimitPolicyDraft {
  if (!isRecord(value)) {
    return { ...fallback, action: { ...fallback.action } };
  }
  return {
    enabled: readBoolean(value.enabled, fallback.enabled),
    limit: readNonNegativeInt(value.limit, fallback.limit),
    windowSeconds: readNonNegativeInt(value.window_seconds, fallback.windowSeconds),
    burst: readNonNegativeInt(value.burst, fallback.burst),
    keyBy: readKeyBy(value.key_by, fallback.keyBy),
    action: {
      status: readPositiveInt(readNested(value.action, "status"), fallback.action.status),
      retryAfterSeconds: readNonNegativeInt(readNested(value.action, "retry_after_seconds"), fallback.action.retryAfterSeconds),
    },
  };
}

function readRuleDrafts(value: unknown): { ruleBases: JSONRecord[]; rules: RateLimitRuleDraft[] } {
  if (!Array.isArray(value)) {
    return {
      ruleBases: [],
      rules: [],
    };
  }
  const out = value.map((entry, index) => {
    const fallback = createEmptyRateLimitRule(index + 1);
    if (!isRecord(entry)) {
      return {
        base: {},
        rule: fallback,
      };
    }
    return {
      base: deepCloneRecord(entry),
      rule: {
        name: readString(entry.name, fallback.name),
        matchType: readMatchType(entry.match_type, fallback.matchType),
        matchValue: readString(entry.match_value, fallback.matchValue),
        methods: normalizeMethods(readList(entry.methods)),
        policy: readPolicyDraft(entry.policy, fallback.policy),
      },
    };
  });
  return {
    ruleBases: out.map((entry) => entry.base),
    rules: out.map((entry) => entry.rule),
  };
}

function deleteLegacyRateLimitRootKeys(value: JSONRecord) {
  delete value.enabled;
  delete value.allowlist_ips;
  delete value.allowlist_countries;
  delete value.session_cookie_names;
  delete value.jwt_header_names;
  delete value.jwt_cookie_names;
  delete value.adaptive_enabled;
  delete value.adaptive_score_threshold;
  delete value.adaptive_limit_factor_percent;
  delete value.adaptive_burst_factor_percent;
  delete value.feedback;
  delete value.default_policy;
  delete value.rules;
}

function mergeJSONRecords(base: JSONRecord, override: JSONRecord): JSONRecord {
  const out = deepCloneRecord(base);
  for (const [key, value] of Object.entries(override)) {
    const current = out[key];
    if (isRecord(current) && isRecord(value)) {
      out[key] = mergeJSONRecords(current, value);
      continue;
    }
    out[key] = deepCloneValue(value);
  }
  return out;
}

function deepCloneValue<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function readNested(value: unknown, key: string): unknown {
  return isRecord(value) ? value[key] : undefined;
}

function readList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
    .filter(Boolean);
}

function normalizeNames(values: string[], fallback: string[] = []): string[] {
  const out = dedupeTrimmed(values);
  return out.length > 0 ? out : [...fallback];
}

function normalizeMethods(values: string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim().toUpperCase()).filter(Boolean))).sort((a, b) => a.localeCompare(b));
}

function normalizeCountryCodes(values: string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim().toUpperCase()).filter(Boolean))).sort((a, b) => a.localeCompare(b));
}

function dedupeTrimmed(values: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = value.trim();
    if (!normalized) {
      continue;
    }
    const key = normalized.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(normalized);
  }
  return out;
}

function readBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function readString(value: unknown, fallback: string): string {
  return typeof value === "string" ? value.trim() : fallback;
}

function readPositiveInt(value: unknown, fallback: number): number {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number.parseInt(value, 10) : Number.NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function readNonNegativeInt(value: unknown, fallback: number): number {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number.parseInt(value, 10) : Number.NaN;
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function readKeyBy(value: unknown, fallback: RateLimitKeyBy): RateLimitKeyBy {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return RATE_LIMIT_KEY_BY_OPTIONS.includes(normalized as RateLimitKeyBy) ? (normalized as RateLimitKeyBy) : fallback;
}

function readMatchType(value: unknown, fallback: RateLimitRuleDraft["matchType"]): RateLimitRuleDraft["matchType"] {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return normalized === "exact" || normalized === "prefix" || normalized === "regex" ? normalized : fallback;
}

function isRecord(value: unknown): value is JSONRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepCloneRecord(value: JSONRecord): JSONRecord {
  return JSON.parse(JSON.stringify(value)) as JSONRecord;
}
