import { serializePolicyHostKey } from "./policyHost.js";

export type CacheRuleMatchType = "prefix" | "regex" | "exact";

export type CacheRuleDraft = {
  kind: "ALLOW" | "DENY";
  match: {
    type: CacheRuleMatchType;
    value: string;
  };
  methods: string[];
  ttl: number;
  vary: string[];
};

export type CacheRuleHostScopeDraft = {
  host: string;
  rules: CacheRuleDraft[];
};

export type CacheRulesEditorState = {
  defaultRules: CacheRuleDraft[];
  hosts: CacheRuleHostScopeDraft[];
};

export type CacheRulesFile = {
  default: { rules: CacheRuleDraft[] };
  hosts?: Record<string, { rules: CacheRuleDraft[] }>;
};

const defaultMethods = ["GET", "HEAD"];
const defaultVary = ["Accept-Encoding"];

export function createDefaultCacheRule(seed = 1): CacheRuleDraft {
  return {
    kind: "ALLOW",
    match: { type: "prefix", value: seed === 1 ? "/assets/" : `/path-${seed}/` },
    methods: [...defaultMethods],
    ttl: 600,
    vary: [...defaultVary],
  };
}

export function createEmptyCacheRuleHostScope(seed = 1): CacheRuleHostScopeDraft {
  return {
    host: `example-${seed}.com`,
    rules: [createDefaultCacheRule(seed)],
  };
}

export function createEmptyCacheRulesEditorState(): CacheRulesEditorState {
  return {
    defaultRules: [],
    hosts: [],
  };
}

export function countCacheRules(state: CacheRulesEditorState): number {
  return state.defaultRules.length + state.hosts.reduce((total, scope) => total + scope.rules.length, 0);
}

export function parseCacheRulesEditorDocument(raw: string): CacheRulesEditorState {
  const trimmed = raw.trim();
  if (!trimmed) {
    return createEmptyCacheRulesEditorState();
  }
  if (!trimmed.startsWith("{")) {
    return {
      defaultRules: parseLegacyCacheRules(raw),
      hosts: [],
    };
  }

  const parsed = JSON.parse(trimmed) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("cache rules config must be a JSON object");
  }
  const hasLegacyRules = Array.isArray(parsed.rules);
  const hasCanonical = isRecord(parsed.default) || isRecord(parsed.hosts);
  if (hasLegacyRules && hasCanonical) {
    throw new Error("cache rules JSON must use either legacy rules or canonical default/hosts, not both");
  }

  const defaultRules = readRuleDrafts(hasLegacyRules ? parsed.rules : isRecord(parsed.default) ? parsed.default.rules : undefined);
  const hosts = readHostScopes(parsed.hosts);
  return {
    defaultRules,
    hosts,
  };
}

export function serializeCacheRulesEditor(state: CacheRulesEditorState): string {
  const out: CacheRulesFile = {
    default: {
      rules: writeRuleDrafts(state.defaultRules),
    },
  };
  const hosts = state.hosts
    .map((scope) => ({
      host: serializePolicyHostKey(scope.host),
      rules: writeRuleDrafts(scope.rules),
    }))
    .filter((scope) => scope.host);
  if (hosts.length > 0) {
    out.hosts = {};
    hosts
      .sort((a, b) => a.host.localeCompare(b.host))
      .forEach((scope) => {
        if (out.hosts && !(scope.host in out.hosts)) {
          out.hosts[scope.host] = { rules: scope.rules };
        }
      });
  }
  return `${JSON.stringify(out, null, 2)}\n`;
}

export function toCacheRulesFile(state: CacheRulesEditorState): CacheRulesFile {
  return JSON.parse(serializeCacheRulesEditor(state)) as CacheRulesFile;
}

function parseLegacyCacheRules(raw: string): CacheRuleDraft[] {
  const out: CacheRuleDraft[] = [];
  for (const rawLine of raw.split(/\r?\n/)) {
    let line = rawLine;
    const commentIndex = line.indexOf("#");
    if (commentIndex >= 0) {
      line = line.slice(0, commentIndex);
    }
    line = line.trim();
    if (!line) {
      continue;
    }
    const fields = line.split(/\s+/);
    if (fields.length < 2) {
      continue;
    }
    const draft = createDefaultCacheRule(out.length + 1);
    draft.kind = normalizeKind(fields[0]);
    draft.ttl = 600;
    draft.vary = [];
    for (const opt of fields.slice(1)) {
      const kv = opt.split("=", 2);
      if (kv.length !== 2) {
        continue;
      }
      const key = kv[0]?.trim().toLowerCase();
      const value = kv[1]?.trim() ?? "";
      switch (key) {
        case "prefix":
          draft.match = { type: "prefix", value };
          break;
        case "regex":
          draft.match = { type: "regex", value };
          break;
        case "exact":
          draft.match = { type: "exact", value };
          break;
        case "methods":
          draft.methods = splitCSV(value).map((method) => method.toUpperCase());
          break;
        case "ttl":
          draft.ttl = Number.parseInt(value || "0", 10) || 0;
          break;
        case "vary":
          draft.vary = splitCSV(value);
          break;
        default:
          break;
      }
    }
    draft.methods = normalizeMethods(draft.methods);
    draft.vary = normalizeVary(draft.vary);
    out.push(draft);
  }
  return out;
}

function readHostScopes(value: unknown): CacheRuleHostScopeDraft[] {
  if (!isRecord(value)) {
    return [];
  }
  return Object.entries(value)
    .map(([host, scope], index) => ({
      host: serializePolicyHostKey(host) || `example-${index + 1}.com`,
      rules: readRuleDrafts(isRecord(scope) ? scope.rules : undefined),
    }))
    .sort((a, b) => a.host.localeCompare(b.host));
}

function readRuleDrafts(value: unknown): CacheRuleDraft[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((entry, index) => readRuleDraft(entry, index));
}

function readRuleDraft(value: unknown, index: number): CacheRuleDraft {
  const fallback = createDefaultCacheRule(index + 1);
  if (!isRecord(value)) {
    return fallback;
  }
  const match = isRecord(value.match) ? value.match : {};
  const matchType = normalizeMatchType(readString(match.type, fallback.match.type));
  return {
    kind: normalizeKind(readString(value.kind, fallback.kind)),
    match: {
      type: matchType,
      value: readString(match.value, fallback.match.value),
    },
    methods: normalizeMethods(readStringArray(value.methods, fallback.methods)),
    ttl: normalizeTTL(readNumber(value.ttl, fallback.ttl)),
    vary: normalizeVary(readStringArray(value.vary, fallback.vary)),
  };
}

function writeRuleDrafts(rules: CacheRuleDraft[]): CacheRuleDraft[] {
  return rules
    .map((rule) => {
      const value = rule.match.value.trim();
      if (!value) {
        return null;
      }
      return {
        kind: normalizeKind(rule.kind),
        match: {
          type: normalizeMatchType(rule.match.type),
          value,
        },
        methods: normalizeMethods(rule.methods),
        ttl: normalizeTTL(rule.ttl),
        vary: normalizeVary(rule.vary),
      };
    })
    .filter((rule): rule is CacheRuleDraft => rule !== null);
}

function normalizeKind(raw: string): "ALLOW" | "DENY" {
  return raw.trim().toUpperCase() === "DENY" ? "DENY" : "ALLOW";
}

function normalizeMatchType(raw: string): CacheRuleMatchType {
  switch (raw.trim().toLowerCase()) {
    case "regex":
      return "regex";
    case "exact":
      return "exact";
    default:
      return "prefix";
  }
}

function normalizeMethods(methods: string[]): string[] {
  const normalized = methods
    .map((method) => method.trim().toUpperCase())
    .filter((method) => method === "GET" || method === "HEAD");
  return normalized.length > 0 ? Array.from(new Set(normalized)) : [...defaultMethods];
}

function normalizeVary(vary: string[]): string[] {
  return vary
    .map((value) => value.trim())
    .filter(Boolean)
    .filter((value, index, items) => items.indexOf(value) === index);
}

function normalizeTTL(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.trunc(value));
}

function splitCSV(raw: string): string[] {
  return raw
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function readString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function readStringArray(value: unknown, fallback: string[] = []): string[] {
  if (!Array.isArray(value)) {
    return [...fallback];
  }
  return value.filter((entry): entry is string => typeof entry === "string");
}

function readNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
