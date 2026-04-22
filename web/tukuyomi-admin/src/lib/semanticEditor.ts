import { serializePolicyHostKey } from "./policyHost.js";

export const SEMANTIC_MODE_OPTIONS = ["off", "log_only", "challenge", "block"] as const;

export type SemanticMode = (typeof SEMANTIC_MODE_OPTIONS)[number];

export type SemanticScopeState = {
  enabled: boolean;
  mode: SemanticMode;
  providerEnabled: boolean;
  providerName: string;
  providerTimeoutMS: number;
  exemptPathPrefixes: string[];
  logThreshold: number;
  challengeThreshold: number;
  blockThreshold: number;
  maxInspectBody: number;
};

export type SemanticHostScopeState = SemanticScopeState & {
  host: string;
};

export type SemanticEditorState = SemanticScopeState & {
  hosts: SemanticHostScopeState[];
};

type JSONRecord = Record<string, unknown>;

export type ParsedSemanticEditor = {
  base: JSONRecord;
  defaultBase: JSONRecord;
  hostBases: JSONRecord[];
  state: SemanticEditorState;
};

export function createDefaultSemanticScopeState(): SemanticScopeState {
  return {
    enabled: false,
    mode: "off",
    providerEnabled: false,
    providerName: "builtin_attack_family",
    providerTimeoutMS: 25,
    exemptPathPrefixes: [],
    logThreshold: 4,
    challengeThreshold: 7,
    blockThreshold: 9,
    maxInspectBody: 16 * 1024,
  };
}

export function createEmptySemanticHostScope(seed = 1): SemanticHostScopeState {
  return {
    host: `example-${seed}.com`,
    ...createDefaultSemanticScopeState(),
  };
}

export function createDefaultSemanticEditorState(): SemanticEditorState {
  return {
    ...createDefaultSemanticScopeState(),
    hosts: [],
  };
}

export function parseSemanticEditorDocument(raw: string): ParsedSemanticEditor {
  const defaults = createDefaultSemanticScopeState();
  const trimmed = raw.trim();
  if (!trimmed) {
    return {
      base: {},
      defaultBase: {},
      hostBases: [],
      state: createDefaultSemanticEditorState(),
    };
  }

  const parsed = JSON.parse(trimmed) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("semantic config must be a JSON object");
  }

  if (!("default" in parsed) && !("hosts" in parsed)) {
    const legacyBase = deepCloneRecord(parsed);
    return {
      base: {},
      defaultBase: legacyBase,
      hostBases: [],
      state: {
        ...readScopeState(legacyBase, defaults),
        hosts: [],
      },
    };
  }

  const base = deepCloneRecord(parsed);
  const defaultBase = isRecord(base.default) ? deepCloneRecord(base.default) : {};
  const hostScopes = readHostScopes(base.hosts, defaultBase, defaults);
  return {
    base,
    defaultBase,
    hostBases: hostScopes.hostBases,
    state: {
      ...readScopeState(defaultBase, defaults),
      hosts: hostScopes.hosts,
    },
  };
}

export function parseSemanticEditor(raw: string): SemanticEditorState {
  return parseSemanticEditorDocument(raw).state;
}

export function serializeSemanticEditor(state: SemanticEditorState): string;
export function serializeSemanticEditor(
  base: JSONRecord,
  state: SemanticEditorState,
  defaultBase?: JSONRecord,
  hostBases?: JSONRecord[],
): string;
export function serializeSemanticEditor(
  baseOrState: JSONRecord | SemanticEditorState,
  maybeState?: SemanticEditorState,
  maybeDefaultBase?: JSONRecord,
  maybeHostBases?: JSONRecord[],
): string {
  const state = maybeState ?? (baseOrState as SemanticEditorState);
  const next = maybeState ? deepCloneRecord(baseOrState as JSONRecord) : {};
  deleteLegacySemanticRootKeys(next);

  next.default = writeScopeState(maybeDefaultBase ?? (isRecord(next.default) ? next.default : null), state);

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
    for (const item of nextHosts) {
      if (item.host in outHosts) {
        throw new Error(`duplicate host scope: ${item.host}`);
      }
      outHosts[item.host] = writeScopeState(maybeHostBases?.[item.index] ?? null, omitHost(item.scope));
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
  defaults: SemanticScopeState,
): { hostBases: JSONRecord[]; hosts: SemanticHostScopeState[] } {
  if (!isRecord(value)) {
    return {
      hostBases: [],
      hosts: [],
    };
  }

  const entries = Object.entries(value)
    .map(([host, scope]) => {
      const normalizedHost = serializePolicyHostKey(host);
      const rawScope = isRecord(scope) ? deepCloneRecord(scope) : {};
      const mergedScope = mergeJSONRecords(defaultBase, rawScope);
      return {
        host: normalizedHost,
        base: mergedScope,
        scope: {
          host: normalizedHost,
          ...readScopeState(mergedScope, defaults),
        },
      };
    })
    .filter((scope) => scope.host)
    .sort((a, b) => a.host.localeCompare(b.host));

  return {
    hostBases: entries.map((entry) => entry.base),
    hosts: entries.map((entry) => entry.scope),
  };
}

function readScopeState(value: JSONRecord | null, defaults: SemanticScopeState): SemanticScopeState {
  const base = value ?? {};
  const provider = isRecord(base.provider) ? base.provider : {};
  return {
    enabled: readBoolean(base.enabled, defaults.enabled),
    mode: readSemanticMode(base.mode, defaults.mode),
    providerEnabled: readBoolean(provider.enabled, defaults.providerEnabled),
    providerName: readString(provider.name, defaults.providerName),
    providerTimeoutMS: readFiniteInt(provider.timeout_ms, defaults.providerTimeoutMS),
    exemptPathPrefixes: readStringList(base.exempt_path_prefixes),
    logThreshold: readFiniteInt(base.log_threshold, defaults.logThreshold),
    challengeThreshold: readFiniteInt(base.challenge_threshold, defaults.challengeThreshold),
    blockThreshold: readFiniteInt(base.block_threshold, defaults.blockThreshold),
    maxInspectBody: readFiniteInt(base.max_inspect_body, defaults.maxInspectBody),
  };
}

function writeScopeState(base: JSONRecord | null, scope: SemanticScopeState): JSONRecord {
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = scope.enabled;
  out.mode = readSemanticMode(scope.mode, "off");
  out.exempt_path_prefixes = normalizeStringList(scope.exemptPathPrefixes);
  out.log_threshold = writeFiniteInt(scope.logThreshold, 4);
  out.challenge_threshold = writeFiniteInt(scope.challengeThreshold, 7);
  out.block_threshold = writeFiniteInt(scope.blockThreshold, 9);
  out.max_inspect_body = writeFiniteInt(scope.maxInspectBody, 16 * 1024);

  const provider = isRecord(out.provider) ? deepCloneRecord(out.provider) : {};
  provider.enabled = scope.providerEnabled;
  provider.name = scope.providerName.trim() || "builtin_attack_family";
  provider.timeout_ms = writeFiniteInt(scope.providerTimeoutMS, 25);
  out.provider = provider;

  return out;
}

function omitHost(scope: SemanticHostScopeState): SemanticScopeState {
  return {
    enabled: scope.enabled,
    mode: scope.mode,
    providerEnabled: scope.providerEnabled,
    providerName: scope.providerName,
    providerTimeoutMS: scope.providerTimeoutMS,
    exemptPathPrefixes: scope.exemptPathPrefixes,
    logThreshold: scope.logThreshold,
    challengeThreshold: scope.challengeThreshold,
    blockThreshold: scope.blockThreshold,
    maxInspectBody: scope.maxInspectBody,
  };
}

function deleteLegacySemanticRootKeys(target: JSONRecord): void {
  delete target.enabled;
  delete target.mode;
  delete target.provider;
  delete target.exempt_path_prefixes;
  delete target.log_threshold;
  delete target.challenge_threshold;
  delete target.block_threshold;
  delete target.max_inspect_body;
}

function normalizeStringList(values: string[]): string[] {
  return values.map((value) => value.trim()).filter(Boolean);
}

function readStringList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean);
}

function readSemanticMode(value: unknown, fallback: SemanticMode): SemanticMode {
  return typeof value === "string" && SEMANTIC_MODE_OPTIONS.includes(value as SemanticMode) ? (value as SemanticMode) : fallback;
}

function readBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function readString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function readFiniteInt(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.trunc(value) : fallback;
}

function writeFiniteInt(value: number, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.trunc(value) : fallback;
}

function isRecord(value: unknown): value is JSONRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepCloneRecord(value: JSONRecord): JSONRecord {
  return JSON.parse(JSON.stringify(value)) as JSONRecord;
}

function mergeJSONRecords(base: JSONRecord, override: JSONRecord): JSONRecord {
  const out = cloneJSONValue(base) as JSONRecord;
  for (const [key, value] of Object.entries(override)) {
    out[key] = mergeJSONValue(out[key], value);
  }
  return out;
}

function mergeJSONValue(base: unknown, override: unknown): unknown {
  if (isRecord(base) && isRecord(override)) {
    return mergeJSONRecords(base, override);
  }
  return cloneJSONValue(override);
}

function cloneJSONValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => cloneJSONValue(item));
  }
  if (isRecord(value)) {
    const out: JSONRecord = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = cloneJSONValue(item);
    }
    return out;
  }
  return value;
}
