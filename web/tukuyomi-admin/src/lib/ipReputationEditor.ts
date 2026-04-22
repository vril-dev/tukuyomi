import { serializePolicyHostKey } from "./policyHost.js";

export type IPReputationScopeState = {
  enabled: boolean;
  feedURLs: string[];
  allowlist: string[];
  blocklist: string[];
  refreshIntervalSec: number;
  requestTimeoutSec: number;
  blockStatusCode: number;
  failOpen: boolean;
};

export type IPReputationHostScopeState = IPReputationScopeState & {
  host: string;
};

export type IPReputationEditorState = IPReputationScopeState & {
  hosts: IPReputationHostScopeState[];
};

type JSONRecord = Record<string, unknown>;

export type ParsedIPReputationEditor = {
  base: JSONRecord;
  defaultBase: JSONRecord;
  hostBases: JSONRecord[];
  state: IPReputationEditorState;
};

export function createDefaultIPReputationScopeState(): IPReputationScopeState {
  return {
    enabled: false,
    feedURLs: [],
    allowlist: [],
    blocklist: [],
    refreshIntervalSec: 900,
    requestTimeoutSec: 5,
    blockStatusCode: 403,
    failOpen: true,
  };
}

export function createEmptyIPReputationHostScope(seed = 1): IPReputationHostScopeState {
  return {
    host: `example-${seed}.com`,
    ...createDefaultIPReputationScopeState(),
  };
}

export function createDefaultIPReputationEditorState(): IPReputationEditorState {
  return {
    ...createDefaultIPReputationScopeState(),
    hosts: [],
  };
}

export function parseIPReputationEditorDocument(raw: string): ParsedIPReputationEditor {
  const defaults = createDefaultIPReputationScopeState();
  const trimmed = raw.trim();
  if (!trimmed) {
    return {
      base: {},
      defaultBase: {},
      hostBases: [],
      state: createDefaultIPReputationEditorState(),
    };
  }

  const parsed = JSON.parse(trimmed) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("ip reputation config must be a JSON object");
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

export function parseIPReputationEditor(raw: string): IPReputationEditorState {
  return parseIPReputationEditorDocument(raw).state;
}

export function serializeIPReputationEditor(state: IPReputationEditorState): string;
export function serializeIPReputationEditor(
  base: JSONRecord,
  state: IPReputationEditorState,
  defaultBase?: JSONRecord,
  hostBases?: JSONRecord[],
): string;
export function serializeIPReputationEditor(
  baseOrState: JSONRecord | IPReputationEditorState,
  maybeState?: IPReputationEditorState,
  maybeDefaultBase?: JSONRecord,
  maybeHostBases?: JSONRecord[],
): string {
  const state = maybeState ?? (baseOrState as IPReputationEditorState);
  const next = maybeState ? deepCloneRecord(baseOrState as JSONRecord) : {};
  deleteLegacyIPReputationRootKeys(next);

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
  defaults: IPReputationScopeState,
): { hostBases: JSONRecord[]; hosts: IPReputationHostScopeState[] } {
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

function readScopeState(value: JSONRecord | null, defaults: IPReputationScopeState): IPReputationScopeState {
  const base = value ?? {};
  return {
    enabled: readBoolean(base.enabled, defaults.enabled),
    feedURLs: readStringList(base.feed_urls),
    allowlist: readStringList(base.allowlist),
    blocklist: readStringList(base.blocklist),
    refreshIntervalSec: readFiniteInt(base.refresh_interval_sec, defaults.refreshIntervalSec),
    requestTimeoutSec: readFiniteInt(base.request_timeout_sec, defaults.requestTimeoutSec),
    blockStatusCode: readFiniteInt(base.block_status_code, defaults.blockStatusCode),
    failOpen: readBoolean(base.fail_open, defaults.failOpen),
  };
}

function writeScopeState(base: JSONRecord | null, scope: IPReputationScopeState): JSONRecord {
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = scope.enabled;
  out.feed_urls = normalizeStringList(scope.feedURLs);
  out.allowlist = normalizeStringList(scope.allowlist);
  out.blocklist = normalizeStringList(scope.blocklist);
  out.refresh_interval_sec = writeFiniteInt(scope.refreshIntervalSec, 900);
  out.request_timeout_sec = writeFiniteInt(scope.requestTimeoutSec, 5);
  out.block_status_code = writeFiniteInt(scope.blockStatusCode, 403);
  out.fail_open = scope.failOpen;
  return out;
}

function omitHost(scope: IPReputationHostScopeState): IPReputationScopeState {
  return {
    enabled: scope.enabled,
    feedURLs: scope.feedURLs,
    allowlist: scope.allowlist,
    blocklist: scope.blocklist,
    refreshIntervalSec: scope.refreshIntervalSec,
    requestTimeoutSec: scope.requestTimeoutSec,
    blockStatusCode: scope.blockStatusCode,
    failOpen: scope.failOpen,
  };
}

function deleteLegacyIPReputationRootKeys(target: JSONRecord): void {
  delete target.enabled;
  delete target.feed_urls;
  delete target.allowlist;
  delete target.blocklist;
  delete target.refresh_interval_sec;
  delete target.request_timeout_sec;
  delete target.block_status_code;
  delete target.fail_open;
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

function readBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
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
