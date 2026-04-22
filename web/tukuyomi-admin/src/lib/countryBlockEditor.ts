import { serializePolicyHostKey } from "./policyHost.js";

export type CountryBlockHostScope = {
  host: string;
  blockedCountries: string[];
};

export type CountryBlockEditorState = {
  defaultBlockedCountries: string[];
  hosts: CountryBlockHostScope[];
};

type JSONRecord = Record<string, unknown>;

export type ParsedCountryBlockEditor = {
  base: JSONRecord;
  hostBases: JSONRecord[];
  state: CountryBlockEditorState;
};

export function createEmptyCountryBlockEditorState(): CountryBlockEditorState {
  return {
    defaultBlockedCountries: [],
    hosts: [],
  };
}

export function createEmptyCountryBlockHostScope(seed = 1): CountryBlockHostScope {
  return {
    host: `example-${seed}.com`,
    blockedCountries: [],
  };
}

export function countryCodesToMultiline(codes: string[]): string {
  return normalizeCountryCodeList(codes).join("\n");
}

export function multilineToCountryCodes(raw: string): string[] {
  const out: string[] = [];
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = stripCountryComment(rawLine);
    if (!line) {
      continue;
    }
    for (const token of line.split(/[,\s]+/)) {
      const normalized = normalizeCountryCode(token);
      if (normalized) {
        out.push(normalized);
      }
    }
  }
  return normalizeCountryCodeList(out);
}

export function collectCountryBlockCodes(state: CountryBlockEditorState): string[] {
  const out = [...state.defaultBlockedCountries];
  for (const scope of state.hosts) {
    out.push(...scope.blockedCountries);
  }
  return normalizeCountryCodeList(out);
}

export function parseCountryBlockEditorDocument(raw: string): ParsedCountryBlockEditor {
  const trimmed = raw.trim();
  if (!trimmed) {
    return {
      base: {},
      hostBases: [],
      state: createEmptyCountryBlockEditorState(),
    };
  }
  if (!trimmed.startsWith("{")) {
    return {
      base: {},
      hostBases: [],
      state: {
        defaultBlockedCountries: multilineToCountryCodes(raw),
        hosts: [],
      },
    };
  }

  const parsed = JSON.parse(trimmed) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("country block config must be a JSON object");
  }
  const base = deepCloneRecord(parsed);

  const defaultBlocked =
    readCountryCodeList(base.default, "blocked_countries") ??
    readStringList(base.blocked_countries);

  const { hostBases, hosts } = readCountryBlockHosts(base.hosts);
  return {
    base,
    hostBases,
    state: {
      defaultBlockedCountries: normalizeCountryCodeList(defaultBlocked),
      hosts,
    },
  };
}

export function parseCountryBlockEditor(raw: string): CountryBlockEditorState {
  return parseCountryBlockEditorDocument(raw).state;
}

export function serializeCountryBlockEditor(state: CountryBlockEditorState): string;
export function serializeCountryBlockEditor(base: JSONRecord, state: CountryBlockEditorState, hostBases?: JSONRecord[]): string;
export function serializeCountryBlockEditor(
  baseOrState: JSONRecord | CountryBlockEditorState,
  maybeState?: CountryBlockEditorState,
  maybeHostBases?: JSONRecord[],
): string {
  const state = maybeState ?? (baseOrState as CountryBlockEditorState);
  const next = maybeState ? deepCloneRecord(baseOrState as JSONRecord) : {};
  const nextHosts = state.hosts
    .map((scope, index) => ({
      index,
      host: serializePolicyHostKey(scope.host),
      blockedCountries: normalizeCountryCodeList(scope.blockedCountries),
    }))
    .filter((scope) => scope.host)
    .sort((a, b) => a.host.localeCompare(b.host));

  const defaultScope = isRecord(next.default) ? deepCloneRecord(next.default) : {};
  defaultScope.blocked_countries = normalizeCountryCodeList(state.defaultBlockedCountries);
  next.default = defaultScope;
  delete next.blocked_countries;

  if (nextHosts.length > 0) {
    const outHosts: Record<string, { blocked_countries: string[] } & JSONRecord> = {};
    for (const scope of nextHosts) {
      if (scope.host in outHosts) {
        throw new Error(`duplicate host scope: ${scope.host}`);
      }
      const existingScope = maybeHostBases?.[scope.index]
        ? deepCloneRecord(maybeHostBases[scope.index] as JSONRecord)
        : {};
      existingScope.blocked_countries = scope.blockedCountries;
      outHosts[scope.host] = existingScope as { blocked_countries: string[] } & JSONRecord;
    }
    next.hosts = outHosts;
  } else {
    delete next.hosts;
  }

  return `${JSON.stringify(next, null, 2)}\n`;
}

function readCountryBlockHosts(value: unknown): { hostBases: JSONRecord[]; hosts: CountryBlockHostScope[] } {
  if (!isRecord(value)) {
    return {
      hostBases: [],
      hosts: [],
    };
  }
  const entries = Object.entries(value)
    .map(([host, scope]) => ({
      host: serializePolicyHostKey(host),
      base: isRecord(scope) ? deepCloneRecord(scope) : {},
      blockedCountries: normalizeCountryCodeList(readCountryCodeList(scope, "blocked_countries") ?? []),
    }))
    .filter((scope) => scope.host)
    .sort((a, b) => a.host.localeCompare(b.host));
  return {
    hostBases: entries.map((entry) => entry.base),
    hosts: entries.map(({ host, blockedCountries }) => ({
      host,
      blockedCountries,
    })),
  };
}

function readCountryCodeList(value: unknown, key: string): string[] | null {
  if (!isRecord(value)) {
    return null;
  }
  return readStringList(value[key]);
}

function readStringList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((item) => (typeof item === "string" ? item : ""))
    .map((item) => normalizeCountryCode(item))
    .filter(Boolean);
}

function normalizeCountryCodeList(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const normalized = normalizeCountryCode(value);
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    out.push(normalized);
  }
  out.sort((a, b) => a.localeCompare(b));
  return out;
}

function normalizeCountryCode(value: string): string {
  return value.trim().toUpperCase();
}

function stripCountryComment(value: string): string {
  const commentIndex = value.indexOf("#");
  return (commentIndex >= 0 ? value.slice(0, commentIndex) : value).trim();
}

function isRecord(value: unknown): value is JSONRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepCloneRecord(value: JSONRecord): JSONRecord {
  return JSON.parse(JSON.stringify(value)) as JSONRecord;
}
