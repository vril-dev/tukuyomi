import { serializePolicyHostKey } from "./policyHost.js";

export type BypassEntryDraft = {
  path: string;
  extraRule: string;
};

export type BypassHostScopeDraft = {
  host: string;
  entries: BypassEntryDraft[];
};

export type BypassRulesEditorState = {
  defaultEntries: BypassEntryDraft[];
  hosts: BypassHostScopeDraft[];
};

type JSONRecord = Record<string, unknown>;

export type ParsedBypassRulesEditor = {
  base: JSONRecord;
  defaultEntryBases: JSONRecord[];
  hostBases: JSONRecord[];
  hostEntryBases: JSONRecord[][];
  state: BypassRulesEditorState;
};

export function createEmptyBypassEntry(seed = 1): BypassEntryDraft {
  return {
    path: `/path-${seed}/`,
    extraRule: "",
  };
}

export function createEmptyBypassHostScope(seed = 1): BypassHostScopeDraft {
  return {
    host: `example-${seed}.com`,
    entries: [createEmptyBypassEntry(seed)],
  };
}

export function createEmptyBypassRulesEditorState(): BypassRulesEditorState {
  return {
    defaultEntries: [],
    hosts: [],
  };
}

export function countBypassEntries(state: BypassRulesEditorState): number {
  return countSerializedEntries(state.defaultEntries) + state.hosts.reduce((total, scope) => total + countSerializedEntries(scope.entries), 0);
}

export function parseBypassRulesEditorDocument(raw: string): ParsedBypassRulesEditor {
  const trimmed = raw.trim();
  if (!trimmed) {
    return {
      base: {},
      defaultEntryBases: [],
      hostBases: [],
      hostEntryBases: [],
      state: createEmptyBypassRulesEditorState(),
    };
  }

  if (!trimmed.startsWith("{")) {
    const entries = parseLegacyBypassEntries(raw);
    return {
      base: {},
      defaultEntryBases: entries.map(() => ({})),
      hostBases: [],
      hostEntryBases: [],
      state: {
        defaultEntries: entries,
        hosts: [],
      },
    };
  }

  const parsed = JSON.parse(trimmed) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("bypass rules config must be a JSON object");
  }
  const base = deepCloneRecord(parsed);
  const defaultEntries = readEntryDrafts(isRecord(base.default) ? base.default.entries : base.entries);
  const hostScopes = readHostScopes(base.hosts);
  return {
    base,
    defaultEntryBases: defaultEntries.entryBases,
    hostBases: hostScopes.hostBases,
    hostEntryBases: hostScopes.hostEntryBases,
    state: {
      defaultEntries: defaultEntries.entries,
      hosts: hostScopes.hosts,
    },
  };
}

export function parseBypassRulesEditor(raw: string): BypassRulesEditorState {
  return parseBypassRulesEditorDocument(raw).state;
}

export function serializeBypassRulesEditor(state: BypassRulesEditorState): string;
export function serializeBypassRulesEditor(
  base: JSONRecord,
  state: BypassRulesEditorState,
  defaultEntryBases?: JSONRecord[],
  hostBases?: JSONRecord[],
  hostEntryBases?: JSONRecord[][],
): string;
export function serializeBypassRulesEditor(
  baseOrState: JSONRecord | BypassRulesEditorState,
  maybeState?: BypassRulesEditorState,
  maybeDefaultEntryBases?: JSONRecord[],
  maybeHostBases?: JSONRecord[],
  maybeHostEntryBases?: JSONRecord[][],
): string {
  const state = maybeState ?? (baseOrState as BypassRulesEditorState);
  const next = maybeState ? deepCloneRecord(baseOrState as JSONRecord) : {};

  const defaultScope = isRecord(next.default) ? deepCloneRecord(next.default) : {};
  defaultScope.entries = writeEntryDrafts(state.defaultEntries, maybeDefaultEntryBases);
  next.default = defaultScope;
  delete next.entries;

  const nextHosts = state.hosts
    .map((scope, index) => ({
      index,
      host: serializePolicyHostKey(scope.host),
      entries: scope.entries,
    }))
    .filter((scope) => scope.host)
    .sort((a, b) => a.host.localeCompare(b.host));

  if (nextHosts.length > 0) {
    const outHosts: Record<string, JSONRecord> = {};
    for (const scope of nextHosts) {
      if (scope.host in outHosts) {
        throw new Error(`duplicate host scope: ${scope.host}`);
      }
      const scopeBase = maybeHostBases?.[scope.index] ? deepCloneRecord(maybeHostBases[scope.index] as JSONRecord) : {};
      scopeBase.entries = writeEntryDrafts(scope.entries, maybeHostEntryBases?.[scope.index]);
      outHosts[scope.host] = scopeBase;
    }
    next.hosts = outHosts;
  } else {
    delete next.hosts;
  }

  return `${JSON.stringify(next, null, 2)}\n`;
}

function parseLegacyBypassEntries(raw: string): BypassEntryDraft[] {
  const out: BypassEntryDraft[] = [];
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
    const parts = line.split(/\s+/);
    if (parts.length === 0) {
      continue;
    }
    out.push({
      path: normalizeBypassPath(parts[0] ?? ""),
      extraRule: parts[1]?.trim() ?? "",
    });
  }
  return out.filter((entry) => entry.path);
}

function readHostScopes(value: unknown): {
  hostBases: JSONRecord[];
  hostEntryBases: JSONRecord[][];
  hosts: BypassHostScopeDraft[];
} {
  if (!isRecord(value)) {
    return {
      hostBases: [],
      hostEntryBases: [],
      hosts: [],
    };
  }

  const entries = Object.entries(value)
    .map(([host, scope]) => {
      const parsedEntries = readEntryDrafts(isRecord(scope) ? scope.entries : undefined);
      return {
        host: serializePolicyHostKey(host),
        base: isRecord(scope) ? deepCloneRecord(scope) : {},
        entryBases: parsedEntries.entryBases,
        entries: parsedEntries.entries,
      };
    })
    .filter((scope) => scope.host)
    .sort((a, b) => a.host.localeCompare(b.host));

  return {
    hostBases: entries.map((entry) => entry.base),
    hostEntryBases: entries.map((entry) => entry.entryBases),
    hosts: entries.map(({ host, entries: scopes }) => ({
      host,
      entries: scopes,
    })),
  };
}

function readEntryDrafts(value: unknown): { entryBases: JSONRecord[]; entries: BypassEntryDraft[] } {
  if (!Array.isArray(value)) {
    return {
      entryBases: [],
      entries: [],
    };
  }
  const out = value.map((entry, index) => {
    const fallback = createEmptyBypassEntry(index + 1);
    if (!isRecord(entry)) {
      return {
        base: {},
        entry: fallback,
      };
    }
    return {
      base: deepCloneRecord(entry),
      entry: {
        path: normalizeBypassPath(readString(entry.path, fallback.path)),
        extraRule: readString(entry.extra_rule, "").trim(),
      },
    };
  });
  return {
    entryBases: out.map((entry) => entry.base),
    entries: out.map((entry) => entry.entry),
  };
}

function writeEntryDrafts(entries: BypassEntryDraft[], entryBases?: JSONRecord[]): JSONRecord[] {
  return entries
    .map((entry, index) => {
      const path = normalizeBypassPath(entry.path);
      if (!path) {
        return null;
      }
      const out = entryBases?.[index] ? deepCloneRecord(entryBases[index] as JSONRecord) : {};
      out.path = path;
      const extraRule = entry.extraRule.trim();
      if (extraRule) {
        out.extra_rule = extraRule;
      } else {
        delete out.extra_rule;
      }
      return out;
    })
    .filter((entry): entry is JSONRecord => entry !== null);
}

function countSerializedEntries(entries: BypassEntryDraft[]): number {
  return entries.filter((entry) => normalizeBypassPath(entry.path)).length;
}

function normalizeBypassPath(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }
  let decoded = trimmed;
  try {
    decoded = decodeURIComponent(trimmed);
  } catch {
    decoded = trimmed;
  }
  const prefixed = decoded.startsWith("/") ? decoded : `/${decoded}`;
  const hadTrailingSlash = prefixed.length > 1 && prefixed.endsWith("/");
  const parts: string[] = [];
  for (const part of prefixed.split("/")) {
    if (!part || part === ".") {
      continue;
    }
    if (part === "..") {
      parts.pop();
      continue;
    }
    parts.push(part);
  }
  let normalized = `/${parts.join("/")}`;
  if (!normalized) {
    normalized = "/";
  }
  if (hadTrailingSlash && normalized !== "/") {
    normalized += "/";
  }
  return normalized;
}

function readString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function isRecord(value: unknown): value is JSONRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepCloneRecord(value: JSONRecord): JSONRecord {
  return JSON.parse(JSON.stringify(value)) as JSONRecord;
}
