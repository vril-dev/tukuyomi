import { serializePolicyHostKey } from "./policyHost.js";

export const BOT_DEFENSE_MODE_OPTIONS = ["suspicious", "always"] as const;
export const BOT_DEFENSE_POLICY_MODE_OPTIONS = ["", ...BOT_DEFENSE_MODE_OPTIONS] as const;
export const BOT_DEFENSE_DRY_RUN_OPTIONS = ["inherit", "enabled", "disabled"] as const;

export type BotDefenseMode = (typeof BOT_DEFENSE_MODE_OPTIONS)[number];
export type BotDefensePolicyMode = (typeof BOT_DEFENSE_POLICY_MODE_OPTIONS)[number];
export type BotDefenseDryRunOverride = (typeof BOT_DEFENSE_DRY_RUN_OPTIONS)[number];

export type BotDefensePathPolicyDraft = {
  name: string;
  pathPrefixes: string[];
  mode: BotDefensePolicyMode;
  dryRun: BotDefenseDryRunOverride;
  riskScoreMultiplierPercent: number;
  riskScoreOffset: number;
  telemetryCookieRequired: boolean;
  disableQuarantine: boolean;
};

export type BotDefenseBehavioralDraft = {
  enabled: boolean;
  windowSeconds: number;
  burstThreshold: number;
  pathFanoutThreshold: number;
  uaChurnThreshold: number;
  missingCookieThreshold: number;
  scoreThreshold: number;
  riskScorePerSignal: number;
};

export type BotDefenseBrowserSignalsDraft = {
  enabled: boolean;
  jsCookieName: string;
  scoreThreshold: number;
  riskScorePerSignal: number;
};

export type BotDefenseDeviceSignalsDraft = {
  enabled: boolean;
  requireTimeZone: boolean;
  requirePlatform: boolean;
  requireHardwareConcurrency: boolean;
  checkMobileTouch: boolean;
  invisibleHTMLInjection: boolean;
  invisibleMaxBodyBytes: number;
  scoreThreshold: number;
  riskScorePerSignal: number;
};

export type BotDefenseHeaderSignalsDraft = {
  enabled: boolean;
  requireAcceptLanguage: boolean;
  requireFetchMetadata: boolean;
  requireClientHints: boolean;
  requireUpgradeInsecure: boolean;
  scoreThreshold: number;
  riskScorePerSignal: number;
};

export type BotDefenseTLSSignalsDraft = {
  enabled: boolean;
  requireSNI: boolean;
  requireALPN: boolean;
  requireModernTLS: boolean;
  scoreThreshold: number;
  riskScorePerSignal: number;
};

export type BotDefenseQuarantineDraft = {
  enabled: boolean;
  threshold: number;
  strikesRequired: number;
  strikeWindowSeconds: number;
  ttlSeconds: number;
  statusCode: number;
  reputationFeedbackSeconds: number;
};

export type BotDefenseScopeState = {
  enabled: boolean;
  dryRun: boolean;
  mode: BotDefenseMode;
  pathPrefixes: string[];
  pathPolicies: BotDefensePathPolicyDraft[];
  exemptCIDRs: string[];
  suspiciousUserAgents: string[];
  challengeCookieName: string;
  challengeSecret: string;
  challengeTTLSeconds: number;
  challengeStatusCode: number;
  behavioralDetection: BotDefenseBehavioralDraft;
  browserSignals: BotDefenseBrowserSignalsDraft;
  deviceSignals: BotDefenseDeviceSignalsDraft;
  headerSignals: BotDefenseHeaderSignalsDraft;
  tlsSignals: BotDefenseTLSSignalsDraft;
  quarantine: BotDefenseQuarantineDraft;
};

export type BotDefenseHostScopeState = BotDefenseScopeState & {
  host: string;
};

export type BotDefenseEditorState = BotDefenseScopeState & {
  hosts: BotDefenseHostScopeState[];
};

type JSONRecord = Record<string, unknown>;

export type ParsedBotDefenseEditor = {
  base: JSONRecord;
  defaultBase: JSONRecord;
  defaultPathPolicyBases: JSONRecord[];
  hostBases: JSONRecord[];
  hostPathPolicyBases: JSONRecord[][];
  state: BotDefenseEditorState;
};

const DEFAULT_SUSPICIOUS_USER_AGENTS = [
  "curl",
  "wget",
  "python-requests",
  "python-urllib",
  "go-http-client",
  "libwww-perl",
  "scrapy",
  "sqlmap",
  "nikto",
  "nmap",
  "masscan",
];

export function createDefaultBotDefenseScopeState(): BotDefenseScopeState {
  return {
    enabled: false,
    dryRun: false,
    mode: "suspicious",
    pathPrefixes: ["/"],
    pathPolicies: [],
    exemptCIDRs: [],
    suspiciousUserAgents: [...DEFAULT_SUSPICIOUS_USER_AGENTS],
    challengeCookieName: "__tukuyomi_bot_ok",
    challengeSecret: "",
    challengeTTLSeconds: 24 * 60 * 60,
    challengeStatusCode: 429,
    behavioralDetection: {
      enabled: false,
      windowSeconds: 60,
      burstThreshold: 12,
      pathFanoutThreshold: 6,
      uaChurnThreshold: 4,
      missingCookieThreshold: 6,
      scoreThreshold: 2,
      riskScorePerSignal: 2,
    },
    browserSignals: {
      enabled: false,
      jsCookieName: "__tukuyomi_bot_js",
      scoreThreshold: 1,
      riskScorePerSignal: 2,
    },
    deviceSignals: {
      enabled: false,
      requireTimeZone: true,
      requirePlatform: true,
      requireHardwareConcurrency: true,
      checkMobileTouch: true,
      invisibleHTMLInjection: false,
      invisibleMaxBodyBytes: 256 * 1024,
      scoreThreshold: 2,
      riskScorePerSignal: 2,
    },
    headerSignals: {
      enabled: false,
      requireAcceptLanguage: true,
      requireFetchMetadata: true,
      requireClientHints: true,
      requireUpgradeInsecure: true,
      scoreThreshold: 2,
      riskScorePerSignal: 2,
    },
    tlsSignals: {
      enabled: false,
      requireSNI: true,
      requireALPN: true,
      requireModernTLS: true,
      scoreThreshold: 2,
      riskScorePerSignal: 2,
    },
    quarantine: {
      enabled: false,
      threshold: 8,
      strikesRequired: 2,
      strikeWindowSeconds: 300,
      ttlSeconds: 900,
      statusCode: 403,
      reputationFeedbackSeconds: 0,
    },
  };
}

export function createDefaultBotDefenseEditorState(): BotDefenseEditorState {
  return {
    ...createDefaultBotDefenseScopeState(),
    hosts: [],
  };
}

export function createDefaultBotDefenseState(): BotDefenseEditorState {
  return createDefaultBotDefenseEditorState();
}

export function createEmptyBotDefensePathPolicy(seed = 1): BotDefensePathPolicyDraft {
  return {
    name: `policy-${seed}`,
    pathPrefixes: ["/"],
    mode: "",
    dryRun: "inherit",
    riskScoreMultiplierPercent: 100,
    riskScoreOffset: 0,
    telemetryCookieRequired: false,
    disableQuarantine: false,
  };
}

export function createEmptyBotDefenseHostScope(seed = 1): BotDefenseHostScopeState {
  return {
    host: `example-${seed}.com`,
    ...createDefaultBotDefenseScopeState(),
  };
}

export function parseBotDefenseEditorDocument(raw: string): ParsedBotDefenseEditor {
  const defaults = createDefaultBotDefenseScopeState();
  const trimmed = raw.trim();
  if (!trimmed) {
    return {
      base: {},
      defaultBase: {},
      defaultPathPolicyBases: [],
      hostBases: [],
      hostPathPolicyBases: [],
      state: createDefaultBotDefenseEditorState(),
    };
  }

  const parsed = JSON.parse(trimmed) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("bot defense config must be a JSON object");
  }

  if (!("default" in parsed) && !("hosts" in parsed)) {
    const legacyBase = deepCloneRecord(parsed);
    const legacyScope = readScopeState(legacyBase, defaults);
    return {
      base: {},
      defaultBase: legacyBase,
      defaultPathPolicyBases: legacyScope.pathPolicyBases,
      hostBases: [],
      hostPathPolicyBases: [],
      state: {
        ...legacyScope.scope,
        hosts: [],
      },
    };
  }

  const base = deepCloneRecord(parsed);
  const defaultBase = isRecord(base.default) ? deepCloneRecord(base.default) : {};
  const defaultScope = readScopeState(defaultBase, defaults);
  const hostScopes = readHostScopes(base.hosts, defaultBase, defaults);
  return {
    base,
    defaultBase,
    defaultPathPolicyBases: defaultScope.pathPolicyBases,
    hostBases: hostScopes.hostBases,
    hostPathPolicyBases: hostScopes.hostPathPolicyBases,
    state: {
      ...defaultScope.scope,
      hosts: hostScopes.hosts,
    },
  };
}

export function parseBotDefenseEditor(raw: string): BotDefenseEditorState {
  return parseBotDefenseEditorDocument(raw).state;
}

export function serializeBotDefenseEditor(state: BotDefenseEditorState): string;
export function serializeBotDefenseEditor(
  base: JSONRecord,
  state: BotDefenseEditorState,
  defaultBase?: JSONRecord,
  defaultPathPolicyBases?: JSONRecord[],
  hostBases?: JSONRecord[],
  hostPathPolicyBases?: JSONRecord[][],
): string;
export function serializeBotDefenseEditor(
  baseOrState: JSONRecord | BotDefenseEditorState,
  maybeState?: BotDefenseEditorState,
  maybeDefaultBase?: JSONRecord,
  maybeDefaultPathPolicyBases?: JSONRecord[],
  maybeHostBases?: JSONRecord[],
  maybeHostPathPolicyBases?: JSONRecord[][],
): string {
  const state = maybeState ?? (baseOrState as BotDefenseEditorState);
  const next = maybeState ? deepCloneRecord(baseOrState as JSONRecord) : {};
  deleteLegacyBotDefenseRootKeys(next);

  next.default = writeScopeState(
    maybeDefaultBase ?? (isRecord(next.default) ? next.default : null),
    state,
    maybeDefaultPathPolicyBases,
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
      outHosts[scope.host] = writeScopeState(
        maybeHostBases?.[scope.index] ?? null,
        scope.scope,
        maybeHostPathPolicyBases?.[scope.index],
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
  defaults: BotDefenseScopeState,
): {
  hostBases: JSONRecord[];
  hostPathPolicyBases: JSONRecord[][];
  hosts: BotDefenseHostScopeState[];
} {
  if (!isRecord(value)) {
    return {
      hostBases: [],
      hostPathPolicyBases: [],
      hosts: [],
    };
  }

  const entries = Object.entries(value)
    .map(([host, scope]) => {
      const normalizedHost = serializePolicyHostKey(host);
      const rawScope = isRecord(scope) ? deepCloneRecord(scope) : {};
      const mergedScope = mergeJSONRecords(defaultBase, rawScope);
      const parsed = readScopeState(mergedScope, defaults);
      return {
        host: normalizedHost,
        base: mergedScope,
        pathPolicyBases: parsed.pathPolicyBases,
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
    hostPathPolicyBases: entries.map((entry) => entry.pathPolicyBases),
    hosts: entries.map((entry) => entry.scope),
  };
}

function readScopeState(
  value: JSONRecord | null,
  defaults: BotDefenseScopeState,
): { pathPolicyBases: JSONRecord[]; scope: BotDefenseScopeState } {
  const base = value ?? {};
  const pathPolicies = readPathPolicies(base.path_policies);
  const behavioral = isRecord(base.behavioral_detection) ? base.behavioral_detection : {};
  const browserSignals = isRecord(base.browser_signals) ? base.browser_signals : {};
  const deviceSignals = isRecord(base.device_signals) ? base.device_signals : {};
  const headerSignals = isRecord(base.header_signals) ? base.header_signals : {};
  const tlsSignals = isRecord(base.tls_signals) ? base.tls_signals : {};
  const quarantine = isRecord(base.quarantine) ? base.quarantine : {};

  return {
    pathPolicyBases: pathPolicies.policyBases,
    scope: {
      enabled: readBoolean(base.enabled, defaults.enabled),
      dryRun: readBoolean(base.dry_run, defaults.dryRun),
      mode: readBotDefenseMode(base.mode, defaults.mode),
      pathPrefixes: normalizePathPrefixes(readStringList(base.path_prefixes), defaults.pathPrefixes),
      pathPolicies: pathPolicies.policies,
      exemptCIDRs: dedupeTrimmed(readStringList(base.exempt_cidrs)),
      suspiciousUserAgents: normalizeUserAgentList(readStringList(base.suspicious_user_agents), defaults.suspiciousUserAgents),
      challengeCookieName: readString(base.challenge_cookie_name, defaults.challengeCookieName),
      challengeSecret: typeof base.challenge_secret === "string" ? base.challenge_secret : defaults.challengeSecret,
      challengeTTLSeconds: readPositiveInt(base.challenge_ttl_seconds, defaults.challengeTTLSeconds),
      challengeStatusCode: readStatusCode(base.challenge_status_code, defaults.challengeStatusCode),
      behavioralDetection: {
        enabled: readBoolean(behavioral.enabled, defaults.behavioralDetection.enabled),
        windowSeconds: readPositiveInt(behavioral.window_seconds, defaults.behavioralDetection.windowSeconds),
        burstThreshold: readPositiveInt(behavioral.burst_threshold, defaults.behavioralDetection.burstThreshold),
        pathFanoutThreshold: readPositiveInt(behavioral.path_fanout_threshold, defaults.behavioralDetection.pathFanoutThreshold),
        uaChurnThreshold: readPositiveInt(behavioral.ua_churn_threshold, defaults.behavioralDetection.uaChurnThreshold),
        missingCookieThreshold: readPositiveInt(behavioral.missing_cookie_threshold, defaults.behavioralDetection.missingCookieThreshold),
        scoreThreshold: readPositiveInt(behavioral.score_threshold, defaults.behavioralDetection.scoreThreshold),
        riskScorePerSignal: readPositiveInt(behavioral.risk_score_per_signal, defaults.behavioralDetection.riskScorePerSignal),
      },
      browserSignals: {
        enabled: readBoolean(browserSignals.enabled, defaults.browserSignals.enabled),
        jsCookieName: readString(browserSignals.js_cookie_name, defaults.browserSignals.jsCookieName),
        scoreThreshold: readPositiveInt(browserSignals.score_threshold, defaults.browserSignals.scoreThreshold),
        riskScorePerSignal: readPositiveInt(browserSignals.risk_score_per_signal, defaults.browserSignals.riskScorePerSignal),
      },
      deviceSignals: {
        enabled: readBoolean(deviceSignals.enabled, defaults.deviceSignals.enabled),
        requireTimeZone: readBoolean(deviceSignals.require_time_zone, defaults.deviceSignals.requireTimeZone),
        requirePlatform: readBoolean(deviceSignals.require_platform, defaults.deviceSignals.requirePlatform),
        requireHardwareConcurrency: readBoolean(deviceSignals.require_hardware_concurrency, defaults.deviceSignals.requireHardwareConcurrency),
        checkMobileTouch: readBoolean(deviceSignals.check_mobile_touch, defaults.deviceSignals.checkMobileTouch),
        invisibleHTMLInjection: readBoolean(deviceSignals.invisible_html_injection, defaults.deviceSignals.invisibleHTMLInjection),
        invisibleMaxBodyBytes: readPositiveInt(deviceSignals.invisible_max_body_bytes, defaults.deviceSignals.invisibleMaxBodyBytes),
        scoreThreshold: readPositiveInt(deviceSignals.score_threshold, defaults.deviceSignals.scoreThreshold),
        riskScorePerSignal: readPositiveInt(deviceSignals.risk_score_per_signal, defaults.deviceSignals.riskScorePerSignal),
      },
      headerSignals: {
        enabled: readBoolean(headerSignals.enabled, defaults.headerSignals.enabled),
        requireAcceptLanguage: readBoolean(headerSignals.require_accept_language, defaults.headerSignals.requireAcceptLanguage),
        requireFetchMetadata: readBoolean(headerSignals.require_fetch_metadata, defaults.headerSignals.requireFetchMetadata),
        requireClientHints: readBoolean(headerSignals.require_client_hints, defaults.headerSignals.requireClientHints),
        requireUpgradeInsecure: readBoolean(headerSignals.require_upgrade_insecure_requests, defaults.headerSignals.requireUpgradeInsecure),
        scoreThreshold: readPositiveInt(headerSignals.score_threshold, defaults.headerSignals.scoreThreshold),
        riskScorePerSignal: readPositiveInt(headerSignals.risk_score_per_signal, defaults.headerSignals.riskScorePerSignal),
      },
      tlsSignals: {
        enabled: readBoolean(tlsSignals.enabled, defaults.tlsSignals.enabled),
        requireSNI: readBoolean(tlsSignals.require_sni, defaults.tlsSignals.requireSNI),
        requireALPN: readBoolean(tlsSignals.require_alpn, defaults.tlsSignals.requireALPN),
        requireModernTLS: readBoolean(tlsSignals.require_modern_tls, defaults.tlsSignals.requireModernTLS),
        scoreThreshold: readPositiveInt(tlsSignals.score_threshold, defaults.tlsSignals.scoreThreshold),
        riskScorePerSignal: readPositiveInt(tlsSignals.risk_score_per_signal, defaults.tlsSignals.riskScorePerSignal),
      },
      quarantine: {
        enabled: readBoolean(quarantine.enabled, defaults.quarantine.enabled),
        threshold: readPositiveInt(quarantine.threshold, defaults.quarantine.threshold),
        strikesRequired: readPositiveInt(quarantine.strikes_required, defaults.quarantine.strikesRequired),
        strikeWindowSeconds: readPositiveInt(quarantine.strike_window_seconds, defaults.quarantine.strikeWindowSeconds),
        ttlSeconds: readPositiveInt(quarantine.ttl_seconds, defaults.quarantine.ttlSeconds),
        statusCode: readStatusCode(quarantine.status_code, defaults.quarantine.statusCode),
        reputationFeedbackSeconds: readNonNegativeInt(quarantine.reputation_feedback_seconds, defaults.quarantine.reputationFeedbackSeconds),
      },
    },
  };
}

function writeScopeState(base: JSONRecord | null, scope: BotDefenseScopeState, pathPolicyBases?: JSONRecord[]): JSONRecord {
  const defaults = createDefaultBotDefenseScopeState();
  const out = base ? deepCloneRecord(base) : {};

  out.enabled = scope.enabled;
  out.dry_run = scope.dryRun;
  out.mode = readBotDefenseMode(scope.mode, defaults.mode);
  out.path_prefixes = normalizePathPrefixes(scope.pathPrefixes, defaults.pathPrefixes);
  out.path_policies = scope.pathPolicies.map((policy, index) => writePathPolicy(pathPolicyBases?.[index] ?? null, policy));
  out.exempt_cidrs = dedupeTrimmed(scope.exemptCIDRs);
  out.suspicious_user_agents = normalizeUserAgentList(scope.suspiciousUserAgents, defaults.suspiciousUserAgents);
  out.challenge_cookie_name = scope.challengeCookieName.trim() || defaults.challengeCookieName;
  out.challenge_secret = scope.challengeSecret.trim();
  out.challenge_ttl_seconds = readPositiveInt(scope.challengeTTLSeconds, defaults.challengeTTLSeconds);
  out.challenge_status_code = readStatusCode(scope.challengeStatusCode, defaults.challengeStatusCode);

  out.behavioral_detection = writeBehavioralDraftWithBase(isRecord(out.behavioral_detection) ? out.behavioral_detection : null, scope.behavioralDetection);
  out.browser_signals = writeBrowserSignalsDraftWithBase(isRecord(out.browser_signals) ? out.browser_signals : null, scope.browserSignals);
  out.device_signals = writeDeviceSignalsDraftWithBase(isRecord(out.device_signals) ? out.device_signals : null, scope.deviceSignals);
  out.header_signals = writeHeaderSignalsDraftWithBase(isRecord(out.header_signals) ? out.header_signals : null, scope.headerSignals);
  out.tls_signals = writeTLSSignalsDraftWithBase(isRecord(out.tls_signals) ? out.tls_signals : null, scope.tlsSignals);
  out.quarantine = writeQuarantineDraftWithBase(isRecord(out.quarantine) ? out.quarantine : null, scope.quarantine);

  return out;
}

function readPathPolicies(value: unknown): { policyBases: JSONRecord[]; policies: BotDefensePathPolicyDraft[] } {
  if (!Array.isArray(value)) {
    return {
      policyBases: [],
      policies: [],
    };
  }
  const out = value.map((entry, index) => {
    const defaultPolicy = createEmptyBotDefensePathPolicy(index + 1);
    if (!isRecord(entry)) {
      return {
        base: {},
        policy: defaultPolicy,
      };
    }
    return {
      base: deepCloneRecord(entry),
      policy: {
        name: readString(entry.name, defaultPolicy.name),
        pathPrefixes: normalizePathPrefixes(readStringList(entry.path_prefixes), defaultPolicy.pathPrefixes),
        mode: readPolicyMode(entry.mode),
        dryRun: readDryRunOverride(entry.dry_run),
        riskScoreMultiplierPercent: readPositiveInt(entry.risk_score_multiplier_percent, defaultPolicy.riskScoreMultiplierPercent),
        riskScoreOffset: readInt(entry.risk_score_offset, defaultPolicy.riskScoreOffset),
        telemetryCookieRequired: readBoolean(entry.telemetry_cookie_required, defaultPolicy.telemetryCookieRequired),
        disableQuarantine: readBoolean(entry.disable_quarantine, defaultPolicy.disableQuarantine),
      },
    };
  });
  return {
    policyBases: out.map((entry) => entry.base),
    policies: out.map((entry) => entry.policy),
  };
}

function writePathPolicy(base: JSONRecord | null, policy: BotDefensePathPolicyDraft): JSONRecord {
  const defaults = createEmptyBotDefensePathPolicy();
  const out = base ? deepCloneRecord(base) : {};
  out.name = policy.name.trim() || defaults.name;
  out.path_prefixes = normalizePathPrefixes(policy.pathPrefixes, defaults.pathPrefixes);
  const mode = readPolicyMode(policy.mode);
  if (mode) {
    out.mode = mode;
  } else {
    delete out.mode;
  }
  const dryRun = writeDryRunOverride(policy.dryRun);
  if (dryRun === null) {
    delete out.dry_run;
  } else {
    out.dry_run = dryRun;
  }
  out.risk_score_multiplier_percent = readPositiveInt(policy.riskScoreMultiplierPercent, defaults.riskScoreMultiplierPercent);
  out.risk_score_offset = readInt(policy.riskScoreOffset, defaults.riskScoreOffset);
  out.telemetry_cookie_required = policy.telemetryCookieRequired;
  out.disable_quarantine = policy.disableQuarantine;
  return out;
}

function writeBehavioralDraftWithBase(base: JSONRecord | null, draft: BotDefenseBehavioralDraft): JSONRecord {
  const defaults = createDefaultBotDefenseScopeState().behavioralDetection;
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = draft.enabled;
  out.window_seconds = readPositiveInt(draft.windowSeconds, defaults.windowSeconds);
  out.burst_threshold = readPositiveInt(draft.burstThreshold, defaults.burstThreshold);
  out.path_fanout_threshold = readPositiveInt(draft.pathFanoutThreshold, defaults.pathFanoutThreshold);
  out.ua_churn_threshold = readPositiveInt(draft.uaChurnThreshold, defaults.uaChurnThreshold);
  out.missing_cookie_threshold = readPositiveInt(draft.missingCookieThreshold, defaults.missingCookieThreshold);
  out.score_threshold = readPositiveInt(draft.scoreThreshold, defaults.scoreThreshold);
  out.risk_score_per_signal = readPositiveInt(draft.riskScorePerSignal, defaults.riskScorePerSignal);
  return out;
}

function writeBrowserSignalsDraftWithBase(base: JSONRecord | null, draft: BotDefenseBrowserSignalsDraft): JSONRecord {
  const defaults = createDefaultBotDefenseScopeState().browserSignals;
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = draft.enabled;
  out.js_cookie_name = draft.jsCookieName.trim() || defaults.jsCookieName;
  out.score_threshold = readPositiveInt(draft.scoreThreshold, defaults.scoreThreshold);
  out.risk_score_per_signal = readPositiveInt(draft.riskScorePerSignal, defaults.riskScorePerSignal);
  return out;
}

function writeDeviceSignalsDraftWithBase(base: JSONRecord | null, draft: BotDefenseDeviceSignalsDraft): JSONRecord {
  const defaults = createDefaultBotDefenseScopeState().deviceSignals;
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = draft.enabled;
  out.require_time_zone = draft.requireTimeZone;
  out.require_platform = draft.requirePlatform;
  out.require_hardware_concurrency = draft.requireHardwareConcurrency;
  out.check_mobile_touch = draft.checkMobileTouch;
  out.invisible_html_injection = draft.invisibleHTMLInjection;
  out.invisible_max_body_bytes = readPositiveInt(draft.invisibleMaxBodyBytes, defaults.invisibleMaxBodyBytes);
  out.score_threshold = readPositiveInt(draft.scoreThreshold, defaults.scoreThreshold);
  out.risk_score_per_signal = readPositiveInt(draft.riskScorePerSignal, defaults.riskScorePerSignal);
  return out;
}

function writeHeaderSignalsDraftWithBase(base: JSONRecord | null, draft: BotDefenseHeaderSignalsDraft): JSONRecord {
  const defaults = createDefaultBotDefenseScopeState().headerSignals;
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = draft.enabled;
  out.require_accept_language = draft.requireAcceptLanguage;
  out.require_fetch_metadata = draft.requireFetchMetadata;
  out.require_client_hints = draft.requireClientHints;
  out.require_upgrade_insecure_requests = draft.requireUpgradeInsecure;
  out.score_threshold = readPositiveInt(draft.scoreThreshold, defaults.scoreThreshold);
  out.risk_score_per_signal = readPositiveInt(draft.riskScorePerSignal, defaults.riskScorePerSignal);
  return out;
}

function writeTLSSignalsDraftWithBase(base: JSONRecord | null, draft: BotDefenseTLSSignalsDraft): JSONRecord {
  const defaults = createDefaultBotDefenseScopeState().tlsSignals;
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = draft.enabled;
  out.require_sni = draft.requireSNI;
  out.require_alpn = draft.requireALPN;
  out.require_modern_tls = draft.requireModernTLS;
  out.score_threshold = readPositiveInt(draft.scoreThreshold, defaults.scoreThreshold);
  out.risk_score_per_signal = readPositiveInt(draft.riskScorePerSignal, defaults.riskScorePerSignal);
  return out;
}

function writeQuarantineDraftWithBase(base: JSONRecord | null, draft: BotDefenseQuarantineDraft): JSONRecord {
  const defaults = createDefaultBotDefenseScopeState().quarantine;
  const out = base ? deepCloneRecord(base) : {};
  out.enabled = draft.enabled;
  out.threshold = readPositiveInt(draft.threshold, defaults.threshold);
  out.strikes_required = readPositiveInt(draft.strikesRequired, defaults.strikesRequired);
  out.strike_window_seconds = readPositiveInt(draft.strikeWindowSeconds, defaults.strikeWindowSeconds);
  out.ttl_seconds = readPositiveInt(draft.ttlSeconds, defaults.ttlSeconds);
  out.status_code = readStatusCode(draft.statusCode, defaults.statusCode);
  out.reputation_feedback_seconds = readNonNegativeInt(draft.reputationFeedbackSeconds, defaults.reputationFeedbackSeconds);
  return out;
}

function deleteLegacyBotDefenseRootKeys(value: JSONRecord) {
  delete value.enabled;
  delete value.dry_run;
  delete value.mode;
  delete value.path_prefixes;
  delete value.path_policies;
  delete value.exempt_cidrs;
  delete value.suspicious_user_agents;
  delete value.challenge_cookie_name;
  delete value.challenge_secret;
  delete value.challenge_ttl_seconds;
  delete value.challenge_status_code;
  delete value.behavioral_detection;
  delete value.browser_signals;
  delete value.device_signals;
  delete value.header_signals;
  delete value.tls_signals;
  delete value.quarantine;
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

function normalizePathPrefixes(values: string[], fallback: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    let normalized = value.trim();
    if (!normalized) {
      continue;
    }
    if (!normalized.startsWith("/")) {
      normalized = `/${normalized}`;
    }
    if (seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    out.push(normalized);
  }
  return out.length > 0 ? out : [...fallback];
}

function normalizeUserAgentList(values: string[], fallback: string[]): string[] {
  const out = values.map((value) => value.trim().toLowerCase()).filter(Boolean);
  const deduped = dedupeTrimmed(out);
  return deduped.length > 0 ? deduped : [...fallback];
}

function readBotDefenseMode(value: unknown, fallback: BotDefenseMode): BotDefenseMode {
  return typeof value === "string" && BOT_DEFENSE_MODE_OPTIONS.includes(value as BotDefenseMode) ? (value as BotDefenseMode) : fallback;
}

function readPolicyMode(value: unknown): BotDefensePolicyMode {
  return typeof value === "string" && BOT_DEFENSE_POLICY_MODE_OPTIONS.includes(value as BotDefensePolicyMode)
    ? (value as BotDefensePolicyMode)
    : "";
}

function readDryRunOverride(value: unknown): BotDefenseDryRunOverride {
  return typeof value === "boolean" ? (value ? "enabled" : "disabled") : "inherit";
}

function writeDryRunOverride(value: BotDefenseDryRunOverride): boolean | null {
  return value === "enabled" ? true : value === "disabled" ? false : null;
}

function readStringList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => (typeof item === "string" ? item.trim() : "")).filter(Boolean);
}

function dedupeTrimmed(values: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = value.trim();
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

function readBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function readString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function readPositiveInt(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.trunc(value) : fallback;
}

function readNonNegativeInt(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? Math.trunc(value) : fallback;
}

function readInt(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.trunc(value) : fallback;
}

function readStatusCode(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 400 && value <= 599 ? Math.trunc(value) : fallback;
}

function isRecord(value: unknown): value is JSONRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepCloneRecord(value: JSONRecord): JSONRecord {
  return JSON.parse(JSON.stringify(value)) as JSONRecord;
}
