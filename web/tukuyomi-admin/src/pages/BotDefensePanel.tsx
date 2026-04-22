import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import {
  ActionResultNotice,
  ActionButton,
  Alert,
  Badge,
  EmptyState,
  Field,
  MonoTag,
  NoticeBar,
  PrimaryButton,
  SectionCard,
  StatBox,
  inputClass,
  textareaClass,
} from "@/components/EditorChrome";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import {
  BOT_DEFENSE_DRY_RUN_OPTIONS,
  BOT_DEFENSE_MODE_OPTIONS,
  BOT_DEFENSE_POLICY_MODE_OPTIONS,
  createDefaultBotDefenseEditorState,
  createDefaultBotDefenseState,
  createEmptyBotDefenseHostScope,
  createEmptyBotDefensePathPolicy,
  parseBotDefenseEditorDocument,
  serializeBotDefenseEditor,
  type BotDefenseDryRunOverride,
  type BotDefenseEditorState,
  type BotDefensePathPolicyDraft,
  type BotDefenseScopeState,
} from "@/lib/botDefenseEditor";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";
import { parseSavedAt } from "@/lib/savedAt";

type BotDefenseDTO = {
  etag?: string;
  raw?: string;
  saved_at?: string;
};

type BotDecisionDTO = {
  timestamp?: string;
  request_id?: string;
  client_ip?: string;
  country?: string;
  method?: string;
  path?: string;
  user_agent?: string;
  host_scope?: string;
  flow_policy?: string;
  action?: string;
  dry_run?: boolean;
  status?: number;
  mode?: string;
  risk_score?: number;
  signals?: string[];
};

type BotDecisionListDTO = {
  items?: BotDecisionDTO[];
};

const exampleState: BotDefenseEditorState = {
  ...createDefaultBotDefenseEditorState(),
  enabled: true,
  pathPolicies: [
    {
      name: "login",
      pathPrefixes: ["/login", "/account/login"],
      mode: "always",
      dryRun: "enabled",
      riskScoreMultiplierPercent: 150,
      riskScoreOffset: 0,
      telemetryCookieRequired: true,
      disableQuarantine: false,
    },
  ],
  behavioralDetection: {
    enabled: true,
    windowSeconds: 60,
    burstThreshold: 12,
    pathFanoutThreshold: 6,
    uaChurnThreshold: 4,
    missingCookieThreshold: 6,
    scoreThreshold: 2,
    riskScorePerSignal: 2,
  },
  browserSignals: {
    enabled: true,
    jsCookieName: "__tukuyomi_bot_js",
    scoreThreshold: 1,
    riskScorePerSignal: 2,
  },
  headerSignals: {
    enabled: true,
    requireAcceptLanguage: true,
    requireFetchMetadata: true,
    requireClientHints: true,
    requireUpgradeInsecure: true,
    scoreThreshold: 2,
    riskScorePerSignal: 2,
  },
  hosts: [
    {
      ...createEmptyBotDefenseHostScope(1),
      host: "admin.example.com",
      enabled: true,
      dryRun: true,
      pathPrefixes: ["/admin"],
      pathPolicies: [
        {
          name: "admin-login",
          pathPrefixes: ["/admin/login"],
          mode: "always",
          dryRun: "disabled",
          riskScoreMultiplierPercent: 125,
          riskScoreOffset: 1,
          telemetryCookieRequired: true,
          disableQuarantine: false,
        },
      ],
    },
  ],
};

const exampleRaw = serializeBotDefenseEditor(exampleState);

export default function BotDefensePanel() {
  const { locale, tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [editorState, setEditorState] = useState<BotDefenseEditorState>(createDefaultBotDefenseState);
  const [editorBase, setEditorBase] = useState<Record<string, unknown>>({});
  const [defaultBase, setDefaultBase] = useState<Record<string, unknown>>({});
  const [defaultPathPolicyBases, setDefaultPathPolicyBases] = useState<Record<string, unknown>[]>([]);
  const [hostBases, setHostBases] = useState<Record<string, unknown>[]>([]);
  const [hostPathPolicyBases, setHostPathPolicyBases] = useState<Record<string, unknown>[][]>([]);
  const [raw, setRaw] = useState("");
  const [serverRaw, setServerRaw] = useState("");
  const [etag, setEtag] = useState<string | null>(null);
  const [valid, setValid] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
  const [recentDecisions, setRecentDecisions] = useState<BotDecisionDTO[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [rawError, setRawError] = useState<string | null>(null);
  const [structuredError, setStructuredError] = useState<string | null>(null);
  const [decisionsError, setDecisionsError] = useState<string | null>(null);

  const anyEnabled = useMemo(
    () => editorState.enabled || editorState.hosts.some((scope) => scope.enabled),
    [editorState.enabled, editorState.hosts],
  );
  const anyDryRun = useMemo(
    () => editorState.dryRun || editorState.hosts.some((scope) => scope.dryRun),
    [editorState.dryRun, editorState.hosts],
  );
  const totalPathPolicies = useMemo(
    () => editorState.pathPolicies.length + editorState.hosts.reduce((sum, scope) => sum + scope.pathPolicies.length, 0),
    [editorState.hosts, editorState.pathPolicies.length],
  );
  const dirty = useMemo(() => raw !== serverRaw || !!structuredError, [raw, serverRaw, structuredError]);
  const lineCount = useMemo(() => (raw ? raw.split(/\n/).length : 0), [raw]);

  const applyStructuredState = useCallback(
    (
      next: BotDefenseEditorState,
      nextDefaultPathPolicyBases = defaultPathPolicyBases,
      nextHostBases = hostBases,
      nextHostPathPolicyBases = hostPathPolicyBases,
    ) => {
      setEditorState(next);
      setDefaultPathPolicyBases(nextDefaultPathPolicyBases);
      setHostBases(nextHostBases);
      setHostPathPolicyBases(nextHostPathPolicyBases);
      try {
        setRaw(serializeBotDefenseEditor(editorBase, next, defaultBase, nextDefaultPathPolicyBases, nextHostBases, nextHostPathPolicyBases));
        setRawError(null);
        setStructuredError(null);
      } catch (e: unknown) {
        setValid(null);
        setMessages([]);
        setStructuredError(getErrorMessage(e, tx("Structured editor has conflicting host scopes.")));
      }
    },
    [defaultBase, defaultPathPolicyBases, editorBase, hostBases, hostPathPolicyBases, tx],
  );

  const applyStructuredDocument = useCallback(
    (
      base: Record<string, unknown>,
      next: BotDefenseEditorState,
      nextDefaultBase: Record<string, unknown>,
      nextDefaultPathPolicyBases: Record<string, unknown>[],
      nextHostBases: Record<string, unknown>[],
      nextHostPathPolicyBases: Record<string, unknown>[][],
    ) => {
      setEditorBase(base);
      setDefaultBase(nextDefaultBase);
      setEditorState(next);
      setDefaultPathPolicyBases(nextDefaultPathPolicyBases);
      setHostBases(nextHostBases);
      setHostPathPolicyBases(nextHostPathPolicyBases);
      setRaw(serializeBotDefenseEditor(base, next, nextDefaultBase, nextDefaultPathPolicyBases, nextHostBases, nextHostPathPolicyBases));
      setRawError(null);
      setStructuredError(null);
    },
    [],
  );

  const loadDecisions = useCallback(async () => {
    try {
      const decisions = await apiGetJson<BotDecisionListDTO>("/bot-defense-decisions?limit=8");
      setRecentDecisions(Array.isArray(decisions.items) ? decisions.items : []);
      setDecisionsError(null);
    } catch (e: unknown) {
      setDecisionsError(getErrorMessage(e, tx("Failed to load recent decisions")));
    }
  }, [tx]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGetJson<BotDefenseDTO>("/bot-defense-rules");
      const nextRaw = data.raw ?? "";
      const parsed = parseBotDefenseEditorDocument(nextRaw);
      setEditorBase(parsed.base);
      setDefaultBase(parsed.defaultBase);
      setDefaultPathPolicyBases(parsed.defaultPathPolicyBases);
      setHostBases(parsed.hostBases);
      setHostPathPolicyBases(parsed.hostPathPolicyBases);
      setEditorState(parsed.state);
      setRaw(nextRaw);
      setServerRaw(nextRaw);
      setEtag(data.etag ?? null);
      setValid(null);
      setMessages([]);
      setLastSavedAt(parseSavedAt(data.saved_at));
      setRawError(null);
      setStructuredError(null);
      await loadDecisions();
    } catch (e: unknown) {
      setError(getErrorMessage(e, tx("Failed to load")));
    } finally {
      setLoading(false);
    }
  }, [loadDecisions, tx]);

  useEffect(() => {
    void load();
  }, [load]);

  const debounceRef = useRef<number | null>(null);
  useEffect(() => {
    if (debounceRef.current) {
      window.clearTimeout(debounceRef.current);
    }
    if (loading || structuredError) {
      return;
    }
    debounceRef.current = window.setTimeout(async () => {
      try {
        const js = await apiPostJson<{ ok: boolean; messages?: string[] }>("/bot-defense-rules:validate", { raw });
        setValid(!!js.ok);
        setMessages(Array.isArray(js.messages) ? js.messages : []);
      } catch (e: unknown) {
        setValid(false);
        setMessages([getErrorMessage(e, tx("Validate failed"))]);
      }
    }, 300);
    return () => {
      if (debounceRef.current) {
        window.clearTimeout(debounceRef.current);
      }
    };
  }, [loading, raw, structuredError, tx]);

  const doSave = useCallback(async () => {
    setSaving(true);
    setError(null);
    try {
      const js = await apiPutJson<{ ok: boolean; etag?: string; saved_at?: string }>(
        "/bot-defense-rules",
        { raw },
        { headers: etag ? { "If-Match": etag } : {} },
      );
      if (!js.ok) {
        throw new Error(tx("Failed to save"));
      }
      const parsed = parseBotDefenseEditorDocument(raw);
      setEditorBase(parsed.base);
      setDefaultBase(parsed.defaultBase);
      setDefaultPathPolicyBases(parsed.defaultPathPolicyBases);
      setHostBases(parsed.hostBases);
      setHostPathPolicyBases(parsed.hostPathPolicyBases);
      setEditorState(parsed.state);
      setServerRaw(raw);
      setEtag(js.etag ?? null);
      setRawError(null);
      setStructuredError(null);
      setLastSavedAt(parseSavedAt(js.saved_at));
      await loadDecisions();
    } catch (e: unknown) {
      setError(getErrorMessage(e, tx("Save failed")));
    } finally {
      setSaving(false);
    }
  }, [etag, loadDecisions, raw, tx]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const isSave = (e.key === "s" || e.key === "S") && (e.ctrlKey || e.metaKey);
      if (!isSave) {
        return;
      }
      e.preventDefault();
      if (!saving && !readOnly && !rawError && !structuredError) {
        void doSave();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [doSave, rawError, readOnly, saving, structuredError]);

  const statusBadge = useMemo(() => {
    if (loading) {
      return <Badge color="gray">{tx("Loading")}</Badge>;
    }
    if (valid === null) {
      return <Badge color="gray">{tx("Unvalidated")}</Badge>;
    }
    return valid ? <Badge color="green">{tx("Valid")}</Badge> : <Badge color="red">{tx("Invalid")}</Badge>;
  }, [loading, tx, valid]);

  const updateHost = useCallback(
    (
      index: number,
      updater: (scope: BotDefenseEditorState["hosts"][number]) => BotDefenseEditorState["hosts"][number],
      nextHostBases = hostBases,
      nextHostPathPolicyBases = hostPathPolicyBases,
    ) => {
      const nextHosts = editorState.hosts.map((scope, currentIndex) => (currentIndex === index ? updater(scope) : scope));
      applyStructuredState(
        {
          ...editorState,
          hosts: nextHosts,
        },
        defaultPathPolicyBases,
        nextHostBases,
        nextHostPathPolicyBases,
      );
    },
    [applyStructuredState, defaultPathPolicyBases, editorState, hostBases, hostPathPolicyBases],
  );

  const handleRawChange = useCallback(
    (nextRaw: string) => {
      setRaw(nextRaw);
      try {
        const parsed = parseBotDefenseEditorDocument(nextRaw);
        setEditorBase(parsed.base);
        setDefaultBase(parsed.defaultBase);
        setDefaultPathPolicyBases(parsed.defaultPathPolicyBases);
        setHostBases(parsed.hostBases);
        setHostPathPolicyBases(parsed.hostPathPolicyBases);
        setEditorState(parsed.state);
        setRawError(null);
        setStructuredError(null);
      } catch (e: unknown) {
        setRawError(getErrorMessage(e, tx("Invalid")));
        setStructuredError(null);
      }
    },
    [tx],
  );

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Bot Defense")}</h1>
          <p className="text-sm text-neutral-500">
            {tx("Manage default and per-host bot-defense scopes with structured forms while keeping advanced JSON fallback and recent decision history below.")}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {statusBadge}
          {anyEnabled ? <Badge color="green">{tx("Enabled")}</Badge> : <Badge color="gray">{tx("Disabled")}</Badge>}
          {anyDryRun ? <Badge color="amber">{tx("Dry run in some scope")}</Badge> : null}
          <Badge color={rawError || structuredError ? "red" : "green"}>
            {structuredError ? tx("Structured editor conflict") : rawError ? tx("Raw JSON out of sync") : tx("Structured editor synced")}
          </Badge>
          {dirty ? <Badge color="amber">{tx("Unsaved")}</Badge> : null}
          {etag ? <MonoTag label="ETag" value={etag} /> : null}
        </div>
      </header>

      {error ? <Alert kind="error" title={tx("Error")} message={error} onClose={() => setError(null)} closeLabel={tx("Close")} /> : null}
      {rawError ? (
        <NoticeBar tone="warn">
          {tx("Advanced JSON is currently invalid. The structured editor is still showing the last valid bot-defense snapshot. Any structured edit will regenerate valid JSON from that snapshot.")}
        </NoticeBar>
      ) : null}
      {structuredError ? <NoticeBar tone="warn">{structuredError}</NoticeBar> : null}

      <SectionCard
        title={tx("Workflow")}
        subtitle={tx("Host scope precedence stays host:port, then host, then default. Save still uses the existing bot-defense validate and hot-reload API.")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ActionButton
              onClick={() => {
                const parsed = parseBotDefenseEditorDocument(exampleRaw);
                applyStructuredDocument(
                  parsed.base,
                  parsed.state,
                  parsed.defaultBase,
                  parsed.defaultPathPolicyBases,
                  parsed.hostBases,
                  parsed.hostPathPolicyBases,
                );
              }}
              disabled={loading}
            >
              {tx("Insert example")}
            </ActionButton>
            <ActionButton onClick={() => void load()} disabled={loading}>
              {tx("Refresh")}
            </ActionButton>
            <PrimaryButton onClick={() => void doSave()} disabled={readOnly || loading || saving || !dirty || !!rawError || !!structuredError}>
              {saving ? tx("Saving...") : tx("Save & hot reload")}
            </PrimaryButton>
          </div>
        }
      >
        <ActionResultNotice tone={valid === false ? "error" : "success"} messages={messages} />
        <div className="grid gap-3 md:grid-cols-4 xl:grid-cols-6">
          <StatBox label={tx("Default path scopes")} value={String(editorState.pathPrefixes.length)} />
          <StatBox label={tx("Total path policies")} value={String(totalPathPolicies)} />
          <StatBox label={tx("Host scopes")} value={String(editorState.hosts.length)} />
          <StatBox label={tx("Recent decisions")} value={String(recentDecisions.length)} />
          <StatBox label={tx("Default mode")} value={editorState.mode} />
          <StatBox
            label={tx("Last saved")}
            value={lastSavedAt ? new Date(lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") : "-"}
          />
        </div>
      </SectionCard>

      <SectionCard title={tx("Default Scope")} subtitle={tx("These bot-defense settings apply when no more specific host scope matches the request host.")}>
        <BotDefenseScopeEditor
          tx={tx}
          scope={editorState}
          pathPolicyBases={defaultPathPolicyBases}
          readOnly={readOnly}
          onChange={(nextScope, nextPathPolicyBases) =>
            applyStructuredState(
              {
                ...editorState,
                ...nextScope,
              },
              nextPathPolicyBases,
              hostBases,
              hostPathPolicyBases,
            )
          }
        />
      </SectionCard>

      <SectionCard
        title={tx("Host Scopes")}
        subtitle={tx("Use exact host or `host:port` patterns for overrides. Empty host cards are ignored until you fill the host field.")}
        actions={
          <ActionButton
            onClick={() =>
              applyStructuredState(
                {
                  ...editorState,
                  hosts: [...editorState.hosts, createEmptyBotDefenseHostScope(editorState.hosts.length + 1)],
                },
                defaultPathPolicyBases,
                [...hostBases, cloneJSONRecord(defaultBase)],
                [...hostPathPolicyBases, cloneJSONRecords(defaultPathPolicyBases)],
              )
            }
            disabled={readOnly}
          >
            {tx("Add host scope")}
          </ActionButton>
        }
      >
        {editorState.hosts.length === 0 ? <EmptyState>{tx("No host-specific bot-defense overrides yet.")}</EmptyState> : null}
        <div className="space-y-4">
          {editorState.hosts.map((scope, index) => (
            <div key={`bot-defense-host-${index}`} className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-medium">{scope.host || tx("New host scope")}</div>
                <ActionButton
                  onClick={() =>
                    applyStructuredState(
                      {
                        ...editorState,
                        hosts: editorState.hosts.filter((_, currentIndex) => currentIndex !== index),
                      },
                      defaultPathPolicyBases,
                      hostBases.filter((_, currentIndex) => currentIndex !== index),
                      hostPathPolicyBases.filter((_, currentIndex) => currentIndex !== index),
                    )
                  }
                  disabled={readOnly}
                >
                  {tx("Remove")}
                </ActionButton>
              </div>
              <Field label={tx("Host pattern")} hint={tx("Examples: `example.com`, `admin.example.com`, `example.com:8443`.")}>
                <input
                  className={inputClass}
                  value={scope.host}
                  onChange={(event) => updateHost(index, (current) => ({ ...current, host: event.target.value }))}
                  placeholder="admin.example.com"
                />
              </Field>
              <BotDefenseScopeEditor
                tx={tx}
                scope={scope}
                pathPolicyBases={hostPathPolicyBases[index] ?? []}
                readOnly={readOnly}
                onChange={(nextScope, nextPathPolicyBases) =>
                  updateHost(
                    index,
                    (current) => ({
                      ...current,
                      ...nextScope,
                    }),
                    hostBases,
                    hostPathPolicyBases.map((bases, currentIndex) => (currentIndex === index ? nextPathPolicyBases : bases)),
                  )
                }
              />
            </div>
          ))}
        </div>
      </SectionCard>

      <SectionCard
        title={tx("Recent Bot Decisions")}
        subtitle={tx("Recent challenge/quarantine events and high-risk allowed requests. Use this to understand why bot suspicion increased before tightening rollout.")}
        actions={
          <ActionButton onClick={() => void loadDecisions()} disabled={loading}>
            {tx("Refresh Decisions")}
          </ActionButton>
        }
      >
        {decisionsError ? <NoticeBar tone="warn">{decisionsError}</NoticeBar> : null}
        {recentDecisions.length === 0 ? (
          <EmptyState>{tx("No recent bot decisions.")}</EmptyState>
        ) : (
          <div className="space-y-2">
            {recentDecisions.map((item, index) => (
              <div key={`${item.timestamp ?? "decision"}-${index}`} className="rounded-xl border border-neutral-200 bg-neutral-50/70 px-3 py-2 text-xs">
                <div className="flex flex-wrap items-center gap-2 text-neutral-700">
                  <span className="font-semibold">
                    {item.action || tx("allow")}
                    {item.dry_run ? ` (${tx("dry-run")})` : ""}
                  </span>
                  <span>{tx("risk")} {item.risk_score ?? 0}</span>
                  {item.status ? <span>HTTP {item.status}</span> : null}
                  {item.host_scope ? <span>{tx("host")} {item.host_scope}</span> : null}
                  {item.flow_policy ? <span>{tx("policy")} {item.flow_policy}</span> : null}
                  {item.country ? <span>{item.country}</span> : null}
                  {item.client_ip ? <span>{item.client_ip}</span> : null}
                  {item.timestamp ? <span>{new Date(item.timestamp).toLocaleString(locale === "ja" ? "ja-JP" : "en-US")}</span> : null}
                </div>
                <div className="mt-1 font-mono text-neutral-600 break-all">
                  {item.method || tx("GET")} {item.path || "/"}
                </div>
                {Array.isArray(item.signals) && item.signals.length > 0 ? (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {item.signals.map((signal, signalIndex) => (
                      <span key={`${signal}-${signalIndex}`} className="rounded border border-neutral-200 bg-white px-2 py-0.5 text-[11px]">
                        {signal}
                      </span>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </SectionCard>

      <SectionCard title={tx("Advanced JSON")} subtitle={tx("Keep using raw JSON when needed. Structured edits and valid raw edits stay in sync.")}>
        <textarea
          className="w-full h-[360px] p-3 border rounded-xl font-mono text-sm leading-5 outline-none focus:ring-2 focus:ring-black/20"
          value={raw}
          onChange={(event) => handleRawChange(event.target.value)}
          spellCheck={false}
        />
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-neutral-500">
          <div className="flex items-center gap-3 flex-wrap">
            <span>{tx("Lines")}: {lineCount}</span>
            <span>{tx("Host scopes")}: {editorState.hosts.length}</span>
            <span>{tx("Default mode")}: {editorState.mode}</span>
            <span>{tx("Total path policies")}: {totalPathPolicies}</span>
            {lastSavedAt ? <span>{tx("Last saved: {time}", { time: new Date(lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") })}</span> : null}
          </div>
        </div>
      </SectionCard>
    </div>
  );
}

function BotDefenseScopeEditor({
  tx,
  scope,
  pathPolicyBases,
  readOnly,
  onChange,
}: {
  tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
  scope: BotDefenseScopeState;
  pathPolicyBases: Record<string, unknown>[];
  readOnly: boolean;
  onChange: (scope: BotDefenseScopeState, pathPolicyBases: Record<string, unknown>[]) => void;
}) {
  const pathPolicyDryRunCount = useMemo(
    () => scope.pathPolicies.filter((policy) => policy.dryRun === "enabled").length,
    [scope.pathPolicies],
  );
  const cookieNameConflict = useMemo(() => {
    const challengeCookie = scope.challengeCookieName.trim();
    const browserCookie = scope.browserSignals.jsCookieName.trim();
    if (!challengeCookie || !browserCookie) {
      return false;
    }
    return (scope.browserSignals.enabled || scope.deviceSignals.enabled) && challengeCookie === browserCookie;
  }, [scope.browserSignals.enabled, scope.browserSignals.jsCookieName, scope.challengeCookieName, scope.deviceSignals.enabled]);

  const applyScope = useCallback(
    (nextScope: BotDefenseScopeState, nextPathPolicyBases = pathPolicyBases) => {
      onChange(nextScope, nextPathPolicyBases);
    },
    [onChange, pathPolicyBases],
  );

  const updatePathPolicy = useCallback(
    (index: number, updater: (policy: BotDefensePathPolicyDraft) => BotDefensePathPolicyDraft, nextPathPolicyBases = pathPolicyBases) => {
      applyScope(
        {
          ...scope,
          pathPolicies: scope.pathPolicies.map((policy, currentIndex) => (currentIndex === index ? updater(policy) : policy)),
        },
        nextPathPolicyBases,
      );
    },
    [applyScope, pathPolicyBases, scope],
  );

  return (
    <div className="space-y-6">
      {scope.enabled && !scope.challengeSecret.trim() ? (
        <NoticeBar tone="warn">
          {tx("Challenge secret is empty. Runtime will generate an ephemeral secret for this scope, so active challenge cookies will rotate on restart.")}
        </NoticeBar>
      ) : null}
      {cookieNameConflict ? (
        <NoticeBar tone="warn">
          {tx("Challenge cookie name and browser telemetry cookie name must differ when browser or device signals are enabled.")}
        </NoticeBar>
      ) : null}

      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Core Policy")}</div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,0.9fr)_minmax(0,1.1fr)_minmax(0,1.1fr)]">
          <div className="space-y-4">
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.enabled} onChange={(event) => applyScope({ ...scope, enabled: event.target.checked })} />
              <span>{tx("Enable bot defense for this scope")}</span>
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.dryRun} onChange={(event) => applyScope({ ...scope, dryRun: event.target.checked })} />
              <span>{tx("Dry run all actions in this scope")}</span>
            </label>
            <Field label={tx("Mode")} hint={tx("`suspicious` challenges only suspicious or scored requests. `always` challenges all GET requests under the selected prefixes.")}>
              <select
                className={inputClass}
                value={scope.mode}
                onChange={(event) =>
                  applyScope({
                    ...scope,
                    mode: BOT_DEFENSE_MODE_OPTIONS.includes(event.target.value as BotDefenseScopeState["mode"])
                      ? (event.target.value as BotDefenseScopeState["mode"])
                      : "suspicious",
                  })
                }
              >
                {BOT_DEFENSE_MODE_OPTIONS.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <Field label={tx("Path prefixes")} hint={tx("One prefix per line. Requests outside these prefixes bypass bot defense entirely.")}>
            <textarea
              className={`${textareaClass} min-h-40`}
              value={listToMultiline(scope.pathPrefixes)}
              onChange={(event) => applyScope({ ...scope, pathPrefixes: multilineToList(event.target.value) })}
              placeholder="/"
              spellCheck={false}
            />
          </Field>
          <Field label={tx("Exempt CIDRs")} hint={tx("One IP or CIDR per line. Matching clients skip bot defense before path or signal evaluation.")}>
            <textarea
              className={`${textareaClass} min-h-40`}
              value={listToMultiline(scope.exemptCIDRs)}
              onChange={(event) => applyScope({ ...scope, exemptCIDRs: multilineToList(event.target.value) })}
              placeholder={"127.0.0.1/32\n10.0.0.0/8"}
              spellCheck={false}
            />
          </Field>
          <Field label={tx("Suspicious user-agent fragments")} hint={tx("Lowercase fragments matched against the request user-agent. One value per line.")}>
            <textarea
              className={`${textareaClass} min-h-40`}
              value={listToMultiline(scope.suspiciousUserAgents)}
              onChange={(event) => applyScope({ ...scope, suspiciousUserAgents: multilineToList(event.target.value) })}
              placeholder={"curl\nwget\npython-requests"}
              spellCheck={false}
            />
          </Field>
        </div>
      </div>

      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Challenge Settings")}</div>
        <div className="grid gap-4 xl:grid-cols-4">
          <Field label={tx("Challenge cookie name")}>
            <input
              className={inputClass}
              value={scope.challengeCookieName}
              onChange={(event) => applyScope({ ...scope, challengeCookieName: event.target.value })}
              placeholder="__tukuyomi_bot_ok"
            />
          </Field>
          <Field label={tx("Challenge secret")} hint={tx("Leave blank only if you intentionally want an ephemeral in-memory secret.")}>
            <input
              className={inputClass}
              value={scope.challengeSecret}
              onChange={(event) => applyScope({ ...scope, challengeSecret: event.target.value })}
              placeholder={tx("set a stable secret")}
            />
          </Field>
          <Field label={tx("Challenge TTL seconds")}>
            <input
              type="number"
              min={1}
              className={inputClass}
              value={scope.challengeTTLSeconds}
              onChange={(event) => applyScope({ ...scope, challengeTTLSeconds: readPositiveIntInput(event.target.value, 1) })}
            />
          </Field>
          <Field label={tx("Challenge status code")}>
            <input
              type="number"
              min={400}
              max={599}
              className={inputClass}
              value={scope.challengeStatusCode}
              onChange={(event) => applyScope({ ...scope, challengeStatusCode: clampStatusCode(event.target.value, 429) })}
            />
          </Field>
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-sm font-medium">{tx("Path Policies")}</div>
          <div className="flex items-center gap-2 text-xs text-neutral-500">
            <span>{tx("Policies")}: {scope.pathPolicies.length}</span>
            <span>{tx("Dry run")}: {pathPolicyDryRunCount}</span>
            <ActionButton
              onClick={() =>
                applyScope(
                  {
                    ...scope,
                    pathPolicies: [...scope.pathPolicies, createEmptyBotDefensePathPolicy(scope.pathPolicies.length + 1)],
                  },
                  [...pathPolicyBases, {}],
                )
              }
              disabled={readOnly}
            >
              {tx("Add path policy")}
            </ActionButton>
          </div>
        </div>
        {scope.pathPolicies.length === 0 ? <EmptyState>{tx("No path-policy overrides yet.")}</EmptyState> : null}
        <div className="space-y-4">
          {scope.pathPolicies.map((policy, index) => (
            <div key={`bot-policy-${index}`} className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-medium">{policy.name || `${tx("Policy")} ${index + 1}`}</div>
                <ActionButton
                  onClick={() =>
                    applyScope(
                      {
                        ...scope,
                        pathPolicies: scope.pathPolicies.filter((_, currentIndex) => currentIndex !== index),
                      },
                      pathPolicyBases.filter((_, currentIndex) => currentIndex !== index),
                    )
                  }
                  disabled={readOnly}
                >
                  {tx("Remove")}
                </ActionButton>
              </div>
              <div className="grid gap-4 xl:grid-cols-[minmax(220px,1fr)_minmax(180px,0.7fr)_minmax(180px,0.7fr)]">
                <Field label={tx("Name")}>
                  <input
                    className={inputClass}
                    value={policy.name}
                    onChange={(event) => updatePathPolicy(index, (current) => ({ ...current, name: event.target.value }))}
                    placeholder="login"
                  />
                </Field>
                <Field label={tx("Mode override")}>
                  <select
                    className={inputClass}
                    value={policy.mode}
                    onChange={(event) =>
                      updatePathPolicy(index, (current) => ({
                        ...current,
                        mode: BOT_DEFENSE_POLICY_MODE_OPTIONS.includes(event.target.value as BotDefensePathPolicyDraft["mode"])
                          ? (event.target.value as BotDefensePathPolicyDraft["mode"])
                          : "",
                      }))
                    }
                  >
                    <option value="">{tx("inherit")}</option>
                    {BOT_DEFENSE_MODE_OPTIONS.map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label={tx("Dry-run override")}>
                  <select
                    className={inputClass}
                    value={policy.dryRun}
                    onChange={(event) =>
                      updatePathPolicy(index, (current) => ({
                        ...current,
                        dryRun: BOT_DEFENSE_DRY_RUN_OPTIONS.includes(event.target.value as BotDefenseDryRunOverride)
                          ? (event.target.value as BotDefenseDryRunOverride)
                          : "inherit",
                      }))
                    }
                  >
                    <option value="inherit">{tx("inherit")}</option>
                    <option value="enabled">{tx("enabled")}</option>
                    <option value="disabled">{tx("disabled")}</option>
                  </select>
                </Field>
              </div>
              <Field label={tx("Path prefixes")} hint={tx("One path prefix per line. Policies without prefixes are invalid.")}>
                <textarea
                  className={`${textareaClass} min-h-28`}
                  value={listToMultiline(policy.pathPrefixes)}
                  onChange={(event) =>
                    updatePathPolicy(index, (current) => ({
                      ...current,
                      pathPrefixes: multilineToList(event.target.value),
                    }))
                  }
                  placeholder={"/login\n/account/login"}
                  spellCheck={false}
                />
              </Field>
              <div className="grid gap-4 lg:grid-cols-4">
                <Field label={tx("Risk multiplier %")}>
                  <input
                    type="number"
                    min={1}
                    className={inputClass}
                    value={policy.riskScoreMultiplierPercent}
                    onChange={(event) =>
                      updatePathPolicy(index, (current) => ({
                        ...current,
                        riskScoreMultiplierPercent: readPositiveIntInput(event.target.value, 1),
                      }))
                    }
                  />
                </Field>
                <Field label={tx("Risk offset")}>
                  <input
                    type="number"
                    className={inputClass}
                    value={policy.riskScoreOffset}
                    onChange={(event) =>
                      updatePathPolicy(index, (current) => ({
                        ...current,
                        riskScoreOffset: readIntInput(event.target.value, 0),
                      }))
                    }
                  />
                </Field>
                <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
                  <input
                    type="checkbox"
                    checked={policy.telemetryCookieRequired}
                    onChange={(event) =>
                      updatePathPolicy(index, (current) => ({
                        ...current,
                        telemetryCookieRequired: event.target.checked,
                      }))
                    }
                  />
                  <span>{tx("Require telemetry cookie")}</span>
                </label>
                <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
                  <input
                    type="checkbox"
                    checked={policy.disableQuarantine}
                    onChange={(event) =>
                      updatePathPolicy(index, (current) => ({
                        ...current,
                        disableQuarantine: event.target.checked,
                      }))
                    }
                  />
                  <span>{tx("Disable quarantine escalation")}</span>
                </label>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <SignalCard title={tx("Behavioral Detection")} enabled={scope.behavioralDetection.enabled} onEnabledChange={(checked) => applyScope({ ...scope, behavioralDetection: { ...scope.behavioralDetection, enabled: checked } })}>
          <NumberGrid
            fields={[
              { label: tx("Window seconds"), value: scope.behavioralDetection.windowSeconds, onChange: (value) => applyScope({ ...scope, behavioralDetection: { ...scope.behavioralDetection, windowSeconds: value } }) },
              { label: tx("Burst threshold"), value: scope.behavioralDetection.burstThreshold, onChange: (value) => applyScope({ ...scope, behavioralDetection: { ...scope.behavioralDetection, burstThreshold: value } }) },
              { label: tx("Path fanout threshold"), value: scope.behavioralDetection.pathFanoutThreshold, onChange: (value) => applyScope({ ...scope, behavioralDetection: { ...scope.behavioralDetection, pathFanoutThreshold: value } }) },
              { label: tx("UA churn threshold"), value: scope.behavioralDetection.uaChurnThreshold, onChange: (value) => applyScope({ ...scope, behavioralDetection: { ...scope.behavioralDetection, uaChurnThreshold: value } }) },
              { label: tx("Missing-cookie threshold"), value: scope.behavioralDetection.missingCookieThreshold, onChange: (value) => applyScope({ ...scope, behavioralDetection: { ...scope.behavioralDetection, missingCookieThreshold: value } }) },
              { label: tx("Score threshold"), value: scope.behavioralDetection.scoreThreshold, onChange: (value) => applyScope({ ...scope, behavioralDetection: { ...scope.behavioralDetection, scoreThreshold: value } }) },
              { label: tx("Risk per signal"), value: scope.behavioralDetection.riskScorePerSignal, onChange: (value) => applyScope({ ...scope, behavioralDetection: { ...scope.behavioralDetection, riskScorePerSignal: value } }) },
            ]}
          />
        </SignalCard>

        <SignalCard title={tx("Browser Signals")} enabled={scope.browserSignals.enabled} onEnabledChange={(checked) => applyScope({ ...scope, browserSignals: { ...scope.browserSignals, enabled: checked } })}>
          <div className="grid gap-4 lg:grid-cols-3">
            <Field label={tx("Telemetry cookie name")}>
              <input
                className={inputClass}
                value={scope.browserSignals.jsCookieName}
                onChange={(event) => applyScope({ ...scope, browserSignals: { ...scope.browserSignals, jsCookieName: event.target.value } })}
                placeholder="__tukuyomi_bot_js"
              />
            </Field>
            <Field label={tx("Score threshold")}>
              <input
                type="number"
                min={1}
                className={inputClass}
                value={scope.browserSignals.scoreThreshold}
                onChange={(event) => applyScope({ ...scope, browserSignals: { ...scope.browserSignals, scoreThreshold: readPositiveIntInput(event.target.value, 1) } })}
              />
            </Field>
            <Field label={tx("Risk per signal")}>
              <input
                type="number"
                min={1}
                className={inputClass}
                value={scope.browserSignals.riskScorePerSignal}
                onChange={(event) => applyScope({ ...scope, browserSignals: { ...scope.browserSignals, riskScorePerSignal: readPositiveIntInput(event.target.value, 1) } })}
              />
            </Field>
          </div>
        </SignalCard>

        <SignalCard title={tx("Device Signals")} enabled={scope.deviceSignals.enabled} onEnabledChange={(checked) => applyScope({ ...scope, deviceSignals: { ...scope.deviceSignals, enabled: checked } })}>
          <div className="grid gap-4 lg:grid-cols-3">
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.deviceSignals.requireTimeZone} onChange={(event) => applyScope({ ...scope, deviceSignals: { ...scope.deviceSignals, requireTimeZone: event.target.checked } })} />
              <span>{tx("Require time zone")}</span>
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.deviceSignals.requirePlatform} onChange={(event) => applyScope({ ...scope, deviceSignals: { ...scope.deviceSignals, requirePlatform: event.target.checked } })} />
              <span>{tx("Require platform")}</span>
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.deviceSignals.requireHardwareConcurrency} onChange={(event) => applyScope({ ...scope, deviceSignals: { ...scope.deviceSignals, requireHardwareConcurrency: event.target.checked } })} />
              <span>{tx("Require hardware concurrency")}</span>
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.deviceSignals.checkMobileTouch} onChange={(event) => applyScope({ ...scope, deviceSignals: { ...scope.deviceSignals, checkMobileTouch: event.target.checked } })} />
              <span>{tx("Check mobile touch")}</span>
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.deviceSignals.invisibleHTMLInjection} onChange={(event) => applyScope({ ...scope, deviceSignals: { ...scope.deviceSignals, invisibleHTMLInjection: event.target.checked } })} />
              <span>{tx("Inject invisible HTML telemetry")}</span>
            </label>
            <Field label={tx("Invisible max body bytes")}>
              <input
                type="number"
                min={1}
                className={inputClass}
                value={scope.deviceSignals.invisibleMaxBodyBytes}
                onChange={(event) => applyScope({ ...scope, deviceSignals: { ...scope.deviceSignals, invisibleMaxBodyBytes: readPositiveIntInput(event.target.value, 1) } })}
              />
            </Field>
            <Field label={tx("Score threshold")}>
              <input
                type="number"
                min={1}
                className={inputClass}
                value={scope.deviceSignals.scoreThreshold}
                onChange={(event) => applyScope({ ...scope, deviceSignals: { ...scope.deviceSignals, scoreThreshold: readPositiveIntInput(event.target.value, 1) } })}
              />
            </Field>
            <Field label={tx("Risk per signal")}>
              <input
                type="number"
                min={1}
                className={inputClass}
                value={scope.deviceSignals.riskScorePerSignal}
                onChange={(event) => applyScope({ ...scope, deviceSignals: { ...scope.deviceSignals, riskScorePerSignal: readPositiveIntInput(event.target.value, 1) } })}
              />
            </Field>
          </div>
        </SignalCard>

        <SignalCard title={tx("Header Signals")} enabled={scope.headerSignals.enabled} onEnabledChange={(checked) => applyScope({ ...scope, headerSignals: { ...scope.headerSignals, enabled: checked } })}>
          <div className="grid gap-4 lg:grid-cols-3">
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.headerSignals.requireAcceptLanguage} onChange={(event) => applyScope({ ...scope, headerSignals: { ...scope.headerSignals, requireAcceptLanguage: event.target.checked } })} />
              <span>{tx("Require Accept-Language")}</span>
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.headerSignals.requireFetchMetadata} onChange={(event) => applyScope({ ...scope, headerSignals: { ...scope.headerSignals, requireFetchMetadata: event.target.checked } })} />
              <span>{tx("Require Fetch Metadata")}</span>
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.headerSignals.requireClientHints} onChange={(event) => applyScope({ ...scope, headerSignals: { ...scope.headerSignals, requireClientHints: event.target.checked } })} />
              <span>{tx("Require client hints")}</span>
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.headerSignals.requireUpgradeInsecure} onChange={(event) => applyScope({ ...scope, headerSignals: { ...scope.headerSignals, requireUpgradeInsecure: event.target.checked } })} />
              <span>{tx("Require Upgrade-Insecure-Requests")}</span>
            </label>
            <Field label={tx("Score threshold")}>
              <input
                type="number"
                min={1}
                className={inputClass}
                value={scope.headerSignals.scoreThreshold}
                onChange={(event) => applyScope({ ...scope, headerSignals: { ...scope.headerSignals, scoreThreshold: readPositiveIntInput(event.target.value, 1) } })}
              />
            </Field>
            <Field label={tx("Risk per signal")}>
              <input
                type="number"
                min={1}
                className={inputClass}
                value={scope.headerSignals.riskScorePerSignal}
                onChange={(event) => applyScope({ ...scope, headerSignals: { ...scope.headerSignals, riskScorePerSignal: readPositiveIntInput(event.target.value, 1) } })}
              />
            </Field>
          </div>
        </SignalCard>

        <SignalCard title={tx("TLS Signals")} enabled={scope.tlsSignals.enabled} onEnabledChange={(checked) => applyScope({ ...scope, tlsSignals: { ...scope.tlsSignals, enabled: checked } })}>
          <div className="grid gap-4 lg:grid-cols-3">
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.tlsSignals.requireSNI} onChange={(event) => applyScope({ ...scope, tlsSignals: { ...scope.tlsSignals, requireSNI: event.target.checked } })} />
              <span>{tx("Require SNI")}</span>
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.tlsSignals.requireALPN} onChange={(event) => applyScope({ ...scope, tlsSignals: { ...scope.tlsSignals, requireALPN: event.target.checked } })} />
              <span>{tx("Require ALPN")}</span>
            </label>
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input type="checkbox" checked={scope.tlsSignals.requireModernTLS} onChange={(event) => applyScope({ ...scope, tlsSignals: { ...scope.tlsSignals, requireModernTLS: event.target.checked } })} />
              <span>{tx("Require modern TLS")}</span>
            </label>
            <Field label={tx("Score threshold")}>
              <input
                type="number"
                min={1}
                className={inputClass}
                value={scope.tlsSignals.scoreThreshold}
                onChange={(event) => applyScope({ ...scope, tlsSignals: { ...scope.tlsSignals, scoreThreshold: readPositiveIntInput(event.target.value, 1) } })}
              />
            </Field>
            <Field label={tx("Risk per signal")}>
              <input
                type="number"
                min={1}
                className={inputClass}
                value={scope.tlsSignals.riskScorePerSignal}
                onChange={(event) => applyScope({ ...scope, tlsSignals: { ...scope.tlsSignals, riskScorePerSignal: readPositiveIntInput(event.target.value, 1) } })}
              />
            </Field>
          </div>
        </SignalCard>
      </div>

      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Quarantine")}</div>
        <div className="grid gap-4 xl:grid-cols-3">
          <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
            <input type="checkbox" checked={scope.quarantine.enabled} onChange={(event) => applyScope({ ...scope, quarantine: { ...scope.quarantine, enabled: event.target.checked } })} />
            <span>{tx("Enable quarantine")}</span>
          </label>
          <Field label={tx("Quarantine status code")}>
            <input
              type="number"
              min={400}
              max={599}
              className={inputClass}
              value={scope.quarantine.statusCode}
              onChange={(event) => applyScope({ ...scope, quarantine: { ...scope.quarantine, statusCode: clampStatusCode(event.target.value, 403) } })}
            />
          </Field>
          <Field label={tx("IP reputation feedback seconds")} hint={tx("Use `0` to disable temporary IP reputation penalties when quarantine triggers.")}>
            <input
              type="number"
              min={0}
              className={inputClass}
              value={scope.quarantine.reputationFeedbackSeconds}
              onChange={(event) => applyScope({ ...scope, quarantine: { ...scope.quarantine, reputationFeedbackSeconds: readNonNegativeIntInput(event.target.value, 0) } })}
            />
          </Field>
        </div>
        <NumberGrid
          fields={[
            { label: tx("Threshold"), value: scope.quarantine.threshold, onChange: (value) => applyScope({ ...scope, quarantine: { ...scope.quarantine, threshold: value } }) },
            { label: tx("Strikes required"), value: scope.quarantine.strikesRequired, onChange: (value) => applyScope({ ...scope, quarantine: { ...scope.quarantine, strikesRequired: value } }) },
            { label: tx("Strike window seconds"), value: scope.quarantine.strikeWindowSeconds, onChange: (value) => applyScope({ ...scope, quarantine: { ...scope.quarantine, strikeWindowSeconds: value } }) },
            { label: tx("TTL seconds"), value: scope.quarantine.ttlSeconds, onChange: (value) => applyScope({ ...scope, quarantine: { ...scope.quarantine, ttlSeconds: value } }) },
          ]}
        />
      </div>
    </div>
  );
}

function SignalCard({
  title,
  enabled,
  onEnabledChange,
  children,
}: {
  title: string;
  enabled: boolean;
  onEnabledChange: (checked: boolean) => void;
  children: ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-medium">{title}</div>
        <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(event) => onEnabledChange(event.target.checked)} />
          <span>{enabled ? "on" : "off"}</span>
        </label>
      </div>
      {children}
    </div>
  );
}

function NumberGrid({
  fields,
}: {
  fields: Array<{
    label: string;
    value: number;
    onChange: (value: number) => void;
  }>;
}) {
  return (
    <div className="grid gap-4 lg:grid-cols-3 xl:grid-cols-4">
      {fields.map((field) => (
        <Field key={field.label} label={field.label}>
          <input
            type="number"
            min={0}
            className={inputClass}
            value={field.value}
            onChange={(event) => field.onChange(readPositiveIntInput(event.target.value, 1))}
          />
        </Field>
      ))}
    </div>
  );
}

function listToMultiline(values: string[]): string {
  return values.join("\n");
}

function multilineToList(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function readPositiveIntInput(value: string, fallback: number): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function readNonNegativeIntInput(value: string, fallback: number): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function readIntInput(value: string, fallback: number): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function clampStatusCode(value: string, fallback: number): number {
  const parsed = readIntInput(value, fallback);
  return Math.max(400, Math.min(599, parsed));
}

function cloneJSONRecord(value: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}

function cloneJSONRecords(values: Record<string, unknown>[]): Record<string, unknown>[] {
  return values.map((value) => cloneJSONRecord(value));
}
