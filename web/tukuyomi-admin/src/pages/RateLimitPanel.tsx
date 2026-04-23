import { useCallback, useEffect, useMemo, useRef, useState } from "react";

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
import { useI18n } from "@/lib/i18n";
import {
  RATE_LIMIT_KEY_BY_OPTIONS,
  createDefaultRateLimitEditorState,
  createDefaultRateLimitScopeDraft,
  createEmptyRateLimitHostScope,
  createEmptyRateLimitRule,
  parseRateLimitEditorDocument,
  serializeRateLimitEditor,
  type RateLimitEditorState,
  type RateLimitPolicyDraft,
  type RateLimitRuleDraft,
  type RateLimitScopeDraft,
} from "@/lib/rateLimitEditor";
import { parseSavedAt } from "@/lib/savedAt";

type RateLimitDTO = {
  etag?: string;
  raw?: string;
  enabled?: boolean;
  rules?: number;
  saved_at?: string;
};

const exampleState: RateLimitEditorState = {
  ...createDefaultRateLimitEditorState(),
  allowlistIPs: [],
  allowlistCountries: [],
  rules: [
    {
      name: "login",
      matchType: "prefix",
      matchValue: "/login",
      methods: ["POST"],
      policy: {
        enabled: true,
        limit: 10,
        windowSeconds: 60,
        burst: 0,
        keyBy: "ip",
        action: {
          status: 429,
          retryAfterSeconds: 60,
        },
      },
    },
  ],
  hosts: [
    {
      host: "admin.example.com",
      ...createDefaultRateLimitScopeDraft(),
      defaultPolicy: {
        enabled: true,
        limit: 5,
        windowSeconds: 60,
        burst: 0,
        keyBy: "ip_country",
        action: {
          status: 429,
          retryAfterSeconds: 60,
        },
      },
      rules: [],
    },
  ],
};

const exampleRaw = serializeRateLimitEditor(exampleState);

export default function RateLimitPanel() {
  const { locale, tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [editorState, setEditorState] = useState<RateLimitEditorState>(createDefaultRateLimitEditorState);
  const [editorBase, setEditorBase] = useState<Record<string, unknown>>({});
  const [defaultBase, setDefaultBase] = useState<Record<string, unknown>>({});
  const [defaultRuleBases, setDefaultRuleBases] = useState<Record<string, unknown>[]>([]);
  const [hostBases, setHostBases] = useState<Record<string, unknown>[]>([]);
  const [hostRuleBases, setHostRuleBases] = useState<Record<string, unknown>[][]>([]);
  const [raw, setRaw] = useState("");
  const [serverRaw, setServerRaw] = useState("");
  const [etag, setEtag] = useState<string | null>(null);
  const [valid, setValid] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [structuredError, setStructuredError] = useState<string | null>(null);

  const ruleCount = useMemo(() => countRateLimitRules(editorState), [editorState]);
  const dirty = useMemo(() => raw !== serverRaw || !!structuredError, [raw, serverRaw, structuredError]);

  const applyStructuredState = useCallback(
    (
      next: RateLimitEditorState,
      nextDefaultRuleBases = defaultRuleBases,
      nextHostBases = hostBases,
      nextHostRuleBases = hostRuleBases,
    ) => {
      setEditorState(next);
      setDefaultRuleBases(nextDefaultRuleBases);
      setHostBases(nextHostBases);
      setHostRuleBases(nextHostRuleBases);
      try {
        setRaw(
          serializeRateLimitEditor(
            editorBase,
            next,
            defaultBase,
            nextDefaultRuleBases,
            nextHostBases,
            nextHostRuleBases,
          ),
        );
        setStructuredError(null);
      } catch (e: unknown) {
        setValid(null);
        setMessages([]);
        setStructuredError(getErrorMessage(e, tx("Structured editor has conflicting host scopes.")));
      }
    },
    [defaultBase, defaultRuleBases, editorBase, hostBases, hostRuleBases, tx],
  );

  const applyStructuredDocument = useCallback(
    (
      base: Record<string, unknown>,
      next: RateLimitEditorState,
      nextDefaultBase: Record<string, unknown>,
      nextDefaultRuleBases: Record<string, unknown>[],
      nextHostBases: Record<string, unknown>[],
      nextHostRuleBases: Record<string, unknown>[][],
    ) => {
      setEditorBase(base);
      setDefaultBase(nextDefaultBase);
      setEditorState(next);
      setDefaultRuleBases(nextDefaultRuleBases);
      setHostBases(nextHostBases);
      setHostRuleBases(nextHostRuleBases);
      setRaw(
        serializeRateLimitEditor(
          base,
          next,
          nextDefaultBase,
          nextDefaultRuleBases,
          nextHostBases,
          nextHostRuleBases,
        ),
      );
      setStructuredError(null);
    },
    [],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGetJson<RateLimitDTO>("/rate-limit-rules");
      const nextRaw = data.raw ?? "";
      const parsed = parseRateLimitEditorDocument(nextRaw);
      setEditorBase(parsed.base);
      setDefaultBase(parsed.defaultBase);
      setDefaultRuleBases(parsed.defaultRuleBases);
      setHostBases(parsed.hostBases);
      setHostRuleBases(parsed.hostRuleBases);
      setEditorState(parsed.state);
      setRaw(nextRaw);
      setServerRaw(nextRaw);
      setEtag(data.etag ?? null);
      setValid(null);
      setMessages([]);
      setLastSavedAt(parseSavedAt(data.saved_at));
      setStructuredError(null);
    } catch (e: unknown) {
      setError(getErrorMessage(e, String(e)));
    } finally {
      setLoading(false);
    }
  }, []);

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
        const js = await apiPostJson<{ ok: boolean; messages?: string[]; enabled?: boolean; rules?: number }>(
          "/rate-limit-rules:validate",
          { raw },
        );
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
      const js = await apiPutJson<{ ok: boolean; etag?: string; enabled?: boolean; rules?: number; saved_at?: string }>(
        "/rate-limit-rules",
        { raw },
        { headers: etag ? { "If-Match": etag } : {} },
      );
      if (!js.ok) {
        throw new Error(tx("Failed to save"));
      }
      const nextRaw = raw;
      const parsed = parseRateLimitEditorDocument(nextRaw);
      setEditorBase(parsed.base);
      setDefaultBase(parsed.defaultBase);
      setDefaultRuleBases(parsed.defaultRuleBases);
      setHostBases(parsed.hostBases);
      setHostRuleBases(parsed.hostRuleBases);
      setEditorState(parsed.state);
      setEtag(js.etag ?? null);
      setRaw(nextRaw);
      setServerRaw(nextRaw);
      setStructuredError(null);
      setLastSavedAt(parseSavedAt(js.saved_at));
    } catch (e: unknown) {
      setError(getErrorMessage(e, tx("Save failed")));
    } finally {
      setSaving(false);
    }
  }, [etag, raw, tx]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const isSave = (e.key === "s" || e.key === "S") && (e.ctrlKey || e.metaKey);
      if (!isSave) {
        return;
      }
      e.preventDefault();
      if (!saving && !readOnly && !structuredError) {
        void doSave();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [doSave, readOnly, saving, structuredError]);

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
      updater: (host: RateLimitEditorState["hosts"][number]) => RateLimitEditorState["hosts"][number],
      nextHostBases = hostBases,
      nextHostRuleBases = hostRuleBases,
    ) => {
      const nextHosts = editorState.hosts.map((host, currentIndex) => (currentIndex === index ? updater(host) : host));
      applyStructuredState(
        {
          ...editorState,
          hosts: nextHosts,
        },
        defaultRuleBases,
        nextHostBases,
        nextHostRuleBases,
      );
    },
    [applyStructuredState, defaultRuleBases, editorState, hostBases, hostRuleBases],
  );

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Rate Limit")}</h1>
          <p className="text-sm text-neutral-500">
            {tx("Edit default and per-host rate-limit policy scopes with structured controls.")}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {statusBadge}
          {editorState.enabled ? <Badge color="green">{tx("Enabled")}</Badge> : <Badge color="gray">{tx("Disabled")}</Badge>}
          <Badge color={structuredError ? "red" : "green"}>
            {structuredError ? tx("Structured editor conflict") : tx("Structured editor synced")}
          </Badge>
          {dirty ? <Badge color="amber">{tx("Unsaved")}</Badge> : null}
          {etag ? <MonoTag label="ETag" value={etag} /> : null}
        </div>
      </header>

      {error ? <Alert kind="error" title={tx("Error")} message={error} onClose={() => setError(null)} closeLabel={tx("Close")} /> : null}
      {structuredError ? <NoticeBar tone="warn">{structuredError}</NoticeBar> : null}

      <SectionCard
        title={tx("Workflow")}
        subtitle={tx("Structured edits validate, save, and hot reload through the existing rate-limit backend API.")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ActionButton
              onClick={() => {
                const parsed = parseRateLimitEditorDocument(exampleRaw);
                applyStructuredDocument(
                  parsed.base,
                  parsed.state,
                  parsed.defaultBase,
                  parsed.defaultRuleBases,
                  parsed.hostBases,
                  parsed.hostRuleBases,
                );
              }}
              disabled={loading}
            >
              {tx("Insert example")}
            </ActionButton>
            <ActionButton onClick={() => void load()} disabled={loading}>
              {tx("Refresh")}
            </ActionButton>
            <PrimaryButton onClick={() => void doSave()} disabled={readOnly || loading || saving || !dirty || !!structuredError}>
              {saving ? tx("Saving...") : tx("Save & hot reload")}
            </PrimaryButton>
          </div>
        }
      >
        <ActionResultNotice tone={valid === false ? "error" : "success"} messages={messages} />
        <div className="grid gap-3 md:grid-cols-4">
          <StatBox label={tx("Rules")} value={String(ruleCount)} />
          <StatBox label={tx("Host scopes")} value={String(editorState.hosts.length)} />
          <StatBox label={tx("Allowlist IPs")} value={String(editorState.allowlistIPs.length)} />
          <StatBox
            label={tx("Last saved")}
            value={lastSavedAt ? new Date(lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") : "-"}
          />
        </div>
      </SectionCard>

      <SectionCard
        title={tx("Default Scope")}
        subtitle={tx("These rate-limit settings apply when no more specific host scope matches the request host.")}
      >
        <RateLimitScopeEditor
          tx={tx}
          readOnly={readOnly}
          scope={editorState}
          ruleBases={defaultRuleBases}
          onChange={(nextScope, nextRuleBases = defaultRuleBases) =>
            applyStructuredState(
              {
                ...editorState,
                ...nextScope,
              },
              nextRuleBases,
              hostBases,
              hostRuleBases,
            )
          }
        />
      </SectionCard>

      <SectionCard
        title={tx("Host Scopes")}
        subtitle={tx("Requests use `host:port`, then bare `host`, then the default scope. Add host overrides only where they differ from the default scope.")}
        actions={
          <ActionButton
            onClick={() =>
              applyStructuredState(
                {
                  ...editorState,
                  hosts: [...editorState.hosts, createEmptyRateLimitHostScope(editorState.hosts.length + 1)],
                },
                defaultRuleBases,
                [...hostBases, cloneJSONRecord(defaultBase)],
                [...hostRuleBases, cloneRuleBases(defaultRuleBases)],
              )
            }
            disabled={readOnly}
          >
            {tx("Add host scope")}
          </ActionButton>
        }
      >
        {editorState.hosts.length === 0 ? <EmptyState>{tx("No host-specific rate-limit overrides yet.")}</EmptyState> : null}
        <div className="space-y-4">
          {editorState.hosts.map((scope, index) => (
            <div key={`rate-limit-host-${index}`} className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-medium">{scope.host || tx("New host scope")}</div>
                <ActionButton
                  onClick={() =>
                    applyStructuredState(
                      {
                        ...editorState,
                        hosts: editorState.hosts.filter((_, currentIndex) => currentIndex !== index),
                      },
                      defaultRuleBases,
                      hostBases.filter((_, currentIndex) => currentIndex !== index),
                      hostRuleBases.filter((_, currentIndex) => currentIndex !== index),
                    )
                  }
                  disabled={readOnly}
                >
                  {tx("Remove")}
                </ActionButton>
              </div>
              <Field label={tx("Host pattern")} hint={tx("Use exact host or `host:port`. Wildcards are not supported for request-security host scopes.")}>
                <input
                  className={inputClass}
                  value={scope.host}
                  onChange={(event) => updateHost(index, (current) => ({ ...current, host: event.target.value }))}
                  placeholder="admin.example.com"
                />
              </Field>
              <RateLimitScopeEditor
                tx={tx}
                readOnly={readOnly}
                scope={scope}
                ruleBases={hostRuleBases[index] ?? []}
                onChange={(nextScope, nextRuleBases = hostRuleBases[index] ?? []) =>
                  updateHost(
                    index,
                    (current) => ({
                      ...current,
                      ...nextScope,
                    }),
                    hostBases,
                    hostRuleBases.map((bases, currentIndex) => (currentIndex === index ? nextRuleBases : bases)),
                  )
                }
              />
            </div>
          ))}
        </div>
      </SectionCard>

    </div>
  );
}

function RateLimitScopeEditor({
  tx,
  readOnly,
  scope,
  ruleBases,
  onChange,
}: {
  tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
  readOnly: boolean;
  scope: RateLimitScopeDraft;
  ruleBases: Record<string, unknown>[];
  onChange: (scope: RateLimitScopeDraft, nextRuleBases?: Record<string, unknown>[]) => void;
}) {
  const applyScope = useCallback(
    (nextScope: RateLimitScopeDraft, nextRuleBases = ruleBases) => {
      onChange(nextScope, nextRuleBases);
    },
    [onChange, ruleBases],
  );

  const updateRule = useCallback(
    (index: number, updater: (rule: RateLimitRuleDraft) => RateLimitRuleDraft) => {
      applyScope({
        ...scope,
        rules: scope.rules.map((rule, currentIndex) => (currentIndex === index ? updater(rule) : rule)),
      });
    },
    [applyScope, scope],
  );

  return (
    <div className="space-y-6">
      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Global Settings")}</div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div className="space-y-4">
            <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
              <input
                type="checkbox"
                checked={scope.enabled}
                onChange={(event) => applyScope({ ...scope, enabled: event.target.checked })}
              />
              <span>{tx("Enable rate limiting for this scope")}</span>
            </label>
            <Field label={tx("Allowlist IPs")} hint={tx("One CIDR or IP per line. These clients bypass rate limiting before policy matching.")}>
              <textarea
                className={`${textareaClass} min-h-32`}
                value={listToMultiline(scope.allowlistIPs)}
                onChange={(event) => applyScope({ ...scope, allowlistIPs: multilineToList(event.target.value) })}
                placeholder={"127.0.0.1/32\n10.0.0.0/8"}
                spellCheck={false}
              />
            </Field>
          </div>
          <Field label={tx("Allowlist countries")} hint={tx("One ISO-3166 alpha-2 code per line. These countries bypass rate limiting when country metadata is available.")}>
            <textarea
              className={`${textareaClass} min-h-32`}
              value={listToMultiline(scope.allowlistCountries)}
              onChange={(event) => applyScope({ ...scope, allowlistCountries: multilineToList(event.target.value) })}
              placeholder={"JP\nUS"}
              spellCheck={false}
            />
          </Field>
        </div>
      </div>

      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Identity & Adaptive")}</div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]">
          <Field label={tx("Session cookie names")} hint={tx("When `key_by` uses `session`, these cookie names are checked in order.")}>
            <textarea
              className={textareaClass}
              value={listToMultiline(scope.sessionCookieNames)}
              onChange={(event) => applyScope({ ...scope, sessionCookieNames: multilineToList(event.target.value) })}
              spellCheck={false}
            />
          </Field>
          <Field label={tx("JWT header names")} hint={tx("Authorization-style headers searched for bearer tokens when `key_by` uses `jwt_sub`.")}>
            <textarea
              className={textareaClass}
              value={listToMultiline(scope.jwtHeaderNames)}
              onChange={(event) => applyScope({ ...scope, jwtHeaderNames: multilineToList(event.target.value) })}
              spellCheck={false}
            />
          </Field>
          <Field label={tx("JWT cookie names")} hint={tx("Cookies searched for JWTs when `key_by` uses `jwt_sub`.")}>
            <textarea
              className={textareaClass}
              value={listToMultiline(scope.jwtCookieNames)}
              onChange={(event) => applyScope({ ...scope, jwtCookieNames: multilineToList(event.target.value) })}
              spellCheck={false}
            />
          </Field>
        </div>
        <div className="grid gap-4 lg:grid-cols-4">
          <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={scope.adaptiveEnabled}
              onChange={(event) => applyScope({ ...scope, adaptiveEnabled: event.target.checked })}
            />
            <span>{tx("Enable adaptive shrinking")}</span>
          </label>
          <Field label={tx("Adaptive score threshold")}>
            <input
              type="number"
              min={1}
              className={inputClass}
              value={scope.adaptiveScoreThreshold}
              onChange={(event) => applyScope({ ...scope, adaptiveScoreThreshold: readIntInput(event.target.value, 1) })}
            />
          </Field>
          <Field label={tx("Adaptive limit factor %")}>
            <input
              type="number"
              min={1}
              className={inputClass}
              value={scope.adaptiveLimitFactorPercent}
              onChange={(event) => applyScope({ ...scope, adaptiveLimitFactorPercent: readIntInput(event.target.value, 1) })}
            />
          </Field>
          <Field label={tx("Adaptive burst factor %")}>
            <input
              type="number"
              min={0}
              className={inputClass}
              value={scope.adaptiveBurstFactorPercent}
              onChange={(event) => applyScope({ ...scope, adaptiveBurstFactorPercent: readIntInput(event.target.value, 0) })}
            />
          </Field>
        </div>
      </div>

      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Feedback Promotion")}</div>
        <div className="grid gap-4 lg:grid-cols-5">
          <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={scope.feedback.enabled}
              onChange={(event) =>
                applyScope({
                  ...scope,
                  feedback: { ...scope.feedback, enabled: event.target.checked },
                })
              }
            />
            <span>{tx("Enable feedback")}</span>
          </label>
          <Field label={tx("Strikes required")}>
            <input
              type="number"
              min={1}
              className={inputClass}
              value={scope.feedback.strikesRequired}
              onChange={(event) =>
                applyScope({
                  ...scope,
                  feedback: { ...scope.feedback, strikesRequired: readIntInput(event.target.value, 1) },
                })
              }
            />
          </Field>
          <Field label={tx("Strike window seconds")}>
            <input
              type="number"
              min={1}
              className={inputClass}
              value={scope.feedback.strikeWindowSeconds}
              onChange={(event) =>
                applyScope({
                  ...scope,
                  feedback: { ...scope.feedback, strikeWindowSeconds: readIntInput(event.target.value, 1) },
                })
              }
            />
          </Field>
          <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={scope.feedback.adaptiveOnly}
              onChange={(event) =>
                applyScope({
                  ...scope,
                  feedback: { ...scope.feedback, adaptiveOnly: event.target.checked },
                })
              }
            />
            <span>{tx("Adaptive only")}</span>
          </label>
          <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={scope.feedback.dryRun}
              onChange={(event) =>
                applyScope({
                  ...scope,
                  feedback: { ...scope.feedback, dryRun: event.target.checked },
                })
              }
            />
            <span>{tx("Dry run")}</span>
          </label>
        </div>
      </div>

      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Default Policy")}</div>
        <RateLimitPolicyEditor tx={tx} policy={scope.defaultPolicy} onChange={(policy) => applyScope({ ...scope, defaultPolicy: policy })} />
      </div>

      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-sm font-medium">{tx("Rules")}</div>
          <ActionButton
            onClick={() =>
              applyScope(
                {
                  ...scope,
                  rules: [...scope.rules, createEmptyRateLimitRule(scope.rules.length + 1)],
                },
                [...ruleBases, {}],
              )
            }
            disabled={readOnly}
          >
            {tx("Add rule")}
          </ActionButton>
        </div>
        {scope.rules.length === 0 ? <EmptyState>{tx("No path-specific rules yet.")}</EmptyState> : null}
        <div className="space-y-4">
          {scope.rules.map((rule, index) => (
            <div key={`rate-rule-${index}`} className="rounded-2xl border border-neutral-200 bg-white p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-medium">{rule.name || `${tx("Rule")} ${index + 1}`}</div>
                <ActionButton
                  onClick={() =>
                    applyScope(
                      {
                        ...scope,
                        rules: scope.rules.filter((_, currentIndex) => currentIndex !== index),
                      },
                      ruleBases.filter((_, currentIndex) => currentIndex !== index),
                    )
                  }
                  disabled={readOnly}
                >
                  {tx("Remove")}
                </ActionButton>
              </div>
              <div className="grid gap-4 xl:grid-cols-[minmax(220px,1fr)_minmax(160px,0.6fr)_minmax(0,1fr)]">
                <Field label={tx("Name")}>
                  <input
                    className={inputClass}
                    value={rule.name}
                    onChange={(event) => updateRule(index, (current) => ({ ...current, name: event.target.value }))}
                    placeholder="login"
                  />
                </Field>
                <Field label={tx("Match type")}>
                  <select
                    className={inputClass}
                    value={rule.matchType}
                    onChange={(event) =>
                      updateRule(index, (current) => ({
                        ...current,
                        matchType: readMatchType(event.target.value),
                      }))
                    }
                  >
                    <option value="prefix">prefix</option>
                    <option value="exact">exact</option>
                    <option value="regex">regex</option>
                  </select>
                </Field>
                <Field label={tx("Match value")}>
                  <input
                    className={inputClass}
                    value={rule.matchValue}
                    onChange={(event) => updateRule(index, (current) => ({ ...current, matchValue: event.target.value }))}
                    placeholder="/login"
                  />
                </Field>
              </div>
              <Field label={tx("Methods")} hint={tx("One HTTP method per line or separated by commas. Leave empty to match any method.")}>
                <textarea
                  className={textareaClass}
                  value={listToMultiline(rule.methods)}
                  onChange={(event) =>
                    updateRule(index, (current) => ({
                      ...current,
                      methods: multilineToList(event.target.value),
                    }))
                  }
                  placeholder={"POST\nGET"}
                  spellCheck={false}
                />
              </Field>
              <RateLimitPolicyEditor
                tx={tx}
                policy={rule.policy}
                onChange={(policy) =>
                  updateRule(index, (current) => ({
                    ...current,
                    policy,
                  }))
                }
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function RateLimitPolicyEditor({
  tx,
  policy,
  onChange,
}: {
  tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
  policy: RateLimitPolicyDraft;
  onChange: (policy: RateLimitPolicyDraft) => void;
}) {
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
        <input type="checkbox" checked={policy.enabled} onChange={(event) => onChange({ ...policy, enabled: event.target.checked })} />
        <span>{tx("Policy enabled")}</span>
      </label>
      <Field label={tx("Limit")}>
        <input type="number" min={0} className={inputClass} value={policy.limit} onChange={(event) => onChange({ ...policy, limit: readIntInput(event.target.value, 0) })} />
      </Field>
      <Field label={tx("Window seconds")}>
        <input
          type="number"
          min={0}
          className={inputClass}
          value={policy.windowSeconds}
          onChange={(event) => onChange({ ...policy, windowSeconds: readIntInput(event.target.value, 0) })}
        />
      </Field>
      <Field label={tx("Burst")}>
        <input type="number" min={0} className={inputClass} value={policy.burst} onChange={(event) => onChange({ ...policy, burst: readIntInput(event.target.value, 0) })} />
      </Field>
      <Field label={tx("Key by")}>
        <select
          className={inputClass}
          value={policy.keyBy}
          onChange={(event) =>
            onChange({
              ...policy,
              keyBy: RATE_LIMIT_KEY_BY_OPTIONS.includes(event.target.value as RateLimitPolicyDraft["keyBy"])
                ? (event.target.value as RateLimitPolicyDraft["keyBy"])
                : "ip",
            })
          }
        >
          {RATE_LIMIT_KEY_BY_OPTIONS.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </Field>
      <Field label={tx("Action status")}>
        <input
          type="number"
          min={400}
          max={599}
          className={inputClass}
          value={policy.action.status}
          onChange={(event) =>
            onChange({
              ...policy,
              action: { ...policy.action, status: readIntInput(event.target.value, 429) },
            })
          }
        />
      </Field>
      <Field label={tx("Retry after seconds")} hint={tx("Use `0` to let runtime derive the next window automatically.")}>
        <input
          type="number"
          min={0}
          className={inputClass}
          value={policy.action.retryAfterSeconds}
          onChange={(event) =>
            onChange({
              ...policy,
              action: { ...policy.action, retryAfterSeconds: readIntInput(event.target.value, 0) },
            })
          }
        />
      </Field>
    </div>
  );
}

function listToMultiline(values: string[]): string {
  return values.join("\n");
}

function multilineToList(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[\r\n,]+/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );
}

function readIntInput(value: string, fallback: number): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function readMatchType(value: string): RateLimitRuleDraft["matchType"] {
  return value === "exact" || value === "regex" ? value : "prefix";
}

function countRateLimitRules(state: RateLimitEditorState): number {
  return state.rules.length + state.hosts.reduce((total, scope) => total + scope.rules.length, 0);
}

function cloneJSONRecord(value: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}

function cloneRuleBases(value: Record<string, unknown>[]): Record<string, unknown>[] {
  return value.map((entry) => cloneJSONRecord(entry));
}

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}
