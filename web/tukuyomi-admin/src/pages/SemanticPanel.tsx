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
  ParsedTextArea,
  PrimaryButton,
  QuietActionButton,
  SectionCard,
  StatBox,
  inputClass,
  stringListEqual,
  textareaClass,
} from "@/components/EditorChrome";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import {
  SEMANTIC_MODE_OPTIONS,
  createDefaultSemanticEditorState,
  createDefaultSemanticScopeState,
  createEmptySemanticHostScope,
  parseSemanticEditorDocument,
  serializeSemanticEditor,
  type SemanticEditorState,
  type SemanticScopeState,
} from "@/lib/semanticEditor";
import { useI18n } from "@/lib/i18n";
import { parseSavedAt } from "@/lib/savedAt";

type SemanticStats = {
  inspected_requests?: number;
  scored_requests?: number;
  log_only_actions?: number;
  challenge_actions?: number;
  block_actions?: number;
};

type SemanticDTO = {
  etag?: string;
  raw?: string;
  stats?: SemanticStats;
  saved_at?: string;
};

const exampleState: SemanticEditorState = {
  ...createDefaultSemanticEditorState(),
  enabled: true,
  mode: "challenge",
  providerEnabled: true,
  providerName: "builtin_attack_family",
  providerTimeoutMS: 25,
  exemptPathPrefixes: ["/healthz", "/metrics"],
  logThreshold: 4,
  challengeThreshold: 7,
  blockThreshold: 9,
  maxInspectBody: 16 * 1024,
  hosts: [
    {
      host: "admin.example.com",
      ...createDefaultSemanticScopeState(),
      enabled: true,
      mode: "block",
      providerEnabled: true,
      challengeThreshold: 5,
      blockThreshold: 7,
    },
  ],
};

const exampleRaw = serializeSemanticEditor(exampleState);
const toggleCardClass = "flex min-h-9 items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-xs";
const policyGridClass = "grid max-w-[58rem] items-start gap-4 lg:grid-cols-[minmax(13rem,18rem)_minmax(12rem,18rem)_minmax(10rem,14rem)]";
const providerGridClass = "grid max-w-[60rem] items-start gap-4 lg:grid-cols-[minmax(13rem,18rem)_minmax(16rem,24rem)_minmax(10rem,14rem)]";
const thresholdGridClass = "grid max-w-[44rem] items-start gap-4 md:grid-cols-3";

export default function SemanticPanel() {
  const { locale, tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [editorState, setEditorState] = useState<SemanticEditorState>(createDefaultSemanticEditorState);
  const [editorBase, setEditorBase] = useState<Record<string, unknown>>({});
  const [defaultBase, setDefaultBase] = useState<Record<string, unknown>>({});
  const [hostBases, setHostBases] = useState<Record<string, unknown>[]>([]);
  const [stats, setStats] = useState<SemanticStats>({});
  const [raw, setRaw] = useState("");
  const [serverRaw, setServerRaw] = useState("");
  const [etag, setEtag] = useState<string | null>(null);
  const [valid, setValid] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [structuredError, setStructuredError] = useState<string | null>(null);

  const anyEnabled = useMemo(
    () => editorState.enabled || editorState.hosts.some((scope) => scope.enabled),
    [editorState.enabled, editorState.hosts],
  );
  const dirty = useMemo(() => raw !== serverRaw || !!structuredError, [raw, serverRaw, structuredError]);

  const applyStructuredState = useCallback(
    (next: SemanticEditorState, nextHostBases = hostBases) => {
      setEditorState(next);
      setHostBases(nextHostBases);
      try {
        setRaw(serializeSemanticEditor(editorBase, next, defaultBase, nextHostBases));
        setStructuredError(null);
      } catch (e: unknown) {
        setValid(null);
        setMessages([]);
        setStructuredError(getErrorMessage(e, tx("Structured editor has conflicting host scopes.")));
      }
    },
    [defaultBase, editorBase, hostBases, tx],
  );

  const applyStructuredDocument = useCallback(
    (
      base: Record<string, unknown>,
      next: SemanticEditorState,
      nextDefaultBase: Record<string, unknown>,
      nextHostBases: Record<string, unknown>[],
    ) => {
      setEditorBase(base);
      setDefaultBase(nextDefaultBase);
      setEditorState(next);
      setHostBases(nextHostBases);
      setRaw(serializeSemanticEditor(base, next, nextDefaultBase, nextHostBases));
      setStructuredError(null);
    },
    [],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGetJson<SemanticDTO>("/semantic-rules");
      const nextRaw = data.raw ?? "";
      const parsed = parseSemanticEditorDocument(nextRaw);
      setEditorBase(parsed.base);
      setDefaultBase(parsed.defaultBase);
      setHostBases(parsed.hostBases);
      setEditorState(parsed.state);
      setStats(data.stats ?? {});
      setRaw(nextRaw);
      setServerRaw(nextRaw);
      setEtag(data.etag ?? null);
      setValid(null);
      setMessages([]);
      setLastSavedAt(parseSavedAt(data.saved_at));
      setStructuredError(null);
    } catch (e: unknown) {
      setError(getErrorMessage(e, tx("Failed to load")));
    } finally {
      setLoading(false);
    }
  }, [tx]);

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
        const js = await apiPostJson<{ ok: boolean; messages?: string[] }>("/semantic-rules:validate", { raw });
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
        "/semantic-rules",
        { raw },
        { headers: etag ? { "If-Match": etag } : {} },
      );
      if (!js.ok) {
        throw new Error(tx("Failed to save"));
      }
      const parsed = parseSemanticEditorDocument(raw);
      setEditorBase(parsed.base);
      setDefaultBase(parsed.defaultBase);
      setHostBases(parsed.hostBases);
      setEditorState(parsed.state);
      setServerRaw(raw);
      setEtag(js.etag ?? null);
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
      updater: (scope: SemanticEditorState["hosts"][number]) => SemanticEditorState["hosts"][number],
      nextHostBases = hostBases,
    ) => {
      const nextHosts = editorState.hosts.map((scope, currentIndex) => (currentIndex === index ? updater(scope) : scope));
      applyStructuredState(
        {
          ...editorState,
          hosts: nextHosts,
        },
        nextHostBases,
      );
    },
    [applyStructuredState, editorState, hostBases],
  );

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Semantic Security")}</h1>
          <p className="text-xs text-neutral-500">
            {tx("Manage default and per-host semantic anomaly scopes with structured controls.")}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {statusBadge}
          {anyEnabled ? <Badge color="green">{tx("Enabled")}</Badge> : <Badge color="gray">{tx("Disabled")}</Badge>}
          <Badge color="gray">{tx("Default mode")}: {editorState.mode}</Badge>
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
        subtitle={tx("Host scope precedence stays host:port, then host, then default. Save still uses the existing semantic validate and hot-reload API.")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ActionButton onClick={() => void load()} disabled={loading}>
              {tx("Refresh")}
            </ActionButton>
            <PrimaryButton onClick={() => void doSave()} disabled={readOnly || loading || saving || !dirty || !!structuredError}>
              {saving ? tx("Saving...") : tx("Save & hot reload")}
            </PrimaryButton>
            <QuietActionButton
              onClick={() => {
                const parsed = parseSemanticEditorDocument(exampleRaw);
                applyStructuredDocument(parsed.base, parsed.state, parsed.defaultBase, parsed.hostBases);
              }}
              disabled={loading}
            >
              {tx("Insert example")}
            </QuietActionButton>
          </div>
        }
      >
        <ActionResultNotice tone={valid === false ? "error" : "success"} messages={messages} />
        <div className="grid gap-3 md:grid-cols-4">
          <StatBox label={tx("Exempt paths")} value={String(editorState.exemptPathPrefixes.length)} />
          <StatBox label={tx("Host scopes")} value={String(editorState.hosts.length)} />
          <StatBox label={tx("Provider timeout")} value={`${editorState.providerTimeoutMS} ms`} />
          <StatBox
            label={tx("Last saved")}
            value={lastSavedAt ? new Date(lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") : "-"}
          />
        </div>
      </SectionCard>

      <SectionCard title={tx("Default Scope")} subtitle={tx("These semantic anomaly settings apply when no more specific host scope matches the request host.")}>
        <SemanticScopeEditor
          tx={tx}
          scope={editorState}
          onChange={(nextScope) =>
            applyStructuredState({
              ...editorState,
              ...nextScope,
            })
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
                  hosts: [...editorState.hosts, createEmptySemanticHostScope(editorState.hosts.length + 1)],
                },
                [...hostBases, cloneJSONRecord(defaultBase)],
              )
            }
            disabled={readOnly}
          >
            {tx("Add host scope")}
          </ActionButton>
        }
      >
        {editorState.hosts.length === 0 ? <EmptyState>{tx("No host-specific semantic overrides yet.")}</EmptyState> : null}
        <div className="space-y-4">
          {editorState.hosts.map((scope, index) => (
            <div key={`semantic-host-${index}`} className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-medium">{scope.host || tx("New host scope")}</div>
                <ActionButton
                  onClick={() =>
                    applyStructuredState(
                      {
                        ...editorState,
                        hosts: editorState.hosts.filter((_, currentIndex) => currentIndex !== index),
                      },
                      hostBases.filter((_, currentIndex) => currentIndex !== index),
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
              <SemanticScopeEditor
                tx={tx}
                scope={scope}
                onChange={(nextScope) =>
                  updateHost(index, (current) => ({
                    ...current,
                    ...nextScope,
                  }))
                }
              />
            </div>
          ))}
        </div>
      </SectionCard>

      <SectionCard title={tx("Runtime Stats")} subtitle={tx("These counters aggregate the live semantic runtime after reload across all configured scopes.")}>
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-5">
          <StatBox label={tx("Inspected")} value={String(stats.inspected_requests ?? 0)} />
          <StatBox label={tx("Scored")} value={String(stats.scored_requests ?? 0)} />
          <StatBox label={tx("Log only")} value={String(stats.log_only_actions ?? 0)} />
          <StatBox label={tx("Challenges")} value={String(stats.challenge_actions ?? 0)} />
          <StatBox label={tx("Blocks")} value={String(stats.block_actions ?? 0)} />
        </div>
      </SectionCard>

    </div>
  );
}

function SemanticScopeEditor({
  tx,
  scope,
  onChange,
}: {
  tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
  scope: SemanticScopeState;
  onChange: (scope: SemanticScopeState) => void;
}) {
  const applyScope = useCallback(
    (nextScope: SemanticScopeState) => {
      onChange(nextScope);
    },
    [onChange],
  );

  return (
    <div className="space-y-6">
      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Policy")}</div>
        <div className={policyGridClass}>
          <div className="grid gap-1">
            <span className="text-xs font-medium">{tx("Semantic scoring")}</span>
            <label className={toggleCardClass}>
              <input
                type="checkbox"
                checked={scope.enabled}
                onChange={(event) => applyScope({ ...scope, enabled: event.target.checked })}
              />
              <span className="min-w-0 leading-5">{tx("Enable semantic scoring")}</span>
            </label>
          </div>
          <Field label={tx("Mode")}>
            <select
              className={inputClass}
              value={scope.mode}
              onChange={(event) =>
                applyScope({
                  ...scope,
                  mode: SEMANTIC_MODE_OPTIONS.includes(event.target.value as SemanticScopeState["mode"])
                    ? (event.target.value as SemanticScopeState["mode"])
                    : "off",
                })
              }
            >
              {SEMANTIC_MODE_OPTIONS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </Field>
          <Field label={tx("Max inspect body bytes")}>
            <input
              type="number"
              min={1}
              className={inputClass}
              value={scope.maxInspectBody}
              onChange={(event) => applyScope({ ...scope, maxInspectBody: readIntInput(event.target.value, 1) })}
            />
          </Field>
          <Field label={tx("Exempt path prefixes")} hint={tx("One path prefix per line. Matching paths skip semantic scoring entirely.")}>
            <ParsedTextArea
              className={`${textareaClass} min-h-28`}
              value={scope.exemptPathPrefixes}
              onValueChange={(next) => applyScope({ ...scope, exemptPathPrefixes: next })}
              serialize={listToMultiline}
              parse={multilineToList}
              equals={stringListEqual}
              placeholder={"/healthz\n/metrics"}
              spellCheck={false}
            />
          </Field>
        </div>
      </div>

      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Provider")}</div>
        <div className={providerGridClass}>
          <div className="grid gap-1">
            <span className="text-xs font-medium">{tx("Provider status")}</span>
            <label className={toggleCardClass}>
              <input
                type="checkbox"
                checked={scope.providerEnabled}
                onChange={(event) => applyScope({ ...scope, providerEnabled: event.target.checked })}
              />
              <span className="min-w-0 leading-5">{tx("Enable provider")}</span>
            </label>
          </div>
          <Field label={tx("Provider name")}>
            <input
              className={inputClass}
              value={scope.providerName}
              onChange={(event) => applyScope({ ...scope, providerName: event.target.value })}
              placeholder="builtin_attack_family"
            />
          </Field>
          <Field label={tx("Provider timeout ms")} hint={tx("Backend currently accepts values between 1 and 250 ms.")}>
            <input
              type="number"
              min={1}
              max={250}
              className={inputClass}
              value={scope.providerTimeoutMS}
              onChange={(event) => applyScope({ ...scope, providerTimeoutMS: clampProviderTimeout(event.target.value) })}
            />
          </Field>
        </div>
      </div>

      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Thresholds")}</div>
        <div className={thresholdGridClass}>
          <Field label={tx("Log threshold")}>
            <input
              type="number"
              min={1}
              className={inputClass}
              value={scope.logThreshold}
              onChange={(event) => applyScope({ ...scope, logThreshold: readIntInput(event.target.value, 1) })}
            />
          </Field>
          <Field label={tx("Challenge threshold")}>
            <input
              type="number"
              min={1}
              className={inputClass}
              value={scope.challengeThreshold}
              onChange={(event) => applyScope({ ...scope, challengeThreshold: readIntInput(event.target.value, 1) })}
            />
          </Field>
          <Field label={tx("Block threshold")}>
            <input
              type="number"
              min={1}
              className={inputClass}
              value={scope.blockThreshold}
              onChange={(event) => applyScope({ ...scope, blockThreshold: readIntInput(event.target.value, 1) })}
            />
          </Field>
        </div>
      </div>
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

function readIntInput(value: string, fallback: number): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function clampProviderTimeout(value: string): number {
  const parsed = readIntInput(value, 25);
  return Math.max(1, Math.min(250, parsed));
}

function cloneJSONRecord(value: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}
