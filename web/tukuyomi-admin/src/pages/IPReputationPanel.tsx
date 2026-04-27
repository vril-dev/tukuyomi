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
  createDefaultIPReputationEditorState,
  createDefaultIPReputationScopeState,
  createEmptyIPReputationHostScope,
  parseIPReputationEditorDocument,
  serializeIPReputationEditor,
  type IPReputationEditorState,
  type IPReputationScopeState,
} from "@/lib/ipReputationEditor";
import { useI18n } from "@/lib/i18n";
import { parseSavedAt } from "@/lib/savedAt";

type IPReputationDTO = {
  etag?: string;
  raw?: string;
  status?: {
    enabled?: boolean;
    feed_urls?: string[];
    last_refresh_at?: string;
    last_refresh_error?: string;
    effective_allow_count?: number;
    effective_block_count?: number;
    feed_allow_count?: number;
    feed_block_count?: number;
    dynamic_penalty_count?: number;
      block_status_code?: number;
      fail_open?: boolean;
  };
  saved_at?: string;
};

type IPReputationRuntimeStatus = {
  effectiveAllowCount: number;
  effectiveBlockCount: number;
  feedAllowCount: number;
  feedBlockCount: number;
  dynamicPenaltyCount: number;
  lastRefreshAt: string;
  lastRefreshError: string;
};

const exampleState: IPReputationEditorState = {
  ...createDefaultIPReputationEditorState(),
  enabled: true,
  feedURLs: ["https://feeds.example.invalid/ip-reputation.txt"],
  allowlist: ["127.0.0.1/32", "::1/128"],
  blocklist: ["203.0.113.0/24", "2001:db8:dead:beef::/64"],
  refreshIntervalSec: 900,
  requestTimeoutSec: 5,
  blockStatusCode: 403,
  failOpen: true,
  hosts: [
    {
      host: "admin.example.com",
      ...createDefaultIPReputationScopeState(),
      enabled: true,
      blockStatusCode: 451,
      failOpen: false,
      blocklist: ["198.51.100.0/24"],
    },
  ],
};

const exampleRaw = serializeIPReputationEditor(exampleState);

function createEmptyRuntimeStatus(): IPReputationRuntimeStatus {
  return {
    effectiveAllowCount: 0,
    effectiveBlockCount: 0,
    feedAllowCount: 0,
    feedBlockCount: 0,
    dynamicPenaltyCount: 0,
    lastRefreshAt: "",
    lastRefreshError: "",
  };
}

export default function IPReputationPanel() {
  const { locale, tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [editorState, setEditorState] = useState<IPReputationEditorState>(createDefaultIPReputationEditorState);
  const [editorBase, setEditorBase] = useState<Record<string, unknown>>({});
  const [defaultBase, setDefaultBase] = useState<Record<string, unknown>>({});
  const [hostBases, setHostBases] = useState<Record<string, unknown>[]>([]);
  const [runtimeStatus, setRuntimeStatus] = useState<IPReputationRuntimeStatus>(createEmptyRuntimeStatus);
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
    (next: IPReputationEditorState, nextHostBases = hostBases) => {
      setEditorState(next);
      setHostBases(nextHostBases);
      try {
        setRaw(serializeIPReputationEditor(editorBase, next, defaultBase, nextHostBases));
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
      next: IPReputationEditorState,
      nextDefaultBase: Record<string, unknown>,
      nextHostBases: Record<string, unknown>[],
    ) => {
      setEditorBase(base);
      setDefaultBase(nextDefaultBase);
      setEditorState(next);
      setHostBases(nextHostBases);
      setRaw(serializeIPReputationEditor(base, next, nextDefaultBase, nextHostBases));
      setStructuredError(null);
    },
    [],
  );

  const applyRuntimeStatus = useCallback((data?: IPReputationDTO) => {
    const status = data?.status ?? {};
    setRuntimeStatus({
      effectiveAllowCount: typeof status.effective_allow_count === "number" ? status.effective_allow_count : 0,
      effectiveBlockCount: typeof status.effective_block_count === "number" ? status.effective_block_count : 0,
      feedAllowCount: typeof status.feed_allow_count === "number" ? status.feed_allow_count : 0,
      feedBlockCount: typeof status.feed_block_count === "number" ? status.feed_block_count : 0,
      dynamicPenaltyCount: typeof status.dynamic_penalty_count === "number" ? status.dynamic_penalty_count : 0,
      lastRefreshAt: status.last_refresh_at ?? "",
      lastRefreshError: status.last_refresh_error ?? "",
    });
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGetJson<IPReputationDTO>("/ip-reputation");
      const nextRaw = data.raw ?? "";
      const parsed = parseIPReputationEditorDocument(nextRaw);
      setEditorBase(parsed.base);
      setDefaultBase(parsed.defaultBase);
      setHostBases(parsed.hostBases);
      setEditorState(parsed.state);
      setRaw(nextRaw);
      setServerRaw(nextRaw);
      setEtag(data.etag ?? null);
      setValid(null);
      setMessages([]);
      setLastSavedAt(parseSavedAt(data.saved_at));
      setStructuredError(null);
      applyRuntimeStatus(data);
    } catch (e: unknown) {
      setError(getErrorMessage(e, tx("Failed to load")));
    } finally {
      setLoading(false);
    }
  }, [applyRuntimeStatus, tx]);

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
        const js = await apiPostJson<{ ok: boolean; messages?: string[] }>("/ip-reputation:validate", { raw });
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
      const js = await apiPutJson<{ ok: boolean; etag?: string; status?: IPReputationDTO["status"]; saved_at?: string }>(
        "/ip-reputation",
        { raw },
        { headers: etag ? { "If-Match": etag } : {} },
      );
      if (!js.ok) {
        throw new Error(tx("Failed to save"));
      }
      const parsed = parseIPReputationEditorDocument(raw);
      setEditorBase(parsed.base);
      setDefaultBase(parsed.defaultBase);
      setHostBases(parsed.hostBases);
      setEditorState(parsed.state);
      setRaw(raw);
      setServerRaw(raw);
      setEtag(js.etag ?? null);
      setStructuredError(null);
      setLastSavedAt(parseSavedAt(js.saved_at));
      applyRuntimeStatus({ status: js.status, saved_at: js.saved_at });
    } catch (e: unknown) {
      setError(getErrorMessage(e, tx("Save failed")));
    } finally {
      setSaving(false);
    }
  }, [applyRuntimeStatus, etag, raw, tx]);

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
      updater: (scope: IPReputationEditorState["hosts"][number]) => IPReputationEditorState["hosts"][number],
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
          <h1 className="text-xl font-semibold">{tx("IP Reputation")}</h1>
          <p className="text-sm text-neutral-500">
            {tx("Manage default and per-host IP reputation scopes with structured controls.")}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {statusBadge}
          {anyEnabled ? <Badge color="green">{tx("Enabled")}</Badge> : <Badge color="gray">{tx("Disabled")}</Badge>}
          {editorState.failOpen ? <Badge color="amber">{tx("Default fail open")}</Badge> : <Badge color="red">{tx("Default fail closed")}</Badge>}
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
        subtitle={tx("Host scope precedence stays host:port, then host, then default. Save still uses the existing IP reputation validate and hot-reload API.")}
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
                const parsed = parseIPReputationEditorDocument(exampleRaw);
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
          <StatBox label={tx("Feeds")} value={String(editorState.feedURLs.length)} />
          <StatBox label={tx("Blocklist")} value={String(editorState.blocklist.length)} />
          <StatBox label={tx("Host scopes")} value={String(editorState.hosts.length)} />
          <StatBox
            label={tx("Last saved")}
            value={lastSavedAt ? new Date(lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") : "-"}
          />
        </div>
      </SectionCard>

      <SectionCard title={tx("Default Scope")} subtitle={tx("These IP reputation settings apply when no more specific host scope matches the request host.")}>
        <IPReputationScopeEditor
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
                  hosts: [...editorState.hosts, createEmptyIPReputationHostScope(editorState.hosts.length + 1)],
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
        {editorState.hosts.length === 0 ? <EmptyState>{tx("No host-specific IP reputation overrides yet.")}</EmptyState> : null}
        <div className="space-y-4">
          {editorState.hosts.map((scope, index) => (
            <div key={`ip-reputation-host-${index}`} className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4 space-y-4">
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
              <IPReputationScopeEditor
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

      <SectionCard
        title={tx("Runtime Status")}
        subtitle={tx("These counters currently reflect the live default-scope runtime snapshot after reload. Use them to confirm feed refresh and dynamic penalties are working as expected.")}
      >
        {runtimeStatus.lastRefreshError ? <NoticeBar tone="warn">{runtimeStatus.lastRefreshError}</NoticeBar> : null}
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          <StatBox label={tx("Effective allow")} value={String(runtimeStatus.effectiveAllowCount)} />
          <StatBox label={tx("Effective block")} value={String(runtimeStatus.effectiveBlockCount)} />
          <StatBox label={tx("Feed allow")} value={String(runtimeStatus.feedAllowCount)} />
          <StatBox label={tx("Feed block")} value={String(runtimeStatus.feedBlockCount)} />
          <StatBox label={tx("Dynamic penalties")} value={String(runtimeStatus.dynamicPenaltyCount)} />
          <StatBox
            label={tx("Last refresh")}
            value={runtimeStatus.lastRefreshAt ? new Date(runtimeStatus.lastRefreshAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") : "-"}
          />
        </div>
      </SectionCard>

    </div>
  );
}

function IPReputationScopeEditor({
  tx,
  scope,
  onChange,
}: {
  tx: (key: string, vars?: Record<string, string | number | boolean | null | undefined>) => string;
  scope: IPReputationScopeState;
  onChange: (scope: IPReputationScopeState) => void;
}) {
  const applyScope = useCallback(
    (nextScope: IPReputationScopeState) => {
      onChange(nextScope);
    },
    [onChange],
  );

  return (
    <div className="space-y-6">
      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Global Settings")}</div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]">
          <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={scope.enabled}
              onChange={(event) => applyScope({ ...scope, enabled: event.target.checked })}
            />
            <span>{tx("Enable IP reputation for this scope")}</span>
          </label>
          <label className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={scope.failOpen}
              onChange={(event) => applyScope({ ...scope, failOpen: event.target.checked })}
            />
            <span>{tx("Fail open on feed errors")}</span>
          </label>
          <Field label={tx("Block status code")}>
            <input
              type="number"
              min={400}
              max={599}
              className={inputClass}
              value={scope.blockStatusCode}
              onChange={(event) => applyScope({ ...scope, blockStatusCode: clampStatusCode(event.target.value) })}
            />
          </Field>
        </div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <Field label={tx("Refresh interval seconds")}>
            <input
              type="number"
              min={1}
              className={inputClass}
              value={scope.refreshIntervalSec}
              onChange={(event) => applyScope({ ...scope, refreshIntervalSec: readIntInput(event.target.value, 1) })}
            />
          </Field>
          <Field label={tx("Request timeout seconds")}>
            <input
              type="number"
              min={1}
              className={inputClass}
              value={scope.requestTimeoutSec}
              onChange={(event) => applyScope({ ...scope, requestTimeoutSec: readIntInput(event.target.value, 1) })}
            />
          </Field>
        </div>
      </div>

      <div className="space-y-4">
        <div className="text-sm font-medium">{tx("Lists")}</div>
        <div className="grid gap-4 xl:grid-cols-3">
          <Field label={tx("Feed URLs")} hint={tx("Plain text feeds are fetched in order. Leave empty if you only use static CIDRs.")}>
            <ParsedTextArea
              className={`${textareaClass} min-h-40`}
              value={scope.feedURLs}
              onValueChange={(next) => applyScope({ ...scope, feedURLs: next })}
              serialize={listToMultiline}
              parse={multilineToList}
              equals={stringListEqual}
              placeholder="https://feeds.example.invalid/ip-reputation.txt"
              spellCheck={false}
            />
          </Field>
          <Field label={tx("Allowlist")} hint={tx("One IP or CIDR per line. These entries bypass static, feed, and dynamic block decisions.")}>
            <ParsedTextArea
              className={`${textareaClass} min-h-40`}
              value={scope.allowlist}
              onValueChange={(next) => applyScope({ ...scope, allowlist: next })}
              serialize={listToMultiline}
              parse={multilineToList}
              equals={stringListEqual}
              placeholder={"127.0.0.1/32\n::1/128"}
              spellCheck={false}
            />
          </Field>
          <Field label={tx("Blocklist")} hint={tx("One IP or CIDR per line. These entries apply before feed results are merged.")}>
            <ParsedTextArea
              className={`${textareaClass} min-h-40`}
              value={scope.blocklist}
              onValueChange={(next) => applyScope({ ...scope, blocklist: next })}
              serialize={listToMultiline}
              parse={multilineToList}
              equals={stringListEqual}
              placeholder={"203.0.113.0/24\n2001:db8:dead:beef::/64"}
              spellCheck={false}
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

function clampStatusCode(value: string): number {
  const parsed = readIntInput(value, 403);
  return Math.max(400, Math.min(599, parsed));
}

function cloneJSONRecord(value: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}
