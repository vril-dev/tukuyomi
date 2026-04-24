import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  ActionResultNotice,
  ActionButton,
  Alert,
  Badge,
  EmptyState,
  Field,
  MonoTag,
  PrimaryButton,
  SectionCard,
  StatBox,
  inputClass,
} from "@/components/EditorChrome";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import {
  countCacheRules,
  createDefaultCacheRule,
  createEmptyCacheRuleHostScope,
  createEmptyCacheRulesEditorState,
  parseCacheRulesEditorDocument,
  serializeCacheRulesEditor,
  toCacheRulesFile,
  type CacheRuleDraft,
  type CacheRuleHostScopeDraft,
  type CacheRulesEditorState,
  type CacheRulesFile,
} from "@/lib/cacheRulesEditor";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";
import { parseSavedAt } from "@/lib/savedAt";

type CacheRulesDTO = {
  etag?: string;
  raw?: string;
  rules?: CacheRulesFile;
  saved_at?: string;
};

type CacheStoreConfig = {
  enabled: boolean;
  store_dir: string;
  max_bytes: number;
  memory_enabled: boolean;
  memory_max_bytes: number;
  memory_max_entries: number;
};

type CacheStoreStats = {
  size_bytes?: number;
  entry_count?: number;
  hits_total?: number;
  misses_total?: number;
  stores_total?: number;
  evictions_total?: number;
  clears_total?: number;
  memory_enabled?: boolean;
  memory_max_bytes?: number;
  memory_max_entries?: number;
  memory_size_bytes?: number;
  memory_entry_count?: number;
  memory_hits_total?: number;
  memory_misses_total?: number;
  memory_stores_total?: number;
  memory_evictions_total?: number;
};

type CacheStoreDTO = {
  etag?: string;
  store?: CacheStoreConfig;
  stats?: CacheStoreStats;
};

type ValidateResp = {
  ok: boolean;
  messages?: string[];
};

type SaveResp = {
  ok: boolean;
  etag?: string;
  saved_at?: string;
};

const exampleState: CacheRulesEditorState = {
  defaultRules: [
    {
      kind: "ALLOW",
      match: { type: "prefix", value: "/assets/" },
      methods: ["GET", "HEAD"],
      ttl: 600,
      vary: ["Accept-Encoding"],
    },
    {
      kind: "DENY",
      match: { type: "prefix", value: "/tukuyomi-api/" },
      methods: ["GET", "HEAD"],
      ttl: 600,
      vary: [],
    },
  ],
  hosts: [
    {
      host: "admin.example.com",
      rules: [
        {
          kind: "DENY",
          match: { type: "prefix", value: "/" },
          methods: ["GET", "HEAD"],
          ttl: 600,
          vary: [],
        },
      ],
    },
  ],
};

const defaultStoreConfig: CacheStoreConfig = {
  enabled: true,
  store_dir: "cache/response",
  max_bytes: 2 * 1024 * 1024 * 1024,
  memory_enabled: false,
  memory_max_bytes: 256 * 1024 * 1024,
  memory_max_entries: 4096,
};

export default function CacheRulePanel() {
  const { locale, tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [editorState, setEditorState] = useState<CacheRulesEditorState>(createEmptyCacheRulesEditorState);
  const [raw, setRaw] = useState("");
  const [serverRaw, setServerRaw] = useState("");
  const [etag, setEtag] = useState<string | null>(null);
  const [storeEtag, setStoreEtag] = useState<string | null>(null);
  const [storeConfig, setStoreConfig] = useState<CacheStoreConfig>(defaultStoreConfig);
  const [storeStats, setStoreStats] = useState<CacheStoreStats>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingStore, setSavingStore] = useState(false);
  const [clearingStore, setClearingStore] = useState(false);
  const [validating, setValidating] = useState(false);
  const [valid, setValid] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [messagesTone, setMessagesTone] = useState<"success" | "error">("success");
  const [storeNotice, setStoreNotice] = useState<{ tone: "success" | "error"; messages: string[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
  const [serverStoreSig, setServerStoreSig] = useState("");

  const totalRules = useMemo(() => countCacheRules(editorState), [editorState]);
  const hostScopeCount = editorState.hosts.length;
  const dirty = useMemo(() => raw !== serverRaw, [raw, serverRaw]);
  const storeSig = useMemo(() => JSON.stringify(storeConfig), [storeConfig]);
  const storeDirty = storeSig !== serverStoreSig;

  const applyStructuredState = useCallback((next: CacheRulesEditorState) => {
    setEditorState(next);
    setRaw(serializeCacheRulesEditor(next));
  }, []);

  const applyStoreData = useCallback((storeData: CacheStoreDTO) => {
    const nextStore = storeData.store ?? defaultStoreConfig;
    setStoreEtag(storeData.etag ?? null);
    setStoreConfig(nextStore);
    setStoreStats(storeData.stats ?? {});
    setServerStoreSig(JSON.stringify(nextStore));
  }, []);

  const refreshStore = useCallback(async () => {
    const storeData = await apiGetJson<CacheStoreDTO>("/cache-store");
    applyStoreData(storeData);
  }, [applyStoreData]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rulesData, storeData] = await Promise.all([
        apiGetJson<CacheRulesDTO>("/cache-rules"),
        apiGetJson<CacheStoreDTO>("/cache-store"),
      ]);
      const nextRaw = rulesData.raw ?? serializeCacheRulesEditor(createEmptyCacheRulesEditorState());
      const nextState = parseCacheRulesEditorDocument(nextRaw);
      setEditorState(nextState);
      setRaw(nextRaw);
      setServerRaw(nextRaw);
      setEtag(rulesData.etag ?? null);
      applyStoreData(storeData);
      setLastSavedAt(parseSavedAt(rulesData.saved_at));
      setValid(null);
      setMessages([]);
      setMessagesTone("success");
      setStoreNotice(null);
    } catch (e: unknown) {
      setError(getErrorMessage(e, tx("Failed to load")));
    } finally {
      setLoading(false);
    }
  }, [applyStoreData, tx]);

  useEffect(() => {
    void load();
  }, [load]);

  const debounceRef = useRef<number | null>(null);
  useEffect(() => {
    if (debounceRef.current) {
      window.clearTimeout(debounceRef.current);
    }
    if (loading) {
      return;
    }
    debounceRef.current = window.setTimeout(async () => {
      try {
        const js = await apiPostJson<ValidateResp>("/cache-rules:validate", { rawMode: false, rules: toCacheRulesFile(editorState) });
        setValid(!!js.ok);
        setMessagesTone(js.ok ? "success" : "error");
        setMessages(Array.isArray(js.messages) ? js.messages : []);
      } catch (e: unknown) {
        setValid(false);
        setMessagesTone("error");
        setMessages([getErrorMessage(e, tx("Validate failed"))]);
      }
    }, 300);
    return () => {
      if (debounceRef.current) {
        window.clearTimeout(debounceRef.current);
      }
    };
  }, [editorState, loading, tx]);

  const validate = useCallback(async () => {
    setValidating(true);
    setMessages([]);
    try {
      const js = await apiPostJson<ValidateResp>("/cache-rules:validate", { rawMode: false, rules: toCacheRulesFile(editorState) });
      setValid(!!js.ok);
      const nextMessages = Array.isArray(js.messages) && js.messages.length > 0 ? js.messages : js.ok ? [tx("Validation passed.")] : [tx("Validation failed.")];
      setMessagesTone(js.ok ? "success" : "error");
      setMessages(nextMessages);
    } catch (e: unknown) {
      setValid(false);
      const nextMessage = getErrorMessage(e, tx("Validate failed"));
      setMessagesTone("error");
      setMessages([nextMessage]);
    } finally {
      setValidating(false);
    }
  }, [editorState, tx]);

  const save = useCallback(async () => {
    setSaving(true);
    setMessages([]);
    try {
      const js = await apiPutJson<SaveResp>("/cache-rules", { rawMode: false, rules: toCacheRulesFile(editorState) }, {
        headers: etag ? { "If-Match": etag } : {},
      });
      if (!js.ok) {
        throw new Error(tx("save failed"));
      }
      setEtag(js.etag ?? null);
      setLastSavedAt(parseSavedAt(js.saved_at));
      await load();
      setMessagesTone("success");
      setMessages([tx("Saved. Hot reload applied immediately.")]);
    } catch (e: unknown) {
      setMessagesTone("error");
      setMessages([getErrorMessage(e, tx("save failed"))]);
    } finally {
      setSaving(false);
    }
  }, [editorState, etag, load, tx]);

  const saveStore = useCallback(async () => {
    setSavingStore(true);
    setError(null);
    setStoreNotice(null);
    try {
      const js = await apiPutJson<{ ok: boolean; etag?: string }>("/cache-store", storeConfig, {
        headers: storeEtag ? { "If-Match": storeEtag } : {},
      });
      if (!js.ok) {
        throw new Error(tx("save failed"));
      }
      setStoreEtag(js.etag ?? null);
      await refreshStore();
      setStoreNotice({ tone: "success", messages: [tx("Cache store settings saved.")] });
    } catch (e: unknown) {
      setStoreNotice({ tone: "error", messages: [getErrorMessage(e, tx("save failed"))] });
    } finally {
      setSavingStore(false);
    }
  }, [refreshStore, storeConfig, storeEtag, tx]);

  const clearStore = useCallback(async () => {
    setClearingStore(true);
    setError(null);
    setStoreNotice(null);
    try {
      const js = await apiPostJson<{ ok: boolean; clear?: { cleared_entries?: number; cleared_bytes?: number } }>("/cache-store/clear", {});
      const clear = js.clear ?? {};
      const nextStoreNotice = {
        tone: "success" as const,
        messages: [
          tx("Cache cleared. entries={entries} bytes={bytes}", {
            entries: clear.cleared_entries ?? 0,
            bytes: clear.cleared_bytes ?? 0,
          }),
        ],
      };
      await refreshStore();
      setStoreNotice(nextStoreNotice);
    } catch (e: unknown) {
      setStoreNotice({ tone: "error", messages: [getErrorMessage(e, tx("clear failed"))] });
    } finally {
      setClearingStore(false);
    }
  }, [refreshStore, tx]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const isSave = (e.key === "s" || e.key === "S") && (e.ctrlKey || e.metaKey);
      if (!isSave) {
        return;
      }
      e.preventDefault();
      if (!saving && !readOnly) {
        void save();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [readOnly, save, saving]);

  const statusBadge = useMemo(() => {
    if (loading) {
      return <Badge color="gray">{tx("Loading")}</Badge>;
    }
    if (valid === null) {
      return <Badge color="gray">{tx("Unvalidated")}</Badge>;
    }
    return valid ? <Badge color="green">{tx("Valid")}</Badge> : <Badge color="red">{tx("Invalid")}</Badge>;
  }, [loading, tx, valid]);

  const updateDefaultRule = useCallback(
    (index: number, next: CacheRuleDraft) => {
      applyStructuredState({
        ...editorState,
        defaultRules: editorState.defaultRules.map((rule, currentIndex) => (currentIndex === index ? next : rule)),
      });
    },
    [applyStructuredState, editorState],
  );

  const updateHostScope = useCallback(
    (index: number, updater: (scope: CacheRuleHostScopeDraft) => CacheRuleHostScopeDraft) => {
      applyStructuredState({
        ...editorState,
        hosts: editorState.hosts.map((scope, currentIndex) => (currentIndex === index ? updater(scope) : scope)),
      });
    },
    [applyStructuredState, editorState],
  );

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Cache Rules")}</h1>
          <p className="text-sm text-neutral-500">
            {tx("Manage default and per-host cache policy rules with structured controls.")}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {statusBadge}
          <Badge color="green">{tx("Structured editor synced")}</Badge>
          {dirty ? <Badge color="amber">{tx("Unsaved")}</Badge> : null}
          {etag ? <MonoTag label="ETag" value={etag} /> : null}
        </div>
      </header>

      {error ? <Alert kind="error" title={tx("Error")} message={error} closeLabel={tx("Close")} onClose={() => setError(null)} /> : null}

      <SectionCard
        title={tx("Internal Cache Store")}
        subtitle={tx("Disk-backed cache for matched ALLOW rules.")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {storeDirty ? <Badge color="amber">{tx("Unsaved")}</Badge> : null}
            {storeEtag ? <MonoTag label={tx("Store ETag")} value={storeEtag} /> : null}
            <ActionButton onClick={() => void clearStore()} disabled={readOnly || loading || clearingStore}>
              {clearingStore ? tx("Clearing...") : tx("Clear All")}
            </ActionButton>
            <ActionButton onClick={() => void saveStore()} disabled={readOnly || loading || savingStore || !storeDirty}>
              {savingStore ? tx("Saving...") : tx("Save Store")}
            </ActionButton>
          </div>
        }
      >
        <ActionResultNotice tone={storeNotice?.tone || "success"} messages={storeNotice?.messages} />

        <div className="grid gap-3 md:grid-cols-3">
          <Field label={tx("Enabled")}>
            <label className="inline-flex items-center gap-2 rounded-xl border px-3 py-2">
              <input
                type="checkbox"
                checked={storeConfig.enabled}
                onChange={(e) => setStoreConfig((prev) => ({ ...prev, enabled: e.target.checked }))}
              />
              <span className="text-sm">{tx("Enable internal cache")}</span>
            </label>
          </Field>
          <Field label={tx("Store Directory")}>
            <input
              className={inputClass}
              value={storeConfig.store_dir}
              onChange={(e) => setStoreConfig((prev) => ({ ...prev, store_dir: e.target.value }))}
            />
          </Field>
          <Field label={tx("Max Bytes")}>
            <input
              type="number"
              className={inputClass}
              value={storeConfig.max_bytes}
              onChange={(e) =>
                setStoreConfig((prev) => ({
                  ...prev,
                  max_bytes: Number.isFinite(+e.target.value) ? parseInt(e.target.value || "0", 10) : 0,
                }))
              }
            />
          </Field>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          <Field label={tx("Memory Front")}>
            <label className="inline-flex items-center gap-2 rounded-xl border px-3 py-2">
              <input
                type="checkbox"
                checked={storeConfig.memory_enabled}
                onChange={(e) => setStoreConfig((prev) => ({ ...prev, memory_enabled: e.target.checked }))}
              />
              <span className="text-sm">{tx("Enable bounded L1 memory cache")}</span>
            </label>
          </Field>
          <Field label={tx("Memory Max Bytes")}>
            <input
              type="number"
              className={inputClass}
              value={storeConfig.memory_max_bytes}
              onChange={(e) =>
                setStoreConfig((prev) => ({
                  ...prev,
                  memory_max_bytes: Number.isFinite(+e.target.value) ? parseInt(e.target.value || "0", 10) : 0,
                }))
              }
            />
          </Field>
          <Field label={tx("Memory Max Entries")}>
            <input
              type="number"
              className={inputClass}
              value={storeConfig.memory_max_entries}
              onChange={(e) =>
                setStoreConfig((prev) => ({
                  ...prev,
                  memory_max_entries: Number.isFinite(+e.target.value) ? parseInt(e.target.value || "0", 10) : 0,
                }))
              }
            />
          </Field>
        </div>

        <div className="grid gap-2 md:grid-cols-3 xl:grid-cols-6 text-sm">
          <StatBox label={tx("Disk Entries")} value={String(storeStats.entry_count ?? 0)} />
          <StatBox label={tx("Disk Size")} value={String(storeStats.size_bytes ?? 0)} />
          <StatBox label={tx("Hits")} value={String(storeStats.hits_total ?? 0)} />
          <StatBox label={tx("Misses")} value={String(storeStats.misses_total ?? 0)} />
          <StatBox label={tx("Stores")} value={String(storeStats.stores_total ?? 0)} />
          <StatBox label={tx("Evictions")} value={String(storeStats.evictions_total ?? 0)} />
        </div>

        <div className="grid gap-2 md:grid-cols-3 xl:grid-cols-6 text-sm">
          <StatBox label={tx("L1 Enabled")} value={String(storeStats.memory_enabled ?? false)} />
          <StatBox label={tx("L1 Entries")} value={String(storeStats.memory_entry_count ?? 0)} />
          <StatBox label={tx("L1 Size")} value={String(storeStats.memory_size_bytes ?? 0)} />
          <StatBox label={tx("L1 Hits")} value={String(storeStats.memory_hits_total ?? 0)} />
          <StatBox label={tx("L1 Misses")} value={String(storeStats.memory_misses_total ?? 0)} />
          <StatBox label={tx("L1 Evictions")} value={String(storeStats.memory_evictions_total ?? 0)} />
        </div>
      </SectionCard>

      <SectionCard
        title={tx("Cache Rules")}
        subtitle={tx("Host-specific cache scopes replace the default scope for matching host requests.")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ActionButton onClick={() => applyStructuredState(exampleState)} disabled={readOnly || loading || saving}>
              {tx("Insert example")}
            </ActionButton>
            <ActionButton onClick={() => void load()} disabled={loading || saving}>
              {tx("Refresh")}
            </ActionButton>
            <ActionButton onClick={() => void validate()} disabled={loading || saving || validating}>
              {validating ? tx("Validating...") : tx("Validate")}
            </ActionButton>
            <PrimaryButton onClick={() => void save()} disabled={readOnly || loading || saving || !dirty}>
              {saving ? tx("Saving...") : tx("Save & hot reload")}
            </PrimaryButton>
          </div>
        }
      >
        <ActionResultNotice tone={messagesTone} messages={messages} />
        <SectionCard
          title={tx("Default Scope")}
          subtitle={tx("Applied when no host-specific cache scope matches the request host.")}
          actions={
            <ActionButton
              onClick={() =>
                applyStructuredState({
                  ...editorState,
                  defaultRules: [...editorState.defaultRules, createDefaultCacheRule(editorState.defaultRules.length + 1)],
                })
              }
              disabled={readOnly || loading || saving}
            >
              {tx("Add rule")}
            </ActionButton>
          }
        >
          <CacheRulesTable
            rules={editorState.defaultRules}
            readOnly={readOnly}
            tx={tx}
            onChange={updateDefaultRule}
            onDelete={(index) =>
              applyStructuredState({
                ...editorState,
                defaultRules: editorState.defaultRules.filter((_, currentIndex) => currentIndex !== index),
              })
            }
          />
        </SectionCard>

        <SectionCard
          title={tx("Host Scopes")}
          subtitle={tx("Exact host[:port] and host-specific cache rules replace the default scope for matching requests.")}
          actions={
            <ActionButton
              onClick={() =>
                applyStructuredState({
                  ...editorState,
                  hosts: [...editorState.hosts, createEmptyCacheRuleHostScope(editorState.hosts.length + 1)],
                })
              }
              disabled={readOnly || loading || saving}
            >
              {tx("Add host scope")}
            </ActionButton>
          }
        >
              {editorState.hosts.length === 0 ? (
                <EmptyState>{tx("No host scopes yet. Add one when a host needs cache rules that differ from the default scope.")}</EmptyState>
              ) : (
                <div className="space-y-4">
                  {editorState.hosts.map((scope, index) => (
                    <section key={`host-scope-${index}`} className="rounded-xl border border-neutral-200 p-4 space-y-3">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <Field label={tx("Host")} hint={tx("Exact host or host:port. Default ports collapse to the host-only scope.")}>
                          <input
                            className={inputClass}
                            value={scope.host}
                            onChange={(e) => updateHostScope(index, (current) => ({ ...current, host: e.target.value }))}
                            disabled={readOnly}
                            placeholder="admin.example.com"
                          />
                        </Field>
                        <div className="flex items-center gap-2 pt-6">
                          <ActionButton
                            onClick={() =>
                              updateHostScope(index, (current) => ({
                                ...current,
                                rules: [...current.rules, createDefaultCacheRule(current.rules.length + 1)],
                              }))
                            }
                            disabled={readOnly || loading || saving}
                          >
                            {tx("Add rule")}
                          </ActionButton>
                          <ActionButton
                            onClick={() =>
                              applyStructuredState({
                                ...editorState,
                                hosts: editorState.hosts.filter((_, currentIndex) => currentIndex !== index),
                              })
                            }
                            disabled={readOnly || loading || saving}
                          >
                            {tx("Remove host scope")}
                          </ActionButton>
                        </div>
                      </div>
                      <CacheRulesTable
                        rules={scope.rules}
                        readOnly={readOnly}
                        tx={tx}
                        onChange={(ruleIndex, nextRule) =>
                          updateHostScope(index, (current) => ({
                            ...current,
                            rules: current.rules.map((rule, currentRuleIndex) => (currentRuleIndex === ruleIndex ? nextRule : rule)),
                          }))
                        }
                        onDelete={(ruleIndex) =>
                          updateHostScope(index, (current) => ({
                            ...current,
                            rules: current.rules.filter((_, currentRuleIndex) => currentRuleIndex !== ruleIndex),
                          }))
                        }
                      />
                    </section>
                  ))}
                </div>
              )}
        </SectionCard>

        <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-neutral-500">
          <div className="flex flex-wrap items-center gap-3">
            <span>{tx("Rules")}: {totalRules}</span>
            <span>{tx("Host scopes")}: {hostScopeCount}</span>
            {lastSavedAt ? <span>{tx("Last saved: {time}", { time: new Date(lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") })}</span> : null}
          </div>
        </div>
      </SectionCard>
    </div>
  );
}

function CacheRulesTable({
  rules,
  readOnly,
  tx,
  onChange,
  onDelete,
}: {
  rules: CacheRuleDraft[];
  readOnly: boolean;
  tx: (key: string, vars?: Record<string, string | number>) => string;
  onChange: (index: number, next: CacheRuleDraft) => void;
  onDelete: (index: number) => void;
}) {
  if (rules.length === 0) {
    return <EmptyState>{tx("No rules")}</EmptyState>;
  }

  return (
    <div className="app-table-shell">
      <div className="app-table-scroll-shell overflow-auto">
        <table className="app-table min-w-[980px] w-full text-sm">
          <thead className="app-table-head">
            <tr>
              <th className="p-2 text-left border-b">{tx("Kind")}</th>
              <th className="p-2 text-left border-b">{tx("Match Type")}</th>
              <th className="p-2 text-left border-b">{tx("Value")}</th>
              <th className="p-2 text-left border-b">{tx("Methods")}</th>
              <th className="p-2 text-left border-b">{tx("TTL(s)")}</th>
              <th className="p-2 text-left border-b">{tx("Vary")}</th>
              <th className="p-2 text-center border-b w-28">{tx("Action")}</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule, index) => (
              <tr key={index}>
                <td className="p-1.5 border-b">
                  <select
                    value={rule.kind}
                    onChange={(e) => onChange(index, { ...rule, kind: e.target.value === "DENY" ? "DENY" : "ALLOW" })}
                    className={inputClass}
                    disabled={readOnly}
                  >
                    <option value="ALLOW">ALLOW</option>
                    <option value="DENY">DENY</option>
                  </select>
                </td>
                <td className="p-1.5 border-b">
                  <select
                    value={rule.match.type}
                    onChange={(e) => onChange(index, { ...rule, match: { ...rule.match, type: e.target.value as CacheRuleDraft["match"]["type"] } })}
                    className={inputClass}
                    disabled={readOnly}
                  >
                    <option value="prefix">prefix</option>
                    <option value="regex">regex</option>
                    <option value="exact">exact</option>
                  </select>
                </td>
                <td className="p-1.5 border-b">
                  <input
                    className={inputClass}
                    value={rule.match.value}
                    onChange={(e) => onChange(index, { ...rule, match: { ...rule.match, value: e.target.value } })}
                    disabled={readOnly}
                  />
                </td>
                <td className="p-1.5 border-b">
                  <input
                    className={inputClass}
                    value={rule.methods.join(",")}
                    onChange={(e) =>
                      onChange(index, {
                        ...rule,
                        methods: e.target.value
                          .split(",")
                          .map((value) => value.trim().toUpperCase())
                          .filter(Boolean),
                      })
                    }
                    placeholder={tx("GET,HEAD")}
                    disabled={readOnly}
                  />
                </td>
                <td className="p-1.5 border-b">
                  <input
                    type="number"
                    className={inputClass}
                    value={rule.ttl}
                    onChange={(e) =>
                      onChange(index, {
                        ...rule,
                        ttl: Number.isFinite(+e.target.value) ? parseInt(e.target.value || "0", 10) : 0,
                      })
                    }
                    disabled={readOnly}
                  />
                </td>
                <td className="p-1.5 border-b">
                  <input
                    className={inputClass}
                    value={rule.vary.join(",")}
                    onChange={(e) =>
                      onChange(index, {
                        ...rule,
                        vary: e.target.value
                          .split(",")
                          .map((value) => value.trim())
                          .filter(Boolean),
                      })
                    }
                    placeholder={tx("Accept-Encoding,Accept-Language")}
                    disabled={readOnly}
                  />
                </td>
                <td className="p-1.5 border-b text-center">
                  <ActionButton onClick={() => onDelete(index)} disabled={readOnly}>
                    {tx("Delete")}
                  </ActionButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
