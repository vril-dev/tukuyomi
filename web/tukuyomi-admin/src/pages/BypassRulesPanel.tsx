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
} from "@/components/EditorChrome";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import {
  countBypassEntries,
  createEmptyBypassEntry,
  createEmptyBypassHostScope,
  createEmptyBypassRulesEditorState,
  parseBypassRulesEditorDocument,
  serializeBypassRulesEditor,
  type BypassRulesEditorState,
} from "@/lib/bypassRulesEditor";
import { getErrorMessage } from "@/lib/errors";
import { useI18n } from "@/lib/i18n";
import { parseSavedAt } from "@/lib/savedAt";

type BypassRulesDTO = {
  etag?: string;
  raw?: string;
  saved_at?: string;
};

const exampleState: BypassRulesEditorState = {
  defaultEntries: [
    { path: "/assets/", extraRule: "" },
    { path: "/search", extraRule: "" },
  ],
  hosts: [
    {
      host: "example.com",
      entries: [
        { path: "/internal/", extraRule: "" },
        { path: "/admin/login", extraRule: "" },
      ],
    },
  ],
};

const exampleRaw = serializeBypassRulesEditor(exampleState);

export default function BypassRulesPanel() {
  const { locale, tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [editorState, setEditorState] = useState<BypassRulesEditorState>(createEmptyBypassRulesEditorState);
  const [editorBase, setEditorBase] = useState<Record<string, unknown>>({});
  const [defaultEntryBases, setDefaultEntryBases] = useState<Record<string, unknown>[]>([]);
  const [hostBases, setHostBases] = useState<Record<string, unknown>[]>([]);
  const [hostEntryBases, setHostEntryBases] = useState<Record<string, unknown>[][]>([]);
  const [raw, setRaw] = useState("");
  const [serverRaw, setServerRaw] = useState("");
  const [etag, setEtag] = useState<string | null>(null);
  const [valid, setValid] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [structuredError, setStructuredError] = useState<string | null>(null);

  const totalEntries = useMemo(() => countBypassEntries(editorState), [editorState]);
  const dirty = useMemo(() => raw !== serverRaw || !!structuredError, [raw, serverRaw, structuredError]);

  const applyStructuredState = useCallback(
    (
      next: BypassRulesEditorState,
      nextDefaultEntryBases = defaultEntryBases,
      nextHostBases = hostBases,
      nextHostEntryBases = hostEntryBases,
    ) => {
      setEditorState(next);
      setDefaultEntryBases(nextDefaultEntryBases);
      setHostBases(nextHostBases);
        setHostEntryBases(nextHostEntryBases);
      try {
        setRaw(serializeBypassRulesEditor(editorBase, next, nextDefaultEntryBases, nextHostBases, nextHostEntryBases));
        setStructuredError(null);
      } catch (e: unknown) {
        setValid(null);
        setMessages([]);
        setStructuredError(getErrorMessage(e, tx("Structured editor has conflicting host scopes.")));
      }
    },
    [defaultEntryBases, editorBase, hostBases, hostEntryBases, tx],
  );

  const applyStructuredDocument = useCallback(
    (
      base: Record<string, unknown>,
      next: BypassRulesEditorState,
      nextDefaultEntryBases: Record<string, unknown>[],
      nextHostBases: Record<string, unknown>[],
      nextHostEntryBases: Record<string, unknown>[][],
    ) => {
      setEditorBase(base);
      setEditorState(next);
      setDefaultEntryBases(nextDefaultEntryBases);
      setHostBases(nextHostBases);
      setHostEntryBases(nextHostEntryBases);
      setRaw(serializeBypassRulesEditor(base, next, nextDefaultEntryBases, nextHostBases, nextHostEntryBases));
      setStructuredError(null);
    },
    [],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGetJson<BypassRulesDTO>("/bypass-rules");
      const nextRaw = data.raw ?? "";
      const parsed = parseBypassRulesEditorDocument(nextRaw);
      setEditorBase(parsed.base);
      setDefaultEntryBases(parsed.defaultEntryBases);
      setHostBases(parsed.hostBases);
      setHostEntryBases(parsed.hostEntryBases);
      setEditorState(parsed.state);
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
        const js = await apiPostJson<{ ok: boolean; messages?: string[] }>("/bypass-rules:validate", { raw });
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
      const js = await apiPutJson<{ ok: boolean; etag?: string; raw?: string; saved_at?: string }>(
        "/bypass-rules",
        { raw },
        { headers: etag ? { "If-Match": etag } : {} },
      );
      if (!js.ok) {
        throw new Error(tx("Failed to save"));
      }
      const nextRaw = typeof js.raw === "string" ? js.raw : raw;
      const parsed = parseBypassRulesEditorDocument(nextRaw);
      setEditorBase(parsed.base);
      setDefaultEntryBases(parsed.defaultEntryBases);
      setHostBases(parsed.hostBases);
      setHostEntryBases(parsed.hostEntryBases);
      setEditorState(parsed.state);
      setRaw(nextRaw);
      setServerRaw(nextRaw);
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

  const updateDefaultEntry = useCallback(
    (index: number, updater: (entry: BypassRulesEditorState["defaultEntries"][number]) => BypassRulesEditorState["defaultEntries"][number]) => {
      applyStructuredState({
        ...editorState,
        defaultEntries: editorState.defaultEntries.map((entry, currentIndex) => (currentIndex === index ? updater(entry) : entry)),
      });
    },
    [applyStructuredState, editorState],
  );

  const updateHost = useCallback(
    (index: number, updater: (scope: BypassRulesEditorState["hosts"][number]) => BypassRulesEditorState["hosts"][number]) => {
      applyStructuredState({
        ...editorState,
        hosts: editorState.hosts.map((scope, currentIndex) => (currentIndex === index ? updater(scope) : scope)),
      });
    },
    [applyStructuredState, editorState],
  );

  const updateHostEntry = useCallback(
    (
      hostIndex: number,
      entryIndex: number,
      updater: (entry: BypassRulesEditorState["hosts"][number]["entries"][number]) => BypassRulesEditorState["hosts"][number]["entries"][number],
    ) => {
      updateHost(hostIndex, (scope) => ({
        ...scope,
        entries: scope.entries.map((entry, currentIndex) => (currentIndex === entryIndex ? updater(entry) : entry)),
      }));
    },
    [updateHost],
  );

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Bypass Rules")}</h1>
          <p className="text-sm text-neutral-500">
            {tx("Edit default and host-scoped bypass entries with structured controls.")}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {statusBadge}
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
        subtitle={tx("Host scope precedence stays host:port, then host, then default. Save still uses the existing bypass validate and hot-reload API.")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ActionButton
              onClick={() => {
                const parsed = parseBypassRulesEditorDocument(exampleRaw);
                applyStructuredDocument(parsed.base, parsed.state, parsed.defaultEntryBases, parsed.hostBases, parsed.hostEntryBases);
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
          <StatBox label={tx("Entries")} value={String(totalEntries)} />
          <StatBox label={tx("Default entries")} value={String(editorState.defaultEntries.length)} />
          <StatBox label={tx("Host scopes")} value={String(editorState.hosts.length)} />
          <StatBox
            label={tx("Last saved")}
            value={lastSavedAt ? new Date(lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") : "-"}
          />
        </div>
      </SectionCard>

      <SectionCard
        title={tx("Default Scope")}
        subtitle={tx("These entries apply when no more specific host scope matches the request host.")}
        actions={
          <ActionButton
            onClick={() =>
              applyStructuredState(
                {
                  ...editorState,
                  defaultEntries: [...editorState.defaultEntries, createEmptyBypassEntry(editorState.defaultEntries.length + 1)],
                },
                [...defaultEntryBases, {}],
              )
            }
            disabled={readOnly}
          >
            {tx("Add entry")}
          </ActionButton>
        }
      >
        {editorState.defaultEntries.length === 0 ? <EmptyState>{tx("No default bypass entries yet.")}</EmptyState> : null}
        <div className="space-y-3">
          {editorState.defaultEntries.map((entry, index) => (
            <div key={`default-entry-${index}`} className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-medium">{entry.path || `${tx("Entry")} ${index + 1}`}</div>
                <ActionButton
                  onClick={() =>
                    applyStructuredState(
                      {
                        ...editorState,
                        defaultEntries: editorState.defaultEntries.filter((_, currentIndex) => currentIndex !== index),
                      },
                      defaultEntryBases.filter((_, currentIndex) => currentIndex !== index),
                    )
                  }
                  disabled={readOnly}
                >
                  {tx("Remove")}
                </ActionButton>
              </div>
              <div className="grid gap-3 lg:grid-cols-[minmax(220px,1fr)_minmax(0,1fr)]">
                <Field label={tx("Path")} hint={tx("Use path prefixes like `/assets/` or exact paths like `/login`.")}>
                  <input
                    className={inputClass}
                    value={entry.path}
                    onChange={(event) => updateDefaultEntry(index, (current) => ({ ...current, path: event.target.value }))}
                    placeholder="/assets/"
                  />
                </Field>
                <Field label={tx("Extra rule file")} hint={tx("Optional `.conf` file applied instead of a full bypass when you need a narrow override.")}>
                  <input
                    className={inputClass}
                    value={entry.extraRule}
                    onChange={(event) => updateDefaultEntry(index, (current) => ({ ...current, extraRule: event.target.value }))}
                    placeholder="conf/rules/override.conf"
                  />
                </Field>
              </div>
              {entry.extraRule ? <Badge color="amber">{entry.extraRule}</Badge> : null}
            </div>
          ))}
        </div>
      </SectionCard>

      <SectionCard
        title={tx("Host Scopes")}
        subtitle={tx("Use host or host:port patterns for overrides. Empty host cards are ignored until you fill in the host field.")}
        actions={
          <ActionButton
            onClick={() => {
              const nextHost = createEmptyBypassHostScope(editorState.hosts.length + 1);
              applyStructuredState(
                {
                  ...editorState,
                  hosts: [...editorState.hosts, nextHost],
                },
                defaultEntryBases,
                [...hostBases, {}],
                [...hostEntryBases, nextHost.entries.map(() => ({}))],
              );
            }}
            disabled={readOnly}
          >
            {tx("Add host scope")}
          </ActionButton>
        }
      >
        {editorState.hosts.length === 0 ? <EmptyState>{tx("No host-specific bypass overrides yet.")}</EmptyState> : null}
        <div className="space-y-4">
          {editorState.hosts.map((scope, hostIndex) => (
            <div key={`host-scope-${hostIndex}`} className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-medium">{scope.host || tx("New host scope")}</div>
                <div className="flex flex-wrap items-center gap-2">
                  <ActionButton
                    onClick={() =>
                      applyStructuredState(
                        {
                          ...editorState,
                          hosts: editorState.hosts.filter((_, currentIndex) => currentIndex !== hostIndex),
                        },
                        defaultEntryBases,
                        hostBases.filter((_, currentIndex) => currentIndex !== hostIndex),
                        hostEntryBases.filter((_, currentIndex) => currentIndex !== hostIndex),
                      )
                    }
                    disabled={readOnly}
                  >
                    {tx("Remove host")}
                  </ActionButton>
                  <ActionButton
                    onClick={() =>
                      applyStructuredState(
                        {
                          ...editorState,
                          hosts: editorState.hosts.map((currentScope, currentIndex) =>
                            currentIndex === hostIndex
                              ? {
                                  ...currentScope,
                                  entries: [...currentScope.entries, createEmptyBypassEntry(currentScope.entries.length + 1)],
                                }
                              : currentScope,
                          ),
                        },
                        defaultEntryBases,
                        hostBases,
                        hostEntryBases.map((bases, currentIndex) => (currentIndex === hostIndex ? [...bases, {}] : bases)),
                      )
                    }
                    disabled={readOnly}
                  >
                    {tx("Add entry")}
                  </ActionButton>
                </div>
              </div>
              <Field label={tx("Host")} hint={tx("Examples: `example.com`, `admin.example.com`, `example.com:8443`.")}>
                <input
                  className={inputClass}
                  value={scope.host}
                  onChange={(event) => updateHost(hostIndex, (current) => ({ ...current, host: event.target.value }))}
                  placeholder="example.com"
                />
              </Field>
              {scope.entries.length === 0 ? <EmptyState>{tx("This host scope has no entries yet.")}</EmptyState> : null}
              <div className="space-y-3">
                {scope.entries.map((entry, entryIndex) => (
                  <div key={`host-entry-${hostIndex}-${entryIndex}`} className="rounded-xl border border-neutral-200 bg-white p-3 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-sm font-medium">{entry.path || `${tx("Entry")} ${entryIndex + 1}`}</div>
                      <ActionButton
                        onClick={() =>
                          applyStructuredState(
                            {
                              ...editorState,
                              hosts: editorState.hosts.map((currentScope, currentIndex) =>
                                currentIndex === hostIndex
                                  ? {
                                      ...currentScope,
                                      entries: currentScope.entries.filter((_, currentEntryIndex) => currentEntryIndex !== entryIndex),
                                    }
                                  : currentScope,
                              ),
                            },
                            defaultEntryBases,
                            hostBases,
                            hostEntryBases.map((bases, currentIndex) =>
                              currentIndex === hostIndex ? bases.filter((_, currentEntryIndex) => currentEntryIndex !== entryIndex) : bases,
                            ),
                          )
                        }
                        disabled={readOnly}
                      >
                        {tx("Remove")}
                      </ActionButton>
                    </div>
                    <div className="grid gap-3 lg:grid-cols-[minmax(220px,1fr)_minmax(0,1fr)]">
                      <Field label={tx("Path")}>
                        <input
                          className={inputClass}
                          value={entry.path}
                          onChange={(event) =>
                            updateHostEntry(hostIndex, entryIndex, (current) => ({ ...current, path: event.target.value }))
                          }
                          placeholder="/internal/"
                        />
                      </Field>
                      <Field label={tx("Extra rule file")}>
                        <input
                          className={inputClass}
                          value={entry.extraRule}
                          onChange={(event) =>
                            updateHostEntry(hostIndex, entryIndex, (current) => ({ ...current, extraRule: event.target.value }))
                          }
                          placeholder="conf/rules/internal.conf"
                        />
                      </Field>
                    </div>
                    {entry.extraRule ? <Badge color="amber">{entry.extraRule}</Badge> : null}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </SectionCard>

    </div>
  );
}
