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
import {
  collectCountryBlockCodes,
  countryCodesToMultiline,
  createEmptyCountryBlockEditorState,
  createEmptyCountryBlockHostScope,
  multilineToCountryCodes,
  parseCountryBlockEditorDocument,
  serializeCountryBlockEditor,
  type CountryBlockEditorState,
} from "@/lib/countryBlockEditor";
import { useI18n } from "@/lib/i18n";
import { parseSavedAt } from "@/lib/savedAt";

type CountryBlockDTO = {
  etag?: string;
  raw?: string;
  blocked?: string[];
  saved_at?: string;
};

const exampleState: CountryBlockEditorState = {
  defaultBlockedCountries: [],
  hosts: [
    {
      host: "example.com",
      blockedCountries: ["CN", "DE", "FR", "GB", "IN", "KR", "RU", "SG", "US"],
    },
    {
      host: "admin.example.com",
      blockedCountries: ["CN", "KR", "UNKNOWN", "US"],
    },
  ],
};

const exampleRaw = serializeCountryBlockEditor(exampleState);

export default function CountryBlockPanel() {
  const { locale, tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [editorState, setEditorState] = useState<CountryBlockEditorState>(createEmptyCountryBlockEditorState);
  const [editorBase, setEditorBase] = useState<Record<string, unknown>>({});
  const [hostBases, setHostBases] = useState<Record<string, unknown>[]>([]);
  const [raw, setRaw] = useState("");
  const [serverRaw, setServerRaw] = useState("");
  const [etag, setEtag] = useState<string | null>(null);
  const [valid, setValid] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rawError, setRawError] = useState<string | null>(null);
  const [structuredError, setStructuredError] = useState<string | null>(null);

  const blocked = useMemo(() => collectCountryBlockCodes(editorState), [editorState]);
  const dirty = useMemo(() => raw !== serverRaw || !!structuredError, [raw, serverRaw, structuredError]);
  const lineCount = useMemo(() => (raw ? raw.split(/\n/).length : 0), [raw]);

  const applyStructuredState = useCallback((next: CountryBlockEditorState, nextHostBases = hostBases) => {
    setEditorState(next);
    setHostBases(nextHostBases);
    try {
      setRaw(serializeCountryBlockEditor(editorBase, next, nextHostBases));
      setRawError(null);
      setStructuredError(null);
    } catch (e: unknown) {
      setValid(null);
      setMessages([]);
      setStructuredError(getErrorMessage(e, tx("Structured editor has conflicting host scopes.")));
    }
  }, [editorBase, hostBases, tx]);

  const applyStructuredDocument = useCallback(
    (base: Record<string, unknown>, next: CountryBlockEditorState, nextHostBases: Record<string, unknown>[]) => {
      setEditorBase(base);
      setEditorState(next);
      setHostBases(nextHostBases);
      setRaw(serializeCountryBlockEditor(base, next, nextHostBases));
      setRawError(null);
      setStructuredError(null);
    },
    [],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGetJson<CountryBlockDTO>("/country-block-rules");
      const nextRaw = data.raw ?? "";
      const parsed = parseCountryBlockEditorDocument(nextRaw);
      setEditorBase(parsed.base);
      setHostBases(parsed.hostBases);
      setEditorState(parsed.state);
      setRaw(nextRaw);
      setServerRaw(nextRaw);
      setEtag(data.etag ?? null);
      setValid(null);
      setMessages([]);
      setLastSavedAt(parseSavedAt(data.saved_at));
      setRawError(null);
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
        const js = await apiPostJson<{ ok: boolean; messages?: string[] }>("/country-block-rules:validate", { raw });
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
        "/country-block-rules",
        { raw },
        { headers: etag ? { "If-Match": etag } : {} },
      );
      if (!js.ok) {
        throw new Error(tx("Failed to save"));
      }
      const nextRaw = typeof js.raw === "string" ? js.raw : raw;
      const parsed = parseCountryBlockEditorDocument(nextRaw);
      setEditorBase(parsed.base);
      setHostBases(parsed.hostBases);
      setEditorState(parsed.state);
      setRaw(nextRaw);
      setServerRaw(nextRaw);
      setEtag(js.etag ?? null);
      setRawError(null);
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
    (index: number, updater: (current: CountryBlockEditorState["hosts"][number]) => CountryBlockEditorState["hosts"][number]) => {
      const next = editorState.hosts.map((scope, currentIndex) => (currentIndex === index ? updater(scope) : scope));
      applyStructuredState({ ...editorState, hosts: next });
    },
    [applyStructuredState, editorState],
  );

  const handleRawChange = useCallback(
    (nextRaw: string) => {
      setRaw(nextRaw);
      try {
        const parsed = parseCountryBlockEditorDocument(nextRaw);
        setEditorBase(parsed.base);
        setHostBases(parsed.hostBases);
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
          <h1 className="text-xl font-semibold">{tx("Country Block")}</h1>
          <p className="text-sm text-neutral-500">
            {tx("Manage default and per-host blocked country lists with a structured editor, then keep advanced JSON available below.")}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {statusBadge}
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
          {tx("Advanced JSON is currently invalid. The structured editor is still showing the last valid country-block snapshot. Any structured edit will regenerate valid JSON from that snapshot.")}
        </NoticeBar>
      ) : null}
      {structuredError ? <NoticeBar tone="warn">{structuredError}</NoticeBar> : null}

      <SectionCard
        title={tx("Workflow")}
        subtitle={tx("Host scope precedence stays host:port, then host, then default. Save still uses the existing country-block validate and hot-reload API.")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ActionButton
              onClick={() => {
                const parsed = parseCountryBlockEditorDocument(exampleRaw);
                applyStructuredDocument(parsed.base, parsed.state, parsed.hostBases);
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

        <div className="grid gap-3 md:grid-cols-3">
          <StatBox label={tx("Blocked countries")} value={String(blocked.length)} />
          <StatBox label={tx("Host scopes")} value={String(editorState.hosts.length)} />
          <StatBox
            label={tx("Last saved: {time}", {
              time: lastSavedAt ? new Date(lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") : "-",
            })}
            value={lastSavedAt ? new Date(lastSavedAt).toLocaleTimeString(locale === "ja" ? "ja-JP" : "en-US") : "-"}
          />
        </div>
      </SectionCard>

      <SectionCard title={tx("Default Scope")} subtitle={tx("These country codes apply when no more specific host scope matches.")}>
        <Field label={tx("Blocked countries")} hint={tx("One country code per line. `UNKNOWN` is allowed for unresolved lookups.")}>
          <textarea
            className={`${textareaClass} min-h-32`}
            value={countryCodesToMultiline(editorState.defaultBlockedCountries)}
            onChange={(event) =>
              applyStructuredState({
                ...editorState,
                defaultBlockedCountries: multilineToCountryCodes(event.target.value),
              })
            }
            placeholder={"US\nCN\nUNKNOWN"}
            spellCheck={false}
          />
        </Field>
      </SectionCard>

      <SectionCard
        title={tx("Host Scopes")}
        subtitle={tx("Use host or host:port patterns for overrides. Empty host cards are ignored until you fill the host field.")}
        actions={
          <ActionButton
            onClick={() =>
              applyStructuredState({
                ...editorState,
                hosts: [...editorState.hosts, createEmptyCountryBlockHostScope(editorState.hosts.length + 1)],
              }, [...hostBases, {}])
            }
            disabled={readOnly}
          >
            {tx("Add host scope")}
          </ActionButton>
        }
      >
        {editorState.hosts.length === 0 ? <EmptyState>{tx("No host-specific overrides yet.")}</EmptyState> : null}
        <div className="space-y-3">
          {editorState.hosts.map((scope, index) => (
            <div key={`host-scope-${index}`} className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-medium">{scope.host || tx("New host scope")}</div>
                <ActionButton
                  onClick={() =>
                    applyStructuredState({
                      ...editorState,
                      hosts: editorState.hosts.filter((_, currentIndex) => currentIndex !== index),
                    }, hostBases.filter((_, currentIndex) => currentIndex !== index))
                  }
                  disabled={readOnly}
                >
                  {tx("Remove")}
                </ActionButton>
              </div>
              <div className="grid gap-3 lg:grid-cols-[minmax(240px,1fr)_minmax(0,2fr)]">
                <Field label={tx("Host")} hint={tx("Examples: `example.com`, `admin.example.com`, `example.com:8443`.")}>
                  <input
                    className={inputClass}
                    value={scope.host}
                    onChange={(event) => updateHost(index, (current) => ({ ...current, host: event.target.value }))}
                    placeholder="example.com"
                  />
                </Field>
                <Field label={tx("Blocked countries")} hint={tx("One code per line. You can paste multiple lines directly from a spreadsheet or notes.")}>
                  <textarea
                    className={`${textareaClass} min-h-32`}
                    value={countryCodesToMultiline(scope.blockedCountries)}
                    onChange={(event) =>
                      updateHost(index, (current) => ({
                        ...current,
                        blockedCountries: multilineToCountryCodes(event.target.value),
                      }))
                    }
                    placeholder={"US\nCN\nUNKNOWN"}
                    spellCheck={false}
                  />
                </Field>
              </div>
              {scope.blockedCountries.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {scope.blockedCountries.map((code) => (
                    <span key={`${scope.host}-${code}`} className="rounded-full border border-neutral-200 bg-white px-2 py-1 text-xs">
                      {code}
                    </span>
                  ))}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      </SectionCard>

      <SectionCard title={tx("Advanced JSON")} subtitle={tx("Keep using raw JSON when needed. Structured edits and valid raw edits stay in sync.")}>
        <textarea
          className="w-full h-[320px] p-3 border rounded-xl font-mono text-sm leading-5 outline-none focus:ring-2 focus:ring-black/20"
          value={raw}
          onChange={(event) => handleRawChange(event.target.value)}
          spellCheck={false}
        />
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-neutral-500">
          <div className="flex items-center gap-3">
            <span>{tx("Lines")}: {lineCount}</span>
            <span>{tx("Blocked countries")}: {blocked.length}</span>
            {lastSavedAt ? <span>{tx("Last saved: {time}", { time: new Date(lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") })}</span> : null}
          </div>
          <div className="flex flex-wrap gap-2">
            {blocked.slice(0, 12).map((code) => (
              <span key={code} className="rounded bg-neutral-100 px-2 py-0.5">
                {code}
              </span>
            ))}
          </div>
        </div>
      </SectionCard>
    </div>
  );
}

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}
