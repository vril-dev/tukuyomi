import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  ActionButton,
  ActionResultNotice,
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
import { useI18n } from "@/lib/i18n";
import {
  countEnabledNotificationSinkDrafts,
  createDefaultNotificationEditorState,
  createEmailNotificationSink,
  createWebhookNotificationSink,
  parseNotificationEditorDocument,
  serializeNotificationEditor,
  type NotificationEditorState,
  type NotificationHeaderDraft,
  type NotificationSinkDraft,
  type NotificationTriggerDraft,
} from "@/lib/notificationEditor";
import { parseSavedAt } from "@/lib/savedAt";

type NotificationsDTO = {
  etag?: string;
  raw?: string;
  enabled?: boolean;
  sinks?: number;
  enabled_sinks?: number;
  active_alerts?: number;
  saved_at?: string;
};

const exampleState: NotificationEditorState = {
  ...createDefaultNotificationEditorState(),
  enabled: false,
  sinks: [
    {
      ...createWebhookNotificationSink(1),
      headers: [{ key: "X-Tukuyomi-Token", value: "change-me" }],
    },
    {
      ...createEmailNotificationSink(1),
      smtpPassword: "change-me",
    },
  ],
  upstream: {
    enabled: true,
    windowSeconds: 60,
    activeThreshold: 3,
    escalatedThreshold: 10,
  },
  security: {
    enabled: true,
    windowSeconds: 300,
    activeThreshold: 20,
    escalatedThreshold: 100,
    sources: ["waf_block", "rate_limited", "semantic_anomaly", "bot_challenge"],
  },
};

const exampleRaw = serializeNotificationEditor(exampleState);

export default function NotificationsPanel() {
  const { locale, tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [editorState, setEditorState] = useState<NotificationEditorState>(createDefaultNotificationEditorState);
  const [editorBase, setEditorBase] = useState<Record<string, unknown>>({});
  const [sinkBases, setSinkBases] = useState<Record<string, unknown>[]>([]);
  const [raw, setRaw] = useState("");
  const [serverRaw, setServerRaw] = useState("");
  const [etag, setEtag] = useState<string | null>(null);
  const [valid, setValid] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [messagesTone, setMessagesTone] = useState<"success" | "error" | "warn">("success");
  const [activeAlerts, setActiveAlerts] = useState<number>(0);
  const [lastSavedAt, setLastSavedAt] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [structuredError, setStructuredError] = useState<string | null>(null);

  const dirty = useMemo(() => raw !== serverRaw || !!structuredError, [raw, serverRaw, structuredError]);
  const enabledSinkCount = useMemo(() => countEnabledNotificationSinkDrafts(editorState), [editorState]);

  const applyStructuredState = useCallback(
    (next: NotificationEditorState, nextSinkBases = sinkBases) => {
      setEditorState(next);
      setSinkBases(nextSinkBases);
      try {
        setRaw(serializeNotificationEditor(editorBase, next, nextSinkBases));
        setStructuredError(null);
      } catch (e: unknown) {
        setValid(null);
        setMessages([]);
        setStructuredError(getErrorMessage(e, tx("Structured editor conflict")));
      }
    },
    [editorBase, sinkBases, tx],
  );

  const applyStructuredDocument = useCallback(
    (base: Record<string, unknown>, next: NotificationEditorState, nextSinkBases: Record<string, unknown>[]) => {
      setEditorBase(base);
      setEditorState(next);
      setSinkBases(nextSinkBases);
      setRaw(serializeNotificationEditor(base, next, nextSinkBases));
      setStructuredError(null);
    },
    [],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGetJson<NotificationsDTO>("/notifications");
      const nextRaw = data.raw ?? "";
      const parsed = parseNotificationEditorDocument(nextRaw);
      setEditorBase(parsed.base);
      setSinkBases(parsed.sinkBases);
      setEditorState(parsed.state);
      setRaw(nextRaw);
      setServerRaw(nextRaw);
      setEtag(data.etag ?? null);
      setActiveAlerts(typeof data.active_alerts === "number" ? data.active_alerts : 0);
      setLastSavedAt(parseSavedAt(data.saved_at));
      setValid(null);
      setMessages([]);
      setMessagesTone("success");
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
        const js = await apiPostJson<{ ok: boolean; messages?: string[]; active_alerts?: number }>(
          "/notifications/validate",
          { raw },
        );
        setValid(!!js.ok);
        setMessages(Array.isArray(js.messages) ? js.messages : []);
        setMessagesTone(js.ok ? "success" : "error");
      } catch (e: unknown) {
        setValid(false);
        setMessages([getErrorMessage(e, tx("Validate failed"))]);
        setMessagesTone("error");
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
    setMessages([]);
    setMessagesTone("success");
    try {
      const js = await apiPutJson<{ ok: boolean; etag?: string; saved_at?: string; active_alerts?: number }>(
        "/notifications",
        { raw },
        { headers: etag ? { "If-Match": etag } : {} },
      );
      if (!js.ok) {
        throw new Error(tx("Failed to save"));
      }
      const parsed = parseNotificationEditorDocument(raw);
      setEditorBase(parsed.base);
      setSinkBases(parsed.sinkBases);
      setEditorState(parsed.state);
      setEtag(js.etag ?? null);
      setRaw(raw);
      setServerRaw(raw);
      setStructuredError(null);
      setActiveAlerts(typeof js.active_alerts === "number" ? js.active_alerts : activeAlerts);
      setLastSavedAt(parseSavedAt(js.saved_at));
    } catch (e: unknown) {
      setMessages([getErrorMessage(e, tx("Save failed"))]);
      setMessagesTone("error");
    } finally {
      setSaving(false);
    }
  }, [activeAlerts, etag, raw, tx]);

  const doTest = useCallback(async () => {
    setTesting(true);
    setError(null);
    setMessages([]);
    setMessagesTone("success");
    try {
      await apiPostJson<{ ok: boolean }>("/notifications/test", { note: "notifications panel test send" });
    } catch (e: unknown) {
      setMessages([getErrorMessage(e, tx("Test send failed"))]);
      setMessagesTone("error");
    } finally {
      setTesting(false);
    }
  }, [tx]);

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

  const updateTrigger = useCallback(
    (name: "upstream" | "security", updater: (trigger: NotificationTriggerDraft) => NotificationTriggerDraft) => {
      applyStructuredState({
        ...editorState,
        [name]: updater(editorState[name]),
      });
    },
    [applyStructuredState, editorState],
  );

  const updateSecuritySources = useCallback(
    (sources: string[]) => {
      applyStructuredState({
        ...editorState,
        security: {
          ...editorState.security,
          sources,
        },
      });
    },
    [applyStructuredState, editorState],
  );

  const updateSink = useCallback(
    (index: number, updater: (sink: NotificationSinkDraft) => NotificationSinkDraft) => {
      applyStructuredState({
        ...editorState,
        sinks: editorState.sinks.map((sink, currentIndex) => (currentIndex === index ? updater(sink) : sink)),
      });
    },
    [applyStructuredState, editorState],
  );

  const updateSinkHeaders = useCallback(
    (sinkIndex: number, headers: NotificationHeaderDraft[]) => {
      updateSink(sinkIndex, (sink) => ({ ...sink, headers }));
    },
    [updateSink],
  );

  return (
    <div className="notification-page w-full p-4 space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("Notifications")}</h1>
          <p className="text-xs text-neutral-500">
            {tx("Configure aggregate notifications for upstream and security state changes. Notifications are off by default.")}
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
        subtitle={tx("Structured edits validate, save, and hot reload through the existing notification backend API.")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ActionButton onClick={() => void load()} disabled={loading}>
              {tx("Refresh")}
            </ActionButton>
            <ActionButton onClick={() => void doTest()} disabled={readOnly || loading || testing}>
              {testing ? tx("Sending...") : tx("Test send")}
            </ActionButton>
            <PrimaryButton onClick={() => void doSave()} disabled={readOnly || loading || saving || !dirty || !!structuredError}>
              {saving ? tx("Saving...") : tx("Save & hot reload")}
            </PrimaryButton>
            <QuietActionButton
              onClick={() => {
                const parsed = parseNotificationEditorDocument(exampleRaw);
                applyStructuredDocument(parsed.base, parsed.state, parsed.sinkBases);
              }}
              disabled={loading}
            >
              {tx("Insert example")}
            </QuietActionButton>
          </div>
        }
      >
        <ActionResultNotice tone={messagesTone || (valid === false ? "error" : "success")} messages={messages} />
        <div className="grid gap-3 md:grid-cols-5">
          <StatBox label={tx("Sinks")} value={String(editorState.sinks.length)} />
          <StatBox label={tx("Enabled sinks")} value={String(enabledSinkCount)} />
          <StatBox label={tx("Active alerts")} value={String(activeAlerts)} />
          <StatBox label={tx("Cooldown seconds")} value={String(editorState.cooldownSeconds)} />
          <StatBox
            label={tx("Last saved")}
            value={lastSavedAt ? new Date(lastSavedAt).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") : "-"}
          />
        </div>
      </SectionCard>

      <SectionCard title={tx("Global Settings")} subtitle={tx("Notifications require at least one enabled sink before global delivery can be enabled.")}>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="flex items-center gap-2 rounded-xl border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs">
            <input
              type="checkbox"
              checked={editorState.enabled}
              onChange={(event) => applyStructuredState({ ...editorState, enabled: event.target.checked })}
            />
            <span>{tx("Enable notification delivery")}</span>
          </label>
          <Field label={tx("Cooldown seconds")} hint={tx("Minimum seconds between repeated notifications for the same alert state.")}>
            <input
              className={inputClass}
              type="number"
              min={0}
              max={86400}
              value={editorState.cooldownSeconds}
              onChange={(event) => applyStructuredState({ ...editorState, cooldownSeconds: numberFromInput(event.target.value) })}
            />
          </Field>
        </div>
      </SectionCard>

      <SectionCard title={tx("Triggers")} subtitle={tx("Thresholds are evaluated over each trigger window before notifications transition state.")}>
        <div className="grid gap-4 xl:grid-cols-2">
          <TriggerEditor
            title={tx("Upstream")}
            tx={tx}
            trigger={editorState.upstream}
            onChange={(updater) => updateTrigger("upstream", updater)}
          />
          <div className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
            <TriggerFields title={tx("Security")} tx={tx} trigger={editorState.security} onChange={(updater) => updateTrigger("security", updater)} />
            <Field label={tx("Security sources")} hint={tx("One source per line. Empty input falls back to the runtime default source set.")}>
              <ParsedTextArea
                className={textareaClass}
                value={editorState.security.sources}
                onValueChange={updateSecuritySources}
                serialize={listToMultiline}
                parse={multilineToList}
                equals={stringListEqual}
                spellCheck={false}
              />
            </Field>
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title={tx("Sinks")}
        subtitle={tx("Add webhook or email delivery targets. Disabled sinks stay in the file but do not receive notifications.")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ActionButton
              onClick={() =>
                applyStructuredState(
                  {
                    ...editorState,
                    sinks: [...editorState.sinks, createWebhookNotificationSink(editorState.sinks.length + 1)],
                  },
                  [...sinkBases, {}],
                )
              }
              disabled={readOnly}
            >
              {tx("Add webhook")}
            </ActionButton>
            <ActionButton
              onClick={() =>
                applyStructuredState(
                  {
                    ...editorState,
                    sinks: [...editorState.sinks, createEmailNotificationSink(editorState.sinks.length + 1)],
                  },
                  [...sinkBases, {}],
                )
              }
              disabled={readOnly}
            >
              {tx("Add email")}
            </ActionButton>
          </div>
        }
      >
        {editorState.sinks.length === 0 ? <EmptyState>{tx("No notification sinks yet.")}</EmptyState> : null}
        <div className="space-y-4">
          {editorState.sinks.map((sink, sinkIndex) => (
            <div key={`sink-${sinkIndex}`} className="notification-sink-card rounded-2xl border border-neutral-200 bg-neutral-50 p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="text-sm font-medium">{sink.name || `${tx("Sink")} ${sinkIndex + 1}`}</div>
                  <Badge color={sink.enabled ? "green" : "gray"}>{sink.enabled ? tx("Enabled") : tx("Disabled")}</Badge>
                  <Badge color="gray">{sink.type}</Badge>
                </div>
                <ActionButton
                  onClick={() =>
                    applyStructuredState(
                      {
                        ...editorState,
                        sinks: editorState.sinks.filter((_, currentIndex) => currentIndex !== sinkIndex),
                      },
                      sinkBases.filter((_, currentIndex) => currentIndex !== sinkIndex),
                    )
                  }
                  disabled={readOnly}
                >
                  {tx("Remove")}
                </ActionButton>
              </div>

              <div className="notification-sink-grid">
                <Field label={tx("Name")}>
                  <input
                    className={inputClass}
                    value={sink.name}
                    onChange={(event) => updateSink(sinkIndex, (current) => ({ ...current, name: event.target.value }))}
                    placeholder="primary-webhook"
                  />
                </Field>
                <Field label={tx("Type")}>
                  <select
                    className={inputClass}
                    value={sink.type}
                    onChange={(event) =>
                      updateSink(sinkIndex, (current) => ({
                        ...current,
                        type: event.target.value === "email" ? "email" : "webhook",
                      }))
                    }
                  >
                    <option value="webhook">webhook</option>
                    <option value="email">email</option>
                  </select>
                </Field>
                <label className="notification-checkline">
                  <input
                    type="checkbox"
                    checked={sink.enabled}
                    onChange={(event) => updateSink(sinkIndex, (current) => ({ ...current, enabled: event.target.checked }))}
                  />
                  <span>{tx("Enabled")}</span>
                </label>
              </div>

              {sink.type === "webhook" ? (
                <WebhookSinkEditor tx={tx} sink={sink} sinkIndex={sinkIndex} onSinkChange={updateSink} onHeadersChange={updateSinkHeaders} />
              ) : (
                <EmailSinkEditor tx={tx} sink={sink} sinkIndex={sinkIndex} onSinkChange={updateSink} />
              )}
            </div>
          ))}
        </div>
      </SectionCard>

    </div>
  );
}

function TriggerEditor({
  title,
  tx,
  trigger,
  onChange,
}: {
  title: string;
  tx: (key: string) => string;
  trigger: NotificationTriggerDraft;
  onChange: (updater: (trigger: NotificationTriggerDraft) => NotificationTriggerDraft) => void;
}) {
  return (
    <div className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4">
      <TriggerFields title={title} tx={tx} trigger={trigger} onChange={onChange} />
    </div>
  );
}

function TriggerFields({
  title,
  tx,
  trigger,
  onChange,
}: {
  title: string;
  tx: (key: string) => string;
  trigger: NotificationTriggerDraft;
  onChange: (updater: (trigger: NotificationTriggerDraft) => NotificationTriggerDraft) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-medium">{title}</div>
        <label className="flex items-center gap-2 text-xs">
          <input type="checkbox" checked={trigger.enabled} onChange={(event) => onChange((current) => ({ ...current, enabled: event.target.checked }))} />
          <span>{tx("Enabled")}</span>
        </label>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <Field label={tx("Window seconds")}>
          <input
            className={inputClass}
            type="number"
            min={1}
            max={3600}
            value={trigger.windowSeconds}
            onChange={(event) => onChange((current) => ({ ...current, windowSeconds: numberFromInput(event.target.value) }))}
          />
        </Field>
        <Field label={tx("Active threshold")}>
          <input
            className={inputClass}
            type="number"
            min={1}
            value={trigger.activeThreshold}
            onChange={(event) => onChange((current) => ({ ...current, activeThreshold: numberFromInput(event.target.value) }))}
          />
        </Field>
        <Field label={tx("Escalated threshold")}>
          <input
            className={inputClass}
            type="number"
            min={1}
            value={trigger.escalatedThreshold}
            onChange={(event) => onChange((current) => ({ ...current, escalatedThreshold: numberFromInput(event.target.value) }))}
          />
        </Field>
      </div>
    </div>
  );
}

function WebhookSinkEditor({
  tx,
  sink,
  sinkIndex,
  onSinkChange,
  onHeadersChange,
}: {
  tx: (key: string) => string;
  sink: NotificationSinkDraft;
  sinkIndex: number;
  onSinkChange: (index: number, updater: (sink: NotificationSinkDraft) => NotificationSinkDraft) => void;
  onHeadersChange: (sinkIndex: number, headers: NotificationHeaderDraft[]) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="notification-webhook-grid">
        <Field label={tx("Webhook URL")} hint={tx("Use http or https. The runtime sends aggregate alert state changes to this endpoint.")}>
          <input
            className={inputClass}
            value={sink.webhookURL}
            onChange={(event) => onSinkChange(sinkIndex, (current) => ({ ...current, webhookURL: event.target.value }))}
            placeholder="https://hooks.example.invalid/tukuyomi"
          />
        </Field>
        <Field label={tx("Timeout seconds")}>
          <input
            className={inputClass}
            type="number"
            min={1}
            max={120}
            value={sink.timeoutSeconds}
            onChange={(event) => onSinkChange(sinkIndex, (current) => ({ ...current, timeoutSeconds: numberFromInput(event.target.value) }))}
          />
        </Field>
      </div>

      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-medium">{tx("Headers")}</div>
          <ActionButton onClick={() => onHeadersChange(sinkIndex, [...sink.headers, { key: "", value: "" }])}>{tx("Add header")}</ActionButton>
        </div>
        {sink.headers.length === 0 ? <EmptyState>{tx("No webhook headers configured.")}</EmptyState> : null}
        <div className="space-y-2">
          {sink.headers.map((header, headerIndex) => (
            <div key={`sink-${sinkIndex}-header-${headerIndex}`} className="notification-header-row">
              <input
                className={inputClass}
                value={header.key}
                onChange={(event) =>
                  onHeadersChange(
                    sinkIndex,
                    sink.headers.map((current, currentIndex) => (currentIndex === headerIndex ? { ...current, key: event.target.value } : current)),
                  )
                }
                placeholder="X-Tukuyomi-Token"
              />
              <input
                className={inputClass}
                value={header.value}
                onChange={(event) =>
                  onHeadersChange(
                    sinkIndex,
                    sink.headers.map((current, currentIndex) => (currentIndex === headerIndex ? { ...current, value: event.target.value } : current)),
                  )
                }
                placeholder="change-me"
              />
              <ActionButton onClick={() => onHeadersChange(sinkIndex, sink.headers.filter((_, currentIndex) => currentIndex !== headerIndex))}>
                {tx("Remove")}
              </ActionButton>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function EmailSinkEditor({
  tx,
  sink,
  sinkIndex,
  onSinkChange,
}: {
  tx: (key: string) => string;
  sink: NotificationSinkDraft;
  sinkIndex: number;
  onSinkChange: (index: number, updater: (sink: NotificationSinkDraft) => NotificationSinkDraft) => void;
}) {
  return (
    <div className="notification-email-grid">
      <Field label={tx("SMTP address")} hint={tx("Host and port for the SMTP server, for example `smtp.example.invalid:587`.")}>
        <input
          className={inputClass}
          value={sink.smtpAddress}
          onChange={(event) => onSinkChange(sinkIndex, (current) => ({ ...current, smtpAddress: event.target.value }))}
          placeholder="smtp.example.invalid:587"
        />
      </Field>
      <Field label={tx("SMTP username")}>
        <input
          className={inputClass}
          value={sink.smtpUsername}
          onChange={(event) => onSinkChange(sinkIndex, (current) => ({ ...current, smtpUsername: event.target.value }))}
          placeholder="alerts@example.invalid"
        />
      </Field>
      <Field label={tx("SMTP password")}>
        <input
          className={inputClass}
          type="password"
          value={sink.smtpPassword}
          onChange={(event) => onSinkChange(sinkIndex, (current) => ({ ...current, smtpPassword: event.target.value }))}
          placeholder="change-me"
        />
      </Field>
      <Field label={tx("From")}>
        <input
          className={inputClass}
          value={sink.from}
          onChange={(event) => onSinkChange(sinkIndex, (current) => ({ ...current, from: event.target.value }))}
          placeholder="alerts@example.invalid"
        />
      </Field>
      <Field label={tx("Recipients")} hint={tx("One email address per line.")}>
        <ParsedTextArea
          className={textareaClass}
          value={sink.to}
          onValueChange={(next) => onSinkChange(sinkIndex, (current) => ({ ...current, to: next }))}
          serialize={listToMultiline}
          parse={multilineToList}
          equals={stringListEqual}
          spellCheck={false}
        />
      </Field>
      <Field label={tx("Subject prefix")}>
        <input
          className={inputClass}
          value={sink.subjectPrefix}
          onChange={(event) => onSinkChange(sinkIndex, (current) => ({ ...current, subjectPrefix: event.target.value }))}
          placeholder="[tukuyomi]"
        />
      </Field>
    </div>
  );
}

function numberFromInput(value: string): number {
  const next = Number(value);
  return Number.isFinite(next) ? next : 0;
}

function multilineToList(raw: string): string[] {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function listToMultiline(values: string[]): string {
  return values.join("\n");
}
