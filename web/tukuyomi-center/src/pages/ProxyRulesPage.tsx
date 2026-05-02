import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { apiGetJson, apiPostJson } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

type DeviceRecord = {
  device_id: string;
  status: string;
  last_seen_at_unix?: number;
};

type ProxyRuleSnapshot = {
  config_revision: string;
  proxy_etag: string;
  raw: string;
  error?: string;
  snapshot_created_at_unix?: number;
};

type ProxyRuleBundle = {
  bundle_revision: string;
  source_config_revision: string;
  source_proxy_etag: string;
  payload_etag: string;
  payload_hash: string;
  size_bytes: number;
  created_by: string;
  created_at_unix: number;
  local_proxy_etag?: string;
  apply_state?: string;
  apply_error?: string;
  last_attempt_at_unix?: number;
  applied_at_unix?: number;
  apply_updated_at_unix?: number;
};

type ProxyRuleAssignment = {
  bundle_revision: string;
  base_proxy_etag: string;
  reason: string;
  assigned_by: string;
  assigned_at_unix: number;
  dispatched_at_unix?: number;
  payload_etag: string;
  payload_hash: string;
  size_bytes: number;
};

type ProxyRuleApplyStatus = {
  desired_bundle_revision: string;
  local_proxy_etag: string;
  apply_state: string;
  apply_error: string;
  last_attempt_at_unix: number;
  updated_at_unix: number;
};

type ProxyRulesView = {
  device: DeviceRecord;
  current?: ProxyRuleSnapshot | null;
  bundles?: ProxyRuleBundle[];
  assignment?: ProxyRuleAssignment | null;
  apply_status?: ProxyRuleApplyStatus | null;
};

type ValidateResponse = {
  ok: boolean;
  raw?: string;
  etag?: string;
  messages?: string[];
};

type BuildResponse = {
  bundle?: ProxyRuleBundle;
  assignment?: ProxyRuleAssignment;
};

type BundleDetailResponse = {
  bundle: ProxyRuleBundle;
  raw: string;
};

type RuleCounts = {
  upstreams: number;
  backendPools: number;
  routes: number;
  defaultRoute: string;
};

const emptyRules = "{\n  \"upstreams\": []\n}\n";
const proxyRuleDispatchLeaseSeconds = 60;

function rulesPageDevicePath(deviceID: string) {
  return `/device-approvals/devices/${encodeURIComponent(deviceID)}/proxy-rules`;
}

function compactRevision(value: string | undefined) {
  if (!value) {
    return "-";
  }
  return value.length > 14 ? `R: ${value.slice(0, 12)}` : value;
}

function formatUnix(value: number | undefined, locale: string) {
  if (!value) {
    return "-";
  }
  return new Date(value * 1000).toLocaleString(locale === "ja" ? "ja-JP" : "en-US");
}

function formatSize(bytes: number | undefined) {
  if (!bytes || !Number.isFinite(bytes)) {
    return "-";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function rulesCounts(raw: string): RuleCounts {
  try {
    const parsed = JSON.parse(raw || "{}") as Record<string, unknown>;
    return {
      upstreams: Array.isArray(parsed.upstreams) ? parsed.upstreams.length : 0,
      backendPools: Array.isArray(parsed.backend_pools) ? parsed.backend_pools.length : 0,
      routes: Array.isArray(parsed.routes) ? parsed.routes.length : 0,
      defaultRoute: parsed.default_route && typeof parsed.default_route === "object" ? "enabled" : "none",
    };
  } catch {
    return { upstreams: 0, backendPools: 0, routes: 0, defaultRoute: "invalid" };
  }
}

function formatRulesRaw(raw: string | undefined) {
  if (!raw) {
    return emptyRules;
  }
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

function proxyRuleDispatchActive(dispatchedAtUnix: number | undefined) {
  if (!dispatchedAtUnix) {
    return false;
  }
  return Math.floor(Date.now() / 1000) - dispatchedAtUnix < proxyRuleDispatchLeaseSeconds;
}

function proxyRuleETagContentHash(value: string | undefined) {
  const trimmed = (value || "").trim();
  if (!trimmed) {
    return "";
  }
  const weak = trimmed.match(/^W\/"sha256:([a-f0-9]{64})"$/);
  if (weak) {
    return weak[1];
  }
  const strong = trimmed.match(/^"sha256:([a-f0-9]{64})"$/);
  if (strong) {
    return strong[1];
  }
  const configVersion = trimmed.match(/^proxy:\d+:([a-f0-9]{64})$/);
  if (configVersion) {
    return configVersion[1];
  }
  return "";
}

function proxyRuleETagSameContent(a: string | undefined, b: string | undefined) {
  const aHash = proxyRuleETagContentHash(a);
  const bHash = proxyRuleETagContentHash(b);
  return Boolean(aHash && bHash && aHash === bHash);
}

export default function ProxyRulesPage() {
  const { deviceID = "" } = useParams();
  const navigate = useNavigate();
  const { locale, tx } = useI18n();
  const [view, setView] = useState<ProxyRulesView | null>(null);
  const [raw, setRaw] = useState(emptyRules);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState<{ kind: "info" | "success" | "error"; text: string } | null>(null);
  const [validatedETag, setValidatedETag] = useState("");
  const [selectedBundle, setSelectedBundle] = useState<BundleDetailResponse | null>(null);
  const editorDeviceIDRef = useRef("");

  const current = view?.current || null;
  const assignment = view?.assignment || null;
  const assignmentDispatchActive = proxyRuleDispatchActive(assignment?.dispatched_at_unix);
  const applyStatus = view?.apply_status || null;
  const bundles = useMemo(() => [...(view?.bundles || [])], [view?.bundles]);
  const counts = useMemo(() => rulesCounts(raw), [raw]);

  const loadRules = useCallback(async () => {
    if (!deviceID) {
      navigate("/device-approvals", { replace: true });
      return;
    }
    setLoading(true);
    try {
      const data = await apiGetJson<ProxyRulesView>(`/devices/${encodeURIComponent(deviceID)}/proxy-rules`);
      const previousEditorDeviceID = editorDeviceIDRef.current;
      const nextEditorRaw = formatRulesRaw(data.current?.raw);
      setView(data);
      if (previousEditorDeviceID !== data.device.device_id) {
        setSelectedBundle(null);
      }
      setRaw((currentRaw) => {
        if (previousEditorDeviceID !== data.device.device_id) {
          return nextEditorRaw;
        }
        if (currentRaw.trim() && currentRaw !== emptyRules) {
          return currentRaw;
        }
        return nextEditorRaw;
      });
      editorDeviceIDRef.current = data.device.device_id;
      setMessage(null);
    } catch (err) {
      setMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to load rules") });
    } finally {
      setLoading(false);
    }
  }, [deviceID, navigate, tx]);

  useEffect(() => {
    void loadRules();
  }, [loadRules]);

  useEffect(() => {
    if (!assignment && !assignmentDispatchActive) {
      return;
    }
    const timer = window.setInterval(() => {
      void loadRules();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [assignment, assignmentDispatchActive, loadRules]);

  useEffect(() => {
    if (!selectedBundle) {
      return;
    }
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setSelectedBundle(null);
      }
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", closeOnEscape);
    };
  }, [selectedBundle]);

  function importCurrent() {
    if (!current?.raw) {
      setMessage({ kind: "error", text: tx("No reported Proxy Rules snapshot.") });
      return;
    }
    setRaw(formatRulesRaw(current.raw));
    setValidatedETag("");
    setMessage({ kind: "info", text: tx("Imported current Proxy Rules.") });
  }

  async function validateRules() {
    setBusy("validate");
    try {
      const data = await apiPostJson<ValidateResponse>(`/devices/${encodeURIComponent(deviceID)}/proxy-rules/validate`, { raw });
      if (data.raw) {
        setRaw(formatRulesRaw(data.raw));
      }
      setValidatedETag(data.etag || "");
      setMessage({ kind: "success", text: tx("Proxy Rules validated.") });
    } catch (err) {
      setMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Proxy Rules validation failed") });
    } finally {
      setBusy("");
    }
  }

  async function buildAndAssign() {
    setBusy("build");
    try {
      const data = await apiPostJson<BuildResponse>(`/devices/${encodeURIComponent(deviceID)}/proxy-rules/bundles`, {
        raw,
        source_config_revision: current?.config_revision || "",
        source_proxy_etag: current?.proxy_etag || "",
        assign: true,
        reason: "proxy rules assigned from rules page",
      });
      setValidatedETag(data.bundle?.payload_etag || validatedETag);
      setMessage({ kind: "success", text: tx("Proxy Rules request assigned.") });
      await loadRules();
    } catch (err) {
      setMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to assign Proxy Rules") });
    } finally {
      setBusy("");
    }
  }

  async function assignBundle(bundle: ProxyRuleBundle) {
    setBusy(`assign:${bundle.bundle_revision}`);
    try {
      await apiPostJson(`/devices/${encodeURIComponent(deviceID)}/proxy-rules/assignments`, {
        bundle_revision: bundle.bundle_revision,
        reason: "proxy rules bundle assigned from rules page",
      });
      setMessage({ kind: "success", text: tx("Proxy Rules request assigned.") });
      await loadRules();
    } catch (err) {
      setMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to assign Proxy Rules") });
    } finally {
      setBusy("");
    }
  }

  async function viewBundle(bundle: ProxyRuleBundle) {
    setBusy(`view:${bundle.bundle_revision}`);
    try {
      const data = await apiGetJson<BundleDetailResponse>(
        `/devices/${encodeURIComponent(deviceID)}/proxy-rules/bundles/${encodeURIComponent(bundle.bundle_revision)}`,
      );
      setSelectedBundle({
        bundle: data.bundle,
        raw: formatRulesRaw(data.raw),
      });
      setMessage(null);
    } catch (err) {
      setMessage({ kind: "error", text: err instanceof Error ? err.message : tx("Failed to load rule bundle") });
    } finally {
      setBusy("");
    }
  }

  async function clearAssignment() {
    setBusy("clear");
    try {
      await apiPostJson(`/devices/${encodeURIComponent(deviceID)}/proxy-rules/assignments/clear`, {});
      setMessage({ kind: "success", text: tx("Proxy Rules request canceled.") });
      await loadRules();
    } catch (err) {
      const text = err instanceof Error ? err.message : tx("Failed to cancel Proxy Rules request");
      await loadRules().catch(() => undefined);
      setMessage({
        kind: "error",
        text: text.includes("already been dispatched") ? tx("Gateway has already picked up this request.") : text,
      });
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="content-panel rules-page">
      <section className="content-section">
        <div className="section-header">
          <div>
            <h3 className="section-title">{tx("Proxy Rules")}</h3>
            <p className="section-note">{deviceID}</p>
          </div>
        </div>

        <div className="summary-grid rules-summary-grid">
          <div><span>{tx("Current proxy ETag")}</span><strong title={current?.proxy_etag || undefined}>{current?.proxy_etag || "-"}</strong></div>
          <div><span>{tx("Config revision")}</span><strong title={current?.config_revision || undefined}>{compactRevision(current?.config_revision)}</strong></div>
          <div><span>{tx("Apply state")}</span><strong title={view?.apply_status?.apply_error || undefined}>{view?.apply_status?.apply_state || "-"}</strong></div>
        </div>
      </section>

      <section className="content-section">
        <div className="section-header">
          <div>
            <h3 className="section-title">{tx("Proxy Rules editor")}</h3>
            <p className="section-note">{tx("Edit the proxy domain for this Gateway.")}</p>
          </div>
          <div className="inline-actions">
            <button onClick={importCurrent} disabled={busy !== "" || !current?.raw}>{tx("Import current")}</button>
            <button onClick={() => void validateRules()} disabled={busy !== ""}>{busy === "validate" ? tx("Validating...") : tx("Validate")}</button>
            <button onClick={() => void buildAndAssign()} disabled={busy !== "" || !current?.proxy_etag}>
              {busy === "build" ? tx("Assigning...") : tx("Build & assign")}
            </button>
          </div>
        </div>

        <div className="facts rules-counts">
          <div className="fact"><span>{tx("Upstreams")}</span><strong>{counts.upstreams}</strong></div>
          <div className="fact"><span>{tx("Backend pools")}</span><strong>{counts.backendPools}</strong></div>
          <div className="fact"><span>{tx("Routes")}</span><strong>{counts.routes}</strong></div>
          <div className="fact"><span>{tx("Default route")}</span><strong>{tx(counts.defaultRoute)}</strong></div>
        </div>

        <textarea
          className="rules-json-editor"
          value={raw}
          spellCheck={false}
          onChange={(event) => {
            setRaw(event.target.value);
            setValidatedETag("");
          }}
        />
        <div className="form-footer">
          <span className={`form-message ${message?.kind || ""}`}>{message?.text || (validatedETag ? `${tx("Validated ETag")}: ${validatedETag}` : "")}</span>
        </div>
      </section>

      <section className="content-section">
        <h3 className="section-title">{tx("Pending rule requests")}</h3>
        {assignmentDispatchActive ? (
          <p className="section-note">{tx("Gateway picked up this request. Waiting for the next apply report.")}</p>
        ) : null}
        <div className="table-wrap rules-request-table">
          <table>
            <colgroup>
              <col className="rules-request-col-actions" />
              <col className="rules-request-col-revision" />
              <col className="rules-request-col-etag" />
              <col className="rules-request-col-etag" />
              <col className="rules-request-col-time" />
              <col className="rules-request-col-time" />
            </colgroup>
            <thead>
              <tr>
                <th>{tx("Actions")}</th>
                <th>{tx("Bundle")}</th>
                <th>{tx("Base ETag")}</th>
                <th>{tx("Payload ETag")}</th>
                <th>{tx("Assigned")}</th>
                <th>{tx("Dispatched")}</th>
              </tr>
            </thead>
            <tbody>
              {assignment ? (
                <tr>
                  <td className="actions-cell">
                    <div className="inline-actions">
                      <button onClick={() => void clearAssignment()} disabled={busy !== "" || assignmentDispatchActive}>
                        {assignmentDispatchActive ? tx("Picked up") : tx("Cancel request")}
                      </button>
                    </div>
                  </td>
                  <td title={assignment.bundle_revision}>{compactRevision(assignment.bundle_revision)}</td>
                  <td title={assignment.base_proxy_etag}>{assignment.base_proxy_etag || "-"}</td>
                  <td title={assignment.payload_etag}>{assignment.payload_etag || "-"}</td>
                  <td>{formatUnix(assignment.assigned_at_unix, locale)}</td>
                  <td>{assignment.dispatched_at_unix ? formatUnix(assignment.dispatched_at_unix, locale) : "-"}</td>
                </tr>
              ) : (
                <tr><td colSpan={6}>{tx("No pending rule requests.")}</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="content-section">
        <h3 className="section-title">{tx("Saved rule bundles")}</h3>
        <p className="section-note">{tx("Latest 20 saved bundles. Use Assign to redeploy a saved bundle.")}</p>
        <div className="table-wrap rules-bundle-table">
          <table>
            <colgroup>
              <col className="rules-bundle-col-actions" />
              <col className="rules-bundle-col-revision" />
              <col className="rules-bundle-col-state" />
              <col className="rules-bundle-col-time" />
              <col className="rules-bundle-col-time" />
              <col className="rules-bundle-col-etag" />
              <col className="rules-bundle-col-etag" />
              <col className="rules-bundle-col-size" />
            </colgroup>
            <thead>
              <tr>
                <th>{tx("Actions")}</th>
                <th>{tx("Bundle")}</th>
                <th>{tx("Apply state")}</th>
                <th>{tx("Applied at")}</th>
                <th>{tx("Created")}</th>
                <th>{tx("Payload ETag")}</th>
                <th>{tx("Source ETag")}</th>
                <th>{tx("Size")}</th>
              </tr>
            </thead>
            <tbody>
              {bundles.map((bundle) => {
                const assigned = assignment?.bundle_revision === bundle.bundle_revision;
                const currentBundle =
                  applyStatus?.apply_state === "applied" &&
                  applyStatus.desired_bundle_revision === bundle.bundle_revision &&
                  proxyRuleETagSameContent(applyStatus.local_proxy_etag, bundle.payload_etag);
                const rowHistoryApplied = bundle.apply_state === "applied" && Boolean(bundle.applied_at_unix);
                const rowApplyLabel = currentBundle || rowHistoryApplied
                  ? "applied"
                  : bundle.apply_state === "applied"
                    ? ""
                    : bundle.apply_state || "";
                const rowAppliedAt = currentBundle
                  ? applyStatus.last_attempt_at_unix || applyStatus.updated_at_unix || bundle.applied_at_unix
                  : bundle.applied_at_unix;
                return (
                  <tr key={bundle.bundle_revision}>
                    <td className="actions-cell">
                      <div className="inline-actions">
                        <button onClick={() => void viewBundle(bundle)} disabled={busy !== ""}>
                          {tx("View JSON")}
                        </button>
                        {currentBundle || assigned ? null : (
                          <button onClick={() => void assignBundle(bundle)} disabled={busy !== "" || assigned}>
                            {tx("Assign")}
                          </button>
                        )}
                      </div>
                    </td>
                    <td title={bundle.bundle_revision}>{compactRevision(bundle.bundle_revision)}</td>
                    <td title={bundle.apply_error || undefined}>
                      {rowApplyLabel ? <span className={`status-pill apply-${rowApplyLabel}`}>{tx(rowApplyLabel)}</span> : "-"}
                    </td>
                    <td>{rowAppliedAt ? formatUnix(rowAppliedAt, locale) : "-"}</td>
                    <td>{formatUnix(bundle.created_at_unix, locale)}</td>
                    <td title={bundle.payload_etag}>{bundle.payload_etag || "-"}</td>
                    <td title={bundle.source_proxy_etag}>{bundle.source_proxy_etag || "-"}</td>
                    <td>{formatSize(bundle.size_bytes)}</td>
                  </tr>
                );
              })}
              {bundles.length === 0 ? <tr><td colSpan={8}>{tx("No rule bundles.")}</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
      {selectedBundle ? (
        <div
          className="rules-bundle-modal-backdrop"
          role="presentation"
          onMouseDown={() => setSelectedBundle(null)}
        >
          <div
            className="rules-bundle-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="rules-bundle-modal-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="section-header">
              <div>
                <h4 id="rules-bundle-modal-title" className="section-subtitle">{tx("Selected bundle")}</h4>
                <p className="section-note" title={selectedBundle.bundle.bundle_revision}>{compactRevision(selectedBundle.bundle.bundle_revision)}</p>
              </div>
              <button onClick={() => setSelectedBundle(null)}>{tx("Close")}</button>
            </div>
            <div className="facts rules-bundle-modal-facts">
              <div className="fact"><span>{tx("Payload ETag")}</span><strong title={selectedBundle.bundle.payload_etag}>{selectedBundle.bundle.payload_etag || "-"}</strong></div>
              <div className="fact"><span>{tx("Source ETag")}</span><strong title={selectedBundle.bundle.source_proxy_etag}>{selectedBundle.bundle.source_proxy_etag || "-"}</strong></div>
              <div className="fact"><span>{tx("Size")}</span><strong>{formatSize(selectedBundle.bundle.size_bytes)}</strong></div>
              <div className="fact"><span>{tx("Created")}</span><strong>{formatUnix(selectedBundle.bundle.created_at_unix, locale)}</strong></div>
            </div>
            <textarea
              className="rules-json-editor rules-bundle-json"
              value={selectedBundle.raw}
              readOnly
              spellCheck={false}
            />
          </div>
        </div>
      ) : null}
    </div>
  );
}
