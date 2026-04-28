import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiGetBinary, apiGetJson } from "@/lib/api";
import { getErrorMessage, isAbortLikeError } from "@/lib/errors";
import { useI18n, translateCurrent } from "@/lib/i18n";
import {
  extractRequestEventFields,
  formatPolicyFamilyLabel,
  formatRequestEventRoleLabel,
  sortLogLinesNewestFirst,
  summarizeRequestEvents,
  type LogLine,
  type PolicyFamily,
  type RequestDecision,
  type RequestEventRole,
} from "@/lib/logRequestDetails";
import {
  formatSecurityAuditAction,
  formatSecurityAuditVerify,
  summarizeSecurityAuditNode,
  type SecurityAuditRecord,
  type SecurityAuditResponse,
  type SecurityAuditVerifyResponse,
} from "@/lib/securityAudit";

type ReadResponse = {
  lines: LogLine[];
  next_cursor?: number;
  page_start?: number;
  page_end?: number;
  has_more: boolean;
  has_prev?: boolean;
  has_next?: boolean;
};

async function readSecurityAudit(reqID: string, signal?: AbortSignal): Promise<SecurityAuditResponse> {
  const q = new URLSearchParams();
  q.set("req_id", reqID);
  return apiGetJson<SecurityAuditResponse>(`/logs/security-audit?${q.toString()}`, {
    signal,
  });
}

async function readSecurityAuditVerify(signal?: AbortSignal): Promise<SecurityAuditVerifyResponse> {
  return apiGetJson<SecurityAuditVerifyResponse>("/logs/security-audit/verify", {
    signal,
  });
}

async function readLogs(params: {
  tail: number;
  cursor?: number;
  dir?: "prev" | "next";
  country?: string;
  reqID?: string;
  search?: string;
  signal?: AbortSignal;
}): Promise<ReadResponse> {
  const q = new URLSearchParams();
  q.set("src", "waf");
  q.set("tail", String(params.tail));

  if (params.cursor != null) {
    q.set("cursor", String(params.cursor));
  }

  if (params.dir) {
    q.set("dir", params.dir);
  }

  if (params.country) {
    q.set("country", params.country);
  }

  if (params.reqID) {
    q.set("req_id", params.reqID);
  }

  if (params.search) {
    q.set("q", params.search);
  }

  return apiGetJson<ReadResponse>(`/logs/read?${q.toString()}`, {
    signal: params.signal,
  });
}

function buildDownloadPath(country?: string, search?: string) {
  const q = new URLSearchParams();
  q.set("src", "waf");
  if (country) {
    q.set("country", country);
  }
  if (search) {
    q.set("q", search);
  }

  return `/logs/download?${q.toString()}`;
}

function classNames(...xs: (string | false | null | undefined)[]) {
  return xs.filter(Boolean).join(" ");
}

function normalizeCountryFilterValue(v: string) {
  const s = v.trim().toUpperCase();
  if (!s || s === "ALL") {
    return "";
  }

  return s;
}

function displayCountry(v: unknown) {
  if (typeof v !== "string") {
    return translateCurrent("UNKNOWN");
  }

  const s = v.trim().toUpperCase();
  return s || translateCurrent("UNKNOWN");
}

function displayHost(line: LogLine) {
  const originalHost = typeof line.original_host === "string" ? line.original_host.trim() : "";
  if (originalHost) {
    return originalHost;
  }
  const fallbackHost = typeof line.host === "string" ? line.host.trim() : "";
  return fallbackHost || "-";
}

function colorClass(line: LogLine) {
  if (line.event === "waf_block") {
    return "bg-red-50 text-red-700";
  }

  if (line.event === "waf_hit_allow") {
    return "bg-yellow-50 text-yellow-700";
  }

  if (typeof line.status === "number" && line.status >= 500) {
    return "bg-orange-50 text-orange-700";
  }

  return "";
}

function formatTimestamp(ts: string | undefined, locale: "en" | "ja" = "en") {
  return ts ? new Date(ts).toLocaleString(locale === "ja" ? "ja-JP" : "en-US") : "-";
}

function formatDecisionLabel(decision: RequestDecision) {
  switch (decision) {
    case "blocked":
      return translateCurrent("blocked");
    case "rate_limited":
      return translateCurrent("rate limited");
    case "challenged":
      return translateCurrent("challenged");
    case "allowed_with_findings":
      return translateCurrent("allowed with findings");
    case "allowed":
    default:
      return translateCurrent("allowed");
  }
}

function formatPolicyLabel(policy: PolicyFamily) {
  return formatPolicyFamilyLabel(policy);
}

function roleBadgeClass(role: RequestEventRole) {
  switch (role) {
    case "enforced":
      return "bg-red-100 text-red-700";
    case "observed":
      return "bg-amber-100 text-amber-700";
    case "dry_run":
      return "bg-sky-100 text-sky-700";
    case "informational":
    default:
      return "bg-gray-100 text-gray-700";
  }
}

function decisionBadgeClass(decision: RequestDecision) {
  switch (decision) {
    case "blocked":
      return "bg-red-600 text-white";
    case "rate_limited":
      return "bg-orange-500 text-white";
    case "challenged":
      return "bg-amber-500 text-black";
    case "allowed_with_findings":
      return "bg-blue-100 text-blue-800";
    case "allowed":
    default:
      return "bg-emerald-100 text-emerald-700";
  }
}

export default function Logs() {
  const { locale, tx } = useI18n();
  const [tail, setTail] = useState<number>(30);
  const [countryFilter, setCountryFilter] = useState<string>("ALL");
  const [reqIDFilter, setReqIDFilter] = useState<string>("");
  const [searchInput, setSearchInput] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [pageStart, setPageStart] = useState<number | undefined>(undefined);
  const [pageEnd, setPageEnd] = useState<number | undefined>(undefined);
  const [dir, setDir] = useState<"prev" | "next" | undefined>(undefined);
  const [data, setData] = useState<ReadResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [canPrev, setCanPrev] = useState(false);
  const [canNext, setCanNext] = useState(false);
  const [detailReqID, setDetailReqID] = useState<string | null>(null);
  const [detailLines, setDetailLines] = useState<LogLine[]>([]);
  const [detailAudit, setDetailAudit] = useState<SecurityAuditRecord | null>(null);
  const [detailAuditVerify, setDetailAuditVerify] = useState<SecurityAuditVerifyResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");

  const controllerRef = useRef<AbortController | null>(null);
  const detailControllerRef = useRef<AbortController | null>(null);

  const load = useCallback(
    async (opts?: {
      reset?: boolean;
      dir?: "prev" | "next";
      cursor?: number;
    }) => {
      if (controllerRef.current) {
        controllerRef.current.abort("refresh");
      }

      const ac = new AbortController();
      controllerRef.current = ac;

      setLoading(true);
      setLoadError("");
      try {
        const useReqID = reqIDFilter.trim();
        const useDir = useReqID ? undefined : opts?.dir ?? dir;

        let useCursor: number | undefined;
        if (useReqID || opts?.reset || useDir === undefined) {
          useCursor = undefined;
        } else if (opts?.cursor != null) {
          useCursor = opts.cursor;
        } else if (useDir === "prev") {
          useCursor = pageStart;
        } else if (useDir === "next") {
          useCursor = pageEnd;
        }

        const r = await readLogs({
          tail,
          cursor: useCursor,
          dir: useDir,
          country: normalizeCountryFilterValue(countryFilter),
          reqID: useReqID || undefined,
          search: useReqID ? undefined : searchQuery.trim() || undefined,
          signal: ac.signal,
        });

        setData(r);

        if (useReqID) {
          setPageStart(0);
          setPageEnd(r.lines.length);
          setDir(undefined);
          setCanPrev(false);
          setCanNext(false);
          return;
        }

        const n = r?.lines?.length ?? 0;
        let nextStart = 0;
        let nextEnd = 0;
        if (useDir === "prev") {
          const start = r.next_cursor ?? 0;
          const end = start + n;
          nextStart = start;
          nextEnd = end;
        } else {
          const end = r.next_cursor ?? 0;
          const start = Math.max(0, end - n);
          nextStart = start;
          nextEnd = end;
        }
        if (typeof r.page_start === "number") {
          nextStart = r.page_start;
        }
        if (typeof r.page_end === "number") {
          nextEnd = r.page_end;
        }
        setPageStart(nextStart);
        setPageEnd(nextEnd);
        setDir(useDir);

        if (typeof r.has_prev === "boolean" || typeof r.has_next === "boolean") {
          setCanNext(!!r.has_prev);
          setCanPrev(!!r.has_next);
        } else if (opts?.reset || useDir === undefined) {
          setCanPrev(false);
          setCanNext(!!r.has_more);
        } else if (useDir === "next") {
          setCanPrev(true);
          setCanNext(!!r.has_more);
        } else if (useDir === "prev") {
          setCanPrev(!!r.has_more);
          setCanNext(true);
        }
      } catch (error: unknown) {
        if (isAbortLikeError(error)) {
          return;
        }

        console.error(error);
        setLoadError(getErrorMessage(error, tx("Failed to load")));
      } finally {
        setLoading(false);
      }
    },
    [countryFilter, dir, pageEnd, pageStart, reqIDFilter, searchQuery, tail, tx]
  );

  const openRequestDetail = useCallback(
    async (rawReqID: string) => {
      const reqID = rawReqID.trim();
      if (!reqID) {
        return;
      }
      if (detailControllerRef.current) {
        detailControllerRef.current.abort("refresh");
      }

      const ac = new AbortController();
      detailControllerRef.current = ac;

      setDetailReqID(reqID);
      setDetailLoading(true);
      setDetailError("");
      try {
        const [r, audit] = await Promise.all([
          readLogs({
            tail,
            reqID,
            signal: ac.signal,
          }),
          readSecurityAudit(reqID, ac.signal),
        ]);
        setDetailLines(r.lines);
        const auditItem = audit.items?.[0] ?? null;
        setDetailAudit(auditItem);
        if (auditItem) {
          setDetailAuditVerify(await readSecurityAuditVerify(ac.signal));
        } else {
          setDetailAuditVerify(null);
        }
      } catch (error: unknown) {
        if (isAbortLikeError(error)) {
          return;
        }

        console.error(error);
        setDetailLines([]);
        setDetailAudit(null);
        setDetailAuditVerify(null);
        setDetailError(getErrorMessage(error, tx("Failed to load request detail")));
      } finally {
        setDetailLoading(false);
      }
    },
    [tail, tx]
  );

  useEffect(() => {
    void load({ reset: true });
  }, [load]);

  useEffect(() => {
    return () => {
      if (controllerRef.current) {
        controllerRef.current.abort("unmount");
      }
      if (detailControllerRef.current) {
        detailControllerRef.current.abort("unmount");
      }
    };
  }, []);

  async function downloadAll() {
    const country = normalizeCountryFilterValue(countryFilter);
    const path = buildDownloadPath(country, searchQuery.trim() || undefined);
    const { blob, filename } = await apiGetBinary(path);
    const a = document.createElement("a");
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download =
      filename ||
      `waf-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}.ndjson.gz`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  const detailSummary = detailReqID ? summarizeRequestEvents(detailReqID, detailLines) : null;
  const normalizedCountry = normalizeCountryFilterValue(countryFilter) || "ALL";
  const reqIDActive = reqIDFilter.trim();
  const searchActive = searchQuery.trim();
  const displayLines = useMemo(() => sortLogLinesNewestFirst(data?.lines ?? []), [data?.lines]);

  return (
    <div className="p-4 space-y-4">
      <h1 className="text-xl font-semibold">{tx("Logs")}</h1>

      <div className="flex flex-wrap items-center gap-2">
        <label className="ml-2 text-sm">
          {tx("Search")}:
          <input
            className="ml-1 w-64 rounded border px-2 py-1 font-mono"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                setDir(undefined);
                setSearchQuery(searchInput.trim());
              }
            }}
            placeholder={tx("path, rule_id, host, message")}
          />
        </label>

        <button
          disabled={loading}
          onClick={() => {
            setDir(undefined);
            setSearchQuery(searchInput.trim());
          }}
          className="rounded border px-3 py-1 text-sm"
          title={tx("Search logs")}
        >
          {tx("Search")}
        </button>

        {searchActive && (
          <button
            className="rounded border px-3 py-1 text-sm"
            onClick={() => {
              setSearchInput("");
              setSearchQuery("");
              setDir(undefined);
            }}
          >
            {tx("Clear search")}
          </button>
        )}

        <label className="ml-2 text-sm">
          {tx("Country")}:
          <input
            className="ml-1 w-40 rounded border px-2 py-1"
            value={countryFilter}
            onChange={(e) => setCountryFilter(e.target.value.toUpperCase())}
            placeholder="ALL / JP / US"
          />
        </label>

        <label className="ml-2 text-sm">
          {tx("req_id")}:
          <input
            className="ml-1 w-48 rounded border px-2 py-1 font-mono"
            value={reqIDFilter}
            onChange={(e) => setReqIDFilter(e.target.value)}
            placeholder={tx("req-...")}
          />
        </label>

        {reqIDActive && (
          <button
            className="rounded border px-3 py-1 text-sm"
            onClick={() => setReqIDFilter("")}
          >
            {tx("Clear req_id")}
          </button>
        )}

        <label className="ml-2 text-sm">
          {tx("Rows")}:
          <select
            className="ml-1 rounded border px-1 py-1"
            value={tail}
            onChange={(e) => setTail(Number(e.target.value))}
          >
            {[30, 50, 100, 200].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>

        <button
          className="ml-auto text-sm underline"
          onClick={async () => {
            try {
              await downloadAll();
            } catch (e) {
              console.error(e);
              alert(tx("Download failed. Check the browser console."));
            }
          }}
          title={tx("Download all log files")}
        >
          {tx("Download")}
        </button>

        <button
          disabled={loading}
          onClick={() => {
            setDir(undefined);
            load({ reset: true });
          }}
          className="rounded border px-3 py-1 text-sm"
          title={tx("Reload from latest")}
        >
          {tx("Reload latest")}
        </button>
      </div>

      <div className="flex items-center gap-2">
        <button
          disabled={loading || !canPrev || !!reqIDActive}
          onClick={() => load({ dir: "next" })}
          className="rounded border px-3 py-1 text-sm"
          title={tx("Previous page")}
        >
          {tx("◀ prev")}
        </button>
        <button
          disabled={loading || !canNext || !!reqIDActive}
          onClick={() => load({ dir: "prev" })}
          className="rounded border px-3 py-1 text-sm"
          title={tx("Next page")}
        >
          {tx("next ▶")}
        </button>
        {loading && <span className="text-sm text-gray-500">{tx("loading…")}</span>}
        {reqIDActive && (
          <span className="text-sm text-gray-500">
            {tx("request filter active")}: <code>{reqIDActive}</code>
          </span>
        )}
        {searchActive && (
          <span className="text-sm text-gray-500">
            {tx("search active")}: <code>{searchActive}</code>
          </span>
        )}
      </div>

      {loadError && (
        <div className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {loadError}
        </div>
      )}

      <div className="app-table-shell">
        <div className="app-table-x-scroll">
        <table className="app-table min-w-[1120px] w-full text-sm">
          <thead className="app-table-head">
            <tr>
              <th className="px-2 py-1 text-left">{tx("ts")}</th>
              <th className="px-2 py-1 text-left">{tx("status")}</th>
              <th className="px-2 py-1 text-left">{tx("event")}</th>
              <th className="px-2 py-1 text-left">{tx("rule_id")}</th>
              <th className="px-2 py-1 text-left">{tx("method")}</th>
              <th className="px-2 py-1 text-left">{tx("country")}</th>
              <th className="px-2 py-1 text-left">{tx("host")}</th>
              <th className="px-2 py-1 text-left">{tx("path")}</th>
              <th className="px-2 py-1 text-left">{tx("req_id")}</th>
              <th className="px-2 py-1 text-left">{tx("raw")}</th>
            </tr>
          </thead>
          <tbody>
            {displayLines.map((line, i) => {
              const reqID = String(line.req_id ?? "").trim();
              const clickable = !!reqID;
              return (
                <tr
                  key={i}
                  className={classNames(
                    colorClass(line),
                    clickable && "cursor-pointer hover:bg-neutral-50/80"
                  )}
                  onClick={clickable ? () => void openRequestDetail(reqID) : undefined}
                >
                  <td className="whitespace-nowrap px-2 py-1">{formatTimestamp(line.ts, locale)}</td>
                  <td className="px-2 py-1">{line.status ?? "-"}</td>
                  <td className="px-2 py-1">{String(line.event ?? "-")}</td>
                  <td className="px-2 py-1">{String(line.rule_id ?? "-")}</td>
                  <td className="px-2 py-1">{line.method ?? "-"}</td>
                  <td className="px-2 py-1">{displayCountry(line.country)}</td>
                  <td className="px-2 py-1">{displayHost(line)}</td>
                  <td className="px-2 py-1">{line.path ?? "-"}</td>
                  <td className="px-2 py-1">
                    {reqID ? (
                      <button
                        className="font-mono underline"
                        onClick={(e) => {
                          e.stopPropagation();
                          void openRequestDetail(reqID);
                        }}
                      >
                        {reqID}
                      </button>
                    ) : (
                      "-"
                    )}
                  </td>
                  <td className="px-2 py-1" onClick={(e) => e.stopPropagation()}>
                    <details>
                      <summary className="cursor-pointer underline">{tx("JSON")}</summary>
                      <div className="mt-2 app-code-shell">
                        <pre className="app-code-block">{JSON.stringify(line, null, 2)}</pre>
                      </div>
                    </details>
                  </td>
                </tr>
              );
            })}
            {!data?.lines?.length && (
              <tr>
                <td colSpan={10} className="px-2 py-6 text-center text-gray-500">
                  {tx("No data.")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        </div>
      </div>

      {data && (
        <div className="text-xs text-gray-500">
          has_more: {String(data.has_more)} / next_cursor:{" "}
          {data.next_cursor != null ? data.next_cursor : "-"} / page: [{pageStart ?? "-"},{" "}
          {pageEnd ?? "-"}) / country: {normalizedCountry} / search: {searchActive || "-"}
        </div>
      )}

      {detailReqID && (
        <div className="fixed inset-0 z-40">
          <div className="absolute inset-0 bg-black/20" onClick={() => setDetailReqID(null)} aria-hidden="true" />
          <div className="relative ml-auto h-full w-full max-w-2xl overflow-y-auto border-l bg-white shadow-2xl">
            <div className="sticky top-0 border-b bg-white px-4 py-3">
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <h2 className="text-lg font-semibold">{tx("Request Detail")}</h2>
                  {detailSummary && (
                    <>
                      <p className="text-sm text-gray-700">{detailSummary.summaryText}</p>
                      <p className="text-sm text-gray-500">
                        {tx("Final status")}:{" "}
                        {detailSummary.explanation.httpStatusText}
                      </p>
                    </>
                  )}
                </div>
                <button
                  className="rounded border px-3 py-1 text-sm"
                  onClick={() => setDetailReqID(null)}
                >
                  {tx("Close")}
                </button>
              </div>
            </div>

            <div className="space-y-3 p-4">
              {detailLoading && <div className="text-sm text-gray-500">{tx("loading…")}</div>}
              {detailError && (
                <div className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                  {detailError}
                </div>
              )}
              {!detailLoading && !detailError && detailSummary?.orderedLines.length === 0 && (
                <div className="rounded border bg-gray-50 px-3 py-4 text-sm text-gray-500">
                  {tx("No events found for")} <code>{detailReqID}</code>.
                </div>
              )}
              {detailSummary && (
                <section className="rounded border bg-gray-50 p-4">
                  <p className="text-sm text-gray-700">{detailSummary.summaryText}</p>
                  <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
                    <div className="rounded border bg-white p-3">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("Final decision")}
                      </div>
                      <div className="mt-2">
                        <span
                          className={classNames(
                            "rounded px-2 py-1 text-sm font-semibold",
                            decisionBadgeClass(detailSummary.explanation.decision)
                          )}
                        >
                          {formatDecisionLabel(detailSummary.explanation.decision)}
                        </span>
                      </div>
                    </div>
                    <div className="rounded border bg-white p-3">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("Primary reason")}
                      </div>
                      <div className="mt-2 text-sm font-medium text-gray-900">
                        {detailSummary.explanation.primaryReasonText}
                      </div>
                    </div>
                    <div className="rounded border bg-white p-3">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("HTTP status")}
                      </div>
                      <div className="mt-2 text-sm font-medium text-gray-900">
                        {detailSummary.explanation.httpStatusText}
                      </div>
                    </div>
                    <div className="rounded border bg-white p-3">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("Contributing policies")}
                      </div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {detailSummary.explanation.contributingPolicies.length > 0 ? (
                          detailSummary.explanation.contributingPolicies.map((policy) => (
                            <span
                              key={policy}
                              className="rounded bg-black px-2 py-1 text-xs font-medium text-white"
                            >
                              {formatPolicyLabel(policy)}
                            </span>
                          ))
                        ) : (
                          <span className="text-sm text-gray-500">{tx("none")}</span>
                        )}
                      </div>
                    </div>
                    <div className="rounded border bg-white p-3 md:col-span-2">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("Dry-run findings")}
                      </div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {detailSummary.explanation.dryRunPolicies.length > 0 ? (
                          detailSummary.explanation.dryRunPolicies.map((policy) => (
                            <span
                              key={policy}
                              className="rounded bg-sky-100 px-2 py-1 text-xs font-medium text-sky-700"
                            >
                              {formatPolicyLabel(policy)}
                            </span>
                          ))
                        ) : (
                          <span className="text-sm text-gray-500">{tx("none")}</span>
                        )}
                      </div>
                    </div>
                    <div className="rounded border bg-white p-3 md:col-span-2">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("Rationale")}
                      </div>
                      <div className="mt-2 text-sm text-gray-900">
                        {detailSummary.explanation.rationale}
                      </div>
                    </div>
                  </div>
                </section>
              )}
              {detailAudit && (
                <section className="rounded border bg-slate-50 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-slate-900 px-2 py-1 text-sm font-semibold text-white">
                      {formatSecurityAuditAction(detailAudit.final_action)}
                    </span>
                    <span className="rounded bg-white px-2 py-1 text-xs font-medium text-slate-700">
                      {tx("integrity")}: {formatSecurityAuditVerify(detailAuditVerify)}
                    </span>
                    <span className="text-xs text-slate-500">
                      {tx("seq")} {detailAudit.integrity.sequence} / {tx("key")} {detailAudit.integrity.key_id}
                    </span>
                  </div>

                  <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
                    <div className="rounded border bg-white p-3">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("Terminal policy")}
                      </div>
                      <div className="mt-2 text-sm font-medium text-gray-900">
                        {detailAudit.terminal_policy || "-"}
                      </div>
                    </div>
                    <div className="rounded border bg-white p-3">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("Terminal event")}
                      </div>
                      <div className="mt-2 text-sm font-medium text-gray-900">
                        {detailAudit.terminal_event || "-"}
                      </div>
                    </div>
                    <div className="rounded border bg-white p-3">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("Entry hash")}
                      </div>
                      <div className="mt-2 break-all font-mono text-xs text-gray-900">
                        {detailAudit.integrity.entry_hash}
                      </div>
                    </div>
                    <div className="rounded border bg-white p-3">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("Previous hash")}
                      </div>
                      <div className="mt-2 break-all font-mono text-xs text-gray-900">
                        {detailAudit.integrity.prev_hash || "-"}
                      </div>
                    </div>
                  </div>

                  {detailAudit.evidence && (
                    <div className="mt-3 rounded border bg-white p-3">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("Encrypted evidence")}
                      </div>
                      <dl className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-2">
                        <div className="rounded bg-gray-50 p-2">
                          <dt className="text-xs uppercase tracking-wide text-gray-500">
                            {tx("Capture ID")}
                          </dt>
                          <dd className="mt-1 break-all font-mono text-xs text-gray-900">
                            {detailAudit.evidence.capture_id}
                          </dd>
                        </div>
                        <div className="rounded bg-gray-50 p-2">
                          <dt className="text-xs uppercase tracking-wide text-gray-500">
                            {tx("Cipher")}
                          </dt>
                          <dd className="mt-1 text-sm text-gray-900">
                            {detailAudit.evidence.cipher}
                          </dd>
                        </div>
                        <div className="rounded bg-gray-50 p-2">
                          <dt className="text-xs uppercase tracking-wide text-gray-500">
                            {tx("Headers")}
                          </dt>
                          <dd className="mt-1 text-sm text-gray-900">
                            {detailAudit.evidence.headers_captured ? tx("captured") : tx("not captured")}
                          </dd>
                        </div>
                        <div className="rounded bg-gray-50 p-2">
                          <dt className="text-xs uppercase tracking-wide text-gray-500">
                            {tx("Body")}
                          </dt>
                          <dd className="mt-1 text-sm text-gray-900">
                            {detailAudit.evidence.body_captured
                              ? detailAudit.evidence.body_truncated
                                ? tx("captured (truncated)")
                                : tx("captured")
                              : detailAudit.evidence.body_redacted
                                ? tx("redacted")
                                : tx("not captured")}
                          </dd>
                        </div>
                      </dl>
                    </div>
                  )}

                  {detailAudit.decision_chain?.length ? (
                    <div className="mt-3 space-y-2">
                      <div className="text-xs uppercase tracking-wide text-gray-500">
                        {tx("Decision chain")}
                      </div>
                      {detailAudit.decision_chain.map((node) => (
                        <div key={`audit-node-${node.step}`} className="rounded border bg-white p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="rounded bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-700">
                              {tx("step {step}", { step: node.step })}
                            </span>
                            <span className="text-sm font-medium text-gray-900">
                              {summarizeSecurityAuditNode(node)}
                            </span>
                          </div>
                          <div className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-2">
                            <div className="rounded bg-gray-50 p-2 text-xs text-gray-700">
                              {tx("phase")}: {node.phase || "-"} / {tx("matched")}: {String(!!node.matched)}
                              {typeof node.threshold === "number" ? ` / ${tx("threshold")}: ${node.threshold}` : ""}
                              {typeof node.status === "number" ? ` / ${tx("status")}: ${node.status}` : ""}
                            </div>
                            <div className="rounded bg-gray-50 p-2 text-xs text-gray-700">
                              {tx("score")}: {typeof node.score_before === "number" ? node.score_before : "-"}{" "}
                              {"->"} {typeof node.score_after === "number" ? node.score_after : "-"}
                              {typeof node.score_delta === "number" ? ` (${tx("delta")} ${node.score_delta})` : ""}
                            </div>
                          </div>
                          {node.metadata && Object.keys(node.metadata).length > 0 && (
                            <div className="mt-2 app-code-shell">
                              <pre className="app-code-block">{JSON.stringify(node.metadata, null, 2)}</pre>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : null}

                  {detailAudit.warnings?.length ? (
                    <div className="mt-3 rounded border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
                      {detailAudit.warnings.join(", ")}
                    </div>
                  ) : null}
                </section>
              )}
              {detailSummary?.orderedEvents.map((entry, index) => {
                const fields = extractRequestEventFields(entry.line);
                return (
                  <section
                    key={`${entry.line.event ?? "event"}-${index}`}
                    className="rounded border p-4"
                  >
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="rounded bg-black px-2 py-0.5 text-xs font-semibold text-white">
                        {String(entry.line.event ?? "unknown")}
                      </span>
                      <span
                        className={classNames(
                          "rounded px-2 py-0.5 text-xs font-semibold",
                          roleBadgeClass(entry.role)
                        )}
                      >
                        {formatRequestEventRoleLabel(entry.role)}
                      </span>
                      <span className="text-sm text-gray-600">{formatTimestamp(entry.line.ts, locale)}</span>
                      <span className="text-sm text-gray-600">{entry.line.method ?? "-"}</span>
                      <span className="text-sm text-gray-600">{entry.line.path ?? "-"}</span>
                    </div>
                    {fields.length > 0 ? (
                      <dl className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
                        {fields.map((field) => (
                          <div key={`${field.label}:${field.value}`} className="rounded bg-gray-50 p-2">
                            <dt className="text-xs uppercase tracking-wide text-gray-500">
                              {field.label}
                            </dt>
                            <dd className="mt-1 break-all font-mono text-sm text-gray-900">
                              {field.value}
                            </dd>
                          </div>
                        ))}
                      </dl>
                    ) : (
                      <p className="mt-3 text-sm text-gray-500">{tx("No extra fields.")}</p>
                    )}
                  </section>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
