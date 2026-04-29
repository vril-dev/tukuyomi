import { useCallback, useEffect, useRef, useState } from "react";

import { apiGetJson, apiPostJson } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

type CenterStatus = {
  total_devices?: number;
  approved_devices?: number;
  pending_enrollments?: number;
  rejected_enrollments?: number;
};

type EnrollmentRecord = {
  enrollment_id: number;
  device_id: string;
  key_id: string;
  public_key_fingerprint_sha256: string;
  requested_at_unix: number;
  remote_addr?: string;
  user_agent?: string;
};

type EnrollmentListResponse = {
  enrollments?: EnrollmentRecord[];
};

function formatUnixTime(value: number, locale: string) {
  if (!value) {
    return "-";
  }
  const date = new Date(value * 1000);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return date.toLocaleString(locale === "ja" ? "ja-JP" : "en-US", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function StatusPage({ focusApprovals = false }: { focusApprovals?: boolean }) {
  const { locale, tx } = useI18n();
  const approvalRef = useRef<HTMLElement | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState<CenterStatus>({});
  const [enrollments, setEnrollments] = useState<EnrollmentRecord[]>([]);
  const [decidingID, setDecidingID] = useState<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setMessage("");
    try {
      const [statusData, enrollmentData] = await Promise.all([
        apiGetJson<CenterStatus>("/status"),
        apiGetJson<EnrollmentListResponse>("/devices/enrollments?status=pending&limit=50"),
      ]);
      setStatus(statusData);
      setEnrollments(Array.isArray(enrollmentData.enrollments) ? enrollmentData.enrollments : []);
    } catch (err) {
      const fallback = tx("Failed to load Center status");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setLoading(false);
    }
  }, [tx]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!focusApprovals) {
      return;
    }
    approvalRef.current?.scrollIntoView({ block: "start" });
  }, [focusApprovals, enrollments.length]);

  async function decide(enrollmentID: number, action: "approve" | "reject") {
    setDecidingID(enrollmentID);
    setMessage("");
    try {
      await apiPostJson(`/devices/enrollments/${enrollmentID}/${action}`, action === "reject" ? { reason: "rejected from center ui" } : {});
      await load();
    } catch (err) {
      const fallback = tx(action === "approve" ? "Failed to approve enrollment" : "Failed to reject enrollment");
      setMessage(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setDecidingID(null);
    }
  }

  return (
    <div className="content-panel">
      <section className="content-section">
        <div className="section-header">
          <div>
            <h2 className="section-title">{tx("Device overview")}</h2>
            {loading ? <p className="section-note">{tx("Loading Center status...")}</p> : null}
          </div>
          <button type="button" onClick={() => void load()} disabled={loading}>
            {tx("Refresh")}
          </button>
        </div>
        <div className="facts">
          <div className="fact">
            <span>{tx("Total devices")}</span>
            <strong>{status.total_devices ?? 0}</strong>
          </div>
          <div className="fact">
            <span>{tx("Approved devices")}</span>
            <strong>{status.approved_devices ?? 0}</strong>
          </div>
          <div className="fact">
            <span>{tx("Pending approvals")}</span>
            <strong>{status.pending_enrollments ?? 0}</strong>
          </div>
          <div className="fact">
            <span>{tx("Rejected enrollments")}</span>
            <strong>{status.rejected_enrollments ?? 0}</strong>
          </div>
        </div>
        {message ? <p className="form-message error">{message}</p> : null}
      </section>

      <section id="device-approvals" ref={approvalRef} className="content-section">
        <h2 className="section-title">{tx("Device enrollment approvals")}</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{tx("Device")}</th>
                <th>{tx("Key")}</th>
                <th>{tx("Fingerprint")}</th>
                <th>{tx("Requested")}</th>
                <th>{tx("Actions")}</th>
              </tr>
            </thead>
            <tbody>
              {enrollments.map((enrollment) => (
                <tr key={enrollment.enrollment_id}>
                  <td title={enrollment.device_id}>{enrollment.device_id}</td>
                  <td title={enrollment.key_id}>{enrollment.key_id}</td>
                  <td title={enrollment.public_key_fingerprint_sha256}>{enrollment.public_key_fingerprint_sha256}</td>
                  <td>{formatUnixTime(enrollment.requested_at_unix, locale)}</td>
                  <td className="actions-cell">
                    <div className="inline-actions">
                      <button
                        type="button"
                        onClick={() => void decide(enrollment.enrollment_id, "approve")}
                        disabled={decidingID === enrollment.enrollment_id}
                      >
                        {tx("Approve")}
                      </button>
                      <button
                        type="button"
                        className="danger"
                        onClick={() => void decide(enrollment.enrollment_id, "reject")}
                        disabled={decidingID === enrollment.enrollment_id}
                      >
                        {tx("Reject")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {enrollments.length === 0 ? <div className="empty">{tx("No pending enrollments.")}</div> : null}
        </div>
      </section>
    </div>
  );
}
