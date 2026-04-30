import { useCallback, useEffect, useState } from "react";

import { apiGetJson } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

type CenterStatus = {
  total_devices?: number;
  approved_devices?: number;
  pending_enrollments?: number;
  rejected_enrollments?: number;
};

export default function StatusPage() {
  const { tx } = useI18n();
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState<CenterStatus>({});

  const load = useCallback(async () => {
    setLoading(true);
    setMessage("");
    try {
      const data = await apiGetJson<CenterStatus>("/status");
      setStatus(data);
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

  return (
    <div className="content-panel">
      <section className="content-section">
        <div className="section-header">
          <div>
            <h2 className="section-title">{tx("Device overview")}</h2>
            {loading ? <p className="section-note">{tx("Loading Center status...")}</p> : null}
          </div>
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
    </div>
  );
}
