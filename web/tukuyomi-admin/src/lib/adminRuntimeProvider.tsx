import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { apiGetJson } from "@/lib/api";
import { AdminRuntimeContext, type AdminRuntimeStatus } from "@/lib/adminRuntime";

export function AdminRuntimeProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [readOnly, setReadOnly] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const status = await apiGetJson<AdminRuntimeStatus>("/status");
      setReadOnly(status.admin_read_only === true);
    } catch {
      setReadOnly(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const value = useMemo(
    () => ({
      loading,
      readOnly,
      refresh,
    }),
    [loading, readOnly, refresh],
  );

  return <AdminRuntimeContext.Provider value={value}>{children}</AdminRuntimeContext.Provider>;
}
