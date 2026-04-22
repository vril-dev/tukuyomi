import { createContext, useContext } from "react";

export type AdminRuntimeStatus = {
  admin_read_only?: boolean;
};

export type AdminRuntimeContextValue = {
  loading: boolean;
  readOnly: boolean;
  refresh: () => Promise<void>;
};

export const AdminRuntimeContext = createContext<AdminRuntimeContextValue>({
  loading: true,
  readOnly: false,
  refresh: async () => {},
});

export function useAdminRuntime() {
  return useContext(AdminRuntimeContext);
}
