import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { AUTH_REQUIRED_EVENT, APIUnauthorizedError, apiGetJson, apiPostJson } from "./api";

type AdminSessionState = {
  authenticated: boolean;
  mode: string;
  expires_at?: string;
};

type AuthContextValue = {
  session: AdminSessionState;
  loading: boolean;
  login: (apiKey: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};

const defaultSession: AdminSessionState = {
  authenticated: false,
  mode: "none",
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AdminSessionState>(defaultSession);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const next = await apiGetJson<AdminSessionState>("/auth/session");
      setSession({
        authenticated: !!next.authenticated,
        mode: next.mode || "none",
        expires_at: next.expires_at,
      });
    } catch (error) {
      if (!(error instanceof APIUnauthorizedError)) {
        setSession(defaultSession);
        return;
      }
      setSession(defaultSession);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const onAuthRequired = () => {
      setSession(defaultSession);
      setLoading(false);
    };

    globalThis.addEventListener?.(AUTH_REQUIRED_EVENT, onAuthRequired);
    return () => {
      globalThis.removeEventListener?.(AUTH_REQUIRED_EVENT, onAuthRequired);
    };
  }, []);

  const login = useCallback(async (apiKey: string) => {
    setLoading(true);
    try {
      const next = await apiPostJson<AdminSessionState>("/auth/login", { api_key: apiKey });
      setSession({
        authenticated: !!next.authenticated,
        mode: next.mode || "session",
        expires_at: next.expires_at,
      });
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    setLoading(true);
    try {
      await apiPostJson("/auth/logout", {});
    } catch (error) {
      if (!(error instanceof APIUnauthorizedError)) {
        throw error;
      }
    } finally {
      setSession(defaultSession);
      setLoading(false);
    }
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({ session, loading, login, logout, refresh }),
    [session, loading, login, logout, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return value;
}
