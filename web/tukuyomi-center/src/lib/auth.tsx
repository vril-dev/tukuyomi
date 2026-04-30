import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { APIUnauthorizedError, AUTH_REQUIRED_EVENT, apiGetJson, apiPostJson } from "@/lib/api";

export type CenterSessionUser = {
  user_id?: number;
  username?: string;
  role?: string;
  must_change_password?: boolean;
};

export type CenterSessionState = {
  authenticated: boolean;
  mode: string;
  expires_at?: string;
  must_change_password?: boolean;
  user?: CenterSessionUser;
};

type AuthContextValue = {
  session: CenterSessionState;
  loading: boolean;
  login: (identifier: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};

const defaultSession: CenterSessionState = {
  authenticated: false,
  mode: "none",
};

const AuthContext = createContext<AuthContextValue | null>(null);

function normalizeSession(next: CenterSessionState): CenterSessionState {
  return {
    authenticated: next.authenticated === true,
    mode: next.mode || "none",
    expires_at: next.expires_at,
    must_change_password: next.must_change_password === true,
    user: next.user,
  };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<CenterSessionState>(defaultSession);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const next = await apiGetJson<CenterSessionState>("/auth/session");
      setSession(normalizeSession(next));
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

  const login = useCallback(async (identifier: string, password: string) => {
    setLoading(true);
    try {
      const next = await apiPostJson<CenterSessionState>("/auth/login", {
        identifier,
        password,
      });
      setSession(normalizeSession(next));
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
