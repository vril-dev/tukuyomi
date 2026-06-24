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

export type CenterLoginResult = CenterSessionState & {
  mfa_required?: boolean;
  challenge_token?: string;
};

type AuthContextValue = {
  session: CenterSessionState;
  loading: boolean;
  actionLoading: boolean;
  sessionError: string;
  login: (identifier: string, password: string) => Promise<CenterLoginResult>;
  verifyMFA: (challengeToken: string, code: string) => Promise<CenterLoginResult>;
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

function sessionErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : "admin session check failed";
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<CenterSessionState>(defaultSession);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [sessionError, setSessionError] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const next = await apiGetJson<CenterSessionState>("/auth/session");
      setSession(normalizeSession(next));
      setSessionError("");
    } catch (error) {
      if (error instanceof APIUnauthorizedError) {
        setSession(defaultSession);
        setSessionError("");
      } else {
        setSessionError(sessionErrorMessage(error));
      }
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
      setSessionError("");
      setLoading(false);
    };

    globalThis.addEventListener?.(AUTH_REQUIRED_EVENT, onAuthRequired);
    return () => {
      globalThis.removeEventListener?.(AUTH_REQUIRED_EVENT, onAuthRequired);
    };
  }, []);

  useEffect(() => {
    if (!sessionError) {
      return;
    }
    const timer = window.setInterval(() => {
      void refresh();
    }, 3000);
    return () => window.clearInterval(timer);
  }, [sessionError, refresh]);

  const login = useCallback(async (identifier: string, password: string) => {
    setActionLoading(true);
    try {
      const next = await apiPostJson<CenterLoginResult>("/auth/login", {
        identifier,
        password,
      });
      if (next.mfa_required) {
        setSession(defaultSession);
        setSessionError("");
        return next;
      }
      setSession(normalizeSession(next));
      setSessionError("");
      return next;
    } finally {
      setActionLoading(false);
    }
  }, []);

  const verifyMFA = useCallback(async (challengeToken: string, code: string) => {
    setActionLoading(true);
    try {
      const next = await apiPostJson<CenterLoginResult>("/auth/mfa/verify", {
        challenge_token: challengeToken,
        code,
      });
      setSession(normalizeSession(next));
      setSessionError("");
      return next;
    } finally {
      setActionLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    setActionLoading(true);
    try {
      await apiPostJson("/auth/logout", {});
    } catch (error) {
      if (!(error instanceof APIUnauthorizedError)) {
        throw error;
      }
    } finally {
      setSession(defaultSession);
      setActionLoading(false);
    }
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({ session, loading, actionLoading, sessionError, login, verifyMFA, logout, refresh }),
    [session, loading, actionLoading, sessionError, login, verifyMFA, logout, refresh],
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
