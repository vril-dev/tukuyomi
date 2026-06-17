import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import {
  AuthContext,
  defaultSession,
  type AdminLoginResult,
  type AdminSessionState,
  type AuthContextValue,
} from "@/lib/auth";
import {
  AUTH_REQUIRED_EVENT,
  APIUnauthorizedError,
  apiGetJson,
  apiPostJson,
} from "@/lib/api";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AdminSessionState>(defaultSession);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const next = await apiGetJson<AdminSessionState>("/auth/session");
      setSession({
        authenticated: !!next.authenticated,
        mode: next.mode || "none",
        expires_at: next.expires_at,
        must_change_password: next.must_change_password === true,
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

  const login = useCallback(async (identifier: string, password: string) => {
    setLoading(true);
    try {
      const next = await apiPostJson<AdminLoginResult>("/auth/login", {
        identifier,
        password,
      });
      if (next.mfa_required) {
        setSession(defaultSession);
        return next;
      }
      setSession({
        authenticated: !!next.authenticated,
        mode: next.mode || "session",
        expires_at: next.expires_at,
        must_change_password: next.must_change_password === true,
      });
      return next;
    } finally {
      setLoading(false);
    }
  }, []);

  const verifyMFA = useCallback(async (challengeToken: string, code: string) => {
    setLoading(true);
    try {
      const next = await apiPostJson<AdminLoginResult>("/auth/mfa/verify", {
        challenge_token: challengeToken,
        code,
      });
      setSession({
        authenticated: !!next.authenticated,
        mode: next.mode || "session",
        expires_at: next.expires_at,
        must_change_password: next.must_change_password === true,
      });
      return next;
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
    () => ({ session, loading, login, verifyMFA, logout, refresh }),
    [session, loading, login, verifyMFA, logout, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
