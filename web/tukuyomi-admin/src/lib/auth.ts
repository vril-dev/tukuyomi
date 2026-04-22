import { createContext, useContext } from "react";

export type AdminSessionState = {
  authenticated: boolean;
  mode: string;
  expires_at?: string;
};

export type AuthContextValue = {
  session: AdminSessionState;
  loading: boolean;
  login: (apiKey: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};

export const defaultSession: AdminSessionState = {
  authenticated: false,
  mode: "none",
};

export const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return value;
}
