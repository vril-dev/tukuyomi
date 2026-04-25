import { useState, type FormEvent } from "react";

import { useAuth } from "@/lib/auth";
import { useI18n } from "@/lib/i18n";

export default function Login() {
  const { login, loading } = useAuth();
  const { tx } = useI18n();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    try {
      await login(identifier, password);
      setPassword("");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message || tx("Login failed"));
    }
  }

  return (
    <div className="min-h-screen bg-neutral-100 text-neutral-950 flex items-center justify-center px-4">
      <div className="w-full max-w-md rounded-[28px] border border-neutral-200 bg-white shadow-sm p-8 space-y-6">
        <div className="space-y-2">
          <p className="text-xs uppercase tracking-[0.3em] text-neutral-500">
            TUKUYOMI
          </p>
          <h1 className="text-3xl font-semibold">{tx("Admin Sign In")}</h1>
          <p className="text-sm text-neutral-600">
            {tx("Sign in with your admin user to create a browser session.")}
          </p>
        </div>

        <form className="space-y-4" onSubmit={onSubmit}>
          <label className="block space-y-2">
            <span className="text-sm font-medium text-neutral-700">
              {tx("Username or email")}
            </span>
            <input
              type="text"
              className="w-full rounded-xl border border-neutral-300 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-neutral-900/10"
              value={identifier}
              onChange={(event) => setIdentifier(event.target.value)}
              autoComplete="username"
              placeholder={tx("admin username or email")}
            />
          </label>

          <label className="block space-y-2">
            <span className="text-sm font-medium text-neutral-700">
              {tx("Password")}
            </span>
            <input
              type="password"
              className="w-full rounded-xl border border-neutral-300 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-neutral-900/10"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              placeholder={tx("admin password")}
            />
          </label>

          {error ? (
            <div className="rounded-xl border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800">
              {error}
            </div>
          ) : null}

          <button
            type="submit"
            disabled={
              loading || identifier.trim() === "" || password.trim() === ""
            }
            className="w-full rounded-xl bg-neutral-950 px-4 py-2.5 text-sm font-medium text-white disabled:opacity-50"
          >
            {loading ? tx("Signing in...") : tx("Sign In")}
          </button>
        </form>
      </div>
    </div>
  );
}
