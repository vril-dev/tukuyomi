import { useState, type FormEvent } from "react";

import { useAuth } from "@/lib/auth";

export default function Login() {
  const { login, loading } = useAuth();
  const [apiKey, setAPIKey] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    try {
      await login(apiKey);
      setAPIKey("");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message || "Login failed");
    }
  }

  return (
    <div className="min-h-screen bg-neutral-100 text-neutral-950 flex items-center justify-center px-4">
      <div className="w-full max-w-md rounded-[28px] border border-neutral-200 bg-white shadow-sm p-8 space-y-6">
        <div className="space-y-2">
          <p className="text-xs uppercase tracking-[0.3em] text-neutral-500">TUKUYOMI</p>
          <h1 className="text-3xl font-semibold">Admin Sign In</h1>
          <p className="text-sm text-neutral-600">
            Enter an admin API key once to create a browser session. The key stays server-side after login.
          </p>
        </div>

        <form className="space-y-4" onSubmit={onSubmit}>
          <label className="block space-y-2">
            <span className="text-sm font-medium text-neutral-700">Admin API Key</span>
            <input
              type="password"
              className="w-full rounded-xl border border-neutral-300 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-neutral-900/10"
              value={apiKey}
              onChange={(event) => setAPIKey(event.target.value)}
              autoComplete="current-password"
              placeholder="paste a primary or secondary admin key"
            />
          </label>

          {error ? (
            <div className="rounded-xl border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800">
              {error}
            </div>
          ) : null}

          <button
            type="submit"
            disabled={loading || apiKey.trim() === ""}
            className="w-full rounded-xl bg-neutral-950 px-4 py-2.5 text-sm font-medium text-white disabled:opacity-50"
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}
