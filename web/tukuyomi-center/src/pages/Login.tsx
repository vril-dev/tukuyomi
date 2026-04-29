import { useEffect, useState, type FormEvent } from "react";

import { useAuth } from "@/lib/auth";
import { useI18n } from "@/lib/i18n";

export default function Login({
  noticeKey,
  clearNotice,
}: {
  noticeKey: string;
  clearNotice: () => void;
}) {
  const { login, loading } = useAuth();
  const { tx } = useI18n();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!noticeKey) {
      return;
    }
    setError("");
  }, [noticeKey]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearNotice();
    setError("");

    try {
      await login(identifier, password);
      setPassword("");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message || tx("Login failed"));
    }
  }

  return (
    <div className="login-screen">
      <section className="login-card">
        <div className="login-card-header">
          <p className="eyebrow">TUKUYOMI</p>
          <h1>{tx("Admin Sign In")}</h1>
          <p>{tx("Sign in with your admin user to create a browser session.")}</p>
        </div>

        <form className="login-form" onSubmit={onSubmit}>
          <label>
            <span>{tx("Username or email")}</span>
            <input
              value={identifier}
              onChange={(event) => setIdentifier(event.target.value)}
              autoComplete="username"
              placeholder={tx("admin username or email")}
              required
            />
          </label>

          <label>
            <span>{tx("Password")}</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              placeholder={tx("admin password")}
              required
            />
          </label>

          {noticeKey ? <div className="form-message success">{tx(noticeKey)}</div> : null}
          {error ? <div className="form-message error">{error}</div> : null}

          <button type="submit" className="login-submit" disabled={loading || !identifier.trim() || !password.trim()}>
            {loading ? tx("Signing in...") : tx("Sign In")}
          </button>
        </form>
      </section>
    </div>
  );
}
