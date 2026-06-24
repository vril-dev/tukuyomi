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
  const { login, verifyMFA, actionLoading } = useAuth();
  const { tx } = useI18n();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMFACode] = useState("");
  const [mfaChallenge, setMFAChallenge] = useState("");
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
      if (mfaChallenge) {
        await verifyMFA(mfaChallenge, mfaCode);
        setMFACode("");
        setMFAChallenge("");
        return;
      }
      const result = await login(identifier, password);
      setPassword("");
      if (result.mfa_required && result.challenge_token) {
        setMFAChallenge(result.challenge_token);
        setMFACode("");
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message || tx("Login failed"));
    }
  }

  function resetPasswordStep() {
    setMFAChallenge("");
    setMFACode("");
    setPassword("");
    setError("");
  }

  return (
    <div className="login-screen">
      <section className="login-card">
        <div className="login-card-header">
          <p className="eyebrow">TUKUYOMI</p>
          <h1>{tx("Admin Sign In")}</h1>
        </div>

        <form className="login-form" onSubmit={onSubmit}>
          {mfaChallenge ? (
            <div className="form-message info">
              {tx("Enter the 6-digit code from your authenticator app or a recovery code.")}
            </div>
          ) : null}

          {!mfaChallenge ? (
            <>
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
            </>
          ) : (
            <label>
              <span>{tx("Authentication code")}</span>
              <input
                type="text"
                value={mfaCode}
                onChange={(event) => setMFACode(event.target.value)}
                autoComplete="one-time-code"
                placeholder={tx("6-digit code or recovery code")}
                required
              />
            </label>
          )}

          {noticeKey ? <div className="form-message success">{tx(noticeKey)}</div> : null}
          {error ? <div className="form-message error">{error}</div> : null}

          <button
            type="submit"
            className="login-submit"
            disabled={actionLoading || (mfaChallenge ? !mfaCode.trim() : !identifier.trim() || !password.trim())}
          >
            {actionLoading ? tx("Signing in...") : mfaChallenge ? tx("Verify") : tx("Sign In")}
          </button>
          {mfaChallenge ? (
            <button type="button" className="secondary-btn" onClick={resetPasswordStep} disabled={actionLoading}>
              {tx("Back to password")}
            </button>
          ) : null}
        </form>
      </section>
    </div>
  );
}
