import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";

import { apiGetJson, apiPutJson } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useI18n } from "@/lib/i18n";

type AdminAccount = {
  user_id: number;
  username: string;
  email?: string;
  role: string;
  must_change_password?: boolean;
};

type FormFeedback = {
  tone: "info" | "success" | "error";
  message: string;
};

export default function UserPage({ onPasswordChanged }: { onPasswordChanged: () => void }) {
  const { tx } = useI18n();
  const { refresh, session } = useAuth();
  const [loading, setLoading] = useState(true);
  const [accountSaving, setAccountSaving] = useState(false);
  const [passwordSaving, setPasswordSaving] = useState(false);
  const [account, setAccount] = useState<AdminAccount | null>(null);
  const [loadError, setLoadError] = useState("");
  const [accountFeedback, setAccountFeedback] = useState<FormFeedback | null>(null);
  const [passwordFeedback, setPasswordFeedback] = useState<FormFeedback | null>(null);
  const [accountForm, setAccountForm] = useState({
    username: "",
    email: "",
    currentPassword: "",
  });
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: "",
    newPassword: "",
  });

  const loadAccount = useCallback(async () => {
    setLoading(true);
    setLoadError("");
    try {
      const data = await apiGetJson<AdminAccount>("/auth/account");
      setAccount(data);
      setAccountForm({
        username: data.username || "",
        email: data.email || "",
        currentPassword: "",
      });
    } catch (err) {
      const fallback = tx("Failed to load account");
      setLoadError(err instanceof Error ? err.message || fallback : fallback);
    } finally {
      setLoading(false);
    }
  }, [tx]);

  useEffect(() => {
    void loadAccount();
  }, [loadAccount]);

  async function onSaveAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccountFeedback(null);
    setPasswordFeedback(null);
    if (!accountForm.username.trim()) {
      setAccountFeedback({ tone: "error", message: tx("Username is required.") });
      return;
    }
    if (!accountForm.currentPassword) {
      setAccountFeedback({ tone: "error", message: tx("Enter your current password to save account changes.") });
      return;
    }

    setAccountSaving(true);
    setAccountFeedback({ tone: "info", message: tx("Saving account changes...") });
    try {
      const next = await apiPutJson<AdminAccount>("/auth/account", {
        username: accountForm.username,
        email: accountForm.email,
        current_password: accountForm.currentPassword,
      });
      setAccount(next);
      setAccountForm({
        username: next.username || "",
        email: next.email || "",
        currentPassword: "",
      });
      setAccountFeedback({ tone: "success", message: tx("Account saved.") });
      await refresh();
    } catch (err) {
      const fallback = tx("Failed to save account");
      setAccountFeedback({ tone: "error", message: err instanceof Error ? err.message || fallback : fallback });
    } finally {
      setAccountSaving(false);
    }
  }

  async function onChangePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccountFeedback(null);
    setPasswordFeedback(null);
    if (!passwordForm.currentPassword) {
      setPasswordFeedback({ tone: "error", message: tx("Enter your current password to change password.") });
      return;
    }
    if (passwordForm.newPassword.length < 12) {
      setPasswordFeedback({ tone: "error", message: tx("New password must be at least 12 characters.") });
      return;
    }

    setPasswordSaving(true);
    setPasswordFeedback({ tone: "info", message: tx("Changing password...") });
    try {
      await apiPutJson("/auth/password", {
        current_password: passwordForm.currentPassword,
        new_password: passwordForm.newPassword,
      });
      setPasswordForm({ currentPassword: "", newPassword: "" });
      onPasswordChanged();
      await refresh();
    } catch (err) {
      const fallback = tx("Failed to change password");
      setPasswordFeedback({ tone: "error", message: err instanceof Error ? err.message || fallback : fallback });
    } finally {
      setPasswordSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="content-panel">
        <section className="content-section">
          <p className="section-note">{tx("Loading user...")}</p>
        </section>
      </div>
    );
  }

  return (
    <div className="content-panel user-page">
      <section className="content-section">
        <div className="section-header">
          <div>
            <h2 className="section-title">{tx("User")}</h2>
          </div>
        </div>
        <div className="summary-grid rules-summary-grid">
          <div>
            <span>{tx("user")}</span>
            <strong>{account?.username || "-"}</strong>
          </div>
          <div>
            <span>{tx("role")}</span>
            <strong>{account?.role || "-"}</strong>
          </div>
          <div>
            <span>{tx("Password")}</span>
            <strong>{account?.must_change_password || session.must_change_password ? tx("Password change required") : tx("current")}</strong>
          </div>
        </div>

        {account?.must_change_password || session.must_change_password ? (
          <p className="form-message warning">{tx("Change the initial password before continuing.")}</p>
        ) : null}

        {loadError ? <p className="form-message error">{loadError}</p> : null}

        <div className="device-detail-section">
          <h3>{tx("Account")}</h3>
          <form onSubmit={onSaveAccount}>
            <div className="grid gap-3 md:grid-cols-2">
              <UserField label={tx("Username")}>
                <input
                  value={accountForm.username}
                  onChange={(event) => setAccountForm((current) => ({ ...current, username: event.target.value }))}
                  autoComplete="username"
                  disabled={accountSaving}
                  required
                />
              </UserField>
              <UserField label={tx("Email")}>
                <input
                  value={accountForm.email}
                  onChange={(event) => setAccountForm((current) => ({ ...current, email: event.target.value }))}
                  autoComplete="email"
                  disabled={accountSaving}
                />
              </UserField>
              <UserField label={tx("Current password")} hint={tx("Required to save account changes.")}>
                <input
                  type="password"
                  value={accountForm.currentPassword}
                  onChange={(event) => setAccountForm((current) => ({ ...current, currentPassword: event.target.value }))}
                  autoComplete="current-password"
                  disabled={accountSaving}
                />
              </UserField>
            </div>
            <div className="form-footer">
              <button type="submit" disabled={accountSaving}>
                {accountSaving ? tx("Saving...") : tx("Save Account")}
              </button>
              <FormMessage feedback={accountFeedback} />
            </div>
          </form>
        </div>

        <div className="device-detail-section">
          <h3>{tx("Change Password")}</h3>
          <form onSubmit={onChangePassword}>
            <input className="visually-hidden" value={account?.username || ""} readOnly autoComplete="username" tabIndex={-1} />
            <div className="grid gap-3 md:grid-cols-2">
              <UserField label={tx("Current password")}>
                <input
                  type="password"
                  value={passwordForm.currentPassword}
                  onChange={(event) => setPasswordForm((current) => ({ ...current, currentPassword: event.target.value }))}
                  autoComplete="current-password"
                  disabled={passwordSaving}
                />
              </UserField>
              <UserField label={tx("New password")} hint={tx("12 characters minimum.")}>
                <input
                  type="password"
                  value={passwordForm.newPassword}
                  onChange={(event) => setPasswordForm((current) => ({ ...current, newPassword: event.target.value }))}
                  autoComplete="new-password"
                  disabled={passwordSaving}
                />
              </UserField>
            </div>
            <div className="form-footer">
              <button type="submit" disabled={passwordSaving}>
                {passwordSaving ? tx("Saving...") : tx("Change Password")}
              </button>
              <FormMessage feedback={passwordFeedback} />
            </div>
          </form>
        </div>
      </section>
    </div>
  );
}

function UserField({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="user-field">
      <span>{label}</span>
      {children}
      {hint ? <span className="field-hint">{hint}</span> : null}
    </label>
  );
}

function FormMessage({ feedback }: { feedback: FormFeedback | null }) {
  if (!feedback) {
    return null;
  }
  return (
    <span className={`form-message ${feedback.tone}`} role={feedback.tone === "error" ? "alert" : "status"}>
      {feedback.message}
    </span>
  );
}
