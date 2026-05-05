import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";

import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useI18n } from "@/lib/i18n";

type AdminAccount = {
  user_id: number;
  username: string;
  email?: string;
  role: string;
  must_change_password?: boolean;
};

type AdminAPIToken = {
  token_id: number;
  label: string;
  prefix: string;
  scopes: string[];
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
  revoked_at?: string;
  active: boolean;
};

type AdminAPITokenListResponse = {
  tokens?: AdminAPIToken[];
};

type AdminAPITokenCreateResponse = {
  token: string;
  record: AdminAPIToken;
};

type FormFeedback = {
  tone: "info" | "success" | "error";
  message: string;
};

function formatAdminTokenTime(value?: string) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function localDateTimeToRFC3339(value: string) {
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }
  const date = new Date(trimmed);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return date.toISOString();
}

export default function UserPage({ onPasswordChanged }: { onPasswordChanged: () => void }) {
  const { tx } = useI18n();
  const { refresh, session } = useAuth();
  const [loading, setLoading] = useState(true);
  const [accountSaving, setAccountSaving] = useState(false);
  const [passwordSaving, setPasswordSaving] = useState(false);
  const [tokenSaving, setTokenSaving] = useState(false);
  const [tokenRevokingID, setTokenRevokingID] = useState<number | null>(null);
  const [account, setAccount] = useState<AdminAccount | null>(null);
  const [apiTokens, setAPITokens] = useState<AdminAPIToken[]>([]);
  const [createdToken, setCreatedToken] = useState("");
  const [loadError, setLoadError] = useState("");
  const [accountFeedback, setAccountFeedback] = useState<FormFeedback | null>(null);
  const [passwordFeedback, setPasswordFeedback] = useState<FormFeedback | null>(null);
  const [tokenFeedback, setTokenFeedback] = useState<FormFeedback | null>(null);
  const [accountForm, setAccountForm] = useState({
    username: "",
    email: "",
    currentPassword: "",
  });
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: "",
    newPassword: "",
  });
  const [tokenForm, setTokenForm] = useState({
    label: "",
    scope: "admin:write",
    expiresAt: "",
    currentPassword: "",
  });

  const loadAccount = useCallback(async () => {
    setLoading(true);
    setLoadError("");
    try {
      const [data, tokenData] = await Promise.all([
        apiGetJson<AdminAccount>("/auth/account"),
        apiGetJson<AdminAPITokenListResponse>("/auth/api-tokens"),
      ]);
      setAccount(data);
      setAccountForm({
        username: data.username || "",
        email: data.email || "",
        currentPassword: "",
      });
      setAPITokens(Array.isArray(tokenData.tokens) ? tokenData.tokens : []);
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
    setCreatedToken("");
    setAccountFeedback(null);
    setPasswordFeedback(null);
    setTokenFeedback(null);
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
    setCreatedToken("");
    setAccountFeedback(null);
    setPasswordFeedback(null);
    setTokenFeedback(null);
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

  async function onCreateAPIToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCreatedToken("");
    setAccountFeedback(null);
    setPasswordFeedback(null);
    setTokenFeedback(null);
    if (!tokenForm.label.trim()) {
      setTokenFeedback({ tone: "error", message: tx("Token label is required.") });
      return;
    }
    if (!tokenForm.currentPassword) {
      setTokenFeedback({ tone: "error", message: tx("Enter your current password to create a token.") });
      return;
    }
    const expiresAt = localDateTimeToRFC3339(tokenForm.expiresAt);
    if (tokenForm.expiresAt.trim() && !expiresAt) {
      setTokenFeedback({ tone: "error", message: tx("Token expiration is invalid.") });
      return;
    }

    setTokenSaving(true);
    setTokenFeedback({ tone: "info", message: tx("Creating token...") });
    try {
      const data = await apiPostJson<AdminAPITokenCreateResponse>("/auth/api-tokens", {
        label: tokenForm.label,
        scopes: [tokenForm.scope],
        expires_at: expiresAt,
        current_password: tokenForm.currentPassword,
      });
      setCreatedToken(data.token);
      setTokenForm({
        label: "",
        scope: "admin:write",
        expiresAt: "",
        currentPassword: "",
      });
      const tokenData = await apiGetJson<AdminAPITokenListResponse>("/auth/api-tokens");
      setAPITokens(Array.isArray(tokenData.tokens) ? tokenData.tokens : [data.record]);
      setTokenFeedback({ tone: "success", message: tx("Personal access token created.") });
    } catch (err) {
      const fallback = tx("Failed to create personal access token");
      setTokenFeedback({ tone: "error", message: err instanceof Error ? err.message || fallback : fallback });
    } finally {
      setTokenSaving(false);
    }
  }

  async function onRevokeAPIToken(tokenID: number) {
    setCreatedToken("");
    setAccountFeedback(null);
    setPasswordFeedback(null);
    setTokenFeedback({ tone: "info", message: tx("Revoking token...") });
    setTokenRevokingID(tokenID);
    try {
      const data = await apiPostJson<AdminAPITokenListResponse>(`/auth/api-tokens/${tokenID}/revoke`, {});
      setAPITokens(Array.isArray(data.tokens) ? data.tokens : []);
      setTokenFeedback({ tone: "success", message: tx("Personal access token revoked.") });
    } catch (err) {
      const fallback = tx("Failed to revoke personal access token");
      setTokenFeedback({ tone: "error", message: err instanceof Error ? err.message || fallback : fallback });
    } finally {
      setTokenRevokingID(null);
    }
  }

  async function onCopyCreatedToken() {
    if (!createdToken || !navigator.clipboard) {
      return;
    }
    try {
      await navigator.clipboard.writeText(createdToken);
      setTokenFeedback({ tone: "success", message: tx("Personal access token copied.") });
    } catch (err) {
      const fallback = tx("Failed to copy personal access token");
      setTokenFeedback({ tone: "error", message: err instanceof Error ? err.message || fallback : fallback });
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

        <div className="device-detail-section">
          <h3>{tx("Personal Access Tokens")}</h3>
          <form onSubmit={onCreateAPIToken}>
            <div className="grid gap-3 md:grid-cols-2">
              <UserField label={tx("Label")}>
                <input
                  value={tokenForm.label}
                  onChange={(event) => setTokenForm((current) => ({ ...current, label: event.target.value }))}
                  disabled={tokenSaving}
                  placeholder="remote ssh cli"
                />
              </UserField>
              <UserField label={tx("Scope")}>
                <select
                  value={tokenForm.scope}
                  onChange={(event) => setTokenForm((current) => ({ ...current, scope: event.target.value }))}
                  disabled={tokenSaving}
                >
                  <option value="admin:read">{tx("Read only")}</option>
                  <option value="admin:write">{tx("Read and write")}</option>
                </select>
              </UserField>
              <UserField label={tx("Expires at")} hint={tx("Leave blank for no expiration.")}>
                <input
                  type="datetime-local"
                  value={tokenForm.expiresAt}
                  onChange={(event) => setTokenForm((current) => ({ ...current, expiresAt: event.target.value }))}
                  disabled={tokenSaving}
                />
              </UserField>
              <UserField label={tx("Current password")} hint={tx("Required to create a token.")}>
                <input
                  type="password"
                  value={tokenForm.currentPassword}
                  onChange={(event) => setTokenForm((current) => ({ ...current, currentPassword: event.target.value }))}
                  autoComplete="current-password"
                  disabled={tokenSaving}
                />
              </UserField>
            </div>
            <div className="form-footer">
              <button type="submit" disabled={tokenSaving}>
                {tokenSaving ? tx("Creating token...") : tx("Create Token")}
              </button>
              <FormMessage feedback={tokenFeedback} />
            </div>
          </form>
        </div>

        {createdToken ? (
          <div className="device-detail-section token-created">
            <h3>{tx("New Personal Access Token")}</h3>
            <label>
              <span>{tx("Generated token")}</span>
              <input value={createdToken} readOnly spellCheck={false} onFocus={(event) => event.currentTarget.select()} />
            </label>
            <p>{tx("Copy and store this token now. It will not be shown again.")}</p>
            <div className="form-footer">
              <button type="button" onClick={() => void onCopyCreatedToken()}>
                {tx("Copy Token")}
              </button>
            </div>
          </div>
        ) : null}

        <div className="device-detail-section">
          <h3>{tx("Existing Personal Access Tokens")}</h3>
          {apiTokens.length === 0 ? (
            <div className="empty">{tx("No personal access tokens.")}</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{tx("Label")}</th>
                    <th>{tx("Prefix")}</th>
                    <th>{tx("Scope")}</th>
                    <th>{tx("Created")}</th>
                    <th>{tx("Last used")}</th>
                    <th>{tx("Expires")}</th>
                    <th>{tx("Status")}</th>
                    <th>{tx("Action")}</th>
                  </tr>
                </thead>
                <tbody>
                  {apiTokens.map((token) => (
                    <tr key={token.token_id}>
                      <td>{token.label}</td>
                      <td className="mono">{token.prefix}</td>
                      <td>{token.scopes.join(", ")}</td>
                      <td>{formatAdminTokenTime(token.created_at)}</td>
                      <td>{formatAdminTokenTime(token.last_used_at)}</td>
                      <td>{formatAdminTokenTime(token.expires_at)}</td>
                      <td>{token.active ? tx("active") : tx("inactive")}</td>
                      <td>
                        <button type="button" onClick={() => void onRevokeAPIToken(token.token_id)} disabled={!token.active || tokenRevokingID === token.token_id}>
                          {tokenRevokingID === token.token_id ? tx("Revoking...") : tx("Revoke")}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
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
