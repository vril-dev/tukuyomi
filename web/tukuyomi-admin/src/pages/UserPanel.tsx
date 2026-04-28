import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";

import { apiGetJson, apiPostJson, apiPutJson } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
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

export default function UserPanel() {
  const { tx } = useI18n();
  const { readOnly } = useAdminRuntime();
  const { refresh, session } = useAuth();
  const [loading, setLoading] = useState(true);
  const [accountSaving, setAccountSaving] = useState(false);
  const [passwordSaving, setPasswordSaving] = useState(false);
  const [tokenSaving, setTokenSaving] = useState(false);
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
    scope: "admin:read",
    expiresAt: "",
    currentPassword: "",
  });

  const loadUserSecurity = useCallback(async () => {
    setLoading(true);
    setLoadError("");
    try {
      const [accountData, tokenData] = await Promise.all([
        apiGetJson<AdminAccount>("/auth/account"),
        apiGetJson<AdminAPITokenListResponse>("/auth/api-tokens"),
      ]);
      setAccount(accountData);
      setAccountForm((current) => ({
        ...current,
        username: accountData.username || "",
        email: accountData.email || "",
        currentPassword: "",
      }));
      setAPITokens(Array.isArray(tokenData.tokens) ? tokenData.tokens : []);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setLoadError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadUserSecurity();
  }, [loadUserSecurity]);

  function clearFeedback() {
    setCreatedToken("");
    setAccountFeedback(null);
    setPasswordFeedback(null);
    setTokenFeedback(null);
  }

  function setFormError(setter: (feedback: FormFeedback) => void, message: string) {
    setter({ tone: "error", message });
  }

  function setFormNotice(setter: (feedback: FormFeedback) => void, message: string) {
    setter({ tone: "success", message });
  }

  async function onSaveAccount(e: FormEvent) {
    e.preventDefault();
    clearFeedback();
    if (!accountForm.username.trim()) {
      setFormError(setAccountFeedback, tx("Username is required."));
      return;
    }
    if (!accountForm.currentPassword) {
      setFormError(setAccountFeedback, tx("Enter your current password to save account changes."));
      return;
    }
    setAccountFeedback({ tone: "info", message: tx("Saving account changes...") });
    setAccountSaving(true);
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
      setFormNotice(setAccountFeedback, tx("Account saved."));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setFormError(setAccountFeedback, message);
    } finally {
      setAccountSaving(false);
    }
  }

  async function onChangePassword(e: FormEvent) {
    e.preventDefault();
    clearFeedback();
    if (!passwordForm.currentPassword) {
      setFormError(setPasswordFeedback, tx("Enter your current password to change password."));
      return;
    }
    if (passwordForm.newPassword.length < 12) {
      setFormError(setPasswordFeedback, tx("New password must be at least 12 characters."));
      return;
    }
    setPasswordFeedback({ tone: "info", message: tx("Changing password...") });
    setPasswordSaving(true);
    try {
      await apiPutJson("/auth/password", {
        current_password: passwordForm.currentPassword,
        new_password: passwordForm.newPassword,
      });
      setPasswordForm({ currentPassword: "", newPassword: "" });
      setFormNotice(setPasswordFeedback, tx("Password changed. Sign in again."));
      await refresh();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setFormError(setPasswordFeedback, message);
    } finally {
      setPasswordSaving(false);
    }
  }

  async function onCreateAPIToken(e: FormEvent) {
    e.preventDefault();
    clearFeedback();
    if (!tokenForm.label.trim()) {
      setFormError(setTokenFeedback, tx("Token label is required."));
      return;
    }
    if (!tokenForm.currentPassword) {
      setFormError(setTokenFeedback, tx("Enter your current password to create a token."));
      return;
    }
    const expiresAt = localDateTimeToRFC3339(tokenForm.expiresAt);
    if (tokenForm.expiresAt.trim() && !expiresAt) {
      setFormError(setTokenFeedback, tx("Token expiration is invalid."));
      return;
    }
    setTokenFeedback({ tone: "info", message: tx("Creating token...") });
    setTokenSaving(true);
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
        scope: "admin:read",
        expiresAt: "",
        currentPassword: "",
      });
      const tokenData = await apiGetJson<AdminAPITokenListResponse>("/auth/api-tokens");
      setAPITokens(Array.isArray(tokenData.tokens) ? tokenData.tokens : [data.record]);
      setFormNotice(setTokenFeedback, tx("Personal access token created."));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setFormError(setTokenFeedback, message);
    } finally {
      setTokenSaving(false);
    }
  }

  async function onRevokeAPIToken(tokenID: number) {
    clearFeedback();
    setTokenFeedback({ tone: "info", message: tx("Revoking token...") });
    try {
      const data = await apiPostJson<AdminAPITokenListResponse>(`/auth/api-tokens/${tokenID}/revoke`, {});
      setAPITokens(Array.isArray(data.tokens) ? data.tokens : []);
      setFormNotice(setTokenFeedback, tx("Personal access token revoked."));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setFormError(setTokenFeedback, message);
    }
  }

  async function onCopyCreatedToken() {
    if (!createdToken || !navigator.clipboard) {
      return;
    }
    try {
      await navigator.clipboard.writeText(createdToken);
      setFormNotice(setTokenFeedback, tx("Personal access token copied."));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setFormError(setTokenFeedback, message);
    }
  }

  if (loading) {
    return <div className="w-full p-4 text-neutral-500">{tx("Loading user...")}</div>;
  }

  return (
    <div className="w-full p-4 space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{tx("User")}</h1>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-neutral-500">
          <span className="rounded bg-neutral-100 px-2 py-1">
            {tx("user")}: {account?.username || "-"}
          </span>
          <span className="rounded bg-neutral-100 px-2 py-1">
            {tx("role")}: {account?.role || "-"}
          </span>
          {(account?.must_change_password || session.must_change_password) ? (
            <span className="rounded bg-amber-100 px-2 py-1 text-amber-900">
              {tx("Password change required")}
            </span>
          ) : null}
        </div>
      </header>

      {(account?.must_change_password || session.must_change_password) ? (
        <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
          {tx("Change the initial password before continuing.")}
        </div>
      ) : null}

      {loadError ? (
        <div className="rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">
          {loadError}
        </div>
      ) : null}

      <section className="rounded-lg border border-neutral-200 bg-white p-4">
        <form onSubmit={onSaveAccount} className="space-y-3">
          <div className="text-sm font-medium">{tx("Account")}</div>
          <div className="grid gap-3 md:grid-cols-2">
            <UserField label={tx("Username")}>
              <input
                value={accountForm.username}
                onChange={(e) =>
                  setAccountForm((current) => ({
                    ...current,
                    username: e.target.value,
                  }))
                }
                className="w-full rounded border border-neutral-200 bg-white"
                autoComplete="username"
                disabled={readOnly || accountSaving}
              />
            </UserField>
            <UserField label={tx("Email")}>
              <input
                value={accountForm.email}
                onChange={(e) =>
                  setAccountForm((current) => ({
                    ...current,
                    email: e.target.value,
                  }))
                }
                className="w-full rounded border border-neutral-200 bg-white"
                autoComplete="email"
                disabled={readOnly || accountSaving}
              />
            </UserField>
            <UserField label={tx("Current password")} hint={tx("Required to save account changes.")}>
              <input
                type="password"
                value={accountForm.currentPassword}
                onChange={(e) =>
                  setAccountForm((current) => ({
                    ...current,
                    currentPassword: e.target.value,
                  }))
                }
                className="w-full rounded border border-neutral-200 bg-white"
                autoComplete="current-password"
                disabled={readOnly || accountSaving}
              />
            </UserField>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="submit" disabled={readOnly || accountSaving}>
              {accountSaving ? tx("Saving...") : tx("Save Account")}
            </button>
          </div>
          <FormMessage feedback={accountFeedback} />
        </form>
      </section>

      <section className="rounded-lg border border-neutral-200 bg-white p-4">
        <form onSubmit={onChangePassword} className="space-y-3">
          <div className="text-sm font-medium">{tx("Change Password")}</div>
          <div className="grid gap-3 md:grid-cols-2">
            <UserField label={tx("Current password")}>
              <input
                type="password"
                value={passwordForm.currentPassword}
                onChange={(e) =>
                  setPasswordForm((current) => ({
                    ...current,
                    currentPassword: e.target.value,
                  }))
                }
                className="w-full rounded border border-neutral-200 bg-white"
                autoComplete="current-password"
                disabled={readOnly || passwordSaving}
              />
            </UserField>
            <UserField label={tx("New password")} hint={tx("12 characters minimum.")}>
              <input
                type="password"
                value={passwordForm.newPassword}
                onChange={(e) =>
                  setPasswordForm((current) => ({
                    ...current,
                    newPassword: e.target.value,
                  }))
                }
                className="w-full rounded border border-neutral-200 bg-white"
                autoComplete="new-password"
                disabled={readOnly || passwordSaving}
              />
            </UserField>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="submit" disabled={readOnly || passwordSaving}>
              {passwordSaving ? tx("Saving...") : tx("Change Password")}
            </button>
          </div>
          <FormMessage feedback={passwordFeedback} />
        </form>
      </section>

      <section className="rounded-lg border border-neutral-200 bg-white p-4">
        <form onSubmit={onCreateAPIToken} className="space-y-3">
          <div className="text-sm font-medium">{tx("Personal Access Tokens")}</div>
          <div className="grid gap-3 md:grid-cols-2">
            <UserField label={tx("Label")}>
              <input
                value={tokenForm.label}
                onChange={(e) =>
                  setTokenForm((current) => ({
                    ...current,
                    label: e.target.value,
                  }))
                }
                className="w-full rounded border border-neutral-200 bg-white"
                disabled={readOnly || tokenSaving}
              />
            </UserField>
            <UserField label={tx("Scope")}>
              <select
                value={tokenForm.scope}
                onChange={(e) =>
                  setTokenForm((current) => ({
                    ...current,
                    scope: e.target.value,
                  }))
                }
                className="w-full rounded border border-neutral-200 bg-white"
                disabled={readOnly || tokenSaving}
              >
                <option value="admin:read">{tx("Read only")}</option>
                <option value="admin:write">{tx("Read and write")}</option>
              </select>
            </UserField>
            <UserField label={tx("Expires at")}>
              <input
                type="datetime-local"
                value={tokenForm.expiresAt}
                onChange={(e) =>
                  setTokenForm((current) => ({
                    ...current,
                    expiresAt: e.target.value,
                  }))
                }
                className="w-full rounded border border-neutral-200 bg-white"
                disabled={readOnly || tokenSaving}
              />
            </UserField>
            <UserField label={tx("Current password")} hint={tx("Required to create a token.")}>
              <input
                type="password"
                value={tokenForm.currentPassword}
                onChange={(e) =>
                  setTokenForm((current) => ({
                    ...current,
                    currentPassword: e.target.value,
                  }))
                }
                className="w-full rounded border border-neutral-200 bg-white"
                autoComplete="current-password"
                disabled={readOnly || tokenSaving}
              />
            </UserField>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="submit" disabled={readOnly || tokenSaving}>
              {tokenSaving ? tx("Creating...") : tx("Create Token")}
            </button>
          </div>
          <FormMessage feedback={tokenFeedback} />
        </form>
      </section>

      {createdToken ? (
        <section className="space-y-2 rounded-lg border border-amber-300 bg-amber-50 p-4">
          <div className="text-xs font-medium text-amber-950">{tx("New Personal Access Token")}</div>
          <textarea
            value={createdToken}
            readOnly
            className="min-h-20 w-full rounded border border-amber-200 bg-white font-mono text-xs"
          />
          <button type="button" onClick={() => void onCopyCreatedToken()}>
            {tx("Copy Token")}
          </button>
        </section>
      ) : null}

      <section className="rounded-lg border border-neutral-200 bg-white p-4 space-y-3">
        <div className="text-sm font-medium">{tx("Existing Personal Access Tokens")}</div>
        {apiTokens.length === 0 ? (
          <div className="rounded border border-neutral-200 px-3 py-2 text-xs text-neutral-500">
            {tx("No personal access tokens.")}
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-neutral-200">
            <table className="min-w-full text-left text-xs">
              <thead className="bg-neutral-50 text-xs text-neutral-500">
                <tr>
                  <th className="px-3 py-2 font-medium">{tx("Label")}</th>
                  <th className="px-3 py-2 font-medium">{tx("Prefix")}</th>
                  <th className="px-3 py-2 font-medium">{tx("Scope")}</th>
                  <th className="px-3 py-2 font-medium">{tx("Created")}</th>
                  <th className="px-3 py-2 font-medium">{tx("Last used")}</th>
                  <th className="px-3 py-2 font-medium">{tx("Expires")}</th>
                  <th className="px-3 py-2 font-medium">{tx("Status")}</th>
                  <th className="px-3 py-2 font-medium">{tx("Action")}</th>
                </tr>
              </thead>
              <tbody>
                {apiTokens.map((token) => (
                  <tr key={token.token_id} className="border-t border-neutral-200">
                    <td className="px-3 py-2">{token.label}</td>
                    <td className="px-3 py-2 font-mono text-xs">{token.prefix}</td>
                    <td className="px-3 py-2">{token.scopes.join(", ")}</td>
                    <td className="px-3 py-2">{formatAdminTokenTime(token.created_at)}</td>
                    <td className="px-3 py-2">{formatAdminTokenTime(token.last_used_at)}</td>
                    <td className="px-3 py-2">{formatAdminTokenTime(token.expires_at)}</td>
                    <td className="px-3 py-2">
                      <span
                        className={`rounded px-2 py-0.5 text-xs ${token.active ? "bg-green-100 text-green-800" : "bg-neutral-100 text-neutral-600"}`}
                      >
                        {token.active ? tx("active") : tx("inactive")}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <button
                        type="button"
                        onClick={() => void onRevokeAPIToken(token.token_id)}
                        disabled={readOnly || !token.active}
                      >
                        {tx("Revoke")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
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
    <label className="block space-y-1">
      <span className="block text-xs text-neutral-600">{label}</span>
      {children}
      {hint ? <span className="block text-[11px] text-neutral-500">{hint}</span> : null}
    </label>
  );
}

function FormMessage({ feedback }: { feedback: FormFeedback | null }) {
  if (!feedback) {
    return null;
  }
  const toneClass =
    feedback.tone === "error"
      ? "border-red-300 bg-red-50 text-red-900"
      : feedback.tone === "success"
        ? "border-green-300 bg-green-50 text-green-900"
        : "border-blue-300 bg-blue-50 text-blue-900";
  return (
    <div className={`rounded-md border px-3 py-2 text-xs ${toneClass}`} role={feedback.tone === "error" ? "alert" : "status"}>
      {feedback.message}
    </div>
  );
}
