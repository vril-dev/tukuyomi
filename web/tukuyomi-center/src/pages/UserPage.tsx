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
          {account?.must_change_password || session.must_change_password ? (
            <span className="rounded bg-amber-100 px-2 py-1 text-amber-900">{tx("Password change required")}</span>
          ) : null}
        </div>
      </header>

      {account?.must_change_password || session.must_change_password ? (
        <div className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
          {tx("Change the initial password before continuing.")}
        </div>
      ) : null}

      {loadError ? <div className="rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-900">{loadError}</div> : null}

      <section className="rounded-lg border border-neutral-200 bg-white p-4">
        <form onSubmit={onSaveAccount} className="space-y-3">
          <div className="text-sm font-medium">{tx("Account")}</div>
          <div className="grid gap-3 md:grid-cols-2">
            <UserField label={tx("Username")}>
              <input
                value={accountForm.username}
                onChange={(event) => setAccountForm((current) => ({ ...current, username: event.target.value }))}
                className="w-full rounded border border-neutral-200 bg-white"
                autoComplete="username"
                disabled={accountSaving}
                required
              />
            </UserField>
            <UserField label={tx("Email")}>
              <input
                value={accountForm.email}
                onChange={(event) => setAccountForm((current) => ({ ...current, email: event.target.value }))}
                className="w-full rounded border border-neutral-200 bg-white"
                autoComplete="email"
                disabled={accountSaving}
              />
            </UserField>
            <UserField label={tx("Current password")} hint={tx("Required to save account changes.")}>
              <input
                type="password"
                value={accountForm.currentPassword}
                onChange={(event) => setAccountForm((current) => ({ ...current, currentPassword: event.target.value }))}
                className="w-full rounded border border-neutral-200 bg-white"
                autoComplete="current-password"
                disabled={accountSaving}
              />
            </UserField>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="submit" disabled={accountSaving}>
              {accountSaving ? tx("Saving...") : tx("Save Account")}
            </button>
          </div>
          <FormMessage feedback={accountFeedback} />
        </form>
      </section>

      <section className="rounded-lg border border-neutral-200 bg-white p-4">
        <form onSubmit={onChangePassword} className="space-y-3">
          <div className="text-sm font-medium">{tx("Change Password")}</div>
          <input className="visually-hidden" value={account?.username || ""} readOnly autoComplete="username" tabIndex={-1} />
          <div className="grid gap-3 md:grid-cols-2">
            <UserField label={tx("Current password")}>
              <input
                type="password"
                value={passwordForm.currentPassword}
                onChange={(event) => setPasswordForm((current) => ({ ...current, currentPassword: event.target.value }))}
                className="w-full rounded border border-neutral-200 bg-white"
                autoComplete="current-password"
                disabled={passwordSaving}
              />
            </UserField>
            <UserField label={tx("New password")} hint={tx("12 characters minimum.")}>
              <input
                type="password"
                value={passwordForm.newPassword}
                onChange={(event) => setPasswordForm((current) => ({ ...current, newPassword: event.target.value }))}
                className="w-full rounded border border-neutral-200 bg-white"
                autoComplete="new-password"
                disabled={passwordSaving}
              />
            </UserField>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="submit" disabled={passwordSaving}>
              {passwordSaving ? tx("Saving...") : tx("Change Password")}
            </button>
          </div>
          <FormMessage feedback={passwordFeedback} />
        </form>
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
