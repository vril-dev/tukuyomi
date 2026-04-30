import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

export type Locale = "en" | "ja";

type TranslationVars = Record<string, string | number | boolean | null | undefined>;

type I18nContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  tx: (key: string, vars?: TranslationVars) => string;
};

const STORAGE_KEY = "tukuyomi.center.locale";
const DEFAULT_LOCALE: Locale = "en";

const JA_STRINGS: Record<string, string> = {
  "Checking admin session...": "管理セッションを確認しています...",
  "Admin Sign In": "管理ログイン",
  "Sign in with your admin user to create a browser session.": "管理ユーザーでログインしてブラウザセッションを作成します。",
  "Username or email": "ユーザー名またはメールアドレス",
  "admin username or email": "管理ユーザー名またはメールアドレス",
  Password: "パスワード",
  "admin password": "管理パスワード",
  "Sign In": "ログイン",
  "Signing in...": "ログイン中...",
  "Login failed": "ログインに失敗しました",
  "Control Room": "Control Room",
  "Fleet Control Plane": "フリート制御プレーン",
  Center: "Center",
  Status: "ステータス",
  "Device Approvals": "デバイス承認",
  User: "ユーザー",
  "Current Group": "現在のグループ",
  "Fleet control plane.": "フリート制御プレーンです。",
  "Fleet control plane status.": "フリート制御プレーンの状態を確認します。",
  "Fleet control plane status and device enrollment approvals.": "フリート制御プレーンの状態とデバイス登録申請を確認します。",
  "Pending device enrollment approvals.": "承認待ちのデバイス登録申請を確認します。",
  "Manage your Center sign-in account and password.": "Center のログインアカウントとパスワードを管理します。",
  Language: "言語",
  English: "English",
  Japanese: "日本語",
  Session: "セッション",
  "Auth Disabled": "認証無効",
  "Expires {time}": "{time} に期限切れ",
  Logout: "ログアウト",
  "Device overview": "デバイス概要",
  Refresh: "更新",
  "Total devices": "総デバイス数",
  "Approved devices": "承認済みデバイス",
  "Pending approvals": "承認待ち",
  "Rejected enrollments": "却下済み登録",
  "Enrollment tokens": "登録トークン",
  "Issue a registration token before a Gateway can request device approval.": "Gateway がデバイス承認を申請する前に登録トークンを発行します。",
  "Show inactive token history": "無効なトークン履歴を表示",
  "{count} inactive token(s) hidden": "{count} 件の無効なトークンを非表示",
  Label: "ラベル",
  "factory batch": "工場バッチ",
  "Max uses": "最大使用回数",
  "Expires at": "有効期限",
  "Leave blank for no expiration.": "空欄の場合は期限なし。",
  "Create enrollment token": "登録トークンを作成",
  "Creating enrollment token...": "登録トークンを作成しています...",
  "Enrollment token created.": "登録トークンを作成しました。",
  "Failed to create enrollment token": "登録トークンの作成に失敗しました",
  "Failed to revoke enrollment token": "登録トークンの失効に失敗しました",
  "Failed to revoke device approval": "デバイス承認の解除に失敗しました",
  "Failed to archive device": "デバイスのアーカイブに失敗しました",
  "Generated token": "生成されたトークン",
  "Copy and store this token now. It will not be shown again.": "このトークンは今すぐ控えてください。再表示されません。",
  "Token prefix": "トークン接頭辞",
  Uses: "使用回数",
  Expires: "期限",
  "Last used": "最終使用",
  Usable: "利用可否",
  Revoke: "失効",
  "Revoke approval": "承認解除",
  "Revoking...": "失効中...",
  "No enrollment tokens.": "登録トークンはありません。",
  "No active enrollment tokens.": "有効な登録トークンはありません。",
  "Can enroll": "登録可能",
  "Cannot enroll": "登録不可",
  "Revoked, expired, or exhausted tokens are kept as audit history and cannot enroll devices.":
    "失効、期限切れ、使用済みの token は監査履歴として保持されますが、device 登録には使えません。",
  active: "有効",
  revoked: "失効済み",
  archived: "アーカイブ済み",
  rejected: "却下済み",
  expired: "期限切れ",
  exhausted: "使用済み",
  product_changed: "プロダクト変更",
  "Device enrollment approvals": "デバイス登録承認",
  Device: "デバイス",
  Key: "キー",
  Fingerprint: "フィンガープリント",
  "Product ID": "プロダクトID",
  Runtime: "ランタイム",
  Version: "バージョン",
  "Registered devices": "登録済みデバイス",
  "Show archived devices": "アーカイブ済みデバイスを表示",
  "Enrollment token": "登録トークン",
  "Token status": "トークン状態",
  "Proxy access": "Proxy 利用",
  "Proxy allowed": "Proxy 利用可",
  "Proxy locked": "Proxy ロック",
  Requested: "申請日時",
  Approved: "承認日時",
  "Last seen": "最終確認",
  Actions: "操作",
  Archive: "アーカイブ",
  "Archiving...": "アーカイブ中...",
  Approve: "承認",
  Reject: "却下",
  "No pending enrollments.": "承認待ちの登録はありません。",
  "No approved devices.": "承認済みデバイスはありません。",
  "No registered devices.": "登録済みデバイスはありません。",
  approved: "承認済み",
  "Loading Center status...": "Center ステータスを読み込んでいます...",
  "Loading device approvals...": "デバイス承認を読み込んでいます...",
  "Loading account...": "アカウントを読み込んでいます...",
  "Loading user...": "ユーザーを読み込んでいます...",
  "Failed to load Center status": "Center ステータスの読み込みに失敗しました",
  "Failed to load device approvals": "デバイス承認の読み込みに失敗しました",
  "Failed to approve enrollment": "登録の承認に失敗しました",
  "Failed to reject enrollment": "登録の却下に失敗しました",
  Username: "ユーザー名",
  Role: "ロール",
  user: "ユーザー",
  role: "ロール",
  "Password change required": "パスワード変更が必要",
  "Change the initial password before continuing.": "続行する前に初期パスワードを変更してください。",
  Account: "アカウント",
  Email: "メールアドレス",
  "Current password": "現在のパスワード",
  "Required to save account changes.": "アカウント変更の保存に必要です。",
  "Save Account": "アカウントを保存",
  "Saving...": "保存中...",
  "Saving account changes...": "アカウント変更を保存しています...",
  "Account saved.": "アカウントを保存しました。",
  "Username is required.": "ユーザー名は必須です。",
  "Enter your current password to save account changes.": "アカウント変更を保存するには現在のパスワードを入力してください。",
  "Change Password": "パスワード変更",
  "New password": "新しいパスワード",
  "12 characters minimum.": "12文字以上。",
  "Changing password...": "パスワードを変更しています...",
  "Password changed. Sign in again.": "パスワードを変更しました。再度ログインしてください。",
  "Enter your current password to change password.": "パスワードを変更するには現在のパスワードを入力してください。",
  "New password must be at least 12 characters.": "新しいパスワードは12文字以上にしてください。",
  "Failed to load account": "アカウントの読み込みに失敗しました",
  "Failed to save account": "アカウントの保存に失敗しました",
  "Failed to change password": "パスワードの変更に失敗しました",
};

const I18nContext = createContext<I18nContextValue | null>(null);

function canUseStorage() {
  return typeof globalThis !== "undefined" && typeof globalThis.localStorage !== "undefined";
}

function detectInitialLocale(): Locale {
  if (canUseStorage()) {
    try {
      const stored = globalThis.localStorage.getItem(STORAGE_KEY);
      if (stored === "ja" || stored === "en") {
        return stored;
      }
    } catch {
      // Ignore storage errors.
    }
  }
  if (typeof navigator !== "undefined" && (navigator.language || "").toLowerCase().startsWith("ja")) {
    return "ja";
  }
  return DEFAULT_LOCALE;
}

function normalizeLocale(value: string | null | undefined): Locale {
  return value === "ja" ? "ja" : "en";
}

function translate(locale: Locale, key: string, vars?: TranslationVars) {
  let out = locale === "ja" ? JA_STRINGS[key] || key : key;
  if (!vars) {
    return out;
  }
  for (const [name, value] of Object.entries(vars)) {
    out = out.replaceAll(`{${name}}`, String(value ?? ""));
  }
  return out;
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(detectInitialLocale);

  useEffect(() => {
    if (canUseStorage()) {
      try {
        globalThis.localStorage.setItem(STORAGE_KEY, locale);
      } catch {
        // Ignore storage errors.
      }
    }
    if (typeof document !== "undefined") {
      document.documentElement.lang = locale === "ja" ? "ja" : "en";
      document.documentElement.dataset.locale = locale;
      document.body.dataset.locale = locale;
    }
  }, [locale]);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(normalizeLocale(next));
  }, []);

  const tx = useCallback((key: string, vars?: TranslationVars) => translate(locale, key, vars), [locale]);

  const value = useMemo<I18nContextValue>(() => ({ locale, setLocale, tx }), [locale, setLocale, tx]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const value = useContext(I18nContext);
  if (!value) {
    throw new Error("useI18n must be used within I18nProvider");
  }
  return value;
}
