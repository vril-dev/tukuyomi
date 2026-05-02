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
  Settings: "設定",
  "Selected device": "選択中のデバイス",
  "Device Status": "デバイス状態",
  Rules: "ルール",
  "Proxy Rules": "Proxy Rules",
  "Selected Gateway status and config snapshots.": "選択中 Gateway の状態と設定スナップショットを確認します。",
  "Selected Gateway device menu.": "選択中 Gateway のデバイスメニューです。",
  User: "ユーザー",
  "Current Group": "現在のグループ",
  "Fleet control plane.": "フリート制御プレーンです。",
  "Fleet control plane status.": "フリート制御プレーンの状態を確認します。",
  "Fleet control plane status and device enrollment approvals.": "フリート制御プレーンの状態とデバイス登録申請を確認します。",
  "Pending device enrollment approvals.": "承認待ちのデバイス登録申請を確認します。",
  "Center runtime and policy settings.": "Center の runtime と policy 設定を確認します。",
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
  "Show hidden token history": "非表示のトークン履歴を表示",
  "{count} hidden token(s)": "{count} 件のトークンを非表示",
  Label: "ラベル",
  "factory batch": "工場バッチ",
  "Max uses": "最大使用回数",
  "Expires at": "有効期限",
  "Leave blank for no expiration.": "空欄の場合は期限なし。",
  "Settings default: {value}": "設定デフォルト: {value}",
  "no expiration": "期限なし",
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
  "No visible enrollment tokens.": "表示対象の登録トークンはありません。",
  "Can enroll": "登録可能",
  "Cannot enroll": "登録不可",
  "Tokens that cannot enroll new devices are kept as audit history. Linked tokens stay visible while their devices are registered or awaiting approval.":
    "新規 device 登録に使えない token も監査履歴として保持されます。登録済みまたは承認待ちの device に紐付く token は通常表示に残ります。",
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
  "Platform details": "Platform 詳細",
  OS: "OS",
  Architecture: "アーキテクチャ",
  "Distro ID": "Distro ID",
  "Distro version": "Distro version",
  "Distro ID like": "Distro ID like",
  "Kernel version": "Kernel version",
  "Runtime inventory": "ランタイムインベントリ",
  "Latest runtime summary reported by this Gateway.": "この Gateway が報告した最新のランタイム概要です。",
  "This Gateway has not reported runtime deployment capability.": "この Gateway はランタイム配布機能を報告していません。",
  Family: "ファミリー",
  "Runtime ID": "ランタイムID",
  "Detected version": "検出バージョン",
  Source: "ソース",
  Available: "利用可",
  Modules: "モジュール",
  Apps: "アプリ",
  Process: "プロセス",
  "Apply state": "適用状態",
  "No runtime inventory reported.": "ランタイムインベントリは報告されていません。",
  "Pending runtime requests": "保留中のランタイム要求",
  "Requests waiting for the Gateway to pick them up.": "Gateway が取得する前のランタイム要求です。",
  "Loading runtime deployment...": "ランタイム配布情報を読み込んでいます...",
  "Failed to load runtime deployment": "ランタイム配布情報の読み込みに失敗しました",
  "Failed to assign runtime artifact": "ランタイム artifact の割り当てに失敗しました",
  "Failed to request runtime removal": "ランタイム削除要求に失敗しました",
  "Failed to cancel runtime request": "ランタイム要求のキャンセルに失敗しました",
  "Usage state is not reported yet.": "使用状態がまだ報告されていません。",
  "Removal is not supported for this runtime family.": "このランタイムファミリーの削除は未対応です。",
  "Runtime is used by apps.": "Runtime Apps で使用されています。",
  "Runtime process is running.": "ランタイムプロセスが実行中です。",
  "Removal already requested.": "削除は要求済みです。",
  "Remove": "削除",
  "Removing...": "削除中...",
  "Removal requested": "削除要求済み",
  running: "実行中",
  stopped: "停止中",
  "Requested artifact": "要求 artifact",
  "Local artifact": "ローカル artifact",
  Assigned: "割り当て済み",
  Installed: "展開済み",
  Built: "ビルド済み",
  Current: "現在適用中",
  "Request pending": "要求保留中",
  Assign: "割り当て",
  "Assigning...": "割り当て中...",
  "Cancel request": "要求をキャンセル",
  "Canceling...": "キャンセル中...",
  "No pending runtime requests.": "保留中のランタイム要求はありません。",
  "Compatible artifacts": "互換 artifact",
  "Artifacts matching this Gateway platform.": "この Gateway の platform に一致する artifact です。",
  "Built artifacts": "ビルド済み artifact",
  "Stored artifacts matching this Gateway platform.": "この Gateway の platform に一致する保存済み artifact です。",
  Target: "対象",
  State: "状態",
  "No compatible artifacts.": "互換 artifact はありません。",
  "No built artifacts.": "ビルド済み artifact はありません。",
  "Runtime build": "ランタイムビルド",
  Gateway: "Gateway",
  "Device details": "デバイス詳細",
  "Runtime deployment": "ランタイム配布",
  supported: "対応",
  unsupported: "未対応",
  "Builds use the selected Gateway platform target.": "選択中 Gateway の platform target を使って build します。",
  "Loading runtime devices...": "ランタイム対象デバイスを読み込んでいます...",
  "Failed to load runtime devices": "ランタイム対象デバイスの読み込みに失敗しました",
  "Failed to load runtime builder capability": "runtime builder 機能の読み込みに失敗しました",
  "Failed to load runtime build status": "runtime build 状態の読み込みに失敗しました",
  "Failed to start runtime build": "runtime build の開始に失敗しました",
  "Build is not supported for this runtime family yet.": "この runtime family のビルドはまだ未対応です。",
  "Runtime build is already running.": "この runtime build は実行中です。",
  "Proxy Rules editor": "Proxy Rules エディタ",
  "Edit the proxy domain for this Gateway.": "この Gateway の proxy domain を編集します。",
  "Import current": "現在値を取り込み",
  "No reported Proxy Rules snapshot.": "報告済み Proxy Rules snapshot がありません。",
  "Imported current Proxy Rules.": "現在の Proxy Rules を取り込みました。",
  "Proxy Rules validated.": "Proxy Rules を検証しました。",
  "Proxy Rules validation failed": "Proxy Rules の検証に失敗しました",
  "Proxy Rules request assigned.": "Proxy Rules 要求を割り当てました。",
  "Failed to assign Proxy Rules": "Proxy Rules の割り当てに失敗しました",
  "Proxy Rules request canceled.": "Proxy Rules 要求をキャンセルしました。",
  "Failed to cancel Proxy Rules request": "Proxy Rules 要求のキャンセルに失敗しました",
  "Gateway has already picked up this request.": "Gateway がこの要求を取得済みです。",
  "Picked up": "取得済み",
  "Pending rule requests": "保留中のルール要求",
  "Gateway picked up this request. Waiting for the next apply report.": "Gateway がこの要求を取得済みです。次の適用結果報告を待っています。",
  "No pending rule requests.": "保留中のルール要求はありません。",
  "Rule bundles": "ルール bundle",
  "Saved rule bundles": "保存済みルール bundle",
  "Latest 20 saved bundles. Use Assign to redeploy a saved bundle.": "最新20件の保存済み bundle です。Assign で保存済み bundle を再配布します。",
  "Selected bundle": "選択中 bundle",
  "Failed to load rule bundle": "ルール bundle の読み込みに失敗しました",
  "Last Gateway apply": "最後の Gateway 適用",
  "Desired bundle": "要求 bundle",
  "Local proxy ETag": "ローカル proxy ETag",
  "Last attempt": "最終試行",
  "Applied at": "適用日時",
  "No rule bundles.": "ルール bundle はありません。",
  "Current proxy ETag": "現在の proxy ETag",
  "Payload ETag": "Payload ETag",
  "Source ETag": "Source ETag",
  "Base ETag": "Base ETag",
  "Validated ETag": "検証済み ETag",
  "Validating...": "検証中...",
  "Build & assign": "ビルドして割り当て",
  "Building...": "ビルド中...",
  Queued: "キュー投入",
  Finished: "完了",
  Error: "エラー",
  queued: "待機中",
  succeeded: "成功",
  applied: "適用済み",
  applying: "適用中",
  blocked: "ブロック",
  failed: "失敗",
  Build: "ビルド",
  Rebuild: "再ビルド",
  available: "利用可",
  unavailable: "利用不可",
  Version: "バージョン",
  Platform: "プラットフォーム",
  Config: "設定",
  "Config revision": "設定リビジョン",
  "Config size": "設定サイズ",
  "Config received": "設定受信日時",
  "Config download": "設定をダウンロード",
  "Config snapshots": "設定スナップショット",
  "Latest 6 snapshots are shown per page. History rows do not include JSON payloads until opened.": "1ページあたり最新6件のスナップショットを表示します。履歴行は開くまで JSON 本文を含みません。",
  "Loading config snapshots...": "設定スナップショットを読み込んでいます...",
  "Failed to load config snapshots": "設定スナップショットの読み込みに失敗しました",
  "Failed to load config snapshot": "設定スナップショットの読み込みに失敗しました",
  Revision: "リビジョン",
  Received: "受信日時",
  Size: "サイズ",
  "Payload hash": "ペイロードハッシュ",
  "View JSON": "JSON を表示",
  "Download JSON": "JSON をダウンロード",
  "No config snapshots.": "設定スナップショットはありません。",
  "Showing {start}-{end}": "{start}-{end} を表示",
  Previous: "前へ",
  Next: "次へ",
  "Config JSON": "設定 JSON",
  "No config snapshot received.": "受信済みの設定スナップショットはありません。",
  Manage: "管理",
  "Device actions": "デバイス操作",
  "Back to registered devices": "登録済みデバイスに戻る",
  "Loading device details...": "デバイス詳細を読み込んでいます...",
  "Device not found.": "デバイスが見つかりません。",
  Close: "閉じる",
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
  "Failed to load Center settings": "Center 設定の読み込みに失敗しました",
  "Failed to save Center settings": "Center 設定の保存に失敗しました",
  "Loading Center settings...": "Center 設定を読み込んでいます...",
  "Center settings saved.": "Center 設定を保存しました。",
  "Center settings saved. Restart Center to apply listener changes.": "Center 設定を保存しました。listener 変更を反映するには Center を再起動してください。",
  "Settings revision is missing. Refresh and try again.": "設定 revision がありません。再読み込みしてから再試行してください。",
  "Admin read-only mode disables settings changes.": "管理画面が読み取り専用のため、設定変更は無効です。",
  "Center settings": "Center 設定",
  "Standalone listener": "単体 listener",
  "Applied after Center restart.": "Center 再起動後に反映されます。",
  "TLS mode": "TLS mode",
  Off: "無効",
  "Manual certificate": "手動証明書",
  "Manual TLS is applied after Center restart.": "手動 TLS は Center 再起動後に反映されます。",
  "TLS certificate file": "TLS 証明書ファイル",
  "TLS key file": "TLS キーファイル",
  "TLS minimum version": "TLS 最小バージョン",
  "Center restart required for saved listener settings.": "保存済み listener 設定を反映するには Center の再起動が必要です。",
  "Listen address must include a host and port.": "Listen address には host と port を含めてください。",
  "API and UI base paths must be different absolute paths.": "API と UI の base path は異なる絶対 path にしてください。",
  "Manual TLS requires both certificate and key files.": "手動 TLS には証明書ファイルとキーファイルの両方が必要です。",
  "Admin session": "管理セッション",
  "Session TTL minutes": "セッション TTL 分",
  "5 minutes to 7 days. New sessions use the saved value.": "5 分から 7 日まで。保存後に作成される新規セッションへ反映されます。",
  "Session TTL must be between 5 minutes and 7 days.": "セッション TTL は 5 分から 7 日の範囲で指定してください。",
  "Enrollment token defaults": "Enrollment token デフォルト",
  "Default max uses": "デフォルト最大使用回数",
  "Used when an enrollment token is created without an explicit max use count.": "Enrollment token 作成時に最大使用回数を明示しない場合に使います。",
  "Default token TTL days": "デフォルト token TTL 日数",
  "0 keeps newly-created enrollment tokens non-expiring by default.": "0 の場合、新規 enrollment token はデフォルトで期限なしになります。",
  "Save settings": "設定を保存",
  "Default max uses must be between 1 and 1000000.": "デフォルト最大使用回数は 1 から 1000000 の範囲で指定してください。",
  "Default token TTL must be between 0 and 3650 days.": "デフォルト token TTL は 0 から 3650 日の範囲で指定してください。",
  "Listen address": "Listen address",
  "API base path": "API base path",
  "UI base path": "UI base path",
  "DB driver": "DB driver",
  "DB path": "DB path",
  "DB retention": "DB 保持期間",
  "File retention": "ファイル保持期間",
  "{count} days": "{count} 日",
  "Read only": "読み取り専用",
  enabled: "有効",
  disabled: "無効",
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
