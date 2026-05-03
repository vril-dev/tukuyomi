import { BrowserRouter, Navigate, Route, Routes, useLocation, useParams } from "react-router-dom";
import { useState } from "react";

import Layout from "@/components/Layout";
import { AuthProvider, useAuth } from "@/lib/auth";
import { useI18n } from "@/lib/i18n";
import { getUIBasePath } from "@/lib/runtime";
import DeviceApprovalsPage from "@/pages/DeviceApprovalsPage";
import Login from "@/pages/Login";
import ProxyRulesPage from "@/pages/ProxyRulesPage";
import RuntimePage from "@/pages/RuntimePage";
import SettingsPage from "@/pages/SettingsPage";
import StatusPage from "@/pages/StatusPage";
import UserPage from "@/pages/UserPage";
import WAFRulesPage from "@/pages/WAFRulesPage";

function ProtectedLayout() {
  const { loading, session } = useAuth();
  const { tx } = useI18n();
  const location = useLocation();

  if (loading) {
    return <div className="center-screen-message">{tx("Checking admin session...")}</div>;
  }
  if (!session.authenticated) {
    return <Navigate to="/login" replace state={{ from: `${location.pathname}${location.search}${location.hash}` }} />;
  }
  return <Layout />;
}

function LoginRoute({
  noticeKey,
  clearNotice,
}: {
  noticeKey: string;
  clearNotice: () => void;
}) {
  const { loading, session } = useAuth();
  const { tx } = useI18n();
  const location = useLocation();
  const from = loginReturnPath(location.state);

  if (loading) {
    return <div className="center-screen-message">{tx("Checking admin session...")}</div>;
  }
  if (session.authenticated) {
    return <Navigate to={from} replace />;
  }
  return <Login noticeKey={noticeKey} clearNotice={clearNotice} />;
}

function loginReturnPath(state: unknown) {
  if (!state || typeof state !== "object" || !("from" in state)) {
    return "/status";
  }
  const from = typeof state.from === "string" ? state.from : "";
  if (!from.startsWith("/") || from === "/login" || from.startsWith("/login?") || from.startsWith("//")) {
    return "/status";
  }
  return from;
}

function LegacyRuntimeRedirect() {
  const { deviceID = "" } = useParams();
  if (!deviceID) {
    return <Navigate to="/device-approvals" replace />;
  }
  return <Navigate to={`/device-approvals/devices/${encodeURIComponent(deviceID)}/runtime`} replace />;
}

function LegacyRulesRedirect() {
  const { deviceID = "" } = useParams();
  if (!deviceID) {
    return <Navigate to="/device-approvals" replace />;
  }
  return <Navigate to={`/device-approvals/devices/${encodeURIComponent(deviceID)}/proxy-rules`} replace />;
}

function CenterRoutes() {
  const [loginNoticeKey, setLoginNoticeKey] = useState("");

  return (
    <Routes>
      <Route
        path="/login"
        element={<LoginRoute noticeKey={loginNoticeKey} clearNotice={() => setLoginNoticeKey("")} />}
      />
      <Route path="/" element={<ProtectedLayout />}>
        <Route index element={<Navigate to="/status" replace />} />
        <Route path="status" element={<StatusPage />} />
        <Route path="device-approvals" element={<DeviceApprovalsPage focusApprovals />} />
        <Route path="device-approvals/devices/:deviceID" element={<DeviceApprovalsPage />} />
        <Route path="device-approvals/devices/:deviceID/runtime" element={<RuntimePage />} />
        <Route path="device-approvals/devices/:deviceID/proxy-rules" element={<ProxyRulesPage />} />
        <Route path="device-approvals/devices/:deviceID/waf-rules" element={<WAFRulesPage />} />
        <Route path="device-approvals/devices/:deviceID/rules" element={<LegacyRulesRedirect />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="runtimes" element={<Navigate to="/device-approvals" replace />} />
        <Route path="runtimes/devices/:deviceID" element={<LegacyRuntimeRedirect />} />
        <Route
          path="user"
          element={<UserPage onPasswordChanged={() => setLoginNoticeKey("Password changed. Sign in again.")} />}
        />
        <Route path="*" element={<Navigate to="/status" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/status" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter basename={getUIBasePath()}>
      <AuthProvider>
        <CenterRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
