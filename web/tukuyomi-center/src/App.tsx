import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useState } from "react";

import Layout from "@/components/Layout";
import { AuthProvider, useAuth } from "@/lib/auth";
import { useI18n } from "@/lib/i18n";
import { getUIBasePath } from "@/lib/runtime";
import DeviceApprovalsPage from "@/pages/DeviceApprovalsPage";
import Login from "@/pages/Login";
import StatusPage from "@/pages/StatusPage";
import UserPage from "@/pages/UserPage";

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
