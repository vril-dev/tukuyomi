import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Layout from './components/Layout';
import Status from './pages/Status';
import Logs from './pages/Logs';
import Rules from './pages/Rules';
import CacheRulePanel from './pages/CacheRulesPanel';
import BypassRulesPanel from './pages/BypassRulesPanel';
import CountryBlockPanel from './pages/CountryBlockPanel';
import RateLimitPanel from './pages/RateLimitPanel';
import IPReputationPanel from './pages/IPReputationPanel';
import NotificationsPanel from './pages/NotificationsPanel';
import BotDefensePanel from './pages/BotDefensePanel';
import SemanticPanel from './pages/SemanticPanel';
import FPTunerPanel from './pages/FPTunerPanel';
import ProxyRulesPanel from './pages/ProxyRulesPanel';
import BackendsPanel from './pages/BackendsPanel';
import SitesPanel from './pages/SitesPanel';
import SettingsPanel from './pages/SettingsPanel';
import UserPanel from './pages/UserPanel';
import OptionsPanel from './pages/OptionsPanel';
import VhostsPanel from './pages/VhostsPanel';
import ScheduledTasksPanel from './pages/ScheduledTasksPanel';
import Login from './pages/Login';
import { useAuth } from './lib/auth';
import { AuthProvider } from './lib/authProvider';
import { AdminRuntimeProvider } from './lib/adminRuntimeProvider';
import { useI18n } from './lib/i18n';

function ProtectedLayout() {
  const { loading, session } = useAuth();
  const { tx } = useI18n();
  const location = useLocation();

  if (loading) {
    return <div className="min-h-screen flex items-center justify-center text-neutral-500">{tx("Checking admin session...")}</div>;
  }
  if (!session.authenticated) {
    return <Navigate to="/login" replace state={{ from: `${location.pathname}${location.search}${location.hash}` }} />;
  }
  return (
    <AdminRuntimeProvider>
      <Layout />
    </AdminRuntimeProvider>
  );
}

function LoginRoute() {
  const { loading, session } = useAuth();
  const { tx } = useI18n();
  const location = useLocation();
  const from = loginReturnPath(location.state);

  if (loading) {
    return <div className="min-h-screen flex items-center justify-center text-neutral-500">{tx("Checking admin session...")}</div>;
  }
  if (session.authenticated) {
    return <Navigate to={from} replace />;
  }
  return <Login />;
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

function App() {
  return (
    <BrowserRouter basename="/tukuyomi-ui">
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginRoute />} />
          <Route path="/" element={<ProtectedLayout />}>
            <Route index element={<Navigate to="/status" />} />
            <Route path="status" element={<Status />} />
            <Route path="logs" element={<Logs />} />
            <Route path="rules" element={<Rules />} />
            <Route path="override-rules" element={<Navigate to="/rules" replace />} />
            <Route path="rule-sets" element={<Navigate to="/rules" replace />} />
            <Route path="bypass" element={<BypassRulesPanel />} />
            <Route path="country-block" element={<CountryBlockPanel />} />
            <Route path="rate-limit" element={<RateLimitPanel />} />
            <Route path="ip-reputation" element={<IPReputationPanel />} />
            <Route path="notifications" element={<NotificationsPanel />} />
            <Route path="bot-defense" element={<BotDefensePanel />} />
            <Route path="semantic" element={<SemanticPanel />} />
            <Route path="fp-tuner" element={<FPTunerPanel />} />
            <Route path="cache" element={<CacheRulePanel />} />
            <Route path="proxy-rules" element={<ProxyRulesPanel />} />
            <Route path="backends" element={<BackendsPanel />} />
            <Route path="sites" element={<SitesPanel />} />
            <Route path="vhosts" element={<VhostsPanel />} />
            <Route path="scheduled-tasks" element={<ScheduledTasksPanel />} />
            <Route path="user" element={<UserPanel />} />
            <Route path="settings" element={<SettingsPanel />} />
            <Route path="options" element={<OptionsPanel />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
