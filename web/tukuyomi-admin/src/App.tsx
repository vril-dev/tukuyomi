import { lazy, Suspense, type ReactNode } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Layout from './components/Layout';
import Login from './pages/Login';
import { useAuth } from './lib/auth';
import { AuthProvider } from './lib/authProvider';
import { AdminRuntimeProvider } from './lib/adminRuntimeProvider';
import { useI18n } from './lib/i18n';

const Status = lazy(() => import('./pages/Status'));
const Logs = lazy(() => import('./pages/Logs'));
const Rules = lazy(() => import('./pages/Rules'));
const CacheRulePanel = lazy(() => import('./pages/CacheRulesPanel'));
const BypassRulesPanel = lazy(() => import('./pages/BypassRulesPanel'));
const CountryBlockPanel = lazy(() => import('./pages/CountryBlockPanel'));
const RateLimitPanel = lazy(() => import('./pages/RateLimitPanel'));
const IPReputationPanel = lazy(() => import('./pages/IPReputationPanel'));
const NotificationsPanel = lazy(() => import('./pages/NotificationsPanel'));
const BotDefensePanel = lazy(() => import('./pages/BotDefensePanel'));
const SemanticPanel = lazy(() => import('./pages/SemanticPanel'));
const FPTunerPanel = lazy(() => import('./pages/FPTunerPanel'));
const ProxyRulesPanel = lazy(() => import('./pages/ProxyRulesPanel'));
const BackendsPanel = lazy(() => import('./pages/BackendsPanel'));
const SitesPanel = lazy(() => import('./pages/SitesPanel'));
const SettingsPanel = lazy(() => import('./pages/SettingsPanel'));
const UserPanel = lazy(() => import('./pages/UserPanel'));
const OptionsPanel = lazy(() => import('./pages/OptionsPanel'));
const RuntimeAppsPanel = lazy(() => import('./pages/RuntimeAppsPanel'));
const ScheduledTasksPanel = lazy(() => import('./pages/ScheduledTasksPanel'));

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

function PageFallback() {
  const { tx } = useI18n();
  return <div className="w-full p-4 text-neutral-500">{tx("Loading...")}</div>;
}

function PageElement({ children }: { children: ReactNode }) {
  return <Suspense fallback={<PageFallback />}>{children}</Suspense>;
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
            <Route path="status" element={<PageElement><Status /></PageElement>} />
            <Route path="logs" element={<PageElement><Logs /></PageElement>} />
            <Route path="rules" element={<PageElement><Rules /></PageElement>} />
            <Route path="override-rules" element={<Navigate to="/rules" replace />} />
            <Route path="rule-sets" element={<Navigate to="/rules" replace />} />
            <Route path="bypass" element={<PageElement><BypassRulesPanel /></PageElement>} />
            <Route path="country-block" element={<PageElement><CountryBlockPanel /></PageElement>} />
            <Route path="rate-limit" element={<PageElement><RateLimitPanel /></PageElement>} />
            <Route path="ip-reputation" element={<PageElement><IPReputationPanel /></PageElement>} />
            <Route path="notifications" element={<PageElement><NotificationsPanel /></PageElement>} />
            <Route path="bot-defense" element={<PageElement><BotDefensePanel /></PageElement>} />
            <Route path="semantic" element={<PageElement><SemanticPanel /></PageElement>} />
            <Route path="fp-tuner" element={<PageElement><FPTunerPanel /></PageElement>} />
            <Route path="cache" element={<PageElement><CacheRulePanel /></PageElement>} />
            <Route path="proxy-rules" element={<PageElement><ProxyRulesPanel /></PageElement>} />
            <Route path="backends" element={<PageElement><BackendsPanel /></PageElement>} />
            <Route path="sites" element={<PageElement><SitesPanel /></PageElement>} />
            <Route path="runtime-apps" element={<PageElement><RuntimeAppsPanel /></PageElement>} />
            <Route path="scheduled-tasks" element={<PageElement><ScheduledTasksPanel /></PageElement>} />
            <Route path="user" element={<PageElement><UserPanel /></PageElement>} />
            <Route path="settings" element={<PageElement><SettingsPanel /></PageElement>} />
            <Route path="options" element={<PageElement><OptionsPanel /></PageElement>} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
