import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Status from './pages/Status';
import Logs from './pages/Logs';
import LogOutputPanel from './pages/LogOutputPanel';
import Rules from './pages/Rules';
import RuleSets from './pages/RuleSets';
import CacheRulePanel from './pages/CacheRulesPanel';
import BypassRulesPanel from './pages/BypassRulesPanel';
import CountryBlockPanel from './pages/CountryBlockPanel';
import RateLimitPanel from './pages/RateLimitPanel';
import IPReputationPanel from './pages/IPReputationPanel';
import NotificationsPanel from './pages/NotificationsPanel';
import BotDefensePanel from './pages/BotDefensePanel';
import SemanticPanel from './pages/SemanticPanel';
import FPTunerPanel from './pages/FPTunerPanel';
import Login from './pages/Login';
import { AuthProvider, useAuth } from './lib/auth';

function ProtectedLayout() {
  const { loading, session } = useAuth();

  if (loading) {
    return <div className="min-h-screen flex items-center justify-center text-neutral-500">Checking admin session...</div>;
  }
  if (!session.authenticated) {
    return <Navigate to="/login" replace />;
  }
  return <Layout />;
}

function LoginRoute() {
  const { loading, session } = useAuth();

  if (loading) {
    return <div className="min-h-screen flex items-center justify-center text-neutral-500">Checking admin session...</div>;
  }
  if (session.authenticated) {
    return <Navigate to="/status" replace />;
  }
  return <Login />;
}

function App() {
  return (
    <BrowserRouter basename={import.meta.env.VITE_APP_BASE_PATH}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginRoute />} />
          <Route path="/" element={<ProtectedLayout />}>
            <Route index element={<Navigate to="/status" />} />
            <Route path="status" element={<Status />} />
            <Route path="logs" element={<Logs />} />
            <Route path="log-output" element={<LogOutputPanel />} />
            <Route path="rules" element={<Rules />} />
            <Route path="rule-sets" element={<RuleSets />} />
            <Route path="bypass" element={<BypassRulesPanel />} />
            <Route path="country-block" element={<CountryBlockPanel />} />
            <Route path="rate-limit" element={<RateLimitPanel />} />
            <Route path="ip-reputation" element={<IPReputationPanel />} />
            <Route path="notifications" element={<NotificationsPanel />} />
            <Route path="bot-defense" element={<BotDefensePanel />} />
            <Route path="semantic" element={<SemanticPanel />} />
            <Route path="fp-tuner" element={<FPTunerPanel />} />
            <Route path="cache" element={<CacheRulePanel />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
