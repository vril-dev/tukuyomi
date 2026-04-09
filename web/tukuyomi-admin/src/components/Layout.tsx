import { Link, Outlet, useLocation } from "react-router-dom";
import { useMemo } from "react";
import { useAuth } from "@/lib/auth";

type NavItem = {
  to: string;
  label: string;
  hint: string;
};

type NavGroup = {
  id: string;
  label: string;
  hint: string;
  items: NavItem[];
};

const navGroups: NavGroup[] = [
  {
    id: "observe",
    label: "Observe",
    hint: "health, logs, alerts",
    items: [
      { to: "/status", label: "Status", hint: "runtime health" },
      { to: "/logs", label: "Logs", hint: "events and traces" },
      { to: "/log-output", label: "Log Settings", hint: "stdout and file profiles" },
      { to: "/notifications", label: "Notifications", hint: "state-based alert delivery" },
    ],
  },
  {
    id: "security",
    label: "Security",
    hint: "rules, reputation, anomaly defense",
    items: [
      { to: "/rules", label: "Rules", hint: "base directives" },
      { to: "/rule-sets", label: "Rule Sets", hint: "CRS toggles" },
      { to: "/bypass", label: "Bypass Rules", hint: "path overrides" },
      { to: "/country-block", label: "Country Block", hint: "country deny list" },
      { to: "/rate-limit", label: "Rate Limit", hint: "traffic policies" },
      { to: "/ip-reputation", label: "IP Reputation", hint: "allow/block feeds and CIDRs" },
      { to: "/bot-defense", label: "Bot Defense", hint: "ua challenge policy" },
      { to: "/semantic", label: "Semantic Security", hint: "heuristic anomaly scoring" },
      { to: "/fp-tuner", label: "FP Tuner", hint: "propose and apply exclusions" },
    ],
  },
  {
    id: "operations",
    label: "Operations",
    hint: "cache and runtime controls",
    items: [{ to: "/cache", label: "Cache Rules", hint: "edge cache behavior" }],
  },
];

function isActive(pathname: string, to: string) {
  return pathname === to || pathname.startsWith(`${to}/`);
}

export default function Layout() {
  const { pathname } = useLocation();
  const { logout, session, loading } = useAuth();
  const navItems = useMemo(() => navGroups.flatMap((group) => group.items), []);
  const current = navItems.find((item) => isActive(pathname, item.to));
  const currentGroup = navGroups.find((group) => group.items.some((item) => isActive(pathname, item.to)));

  return (
    <div className="app-shell">
      <aside className="app-sidebar">
        <div className="app-brand">
          <p className="app-brand-tag">TUKUYOMI</p>
          <h1>Control Room</h1>
          <p className="app-brand-sub">Coraza + CRS Security Gateway</p>
        </div>

        <nav className="app-nav" aria-label="primary">
          {navGroups.map((group) => (
            <section key={group.id} className="app-nav-group" aria-label={group.label}>
              <div className="app-nav-group-meta">
                <p className="app-nav-group-title">{group.label}</p>
              </div>
              <div className="app-nav-group-links">
                {group.items.map((item) => {
                  const active = isActive(pathname, item.to);
                  return (
                    <Link key={item.to} to={item.to} className={active ? "app-nav-link active" : "app-nav-link"}>
                      <span className="app-nav-label">{item.label}</span>
                    </Link>
                  );
                })}
              </div>
            </section>
          ))}
        </nav>
      </aside>

      <main className="app-main">
        <header className="app-topbar">
          <div className="app-topbar-main">
            <div className="app-topbar-heading">
              <p className="app-kicker">Current Group</p>
              {currentGroup ? <p className="app-group-chip">{currentGroup.label}</p> : null}
              <h2>{current?.label ?? "Dashboard"}</h2>
              {currentGroup?.hint ? <p className="app-topbar-sub">{currentGroup.hint}</p> : null}
            </div>
            <div className="app-topbar-paths">
              <code>{pathname}</code>
            </div>
          </div>
          <div className="app-top-meta">
            <div className="app-top-meta-cluster">
              <span className="app-pill">{session.mode === "disabled" ? "Auth Disabled" : "Session"}</span>
              {session.expires_at ? (
                <span className="app-pill">Expires {new Date(session.expires_at).toLocaleTimeString()}</span>
              ) : null}
            </div>
            <button type="button" className="app-pill app-pill-action" disabled={loading} onClick={() => void logout()}>
              {loading ? "..." : "Logout"}
            </button>
          </div>
        </header>

        <section className="app-content">
          <Outlet />
        </section>
      </main>
    </div>
  );
}
