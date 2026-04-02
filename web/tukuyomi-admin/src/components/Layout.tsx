import { Link, Outlet, useLocation } from "react-router-dom";

type NavItem = {
  to: string;
  label: string;
  hint: string;
};

const navItems: NavItem[] = [
  { to: "/status", label: "Status", hint: "runtime health" },
  { to: "/logs", label: "Logs", hint: "events and traces" },
  { to: "/rules", label: "Rules", hint: "base directives" },
  { to: "/rule-sets", label: "Rule Sets", hint: "CRS toggles" },
  { to: "/bypass", label: "Bypass Rules", hint: "path overrides" },
  { to: "/country-block", label: "Country Block", hint: "country deny list" },
  { to: "/rate-limit", label: "Rate Limit", hint: "traffic policies" },
  { to: "/ip-reputation", label: "IP Reputation", hint: "allow/block feeds and CIDRs" },
  { to: "/notifications", label: "Notifications", hint: "state-based alert delivery" },
  { to: "/bot-defense", label: "Bot Defense", hint: "ua challenge policy" },
  { to: "/semantic", label: "Semantic Security", hint: "heuristic anomaly scoring" },
  { to: "/fp-tuner", label: "FP Tuner", hint: "propose and apply exclusions" },
  { to: "/cache", label: "Cache Rules", hint: "edge cache behavior" },
];

function isActive(pathname: string, to: string) {
  return pathname === to || pathname.startsWith(`${to}/`);
}

export default function Layout() {
  const { pathname } = useLocation();
  const current = navItems.find((item) => isActive(pathname, item.to));

  return (
    <div className="app-shell">
      <aside className="app-sidebar">
        <div className="app-brand">
          <p className="app-brand-tag">TUKUYOMI</p>
          <h1>Control Room</h1>
          <p className="app-brand-sub">Coraza + CRS Security Gateway</p>
        </div>

        <nav className="app-nav" aria-label="primary">
          {navItems.map((item) => {
            const active = isActive(pathname, item.to);
            return (
              <Link key={item.to} to={item.to} className={active ? "app-nav-link active" : "app-nav-link"}>
                <span className="app-nav-label">{item.label}</span>
                <span className="app-nav-hint">{item.hint}</span>
              </Link>
            );
          })}
        </nav>
      </aside>

      <main className="app-main">
        <header className="app-topbar">
          <div>
            <p className="app-kicker">Current Panel</p>
            <h2>{current?.label ?? "Dashboard"}</h2>
          </div>
          <div className="app-top-meta">
            <span className="app-pill">Admin UI</span>
            <code>{pathname}</code>
          </div>
        </header>

        <section className="app-content">
          <Outlet />
        </section>
      </main>
    </div>
  );
}
