import { Link, Outlet, useLocation } from "react-router-dom";

import { getAPIBasePath } from "@/lib/runtime";
import { useAuth } from "@/lib/auth";
import { useI18n } from "@/lib/i18n";

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
    id: "center",
    label: "Center",
    hint: "Fleet control plane.",
    items: [
      { to: "/status", label: "Status", hint: "Fleet control plane status." },
      { to: "/device-approvals", label: "Device Approvals", hint: "Pending device enrollment approvals." },
    ],
  },
];

const utilityNavItems: NavItem[] = [
  { to: "/user", label: "User", hint: "Manage your Center sign-in account and password." },
];

function isActive(pathname: string, to: string) {
  return pathname === to || pathname.startsWith(`${to}/`);
}

function selectedDeviceIDFromPath(pathname: string) {
  const match = pathname.match(/^\/device-approvals\/devices\/([^/]+)$/);
  if (!match) {
    return "";
  }
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
}

function deviceDetailPath(deviceID: string) {
  return `/device-approvals/devices/${encodeURIComponent(deviceID)}`;
}

function formatSessionTime(value: string | undefined, locale: string) {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleTimeString(locale === "ja" ? "ja-JP" : "en-US");
}

export default function Layout() {
  const { locale, setLocale, tx } = useI18n();
  const { pathname } = useLocation();
  const { logout, session, loading } = useAuth();
  const navItems = [...navGroups.flatMap((group) => group.items), ...utilityNavItems];
  const current = navItems.find((item) => isActive(pathname, item.to));
  const selectedDeviceID = selectedDeviceIDFromPath(pathname);
  const currentGroup =
    navGroups.find((group) => group.items.some((item) => isActive(pathname, item.to))) ||
    (current ? { id: "user", label: current.label, hint: current.hint, items: [current] } : navGroups[0]);

  return (
    <div className="app-shell">
      <aside className="app-sidebar">
        <div className="app-brand">
          <p className="app-brand-tag">TUKUYOMI</p>
          <h1>{tx("Control Room")}</h1>
          <p className="app-brand-sub">{tx("Fleet Control Plane")}</p>
        </div>

        <nav className="app-nav" aria-label="primary">
          {navGroups.map((group) => (
            <section key={group.id} className="app-nav-group" aria-label={tx(group.label)}>
              <div className="app-nav-group-meta">
                <p className="app-nav-group-title">{tx(group.label)}</p>
              </div>
              <div className="app-nav-group-links">
                {group.items.map((item) => (
                  <div key={item.to} className="app-nav-item-block">
                    <Link to={item.to} className={isActive(pathname, item.to) ? "app-nav-link active" : "app-nav-link"}>
                      <span className="app-nav-label">{tx(item.label)}</span>
                    </Link>
                    {item.to === "/device-approvals" && selectedDeviceID ? (
                      <Link
                        to={deviceDetailPath(selectedDeviceID)}
                        className="app-nav-link app-nav-sublink active"
                        title={selectedDeviceID}
                      >
                        <span className="app-nav-sublabel">{tx("Selected device")}</span>
                        <span className="app-nav-label">{selectedDeviceID}</span>
                      </Link>
                    ) : null}
                  </div>
                ))}
              </div>
            </section>
          ))}
        </nav>

        <div className="app-sidebar-footer">
          {utilityNavItems.map((item) => (
            <Link
              key={item.to}
              to={item.to}
              className={isActive(pathname, item.to) ? "app-nav-link active" : "app-nav-link"}
            >
              <span className="app-nav-label">{tx(item.label)}</span>
            </Link>
          ))}
        </div>
      </aside>

      <main className="app-main">
        <header className="app-topbar">
          <div className="app-topbar-main">
            <div className="app-topbar-heading">
              <p className="app-kicker">{tx("Current Group")}</p>
              <p className="app-group-chip">{tx(currentGroup.label)}</p>
              <h2>{tx(current?.label ?? "Status")}</h2>
              {current?.hint ? <p className="app-topbar-sub">{tx(current.hint)}</p> : null}
            </div>
            <div className="app-topbar-paths">
              <code>{getAPIBasePath()}</code>
              <code>{pathname}</code>
            </div>
          </div>
          <div className="app-top-meta">
            <div className="app-top-meta-cluster">
              <label className="app-pill inline-flex items-center gap-2">
                <span>{tx("Language")}</span>
                <select
                  className="bg-transparent outline-none"
                  value={locale}
                  onChange={(event) => setLocale(event.target.value === "ja" ? "ja" : "en")}
                  aria-label={tx("Language")}
                >
                  <option value="en">{tx("English")}</option>
                  <option value="ja">{tx("Japanese")}</option>
                </select>
              </label>
              <span className="app-pill">{session.mode === "disabled" ? tx("Auth Disabled") : tx("Session")}</span>
              {session.expires_at ? (
                <span className="app-pill">
                  {tx("Expires {time}", { time: formatSessionTime(session.expires_at, locale) })}
                </span>
              ) : null}
            </div>
            <button type="button" className="app-pill app-pill-action" disabled={loading} onClick={() => void logout()}>
              {loading ? "..." : tx("Logout")}
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
