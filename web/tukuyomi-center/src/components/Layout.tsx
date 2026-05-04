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
  { to: "/settings", label: "Settings", hint: "Center runtime and policy settings." },
];

function isActive(pathname: string, to: string) {
  return pathname === to || pathname.startsWith(`${to}/`);
}

type SelectedDeviceRoute = {
  deviceID: string;
  page: "status" | "runtime" | "proxy-rules" | "waf-rules" | "remote-ssh";
};

function selectedDeviceRouteFromPath(pathname: string): SelectedDeviceRoute | null {
  const match = pathname.match(/^\/device-approvals\/devices\/([^/]+)(?:\/([^/]+))?$/);
  if (!match) {
    return null;
  }
  let deviceID = match[1];
  try {
    deviceID = decodeURIComponent(match[1]);
  } catch {
  }
  const page =
    match[2] === "runtime" || match[2] === "proxy-rules" || match[2] === "waf-rules" || match[2] === "remote-ssh"
      ? match[2]
      : "status";
  return {
    deviceID,
    page,
  };
}

function deviceStatusPath(deviceID: string) {
  return `/device-approvals/devices/${encodeURIComponent(deviceID)}`;
}

function deviceRuntimePath(deviceID: string) {
  return `/device-approvals/devices/${encodeURIComponent(deviceID)}/runtime`;
}

function deviceProxyRulesPath(deviceID: string) {
  return `/device-approvals/devices/${encodeURIComponent(deviceID)}/proxy-rules`;
}

function deviceWAFRulesPath(deviceID: string) {
  return `/device-approvals/devices/${encodeURIComponent(deviceID)}/waf-rules`;
}

function deviceRemoteSSHPath(deviceID: string) {
  return `/device-approvals/devices/${encodeURIComponent(deviceID)}/remote-ssh`;
}

function deviceMenuItems(deviceID: string): NavItem[] {
  return [
    { to: deviceStatusPath(deviceID), label: "Device Status", hint: "Selected Gateway status and config snapshots." },
    { to: deviceProxyRulesPath(deviceID), label: "Proxy Rules", hint: "" },
    { to: deviceWAFRulesPath(deviceID), label: "WAF Rules", hint: "" },
    { to: deviceRemoteSSHPath(deviceID), label: "Remote SSH", hint: "" },
    { to: deviceRuntimePath(deviceID), label: "Runtime", hint: "" },
  ];
}

function isDeviceMenuItemActive(pathname: string, item: NavItem, deviceID: string) {
  if (item.to === deviceStatusPath(deviceID)) {
    return pathname === item.to;
  }
  return isActive(pathname, item.to);
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
  const selectedDeviceRoute = selectedDeviceRouteFromPath(pathname);
  const selectedDeviceMenuItems = selectedDeviceRoute ? deviceMenuItems(selectedDeviceRoute.deviceID) : [];
  const currentDeviceItem = selectedDeviceRoute
    ? selectedDeviceMenuItems.find((item) => isDeviceMenuItemActive(pathname, item, selectedDeviceRoute.deviceID))
    : undefined;
  const current = currentDeviceItem || navItems.find((item) => isActive(pathname, item.to));
  const currentGroup = selectedDeviceRoute
    ? { id: "device", label: "Device", hint: "Selected Gateway device menu.", items: selectedDeviceMenuItems }
    : navGroups.find((group) => group.items.some((item) => isActive(pathname, item.to))) ||
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
                    {item.to === "/device-approvals" && selectedDeviceRoute ? (
                      <div className="app-device-menu">
                        <div className="app-device-menu-heading" title={selectedDeviceRoute.deviceID}>
                          <span className="app-nav-sublabel">{tx("Selected device")}</span>
                          <span className="app-nav-label">{selectedDeviceRoute.deviceID}</span>
                        </div>
                        {selectedDeviceMenuItems.map((deviceItem) => (
                          <Link
                            key={deviceItem.to}
                            to={deviceItem.to}
                            className={
                              isDeviceMenuItemActive(pathname, deviceItem, selectedDeviceRoute.deviceID)
                                ? "app-nav-link app-nav-sublink active"
                                : "app-nav-link app-nav-sublink"
                            }
                          >
                            <span className="app-nav-label">{tx(deviceItem.label)}</span>
                          </Link>
                        ))}
                      </div>
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
