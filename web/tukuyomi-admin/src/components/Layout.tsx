import { useEffect, useMemo, useState } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { apiGetJson } from "@/lib/api";
import { getAPIBasePath } from "@/lib/api";
import { useAdminRuntime } from "@/lib/adminRuntime";
import { useAuth } from "@/lib/auth";
import { useI18n } from "@/lib/i18n";

type NavItem = {
  to: string;
  label: string;
  hint: string;
};

type NavSection = {
  id: string;
  label: string;
  items: NavItem[];
};

type NavGroup = {
  id: string;
  label: string;
  hint: string;
  items?: NavItem[];
  sections?: NavSection[];
};

type PHPRuntimeNavResponse = {
  runtimes?: {
    runtimes?: Array<{
      available?: boolean;
    }>;
  };
};

type WAFEngineCapability = {
  mode?: string;
  label?: string;
  available?: boolean;
};

type StatusNavResponse = {
  app_version?: string;
  waf_engine_mode?: string;
  waf_engine_modes?: WAFEngineCapability[];
};

const baseNavGroups: NavGroup[] = [
  {
    id: "observe",
    label: "Observe",
    hint: "health, logs, alerts",
    items: [
      { to: "/status", label: "Status", hint: "runtime health" },
      { to: "/logs", label: "Logs", hint: "events and traces" },
      { to: "/notifications", label: "Notifications", hint: "state-based alert delivery" },
    ],
  },
  {
    id: "security",
    label: "Security",
    hint: "rules, reputation, anomaly defense",
    sections: [
      {
        id: "coraza",
        label: "Coraza",
        items: [
          { to: "/rules", label: "Rules", hint: "Coraza and base WAF load order" },
          { to: "/fp-tuner", label: "FP Tuner", hint: "propose and apply exclusions" },
        ],
      },
      {
        id: "request-controls",
        label: "Request Controls",
        items: [
          { to: "/bypass", label: "Bypass Rules", hint: "path overrides" },
          { to: "/country-block", label: "Country Block", hint: "country deny list" },
          { to: "/rate-limit", label: "Rate Limit", hint: "traffic policies" },
          { to: "/ip-reputation", label: "IP Reputation", hint: "allow/block feeds and CIDRs" },
          { to: "/bot-defense", label: "Bot Defense", hint: "ua challenge policy" },
          { to: "/semantic", label: "Semantic Security", hint: "heuristic anomaly scoring" },
        ],
      },
    ],
  },
  {
    id: "proxy",
    label: "Proxy",
    hint: "routes, cache, traffic ownership",
    items: [
      { to: "/cache", label: "Cache Rules", hint: "edge cache behavior" },
      { to: "/proxy-rules", label: "Proxy Rules", hint: "upstream and transport tuning" },
      { to: "/backends", label: "Backends", hint: "canonical backend status and direct-upstream runtime ops" },
      { to: "/sites", label: "Sites", hint: "hostname ownership and tls binding" },
    ],
  },
  {
    id: "operations",
    label: "Operations",
    hint: "runtime helpers and access",
    items: [
      { to: "/scheduled-tasks", label: "Scheduled Tasks", hint: "php cli jobs managed outside the request path" },
      { to: "/options", label: "Options", hint: "runtime inventory and lifecycle state" },
    ],
  },
];

const settingsNavItem: NavItem = {
  to: "/settings",
  label: "Settings",
  hint: "startup config, operator identity, verify manifest",
};

const userNavItem: NavItem = {
  to: "/user",
  label: "User",
  hint: "account, password, tokens",
};

function groupItems(group: NavGroup): NavItem[] {
  if (group.sections) {
    return group.sections.flatMap((section) => section.items);
  }
  return group.items ?? [];
}

function isActive(pathname: string, to: string) {
  return pathname === to || pathname.startsWith(`${to}/`);
}

function normalizeWAFEngineMode(mode: string | undefined) {
  return (mode || "coraza").trim().toLowerCase() || "coraza";
}

function hasAvailableWAFEngine(mode: string, engines: WAFEngineCapability[]) {
  if (engines.length === 0) {
    return mode === "coraza";
  }
  return engines.some((engine) => normalizeWAFEngineMode(engine.mode) === mode && engine.available === true);
}

function formatAppVersion(version: string) {
  const normalized = version.trim();
  if (/^\d+\.\d+\.\d+/.test(normalized)) {
    return `v${normalized}`;
  }
  return normalized;
}

export default function Layout() {
  const { locale, setLocale, tx } = useI18n();
  const { pathname } = useLocation();
  const { logout, session, loading } = useAuth();
  const { readOnly } = useAdminRuntime();
  const [hasBuiltRuntime, setHasBuiltRuntime] = useState(false);
  const [wafEngineMode, setWAFEngineMode] = useState("coraza");
  const [wafEngineModes, setWAFEngineModes] = useState<WAFEngineCapability[]>([]);
  const [appVersion, setAppVersion] = useState("");
  const formattedAppVersion = formatAppVersion(appVersion);

  useEffect(() => {
    let active = true;
    void apiGetJson<PHPRuntimeNavResponse>("/php-runtimes")
      .then((data) => {
        if (!active) {
          return;
        }
        const runtimes = Array.isArray(data.runtimes?.runtimes) ? data.runtimes.runtimes : [];
        setHasBuiltRuntime(runtimes.some((runtime) => runtime.available === true));
      })
      .catch(() => {
        if (!active) {
          return;
        }
        setHasBuiltRuntime(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    void apiGetJson<StatusNavResponse>("/status")
      .then((data) => {
        if (!active) {
          return;
        }
        setAppVersion(typeof data.app_version === "string" ? data.app_version : "");
        setWAFEngineMode(normalizeWAFEngineMode(data.waf_engine_mode));
        setWAFEngineModes(Array.isArray(data.waf_engine_modes) ? data.waf_engine_modes : []);
      })
      .catch(() => {
        if (!active) {
          return;
        }
        setAppVersion("");
        setWAFEngineMode("coraza");
        setWAFEngineModes([]);
      });
    return () => {
      active = false;
    };
  }, []);

  const navGroups = useMemo(
    () =>
      baseNavGroups.map((group) => {
        if (group.id === "security" && group.sections) {
          const showCoraza = wafEngineMode === "coraza" && hasAvailableWAFEngine("coraza", wafEngineModes);
          return {
            ...group,
            sections: group.sections.filter((section) => section.id !== "coraza" || showCoraza),
          };
        }
        if (group.id === "operations") {
          return {
            ...group,
            items: hasBuiltRuntime
              ? [
                  ...groupItems(group),
                  { to: "/runtime-apps", label: "Runtime Apps", hint: "runtime listener, port, and docroot bindings" },
                ]
              : groupItems(group),
          };
        }
        return group;
      }),
    [hasBuiltRuntime, wafEngineMode, wafEngineModes],
  );
  const utilityNavItems = [userNavItem, settingsNavItem];
  const navItems = [...navGroups.flatMap(groupItems), ...utilityNavItems];
  const current = navItems.find((item) => isActive(pathname, item.to));
  const currentUtility = utilityNavItems.find((item) => isActive(pathname, item.to));
  const currentGroup = currentUtility
    ? {
        id: currentUtility.label.toLowerCase(),
        label: currentUtility.label,
        hint: currentUtility.hint,
        items: [currentUtility],
      }
    : navGroups.find((group) =>
        groupItems(group).some((item) => isActive(pathname, item.to)),
      );

  return (
    <div className="app-shell">
      <aside className="app-sidebar">
        <div className="app-brand">
          <p className="app-brand-tag">TUKUYOMI{formattedAppVersion ? ` ${formattedAppVersion}` : ""}</p>
          <h1>{tx("Control Room")}</h1>
          <p className="app-brand-sub">{tx("Coraza + CRS Security Gateway")}</p>
        </div>

        <nav className="app-nav" aria-label="primary">
          {navGroups.map((group) => (
            <section key={group.id} className="app-nav-group" aria-label={tx(group.label)}>
              <div className="app-nav-group-meta">
                <p className="app-nav-group-title">{tx(group.label)}</p>
              </div>
              <div className="app-nav-group-links">
                {group.sections
                  ? group.sections.map((section) => (
                      <div key={section.id} className="app-nav-section">
                        <p className="app-nav-section-title">{tx(section.label)}</p>
                        {section.items.map((item) => {
                          const active = isActive(pathname, item.to);
                          return (
                            <Link key={item.to} to={item.to} className={active ? "app-nav-link active" : "app-nav-link"}>
                              <span className="app-nav-label">{tx(item.label)}</span>
                            </Link>
                          );
                        })}
                      </div>
                    ))
                  : groupItems(group).map((item) => {
                      const active = isActive(pathname, item.to);
                      return (
                        <Link key={item.to} to={item.to} className={active ? "app-nav-link active" : "app-nav-link"}>
                          <span className="app-nav-label">{tx(item.label)}</span>
                        </Link>
                      );
                    })}
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
              {currentGroup ? <p className="app-group-chip">{tx(currentGroup.label)}</p> : null}
              <h2>{tx(current?.label ?? "Dashboard")}</h2>
              {currentGroup?.hint ? <p className="app-topbar-sub">{tx(currentGroup.hint)}</p> : null}
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
                >
                  <option value="en">{tx("English")}</option>
                  <option value="ja">{tx("Japanese")}</option>
                </select>
              </label>
              <span className="app-pill">{session.mode === "disabled" ? tx("Auth Disabled") : tx("Session")}</span>
              {readOnly ? <span className="app-pill bg-amber-100 text-amber-900">{tx("Admin Read-Only")}</span> : null}
              {session.expires_at ? (
                <span className="app-pill">
                  {tx("Expires {time}", {
                    time: new Date(session.expires_at).toLocaleTimeString(locale === "ja" ? "ja-JP" : "en-US"),
                  })}
                </span>
              ) : null}
            </div>
            <button type="button" className="app-pill app-pill-action" disabled={loading} onClick={() => void logout()}>
              {loading ? "..." : tx("Logout")}
            </button>
          </div>
        </header>

        <section className="app-content">
          {readOnly ? (
            <div className="mb-4 rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-xs text-amber-900">
              {tx("This deployment is admin read-only. Inspect, validate, and dry-run actions remain available, but apply/save/rollback actions are disabled. Roll out config changes from source control or image updates instead.")}
            </div>
          ) : null}
          <Outlet />
        </section>
      </main>
    </div>
  );
}
