import assert from "node:assert/strict";
import test from "node:test";

import {
  createDefaultBotDefenseState,
  parseBotDefenseEditor,
  parseBotDefenseEditorDocument,
  serializeBotDefenseEditor,
} from "./botDefenseEditor.js";

test("parseBotDefenseEditor reads legacy nested signal modules and path policies", () => {
  const parsed = parseBotDefenseEditor(`{
    "enabled": true,
    "dry_run": true,
    "mode": "always",
    "path_prefixes": ["/", "/account"],
    "path_policies": [
      {
        "name": "login",
        "path_prefixes": ["/login"],
        "mode": "always",
        "dry_run": false,
        "risk_score_multiplier_percent": 150,
        "risk_score_offset": 2,
        "telemetry_cookie_required": true,
        "disable_quarantine": true
      }
    ],
    "exempt_cidrs": ["127.0.0.1/32"],
    "suspicious_user_agents": ["curl", "python-requests"],
    "challenge_cookie_name": "__bot_ok",
    "challenge_secret": "secret",
    "challenge_ttl_seconds": 1800,
    "challenge_status_code": 451,
    "behavioral_detection": {
      "enabled": true,
      "window_seconds": 30,
      "burst_threshold": 10,
      "path_fanout_threshold": 4,
      "ua_churn_threshold": 3,
      "missing_cookie_threshold": 5,
      "score_threshold": 2,
      "risk_score_per_signal": 3
    },
    "browser_signals": {
      "enabled": true,
      "js_cookie_name": "__bot_js",
      "score_threshold": 1,
      "risk_score_per_signal": 2
    },
    "device_signals": {
      "enabled": true,
      "require_time_zone": true,
      "require_platform": true,
      "require_hardware_concurrency": false,
      "check_mobile_touch": false,
      "invisible_html_injection": true,
      "invisible_max_body_bytes": 8192,
      "score_threshold": 3,
      "risk_score_per_signal": 4
    },
    "header_signals": {
      "enabled": true,
      "require_accept_language": true,
      "require_fetch_metadata": false,
      "require_client_hints": false,
      "require_upgrade_insecure_requests": true,
      "score_threshold": 2,
      "risk_score_per_signal": 4
    },
    "tls_signals": {
      "enabled": true,
      "require_sni": true,
      "require_alpn": false,
      "require_modern_tls": false,
      "score_threshold": 2,
      "risk_score_per_signal": 5
    },
    "quarantine": {
      "enabled": true,
      "threshold": 7,
      "strikes_required": 3,
      "strike_window_seconds": 120,
      "ttl_seconds": 600,
      "status_code": 429,
      "reputation_feedback_seconds": 60
    }
  }`);

  assert.equal(parsed.enabled, true);
  assert.equal(parsed.mode, "always");
  assert.equal(parsed.pathPolicies[0]?.dryRun, "disabled");
  assert.equal(parsed.pathPolicies[0]?.telemetryCookieRequired, true);
  assert.equal(parsed.behavioralDetection.windowSeconds, 30);
  assert.equal(parsed.browserSignals.jsCookieName, "__bot_js");
  assert.equal(parsed.deviceSignals.invisibleHTMLInjection, true);
  assert.equal(parsed.quarantine.reputationFeedbackSeconds, 60);
  assert.deepEqual(parsed.hosts, []);
});

test("parseBotDefenseEditor supports canonical default and hosts", () => {
  const parsed = parseBotDefenseEditor(`{
    "default": {
      "enabled": true,
      "mode": "always",
      "path_prefixes": ["/"],
      "browser_signals": {
        "enabled": true,
        "js_cookie_name": "__bot_js"
      }
    },
    "hosts": {
      "Admin.EXAMPLE.com:8443": {
        "dry_run": true,
        "path_prefixes": ["/admin"],
        "quarantine": {
          "enabled": true,
          "threshold": 9
        }
      }
    }
  }`);

  assert.equal(parsed.enabled, true);
  assert.equal(parsed.mode, "always");
  assert.equal(parsed.browserSignals.enabled, true);
  assert.equal(parsed.hosts.length, 1);
  assert.equal(parsed.hosts[0]?.host, "admin.example.com:8443");
  assert.equal(parsed.hosts[0]?.dryRun, true);
  assert.deepEqual(parsed.hosts[0]?.pathPrefixes, ["/admin"]);
  assert.equal(parsed.hosts[0]?.browserSignals.enabled, true);
  assert.equal(parsed.hosts[0]?.quarantine.enabled, true);
  assert.equal(parsed.hosts[0]?.quarantine.threshold, 9);
});

test("parseBotDefenseEditor supplies backend-aligned defaults", () => {
  const parsed = parseBotDefenseEditor(`{"enabled": true}`);
  const defaults = createDefaultBotDefenseState();

  assert.equal(parsed.enabled, true);
  assert.equal(parsed.mode, defaults.mode);
  assert.deepEqual(parsed.pathPrefixes, defaults.pathPrefixes);
  assert.deepEqual(parsed.suspiciousUserAgents, defaults.suspiciousUserAgents);
  assert.equal(parsed.challengeTTLSeconds, defaults.challengeTTLSeconds);
  assert.equal(parsed.browserSignals.jsCookieName, defaults.browserSignals.jsCookieName);
});

test("serializeBotDefenseEditor writes canonical default and hosts", () => {
  const raw = serializeBotDefenseEditor({
    ...createDefaultBotDefenseState(),
    enabled: true,
    pathPrefixes: ["/"],
    hosts: [
      {
        ...createDefaultBotDefenseState(),
        host: "admin.example.com",
        enabled: true,
        dryRun: true,
        pathPrefixes: ["/admin"],
        hosts: [],
      },
    ],
  } as unknown as ReturnType<typeof createDefaultBotDefenseState>);
  const parsed = JSON.parse(raw) as Record<string, unknown>;

  assert.ok(parsed.default);
  assert.ok(parsed.hosts);
  assert.equal(((parsed.default as Record<string, unknown>).enabled), true);
  assert.equal((((parsed.hosts as Record<string, Record<string, unknown>>)["admin.example.com"]).dry_run), true);
});

test("serializeBotDefenseEditor preserves unrelated nested fields in default and host scopes", () => {
  const initial = parseBotDefenseEditorDocument(`{
    "custom_top": "keep",
    "default": {
      "path_policies": [
        {
          "name": "login",
          "path_prefixes": ["/login"],
          "custom_policy": "default"
        }
      ],
      "behavioral_detection": {
        "enabled": true,
        "window_seconds": 60,
        "custom_behavior": "keep"
      }
    },
    "hosts": {
      "admin.example.com": {
        "path_policies": [
          {
            "name": "admin",
            "path_prefixes": ["/admin"],
            "custom_policy": "host"
          }
        ],
        "browser_signals": {
          "enabled": true,
          "custom_browser": "keep"
        }
      }
    }
  }`);

  const serialized = serializeBotDefenseEditor(
    initial.base,
    {
      ...initial.state,
      pathPolicies: [
        {
          ...initial.state.pathPolicies[0]!,
          riskScoreMultiplierPercent: 175,
        },
      ],
      behavioralDetection: {
        ...initial.state.behavioralDetection,
        burstThreshold: 14,
      },
      hosts: initial.state.hosts.map((scope) => ({
        ...scope,
        browserSignals: {
          ...scope.browserSignals,
          scoreThreshold: 3,
        },
      })),
    },
    initial.defaultBase,
    initial.defaultPathPolicyBases,
    initial.hostBases,
    initial.hostPathPolicyBases,
  );

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  const outDefault = reparsed.default as Record<string, unknown>;
  const outHost = (reparsed.hosts as Record<string, Record<string, unknown>>)["admin.example.com"];
  assert.equal(reparsed.custom_top, "keep");
  assert.equal(((outDefault.path_policies as Array<Record<string, unknown>>)[0]).custom_policy, "default");
  assert.equal((outDefault.behavioral_detection as Record<string, unknown>).custom_behavior, "keep");
  assert.equal(((outHost.path_policies as Array<Record<string, unknown>>)[0]).custom_policy, "host");
  assert.equal((outHost.browser_signals as Record<string, unknown>).custom_browser, "keep");
});

test("serializeBotDefenseEditor preserves correct host extras after host removal", () => {
  const initial = parseBotDefenseEditorDocument(`{
    "hosts": {
      "one.example.com": {
        "browser_signals": {
          "custom_browser": "first"
        }
      },
      "two.example.com": {
        "browser_signals": {
          "custom_browser": "second"
        }
      }
    }
  }`);

  const serialized = serializeBotDefenseEditor(
    initial.base,
    {
      ...initial.state,
      hosts: [initial.state.hosts[1]!],
    },
    initial.defaultBase,
    initial.defaultPathPolicyBases,
    [initial.hostBases[1]!],
    [initial.hostPathPolicyBases[1]!],
  );

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  const hosts = reparsed.hosts as Record<string, Record<string, unknown>>;
  assert.equal(Object.keys(hosts).length, 1);
  assert.equal((hosts["two.example.com"].browser_signals as Record<string, unknown>).custom_browser, "second");
});

test("serializeBotDefenseEditor rejects duplicate normalized host scopes", () => {
  const state = createDefaultBotDefenseState();
  state.hosts = [
    {
      host: "Admin.Example.com:8443",
      ...createDefaultBotDefenseState(),
      hosts: [],
    } as unknown as (typeof state.hosts)[number],
    {
      host: "admin.example.com:8443",
      ...createDefaultBotDefenseState(),
      hosts: [],
    } as unknown as (typeof state.hosts)[number],
  ];

  assert.throws(() => serializeBotDefenseEditor(state), /duplicate host scope/i);
});
