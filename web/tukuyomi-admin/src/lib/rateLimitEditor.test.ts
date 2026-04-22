import assert from "node:assert/strict";
import test from "node:test";

import {
  createDefaultRateLimitEditorState,
  createDefaultRateLimitScopeDraft,
  parseRateLimitEditor,
  parseRateLimitEditorDocument,
  serializeRateLimitEditor,
} from "./rateLimitEditor.js";

test("parseRateLimitEditor reads adaptive and feedback settings from legacy config", () => {
  const parsed = parseRateLimitEditor(`{
    "enabled": true,
    "allowlist_ips": ["127.0.0.1/32", "10.0.0.0/8"],
    "allowlist_countries": ["jp", "US"],
    "session_cookie_names": ["session_id"],
    "jwt_header_names": ["Authorization"],
    "jwt_cookie_names": ["jwt"],
    "adaptive_enabled": true,
    "adaptive_score_threshold": 7,
    "adaptive_limit_factor_percent": 40,
    "adaptive_burst_factor_percent": 20,
    "feedback": {
      "enabled": true,
      "strikes_required": 2,
      "strike_window_seconds": 120,
      "adaptive_only": false,
      "dry_run": true
    },
    "default_policy": {
      "enabled": true,
      "limit": 50,
      "window_seconds": 30,
      "burst": 10,
      "key_by": "session",
      "action": {
        "status": 429,
        "retry_after_seconds": 15
      }
    },
    "rules": [
      {
        "name": "login",
        "match_type": "prefix",
        "match_value": "/login",
        "methods": ["post", "POST"],
        "policy": {
          "enabled": true,
          "limit": 5,
          "window_seconds": 60,
          "burst": 0,
          "key_by": "ip_country",
          "action": {
            "status": 429,
            "retry_after_seconds": 30
          }
        }
      }
    ]
  }`);

  assert.equal(parsed.adaptiveEnabled, true);
  assert.deepEqual(parsed.allowlistCountries, ["JP", "US"]);
  assert.equal(parsed.feedback.enabled, true);
  assert.equal(parsed.feedback.strikeWindowSeconds, 120);
  assert.equal(parsed.defaultPolicy.keyBy, "session");
  assert.deepEqual(parsed.rules[0]?.methods, ["POST"]);
  assert.equal(parsed.rules[0]?.policy.keyBy, "ip_country");
  assert.deepEqual(parsed.hosts, []);
});

test("parseRateLimitEditor supplies backend-aligned defaults", () => {
  const parsed = parseRateLimitEditor(`{"enabled": false}`);
  const defaults = createDefaultRateLimitEditorState();

  assert.equal(parsed.enabled, false);
  assert.deepEqual(parsed.sessionCookieNames, defaults.sessionCookieNames);
  assert.deepEqual(parsed.jwtHeaderNames, defaults.jwtHeaderNames);
  assert.deepEqual(parsed.jwtCookieNames, defaults.jwtCookieNames);
  assert.deepEqual(parsed.defaultPolicy, defaults.defaultPolicy);
  assert.deepEqual(parsed.feedback, defaults.feedback);
  assert.deepEqual(parsed.hosts, []);
});

test("parseRateLimitEditor reads canonical host scopes", () => {
  const parsed = parseRateLimitEditor(`{
    "default": {
      "enabled": true,
      "default_policy": {
        "enabled": true,
        "limit": 50,
        "window_seconds": 30,
        "burst": 10,
        "key_by": "ip",
        "action": {
          "status": 429,
          "retry_after_seconds": 15
        }
      },
      "rules": []
    },
    "hosts": {
      "Admin.EXAMPLE.com": {
        "default_policy": {
          "enabled": true,
          "limit": 5,
          "window_seconds": 30,
          "burst": 0,
          "key_by": "ip_country",
          "action": {
            "status": 429,
            "retry_after_seconds": 15
          }
        }
      }
    }
  }`);

  assert.equal(parsed.defaultPolicy.limit, 50);
  assert.equal(parsed.hosts[0]?.host, "admin.example.com");
  assert.equal(parsed.hosts[0]?.defaultPolicy.limit, 5);
  assert.equal(parsed.hosts[0]?.defaultPolicy.keyBy, "ip_country");
});

test("serializeRateLimitEditor writes canonical host-aware JSON", () => {
  const serialized = serializeRateLimitEditor({
    ...createDefaultRateLimitEditorState(),
    enabled: true,
    allowlistIPs: ["10.0.0.0/8", "127.0.0.1/32"],
    allowlistCountries: ["us", "JP", "us"],
    sessionCookieNames: ["session", "session"],
    jwtHeaderNames: ["Authorization"],
    jwtCookieNames: ["token"],
    rules: [
      {
        name: "login",
        matchType: "prefix",
        matchValue: "/login",
        methods: ["post", "POST", "get"],
        policy: {
          enabled: true,
          limit: 5,
          windowSeconds: 60,
          burst: 0,
          keyBy: "ip_country",
          action: {
            status: 429,
            retryAfterSeconds: 30,
          },
        },
      },
    ],
    hosts: [
      {
        host: "Admin.Example.com",
        ...createDefaultRateLimitScopeDraft(),
        rules: [],
      },
    ],
  });

  const parsedJSON = JSON.parse(serialized) as Record<string, unknown>;
  const defaultScope = parsedJSON.default as Record<string, unknown>;
  const hosts = parsedJSON.hosts as Record<string, Record<string, unknown>>;
  assert.deepEqual(defaultScope.allowlist_countries, ["JP", "US"]);
  assert.deepEqual(defaultScope.session_cookie_names, ["session"]);
  assert.deepEqual((defaultScope.rules as Array<Record<string, unknown>>)[0]?.methods, ["GET", "POST"]);
  assert.ok("admin.example.com" in hosts);
});

test("serializeRateLimitEditor preserves unrelated JSON fields from legacy default scope", () => {
  const initial = parseRateLimitEditorDocument(`{
    "custom_top": "keep",
    "enabled": true,
    "feedback": {
      "enabled": true,
      "strikes_required": 2,
      "strike_window_seconds": 120,
      "adaptive_only": false,
      "dry_run": true,
      "note": "keep"
    },
    "default_policy": {
      "enabled": true,
      "limit": 50,
      "window_seconds": 30,
      "burst": 10,
      "key_by": "session",
      "action": {
        "status": 429,
        "retry_after_seconds": 15,
        "body": "keep"
      },
      "label": "keep"
    },
    "rules": [
      {
        "name": "login",
        "match_type": "prefix",
        "match_value": "/login",
        "methods": ["POST"],
        "policy": {
          "enabled": true,
          "limit": 5,
          "window_seconds": 60,
          "burst": 0,
          "key_by": "ip_country",
          "action": {
            "status": 429,
            "retry_after_seconds": 30,
            "body": "rule-keep"
          },
          "tag": "keep"
        },
        "custom_rule": "keep"
      }
    ]
  }`);

  const serialized = serializeRateLimitEditor(
    initial.base,
    {
      ...initial.state,
      defaultPolicy: {
        ...initial.state.defaultPolicy,
        limit: 75,
      },
    },
    initial.defaultBase,
    initial.defaultRuleBases,
    initial.hostBases,
    initial.hostRuleBases,
  );

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  const defaultScope = reparsed.default as Record<string, unknown>;
  assert.equal((defaultScope as Record<string, unknown>).custom_top, "keep");
  assert.equal((defaultScope.feedback as Record<string, unknown>).note, "keep");
  assert.equal((defaultScope.default_policy as Record<string, unknown>).label, "keep");
  assert.equal(
    ((defaultScope.default_policy as Record<string, unknown>).action as Record<string, unknown>).body,
    "keep",
  );
  assert.equal(((defaultScope.rules as Array<Record<string, unknown>>)[0]).custom_rule, "keep");
  assert.equal(
    ((((defaultScope.rules as Array<Record<string, unknown>>)[0]).policy as Record<string, unknown>).action as Record<string, unknown>).body,
    "rule-keep",
  );
  assert.equal((((defaultScope.rules as Array<Record<string, unknown>>)[0]).policy as Record<string, unknown>).tag, "keep");
});

test("serializeRateLimitEditor preserves correct host extras after host removal", () => {
  const initial = parseRateLimitEditorDocument(`{
    "default": {
      "enabled": true,
      "default_policy": {
        "enabled": true,
        "limit": 1,
        "window_seconds": 60,
        "burst": 0,
        "key_by": "ip",
        "action": {
          "status": 429,
          "retry_after_seconds": 30
        }
      },
      "rules": []
    },
    "hosts": {
      "one.example.com": {
        "enabled": true,
        "custom_host": "first",
        "rules": []
      },
      "two.example.com": {
        "enabled": true,
        "custom_host": "second",
        "rules": []
      }
    }
  }`);

  const serialized = serializeRateLimitEditor(
    initial.base,
    {
      ...initial.state,
      hosts: [initial.state.hosts[1]!],
    },
    initial.defaultBase,
    initial.defaultRuleBases,
    [initial.hostBases[1]!],
    [initial.hostRuleBases[1]!],
  );

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  const hosts = reparsed.hosts as Record<string, Record<string, unknown>>;
  assert.deepEqual(Object.keys(hosts), ["two.example.com"]);
  assert.equal(hosts["two.example.com"]?.custom_host, "second");
});

test("serializeRateLimitEditor rejects duplicate normalized host scopes", () => {
  assert.throws(
    () =>
      serializeRateLimitEditor({
        ...createDefaultRateLimitEditorState(),
        hosts: [
          { host: "Example.com", ...createDefaultRateLimitScopeDraft(), rules: [] },
          { host: "example.com", ...createDefaultRateLimitScopeDraft(), rules: [] },
        ],
      }),
    /duplicate host scope: example\.com/,
  );
});
