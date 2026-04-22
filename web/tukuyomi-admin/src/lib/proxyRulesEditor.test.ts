import assert from "node:assert/strict";
import test from "node:test";
import {
  createEmptyDefaultRoute,
  createEmptyUpstreamDiscovery,
  headerMapToMultiline,
  multilineToQueryMap,
  multilineToHeaderMap,
  multilineToStringList,
  parseProxyRulesEditor,
  queryMapToMultiline,
  serializeProxyRulesEditor,
  stringListToMultiline,
  type ProxyRulesRoutingEditorState,
} from "./proxyRulesEditor.js";

test("parseProxyRulesEditor reads route fields without dropping unrelated config", () => {
  const raw = `{
    "dial_timeout": 5,
    "upstreams": [
      {
        "name": "service-a",
        "url": "http://service-a.internal:8080",
        "weight": 2,
        "enabled": true,
        "http2_mode": "force_attempt",
        "tls": {
          "server_name": "service-a.internal",
          "ca_bundle": "/etc/tukuyomi/ca.pem",
          "min_version": "tls1.2",
          "max_version": "tls1.3",
          "client_cert": "/etc/tukuyomi/client.pem",
          "client_key": "/etc/tukuyomi/client.key"
        }
      },
      {
        "name": "service-a-canary",
        "url": "http://canary.internal:8080",
        "weight": 1,
        "enabled": true
      },
      {
        "name": "fallback",
        "url": "http://fallback.internal:8080",
        "weight": 1,
        "enabled": true
      }
    ],
    "backend_pools": [
      {
        "name": "site-api",
        "strategy": "least_conn",
        "hash_policy": "header",
        "hash_key": "X-Tenant",
        "members": ["service-a", "service-b"],
        "sticky_session": {
          "enabled": true,
          "cookie_name": "tky_lb_site_api",
          "ttl_seconds": 120,
          "path": "/",
          "secure": true,
          "http_only": true,
          "same_site": "lax"
        }
      }
    ],
    "routes": [
      {
        "name": "service-a-prefix",
        "priority": 10,
        "match": {
          "hosts": ["api.example.com", "*.example.net"],
          "path": { "type": "prefix", "value": "/servicea/" }
        },
        "action": {
          "backend_pool": "site-api",
          "upstream": "service-a",
          "canary_upstream": "service-a-canary",
          "canary_weight_percent": 15,
          "hash_policy": "header",
          "hash_key": "X-User",
          "host_rewrite": "service-a.internal",
          "path_rewrite": { "prefix": "/service-a/" },
          "query_rewrite": {
            "remove": ["debug"],
            "remove_prefixes": ["utm_"],
            "set": { "lang": "ja" },
            "add": { "preview": "1" }
          },
          "request_headers": {
            "set": { "X-Service": "service-a" }
          },
          "response_headers": {
            "add": { "Cache-Control": "no-store" }
          }
        }
      }
    ],
    "default_route": {
      "name": "fallback",
      "action": {
        "upstream": "fallback"
      }
    }
  }`;

  const parsed = parseProxyRulesEditor(raw);
  assert.equal(parsed.base.dial_timeout, 5);
  assert.equal(parsed.state.exposeWAFDebugHeaders, false);
  assert.equal(parsed.state.emitUpstreamNameRequestHeader, false);
  assert.equal(parsed.state.responseHeaderSanitize.mode, "auto");
  assert.deepEqual(parsed.state.responseHeaderSanitize.customRemove, []);
  assert.deepEqual(parsed.state.responseHeaderSanitize.customKeep, []);
  assert.equal(parsed.state.responseHeaderSanitize.debugLog, false);
  assert.equal(parsed.state.upstreams.length, 3);
  assert.equal(parsed.state.backendPools.length, 1);
  assert.equal(parsed.state.backendPools[0]?.strategy, "least_conn");
  assert.equal(parsed.state.backendPools[0]?.hashPolicy, "header");
  assert.equal(parsed.state.backendPools[0]?.members[1], "service-b");
  assert.equal(parsed.state.backendPools[0]?.stickySession.enabled, true);
  assert.equal(parsed.state.backendPools[0]?.stickySession.cookieName, "tky_lb_site_api");
  assert.equal(parsed.state.backendPools[0]?.stickySession.ttlSeconds, 120);
  assert.equal(parsed.state.backendPools[0]?.stickySession.secure, true);
  assert.equal(parsed.state.upstreams[0]?.http2Mode, "force_attempt");
  assert.equal(parsed.state.upstreams[0]?.tlsServerName, "service-a.internal");
  assert.equal(parsed.state.upstreams[0]?.tlsCABundle, "/etc/tukuyomi/ca.pem");
  assert.equal(parsed.state.routes.length, 1);
  assert.equal(parsed.state.routes[0]?.action.backendPool, "site-api");
  assert.equal(parsed.state.routes[0]?.path?.type, "prefix");
  assert.equal(parsed.state.routes[0]?.action.hostRewrite, "service-a.internal");
  assert.equal(parsed.state.routes[0]?.action.canaryUpstream, "service-a-canary");
  assert.equal(parsed.state.routes[0]?.action.hashPolicy, "header");
  assert.equal(parsed.state.routes[0]?.action.hashKey, "X-User");
  assert.equal(parsed.state.routes[0]?.action.queryRewrite.set.lang, "ja");
  assert.equal(parsed.state.routes[0]?.action.queryRewrite.removePrefixes[0], "utm_");
  assert.equal(parsed.state.routes[0]?.action.requestHeaders.set["X-Service"], "service-a");
  assert.equal(parsed.state.defaultRoute?.action.upstream, "fallback");
});

test("serializeProxyRulesEditor updates routing fields and preserves unrelated keys", () => {
  const initial = parseProxyRulesEditor(`{
    "dial_timeout": 5,
    "max_idle_conns": 10,
    "response_header_sanitize": {
      "mode": "manual",
      "custom_remove": ["X-Test-Leak"],
      "debug_log": true
    }
  }`);

  const nextState: ProxyRulesRoutingEditorState = {
    exposeWAFDebugHeaders: true,
    emitUpstreamNameRequestHeader: true,
    responseHeaderSanitize: {
      mode: "off",
      customRemove: ["X-Explicit-Remove"],
      customKeep: ["Server"],
      debugLog: false,
    },
    upstreams: [
      {
        name: "service-a",
        url: "http://service-a.internal:8080",
        weight: 2,
        enabled: true,
        discovery: createEmptyUpstreamDiscovery(),
        http2Mode: "force_attempt",
        tlsServerName: "service-a.internal",
        tlsCABundle: "/etc/tukuyomi/ca.pem",
        tlsMinVersion: "tls1.2",
        tlsMaxVersion: "tls1.3",
        tlsClientCert: "/etc/tukuyomi/client.pem",
        tlsClientKey: "/etc/tukuyomi/client.key",
      },
      {
        name: "service-a-canary",
        url: "http://service-a-canary.internal:8080",
        weight: 1,
        enabled: true,
        discovery: createEmptyUpstreamDiscovery(),
        http2Mode: "default",
        tlsServerName: "",
        tlsCABundle: "",
        tlsMinVersion: "",
        tlsMaxVersion: "",
        tlsClientCert: "",
        tlsClientKey: "",
      },
      {
        name: "fallback",
        url: "http://fallback.internal:8080",
        weight: 1,
        enabled: true,
        discovery: createEmptyUpstreamDiscovery(),
        http2Mode: "default",
        tlsServerName: "",
        tlsCABundle: "",
        tlsMinVersion: "",
        tlsMaxVersion: "",
        tlsClientCert: "",
        tlsClientKey: "",
      },
    ],
    backendPools: [
      {
        name: "site-api",
        strategy: "least_conn",
        hashPolicy: "header",
        hashKey: "X-Tenant",
        members: ["service-a", "service-b"],
        stickySession: {
          enabled: true,
          cookieName: "tky_lb_site_api",
          ttlSeconds: 120,
          path: "/",
          domain: "",
          secure: true,
          httpOnly: true,
          sameSite: "lax",
        },
      },
    ],
    routes: [
      {
        name: "service-a-prefix",
        enabled: true,
        priority: 10,
        hosts: ["api.example.com"],
        path: { type: "prefix", value: "/servicea/" },
        action: {
          backendPool: "site-api",
          upstream: "service-a",
          canaryUpstream: "service-a-canary",
          canaryWeightPercent: 20,
          hashPolicy: "cookie",
          hashKey: "session",
          hostRewrite: "",
          pathRewrite: { prefix: "/service-a/" },
          queryRewrite: {
            set: { lang: "ja" },
            add: { preview: "1" },
            remove: ["debug"],
            removePrefixes: ["utm_"],
          },
          requestHeaders: {
            set: { "X-Service": "service-a" },
            add: {},
            remove: [],
          },
          responseHeaders: {
            set: {},
            add: { "Cache-Control": "no-store" },
            remove: [],
          },
        },
      },
    ],
    defaultRoute: createEmptyDefaultRoute(),
  };
  nextState.defaultRoute!.action.upstream = "fallback";

  const serialized = serializeProxyRulesEditor(initial.base, nextState);
  const reparsed = parseProxyRulesEditor(serialized);

  assert.equal(reparsed.base.dial_timeout, 5);
  assert.equal(reparsed.base.max_idle_conns, 10);
  assert.equal(reparsed.base.expose_waf_debug_headers, true);
  assert.equal(reparsed.base.emit_upstream_name_request_header, true);
  assert.deepEqual(reparsed.base.response_header_sanitize, {
    mode: "off",
    custom_remove: ["X-Explicit-Remove"],
    custom_keep: ["Server"],
    debug_log: false,
  });
  assert.equal(reparsed.state.backendPools[0]?.name, "site-api");
  assert.equal(reparsed.state.backendPools[0]?.strategy, "least_conn");
  assert.equal(reparsed.state.backendPools[0]?.hashPolicy, "header");
  assert.equal(reparsed.state.backendPools[0]?.stickySession.cookieName, "tky_lb_site_api");
  assert.equal(reparsed.state.backendPools[0]?.stickySession.ttlSeconds, 120);
  assert.equal(reparsed.state.upstreams[0]?.name, "service-a");
  assert.equal(reparsed.state.upstreams[0]?.http2Mode, "force_attempt");
  assert.equal(reparsed.state.upstreams[0]?.tlsClientKey, "/etc/tukuyomi/client.key");
  assert.equal(reparsed.state.routes[0]?.action.canaryUpstream, "service-a-canary");
  assert.equal(reparsed.state.routes[0]?.action.backendPool, "site-api");
  assert.equal(reparsed.state.routes[0]?.action.hashPolicy, "cookie");
  assert.equal(reparsed.state.routes[0]?.action.hashKey, "session");
  assert.equal(reparsed.state.routes[0]?.action.pathRewrite?.prefix, "/service-a/");
  assert.equal(reparsed.state.routes[0]?.action.queryRewrite.set.lang, "ja");
  assert.equal(reparsed.state.routes[0]?.action.queryRewrite.removePrefixes[0], "utm_");
  assert.equal(reparsed.state.routes[0]?.action.responseHeaders.add["Cache-Control"], "no-store");
  assert.equal(reparsed.state.defaultRoute?.action.upstream, "fallback");
});

test("serializeProxyRulesEditor removes empty routing sections while preserving sanitize defaults", () => {
  const initial = parseProxyRulesEditor(`{
    "dial_timeout": 5,
    "routes": [{"name":"old","priority":1,"action":{"upstream":"old"}}],
    "default_route": {"name":"default","action":{"upstream":"fallback"}}
  }`);

  const serialized = serializeProxyRulesEditor(initial.base, {
    exposeWAFDebugHeaders: false,
    emitUpstreamNameRequestHeader: false,
    responseHeaderSanitize: {
      mode: "auto",
      customRemove: [],
      customKeep: [],
      debugLog: false,
    },
    upstreams: [],
    backendPools: [],
    routes: [],
    defaultRoute: null,
  });
  const parsedJSON = JSON.parse(serialized) as Record<string, unknown>;

  assert.equal(parsedJSON.dial_timeout, 5);
  assert.equal(parsedJSON.routes, undefined);
  assert.equal(parsedJSON.default_route, undefined);
  assert.equal(parsedJSON.upstreams, undefined);
  assert.equal(parsedJSON.expose_waf_debug_headers, false);
  assert.equal(parsedJSON.emit_upstream_name_request_header, false);
  assert.deepEqual(parsedJSON.response_header_sanitize, { mode: "auto" });
});

test("parseProxyRulesEditor preserves dynamic discovery upstream settings", () => {
  const parsed = parseProxyRulesEditor(`{
    "upstreams": [
      {
        "name": "app",
        "enabled": true,
        "weight": 1,
        "discovery": {
          "type": "dns",
          "hostname": "app.default.svc.cluster.local",
          "scheme": "http",
          "port": 8080,
          "record_types": ["A", "AAAA"],
          "refresh_interval_sec": 10,
          "timeout_ms": 1000,
          "max_targets": 32
        }
      }
    ]
  }`);

  assert.equal(parsed.state.upstreams[0]?.discovery.enabled, true);
  assert.equal(parsed.state.upstreams[0]?.discovery.type, "dns");
  assert.equal(parsed.state.upstreams[0]?.discovery.hostname, "app.default.svc.cluster.local");

  const serialized = serializeProxyRulesEditor(parsed.base, parsed.state);
  const reparsed = JSON.parse(serialized) as { upstreams?: Array<{ discovery?: Record<string, unknown>; url?: string }> };
  assert.equal(reparsed.upstreams?.[0]?.url, undefined);
  assert.deepEqual(reparsed.upstreams?.[0]?.discovery?.record_types, ["A", "AAAA"]);
});

test("multiline helpers preserve list and header operations", () => {
  assert.deepEqual(multilineToStringList("api.example.com\n\n*.example.net\n"), ["api.example.com", "*.example.net"]);
  assert.equal(stringListToMultiline(["a", "b"]), "a\nb");
  assert.deepEqual(multilineToHeaderMap("X-Test: one\nX-Trace\nX-Mode:  blue"), {
    "X-Test": "one",
    "X-Trace": "",
    "X-Mode": "blue",
  });
  assert.equal(headerMapToMultiline({ "X-Test": "one", "X-Trace": "" }), "X-Test: one\nX-Trace: ");
  assert.deepEqual(multilineToQueryMap("lang=ja\npreview=1\nflag"), {
    lang: "ja",
    preview: "1",
    flag: "",
  });
  assert.equal(queryMapToMultiline({ lang: "ja", flag: "" }), "lang=ja\nflag");
});
