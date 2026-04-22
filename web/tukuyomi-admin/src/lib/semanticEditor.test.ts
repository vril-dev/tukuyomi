import assert from "node:assert/strict";
import test from "node:test";

import {
  createDefaultSemanticEditorState,
  createDefaultSemanticScopeState,
  parseSemanticEditor,
  parseSemanticEditorDocument,
  serializeSemanticEditor,
} from "./semanticEditor.js";

test("parseSemanticEditor reads legacy provider and threshold settings", () => {
  const parsed = parseSemanticEditor(`{
    "enabled": true,
    "mode": "challenge",
    "provider": {
      "enabled": true,
      "name": "builtin_attack_family",
      "timeout_ms": 50
    },
    "exempt_path_prefixes": ["/healthz", "/status"],
    "log_threshold": 3,
    "challenge_threshold": 6,
    "block_threshold": 8,
    "max_inspect_body": 32768
  }`);

  assert.equal(parsed.enabled, true);
  assert.equal(parsed.mode, "challenge");
  assert.equal(parsed.providerEnabled, true);
  assert.equal(parsed.providerTimeoutMS, 50);
  assert.deepEqual(parsed.exemptPathPrefixes, ["/healthz", "/status"]);
  assert.equal(parsed.maxInspectBody, 32768);
  assert.deepEqual(parsed.hosts, []);
});

test("parseSemanticEditor supplies backend-aligned defaults", () => {
  const parsed = parseSemanticEditor(`{"enabled": true}`);
  const defaults = createDefaultSemanticEditorState();

  assert.equal(parsed.enabled, true);
  assert.equal(parsed.mode, defaults.mode);
  assert.equal(parsed.providerName, defaults.providerName);
  assert.equal(parsed.providerTimeoutMS, defaults.providerTimeoutMS);
  assert.equal(parsed.challengeThreshold, defaults.challengeThreshold);
  assert.equal(parsed.maxInspectBody, defaults.maxInspectBody);
  assert.deepEqual(parsed.hosts, []);
});

test("parseSemanticEditor reads canonical host scopes", () => {
  const parsed = parseSemanticEditor(`{
    "default": {
      "enabled": false,
      "mode": "off"
    },
    "hosts": {
      "Admin.EXAMPLE.com": {
        "enabled": true,
        "mode": "challenge",
        "provider": {
          "enabled": true,
          "timeout_ms": 75
        }
      }
    }
  }`);

  assert.equal(parsed.enabled, false);
  assert.equal(parsed.hosts[0]?.host, "admin.example.com");
  assert.equal(parsed.hosts[0]?.mode, "challenge");
  assert.equal(parsed.hosts[0]?.providerEnabled, true);
  assert.equal(parsed.hosts[0]?.providerTimeoutMS, 75);
});

test("serializeSemanticEditor writes canonical host-aware JSON", () => {
  const serialized = serializeSemanticEditor({
    ...createDefaultSemanticEditorState(),
    enabled: true,
    mode: "challenge",
    providerEnabled: true,
    providerName: "builtin_attack_family",
    providerTimeoutMS: 25,
    exemptPathPrefixes: ["/healthz"],
    hosts: [
      {
        host: "Admin.Example.com",
        ...createDefaultSemanticScopeState(),
        enabled: true,
        mode: "block",
        providerEnabled: true,
      },
    ],
  });

  const parsedJSON = JSON.parse(serialized) as Record<string, unknown>;
  const defaultScope = parsedJSON.default as Record<string, unknown>;
  const hosts = parsedJSON.hosts as Record<string, Record<string, unknown>>;
  assert.equal(parsedJSON.enabled, undefined);
  assert.equal(defaultScope.mode, "challenge");
  assert.deepEqual(defaultScope.exempt_path_prefixes, ["/healthz"]);
  assert.ok("admin.example.com" in hosts);
  assert.equal(hosts["admin.example.com"]?.mode, "block");
});

test("serializeSemanticEditor preserves unrelated top-level provider and host fields", () => {
  const initial = parseSemanticEditorDocument(`{
    "custom_top": "keep",
    "default": {
      "enabled": false,
      "mode": "off",
      "provider": {
        "enabled": false,
        "name": "builtin_attack_family",
        "timeout_ms": 25,
        "custom_provider": "keep"
      },
      "default_note": "keep"
    },
    "hosts": {
      "admin.example.com": {
        "enabled": true,
        "mode": "challenge",
        "host_note": "keep"
      }
    }
  }`);

  const serialized = serializeSemanticEditor(
    initial.base,
    {
      ...initial.state,
      enabled: true,
      mode: "block",
      providerEnabled: true,
      providerTimeoutMS: 75,
      hosts: initial.state.hosts.map((scope) => ({
        ...scope,
        exemptPathPrefixes: ["/internal/healthz"],
      })),
    },
    initial.defaultBase,
    initial.hostBases,
  );

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  assert.equal(reparsed.custom_top, "keep");
  assert.equal((reparsed.default as Record<string, unknown>).default_note, "keep");
  assert.equal(((reparsed.default as Record<string, unknown>).provider as Record<string, unknown>).custom_provider, "keep");
  assert.equal(((reparsed.default as Record<string, unknown>).provider as Record<string, unknown>).timeout_ms, 75);
  assert.equal(((reparsed.hosts as Record<string, Record<string, unknown>>)["admin.example.com"]).host_note, "keep");
  assert.deepEqual(((reparsed.hosts as Record<string, Record<string, unknown>>)["admin.example.com"]).exempt_path_prefixes, ["/internal/healthz"]);
});

test("serializeSemanticEditor preserves correct host extras after host removal", () => {
  const initial = parseSemanticEditorDocument(`{
    "default": {
      "enabled": true
    },
    "hosts": {
      "one.example.com": {
        "enabled": true,
        "note": "one"
      },
      "two.example.com": {
        "enabled": true,
        "note": "two"
      }
    }
  }`);

  const serialized = serializeSemanticEditor(
    initial.base,
    {
      ...initial.state,
      hosts: initial.state.hosts.filter((_, index) => index !== 0),
    },
    initial.defaultBase,
    initial.hostBases.filter((_, index) => index !== 0),
  );

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  const hosts = reparsed.hosts as Record<string, Record<string, unknown>>;
  assert.equal("one.example.com" in hosts, false);
  assert.equal(hosts["two.example.com"]?.note, "two");
});

test("serializeSemanticEditor rejects duplicate normalized host scopes", () => {
  assert.throws(
    () =>
      serializeSemanticEditor({
        ...createDefaultSemanticEditorState(),
        hosts: [
          {
            host: "Admin.Example.com",
            ...createDefaultSemanticScopeState(),
          },
          {
            host: "admin.example.com",
            ...createDefaultSemanticScopeState(),
          },
        ],
      }),
    /duplicate host scope/i,
  );
});

test("serializeSemanticEditor keeps explicit non-positive thresholds for validation", () => {
  const serialized = serializeSemanticEditor({
    ...createDefaultSemanticEditorState(),
    enabled: true,
    mode: "challenge",
    providerEnabled: true,
    providerName: "builtin_attack_family",
    providerTimeoutMS: 0,
    logThreshold: 0,
    challengeThreshold: -1,
    blockThreshold: -2,
    maxInspectBody: 0,
    hosts: [
      {
        host: "admin.example.com",
        ...createDefaultSemanticScopeState(),
        providerTimeoutMS: 0,
        logThreshold: 0,
        challengeThreshold: -1,
        blockThreshold: -2,
        maxInspectBody: 0,
      },
    ],
  });

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  assert.equal(((reparsed.default as Record<string, unknown>).provider as Record<string, unknown>).timeout_ms, 0);
  assert.equal((reparsed.default as Record<string, unknown>).log_threshold, 0);
  assert.equal((reparsed.default as Record<string, unknown>).challenge_threshold, -1);
  assert.equal((reparsed.default as Record<string, unknown>).block_threshold, -2);
  assert.equal((reparsed.default as Record<string, unknown>).max_inspect_body, 0);
  assert.equal((((reparsed.hosts as Record<string, Record<string, unknown>>)["admin.example.com"]).provider as Record<string, unknown>).timeout_ms, 0);
});
