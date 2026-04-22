import assert from "node:assert/strict";
import test from "node:test";

import {
  createDefaultIPReputationEditorState,
  createDefaultIPReputationScopeState,
  parseIPReputationEditor,
  parseIPReputationEditorDocument,
  serializeIPReputationEditor,
} from "./ipReputationEditor.js";

test("parseIPReputationEditor reads legacy config values", () => {
  const parsed = parseIPReputationEditor(`{
    "enabled": true,
    "feed_urls": ["https://feeds.example.test/abuse.txt"],
    "allowlist": ["127.0.0.1/32", "::1/128"],
    "blocklist": ["203.0.113.0/24"],
    "refresh_interval_sec": 1800,
    "request_timeout_sec": 10,
    "block_status_code": 451,
    "fail_open": false
  }`);

  assert.equal(parsed.enabled, true);
  assert.deepEqual(parsed.feedURLs, ["https://feeds.example.test/abuse.txt"]);
  assert.deepEqual(parsed.allowlist, ["127.0.0.1/32", "::1/128"]);
  assert.deepEqual(parsed.blocklist, ["203.0.113.0/24"]);
  assert.equal(parsed.refreshIntervalSec, 1800);
  assert.equal(parsed.requestTimeoutSec, 10);
  assert.equal(parsed.blockStatusCode, 451);
  assert.equal(parsed.failOpen, false);
  assert.deepEqual(parsed.hosts, []);
});

test("parseIPReputationEditor supplies backend-aligned defaults", () => {
  const parsed = parseIPReputationEditor(`{"enabled": true}`);
  const defaults = createDefaultIPReputationEditorState();

  assert.equal(parsed.enabled, true);
  assert.deepEqual(parsed.feedURLs, defaults.feedURLs);
  assert.equal(parsed.refreshIntervalSec, defaults.refreshIntervalSec);
  assert.equal(parsed.requestTimeoutSec, defaults.requestTimeoutSec);
  assert.equal(parsed.blockStatusCode, defaults.blockStatusCode);
  assert.equal(parsed.failOpen, defaults.failOpen);
  assert.deepEqual(parsed.hosts, []);
});

test("parseIPReputationEditor reads canonical host scopes", () => {
  const parsed = parseIPReputationEditor(`{
    "default": {
      "enabled": false,
      "block_status_code": 451
    },
    "hosts": {
      "Admin.EXAMPLE.com": {
        "enabled": true,
        "block_status_code": 452,
        "allowlist": ["203.0.113.10/32"]
      }
    }
  }`);

  assert.equal(parsed.enabled, false);
  assert.equal(parsed.hosts[0]?.host, "admin.example.com");
  assert.equal(parsed.hosts[0]?.enabled, true);
  assert.equal(parsed.hosts[0]?.blockStatusCode, 452);
  assert.deepEqual(parsed.hosts[0]?.allowlist, ["203.0.113.10/32"]);
});

test("serializeIPReputationEditor writes canonical host-aware JSON", () => {
  const serialized = serializeIPReputationEditor({
    ...createDefaultIPReputationEditorState(),
    enabled: true,
    feedURLs: ["https://feeds.example.test/abuse.txt"],
    allowlist: ["127.0.0.1/32"],
    blocklist: ["203.0.113.0/24"],
    refreshIntervalSec: 1800,
    requestTimeoutSec: 10,
    blockStatusCode: 451,
    failOpen: false,
    hosts: [
      {
        host: "Admin.Example.com",
        ...createDefaultIPReputationScopeState(),
        enabled: true,
        blockStatusCode: 452,
      },
    ],
  });

  const parsedJSON = JSON.parse(serialized) as Record<string, unknown>;
  const defaultScope = parsedJSON.default as Record<string, unknown>;
  const hosts = parsedJSON.hosts as Record<string, Record<string, unknown>>;
  assert.equal(parsedJSON.enabled, undefined);
  assert.deepEqual(defaultScope.feed_urls, ["https://feeds.example.test/abuse.txt"]);
  assert.equal(defaultScope.block_status_code, 451);
  assert.ok("admin.example.com" in hosts);
  assert.equal(hosts["admin.example.com"]?.block_status_code, 452);
});

test("serializeIPReputationEditor preserves unrelated default and host fields", () => {
  const initial = parseIPReputationEditorDocument(`{
    "custom_top": "keep",
    "default": {
      "enabled": true,
      "feed_urls": ["https://feeds.example.test/original.txt"],
      "block_status_code": 403,
      "default_note": "keep"
    },
    "hosts": {
      "admin.example.com": {
        "enabled": true,
        "block_status_code": 451,
        "host_note": "keep"
      }
    }
  }`);

  const serialized = serializeIPReputationEditor(
    initial.base,
    {
      ...initial.state,
      feedURLs: ["https://feeds.example.test/updated.txt"],
      hosts: initial.state.hosts.map((scope) => ({
        ...scope,
        allowlist: ["203.0.113.10/32"],
      })),
    },
    initial.defaultBase,
    initial.hostBases,
  );

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  assert.equal(reparsed.custom_top, "keep");
  assert.equal((reparsed.default as Record<string, unknown>).default_note, "keep");
  assert.deepEqual((reparsed.default as Record<string, unknown>).feed_urls, ["https://feeds.example.test/updated.txt"]);
  assert.equal(((reparsed.hosts as Record<string, Record<string, unknown>>)["admin.example.com"]).host_note, "keep");
  assert.deepEqual(((reparsed.hosts as Record<string, Record<string, unknown>>)["admin.example.com"]).allowlist, ["203.0.113.10/32"]);
});

test("serializeIPReputationEditor preserves correct host extras after host removal", () => {
  const initial = parseIPReputationEditorDocument(`{
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

  const serialized = serializeIPReputationEditor(
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

test("serializeIPReputationEditor rejects duplicate normalized host scopes", () => {
  assert.throws(
    () =>
      serializeIPReputationEditor({
        ...createDefaultIPReputationEditorState(),
        hosts: [
          {
            host: "Admin.Example.com",
            ...createDefaultIPReputationScopeState(),
          },
          {
            host: "admin.example.com",
            ...createDefaultIPReputationScopeState(),
          },
        ],
      }),
    /duplicate host scope/i,
  );
});

test("serializeIPReputationEditor keeps explicit non-positive intervals for validation", () => {
  const serialized = serializeIPReputationEditor({
    ...createDefaultIPReputationEditorState(),
    enabled: true,
    refreshIntervalSec: 0,
    requestTimeoutSec: -1,
    hosts: [
      {
        host: "admin.example.com",
        ...createDefaultIPReputationScopeState(),
        refreshIntervalSec: 0,
        requestTimeoutSec: -1,
      },
    ],
  });

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  assert.equal((reparsed.default as Record<string, unknown>).refresh_interval_sec, 0);
  assert.equal((reparsed.default as Record<string, unknown>).request_timeout_sec, -1);
  assert.equal(((reparsed.hosts as Record<string, Record<string, unknown>>)["admin.example.com"]).refresh_interval_sec, 0);
  assert.equal(((reparsed.hosts as Record<string, Record<string, unknown>>)["admin.example.com"]).request_timeout_sec, -1);
});
