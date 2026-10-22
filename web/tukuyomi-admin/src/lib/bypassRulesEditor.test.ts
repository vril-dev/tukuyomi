import assert from "node:assert/strict";
import test from "node:test";

import {
  bypassEntryHasRequestBodyOptions,
  countBypassEntries,
  parseBypassRulesEditor,
  parseBypassRulesEditorDocument,
  serializeBypassRulesEditor,
} from "./bypassRulesEditor.js";

test("parseBypassRulesEditor reads default and host-scoped entries", () => {
  const parsed = parseBypassRulesEditor(`{
    "default": {
      "entries": [
        { "path": "/assets/" }
      ]
    },
    "hosts": {
      "example.com": {
        "entries": [
          { "path": "/login", "extra_rule": "conf/rules/login.conf" }
        ]
      }
    }
  }`);

  assert.equal(parsed.defaultEntries[0]?.path, "/assets/");
  assert.equal(parsed.hosts[0]?.host, "example.com");
  assert.equal(parsed.hosts[0]?.entries[0]?.extraRule, "conf/rules/login.conf");
  assert.equal(countBypassEntries(parsed), 2);
});

test("parseBypassRulesEditor supports legacy line-based raw format", () => {
  const parsed = parseBypassRulesEditor(`
/assets/
/login conf/rules/login.conf
  `);

  assert.deepEqual(parsed.hosts, []);
  assert.equal(parsed.defaultEntries.length, 2);
  assert.equal(parsed.defaultEntries[1]?.path, "/login");
  assert.equal(parsed.defaultEntries[1]?.extraRule, "conf/rules/login.conf");
});

test("serializeBypassRulesEditor preserves unrelated fields", () => {
  const initial = parseBypassRulesEditorDocument(`{
    "custom_top": "keep",
    "default": {
      "entries": [
        {
          "path": "/assets/",
          "note": "keep-default"
        }
      ],
      "custom_default": "keep"
    },
    "hosts": {
      "example.com": {
        "entries": [
          {
            "path": "/login",
            "extra_rule": "conf/rules/login.conf",
            "note": "keep-entry"
          }
        ],
        "custom_host": "keep"
      }
    }
  }`);

  const serialized = serializeBypassRulesEditor(
    initial.base,
    {
      ...initial.state,
      defaultEntries: [{ path: "/static/", extraRule: "" }],
      hosts: [
        {
          host: "example.com",
          entries: [{ path: "/account/login", extraRule: "conf/rules/account.conf" }],
        },
      ],
    },
    initial.defaultEntryBases,
    initial.hostBases,
    initial.hostEntryBases,
  );

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  assert.equal(reparsed.custom_top, "keep");
  assert.equal((reparsed.default as Record<string, unknown>).custom_default, "keep");
  assert.equal((((reparsed.default as Record<string, unknown>).entries as Array<Record<string, unknown>>)[0]).note, "keep-default");
  assert.equal((((reparsed.hosts as Record<string, unknown>)["example.com"] as Record<string, unknown>).custom_host), "keep");
  assert.equal(
    (((((reparsed.hosts as Record<string, unknown>)["example.com"] as Record<string, unknown>).entries as Array<Record<string, unknown>>)[0]).note),
    "keep-entry",
  );
});

test("serializeBypassRulesEditor preserves host and entry extras after removal", () => {
  const initial = parseBypassRulesEditorDocument(`{
    "hosts": {
      "one.example.com": {
        "entries": [
          { "path": "/one", "tag": "first-entry" }
        ],
        "custom_host": "first-host"
      },
      "two.example.com": {
        "entries": [
          { "path": "/two", "tag": "second-entry" }
        ],
        "custom_host": "second-host"
      }
    }
  }`);

  const serialized = serializeBypassRulesEditor(
    initial.base,
    {
      ...initial.state,
      hosts: [initial.state.hosts[1]!],
    },
    initial.defaultEntryBases,
    [initial.hostBases[1]!],
    [initial.hostEntryBases[1]!],
  );

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  const hosts = reparsed.hosts as Record<string, unknown>;
  assert.deepEqual(Object.keys(hosts), ["two.example.com"]);
  assert.equal((hosts["two.example.com"] as Record<string, unknown>).custom_host, "second-host");
  assert.equal((((hosts["two.example.com"] as Record<string, unknown>).entries as Array<Record<string, unknown>>)[0]).tag, "second-entry");
});

test("serializeBypassRulesEditor rejects duplicate normalized host scopes", () => {
  assert.throws(
    () =>
      serializeBypassRulesEditor({
        defaultEntries: [],
        hosts: [
          {
            host: "Example.COM",
            entries: [{ path: "/one", extraRule: "" }],
          },
          {
            host: "example.com",
            entries: [{ path: "/two", extraRule: "" }],
          },
        ],
      }),
    /duplicate host scope: example\.com/,
  );
});

test("bypass editor round-trips request body options", () => {
  const parsed = parseBypassRulesEditorDocument(`{
    "default": {
      "entries": [
        { "path": "/upload/", "request_body": "SKIP" },
        { "path": "/api/", "request_body_inspect_limit_bytes": 65536 },
        { "path": "/assets/" }
      ]
    }
  }`);
  const entries = parsed.state.defaultEntries;
  assert.equal(entries[0]?.requestBody, "skip");
  assert.equal(entries[1]?.requestBodyInspectLimit, "65536");
  assert.equal(entries[2]?.requestBody, "inherit");
  assert.equal(bypassEntryHasRequestBodyOptions(entries[0]!), true);
  assert.equal(bypassEntryHasRequestBodyOptions(entries[1]!), true);
  assert.equal(bypassEntryHasRequestBodyOptions(entries[2]!), false);

  const out = JSON.parse(
    serializeBypassRulesEditor(parsed.base, parsed.state, parsed.defaultEntryBases, parsed.hostBases, parsed.hostEntryBases),
  );
  assert.deepEqual(out.default.entries, [
    { path: "/upload/", request_body: "skip" },
    { path: "/api/", request_body_inspect_limit_bytes: 65536 },
    { path: "/assets/" },
  ]);
});

test("bypass editor drops limits that cannot be saved", () => {
  const parsed = parseBypassRulesEditorDocument(`{
    "default": { "entries": [
      { "path": "/a/", "request_body_inspect_limit_bytes": 4096 },
      { "path": "/b/" }
    ] }
  }`);
  const state = parsed.state;
  state.defaultEntries[0] = { ...state.defaultEntries[0]!, requestBody: "skip" };
  state.defaultEntries[1] = { ...state.defaultEntries[1]!, requestBodyInspectLimit: "12kb" };
  const out = JSON.parse(
    serializeBypassRulesEditor(parsed.base, state, parsed.defaultEntryBases, parsed.hostBases, parsed.hostEntryBases),
  );
  assert.deepEqual(out.default.entries, [{ path: "/a/", request_body: "skip" }, { path: "/b/" }]);
});
