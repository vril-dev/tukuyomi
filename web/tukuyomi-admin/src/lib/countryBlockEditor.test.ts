import assert from "node:assert/strict";
import test from "node:test";

import {
  collectCountryBlockCodes,
  multilineToCountryCodes,
  parseCountryBlockEditor,
  parseCountryBlockEditorDocument,
  serializeCountryBlockEditor,
} from "./countryBlockEditor.js";

test("parseCountryBlockEditor reads scoped JSON config", () => {
  const parsed = parseCountryBlockEditor(`{
    "default": {
      "blocked_countries": ["jp", "US", "JP"]
    },
    "hosts": {
      "admin.example.com": {
        "blocked_countries": ["unknown", "CN"]
      },
      "api.example.com": {
        "blocked_countries": ["SG"]
      }
    }
  }`);

  assert.deepEqual(parsed.defaultBlockedCountries, ["JP", "US"]);
  assert.deepEqual(parsed.hosts, [
    { host: "admin.example.com", blockedCountries: ["CN", "UNKNOWN"] },
    { host: "api.example.com", blockedCountries: ["SG"] },
  ]);
  assert.deepEqual(collectCountryBlockCodes(parsed), ["CN", "JP", "SG", "UNKNOWN", "US"]);
});

test("parseCountryBlockEditor accepts legacy line format", () => {
  const parsed = parseCountryBlockEditor(`
    JP
    us
    # comment
    UNKNOWN, CN
  `);

  assert.deepEqual(parsed, {
    defaultBlockedCountries: ["CN", "JP", "UNKNOWN", "US"],
    hosts: [],
  });
  assert.deepEqual(multilineToCountryCodes("JP\nCN CN\n# skip\nunknown"), ["CN", "JP", "UNKNOWN"]);
});

test("serializeCountryBlockEditor normalizes ordering", () => {
  const serialized = serializeCountryBlockEditor({
    defaultBlockedCountries: ["US", "jp"],
    hosts: [
      { host: "b.example.com", blockedCountries: ["UNKNOWN", "CN"] },
      { host: "a.example.com", blockedCountries: ["FR", "fr"] },
    ],
  });

  assert.equal(
    serialized,
    `{
  "default": {
    "blocked_countries": [
      "JP",
      "US"
    ]
  },
  "hosts": {
    "a.example.com": {
      "blocked_countries": [
        "FR"
      ]
    },
    "b.example.com": {
      "blocked_countries": [
        "CN",
        "UNKNOWN"
      ]
    }
  }
}
`,
  );
});

test("serializeCountryBlockEditor preserves unrelated JSON fields", () => {
  const initial = parseCountryBlockEditorDocument(`{
    "custom_top": "keep",
    "default": {
      "blocked_countries": ["US"],
      "mode": "strict"
    },
    "hosts": {
      "admin.example.com": {
        "blocked_countries": ["JP"],
        "note": "keep"
      }
    }
  }`);

  const serialized = serializeCountryBlockEditor(initial.base, {
    defaultBlockedCountries: ["CN"],
    hosts: [
      { host: "admin.example.com", blockedCountries: ["GB"] },
    ],
  }, initial.hostBases);

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  assert.equal(reparsed.custom_top, "keep");
  assert.deepEqual((reparsed.default as Record<string, unknown>).blocked_countries, ["CN"]);
  assert.equal((reparsed.default as Record<string, unknown>).mode, "strict");
  assert.deepEqual(
    ((reparsed.hosts as Record<string, Record<string, unknown>>)["admin.example.com"]).blocked_countries,
    ["GB"],
  );
  assert.equal(((reparsed.hosts as Record<string, Record<string, unknown>>)["admin.example.com"]).note, "keep");
});

test("serializeCountryBlockEditor preserves host extras across host rename", () => {
  const initial = parseCountryBlockEditorDocument(`{
    "hosts": {
      "admin.example.com": {
        "blocked_countries": ["JP"],
        "note": "keep"
      }
    }
  }`);

  const serialized = serializeCountryBlockEditor(initial.base, {
    defaultBlockedCountries: [],
    hosts: [{ host: "internal.example.com", blockedCountries: ["JP"] }],
  }, initial.hostBases);

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  assert.equal(
    ((reparsed.hosts as Record<string, Record<string, unknown>>)["internal.example.com"]).note,
    "keep",
  );
});

test("serializeCountryBlockEditor rejects duplicate normalized host scopes", () => {
  assert.throws(
    () =>
      serializeCountryBlockEditor({
        defaultBlockedCountries: [],
        hosts: [
          { host: "Example.COM", blockedCountries: ["US"] },
          { host: "example.com", blockedCountries: ["JP"] },
        ],
      }),
    /duplicate host scope: example\.com/,
  );
});
