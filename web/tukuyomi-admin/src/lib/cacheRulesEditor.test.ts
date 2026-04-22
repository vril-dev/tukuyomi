import assert from "node:assert/strict";
import test from "node:test";

import {
  parseCacheRulesEditorDocument,
  serializeCacheRulesEditor,
  type CacheRulesEditorState,
} from "./cacheRulesEditor.js";

test("parseCacheRulesEditorDocument accepts canonical host-scoped JSON", () => {
  const parsed = parseCacheRulesEditorDocument(`{
    "default": {
      "rules": [
        {
          "kind": "allow",
          "match": { "type": "prefix", "value": "/assets/" },
          "ttl": 600
        }
      ]
    },
    "hosts": {
      "Admin.Example.com": {
        "rules": [
          {
            "kind": "deny",
            "match": { "type": "prefix", "value": "/" },
            "methods": ["GET"]
          }
        ]
      }
    }
  }`);

  assert.deepEqual(parsed.defaultRules, [
    {
      kind: "ALLOW",
      match: { type: "prefix", value: "/assets/" },
      methods: ["GET", "HEAD"],
      ttl: 600,
      vary: [],
    },
  ]);
  assert.deepEqual(parsed.hosts, [
    {
      host: "admin.example.com",
      rules: [
        {
          kind: "DENY",
          match: { type: "prefix", value: "/" },
          methods: ["GET"],
          ttl: 600,
          vary: [],
        },
      ],
    },
  ]);
});

test("parseCacheRulesEditorDocument accepts legacy line format", () => {
  const parsed = parseCacheRulesEditorDocument(`
    ALLOW prefix=/assets/ methods=GET,HEAD ttl=600 vary=Accept-Encoding
    DENY exact=/tukuyomi-api/ methods=GET ttl=0
  `);

  assert.equal(parsed.defaultRules.length, 2);
  assert.equal(parsed.defaultRules[0]?.match.value, "/assets/");
  assert.equal(parsed.defaultRules[1]?.kind, "DENY");
  assert.deepEqual(parsed.hosts, []);
});

test("serializeCacheRulesEditor emits canonical default and hosts", () => {
  const state: CacheRulesEditorState = {
    defaultRules: [
      {
        kind: "ALLOW",
        match: { type: "prefix", value: "/assets/" },
        methods: ["GET", "HEAD"],
        ttl: 600,
        vary: ["Accept-Encoding"],
      },
    ],
    hosts: [
      {
        host: "admin.example.com",
        rules: [
          {
            kind: "DENY",
            match: { type: "prefix", value: "/" },
            methods: ["GET"],
            ttl: 60,
            vary: [],
          },
        ],
      },
    ],
  };

  assert.equal(
    serializeCacheRulesEditor(state),
    `{
  "default": {
    "rules": [
      {
        "kind": "ALLOW",
        "match": {
          "type": "prefix",
          "value": "/assets/"
        },
        "methods": [
          "GET",
          "HEAD"
        ],
        "ttl": 600,
        "vary": [
          "Accept-Encoding"
        ]
      }
    ]
  },
  "hosts": {
    "admin.example.com": {
      "rules": [
        {
          "kind": "DENY",
          "match": {
            "type": "prefix",
            "value": "/"
          },
          "methods": [
            "GET"
          ],
          "ttl": 60,
          "vary": []
        }
      ]
    }
  }
}
`,
  );
});
