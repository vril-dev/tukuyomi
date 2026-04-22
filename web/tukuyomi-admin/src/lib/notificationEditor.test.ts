import assert from "node:assert/strict";
import test from "node:test";

import {
  countEnabledNotificationSinkDrafts,
  parseNotificationEditor,
  parseNotificationEditorDocument,
  serializeNotificationEditor,
} from "./notificationEditor.js";

test("parseNotificationEditor reads triggers and sinks", () => {
  const parsed = parseNotificationEditor(`{
    "enabled": true,
    "cooldown_seconds": 120,
    "sinks": [
      {
        "name": "primary",
        "type": "webhook",
        "enabled": true,
        "webhook_url": "https://hooks.example.invalid/tukuyomi",
        "timeout_seconds": 7,
        "headers": {
          "X-Test": "one"
        }
      },
      {
        "name": "email",
        "type": "email",
        "enabled": false,
        "smtp_address": "smtp.example.invalid:587",
        "from": "alerts@example.invalid",
        "to": ["secops@example.invalid"],
        "subject_prefix": "[ops]"
      }
    ],
    "upstream": {
      "enabled": true,
      "window_seconds": 60,
      "active_threshold": 3,
      "escalated_threshold": 10
    },
    "security": {
      "enabled": true,
      "window_seconds": 300,
      "active_threshold": 20,
      "escalated_threshold": 100,
      "sources": ["waf_block", "rate_limited"]
    }
  }`);

  assert.equal(parsed.enabled, true);
  assert.equal(parsed.cooldownSeconds, 120);
  assert.equal(parsed.sinks.length, 2);
  assert.equal(parsed.sinks[0]?.type, "webhook");
  assert.equal(parsed.sinks[0]?.headers[0]?.key, "X-Test");
  assert.equal(parsed.sinks[1]?.type, "email");
  assert.deepEqual(parsed.sinks[1]?.to, ["secops@example.invalid"]);
  assert.equal(parsed.upstream.activeThreshold, 3);
  assert.deepEqual(parsed.security.sources, ["waf_block", "rate_limited"]);
  assert.equal(countEnabledNotificationSinkDrafts(parsed), 1);
});

test("serializeNotificationEditor writes webhook and email sink fields", () => {
  const serialized = serializeNotificationEditor({
    enabled: false,
    cooldownSeconds: 900,
    upstream: {
      enabled: true,
      windowSeconds: 60,
      activeThreshold: 3,
      escalatedThreshold: 10,
    },
    security: {
      enabled: true,
      windowSeconds: 300,
      activeThreshold: 20,
      escalatedThreshold: 100,
      sources: ["waf_block", "waf_block", "rate_limited"],
    },
    sinks: [
      {
        name: "primary-webhook",
        type: "webhook",
        enabled: true,
        timeoutSeconds: 5,
        webhookURL: "https://hooks.example.invalid/tukuyomi",
        headers: [{ key: "X-Token", value: "secret" }],
        smtpAddress: "unused",
        smtpUsername: "unused",
        smtpPassword: "unused",
        from: "unused@example.invalid",
        to: ["unused@example.invalid"],
        subjectPrefix: "[unused]",
      },
      {
        name: "ops-email",
        type: "email",
        enabled: false,
        timeoutSeconds: 5,
        webhookURL: "https://unused.example.invalid",
        headers: [{ key: "X-Unused", value: "unused" }],
        smtpAddress: "smtp.example.invalid:587",
        smtpUsername: "alerts@example.invalid",
        smtpPassword: "change-me",
        from: "alerts@example.invalid",
        to: ["secops@example.invalid", "secops@example.invalid"],
        subjectPrefix: "[tukuyomi]",
      },
    ],
  });

  const parsed = JSON.parse(serialized) as Record<string, unknown>;
  const sinks = parsed.sinks as Array<Record<string, unknown>>;

  assert.equal(sinks[0]?.webhook_url, "https://hooks.example.invalid/tukuyomi");
  assert.deepEqual(sinks[0]?.headers, { "X-Token": "secret" });
  assert.equal("smtp_address" in sinks[0]!, false);
  assert.equal(sinks[1]?.smtp_address, "smtp.example.invalid:587");
  assert.deepEqual(sinks[1]?.to, ["secops@example.invalid"]);
  assert.equal("webhook_url" in sinks[1]!, false);
  assert.deepEqual((parsed.security as Record<string, unknown>).sources, ["waf_block", "rate_limited"]);
});

test("serializeNotificationEditor preserves unmodeled JSON fields", () => {
  const initial = parseNotificationEditorDocument(`{
    "custom_top": "keep",
    "enabled": false,
    "cooldown_seconds": 900,
    "sinks": [
      {
        "name": "primary",
        "type": "webhook",
        "enabled": false,
        "webhook_url": "https://hooks.example.invalid/tukuyomi",
        "timeout_seconds": 5,
        "custom_sink": "keep"
      }
    ],
    "upstream": {
      "enabled": true,
      "window_seconds": 60,
      "active_threshold": 3,
      "escalated_threshold": 10,
      "custom_trigger": "keep"
    },
    "security": {
      "enabled": true,
      "window_seconds": 300,
      "active_threshold": 20,
      "escalated_threshold": 100,
      "sources": ["waf_block"]
    }
  }`);

  const serialized = serializeNotificationEditor(
    initial.base,
    {
      ...initial.state,
      cooldownSeconds: 300,
      sinks: [
        {
          ...initial.state.sinks[0]!,
          enabled: true,
        },
      ],
    },
    initial.sinkBases,
  );

  const reparsed = JSON.parse(serialized) as Record<string, unknown>;
  assert.equal(reparsed.custom_top, "keep");
  assert.equal(((reparsed.upstream as Record<string, unknown>).custom_trigger), "keep");
  assert.equal(((reparsed.sinks as Array<Record<string, unknown>>)[0]).custom_sink, "keep");
  assert.equal(reparsed.cooldown_seconds, 300);
  assert.equal(((reparsed.sinks as Array<Record<string, unknown>>)[0]).enabled, true);
});
