import assert from "node:assert/strict";
import test from "node:test";
import { buildDiffLines, normalizeJSONForDiff } from "./jsonDiff.js";

test("normalizeJSONForDiff pretty prints valid JSON", () => {
  const out = normalizeJSONForDiff('{"b":2,"a":{"x":1}}');
  assert.equal(out.error, "");
  assert.equal(out.formatted, '{\n  "b": 2,\n  "a": {\n    "x": 1\n  }\n}');
});

test("normalizeJSONForDiff returns parse error for invalid JSON", () => {
  const out = normalizeJSONForDiff('{"a":');
  assert.notEqual(out.error, "");
  assert.equal(out.formatted, "");
});

test("buildDiffLines marks additions removals and context", () => {
  const lines = buildDiffLines(
    '{\n  "a": 1,\n  "b": 2\n}',
    '{\n  "a": 1,\n  "c": 3\n}'
  );

  assert.deepEqual(lines, [
    { kind: "context", text: "{" },
    { kind: "context", text: '  "a": 1,' },
    { kind: "remove", text: '  "b": 2' },
    { kind: "add", text: '  "c": 3' },
    { kind: "context", text: "}" },
  ]);
});
