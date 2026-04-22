import assert from "node:assert/strict";
import test from "node:test";

import { normalizePolicyHostPattern, serializePolicyHostKey } from "./policyHost.js";

test("normalizePolicyHostPattern matches backend-style host normalization", () => {
  assert.equal(normalizePolicyHostPattern("Example.COM"), "example.com");
  assert.equal(normalizePolicyHostPattern("Example.COM:8080"), "example.com:8080");
  assert.equal(normalizePolicyHostPattern("[2001:db8::1]:8443"), "[2001:db8::1]:8443");
});

test("normalizePolicyHostPattern rejects invalid patterns", () => {
  assert.equal(normalizePolicyHostPattern(""), null);
  assert.equal(normalizePolicyHostPattern("*.example.com"), null);
  assert.equal(normalizePolicyHostPattern("example.com/path"), null);
  assert.equal(normalizePolicyHostPattern("example.com:99999"), null);
});

test("serializePolicyHostKey falls back to trimmed raw host for invalid patterns", () => {
  assert.equal(serializePolicyHostKey("Example.COM"), "example.com");
  assert.equal(serializePolicyHostKey("bad host value"), "bad host value");
});
