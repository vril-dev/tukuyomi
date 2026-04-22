import test from "node:test";
import assert from "node:assert/strict";
import { runFPTunerApply } from "./fPTunerApply.js";

test("runFPTunerApply refreshes audit after successful apply", async () => {
  const calls: string[] = [];

  await runFPTunerApply({
    applyRequest: async () => {
      calls.push("apply");
      return { simulated: true };
    },
    onSuccess: async (result) => {
      calls.push(`success:${String(result.simulated)}`);
    },
    onError: async (message) => {
      calls.push(`error:${message}`);
    },
    refreshAudit: async () => {
      calls.push("refresh");
    },
  });

  assert.deepEqual(calls, ["apply", "success:true", "refresh"]);
});

test("runFPTunerApply refreshes audit after failed apply and preserves error message", async () => {
  const calls: string[] = [];

  await runFPTunerApply({
    applyRequest: async () => {
      calls.push("apply");
      throw new Error("approval denied");
    },
    onSuccess: async () => {
      calls.push("success");
    },
    onError: async (message) => {
      calls.push(`error:${message}`);
    },
    refreshAudit: async () => {
      calls.push("refresh");
    },
  });

  assert.deepEqual(calls, ["apply", "error:approval denied", "refresh"]);
});
