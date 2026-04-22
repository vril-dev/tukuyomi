import { getErrorMessage } from "./errors.js";

export type DiffLine = {
  kind: "context" | "add" | "remove";
  text: string;
};

export function normalizeJSONForDiff(raw: string): { formatted: string; error: string } {
  try {
    const parsed = JSON.parse(raw);
    return {
      formatted: JSON.stringify(parsed, null, 2),
      error: "",
    };
  } catch (error: unknown) {
    return {
      formatted: "",
      error: getErrorMessage(error, "invalid JSON"),
    };
  }
}

export function buildDiffLines(before: string, after: string): DiffLine[] {
  const left = before.split("\n");
  const right = after.split("\n");
  const dp = Array.from({ length: left.length + 1 }, () => Array<number>(right.length + 1).fill(0));

  for (let i = left.length - 1; i >= 0; i -= 1) {
    for (let j = right.length - 1; j >= 0; j -= 1) {
      if (left[i] === right[j]) {
        dp[i][j] = dp[i + 1][j + 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  const lines: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < left.length && j < right.length) {
    if (left[i] === right[j]) {
      lines.push({ kind: "context", text: left[i] });
      i += 1;
      j += 1;
      continue;
    }
    if (dp[i + 1][j] >= dp[i][j + 1]) {
      lines.push({ kind: "remove", text: left[i] });
      i += 1;
      continue;
    }
    lines.push({ kind: "add", text: right[j] });
    j += 1;
  }
  while (i < left.length) {
    lines.push({ kind: "remove", text: left[i] });
    i += 1;
  }
  while (j < right.length) {
    lines.push({ kind: "add", text: right[j] });
    j += 1;
  }
  return lines;
}
