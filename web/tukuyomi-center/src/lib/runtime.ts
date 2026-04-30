export type CenterSettings = {
  apiBasePath: string;
  uiBasePath: string;
};

const DEFAULT_SETTINGS: CenterSettings = {
  apiBasePath: "/center-api",
  uiBasePath: "/center-ui",
};

function normalizeBasePath(value: unknown, fallback: string) {
  if (typeof value !== "string") {
    return fallback;
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.includes("*")) {
    return fallback;
  }
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

function readSettings(): CenterSettings {
  if (typeof document === "undefined") {
    return DEFAULT_SETTINGS;
  }
  const node = document.getElementById("center-settings");
  if (!node) {
    return DEFAULT_SETTINGS;
  }
  try {
    const parsed = JSON.parse(node.textContent || "{}") as Record<string, unknown>;
    return {
      apiBasePath: normalizeBasePath(parsed.apiBasePath, DEFAULT_SETTINGS.apiBasePath),
      uiBasePath: normalizeBasePath(parsed.uiBasePath, DEFAULT_SETTINGS.uiBasePath),
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export const centerSettings = readSettings();

export function getAPIBasePath() {
  return centerSettings.apiBasePath;
}

export function getUIBasePath() {
  return centerSettings.uiBasePath;
}
