export type CenterSettings = {
  apiBasePath: string;
  uiBasePath: string;
  experimentalAppDeployEnabled: boolean;
};

const DEFAULT_SETTINGS: CenterSettings = {
  apiBasePath: "/center-manage-api",
  uiBasePath: "/center-ui",
  experimentalAppDeployEnabled: true,
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
      experimentalAppDeployEnabled:
        typeof parsed.experimentalAppDeployEnabled === "boolean"
          ? parsed.experimentalAppDeployEnabled
          : DEFAULT_SETTINGS.experimentalAppDeployEnabled,
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

export function isExperimentalAppDeployEnabled() {
  return centerSettings.experimentalAppDeployEnabled;
}
