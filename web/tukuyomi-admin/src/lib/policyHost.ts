export function normalizePolicyHostPattern(raw: string): string | null {
  const host = raw.trim().toLowerCase();
  if (!host || host.includes("/") || host.includes("*")) {
    return null;
  }

  let parsed: URL;
  try {
    parsed = new URL(`http://${host}`);
  } catch {
    return null;
  }

  const normalizedHost = parsed.hostname.replace(/^\[|\]$/g, "").trim().toLowerCase();
  if (!normalizedHost) {
    return null;
  }

  if (!parsed.port) {
    return normalizedHost;
  }

  const port = Number.parseInt(parsed.port, 10);
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    return null;
  }

  return normalizedHost.includes(":") ? `[${normalizedHost}]:${port}` : `${normalizedHost}:${port}`;
}

export function serializePolicyHostKey(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    return "";
  }
  return normalizePolicyHostPattern(trimmed) ?? trimmed;
}
