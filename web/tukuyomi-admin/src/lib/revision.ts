const DEFAULT_REVISION_LENGTH = 8;

export function shortRevision(value: string | null | undefined, length = DEFAULT_REVISION_LENGTH): string {
  const raw = String(value ?? "").trim();
  if (!raw) {
    return "-";
  }

  const sha = raw.match(/sha256:([a-f0-9]{8,})/i);
  if (sha?.[1]) {
    return sha[1].slice(0, Math.max(1, length)).toLowerCase();
  }

  const configVersion = raw.match(/^[^:]+:\d+:([a-f0-9]{12,})$/i);
  if (configVersion?.[1]) {
    return configVersion[1].slice(0, Math.max(1, length)).toLowerCase();
  }

  const trailingHex = raw.match(/([a-f0-9]{32,})$/i);
  if (trailingHex?.[1]) {
    return trailingHex[1].slice(0, Math.max(1, length)).toLowerCase();
  }

  const bareHex = raw.match(/^[a-f0-9]{12,}$/i);
  if (bareHex) {
    return raw.slice(0, Math.max(1, length)).toLowerCase();
  }

  return raw.length > length * 2 ? raw.slice(0, Math.max(1, length)) : raw;
}

export function isRevisionLabel(label: string | null | undefined): boolean {
  return /etag/i.test(String(label ?? ""));
}

export function revisionTagParts(label: string, value: string): { label: string; value: string; title?: string } {
  if (!isRevisionLabel(label)) {
    return { label, value };
  }
  const full = String(value ?? "").trim();
  return {
    label: "R",
    value: shortRevision(full),
    title: full ? `${label}: ${full}` : undefined,
  };
}

export function formatRevision(value: string | null | undefined): string {
  return `R: ${shortRevision(value)}`;
}

export function formatRevisionTransition(prev: string | null | undefined, next: string | null | undefined): string {
  return `${shortRevision(prev)} -> ${shortRevision(next)}`;
}
