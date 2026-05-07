export type SiteEntry = {
  name: string;
  enabled: boolean;
  hosts: string[];
  default_upstream: string;
};

export type SiteStatus = {
  name: string;
  enabled: boolean;
  hosts?: string[];
  default_upstream?: string;
  generated_route?: string;
};

export type SitesResponse = {
  etag?: string;
  raw?: string;
  sites?: {
    sites?: Array<SiteEntry & { tls?: unknown }>;
  };
  site_statuses?: SiteStatus[];
  rollback_depth?: number;
};

export function createEmptySite(index: number): SiteEntry {
  return {
    name: `site-${index}`,
    enabled: true,
    hosts: [],
    default_upstream: "",
  };
}

export function normalizeSites(sites: SiteEntry[]): SiteEntry[] {
  return sites.map((site) => ({
    name: site.name.trim(),
    enabled: !!site.enabled,
    hosts: site.hosts.map((host) => host.trim()).filter(Boolean),
    default_upstream: site.default_upstream.trim(),
  }));
}

export function sitesToRaw(sites: SiteEntry[]) {
  return JSON.stringify({ sites: normalizeSites(sites) }, null, 2);
}

export function parseSitesResponse(data?: SitesResponse): SiteEntry[] {
  if (data?.sites?.sites) {
    return data.sites.sites.map((site, index) => ({
      ...createEmptySite(index + 1),
      name: site.name ?? `site-${index + 1}`,
      enabled: site.enabled !== false,
      hosts: Array.isArray(site.hosts) ? site.hosts : [],
      default_upstream: site.default_upstream ?? "",
    }));
  }
  return [];
}

export function stringListToMultiline(values: string[]) {
  return values.join("\n");
}

export function multilineToStringList(value: string) {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}
