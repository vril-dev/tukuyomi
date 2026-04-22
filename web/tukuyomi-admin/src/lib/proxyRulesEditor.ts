type JSONRecord = Record<string, unknown>;

export type ProxyRouteHeaderOperations = {
  set: Record<string, string>;
  add: Record<string, string>;
  remove: string[];
};

export type ProxyRouteQueryOperations = {
  set: Record<string, string>;
  add: Record<string, string>;
  remove: string[];
  removePrefixes: string[];
};

export type ProxyRoutePathMatch = {
  type: "" | "exact" | "prefix" | "regex";
  value: string;
};

export type ProxyRoutePathRewrite = {
  prefix: string;
};

export type ProxyRouteAction = {
  upstream: string;
  backendPool: string;
  canaryUpstream: string;
  canaryWeightPercent: number;
  hashPolicy: "" | "client_ip" | "header" | "cookie" | "jwt_sub";
  hashKey: string;
  hostRewrite: string;
  pathRewrite: ProxyRoutePathRewrite | null;
  queryRewrite: ProxyRouteQueryOperations;
  requestHeaders: ProxyRouteHeaderOperations;
  responseHeaders: ProxyRouteHeaderOperations;
};

export type ProxyRoute = {
  name: string;
  enabled: boolean;
  priority: number;
  hosts: string[];
  path: ProxyRoutePathMatch | null;
  action: ProxyRouteAction;
};

export type ProxyUpstream = {
  name: string;
  url: string;
  weight: number;
  enabled: boolean;
  discovery: ProxyUpstreamDiscovery;
  http2Mode: "" | "default" | "force_attempt" | "h2c_prior_knowledge";
  tlsServerName: string;
  tlsCABundle: string;
  tlsMinVersion: string;
  tlsMaxVersion: string;
  tlsClientCert: string;
  tlsClientKey: string;
};

export type ProxyUpstreamDiscovery = {
  enabled: boolean;
  type: "" | "dns" | "dns_srv";
  hostname: string;
  scheme: "" | "http" | "https";
  port: number;
  recordTypes: string[];
  service: string;
  proto: string;
  name: string;
  refreshIntervalSec: number;
  timeoutMS: number;
  maxTargets: number;
};

export type ProxyBackendPool = {
  name: string;
  strategy: "" | "round_robin" | "least_conn";
  hashPolicy: "" | "client_ip" | "header" | "cookie" | "jwt_sub";
  hashKey: string;
  members: string[];
  stickySession: ProxyStickySession;
};

export type ProxyStickySession = {
  enabled: boolean;
  cookieName: string;
  ttlSeconds: number;
  path: string;
  domain: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "" | "lax" | "strict" | "none";
};

export type ProxyResponseHeaderSanitizeEditorState = {
  mode: "auto" | "manual" | "off";
  customRemove: string[];
  customKeep: string[];
  debugLog: boolean;
};

export type ProxyRulesRoutingEditorState = {
  exposeWAFDebugHeaders: boolean;
  emitUpstreamNameRequestHeader: boolean;
  responseHeaderSanitize: ProxyResponseHeaderSanitizeEditorState;
  upstreams: ProxyUpstream[];
  backendPools: ProxyBackendPool[];
  routes: ProxyRoute[];
  defaultRoute: ProxyRoute | null;
};

export type ParsedProxyRulesEditor = {
  base: JSONRecord;
  state: ProxyRulesRoutingEditorState;
};

export function createEmptyHeaderOperations(): ProxyRouteHeaderOperations {
  return {
    set: {},
    add: {},
    remove: [],
  };
}

export function createEmptyQueryOperations(): ProxyRouteQueryOperations {
  return {
    set: {},
    add: {},
    remove: [],
    removePrefixes: [],
  };
}

export function createEmptyRouteAction(): ProxyRouteAction {
  return {
    upstream: "",
    backendPool: "",
    canaryUpstream: "",
    canaryWeightPercent: 10,
    hashPolicy: "",
    hashKey: "",
    hostRewrite: "",
    pathRewrite: null,
    queryRewrite: createEmptyQueryOperations(),
    requestHeaders: createEmptyHeaderOperations(),
    responseHeaders: createEmptyHeaderOperations(),
  };
}

export function createEmptyRoute(seed = 1): ProxyRoute {
  return {
    name: `route-${seed}`,
    enabled: true,
    priority: seed * 10,
    hosts: [],
    path: null,
    action: createEmptyRouteAction(),
  };
}

export function createEmptyDefaultRoute(): ProxyRoute {
  return {
    name: "default",
    enabled: true,
    priority: 0,
    hosts: [],
    path: null,
    action: createEmptyRouteAction(),
  };
}

export function createEmptyUpstream(seed = 1): ProxyUpstream {
  return {
    name: `upstream-${seed}`,
    url: "",
    weight: 1,
    enabled: true,
    discovery: createEmptyUpstreamDiscovery(),
    http2Mode: "",
    tlsServerName: "",
    tlsCABundle: "",
    tlsMinVersion: "",
    tlsMaxVersion: "",
    tlsClientCert: "",
    tlsClientKey: "",
  };
}

export function createEmptyUpstreamDiscovery(): ProxyUpstreamDiscovery {
  return {
    enabled: false,
    type: "",
    hostname: "",
    scheme: "http",
    port: 80,
    recordTypes: ["A", "AAAA"],
    service: "http",
    proto: "tcp",
    name: "",
    refreshIntervalSec: 10,
    timeoutMS: 1000,
    maxTargets: 32,
  };
}

export function createEmptyBackendPool(seed = 1): ProxyBackendPool {
  const name = `pool-${seed}`;
  return {
    name,
    strategy: "",
    hashPolicy: "",
    hashKey: "",
    members: [],
    stickySession: createEmptyStickySession(name),
  };
}

export function createEmptyStickySession(poolName = ""): ProxyStickySession {
  return {
    enabled: false,
    cookieName: defaultStickyCookieName(poolName),
    ttlSeconds: 86400,
    path: "/",
    domain: "",
    secure: false,
    httpOnly: true,
    sameSite: "lax",
  };
}

export function stringListToMultiline(values: string[]): string {
  return values.join("\n");
}

export function multilineToStringList(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function headerMapToMultiline(values: Record<string, string>): string {
  return Object.entries(values)
    .map(([key, value]) => `${key}: ${value}`)
    .join("\n");
}

export function multilineToHeaderMap(value: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of value.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    const idx = line.indexOf(":");
    if (idx < 0) {
      out[line] = "";
      continue;
    }
    const key = line.slice(0, idx).trim();
    if (!key) {
      continue;
    }
    out[key] = line.slice(idx + 1).trimStart();
  }
  return out;
}

export function queryMapToMultiline(values: Record<string, string>): string {
  return Object.entries(values)
    .map(([key, value]) => (value ? `${key}=${value}` : key))
    .join("\n");
}

export function multilineToQueryMap(value: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of value.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    const idx = line.indexOf("=");
    if (idx < 0) {
      out[line] = "";
      continue;
    }
    const key = line.slice(0, idx).trim();
    if (!key) {
      continue;
    }
    out[key] = line.slice(idx + 1);
  }
  return out;
}

export function parseProxyRulesEditor(raw: string): ParsedProxyRulesEditor {
  const trimmed = raw.trim();
  const parsed = trimmed ? JSON.parse(trimmed) : {};
  if (!isRecord(parsed)) {
    throw new Error("proxy rules must be a JSON object");
  }
  const base = deepCloneRecord(parsed);
  return {
    base,
    state: {
      exposeWAFDebugHeaders: readBoolean(base.expose_waf_debug_headers, false),
      emitUpstreamNameRequestHeader: readBoolean(base.emit_upstream_name_request_header, false),
      responseHeaderSanitize: readResponseHeaderSanitize(base.response_header_sanitize),
      upstreams: readUpstreams(base.upstreams),
      backendPools: readBackendPools(base.backend_pools),
      routes: readRoutes(base.routes),
      defaultRoute: readDefaultRoute(base.default_route),
    },
  };
}

export function serializeProxyRulesEditor(base: JSONRecord, state: ProxyRulesRoutingEditorState): string {
  const next = deepCloneRecord(base);
  next.expose_waf_debug_headers = state.exposeWAFDebugHeaders;
  next.emit_upstream_name_request_header = state.emitUpstreamNameRequestHeader;

  const responseHeaderSanitize = writeResponseHeaderSanitize(state.responseHeaderSanitize);
  if (responseHeaderSanitize) {
    next.response_header_sanitize = responseHeaderSanitize;
  } else {
    delete next.response_header_sanitize;
  }

  const upstreams = state.upstreams
    .map(writeUpstream)
    .filter((item): item is JSONRecord => item !== null);
  if (upstreams.length > 0) {
    next.upstreams = upstreams;
  } else {
    delete next.upstreams;
  }

  const backendPools = state.backendPools
    .map(writeBackendPool)
    .filter((item): item is JSONRecord => item !== null);
  if (backendPools.length > 0) {
    next.backend_pools = backendPools;
  } else {
    delete next.backend_pools;
  }

  const routes = state.routes
    .map(writeRoute)
    .filter((item): item is JSONRecord => item !== null);
  if (routes.length > 0) {
    next.routes = routes;
  } else {
    delete next.routes;
  }

  const defaultRoute = state.defaultRoute ? writeDefaultRoute(state.defaultRoute) : null;
  if (defaultRoute) {
    next.default_route = defaultRoute;
  } else {
    delete next.default_route;
  }

  return `${JSON.stringify(next, null, 2)}\n`;
}

function readResponseHeaderSanitize(value: unknown): ProxyResponseHeaderSanitizeEditorState {
  const record = isRecord(value) ? value : null;
  const mode = readString(record?.mode);
  const normalizedMode = mode === "manual" || mode === "off" ? mode : "auto";
  return {
    mode: normalizedMode,
    customRemove: readStringList(record?.custom_remove),
    customKeep: readStringList(record?.custom_keep),
    debugLog: readBoolean(record?.debug_log, false),
  };
}

function writeResponseHeaderSanitize(value: ProxyResponseHeaderSanitizeEditorState): JSONRecord | null {
  const customRemove = value.customRemove.map((item) => item.trim()).filter(Boolean);
  const customKeep = value.customKeep.map((item) => item.trim()).filter(Boolean);
  if (value.mode === "auto" && customRemove.length === 0 && customKeep.length === 0 && !value.debugLog) {
    return { mode: "auto" };
  }
  const out: JSONRecord = {
    mode: value.mode,
    debug_log: value.debugLog,
  };
  if (customRemove.length > 0) {
    out.custom_remove = customRemove;
  }
  if (customKeep.length > 0) {
    out.custom_keep = customKeep;
  }
  return out;
}

function readUpstreams(value: unknown): ProxyUpstream[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((item, index) => {
      if (!isRecord(item)) {
        return null;
      }
      return {
        name: readString(item.name) || `upstream-${index + 1}`,
        url: readString(item.url),
        weight: normalizePositiveInt(item.weight, 1),
        enabled: readBoolean(item.enabled, true),
        discovery: readUpstreamDiscovery(item.discovery),
        http2Mode: readHTTP2Mode(item.http2_mode),
        tlsServerName: readString(isRecord(item.tls) ? item.tls.server_name : undefined),
        tlsCABundle: readString(isRecord(item.tls) ? item.tls.ca_bundle : undefined),
        tlsMinVersion: readString(isRecord(item.tls) ? item.tls.min_version : undefined),
        tlsMaxVersion: readString(isRecord(item.tls) ? item.tls.max_version : undefined),
        tlsClientCert: readString(isRecord(item.tls) ? item.tls.client_cert : undefined),
        tlsClientKey: readString(isRecord(item.tls) ? item.tls.client_key : undefined),
      } satisfies ProxyUpstream;
    })
    .filter((item): item is ProxyUpstream => item !== null);
}

function readBackendPools(value: unknown): ProxyBackendPool[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((item, index) => {
      if (!isRecord(item)) {
        return null;
      }
      return {
        name: readString(item.name) || `pool-${index + 1}`,
        strategy: readStrategy(item.strategy),
        hashPolicy: readHashPolicy(item.hash_policy),
        hashKey: readString(item.hash_key),
        members: readStringList(item.members),
        stickySession: readStickySession(item.sticky_session, readString(item.name) || `pool-${index + 1}`),
      } satisfies ProxyBackendPool;
    })
    .filter((item): item is ProxyBackendPool => item !== null);
}

function readRoutes(value: unknown): ProxyRoute[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((item, index) => readRoute(item, `route-${index + 1}`))
    .filter((item): item is ProxyRoute => item !== null);
}

function readDefaultRoute(value: unknown): ProxyRoute | null {
  if (!isRecord(value)) {
    return null;
  }
  return readRoute(value, "default");
}

function readRoute(value: unknown, fallbackName: string): ProxyRoute | null {
  if (!isRecord(value)) {
    return null;
  }
  const match = isRecord(value.match) ? value.match : null;
  const path = match && isRecord(match.path) ? match.path : null;
  const action = isRecord(value.action) ? value.action : null;
  return {
    name: readString(value.name) || fallbackName,
    enabled: readBoolean(value.enabled, true),
    priority: normalizeInt(value.priority, 0),
    hosts: readStringList(match?.hosts),
    path: readPathMatch(path),
    action: readRouteAction(action),
  };
}

function readPathMatch(value: JSONRecord | null): ProxyRoutePathMatch | null {
  if (!value) {
    return null;
  }
  const type = readString(value.type);
  const normalizedType = type === "exact" || type === "prefix" || type === "regex" ? type : "";
  const matchValue = readString(value.value);
  if (!normalizedType && !matchValue) {
    return null;
  }
  return {
    type: normalizedType,
    value: matchValue,
  };
}

function readRouteAction(value: JSONRecord | null): ProxyRouteAction {
  if (!value) {
    return createEmptyRouteAction();
  }
  return {
    upstream: readString(value.upstream),
    backendPool: readString(value.backend_pool),
    canaryUpstream: readString(value.canary_upstream),
    canaryWeightPercent: normalizeInt(value.canary_weight_percent, 10),
    hashPolicy: readHashPolicy(value.hash_policy),
    hashKey: readString(value.hash_key),
    hostRewrite: readString(value.host_rewrite),
    pathRewrite: readPathRewrite(value.path_rewrite),
    queryRewrite: readQueryOperations(value.query_rewrite),
    requestHeaders: readHeaderOperations(value.request_headers),
    responseHeaders: readHeaderOperations(value.response_headers),
  };
}

function readPathRewrite(value: unknown): ProxyRoutePathRewrite | null {
  if (!isRecord(value)) {
    return null;
  }
  const prefix = readString(value.prefix);
  if (!prefix) {
    return null;
  }
  return { prefix };
}

function readHeaderOperations(value: unknown): ProxyRouteHeaderOperations {
  if (!isRecord(value)) {
    return createEmptyHeaderOperations();
  }
  return {
    set: readStringMap(value.set),
    add: readStringMap(value.add),
    remove: readStringList(value.remove),
  };
}

function readQueryOperations(value: unknown): ProxyRouteQueryOperations {
  if (!isRecord(value)) {
    return createEmptyQueryOperations();
  }
  return {
    set: readStringMap(value.set),
    add: readStringMap(value.add),
    remove: readStringList(value.remove),
    removePrefixes: readStringList(value.remove_prefixes),
  };
}

function writeUpstream(upstream: ProxyUpstream): JSONRecord | null {
  if (!upstream.name.trim() && !upstream.url.trim() && !upstream.discovery.enabled) {
    return null;
  }
  const out: JSONRecord = {
    name: upstream.name.trim(),
    weight: normalizePositiveInt(upstream.weight, 1),
    enabled: upstream.enabled,
  };
  if (upstream.discovery.enabled) {
    const discovery = writeUpstreamDiscovery(upstream.discovery);
    if (discovery) {
      out.discovery = discovery;
    }
  } else {
    out.url = upstream.url.trim();
  }
  if (upstream.http2Mode) {
    out.http2_mode = upstream.http2Mode;
  }
  const tls = writeUpstreamTLS(upstream);
  if (tls) {
    out.tls = tls;
  }
  return out;
}

function readUpstreamDiscovery(value: unknown): ProxyUpstreamDiscovery {
  const record = isRecord(value) ? value : null;
  const type = readString(record?.type);
  const scheme = readString(record?.scheme);
  return {
    ...createEmptyUpstreamDiscovery(),
    enabled: Boolean(record && (type === "dns" || type === "dns_srv")),
    type: type === "dns" || type === "dns_srv" ? type : "",
    hostname: readString(record?.hostname),
    scheme: scheme === "https" ? "https" : "http",
    port: normalizePositiveInt(record?.port, 80),
    recordTypes: readStringList(record?.record_types).length > 0 ? readStringList(record?.record_types) : ["A", "AAAA"],
    service: readString(record?.service) || "http",
    proto: readString(record?.proto) || "tcp",
    name: readString(record?.name),
    refreshIntervalSec: normalizePositiveInt(record?.refresh_interval_sec, 10),
    timeoutMS: normalizePositiveInt(record?.timeout_ms, 1000),
    maxTargets: normalizePositiveInt(record?.max_targets, 32),
  };
}

function writeUpstreamDiscovery(discovery: ProxyUpstreamDiscovery): JSONRecord | null {
  if (!discovery.enabled || !discovery.type) {
    return null;
  }
  const out: JSONRecord = {
    type: discovery.type,
    scheme: discovery.scheme || "http",
    refresh_interval_sec: normalizePositiveInt(discovery.refreshIntervalSec, 10),
    timeout_ms: normalizePositiveInt(discovery.timeoutMS, 1000),
    max_targets: normalizePositiveInt(discovery.maxTargets, 32),
  };
  if (discovery.type === "dns") {
    out.hostname = discovery.hostname.trim();
    out.port = normalizePositiveInt(discovery.port, 80);
    const recordTypes = discovery.recordTypes.map((item) => item.trim().toUpperCase()).filter(Boolean);
    out.record_types = recordTypes.length > 0 ? recordTypes : ["A", "AAAA"];
  } else {
    out.service = discovery.service.trim() || "http";
    out.proto = discovery.proto.trim() || "tcp";
    out.name = discovery.name.trim();
  }
  return out;
}

function writeUpstreamTLS(upstream: ProxyUpstream): JSONRecord | null {
  const out: JSONRecord = {};
  if (upstream.tlsServerName.trim()) {
    out.server_name = upstream.tlsServerName.trim();
  }
  if (upstream.tlsCABundle.trim()) {
    out.ca_bundle = upstream.tlsCABundle.trim();
  }
  if (upstream.tlsMinVersion.trim()) {
    out.min_version = upstream.tlsMinVersion.trim();
  }
  if (upstream.tlsMaxVersion.trim()) {
    out.max_version = upstream.tlsMaxVersion.trim();
  }
  if (upstream.tlsClientCert.trim()) {
    out.client_cert = upstream.tlsClientCert.trim();
  }
  if (upstream.tlsClientKey.trim()) {
    out.client_key = upstream.tlsClientKey.trim();
  }
  return Object.keys(out).length > 0 ? out : null;
}

function writeBackendPool(pool: ProxyBackendPool): JSONRecord | null {
  const members = pool.members.map((item) => item.trim()).filter(Boolean);
  if (!pool.name.trim() && members.length === 0) {
    return null;
  }
  const out: JSONRecord = {
    name: pool.name.trim(),
    members,
  };
  if (pool.strategy) {
    out.strategy = pool.strategy;
  }
  if (pool.hashPolicy) {
    out.hash_policy = pool.hashPolicy;
  }
  if (pool.hashKey.trim()) {
    out.hash_key = pool.hashKey.trim();
  }
  const stickySession = writeStickySession(pool.stickySession);
  if (stickySession) {
    out.sticky_session = stickySession;
  }
  return out;
}

function readStickySession(value: unknown, poolName: string): ProxyStickySession {
  const record = isRecord(value) ? value : null;
  return {
    enabled: readBoolean(record?.enabled, false),
    cookieName: readString(record?.cookie_name) || defaultStickyCookieName(poolName),
    ttlSeconds: normalizePositiveInt(record?.ttl_seconds, 86400),
    path: readString(record?.path) || "/",
    domain: readString(record?.domain),
    secure: readBoolean(record?.secure, false),
    httpOnly: readBoolean(record?.http_only, true),
    sameSite: readSameSite(record?.same_site),
  };
}

function writeStickySession(value: ProxyStickySession): JSONRecord | null {
  if (!value.enabled) {
    return null;
  }
  const out: JSONRecord = {
    enabled: true,
    cookie_name: value.cookieName.trim(),
    ttl_seconds: normalizePositiveInt(value.ttlSeconds, 86400),
    path: value.path.trim() || "/",
    secure: value.secure,
    http_only: value.httpOnly,
    same_site: value.sameSite || "lax",
  };
  if (value.domain.trim()) {
    out.domain = value.domain.trim();
  }
  return out;
}

function writeRoute(route: ProxyRoute): JSONRecord | null {
  if (!route.name.trim() && !route.action.upstream.trim() && !route.action.backendPool.trim() && route.hosts.length === 0 && !route.path) {
    return null;
  }
  const out: JSONRecord = {
    name: route.name.trim(),
    priority: normalizeInt(route.priority, 0),
    action: writeRouteAction(route.action),
  };
  if (!route.enabled) {
    out.enabled = false;
  }
  const match = writeRouteMatch(route);
  if (match) {
    out.match = match;
  }
  return out;
}

function writeDefaultRoute(route: ProxyRoute): JSONRecord | null {
  const action = writeRouteAction(route.action);
  if (Object.keys(action).length === 0) {
    return null;
  }
  const out: JSONRecord = {
    name: route.name.trim() || "default",
    action,
  };
  if (!route.enabled) {
    out.enabled = false;
  }
  return out;
}

function writeRouteMatch(route: ProxyRoute): JSONRecord | null {
  const match: JSONRecord = {};
  const hosts = route.hosts.map((item) => item.trim()).filter(Boolean);
  if (hosts.length > 0) {
    match.hosts = hosts;
  }
  if (route.path && route.path.type && route.path.value.trim()) {
    match.path = {
      type: route.path.type,
      value: route.path.value.trim(),
    };
  }
  return Object.keys(match).length > 0 ? match : null;
}

function writeRouteAction(action: ProxyRouteAction): JSONRecord {
  const out: JSONRecord = {};
  if (action.upstream.trim()) {
    out.upstream = action.upstream.trim();
  }
  if (action.backendPool.trim()) {
    out.backend_pool = action.backendPool.trim();
  }
  if (action.canaryUpstream.trim()) {
    out.canary_upstream = action.canaryUpstream.trim();
    out.canary_weight_percent = normalizePositiveInt(action.canaryWeightPercent, 10);
  }
  if (action.hashPolicy) {
    out.hash_policy = action.hashPolicy;
  }
  if (action.hashKey.trim()) {
    out.hash_key = action.hashKey.trim();
  }
  if (action.hostRewrite.trim()) {
    out.host_rewrite = action.hostRewrite.trim();
  }
  if (action.pathRewrite && action.pathRewrite.prefix.trim()) {
    out.path_rewrite = { prefix: action.pathRewrite.prefix.trim() };
  }
  const queryRewrite = writeQueryOperations(action.queryRewrite);
  if (queryRewrite) {
    out.query_rewrite = queryRewrite;
  }
  const requestHeaders = writeHeaderOperations(action.requestHeaders);
  if (requestHeaders) {
    out.request_headers = requestHeaders;
  }
  const responseHeaders = writeHeaderOperations(action.responseHeaders);
  if (responseHeaders) {
    out.response_headers = responseHeaders;
  }
  return out;
}

function writeHeaderOperations(ops: ProxyRouteHeaderOperations): JSONRecord | null {
  const out: JSONRecord = {};
  const set = writeStringMap(ops.set);
  if (set) {
    out.set = set;
  }
  const add = writeStringMap(ops.add);
  if (add) {
    out.add = add;
  }
  const remove = ops.remove.map((item) => item.trim()).filter(Boolean);
  if (remove.length > 0) {
    out.remove = remove;
  }
  return Object.keys(out).length > 0 ? out : null;
}

function writeQueryOperations(ops: ProxyRouteQueryOperations): JSONRecord | null {
  const out: JSONRecord = {};
  const set = writeStringMap(ops.set);
  if (set) {
    out.set = set;
  }
  const add = writeStringMap(ops.add);
  if (add) {
    out.add = add;
  }
  const remove = ops.remove.map((item) => item.trim()).filter(Boolean);
  if (remove.length > 0) {
    out.remove = remove;
  }
  const removePrefixes = ops.removePrefixes.map((item) => item.trim()).filter(Boolean);
  if (removePrefixes.length > 0) {
    out.remove_prefixes = removePrefixes;
  }
  return Object.keys(out).length > 0 ? out : null;
}

function writeStringMap(value: Record<string, string>): JSONRecord | null {
  const out: JSONRecord = {};
  for (const [key, entry] of Object.entries(value)) {
    const nextKey = key.trim();
    if (!nextKey) {
      continue;
    }
    out[nextKey] = entry;
  }
  return Object.keys(out).length > 0 ? out : null;
}

function readString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function readBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function normalizeInt(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.trunc(value) : fallback;
}

function readHashPolicy(value: unknown): "" | "client_ip" | "header" | "cookie" | "jwt_sub" {
  switch (readString(value)) {
    case "client_ip":
    case "header":
    case "cookie":
    case "jwt_sub":
      return readString(value) as "" | "client_ip" | "header" | "cookie" | "jwt_sub";
    default:
      return "";
  }
}

function readStrategy(value: unknown): ProxyBackendPool["strategy"] {
  switch (readString(value)) {
    case "round_robin":
    case "least_conn":
      return readString(value) as ProxyBackendPool["strategy"];
    default:
      return "";
  }
}

function readSameSite(value: unknown): ProxyStickySession["sameSite"] {
  switch (readString(value).toLowerCase()) {
    case "lax":
    case "strict":
    case "none":
      return readString(value).toLowerCase() as ProxyStickySession["sameSite"];
    default:
      return "lax";
  }
}

export function defaultStickyCookieName(poolName: string): string {
  const suffix = poolName
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/_+$/g, "")
    .slice(0, 57);
  return suffix ? `tky_lb_${suffix}` : "tky_lb";
}

function readHTTP2Mode(value: unknown): ProxyUpstream["http2Mode"] {
  const normalized = readString(value).toLowerCase();
  if (normalized === "default" || normalized === "force_attempt" || normalized === "h2c_prior_knowledge") {
    return normalized;
  }
  return "";
}

function normalizePositiveInt(value: unknown, fallback: number): number {
  const normalized = normalizeInt(value, fallback);
  return normalized > 0 ? normalized : fallback;
}

function readStringList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((item) => (typeof item === "string" ? item : ""))
    .map((item) => item.trim())
    .filter(Boolean);
}

function readStringMap(value: unknown): Record<string, string> {
  if (!isRecord(value)) {
    return {};
  }
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry !== "string") {
      continue;
    }
    const nextKey = key.trim();
    if (!nextKey) {
      continue;
    }
    out[nextKey] = entry;
  }
  return out;
}

function isRecord(value: unknown): value is JSONRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepCloneRecord<T extends JSONRecord>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
