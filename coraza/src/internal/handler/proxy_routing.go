package handler

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var proxyRouteHeaderNamePattern = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

const proxyObservabilityUpstreamNameHeader = "X-Tukuyomi-Upstream-Name"

var proxyRouteRestrictedHeaders = map[string]struct{}{
	"Connection":                         {},
	"Host":                               {},
	"Keep-Alive":                         {},
	"Proxy-Authenticate":                 {},
	"Proxy-Authorization":                {},
	"Proxy-Connection":                   {},
	"TE":                                 {},
	"Trailer":                            {},
	"Transfer-Encoding":                  {},
	"Upgrade":                            {},
	"X-Forwarded-For":                    {},
	"X-Forwarded-Host":                   {},
	"X-Forwarded-Proto":                  {},
	proxyObservabilityUpstreamNameHeader: {},
}

var proxyRouteRestrictedResponseHeaders = map[string]struct{}{
	"Connection":        {},
	"Content-Length":    {},
	"Keep-Alive":        {},
	"Proxy-Connection":  {},
	"Set-Cookie":        {},
	"TE":                {},
	"Trailer":           {},
	"Transfer-Encoding": {},
	"Upgrade":           {},
}

type ProxyRoute struct {
	Name      string           `json:"name,omitempty"`
	Enabled   *bool            `json:"enabled,omitempty"`
	Priority  int              `json:"priority"`
	Match     ProxyRouteMatch  `json:"match,omitempty"`
	Action    ProxyRouteAction `json:"action"`
	Generated bool             `json:"-"`
}

type ProxyRouteMatch struct {
	Hosts []string             `json:"hosts,omitempty"`
	Path  *ProxyRoutePathMatch `json:"path,omitempty"`
}

type ProxyRoutePathMatch struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	compiled *regexp.Regexp
}

type ProxyRouteAction struct {
	Upstream                string                      `json:"upstream,omitempty"`
	BackendPool             string                      `json:"backend_pool,omitempty"`
	UpstreamHTTP2Mode       string                      `json:"upstream_http2_mode,omitempty"`
	CanaryUpstream          string                      `json:"canary_upstream,omitempty"`
	CanaryUpstreamHTTP2Mode string                      `json:"canary_upstream_http2_mode,omitempty"`
	CanaryWeightPct         int                         `json:"canary_weight_percent,omitempty"`
	HashPolicy              string                      `json:"hash_policy,omitempty"`
	HashKey                 string                      `json:"hash_key,omitempty"`
	HostRewrite             string                      `json:"host_rewrite,omitempty"`
	PathRewrite             *ProxyRoutePathRewrite      `json:"path_rewrite,omitempty"`
	QueryRewrite            *ProxyRouteQueryOperations  `json:"query_rewrite,omitempty"`
	RequestHeaders          *ProxyRouteHeaderOperations `json:"request_headers,omitempty"`
	ResponseHeaders         *ProxyRouteHeaderOperations `json:"response_headers,omitempty"`
}

type ProxyBackendPool struct {
	Name          string                   `json:"name,omitempty"`
	Strategy      string                   `json:"strategy,omitempty"`
	HashPolicy    string                   `json:"hash_policy,omitempty"`
	HashKey       string                   `json:"hash_key,omitempty"`
	Members       []string                 `json:"members,omitempty"`
	StickySession ProxyStickySessionConfig `json:"sticky_session,omitempty"`
}

type ProxyStickySessionConfig struct {
	Enabled    bool   `json:"enabled"`
	CookieName string `json:"cookie_name,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Path       string `json:"path,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Secure     bool   `json:"secure,omitempty"`
	HTTPOnly   *bool  `json:"http_only,omitempty"`
	SameSite   string `json:"same_site,omitempty"`
}

type ProxyRoutePathRewrite struct {
	Prefix string `json:"prefix"`
}

type ProxyRouteHeaderOperations struct {
	Set    map[string]string `json:"set,omitempty"`
	Add    map[string]string `json:"add,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

type ProxyRouteQueryOperations struct {
	Set            map[string]string `json:"set,omitempty"`
	Add            map[string]string `json:"add,omitempty"`
	Remove         []string          `json:"remove,omitempty"`
	RemovePrefixes []string          `json:"remove_prefixes,omitempty"`
}

type ProxyDefaultRoute struct {
	Name    string           `json:"name,omitempty"`
	Enabled *bool            `json:"enabled,omitempty"`
	Action  ProxyRouteAction `json:"action"`
}

type proxyRouteResolutionSource string

const (
	proxyRouteResolutionUpstream proxyRouteResolutionSource = "upstream"
	proxyRouteResolutionRoute    proxyRouteResolutionSource = "route"
	proxyRouteResolutionDefault  proxyRouteResolutionSource = "default_route"
)

type proxyRouteDecision struct {
	Classification       proxyRouteClassification
	TransportSelection   proxyRouteTransportSelection
	Source               proxyRouteResolutionSource
	RouteName            string
	OriginalHost         string
	OriginalPath         string
	OriginalQuery        string
	RewrittenHost        string
	RewrittenPath        string
	RewrittenRawPath     string
	RewrittenQuery       string
	SelectedUpstream     string
	SelectedUpstreamURL  string
	SelectedHTTP2Mode    string
	SelectedTransportKey string
	Target               *url.URL
	HealthKey            string
	OrderedTargets       []proxyRouteTargetCandidate
	RetryPolicy          proxyRetryPolicy
	StickySession        ProxyStickySessionConfig
	StickySessionHit     bool
	StickyTargetID       string
	RequestHeaderOps     ProxyRouteHeaderOperations
	ResponseHeaderOps    ProxyRouteHeaderOperations
	LogSelection         bool
}

type proxyRouteClassification struct {
	Source            proxyRouteResolutionSource
	RouteName         string
	OriginalHost      string
	OriginalPath      string
	OriginalQuery     string
	RewrittenPath     string
	RewrittenRawPath  string
	RewrittenQuery    string
	RewrittenHost     string
	TargetCandidates  []proxyRouteTargetCandidate
	TargetSelection   proxyRouteTargetSelectionOptions
	RetryPolicy       proxyRetryPolicy
	StickySession     ProxyStickySessionConfig
	RequestHeaderOps  ProxyRouteHeaderOperations
	ResponseHeaderOps ProxyRouteHeaderOperations
	LogSelection      bool
}

type proxyRouteTransportSelection struct {
	SelectedUpstream     string
	SelectedUpstreamURL  string
	SelectedHTTP2Mode    string
	SelectedTransportKey string
	Target               *url.URL
	HealthKey            string
	OrderedTargets       []proxyRouteTargetCandidate
	RewrittenHost        string
	StickySession        ProxyStickySessionConfig
	StickySessionHit     bool
	StickyTargetID       string
}

type proxyRouteDryRunResult struct {
	Source              string `json:"source"`
	RouteName           string `json:"route_name,omitempty"`
	OriginalHost        string `json:"original_host,omitempty"`
	OriginalPath        string `json:"original_path,omitempty"`
	OriginalQuery       string `json:"original_query,omitempty"`
	RewrittenHost       string `json:"rewritten_host,omitempty"`
	RewrittenPath       string `json:"rewritten_path,omitempty"`
	RewrittenQuery      string `json:"rewritten_query,omitempty"`
	SelectedUpstream    string `json:"selected_upstream,omitempty"`
	SelectedUpstreamURL string `json:"selected_upstream_url,omitempty"`
	SelectedHTTP2Mode   string `json:"selected_http2_mode,omitempty"`
	FinalURL            string `json:"final_url,omitempty"`
}

func normalizeProxyRoutes(in []ProxyRoute) []ProxyRoute {
	if len(in) == 0 {
		return nil
	}
	out := make([]ProxyRoute, 0, len(in))
	for i, route := range in {
		next := route
		next.Name = strings.TrimSpace(next.Name)
		if next.Name == "" {
			next.Name = fmt.Sprintf("route-%d", i+1)
		}
		next.Match.Hosts = normalizeProxyRouteHosts(next.Match.Hosts)
		next.Match.Path = normalizeProxyRoutePathMatch(next.Match.Path)
		next.Action = normalizeProxyRouteAction(next.Action)
		out = append(out, next)
	}
	return out
}

func proxyRouteOrder(cfg ProxyRulesConfig) []int {
	if len(cfg.routeOrder) == len(cfg.Routes) {
		return cfg.routeOrder
	}
	return sortedProxyRouteIndexes(cfg.Routes)
}

func normalizeProxyDefaultRoute(in *ProxyDefaultRoute) *ProxyDefaultRoute {
	if in == nil {
		return nil
	}
	out := *in
	out.Name = strings.TrimSpace(out.Name)
	if out.Name == "" {
		out.Name = "default"
	}
	out.Action = normalizeProxyRouteAction(out.Action)
	return &out
}

func normalizeProxyRouteAction(in ProxyRouteAction) ProxyRouteAction {
	out := in
	out.Upstream = strings.TrimSpace(out.Upstream)
	out.BackendPool = strings.TrimSpace(out.BackendPool)
	out.UpstreamHTTP2Mode = normalizeProxyHTTP2Mode(out.UpstreamHTTP2Mode)
	out.CanaryUpstream = strings.TrimSpace(out.CanaryUpstream)
	out.CanaryUpstreamHTTP2Mode = normalizeProxyHTTP2Mode(out.CanaryUpstreamHTTP2Mode)
	out.HashPolicy = normalizeProxyHashPolicy(out.HashPolicy)
	out.HashKey = strings.TrimSpace(out.HashKey)
	out.HostRewrite = strings.TrimSpace(out.HostRewrite)
	out.PathRewrite = normalizeProxyRoutePathRewrite(out.PathRewrite)
	out.QueryRewrite = normalizeProxyRouteQueryOperations(out.QueryRewrite)
	out.RequestHeaders = normalizeProxyRouteHeaderOperations(out.RequestHeaders)
	out.ResponseHeaders = normalizeProxyRouteHeaderOperations(out.ResponseHeaders)
	return out
}

func normalizeProxyBackendPools(in []ProxyBackendPool) []ProxyBackendPool {
	if len(in) == 0 {
		return nil
	}
	out := make([]ProxyBackendPool, 0, len(in))
	for i, pool := range in {
		next := pool
		next.Name = strings.TrimSpace(next.Name)
		if next.Name == "" {
			next.Name = fmt.Sprintf("pool-%d", i+1)
		}
		next.Strategy = normalizeProxyLoadBalancingStrategy(next.Strategy)
		next.HashPolicy = normalizeProxyHashPolicy(next.HashPolicy)
		next.HashKey = strings.TrimSpace(next.HashKey)
		next.Members = normalizeProxyBackendPoolMembers(next.Members)
		next.StickySession = normalizeProxyStickySessionConfig(next.StickySession, next.Name)
		out = append(out, next)
	}
	return out
}

func normalizeProxyBackendPoolMembers(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		next := strings.TrimSpace(raw)
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeProxyRoutePathMatch(in *ProxyRoutePathMatch) *ProxyRoutePathMatch {
	if in == nil {
		return nil
	}
	out := *in
	out.Type = strings.ToLower(strings.TrimSpace(out.Type))
	switch out.Type {
	case "prefix":
		out.Value = normalizeProxyRoutePrefix(out.Value)
	case "exact":
		out.Value = normalizeProxyRouteExactPath(out.Value)
	case "regex":
		out.Value = strings.TrimSpace(out.Value)
	default:
		out.Value = strings.TrimSpace(out.Value)
	}
	out.compiled = nil
	return &out
}

func normalizeProxyRoutePathRewrite(in *ProxyRoutePathRewrite) *ProxyRoutePathRewrite {
	if in == nil {
		return nil
	}
	out := *in
	out.Prefix = normalizeProxyRoutePrefix(out.Prefix)
	return &out
}

func normalizeProxyRouteHeaderOperations(in *ProxyRouteHeaderOperations) *ProxyRouteHeaderOperations {
	if in == nil {
		return nil
	}
	out := &ProxyRouteHeaderOperations{
		Set: make(map[string]string, len(in.Set)),
		Add: make(map[string]string, len(in.Add)),
	}
	for name, value := range in.Set {
		out.Set[canonicalProxyRouteHeaderName(name)] = value
	}
	for name, value := range in.Add {
		out.Add[canonicalProxyRouteHeaderName(name)] = value
	}
	if len(out.Set) == 0 {
		out.Set = nil
	}
	if len(out.Add) == 0 {
		out.Add = nil
	}
	if len(in.Remove) > 0 {
		out.Remove = make([]string, 0, len(in.Remove))
		seen := map[string]struct{}{}
		for _, name := range in.Remove {
			next := canonicalProxyRouteHeaderName(name)
			if next == "" {
				continue
			}
			if _, ok := seen[next]; ok {
				continue
			}
			seen[next] = struct{}{}
			out.Remove = append(out.Remove, next)
		}
		if len(out.Remove) == 0 {
			out.Remove = nil
		}
	}
	if out.Set == nil && out.Add == nil && len(out.Remove) == 0 {
		return nil
	}
	return out
}

func normalizeProxyRouteQueryOperations(in *ProxyRouteQueryOperations) *ProxyRouteQueryOperations {
	if in == nil {
		return nil
	}
	out := &ProxyRouteQueryOperations{
		Set: make(map[string]string, len(in.Set)),
		Add: make(map[string]string, len(in.Add)),
	}
	for key, value := range in.Set {
		nextKey := strings.TrimSpace(key)
		if nextKey == "" {
			continue
		}
		out.Set[nextKey] = value
	}
	for key, value := range in.Add {
		nextKey := strings.TrimSpace(key)
		if nextKey == "" {
			continue
		}
		out.Add[nextKey] = value
	}
	if len(out.Set) == 0 {
		out.Set = nil
	}
	if len(out.Add) == 0 {
		out.Add = nil
	}
	if len(in.Remove) > 0 {
		out.Remove = make([]string, 0, len(in.Remove))
		seen := map[string]struct{}{}
		for _, key := range in.Remove {
			nextKey := strings.TrimSpace(key)
			if nextKey == "" {
				continue
			}
			if _, ok := seen[nextKey]; ok {
				continue
			}
			seen[nextKey] = struct{}{}
			out.Remove = append(out.Remove, nextKey)
		}
		if len(out.Remove) == 0 {
			out.Remove = nil
		}
	}
	if len(in.RemovePrefixes) > 0 {
		out.RemovePrefixes = make([]string, 0, len(in.RemovePrefixes))
		seen := map[string]struct{}{}
		for _, prefix := range in.RemovePrefixes {
			nextPrefix := strings.TrimSpace(prefix)
			if nextPrefix == "" {
				continue
			}
			if _, ok := seen[nextPrefix]; ok {
				continue
			}
			seen[nextPrefix] = struct{}{}
			out.RemovePrefixes = append(out.RemovePrefixes, nextPrefix)
		}
		if len(out.RemovePrefixes) == 0 {
			out.RemovePrefixes = nil
		}
	}
	if out.Set == nil && out.Add == nil && len(out.Remove) == 0 && len(out.RemovePrefixes) == 0 {
		return nil
	}
	return out
}

func normalizeProxyRouteHosts(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		next := normalizeProxyHostPattern(raw)
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeProxyRouteExactPath(v string) string {
	out := strings.TrimSpace(v)
	if out == "" {
		return ""
	}
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return out
}

func normalizeProxyRoutePrefix(v string) string {
	out := normalizeProxyRouteExactPath(v)
	if out == "" || out == "/" {
		return "/"
	}
	return strings.TrimRight(out, "/")
}

func canonicalProxyRouteHeaderName(v string) string {
	return textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(v))
}

func normalizeProxyHostPattern(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if strings.HasPrefix(v, "*.") {
		return "*." + strings.TrimSuffix(strings.TrimPrefix(v, "*."), ".")
	}
	return strings.TrimSuffix(v, ".")
}

func proxyRouteEnabled(v *bool) bool {
	return v == nil || *v
}

func validateProxyRoutes(cfg ProxyRulesConfig) error {
	namedUpstreams := map[string]ProxyUpstream{}
	nameCounts := map[string]int{}
	for i, upstream := range cfg.Upstreams {
		if upstream.Weight <= 0 {
			return fmt.Errorf("upstreams[%d].weight must be > 0", i)
		}
		nameCounts[upstream.Name]++
		namedUpstreams[upstream.Name] = upstream
	}
	backendPools := map[string]ProxyBackendPool{}
	backendPoolCounts := map[string]int{}
	for i, pool := range cfg.BackendPools {
		backendPoolCounts[pool.Name]++
		backendPools[pool.Name] = pool
		if err := validateProxyBackendPool(pool, namedUpstreams, nameCounts, backendPoolCounts, fmt.Sprintf("backend_pools[%d]", i)); err != nil {
			return err
		}
	}

	for i, route := range cfg.Routes {
		if err := validateProxyRouteMatch(route.Match, fmt.Sprintf("routes[%d].match", i)); err != nil {
			return err
		}
		if err := validateProxyRouteAction(route.Action, cfg, namedUpstreams, nameCounts, backendPools, backendPoolCounts, fmt.Sprintf("routes[%d].action", i)); err != nil {
			return err
		}
		if route.Action.PathRewrite != nil && route.Match.Path == nil {
			return fmt.Errorf("routes[%d].action.path_rewrite requires match.path", i)
		}
		if route.Action.PathRewrite != nil && route.Match.Path != nil && route.Match.Path.Type == "regex" {
			return fmt.Errorf("routes[%d].action.path_rewrite does not support regex path matches", i)
		}
	}
	if cfg.DefaultRoute != nil && proxyRouteEnabled(cfg.DefaultRoute.Enabled) {
		if err := validateProxyRouteAction(cfg.DefaultRoute.Action, cfg, namedUpstreams, nameCounts, backendPools, backendPoolCounts, "default_route.action"); err != nil {
			return err
		}
	}

	return nil
}

func validateProxyBackendPool(pool ProxyBackendPool, namedUpstreams map[string]ProxyUpstream, upstreamNameCounts map[string]int, poolNameCounts map[string]int, field string) error {
	if strings.TrimSpace(pool.Name) == "" {
		return fmt.Errorf("%s.name is required", field)
	}
	if poolNameCounts[pool.Name] > 1 {
		return fmt.Errorf("%s.name duplicates backend pool %q", field, pool.Name)
	}
	if len(pool.Members) == 0 {
		return fmt.Errorf("%s.members must contain at least one upstream name", field)
	}
	if err := validateProxyBackendPoolStrategy(pool.Strategy, field+".strategy"); err != nil {
		return err
	}
	if err := validateProxyHashPolicy(pool.HashPolicy, pool.HashKey, field+".hash_policy"); err != nil {
		return err
	}
	if err := validateProxyStickySessionConfig(pool.StickySession, field+".sticky_session"); err != nil {
		return err
	}
	for i, member := range pool.Members {
		upstream, ok := namedUpstreams[member]
		if !ok {
			return fmt.Errorf("%s.members[%d] must reference a configured upstream name", field, i)
		}
		if !proxyUpstreamAllowedInBackendPool(upstream) {
			return fmt.Errorf("%s.members[%d] must reference a configured upstream name", field, i)
		}
		if upstreamNameCounts[member] > 1 {
			return fmt.Errorf("%s.members[%d] references duplicated upstream name %q", field, i, member)
		}
		if !upstream.Enabled {
			return fmt.Errorf("%s.members[%d] references disabled upstream %q", field, i, member)
		}
	}
	return nil
}

func proxyUpstreamAllowedInBackendPool(upstream ProxyUpstream) bool {
	if proxyUpstreamIsDirect(upstream) {
		return true
	}
	return proxyUpstreamIsVhostManaged(upstream) && upstream.GeneratedKind == proxyUpstreamGeneratedKindVhostLinkedTarget
}

func proxyUpstreamAllowedAsRouteTarget(upstream ProxyUpstream) bool {
	return proxyUpstreamAllowedInBackendPool(upstream)
}

func validateProxyBackendPoolStrategy(strategy string, field string) error {
	switch normalizeProxyLoadBalancingStrategy(strategy) {
	case "round_robin", "least_conn":
		return nil
	default:
		return fmt.Errorf("%s must be one of round_robin|least_conn", field)
	}
}

const (
	defaultProxyStickySessionTTLSeconds = 86400
	maxProxyStickySessionTTLSeconds     = 30 * 24 * 60 * 60
)

func normalizeProxyStickySessionConfig(in ProxyStickySessionConfig, poolName string) ProxyStickySessionConfig {
	out := in
	out.CookieName = strings.TrimSpace(out.CookieName)
	if out.Enabled && out.CookieName == "" {
		out.CookieName = defaultProxyStickyCookieName(poolName)
	}
	if out.Enabled && out.TTLSeconds <= 0 {
		out.TTLSeconds = defaultProxyStickySessionTTLSeconds
	}
	out.Path = strings.TrimSpace(out.Path)
	if out.Enabled && out.Path == "" {
		out.Path = "/"
	}
	out.Domain = strings.ToLower(strings.TrimSpace(out.Domain))
	out.SameSite = strings.ToLower(strings.TrimSpace(out.SameSite))
	if out.Enabled && out.SameSite == "" {
		out.SameSite = "lax"
	}
	if out.Enabled && out.HTTPOnly == nil {
		enabled := true
		out.HTTPOnly = &enabled
	}
	return out
}

func defaultProxyStickyCookieName(poolName string) string {
	var b strings.Builder
	b.WriteString("tky_lb")
	normalizedPoolName := strings.TrimSpace(poolName)
	if normalizedPoolName != "" {
		b.WriteRune('_')
	}
	for _, r := range strings.ToLower(normalizedPoolName) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune('_')
		default:
			b.WriteRune('_')
		}
	}
	out := strings.TrimRight(b.String(), "_")
	if out == "" {
		return "tky_lb"
	}
	if len(out) > 64 {
		return out[:64]
	}
	return out
}

func validateProxyStickySessionConfig(cfg ProxyStickySessionConfig, field string) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.CookieName == "" {
		return fmt.Errorf("%s.cookie_name is required when enabled=true", field)
	}
	if !proxyRouteHeaderNamePattern.MatchString(cfg.CookieName) {
		return fmt.Errorf("%s.cookie_name must be a valid HTTP cookie token", field)
	}
	if cfg.TTLSeconds <= 0 || cfg.TTLSeconds > maxProxyStickySessionTTLSeconds {
		return fmt.Errorf("%s.ttl_seconds must be between 1 and %d", field, maxProxyStickySessionTTLSeconds)
	}
	if cfg.Path == "" || !strings.HasPrefix(cfg.Path, "/") {
		return fmt.Errorf("%s.path must start with /", field)
	}
	if strings.ContainsAny(cfg.Domain, ";\r\n\t ") {
		return fmt.Errorf("%s.domain must not contain whitespace or semicolons", field)
	}
	switch cfg.SameSite {
	case "", "lax", "strict", "none":
	default:
		return fmt.Errorf("%s.same_site must be one of lax|strict|none", field)
	}
	if cfg.SameSite == "none" && !cfg.Secure {
		return fmt.Errorf("%s.secure must be true when same_site=none", field)
	}
	return nil
}

func validateProxyRouteMatch(match ProxyRouteMatch, field string) error {
	for i, host := range match.Hosts {
		if err := validateProxyRouteHostPattern(host); err != nil {
			return fmt.Errorf("%s.hosts[%d]: %w", field, i, err)
		}
	}
	if match.Path == nil {
		return nil
	}
	switch match.Path.Type {
	case "exact", "prefix", "regex":
	default:
		return fmt.Errorf("%s.path.type must be exact, prefix, or regex", field)
	}
	if strings.TrimSpace(match.Path.Value) == "" {
		return fmt.Errorf("%s.path.value is required", field)
	}
	if match.Path.Type != "regex" && !strings.HasPrefix(match.Path.Value, "/") {
		return fmt.Errorf("%s.path.value must start with '/'", field)
	}
	if match.Path.Type == "regex" {
		compiled, err := regexp.Compile(match.Path.Value)
		if err != nil {
			return fmt.Errorf("%s.path.value regex compile error: %w", field, err)
		}
		match.Path.compiled = compiled
	}
	return nil
}

func validateProxyRouteAction(action ProxyRouteAction, cfg ProxyRulesConfig, namedUpstreams map[string]ProxyUpstream, nameCounts map[string]int, backendPools map[string]ProxyBackendPool, backendPoolCounts map[string]int, field string) error {
	upstream := strings.TrimSpace(action.Upstream)
	backendPool := strings.TrimSpace(action.BackendPool)
	if backendPool == "" && upstream == "" && len(cfg.Upstreams) == 0 {
		return fmt.Errorf("%s.upstream is required when no upstreams are configured", field)
	}
	if backendPool != "" {
		if _, ok := backendPools[backendPool]; !ok {
			return fmt.Errorf("%s.backend_pool must reference a configured backend pool", field)
		}
		if backendPoolCounts[backendPool] > 1 {
			return fmt.Errorf("%s.backend_pool references duplicated backend pool %q", field, backendPool)
		}
		if upstream != "" {
			return fmt.Errorf("%s.backend_pool conflicts with %s.upstream", field, field)
		}
		if strings.TrimSpace(action.CanaryUpstream) != "" {
			return fmt.Errorf("%s.backend_pool conflicts with %s.canary_upstream", field, field)
		}
		if action.CanaryWeightPct != 0 {
			return fmt.Errorf("%s.backend_pool conflicts with %s.canary_weight_percent", field, field)
		}
		if action.UpstreamHTTP2Mode != "" && action.UpstreamHTTP2Mode != proxyHTTP2ModeDefault {
			return fmt.Errorf("%s.backend_pool conflicts with %s.upstream_http2_mode", field, field)
		}
		if action.CanaryUpstreamHTTP2Mode != "" && action.CanaryUpstreamHTTP2Mode != proxyHTTP2ModeDefault {
			return fmt.Errorf("%s.backend_pool conflicts with %s.canary_upstream_http2_mode", field, field)
		}
	}
	if upstream == "" && action.UpstreamHTTP2Mode != "" && action.UpstreamHTTP2Mode != proxyHTTP2ModeDefault {
		return fmt.Errorf("%s.upstream_http2_mode requires %s.upstream", field, field)
	}
	if upstream != "" {
		up, ok := namedUpstreams[upstream]
		if !ok {
			return fmt.Errorf("%s.upstream must reference a configured upstream name", field)
		}
		if !proxyUpstreamAllowedAsRouteTarget(up) {
			return fmt.Errorf("%s.upstream must reference a configured upstream name", field)
		}
		if nameCounts[upstream] > 1 {
			return fmt.Errorf("%s.upstream references duplicated upstream name %q", field, upstream)
		}
		if !up.Enabled {
			return fmt.Errorf("%s.upstream references disabled upstream %q", field, upstream)
		}
		if action.UpstreamHTTP2Mode != "" && action.UpstreamHTTP2Mode != proxyHTTP2ModeDefault {
			return fmt.Errorf("%s.upstream_http2_mode is not supported on route targets; use upstreams[].http2_mode", field)
		}
	}
	if err := validateProxyHTTP2Mode(action.UpstreamHTTP2Mode, field+".upstream_http2_mode"); err != nil {
		return err
	}
	if canaryUpstream := strings.TrimSpace(action.CanaryUpstream); canaryUpstream != "" {
		if upstream == "" {
			return fmt.Errorf("%s.canary_upstream requires %s.upstream", field, field)
		}
		up, ok := namedUpstreams[canaryUpstream]
		if !ok {
			return fmt.Errorf("%s.canary_upstream must reference a configured upstream name", field)
		}
		if !proxyUpstreamAllowedAsRouteTarget(up) {
			return fmt.Errorf("%s.canary_upstream must reference a configured upstream name", field)
		}
		if nameCounts[canaryUpstream] > 1 {
			return fmt.Errorf("%s.canary_upstream references duplicated upstream name %q", field, canaryUpstream)
		}
		if !up.Enabled {
			return fmt.Errorf("%s.canary_upstream references disabled upstream %q", field, canaryUpstream)
		}
		if action.CanaryUpstreamHTTP2Mode != "" && action.CanaryUpstreamHTTP2Mode != proxyHTTP2ModeDefault {
			return fmt.Errorf("%s.canary_upstream_http2_mode is not supported on route targets; use upstreams[].http2_mode", field)
		}
		if action.CanaryWeightPct <= 0 || action.CanaryWeightPct >= 100 {
			return fmt.Errorf("%s.canary_weight_percent must be between 1 and 99", field)
		}
	} else if action.CanaryWeightPct != 0 {
		return fmt.Errorf("%s.canary_weight_percent requires %s.canary_upstream", field, field)
	} else if action.CanaryUpstreamHTTP2Mode != "" && action.CanaryUpstreamHTTP2Mode != proxyHTTP2ModeDefault {
		return fmt.Errorf("%s.canary_upstream_http2_mode requires %s.canary_upstream", field, field)
	}
	if err := validateProxyHTTP2Mode(action.CanaryUpstreamHTTP2Mode, field+".canary_upstream_http2_mode"); err != nil {
		return err
	}
	if err := validateProxyHashPolicy(action.HashPolicy, action.HashKey, field+".hash_policy"); err != nil {
		return err
	}
	if hostRewrite := strings.TrimSpace(action.HostRewrite); hostRewrite != "" {
		if err := validateProxyRouteOutboundHost(hostRewrite); err != nil {
			return fmt.Errorf("%s.host_rewrite: %w", field, err)
		}
	}
	if action.PathRewrite != nil {
		if strings.TrimSpace(action.PathRewrite.Prefix) == "" {
			return fmt.Errorf("%s.path_rewrite.prefix is required", field)
		}
		if !strings.HasPrefix(action.PathRewrite.Prefix, "/") {
			return fmt.Errorf("%s.path_rewrite.prefix must start with '/'", field)
		}
	}
	if action.QueryRewrite != nil {
		if err := validateProxyRouteQueryOperations(*action.QueryRewrite, field+".query_rewrite"); err != nil {
			return err
		}
	}
	if action.RequestHeaders != nil {
		if err := validateProxyRouteHeaderOperations(*action.RequestHeaders, field+".request_headers", proxyRouteRestrictedHeaders, "route request_headers"); err != nil {
			return err
		}
	}
	if action.ResponseHeaders != nil {
		if err := validateProxyRouteHeaderOperations(*action.ResponseHeaders, field+".response_headers", proxyRouteRestrictedResponseHeaders, "route response_headers"); err != nil {
			return err
		}
	}
	return nil
}

func validateProxyRouteHeaderOperations(ops ProxyRouteHeaderOperations, field string, restricted map[string]struct{}, kind string) error {
	seen := map[string]string{}
	for name := range ops.Set {
		if err := validateProxyRouteHeaderName(name, restricted, kind); err != nil {
			return fmt.Errorf("%s.set.%s: %w", field, name, err)
		}
		seen[name] = "set"
	}
	for name := range ops.Add {
		if err := validateProxyRouteHeaderName(name, restricted, kind); err != nil {
			return fmt.Errorf("%s.add.%s: %w", field, name, err)
		}
		if prev, ok := seen[name]; ok {
			return fmt.Errorf("%s.add.%s conflicts with %s.%s", field, name, field, prev)
		}
		seen[name] = "add"
	}
	for _, name := range ops.Remove {
		if err := validateProxyRouteHeaderName(name, restricted, kind); err != nil {
			return fmt.Errorf("%s.remove.%s: %w", field, name, err)
		}
		if prev, ok := seen[name]; ok {
			return fmt.Errorf("%s.remove.%s conflicts with %s.%s", field, name, field, prev)
		}
		seen[name] = "remove"
	}
	return nil
}

func validateProxyRouteQueryOperations(ops ProxyRouteQueryOperations, field string) error {
	seen := map[string]string{}
	for key := range ops.Set {
		nextKey := strings.TrimSpace(key)
		if nextKey == "" {
			return fmt.Errorf("%s.set: query key is required", field)
		}
		seen[nextKey] = "set"
	}
	for key := range ops.Add {
		nextKey := strings.TrimSpace(key)
		if nextKey == "" {
			return fmt.Errorf("%s.add: query key is required", field)
		}
		if prev, ok := seen[nextKey]; ok {
			return fmt.Errorf("%s.add.%s conflicts with %s.%s", field, nextKey, field, prev)
		}
		seen[nextKey] = "add"
	}
	for _, key := range ops.Remove {
		nextKey := strings.TrimSpace(key)
		if nextKey == "" {
			return fmt.Errorf("%s.remove: query key is required", field)
		}
		if prev, ok := seen[nextKey]; ok {
			return fmt.Errorf("%s.remove.%s conflicts with %s.%s", field, nextKey, field, prev)
		}
		seen[nextKey] = "remove"
	}
	for _, prefix := range ops.RemovePrefixes {
		if strings.TrimSpace(prefix) == "" {
			return fmt.Errorf("%s.remove_prefixes: query prefix is required", field)
		}
	}
	return nil
}

func validateProxyRouteHeaderName(name string, restricted map[string]struct{}, kind string) error {
	if name == "" {
		return fmt.Errorf("header name is required")
	}
	if !proxyRouteHeaderNamePattern.MatchString(name) {
		return fmt.Errorf("invalid header name")
	}
	if _, ok := restricted[canonicalProxyRouteHeaderName(name)]; ok {
		return fmt.Errorf("header is not allowed in %s", kind)
	}
	return nil
}

func validateProxyRouteHostPattern(host string) error {
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if strings.Contains(host, "/") {
		return fmt.Errorf("host must not contain '/'")
	}
	if strings.Contains(host, "*") {
		if !strings.HasPrefix(host, "*.") || strings.Count(host, "*") != 1 {
			return fmt.Errorf("wildcard host must use the form *.example.com")
		}
		if strings.TrimPrefix(host, "*.") == "" {
			return fmt.Errorf("wildcard host suffix is required")
		}
	}
	return nil
}

func validateProxyRouteOutboundHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if strings.Contains(host, "://") {
		return fmt.Errorf("host rewrite must not include scheme")
	}
	if strings.Contains(host, "/") {
		return fmt.Errorf("host rewrite must not contain '/'")
	}
	if strings.Contains(host, "*") {
		return fmt.Errorf("host rewrite does not support wildcards")
	}
	parsed, err := url.Parse("http://" + host)
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("host rewrite must be a valid host or host:port")
	}
	return nil
}

func proxyRouteFallbackTarget(cfg ProxyRulesConfig) (*url.URL, bool, error) {
	if cfg.DefaultRoute != nil && proxyRouteEnabled(cfg.DefaultRoute.Enabled) {
		if target, ok, err := proxyRouteConfiguredTarget(cfg, cfg.DefaultRoute.Action.Upstream); err != nil {
			return nil, false, err
		} else if ok {
			return target, true, nil
		}
	}
	for _, route := range cfg.Routes {
		if !proxyRouteEnabled(route.Enabled) {
			continue
		}
		if target, ok, err := proxyRouteConfiguredTarget(cfg, route.Action.Upstream); err != nil {
			return nil, false, err
		} else if ok {
			return target, true, nil
		}
	}
	return nil, false, nil
}

func proxyRouteConfiguredTarget(cfg ProxyRulesConfig, ref string) (*url.URL, bool, error) {
	return proxyRouteConfiguredTargetField(cfg, "action.upstream", ref)
}

func proxyRoutesProvideFallback(cfg ProxyRulesConfig) bool {
	if cfg.DefaultRoute != nil && proxyRouteEnabled(cfg.DefaultRoute.Enabled) && strings.TrimSpace(cfg.DefaultRoute.Action.Upstream) != "" {
		return true
	}
	for _, route := range cfg.Routes {
		if !proxyRouteEnabled(route.Enabled) {
			continue
		}
		if len(route.Match.Hosts) == 0 && route.Match.Path == nil && strings.TrimSpace(route.Action.Upstream) != "" {
			return true
		}
	}
	return false
}

func withProxyRouteDecision(ctx context.Context, decision proxyRouteDecision) context.Context {
	classification, selection := splitProxyRouteDecision(decision)
	ctx = withProxyRouteClassification(ctx, classification)
	ctx = withProxyRouteTransportSelection(ctx, selection)
	return ctx
}

func withProxyRouteClassification(ctx context.Context, classification proxyRouteClassification) context.Context {
	if state, ok := proxyRequestContextStateFromContext(ctx); ok {
		state.RouteClassification = classification
		state.HasRouteClassification = true
		return ctx
	}
	return context.WithValue(ctx, ctxKeyRouteClass, classification)
}

func proxyRouteClassificationFromContext(ctx context.Context) (proxyRouteClassification, bool) {
	if ctx == nil {
		return proxyRouteClassification{}, false
	}
	if state, ok := proxyRequestContextStateFromContext(ctx); ok && state.HasRouteClassification {
		return state.RouteClassification, true
	}
	classification, ok := ctx.Value(ctxKeyRouteClass).(proxyRouteClassification)
	return classification, ok
}

func withProxyRouteTransportSelection(ctx context.Context, selection proxyRouteTransportSelection) context.Context {
	if state, ok := proxyRequestContextStateFromContext(ctx); ok {
		state.RouteSelection = selection
		state.HasRouteSelection = true
		return ctx
	}
	return context.WithValue(ctx, ctxKeyRouteSelection, selection)
}

func proxyRouteTransportSelectionFromContext(ctx context.Context) (proxyRouteTransportSelection, bool) {
	if ctx == nil {
		return proxyRouteTransportSelection{}, false
	}
	if state, ok := proxyRequestContextStateFromContext(ctx); ok && state.HasRouteSelection {
		return state.RouteSelection, true
	}
	selection, ok := ctx.Value(ctxKeyRouteSelection).(proxyRouteTransportSelection)
	return selection, ok
}

func proxyRouteDecisionFromContext(ctx context.Context) (proxyRouteDecision, bool) {
	classification, classOK := proxyRouteClassificationFromContext(ctx)
	selection, selOK := proxyRouteTransportSelectionFromContext(ctx)
	if !classOK && !selOK {
		return proxyRouteDecision{}, false
	}
	return combineProxyRouteDecision(classification, selection), true
}

func combineProxyRouteDecision(classification proxyRouteClassification, selection proxyRouteTransportSelection) proxyRouteDecision {
	return proxyRouteDecision{
		Classification:       classification,
		TransportSelection:   selection,
		Source:               classification.Source,
		RouteName:            classification.RouteName,
		OriginalHost:         classification.OriginalHost,
		OriginalPath:         classification.OriginalPath,
		OriginalQuery:        classification.OriginalQuery,
		RewrittenHost:        proxyRouteCombinedRewrittenHost(classification, selection),
		RewrittenPath:        classification.RewrittenPath,
		RewrittenRawPath:     classification.RewrittenRawPath,
		RewrittenQuery:       classification.RewrittenQuery,
		SelectedUpstream:     selection.SelectedUpstream,
		SelectedUpstreamURL:  selection.SelectedUpstreamURL,
		SelectedHTTP2Mode:    selection.SelectedHTTP2Mode,
		SelectedTransportKey: selection.SelectedTransportKey,
		Target:               cloneURL(selection.Target),
		HealthKey:            selection.HealthKey,
		OrderedTargets:       append([]proxyRouteTargetCandidate(nil), selection.OrderedTargets...),
		RetryPolicy:          classification.RetryPolicy,
		StickySession:        selection.StickySession,
		StickySessionHit:     selection.StickySessionHit,
		StickyTargetID:       selection.StickyTargetID,
		RequestHeaderOps:     classification.RequestHeaderOps,
		ResponseHeaderOps:    classification.ResponseHeaderOps,
		LogSelection:         classification.LogSelection,
	}
}

func splitProxyRouteDecision(decision proxyRouteDecision) (proxyRouteClassification, proxyRouteTransportSelection) {
	classification := decision.Classification
	selection := decision.TransportSelection

	if classification.Source == "" {
		classification.Source = decision.Source
	}
	if classification.RouteName == "" {
		classification.RouteName = decision.RouteName
	}
	if classification.OriginalHost == "" {
		classification.OriginalHost = decision.OriginalHost
	}
	if classification.OriginalPath == "" {
		classification.OriginalPath = decision.OriginalPath
	}
	if classification.OriginalQuery == "" {
		classification.OriginalQuery = decision.OriginalQuery
	}
	if classification.RewrittenHost == "" {
		classification.RewrittenHost = decision.RewrittenHost
	}
	if classification.RewrittenPath == "" {
		classification.RewrittenPath = decision.RewrittenPath
	}
	if classification.RewrittenRawPath == "" {
		classification.RewrittenRawPath = decision.RewrittenRawPath
	}
	if classification.RewrittenQuery == "" {
		classification.RewrittenQuery = decision.RewrittenQuery
	}
	if len(classification.TargetCandidates) == 0 && len(decision.OrderedTargets) > 0 {
		classification.TargetCandidates = append([]proxyRouteTargetCandidate(nil), decision.OrderedTargets...)
	}
	if proxyRouteRetryPolicyIsZero(classification.RetryPolicy) {
		classification.RetryPolicy = decision.RetryPolicy
	}
	if !classification.StickySession.Enabled && decision.StickySession.Enabled {
		classification.StickySession = decision.StickySession
	}
	if proxyRouteHeaderOperationsIsZero(classification.RequestHeaderOps) {
		classification.RequestHeaderOps = decision.RequestHeaderOps
	}
	if proxyRouteHeaderOperationsIsZero(classification.ResponseHeaderOps) {
		classification.ResponseHeaderOps = decision.ResponseHeaderOps
	}
	if !classification.LogSelection {
		classification.LogSelection = decision.LogSelection
	}

	if selection.SelectedUpstream == "" {
		selection.SelectedUpstream = decision.SelectedUpstream
	}
	if selection.SelectedUpstreamURL == "" {
		selection.SelectedUpstreamURL = decision.SelectedUpstreamURL
	}
	if selection.SelectedHTTP2Mode == "" {
		selection.SelectedHTTP2Mode = decision.SelectedHTTP2Mode
	}
	if selection.SelectedTransportKey == "" {
		selection.SelectedTransportKey = decision.SelectedTransportKey
	}
	if selection.Target == nil {
		selection.Target = cloneURL(decision.Target)
	}
	if selection.HealthKey == "" {
		selection.HealthKey = decision.HealthKey
	}
	if len(selection.OrderedTargets) == 0 && len(decision.OrderedTargets) > 0 {
		selection.OrderedTargets = append([]proxyRouteTargetCandidate(nil), decision.OrderedTargets...)
	}
	if !selection.StickySession.Enabled && decision.StickySession.Enabled {
		selection.StickySession = decision.StickySession
	}
	if !selection.StickySessionHit {
		selection.StickySessionHit = decision.StickySessionHit
	}
	if selection.StickyTargetID == "" {
		selection.StickyTargetID = decision.StickyTargetID
	}
	if selection.RewrittenHost == "" {
		selection.RewrittenHost = decision.RewrittenHost
	}

	return classification, selection
}

func proxyRouteRetryPolicyIsZero(in proxyRetryPolicy) bool {
	return in.Attempts == 0 &&
		in.Backoff == 0 &&
		in.PerTryTimeout == 0 &&
		len(in.StatusCodes) == 0 &&
		len(in.PassiveUnhealthyStatusCodes) == 0 &&
		len(in.Methods) == 0
}

func proxyRouteHeaderOperationsIsZero(in ProxyRouteHeaderOperations) bool {
	return len(in.Set) == 0 && len(in.Add) == 0 && len(in.Remove) == 0
}

func proxyRouteCombinedRewrittenHost(classification proxyRouteClassification, selection proxyRouteTransportSelection) string {
	if strings.TrimSpace(selection.RewrittenHost) != "" {
		return selection.RewrittenHost
	}
	return strings.TrimSpace(classification.RewrittenHost)
}

func appendProxyRouteLogFields(evt map[string]any, req *http.Request) {
	if evt == nil {
		return
	}
	if req != nil {
		evt["original_scheme"] = requestScheme(req)
		evt["original_host"] = req.Host
		evt["original_path"] = requestPath(req)
	}
	ctx := requestContext(req)
	classification, classOK := proxyRouteClassificationFromContext(ctx)
	selection, selectionOK := proxyRouteTransportSelectionFromContext(ctx)
	if !classOK && !selectionOK {
		return
	}
	if classification.OriginalHost != "" {
		evt["original_host"] = classification.OriginalHost
	}
	if classification.OriginalPath != "" {
		evt["original_path"] = classification.OriginalPath
	}
	if classification.OriginalQuery != "" {
		evt["original_query"] = classification.OriginalQuery
	}
	evt["route_source"] = string(classification.Source)
	if classification.RouteName != "" {
		evt["selected_route"] = classification.RouteName
	}
	if selection.SelectedUpstream != "" {
		evt["selected_upstream"] = selection.SelectedUpstream
	}
	if selection.SelectedUpstreamURL != "" {
		evt["selected_upstream_url"] = selection.SelectedUpstreamURL
	}
	if selection.SelectedHTTP2Mode != "" {
		evt["selected_http2_mode"] = selection.SelectedHTTP2Mode
	}
	if selection.HealthKey != "" {
		if backend, ok := ProxyBackendStatusByKey(selection.HealthKey); ok {
			if backend.AdminState != "" {
				evt["selected_upstream_admin_state"] = backend.AdminState
			}
			if backend.HealthState != "" {
				evt["selected_upstream_health_state"] = backend.HealthState
			}
			evt["selected_upstream_effective_selectable"] = backend.EffectiveSelectable
			if backend.EffectiveWeight > 0 {
				evt["selected_upstream_effective_weight"] = backend.EffectiveWeight
			}
			evt["selected_upstream_inflight"] = backend.InFlight
		}
	}
	if selection.StickySession.Enabled {
		evt["sticky_session"] = true
		if selection.StickySession.CookieName != "" {
			evt["sticky_session_cookie_name"] = selection.StickySession.CookieName
		}
		evt["sticky_session_hit"] = selection.StickySessionHit
	}
	if rewrittenHost := proxyRouteCombinedRewrittenHost(classification, selection); rewrittenHost != "" {
		evt["rewritten_host"] = rewrittenHost
	}
	if classification.RewrittenPath != "" {
		evt["rewritten_path"] = classification.RewrittenPath
	}
	if classification.RewrittenQuery != "" {
		evt["rewritten_query"] = classification.RewrittenQuery
	}
}

func requestContext(req *http.Request) context.Context {
	if req == nil {
		return nil
	}
	return req.Context()
}

func resolveProxyRouteClassification(req *http.Request, cfg ProxyRulesConfig) (proxyRouteClassification, error) {
	return resolveProxyRouteClassificationWithHealth(req, cfg, nil)
}

func resolveProxyRouteClassificationWithHealth(req *http.Request, cfg ProxyRulesConfig, health *upstreamHealthMonitor) (proxyRouteClassification, error) {
	originalPath := requestPath(req)
	if originalPath == "" {
		originalPath = "/"
	}
	originalRawPath := proxyRouteRawPath(req)
	originalHost := strings.TrimSpace(req.Host)

	for _, idx := range proxyRouteOrder(cfg) {
		route := cfg.Routes[idx]
		if !proxyRouteEnabled(route.Enabled) {
			continue
		}
		if !proxyRouteMatchesRoute(route, originalHost, originalPath) {
			continue
		}
		classification, err := buildProxyRouteClassification(req, originalHost, originalPath, originalRawPath, route.Name, proxyRouteResolutionRoute, route.Match.Path, route.Action, cfg, health)
		if err != nil {
			return proxyRouteClassification{}, err
		}
		classification.LogSelection = true
		return classification, nil
	}

	if cfg.DefaultRoute != nil && proxyRouteEnabled(cfg.DefaultRoute.Enabled) {
		classification, err := buildProxyRouteClassification(req, originalHost, originalPath, originalRawPath, cfg.DefaultRoute.Name, proxyRouteResolutionDefault, nil, cfg.DefaultRoute.Action, cfg, health)
		if err != nil {
			return proxyRouteClassification{}, err
		}
		classification.LogSelection = true
		return classification, nil
	}

	classification, err := buildProxyRouteClassification(req, originalHost, originalPath, originalRawPath, "upstream", proxyRouteResolutionUpstream, nil, ProxyRouteAction{}, cfg, health)
	if err != nil {
		return proxyRouteClassification{}, err
	}
	classification.LogSelection = len(cfg.Routes) > 0 || cfg.DefaultRoute != nil
	return classification, nil
}

func buildProxyRouteClassification(req *http.Request, originalHost string, originalPath string, originalRawPath string, routeName string, source proxyRouteResolutionSource, match *ProxyRoutePathMatch, action ProxyRouteAction, cfg ProxyRulesConfig, health *upstreamHealthMonitor) (proxyRouteClassification, error) {
	targetCandidates, targetSelection, err := buildProxyRouteTargetCandidatesWithHealth(cfg, action, health)
	if err != nil {
		return proxyRouteClassification{}, err
	}
	if len(targetCandidates) == 0 {
		return proxyRouteClassification{}, fmt.Errorf("no proxy targets available")
	}
	rewrittenPath := originalPath
	rewrittenRawPath := originalRawPath
	rewrittenQuery := proxyRouteRawQuery(req)
	if action.PathRewrite != nil {
		rewrittenPath, err = rewriteProxyRoutePath(originalPath, match, action.PathRewrite.Prefix)
		if err != nil {
			return proxyRouteClassification{}, err
		}
		if originalRawPath != "" {
			rewrittenRawPath, err = rewriteProxyRoutePath(originalRawPath, match, action.PathRewrite.Prefix)
			if err != nil {
				return proxyRouteClassification{}, err
			}
		}
	}
	if action.QueryRewrite != nil {
		rewrittenQuery, err = rewriteProxyRouteQuery(rewrittenQuery, action.QueryRewrite)
		if err != nil {
			return proxyRouteClassification{}, err
		}
	}
	return proxyRouteClassification{
		Source:            source,
		RouteName:         routeName,
		OriginalHost:      originalHost,
		OriginalPath:      originalPath,
		OriginalQuery:     proxyRouteRawQuery(req),
		RewrittenPath:     rewrittenPath,
		RewrittenRawPath:  rewrittenRawPath,
		RewrittenQuery:    rewrittenQuery,
		RewrittenHost:     plannedProxyRouteForwardedHost(originalHost, action.HostRewrite, source),
		TargetCandidates:  targetCandidates,
		TargetSelection:   targetSelection,
		RetryPolicy:       proxyBuildRetryPolicy(cfg),
		StickySession:     targetSelection.StickySession,
		RequestHeaderOps:  valueOrZero(action.RequestHeaders),
		ResponseHeaderOps: valueOrZero(action.ResponseHeaders),
		LogSelection:      source != proxyRouteResolutionUpstream,
	}, nil
}

func resolveProxyRouteTransportSelection(req *http.Request, classification proxyRouteClassification, health *upstreamHealthMonitor) (proxyRouteTransportSelection, error) {
	orderedTargets := orderProxyRouteCandidates(req, classification.TargetCandidates, classification.TargetSelection, health)
	if len(orderedTargets) == 0 {
		return proxyRouteTransportSelection{}, fmt.Errorf("no proxy targets available")
	}
	selectedTarget := orderedTargets[0]
	return proxyRouteTransportSelection{
		SelectedUpstream:     selectedTarget.Name,
		SelectedUpstreamURL:  selectedTarget.Target.String(),
		SelectedHTTP2Mode:    selectedTarget.HTTP2Mode,
		SelectedTransportKey: selectedTarget.TransportKey,
		Target:               cloneURL(selectedTarget.Target),
		HealthKey:            selectedTarget.Key,
		OrderedTargets:       orderedTargets,
		RewrittenHost:        resolveProxyRouteForwardedHost(classification.OriginalHost, selectedTarget.Target.Host, classification.RewrittenHost, classification.Source),
		StickySession:        classification.StickySession,
		StickySessionHit:     proxyStickySessionMatchesID(req, classification.StickySession, proxyRouteCandidateStickyID(selectedTarget), time.Now().UTC()),
		StickyTargetID:       proxyRouteCandidateStickyID(selectedTarget),
	}, nil
}

func resolveProxyRouteDecision(req *http.Request, cfg ProxyRulesConfig, health *upstreamHealthMonitor) (proxyRouteDecision, error) {
	classification, err := resolveProxyRouteClassificationWithHealth(req, cfg, health)
	if err != nil {
		return proxyRouteDecision{}, err
	}
	selection, err := resolveProxyRouteTransportSelection(req, classification, health)
	if err != nil {
		return proxyRouteDecision{}, err
	}
	return combineProxyRouteDecision(classification, selection), nil
}

func plannedProxyRouteForwardedHost(originalHost string, hostRewrite string, source proxyRouteResolutionSource) string {
	if next := strings.TrimSpace(hostRewrite); next != "" {
		return next
	}
	if source == proxyRouteResolutionUpstream {
		return ""
	}
	return strings.TrimSpace(originalHost)
}

func resolveProxyRouteForwardedHost(originalHost string, targetHost string, hostRewrite string, source proxyRouteResolutionSource) string {
	if next := strings.TrimSpace(hostRewrite); next != "" {
		return next
	}
	if source == proxyRouteResolutionUpstream {
		if next := strings.TrimSpace(targetHost); next != "" {
			return next
		}
	}
	if next := strings.TrimSpace(originalHost); next != "" {
		return next
	}
	return strings.TrimSpace(targetHost)
}

func resolveProxyRouteTarget(cfg ProxyRulesConfig, ref string, health *upstreamHealthMonitor) (*url.URL, string, string, string, error) {
	ref = strings.TrimSpace(ref)
	if ref != "" {
		for _, upstream := range cfg.Upstreams {
			if upstream.Name != ref {
				continue
			}
			if !proxyUpstreamAllowedAsRouteTarget(upstream) {
				return nil, "", "", "", fmt.Errorf("route target %q must reference a configured upstream name", ref)
			}
			if proxyUpstreamDiscoveryEnabled(upstream) {
				if health == nil {
					return nil, "", "", "", fmt.Errorf("route target %q has no available discovered targets", ref)
				}
				candidates := health.RouteCandidatesForUpstream(cfg, upstream, proxyPositiveWeight(upstream.Weight), upstream.HTTP2Mode)
				ordered := orderProxyRouteCandidates(nil, candidates, proxyRouteTargetSelectionOptions{}, health)
				if len(ordered) == 0 {
					return nil, "", "", "", fmt.Errorf("route target %q has no available discovered targets", ref)
				}
				selected := ordered[0]
				return selected.Target, selected.Name, selected.Target.String(), selected.Key, nil
			}
			target, err := parseProxyUpstreamURL("action.upstream", upstream.URL)
			if err != nil {
				return nil, "", "", "", err
			}
			return target, upstream.Name, target.String(), "", nil
		}
		return nil, "", "", "", fmt.Errorf("route target %q must reference a configured upstream name", ref)
	}

	if health != nil {
		if selection, ok := health.SelectTarget(); ok && selection.Target != nil {
			name := strings.TrimSpace(selection.Name)
			if name == "" {
				name = strings.TrimSpace(selection.Key)
			}
			return selection.Target, name, selection.Target.String(), selection.Key, nil
		}
	}
	target, err := proxyPrimaryTarget(cfg)
	if err != nil {
		return nil, "", "", "", err
	}
	return target, proxyDefaultUpstreamName(cfg), target.String(), "", nil
}

func proxyDefaultUpstreamName(cfg ProxyRulesConfig) string {
	for _, upstream := range proxyConfiguredUpstreams(cfg) {
		if upstream.Enabled {
			return upstream.Name
		}
	}
	return ""
}

func sortedProxyRouteIndexes(routes []ProxyRoute) []int {
	idxs := make([]int, len(routes))
	for i := range routes {
		idxs[i] = i
	}
	sort.SliceStable(idxs, func(i, j int) bool {
		left := routes[idxs[i]]
		right := routes[idxs[j]]
		if left.Generated != right.Generated {
			return !left.Generated
		}
		return left.Priority < right.Priority
	})
	return idxs
}

func proxyRouteMatchesRoute(route ProxyRoute, host string, reqPath string) bool {
	if route.Generated {
		if !siteHostsMatch(route.Match.Hosts, normalizeProxyRequestHost(host)) {
			return false
		}
		if route.Match.Path == nil {
			return true
		}
		ok, _ := proxyRoutePathMatchDetails(route.Match.Path, reqPath)
		return ok
	}
	return proxyRouteMatches(route.Match, host, reqPath)
}

func proxyRouteMatches(match ProxyRouteMatch, host string, reqPath string) bool {
	if !proxyRouteHostsMatch(match.Hosts, host) {
		return false
	}
	if match.Path == nil {
		return true
	}
	ok, _ := proxyRoutePathMatchDetails(match.Path, reqPath)
	return ok
}

func proxyRouteHostsMatch(patterns []string, host string) bool {
	if len(patterns) == 0 {
		return true
	}
	reqHost := normalizeProxyRequestHost(host)
	for _, pattern := range patterns {
		if proxyRouteHostMatches(pattern, reqHost) {
			return true
		}
	}
	return false
}

func proxyRouteHostMatches(pattern string, reqHost string) bool {
	pattern = normalizeProxyHostPattern(pattern)
	if pattern == "" || reqHost == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		return reqHost != suffix && strings.HasSuffix(reqHost, "."+suffix)
	}
	return reqHost == pattern
}

func normalizeProxyRequestHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if parsed, err := url.Parse("http://" + host); err == nil && parsed.Hostname() != "" {
		return normalizeProxyHostPattern(parsed.Hostname())
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return normalizeProxyHostPattern(strings.Trim(strings.ToLower(h), "[]"))
	}
	return normalizeProxyHostPattern(strings.Trim(host, "[]"))
}

func proxyRoutePathMatchDetails(match *ProxyRoutePathMatch, reqPath string) (bool, string) {
	if match == nil {
		return true, ""
	}
	if reqPath == "" {
		reqPath = "/"
	}
	switch match.Type {
	case "exact":
		return reqPath == match.Value, ""
	case "prefix":
		if match.Value == "/" {
			return true, reqPath
		}
		if reqPath == match.Value {
			return true, ""
		}
		prefixWithSlash := match.Value + "/"
		if strings.HasPrefix(reqPath, prefixWithSlash) {
			return true, strings.TrimPrefix(reqPath, match.Value)
		}
		return false, ""
	case "regex":
		compiled, err := proxyRouteCompiledRegexp(match)
		if err != nil {
			return false, ""
		}
		return compiled.MatchString(reqPath), ""
	default:
		return false, ""
	}
}

func rewriteProxyRoutePath(originalPath string, match *ProxyRoutePathMatch, rewritePrefix string) (string, error) {
	if match != nil && match.Type == "regex" {
		return "", fmt.Errorf("path rewrite does not support regex path matches")
	}
	ok, suffix := proxyRoutePathMatchDetails(match, originalPath)
	if !ok {
		return "", fmt.Errorf("path %q does not match route path rule", originalPath)
	}
	return joinProxyRoutePath(rewritePrefix, suffix), nil
}

func proxyRouteCompiledRegexp(match *ProxyRoutePathMatch) (*regexp.Regexp, error) {
	if match == nil || match.Type != "regex" {
		return nil, fmt.Errorf("regex path match is not configured")
	}
	if match.compiled != nil {
		return match.compiled, nil
	}
	compiled, err := regexp.Compile(match.Value)
	if err != nil {
		return nil, err
	}
	match.compiled = compiled
	return compiled, nil
}

func joinProxyRoutePath(prefix string, suffix string) string {
	prefix = normalizeProxyRoutePrefix(prefix)
	if prefix == "/" {
		if suffix == "" {
			return "/"
		}
		if strings.HasPrefix(suffix, "/") {
			return suffix
		}
		return "/" + suffix
	}
	if suffix == "" {
		return prefix
	}
	if strings.HasPrefix(suffix, "/") {
		return prefix + suffix
	}
	return prefix + "/" + suffix
}

func applyProxyRouteHeaders(header http.Header, ops ProxyRouteHeaderOperations) {
	if header == nil {
		return
	}
	for _, name := range ops.Remove {
		header.Del(name)
	}
	for name, value := range ops.Set {
		header.Set(name, value)
	}
	for name, value := range ops.Add {
		header.Add(name, value)
	}
}

func rewriteProxyOutgoingURL(out *http.Request, target *url.URL, rewrittenPath string, rewrittenRawPath string, rewrittenQuery string) {
	if out == nil || out.URL == nil {
		return
	}
	rewriteProxyTargetURL(out.URL, target, rewrittenPath, rewrittenRawPath, rewrittenQuery)
}

func rewriteProxyTargetURL(out *url.URL, target *url.URL, rewrittenPath string, rewrittenRawPath string, rawQuery string) {
	if out == nil || target == nil {
		return
	}
	reqURL := &url.URL{Path: rewrittenPath, RawPath: rewrittenRawPath, RawQuery: rawQuery}
	targetQuery := target.RawQuery
	out.Scheme = target.Scheme
	out.Host = target.Host
	out.Path, out.RawPath = joinProxyURLPath(target, reqURL)
	if targetQuery == "" || reqURL.RawQuery == "" {
		out.RawQuery = targetQuery + reqURL.RawQuery
	} else {
		out.RawQuery = targetQuery + "&" + reqURL.RawQuery
	}
}

func rewriteProxyRouteQuery(rawQuery string, ops *ProxyRouteQueryOperations) (string, error) {
	if ops == nil {
		return rawQuery, nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", fmt.Errorf("query_rewrite parse error: %w", err)
	}
	for _, key := range ops.Remove {
		values.Del(key)
	}
	if len(ops.RemovePrefixes) > 0 {
		for key := range values {
			for _, prefix := range ops.RemovePrefixes {
				if strings.HasPrefix(key, prefix) {
					values.Del(key)
					break
				}
			}
		}
	}
	for key, value := range ops.Set {
		values.Set(key, value)
	}
	for key, value := range ops.Add {
		values.Add(key, value)
	}
	return values.Encode(), nil
}

func joinProxyURLPath(a, b *url.URL) (string, string) {
	if a == nil || b == nil {
		return "", ""
	}
	if a.RawPath == "" && b.RawPath == "" {
		return proxySingleJoiningSlash(a.Path, b.Path), ""
	}
	apath := a.EscapedPath()
	bpath := b.EscapedPath()
	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")
	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	default:
		return a.Path + b.Path, apath + bpath
	}
}

func proxySingleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	default:
		return a + b
	}
}

func proxyRouteRawPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	return req.URL.RawPath
}

func proxyRouteRawQuery(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	return req.URL.RawQuery
}

func proxyRouteDryRun(cfg ProxyRulesConfig, host string, path string) (proxyRouteDryRunResult, error) {
	return proxyRouteDryRunWithHealth(cfg, host, path, nil)
}

func proxyRouteDryRunWithHealth(cfg ProxyRulesConfig, host string, path string, health *upstreamHealthMonitor) (proxyRouteDryRunResult, error) {
	displayHost := strings.TrimSpace(host)
	if displayHost == "" {
		displayHost = "route.example.invalid"
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+host+path, nil)
	if err != nil {
		req, err = http.NewRequest(http.MethodGet, "http://"+displayHost+path, nil)
		if err != nil {
			return proxyRouteDryRunResult{}, err
		}
	}
	req.Host = displayHost
	decision, err := resolveProxyRouteDecision(req, cfg, health)
	if err != nil {
		return proxyRouteDryRunResult{}, err
	}
	return proxyRouteDryRunResult{
		Source:              string(decision.Source),
		RouteName:           decision.RouteName,
		OriginalHost:        decision.OriginalHost,
		OriginalPath:        decision.OriginalPath,
		OriginalQuery:       decision.OriginalQuery,
		RewrittenHost:       decision.RewrittenHost,
		RewrittenPath:       decision.RewrittenPath,
		RewrittenQuery:      decision.RewrittenQuery,
		SelectedUpstream:    decision.SelectedUpstream,
		SelectedUpstreamURL: decision.SelectedUpstreamURL,
		SelectedHTTP2Mode:   decision.SelectedHTTP2Mode,
		FinalURL:            finalProxyRouteURL(decision.Target, decision.RewrittenPath, decision.RewrittenRawPath, decision.RewrittenQuery),
	}, nil
}

func finalProxyRouteURL(target *url.URL, rewrittenPath string, rewrittenRawPath string, rewrittenQuery string) string {
	if target == nil {
		return ""
	}
	out := cloneURL(target)
	rewriteProxyTargetURL(out, target, rewrittenPath, rewrittenRawPath, rewrittenQuery)
	return out.String()
}

func valueOrZero[T any](in *T) T {
	var zero T
	if in == nil {
		return zero
	}
	return *in
}
