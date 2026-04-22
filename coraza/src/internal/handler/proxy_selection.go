package handler

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

var proxySelectionCursor uint64

type proxyRetryPolicy struct {
	Attempts                    int
	Backoff                     time.Duration
	PerTryTimeout               time.Duration
	StatusCodes                 map[int]struct{}
	PassiveUnhealthyStatusCodes map[int]struct{}
	Methods                     map[string]struct{}
}

type proxyRouteTargetCandidate struct {
	Key          string
	Name         string
	Target       *url.URL
	Weight       int
	Managed      bool
	HTTP2Mode    string
	TransportKey string
	StickyID     string
}

type proxyRouteTargetSelectionOptions struct {
	HashPolicy    string
	HashKey       string
	UseLeastConn  bool
	StickySession ProxyStickySessionConfig
}

type proxyCandidateAvailability struct {
	Selectable bool
	InFlight   int
	Weight     int
}

func normalizeProxyHashPolicy(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "none":
		return ""
	case "client_ip":
		return "client_ip"
	case "header":
		return "header"
	case "cookie":
		return "cookie"
	case "jwt_sub":
		return "jwt_sub"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func validateProxyHashPolicy(policy string, key string, field string) error {
	switch normalizeProxyHashPolicy(policy) {
	case "":
		return nil
	case "client_ip", "jwt_sub":
		return nil
	case "header", "cookie":
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("%s requires hash_key", field)
		}
		return nil
	default:
		return fmt.Errorf("%s must be one of none|client_ip|header|cookie|jwt_sub", field)
	}
}

func normalizeProxyMethodList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		next := strings.ToUpper(strings.TrimSpace(raw))
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	return out
}

func validateProxyRetryMethods(in []string, field string) error {
	for _, method := range in {
		if strings.TrimSpace(method) == "" {
			return fmt.Errorf("%s must not contain empty entries", field)
		}
	}
	return nil
}

func normalizeProxyStatusCodeList(in []int) []int {
	out := make([]int, 0, len(in))
	seen := map[int]struct{}{}
	for _, code := range in {
		if code < 100 || code > 599 {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	sort.Ints(out)
	return out
}

func validateProxyRetryStatusCodes(in []int, field string) error {
	for _, code := range in {
		if code < 100 || code > 599 {
			return fmt.Errorf("%s entries must be valid HTTP status codes", field)
		}
	}
	return nil
}

func validateProxyRetryConfiguration(cfg ProxyRulesConfig) error {
	if cfg.RetryAttempts == 0 {
		return nil
	}
	if cfg.RetryAttempts < 0 || cfg.RetryAttempts > 8 {
		return fmt.Errorf("retry_attempts must be between 0 and 8")
	}
	if cfg.RetryBackoffMS > 10000 {
		return fmt.Errorf("retry_backoff_ms must be <= 10000")
	}
	if cfg.RetryPerTryTimeoutMS > 0 && cfg.RetryPerTryTimeoutMS < 50 {
		return fmt.Errorf("retry_per_try_timeout_ms must be >= 50 when set")
	}
	return nil
}

func validateProxyPassiveCircuitConfiguration(cfg ProxyRulesConfig) error {
	if cfg.PassiveHealthEnabled {
		if cfg.PassiveFailureThreshold > 32 {
			return fmt.Errorf("passive_failure_threshold must be <= 32")
		}
		if err := validateProxyRetryStatusCodes(cfg.PassiveUnhealthyStatusCodes, "passive_unhealthy_status_codes"); err != nil {
			return err
		}
	}
	if cfg.CircuitBreakerEnabled {
		if cfg.CircuitBreakerOpenSec > 3600 {
			return fmt.Errorf("circuit_breaker_open_sec must be <= 3600")
		}
		if cfg.CircuitBreakerHalfOpenRequests > 16 {
			return fmt.Errorf("circuit_breaker_half_open_requests must be <= 16")
		}
	}
	return nil
}

func proxyBuildRetryPolicy(cfg ProxyRulesConfig) proxyRetryPolicy {
	policy := proxyRetryPolicy{
		Attempts: cfg.RetryAttempts,
		Backoff:  time.Duration(cfg.RetryBackoffMS) * time.Millisecond,
	}
	if policy.Attempts <= 0 {
		if len(cfg.RetryStatusCodes) > 0 {
			policy.StatusCodes = make(map[int]struct{}, len(cfg.RetryStatusCodes))
			for _, code := range cfg.RetryStatusCodes {
				policy.StatusCodes[code] = struct{}{}
			}
		}
		if len(cfg.PassiveUnhealthyStatusCodes) > 0 {
			policy.PassiveUnhealthyStatusCodes = make(map[int]struct{}, len(cfg.PassiveUnhealthyStatusCodes))
			for _, code := range cfg.PassiveUnhealthyStatusCodes {
				policy.PassiveUnhealthyStatusCodes[code] = struct{}{}
			}
		}
		return policy
	}
	if cfg.RetryPerTryTimeoutMS > 0 {
		policy.PerTryTimeout = time.Duration(cfg.RetryPerTryTimeoutMS) * time.Millisecond
	}
	if len(cfg.RetryStatusCodes) == 0 {
		policy.StatusCodes = map[int]struct{}{
			http.StatusBadGateway:         {},
			http.StatusServiceUnavailable: {},
			http.StatusGatewayTimeout:     {},
		}
	} else {
		policy.StatusCodes = make(map[int]struct{}, len(cfg.RetryStatusCodes))
		for _, code := range cfg.RetryStatusCodes {
			policy.StatusCodes[code] = struct{}{}
		}
	}
	policy.PassiveUnhealthyStatusCodes = make(map[int]struct{}, len(cfg.PassiveUnhealthyStatusCodes))
	for _, code := range cfg.PassiveUnhealthyStatusCodes {
		policy.PassiveUnhealthyStatusCodes[code] = struct{}{}
	}
	methods := cfg.RetryMethods
	if len(methods) == 0 {
		methods = []string{http.MethodGet, http.MethodHead, http.MethodOptions}
	}
	policy.Methods = make(map[string]struct{}, len(methods))
	for _, method := range methods {
		policy.Methods[strings.ToUpper(strings.TrimSpace(method))] = struct{}{}
	}
	return policy
}

func (p proxyRetryPolicy) Enabled() bool {
	return p.Attempts > 0
}

func (p proxyRetryPolicy) AllowsMethod(method string) bool {
	if !p.Enabled() {
		return false
	}
	_, ok := p.Methods[strings.ToUpper(strings.TrimSpace(method))]
	return ok
}

func (p proxyRetryPolicy) RetryableStatus(code int) bool {
	_, ok := p.StatusCodes[code]
	return ok
}

func (p proxyRetryPolicy) PassiveUnhealthyStatus(code int) bool {
	_, ok := p.PassiveUnhealthyStatusCodes[code]
	return ok
}

// Status error metrics count every upstream response the runtime treats as a
// status-side failure signal, even if no retry is attempted for that response.
func (p proxyRetryPolicy) StatusCountsAsError(code int) bool {
	return code >= http.StatusInternalServerError || p.RetryableStatus(code) || p.PassiveUnhealthyStatus(code)
}

func resolveProxyRouteTargets(req *http.Request, cfg ProxyRulesConfig, action ProxyRouteAction, health *upstreamHealthMonitor) ([]proxyRouteTargetCandidate, error) {
	candidates, options, err := buildProxyRouteTargetCandidatesWithHealth(cfg, action, health)
	if err != nil {
		return nil, err
	}
	return orderProxyRouteCandidates(req, candidates, options, health), nil
}

func buildProxyRouteTargetCandidates(cfg ProxyRulesConfig, action ProxyRouteAction) ([]proxyRouteTargetCandidate, proxyRouteTargetSelectionOptions, error) {
	return buildProxyRouteTargetCandidatesWithHealth(cfg, action, nil)
}

func buildProxyRouteTargetCandidatesWithHealth(cfg ProxyRulesConfig, action ProxyRouteAction, health *upstreamHealthMonitor) ([]proxyRouteTargetCandidate, proxyRouteTargetSelectionOptions, error) {
	options := proxyRouteTargetSelectionOptions{
		HashPolicy:   cfg.HashPolicy,
		HashKey:      cfg.HashKey,
		UseLeastConn: cfg.LoadBalancingStrategy == "least_conn",
	}
	if poolName := strings.TrimSpace(action.BackendPool); poolName != "" {
		pool, ok := proxyBackendPoolByName(cfg, poolName)
		if !ok {
			return nil, proxyRouteTargetSelectionOptions{}, fmt.Errorf("unknown backend pool %q", poolName)
		}
		if pool.HashPolicy != "" {
			options.HashPolicy = pool.HashPolicy
			options.HashKey = pool.HashKey
		}
		if pool.StickySession.Enabled {
			options.StickySession = pool.StickySession
		}
		switch pool.Strategy {
		case "least_conn":
			options.UseLeastConn = true
		case "round_robin":
			options.UseLeastConn = false
		}
		if action.HashPolicy != "" {
			options.HashPolicy = action.HashPolicy
			options.HashKey = action.HashKey
		}
		out := make([]proxyRouteTargetCandidate, 0, len(pool.Members))
		for i, member := range pool.Members {
			candidates, err := proxyRouteTargetCandidatesFromPoolMember(cfg, member, i, health)
			if err != nil {
				return nil, proxyRouteTargetSelectionOptions{}, err
			}
			out = append(out, candidates...)
		}
		return out, options, nil
	}
	if action.HashPolicy != "" {
		options.HashPolicy = action.HashPolicy
		options.HashKey = action.HashKey
	}
	if strings.TrimSpace(action.CanaryUpstream) != "" {
		primary, err := proxyRouteTargetCandidatesFromRefWithMode(cfg, action.Upstream, action.UpstreamHTTP2Mode, 100-action.CanaryWeightPct, health)
		if err != nil {
			return nil, proxyRouteTargetSelectionOptions{}, err
		}
		canary, err := proxyRouteTargetCandidatesFromRefWithMode(cfg, action.CanaryUpstream, action.CanaryUpstreamHTTP2Mode, action.CanaryWeightPct, health)
		if err != nil {
			return nil, proxyRouteTargetSelectionOptions{}, err
		}
		options.UseLeastConn = false
		out := append(primary, canary...)
		return out, options, nil
	}
	if strings.TrimSpace(action.Upstream) != "" {
		candidates, err := proxyRouteTargetCandidatesFromRefWithMode(cfg, action.Upstream, action.UpstreamHTTP2Mode, 1, health)
		if err != nil {
			return nil, proxyRouteTargetSelectionOptions{}, err
		}
		return candidates, options, nil
	}
	if cfg.defaultTargetCandidatesReady {
		return cfg.defaultTargetCandidates, cfg.defaultTargetSelection, nil
	}
	defs := proxyConfiguredUpstreams(cfg)
	out := make([]proxyRouteTargetCandidate, 0, len(defs))
	for i, upstream := range defs {
		candidates, err := proxyRouteTargetCandidatesFromUpstream(cfg, upstream, i, proxyPositiveWeight(upstream.Weight), upstream.HTTP2Mode, health)
		if err != nil {
			return nil, proxyRouteTargetSelectionOptions{}, err
		}
		out = append(out, candidates...)
	}
	return out, options, nil
}

func precomputeProxyStaticFallbackTargets(cfg *ProxyRulesConfig) error {
	if cfg == nil {
		return nil
	}
	cfg.defaultTargetCandidatesReady = false
	cfg.defaultTargetCandidates = nil
	cfg.defaultTargetSelection = proxyRouteTargetSelectionOptions{}
	defs := proxyConfiguredUpstreams(*cfg)
	for _, upstream := range defs {
		if proxyUpstreamDiscoveryEnabled(upstream) {
			return nil
		}
	}
	options := proxyRouteTargetSelectionOptions{
		HashPolicy:   cfg.HashPolicy,
		HashKey:      cfg.HashKey,
		UseLeastConn: cfg.LoadBalancingStrategy == "least_conn",
	}
	out := make([]proxyRouteTargetCandidate, 0, len(defs))
	for i, upstream := range defs {
		candidates, err := proxyRouteTargetCandidatesFromUpstream(*cfg, upstream, i, proxyPositiveWeight(upstream.Weight), upstream.HTTP2Mode, nil)
		if err != nil {
			return err
		}
		out = append(out, candidates...)
	}
	cfg.defaultTargetCandidatesReady = true
	cfg.defaultTargetCandidates = out
	cfg.defaultTargetSelection = options
	return nil
}

func proxyBackendPoolByName(cfg ProxyRulesConfig, name string) (ProxyBackendPool, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ProxyBackendPool{}, false
	}
	for _, pool := range cfg.BackendPools {
		if pool.Name == name {
			return pool, true
		}
	}
	return ProxyBackendPool{}, false
}

func proxyRouteTargetCandidatesFromPoolMember(cfg ProxyRulesConfig, member string, index int, health *upstreamHealthMonitor) ([]proxyRouteTargetCandidate, error) {
	member = strings.TrimSpace(member)
	if member == "" {
		return nil, fmt.Errorf("backend_pools members[%d] is empty", index)
	}
	for i, upstream := range cfg.Upstreams {
		if upstream.Name != member {
			continue
		}
		return proxyRouteTargetCandidatesFromUpstream(cfg, upstream, i, proxyPositiveWeight(upstream.Weight), upstream.HTTP2Mode, health)
	}
	return nil, fmt.Errorf("unknown backend pool member %q", member)
}

func proxyRouteTargetCandidateFromRef(cfg ProxyRulesConfig, ref string, weight int) (proxyRouteTargetCandidate, error) {
	candidates, err := proxyRouteTargetCandidatesFromRefWithMode(cfg, ref, "", weight, nil)
	if err != nil {
		return proxyRouteTargetCandidate{}, err
	}
	if len(candidates) == 0 {
		return proxyRouteTargetCandidate{}, fmt.Errorf("route target %q has no available discovered targets", strings.TrimSpace(ref))
	}
	return candidates[0], nil
}

func proxyRouteTargetCandidateFromRefWithMode(cfg ProxyRulesConfig, ref string, http2Mode string, weight int) (proxyRouteTargetCandidate, error) {
	candidates, err := proxyRouteTargetCandidatesFromRefWithMode(cfg, ref, http2Mode, weight, nil)
	if err != nil {
		return proxyRouteTargetCandidate{}, err
	}
	if len(candidates) == 0 {
		return proxyRouteTargetCandidate{}, fmt.Errorf("route target %q has no available discovered targets", strings.TrimSpace(ref))
	}
	return candidates[0], nil
}

func proxyRouteTargetCandidatesFromRefWithMode(cfg ProxyRulesConfig, ref string, http2Mode string, weight int, health *upstreamHealthMonitor) ([]proxyRouteTargetCandidate, error) {
	ref = strings.TrimSpace(ref)
	for _, upstream := range cfg.Upstreams {
		if upstream.Name != ref {
			continue
		}
		if !proxyUpstreamAllowedAsRouteTarget(upstream) {
			return nil, fmt.Errorf("route target %q must reference a configured upstream name", ref)
		}
		return proxyRouteTargetCandidatesFromUpstream(cfg, upstream, -1, weight, http2Mode, health)
	}
	return nil, fmt.Errorf("route target %q must reference a configured upstream name", ref)
}

func proxyRouteTargetCandidatesFromUpstream(cfg ProxyRulesConfig, upstream ProxyUpstream, index int, weight int, http2Mode string, health *upstreamHealthMonitor) ([]proxyRouteTargetCandidate, error) {
	if proxyUpstreamDiscoveryEnabled(upstream) {
		if health == nil {
			return nil, nil
		}
		return health.RouteCandidatesForUpstream(cfg, upstream, weight, http2Mode), nil
	}
	field := "action.upstream"
	if index >= 0 {
		field = fmt.Sprintf("upstreams[%d].url", index)
	}
	target, err := parseProxyUpstreamURL(field, upstream.URL)
	if err != nil {
		return nil, err
	}
	mode := http2Mode
	if normalizeProxyHTTP2Mode(mode) == proxyHTTP2ModeDefault {
		mode = upstream.HTTP2Mode
	}
	key := proxyBackendLookupKey(upstream.Name, target.String())
	return []proxyRouteTargetCandidate{{
		Key:          key,
		Name:         upstream.Name,
		Target:       target,
		Weight:       proxyPositiveWeight(weight),
		Managed:      !upstream.Generated,
		HTTP2Mode:    proxyConfiguredHTTP2Mode(cfg, mode),
		TransportKey: proxyTransportKey(proxyConfiguredUpstreamTransportProfile(cfg, &upstream, mode)),
		StickyID:     upstream.Name,
	}}, nil
}

func orderProxyRouteCandidates(req *http.Request, candidates []proxyRouteTargetCandidate, options proxyRouteTargetSelectionOptions, health *upstreamHealthMonitor) []proxyRouteTargetCandidate {
	if len(candidates) == 1 && !options.UseLeastConn && normalizeProxyHashPolicy(options.HashPolicy) == "" {
		if proxySingleRouteCandidateSelectable(candidates[0], health) {
			return candidates
		}
		return nil
	}
	availability := proxyCandidateAvailabilities(health, candidates)
	eligible := make([]int, 0, len(candidates))
	for i, candidate := range candidates {
		avail := availability[candidate.Key]
		if !candidate.Managed || avail.Selectable {
			eligible = append(eligible, i)
			continue
		}
	}
	if len(eligible) == 0 {
		return nil
	}

	order := make([]int, 0, len(candidates))
	if options.StickySession.Enabled {
		if selected, ok := proxyStickySessionCandidateIndex(req, candidates, eligible, options.StickySession); ok {
			order = append(order, selected)
			for _, idx := range eligible {
				if idx == selected {
					continue
				}
				order = append(order, idx)
			}
			out := make([]proxyRouteTargetCandidate, 0, len(order))
			for _, idx := range order {
				out = append(out, candidates[idx])
			}
			return out
		}
	}
	switch {
	case options.UseLeastConn && len(eligible) > 1:
		sort.SliceStable(eligible, func(i, j int) bool {
			leftCandidate := candidates[eligible[i]]
			rightCandidate := candidates[eligible[j]]
			left := int64(availability[leftCandidate.Key].InFlight) * int64(proxyCandidateWeight(rightCandidate, availability))
			right := int64(availability[rightCandidate.Key].InFlight) * int64(proxyCandidateWeight(leftCandidate, availability))
			if left == right {
				return leftCandidate.Name < rightCandidate.Name
			}
			return left < right
		})
		order = append(order, eligible...)
	case options.HashPolicy != "":
		selected := proxyWeightedHashIndex(candidates, eligible, availability, proxyRouteSelectionValue(req, options.HashPolicy, options.HashKey))
		order = append(order, eligible[selected])
		for i, idx := range eligible {
			if i == selected {
				continue
			}
			order = append(order, idx)
		}
	default:
		selected := proxyWeightedCursorIndex(candidates, eligible, availability)
		order = append(order, eligible[selected])
		for offset := 1; offset < len(eligible); offset++ {
			order = append(order, eligible[(selected+offset)%len(eligible)])
		}
	}
	out := make([]proxyRouteTargetCandidate, 0, len(order))
	for _, idx := range order {
		out = append(out, candidates[idx])
	}
	return out
}

func proxySingleRouteCandidateSelectable(candidate proxyRouteTargetCandidate, health *upstreamHealthMonitor) bool {
	if !candidate.Managed {
		return true
	}
	if health == nil {
		return true
	}
	health.mu.RLock()
	defer health.mu.RUnlock()
	now := time.Now().UTC()
	for _, backend := range health.backends {
		if backend == nil || backend.Key != candidate.Key {
			continue
		}
		return proxyBackendSelectableLocked(health.cfg, backend, now)
	}
	return false
}

func proxyCandidateAvailabilities(health *upstreamHealthMonitor, candidates []proxyRouteTargetCandidate) map[string]proxyCandidateAvailability {
	out := make(map[string]proxyCandidateAvailability, len(candidates))
	if health == nil {
		for _, candidate := range candidates {
			out[candidate.Key] = proxyCandidateAvailability{
				Selectable: true,
				Weight:     proxyPositiveWeight(candidate.Weight),
			}
		}
		return out
	}
	now := time.Now().UTC()
	health.mu.RLock()
	defer health.mu.RUnlock()
	backends := make(map[string]*proxyBackendState, len(health.backends))
	for _, backend := range health.backends {
		if backend == nil {
			continue
		}
		backends[backend.Key] = backend
	}
	for _, candidate := range candidates {
		if !candidate.Managed {
			out[candidate.Key] = proxyCandidateAvailability{
				Selectable: true,
				Weight:     proxyPositiveWeight(candidate.Weight),
			}
			continue
		}
		backend, ok := backends[candidate.Key]
		if !ok {
			out[candidate.Key] = proxyCandidateAvailability{
				Selectable: false,
				Weight:     proxyPositiveWeight(candidate.Weight),
			}
			continue
		}
		out[candidate.Key] = proxyCandidateAvailability{
			Selectable: proxyBackendSelectableLocked(health.cfg, backend, now),
			InFlight:   backend.InFlight,
			Weight:     proxyBackendEffectiveWeight(backend),
		}
	}
	return out
}

func proxyRouteSelectionValue(req *http.Request, policy string, key string) string {
	switch normalizeProxyHashPolicy(policy) {
	case "client_ip":
		if req == nil {
			return ""
		}
		if forwarded := strings.TrimSpace(req.Header.Get("X-Forwarded-For")); forwarded != "" {
			return strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
		return requestRemoteIP(req)
	case "header":
		if req == nil {
			return ""
		}
		return strings.TrimSpace(req.Header.Get(key))
	case "cookie":
		if req == nil {
			return ""
		}
		c, err := req.Cookie(key)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(c.Value)
	case "jwt_sub":
		if req == nil {
			return ""
		}
		return extractRateLimitJWTSub(req, defaultRateLimitJWTHeaderNames, defaultRateLimitJWTCookieNames)
	default:
		return ""
	}
}

func proxyWeightedHashIndex(candidates []proxyRouteTargetCandidate, eligible []int, availability map[string]proxyCandidateAvailability, value string) int {
	if strings.TrimSpace(value) == "" {
		return proxyWeightedCursorIndex(candidates, eligible, availability)
	}
	totalWeight := 0
	for _, idx := range eligible {
		totalWeight += proxyCandidateWeight(candidates[idx], availability)
	}
	if totalWeight <= 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(value))
	bucket := int(binary.BigEndian.Uint64(sum[:8]) % uint64(totalWeight))
	acc := 0
	for pos, idx := range eligible {
		acc += proxyCandidateWeight(candidates[idx], availability)
		if bucket < acc {
			return pos
		}
	}
	return 0
}

func proxyWeightedCursorIndex(candidates []proxyRouteTargetCandidate, eligible []int, availability map[string]proxyCandidateAvailability) int {
	totalWeight := 0
	for _, idx := range eligible {
		totalWeight += proxyCandidateWeight(candidates[idx], availability)
	}
	if totalWeight <= 0 {
		return 0
	}
	cursor := int((atomic.AddUint64(&proxySelectionCursor, 1) - 1) % uint64(totalWeight))
	acc := 0
	for pos, idx := range eligible {
		acc += proxyCandidateWeight(candidates[idx], availability)
		if cursor < acc {
			return pos
		}
	}
	return 0
}

func proxyPositiveWeight(v int) int {
	if v <= 0 {
		return 1
	}
	return v
}

func proxyCandidateWeight(candidate proxyRouteTargetCandidate, availability map[string]proxyCandidateAvailability) int {
	if candidate.Managed {
		if weight := availability[candidate.Key].Weight; weight > 0 {
			return weight
		}
	}
	return proxyPositiveWeight(candidate.Weight)
}

func proxyRouteCandidateStickyID(candidate proxyRouteTargetCandidate) string {
	if next := strings.TrimSpace(candidate.StickyID); next != "" {
		return next
	}
	if next := strings.TrimSpace(candidate.Name); next != "" {
		return next
	}
	return strings.TrimSpace(candidate.Key)
}

func proxyBackendLookupKey(name string, rawURL string) string {
	trimmedName := strings.TrimSpace(name)
	trimmedURL := strings.TrimSpace(rawURL)
	sum := sha256.Sum256([]byte(trimmedName + "\n" + trimmedURL))
	return fmt.Sprintf("%s--%x", proxyBackendLookupPrefix(trimmedName), sum[:8])
}

func proxyBackendLookupPrefix(name string) string {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" {
		return "backend"
	}
	var b strings.Builder
	b.Grow(len(trimmed))
	lastDash := false
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
		if b.Len() >= 24 {
			break
		}
	}
	out := strings.Trim(b.String(), "-_")
	if out == "" {
		return "backend"
	}
	return out
}
