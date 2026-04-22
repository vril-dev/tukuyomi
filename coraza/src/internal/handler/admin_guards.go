package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

const (
	adminEndpointAPI = "api"
	adminEndpointUI  = "ui"
)

type adminAccessControl struct {
	mu sync.RWMutex

	mode              string
	trustForwardedFor bool
	trustedCIDRs      []netip.Prefix
}

type adminRateLimitStats struct {
	Requests uint64
	Allowed  uint64
	Blocked  uint64
}

type adminRateLimitDecision struct {
	Allowed           bool
	StatusCode        int
	RetryAfterSeconds int
}

type adminRateLimiter struct {
	enabled           bool
	rps               float64
	burst             float64
	statusCode        int
	retryAfterSeconds int

	mu      sync.Mutex
	buckets map[string]*adminTokenBucket
	stats   adminRateLimitStats
}

type adminTokenBucket struct {
	Tokens float64
	Last   time.Time
}

var (
	defaultAdminTrustedCIDRs = []string{
		"127.0.0.1/32",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	adminGuardMu       sync.RWMutex
	currentAdminAccess *adminAccessControl
	currentAdminRate   *adminRateLimiter
)

func InitAdminGuards() error {
	access, err := newAdminAccessControl()
	if err != nil {
		return err
	}
	rate := newAdminRateLimiter()
	adminGuardMu.Lock()
	currentAdminAccess = access
	currentAdminRate = rate
	adminGuardMu.Unlock()
	return nil
}

func AdminAccessMiddleware(endpointKind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		access := currentAdminAccessControl()
		if access != nil && !access.allowsEndpoint(c.Request, endpointKind) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func AdminRateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		limiter := currentAdminRateLimiter()
		if limiter != nil {
			decision := limiter.Evaluate(c.Request)
			if !decision.Allowed {
				if decision.RetryAfterSeconds > 0 {
					c.Header("Retry-After", strconv.Itoa(decision.RetryAfterSeconds))
				}
				c.AbortWithStatusJSON(decision.StatusCode, gin.H{"error": "admin rate limit exceeded"})
				return
			}
		}
		c.Next()
	}
}

func CheckAdminUIAccess(r *http.Request) bool {
	access := currentAdminAccessControl()
	return access == nil || access.allowsEndpoint(r, adminEndpointUI)
}

func EvaluateAdminUIRateLimit(r *http.Request) adminRateLimitDecision {
	limiter := currentAdminRateLimiter()
	if limiter == nil {
		return adminRateLimitDecision{Allowed: true}
	}
	return limiter.Evaluate(r)
}

func AdminRateLimitStatsSnapshot() adminRateLimitStats {
	limiter := currentAdminRateLimiter()
	if limiter == nil {
		return adminRateLimitStats{}
	}
	return limiter.Stats()
}

func currentAdminAccessControl() *adminAccessControl {
	adminGuardMu.RLock()
	defer adminGuardMu.RUnlock()
	return currentAdminAccess
}

func currentAdminRateLimiter() *adminRateLimiter {
	adminGuardMu.RLock()
	defer adminGuardMu.RUnlock()
	return currentAdminRate
}

func newAdminAccessControl() (*adminAccessControl, error) {
	access := &adminAccessControl{}
	if err := access.Update(); err != nil {
		return nil, err
	}
	return access, nil
}

func (a *adminAccessControl) Update() error {
	mode := strings.ToLower(strings.TrimSpace(config.AdminExternalMode))
	if mode == "" {
		mode = "api_only_external"
	}
	switch mode {
	case "deny_external", "api_only_external", "full_external":
	default:
		return fmt.Errorf("admin.external_mode must be one of: deny_external, api_only_external, full_external")
	}

	cidrs := append([]string(nil), config.AdminTrustedCIDRs...)
	if len(cidrs) == 0 {
		cidrs = append([]string(nil), defaultAdminTrustedCIDRs...)
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return err
		}
		prefixes = append(prefixes, prefix)
	}

	a.mu.Lock()
	a.mode = mode
	a.trustForwardedFor = config.AdminTrustForwardedFor
	a.trustedCIDRs = prefixes
	a.mu.Unlock()
	return nil
}

func (a *adminAccessControl) allowsEndpoint(r *http.Request, endpointKind string) bool {
	if a == nil {
		return true
	}
	a.mu.RLock()
	mode := a.mode
	trustForwardedFor := a.trustForwardedFor
	trustedCIDRs := append([]netip.Prefix(nil), a.trustedCIDRs...)
	a.mu.RUnlock()

	clientIP, ok := resolveAdminClientIP(r, trustForwardedFor, trustedCIDRs)
	if !ok {
		return false
	}
	if isAdminIPTrusted(trustedCIDRs, clientIP) {
		return true
	}

	switch mode {
	case "full_external":
		return true
	case "api_only_external":
		return endpointKind == adminEndpointAPI
	default:
		return false
	}
}

func newAdminRateLimiter() *adminRateLimiter {
	rl := &adminRateLimiter{
		buckets: make(map[string]*adminTokenBucket),
	}
	rl.Update()
	return rl
}

func (r *adminRateLimiter) Update() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = config.AdminRateLimitEnabled
	r.rps = float64(config.AdminRateLimitRPS)
	r.burst = float64(config.AdminRateLimitBurst)
	r.statusCode = config.AdminRateLimitStatusCode
	r.retryAfterSeconds = config.AdminRateLimitRetryAfter
	if r.statusCode == 0 {
		r.statusCode = http.StatusTooManyRequests
	}
	if !r.enabled {
		r.buckets = make(map[string]*adminTokenBucket)
	}
}

func (r *adminRateLimiter) Evaluate(req *http.Request) adminRateLimitDecision {
	if r == nil {
		return adminRateLimitDecision{Allowed: true}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats.Requests++
	if !r.enabled || r.rps <= 0 || r.burst <= 0 {
		r.stats.Allowed++
		return adminRateLimitDecision{Allowed: true}
	}
	now := time.Now().UTC()
	key := adminRateLimitKey(req)
	bucket := r.buckets[key]
	if bucket == nil {
		bucket = &adminTokenBucket{Tokens: r.burst, Last: now}
		r.buckets[key] = bucket
	}
	elapsed := now.Sub(bucket.Last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	bucket.Tokens += elapsed * r.rps
	if bucket.Tokens > r.burst {
		bucket.Tokens = r.burst
	}
	bucket.Last = now
	if bucket.Tokens < 1 {
		r.stats.Blocked++
		return adminRateLimitDecision{
			Allowed:           false,
			StatusCode:        r.statusCode,
			RetryAfterSeconds: r.retryAfterSeconds,
		}
	}
	bucket.Tokens--
	r.stats.Allowed++
	if len(r.buckets) > 4096 {
		r.pruneLocked(now.Add(-10 * time.Minute))
	}
	return adminRateLimitDecision{Allowed: true}
}

func (r *adminRateLimiter) Stats() adminRateLimitStats {
	if r == nil {
		return adminRateLimitStats{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func (r *adminRateLimiter) pruneLocked(cutoff time.Time) {
	for key, bucket := range r.buckets {
		if bucket == nil || bucket.Last.Before(cutoff) {
			delete(r.buckets, key)
		}
	}
}

func adminRateLimitKey(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	parts := []string{requestRemoteIP(r)}
	if key := strings.TrimSpace(r.Header.Get("X-API-Key")); key != "" {
		sum := sha256.Sum256([]byte(key))
		parts = append(parts, hex.EncodeToString(sum[:8]))
	}
	return strings.Join(parts, "|")
}

func isAdminIPTrusted(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func resolveAdminClientIP(r *http.Request, trustForwarded bool, trustedCIDRs []netip.Prefix) (netip.Addr, bool) {
	if r == nil {
		return netip.Addr{}, false
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	sourceIP, ok := parseIPLiteral(host)
	if !ok {
		return netip.Addr{}, false
	}
	if trustForwarded && isAdminIPTrusted(trustedCIDRs, sourceIP) {
		if ip, ok := parseXForwardedForIP(r.Header.Get("X-Forwarded-For")); ok {
			return ip, true
		}
		if ip, ok := parseIPLiteral(r.Header.Get("X-Real-IP")); ok {
			return ip, true
		}
	}
	return sourceIP, true
}

func parseXForwardedForIP(raw string) (netip.Addr, bool) {
	for _, part := range strings.Split(raw, ",") {
		if ip, ok := parseIPLiteral(part); ok {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func parseIPLiteral(raw string) (netip.Addr, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Addr{}, false
	}
	if idx := strings.IndexByte(value, '%'); idx >= 0 {
		value = value[:idx]
	}
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}
