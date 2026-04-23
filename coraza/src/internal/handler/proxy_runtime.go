package handler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/observability"
)

const (
	defaultProxyDialTimeoutSec           = 5
	defaultProxyResponseHeaderTimeoutSec = 10
	defaultProxyIdleConnTimeoutSec       = 90
	defaultProxyUpstreamKeepAliveSec     = 30
	defaultProxyExpectContinueSec        = 1
	defaultProxyMaxIdleConns             = 100
	defaultProxyMaxIdleConnsPerHost      = 100
	defaultProxyMaxConnsPerHost          = 200
	defaultProxyHealthCheckIntervalSec   = 15
	defaultProxyHealthCheckTimeoutSec    = 2
	defaultProxyHealthCheckBodyLimit     = 64 * 1024
	defaultProxyDiscoveryRefreshSec      = 10
	defaultProxyDiscoveryTimeoutMS       = 1000
	defaultProxyDiscoveryMaxTargets      = 32
	maxProxyDiscoveryRefreshSec          = 3600
	maxProxyDiscoveryTimeoutMS           = 10000
	maxProxyDiscoveryTargets             = 256

	proxyHTTP2ModeDefault      = "default"
	proxyHTTP2ModeForceAttempt = "force_attempt"
	proxyHTTP2ModeH2C          = "h2c_prior_knowledge"
)

type ProxyRulesConfig struct {
	Upstreams                      []ProxyUpstream                   `json:"upstreams,omitempty"`
	BackendPools                   []ProxyBackendPool                `json:"backend_pools,omitempty"`
	LoadBalancingStrategy          string                            `json:"load_balancing_strategy,omitempty"`
	HashPolicy                     string                            `json:"hash_policy,omitempty"`
	HashKey                        string                            `json:"hash_key,omitempty"`
	Routes                         []ProxyRoute                      `json:"routes,omitempty"`
	DefaultRoute                   *ProxyDefaultRoute                `json:"default_route,omitempty"`
	DialTimeout                    int                               `json:"dial_timeout"`
	ResponseHeaderTimeout          int                               `json:"response_header_timeout"`
	IdleConnTimeout                int                               `json:"idle_conn_timeout"`
	UpstreamKeepAliveSec           int                               `json:"upstream_keepalive_sec"`
	MaxIdleConns                   int                               `json:"max_idle_conns"`
	MaxIdleConnsPerHost            int                               `json:"max_idle_conns_per_host"`
	MaxConnsPerHost                int                               `json:"max_conns_per_host"`
	ForceHTTP2                     bool                              `json:"force_http2"`
	H2CUpstream                    bool                              `json:"h2c_upstream"`
	DisableCompression             bool                              `json:"disable_compression"`
	ExposeWAFDebugHeaders          bool                              `json:"expose_waf_debug_headers"`
	EmitUpstreamNameRequestHeader  bool                              `json:"emit_upstream_name_request_header"`
	AccessLogMode                  string                            `json:"access_log_mode,omitempty"`
	ResponseCompression            ProxyResponseCompressionConfig    `json:"response_compression"`
	ExpectContinueTimeout          int                               `json:"expect_continue_timeout"`
	ResponseHeaderSanitize         ProxyResponseHeaderSanitizeConfig `json:"response_header_sanitize,omitempty"`
	TLSInsecureSkipVerify          bool                              `json:"tls_insecure_skip_verify"`
	TLSCABundle                    string                            `json:"tls_ca_bundle,omitempty"`
	TLSMinVersion                  string                            `json:"tls_min_version,omitempty"`
	TLSMaxVersion                  string                            `json:"tls_max_version,omitempty"`
	TLSClientCert                  string                            `json:"tls_client_cert"`
	TLSClientKey                   string                            `json:"tls_client_key"`
	RetryAttempts                  int                               `json:"retry_attempts,omitempty"`
	RetryBackoffMS                 int                               `json:"retry_backoff_ms,omitempty"`
	RetryPerTryTimeoutMS           int                               `json:"retry_per_try_timeout_ms,omitempty"`
	RetryStatusCodes               []int                             `json:"retry_status_codes,omitempty"`
	RetryMethods                   []string                          `json:"retry_methods,omitempty"`
	PassiveHealthEnabled           bool                              `json:"passive_health_enabled,omitempty"`
	PassiveFailureThreshold        int                               `json:"passive_failure_threshold,omitempty"`
	PassiveUnhealthyStatusCodes    []int                             `json:"passive_unhealthy_status_codes,omitempty"`
	CircuitBreakerEnabled          bool                              `json:"circuit_breaker_enabled,omitempty"`
	CircuitBreakerOpenSec          int                               `json:"circuit_breaker_open_sec,omitempty"`
	CircuitBreakerHalfOpenRequests int                               `json:"circuit_breaker_half_open_requests,omitempty"`

	BufferRequestBody      bool  `json:"buffer_request_body"`
	MaxResponseBufferBytes int64 `json:"max_response_buffer_bytes"`
	FlushIntervalMS        int   `json:"flush_interval_ms"`

	HealthCheckPath              string            `json:"health_check_path"`
	HealthCheckInterval          int               `json:"health_check_interval_sec"`
	HealthCheckTimeout           int               `json:"health_check_timeout_sec"`
	HealthCheckHeaders           map[string]string `json:"health_check_headers,omitempty"`
	HealthCheckExpectedBody      string            `json:"health_check_expected_body,omitempty"`
	HealthCheckExpectedBodyRegex string            `json:"health_check_expected_body_regex,omitempty"`
	ErrorHTMLFile                string            `json:"error_html_file"`
	ErrorRedirectURL             string            `json:"error_redirect_url"`

	responseHeaderSanitizePolicy proxyResponseHeaderSanitizePolicy `json:"-"`
	routeOrder                   []int                             `json:"-"`
	defaultTargetCandidatesReady bool                              `json:"-"`
	defaultTargetCandidates      []proxyRouteTargetCandidate       `json:"-"`
	defaultTargetSelection       proxyRouteTargetSelectionOptions  `json:"-"`
}

type ProxyUpstreamTLSConfig struct {
	ServerName string `json:"server_name,omitempty"`
	CABundle   string `json:"ca_bundle,omitempty"`
	MinVersion string `json:"min_version,omitempty"`
	MaxVersion string `json:"max_version,omitempty"`
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
}

type ProxyUpstream struct {
	Name           string                 `json:"name,omitempty"`
	URL            string                 `json:"url,omitempty"`
	Weight         int                    `json:"weight,omitempty"`
	Enabled        bool                   `json:"enabled"`
	HTTP2Mode      string                 `json:"http2_mode,omitempty"`
	TLS            ProxyUpstreamTLSConfig `json:"tls,omitempty"`
	Discovery      ProxyDiscoveryConfig   `json:"discovery,omitempty"`
	Generated      bool                   `json:"-"`
	GeneratedKind  string                 `json:"-"`
	ProviderClass  string                 `json:"-"`
	ManagedByVhost string                 `json:"-"`
}

type ProxyDiscoveryConfig struct {
	Type               string   `json:"type,omitempty"`
	Hostname           string   `json:"hostname,omitempty"`
	Scheme             string   `json:"scheme,omitempty"`
	Port               int      `json:"port,omitempty"`
	RecordTypes        []string `json:"record_types,omitempty"`
	Service            string   `json:"service,omitempty"`
	Proto              string   `json:"proto,omitempty"`
	Name               string   `json:"name,omitempty"`
	RefreshIntervalSec int      `json:"refresh_interval_sec,omitempty"`
	TimeoutMS          int      `json:"timeout_ms,omitempty"`
	MaxTargets         int      `json:"max_targets,omitempty"`
}

const (
	proxyUpstreamGeneratedKindNone              = ""
	proxyUpstreamGeneratedKindVhostTarget       = "vhost_target"
	proxyUpstreamGeneratedKindVhostLinkedTarget = "vhost_linked_upstream"
	proxyUpstreamGeneratedKindDiscoveredTarget  = "discovered_target"

	proxyUpstreamProviderClassDirect       = "direct"
	proxyUpstreamProviderClassVhostManaged = "vhost_managed"
	proxyUpstreamProviderClassDiscovered   = "discovered"
)

func proxyUpstreamProviderClass(upstream ProxyUpstream) string {
	if strings.TrimSpace(upstream.ProviderClass) != "" {
		return upstream.ProviderClass
	}
	if upstream.Generated {
		return proxyUpstreamProviderClassVhostManaged
	}
	return proxyUpstreamProviderClassDirect
}

func proxyUpstreamIsDirect(upstream ProxyUpstream) bool {
	return proxyUpstreamProviderClass(upstream) == proxyUpstreamProviderClassDirect
}

func proxyUpstreamIsVhostManaged(upstream ProxyUpstream) bool {
	return proxyUpstreamProviderClass(upstream) == proxyUpstreamProviderClassVhostManaged
}

type proxyTransportTLSConfig struct {
	InsecureSkipVerify bool
	CABundle           string
	MinVersion         string
	MaxVersion         string
	ServerName         string
	ClientCert         string
	ClientKey          string
}

type proxyTransportProfile struct {
	HTTP2Mode string
	TLS       proxyTransportTLSConfig
}

type proxyRulesPreparedUpdate struct {
	cfg          ProxyRulesConfig
	effectiveCfg ProxyRulesConfig
	target       *url.URL
	raw          string
	etag         string
	errRes       proxyErrorResponse
}

type proxyRulesValidationOptions struct {
	skipDirectUpstreamDeleteGuard bool
}

type proxyRulesConflictError struct {
	CurrentETag string
}

func (e proxyRulesConflictError) Error() string {
	return "conflict"
}

type proxyRollbackEntry struct {
	Raw       string `json:"raw"`
	ETag      string `json:"etag,omitempty"`
	Timestamp string `json:"timestamp"`
}

type proxyRuntime struct {
	mu            sync.RWMutex
	configPath    string
	raw           string
	etag          string
	cfg           ProxyRulesConfig
	effectiveCfg  ProxyRulesConfig
	target        *url.URL
	proxyEngine   http.Handler
	transport     *dynamicProxyTransport
	health        *upstreamHealthMonitor
	errRes        proxyErrorResponse
	rollbackMax   int
	rollbackStack []proxyRollbackEntry
}

var (
	proxyRuntimeMu sync.RWMutex
	proxyRt        *proxyRuntime
)

func InitProxyRuntime(configPath string, rollbackMax int) error {
	path := strings.TrimSpace(configPath)
	if path == "" {
		return fmt.Errorf("proxy config path is required")
	}
	raw, shouldSeedDB, err := loadProxyRulesStartupRaw(path)
	if err != nil {
		return err
	}
	prepared, err := prepareProxyRulesRaw(raw)
	if err != nil {
		return fmt.Errorf("invalid proxy config (%s): %w", path, err)
	}
	if shouldSeedDB {
		if store := getLogsStatsStore(); store != nil {
			if err := store.UpsertConfigBlob(proxyRulesConfigBlobKey, []byte(prepared.raw), prepared.etag, time.Now().UTC()); err != nil {
				return fmt.Errorf("seed proxy_rules db blob: %w", err)
			}
		}
	}

	health, err := newUpstreamHealthMonitor(prepared.effectiveCfg)
	if err != nil {
		return fmt.Errorf("build upstream health monitor: %w", err)
	}
	transport, err := newDynamicProxyTransport(prepared.effectiveCfg, health)
	if err != nil {
		return fmt.Errorf("build proxy transport: %w", err)
	}
	flushInterval := time.Duration(prepared.effectiveCfg.FlushIntervalMS) * time.Millisecond
	engine, err := newProxyEngine(transport, config.ProxyEngineMode, flushInterval)
	if err != nil {
		return err
	}

	rt := &proxyRuntime{
		configPath:    path,
		raw:           prepared.raw,
		etag:          prepared.etag,
		cfg:           prepared.cfg,
		effectiveCfg:  prepared.effectiveCfg,
		target:        prepared.target,
		proxyEngine:   engine,
		transport:     transport,
		errRes:        prepared.errRes,
		rollbackMax:   clampProxyRollbackMax(rollbackMax),
		rollbackStack: make([]proxyRollbackEntry, 0, clampProxyRollbackMax(rollbackMax)),
	}
	rt.health = health
	setRuntimeProxyAccessLogMode(prepared.effectiveCfg.AccessLogMode)

	proxyRuntimeMu.Lock()
	proxyRt = rt
	proxyRuntimeMu.Unlock()

	emitProxyConfigApplied("proxy transport initialized", prepared.effectiveCfg)
	emitProxyTLSInsecureWarning(prepared.effectiveCfg)
	return nil
}

func loadProxyRulesStartupRaw(path string) (string, bool, error) {
	if store := getLogsStatsStore(); store != nil {
		dbRaw, _, found, err := store.GetConfigBlob(proxyRulesConfigBlobKey)
		if err != nil {
			return "", false, fmt.Errorf("read proxy_rules from db: %w", err)
		}
		if found {
			return string(dbRaw), false, nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", false, fmt.Errorf("read proxy seed file (%s): %w", path, err)
		}
		return string(raw), true, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false, fmt.Errorf("read proxy config (%s): %w", path, err)
	}
	return string(raw), false, nil
}

func rewriteTukuyomiProxyRequest(in *http.Request, out *http.Request) *http.Request {
	if in == nil || out == nil {
		return out
	}
	cfg := currentProxyConfig()
	target := currentProxyTarget()
	selection, selectionOK := proxyRouteTransportSelectionFromContext(in.Context())
	classification, classOK := proxyRouteClassificationFromContext(in.Context())
	if selectionOK && selection.Target != nil {
		target = selection.Target
	}
	if target == nil {
		target, _ = proxyPrimaryTarget(currentProxyConfig())
	}
	rewrittenPath := in.URL.Path
	rewrittenRawPath := in.URL.RawPath
	if classOK {
		rewrittenPath = classification.RewrittenPath
		rewrittenRawPath = classification.RewrittenRawPath
	}
	rewrittenQuery := in.URL.RawQuery
	if classOK {
		rewrittenQuery = classification.RewrittenQuery
	}
	rewriteProxyOutgoingURL(out, target, rewrittenPath, rewrittenRawPath, rewrittenQuery)
	setTukuyomiProxyXForwarded(out.Header, in)
	out.Header.Del(proxyObservabilityUpstreamNameHeader)
	outboundHost := in.Host
	if selectionOK && strings.TrimSpace(selection.RewrittenHost) != "" {
		outboundHost = selection.RewrittenHost
	}
	out.Host = outboundHost
	if classOK || selectionOK {
		if classOK {
			applyProxyRouteHeaders(out.Header, classification.RequestHeaderOps)
		}
		if cfg.EmitUpstreamNameRequestHeader && selectionOK && selection.HealthKey != "" {
			if upstreamName := strings.TrimSpace(selection.SelectedUpstream); upstreamName != "" {
				out.Header.Set(proxyObservabilityUpstreamNameHeader, upstreamName)
			}
		}
		originalCtx := out.Context()
		ctx := originalCtx
		if classOK {
			ctx = withProxyRouteClassification(ctx, classification)
		}
		if selectionOK {
			ctx = withProxyRouteTransportSelection(ctx, selection)
		}
		if selectionOK && selection.HealthKey != "" {
			ctx = withProxySelectedUpstream(ctx, selection.HealthKey)
		}
		if ctx != originalCtx {
			out = out.WithContext(ctx)
		}
	}
	return out
}

func handleProxyRoundTripError(w http.ResponseWriter, r *http.Request, err error) {
	currentProxyErrorResponse().Write(w, r)
	evt := map[string]any{
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
		"service":  "coraza",
		"level":    "ERROR",
		"event":    "proxy_error",
		"path":     requestPath(r),
		"trace_id": observability.TraceIDFromContext(r.Context()),
		"ip":       requestRemoteIP(r),
		"status":   proxyResponseStatus(w, http.StatusBadGateway),
		"error":    err.Error(),
	}
	appendProxyRequestContextLogFields(evt, r)
	appendProxyRouteLogFields(evt, r)
	appendProxyTransferLogFields(evt, r, w)
	emitJSONLogAndAppendEvent(evt)
	log.Printf("[PROXY][ERROR] upstream unavailable method=%s path=%s err=%v", r.Method, r.URL.Path, err)
}

func proxyRuntimeInstance() *proxyRuntime {
	proxyRuntimeMu.RLock()
	defer proxyRuntimeMu.RUnlock()
	return proxyRt
}

func currentProxyTarget() *url.URL {
	rt := proxyRuntimeInstance()
	if rt == nil {
		return nil
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if rt.target == nil {
		return nil
	}
	out := *rt.target
	return &out
}

func currentProxyConfig() ProxyRulesConfig {
	rt := proxyRuntimeInstance()
	if rt == nil {
		return normalizeProxyRulesConfig(ProxyRulesConfig{})
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.effectiveCfg
}

type proxyResponseSanitizeWriter struct {
	http.ResponseWriter
	req     *http.Request
	applied bool
}

func wrapProxyResponseSanitizeWriter(w http.ResponseWriter, req *http.Request) http.ResponseWriter {
	if w == nil || req == nil {
		return w
	}
	if _, ok := w.(*proxyResponseSanitizeWriter); ok {
		return w
	}
	return &proxyResponseSanitizeWriter{ResponseWriter: w, req: req}
}

func (w *proxyResponseSanitizeWriter) ensure() {
	if w.applied {
		return
	}
	w.applied = true
	sanitizeProxyResponseHeaderMapInPlace(w.Header(), w.req, proxyResponseHeaderPolicySurfaceLive)
}

func (w *proxyResponseSanitizeWriter) WriteHeader(statusCode int) {
	if isProxyInformationalResponse(statusCode) {
		sanitizeProxyResponseHeaderMapInPlace(w.Header(), w.req, proxyResponseHeaderPolicySurfaceLive)
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}
	w.ensure()
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *proxyResponseSanitizeWriter) Write(p []byte) (int, error) {
	w.ensure()
	return w.ResponseWriter.Write(p)
}

func (w *proxyResponseSanitizeWriter) Status() int {
	if sw, ok := w.ResponseWriter.(interface{ Status() int }); ok {
		return sw.Status()
	}
	return 0
}

func (w *proxyResponseSanitizeWriter) Size() int {
	if sw, ok := w.ResponseWriter.(interface{ Size() int }); ok {
		return sw.Size()
	}
	return -1
}

func (w *proxyResponseSanitizeWriter) WriteString(s string) (int, error) {
	w.ensure()
	if sw, ok := w.ResponseWriter.(io.StringWriter); ok {
		return sw.WriteString(s)
	}
	return w.ResponseWriter.Write([]byte(s))
}

func (w *proxyResponseSanitizeWriter) ReadFrom(r io.Reader) (int64, error) {
	w.ensure()
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(w.ResponseWriter, r)
}

func (w *proxyResponseSanitizeWriter) Flush() {
	w.ensure()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func isProxyInformationalResponse(statusCode int) bool {
	return statusCode >= 100 && statusCode < 200 && statusCode != http.StatusSwitchingProtocols
}

func (w *proxyResponseSanitizeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.ensure()
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (w *proxyResponseSanitizeWriter) Push(target string, opts *http.PushOptions) error {
	w.ensure()
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func currentProxyErrorResponse() proxyErrorResponse {
	rt := proxyRuntimeInstance()
	if rt == nil {
		resp, _ := newProxyErrorResponse(ProxyRulesConfig{})
		return resp
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.errRes
}

func ServeProxy(w http.ResponseWriter, r *http.Request) {
	rt := proxyRuntimeInstance()
	if rt == nil || rt.proxyEngine == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"proxy runtime is not initialized"}`))
		return
	}
	wrapped := wrapProxyResponseSanitizeWriter(w, r)
	if decision, ok := proxyRouteDecisionFromContext(r.Context()); ok && shouldServeDirectProxyTarget(decision.Target) {
		if err := serveDirectProxyTarget(wrapped, r, decision); err != nil {
			log.Printf("[PROXY][ERROR] direct target unavailable method=%s path=%s err=%v", r.Method, r.URL.Path, err)
			currentProxyErrorResponse().Write(wrapped, r)
		}
		return
	}
	rt.proxyEngine.ServeHTTP(wrapped, r)
}

func ProxyRulesSnapshot() (raw string, etag string, cfg ProxyRulesConfig, health upstreamHealthStatus, rollbackDepth int) {
	rt := proxyRuntimeInstance()
	if rt == nil {
		return "", "", normalizeProxyRulesConfig(ProxyRulesConfig{}), upstreamHealthStatus{Status: "disabled"}, 0
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	health = upstreamHealthStatus{Status: "disabled"}
	if rt.health != nil {
		health = rt.health.Snapshot()
	}
	return rt.raw, rt.etag, rt.cfg, health, len(rt.rollbackStack)
}

func ProxyTransportMetricsSnapshot() proxyTransportMetricsSnapshot {
	rt := proxyRuntimeInstance()
	if rt == nil || rt.health == nil {
		return proxyTransportMetricsSnapshot{
			BucketBounds: append([]float64(nil), proxyTransportLatencyBucketsSeconds...),
		}
	}
	return rt.health.TransportMetricsSnapshot()
}

func ProxyBackendStatusByKey(key string) (upstreamBackendStatus, bool) {
	rt := proxyRuntimeInstance()
	if rt == nil || rt.health == nil || strings.TrimSpace(key) == "" {
		return upstreamBackendStatus{}, false
	}
	return rt.health.BackendStatusByKey(key)
}

func (m *upstreamHealthMonitor) BackendStatusByKey(key string) (upstreamBackendStatus, bool) {
	if m == nil || strings.TrimSpace(key) == "" {
		return upstreamBackendStatus{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, backend := range m.status.Backends {
		if backend.Key == key {
			return backend, true
		}
	}
	return upstreamBackendStatus{}, false
}

func ProxyRollbackPreview() (proxyRollbackEntry, error) {
	rt := proxyRuntimeInstance()
	if rt == nil {
		return proxyRollbackEntry{}, fmt.Errorf("proxy runtime is not initialized")
	}

	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if len(rt.rollbackStack) == 0 {
		return proxyRollbackEntry{}, fmt.Errorf("no rollback snapshot")
	}
	return rt.rollbackStack[len(rt.rollbackStack)-1], nil
}

func ValidateProxyRulesRaw(raw string) (ProxyRulesConfig, error) {
	prepared, err := prepareProxyRulesRaw(raw)
	if err != nil {
		return ProxyRulesConfig{}, err
	}
	return prepared.cfg, nil
}

func ApplyProxyRulesRaw(ifMatch string, raw string) (string, ProxyRulesConfig, error) {
	rt := proxyRuntimeInstance()
	if rt == nil {
		return "", ProxyRulesConfig{}, fmt.Errorf("proxy runtime is not initialized")
	}
	prepared, err := prepareProxyRulesRaw(raw)
	if err != nil {
		return "", ProxyRulesConfig{}, err
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if ifMatch = strings.TrimSpace(ifMatch); ifMatch != "" && ifMatch != rt.etag {
		return "", ProxyRulesConfig{}, proxyRulesConflictError{CurrentETag: rt.etag}
	}

	prevRaw := rt.raw
	prevETag := rt.etag
	prevTarget := rt.target

	if err := persistProxyConfigAuthoritative(rt.configPath, prepared.raw, prepared.etag); err != nil {
		return "", ProxyRulesConfig{}, err
	}
	if err := rt.transport.Update(prepared.effectiveCfg); err != nil {
		_ = persistProxyConfigAuthoritative(rt.configPath, prevRaw, prevETag)
		return "", ProxyRulesConfig{}, err
	}

	rt.raw = prepared.raw
	rt.etag = prepared.etag
	rt.cfg = prepared.cfg
	rt.effectiveCfg = prepared.effectiveCfg
	rt.target = prepared.target
	rt.errRes = prepared.errRes
	setRuntimeProxyAccessLogMode(prepared.effectiveCfg.AccessLogMode)
	flushInterval := time.Duration(prepared.effectiveCfg.FlushIntervalMS) * time.Millisecond
	if setter, ok := rt.proxyEngine.(proxyEngineFlushIntervalSetter); ok {
		setter.SetFlushInterval(flushInterval)
	}
	if rt.health != nil {
		if err := rt.health.Update(prepared.effectiveCfg); err != nil {
			_ = persistProxyConfigAuthoritative(rt.configPath, prevRaw, prevETag)
			return "", ProxyRulesConfig{}, err
		}
	}
	rt.pushRollbackLocked(proxyRollbackEntry{
		Raw:       prevRaw,
		ETag:      prevETag,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})

	emitProxyConfigApplied("proxy rules updated", prepared.effectiveCfg)
	emitProxyTLSInsecureWarning(prepared.effectiveCfg)
	if !proxyURLSame(prevTarget, prepared.target) {
		log.Printf("[PROXY][INFO] upstream changed from=%s to=%s", proxyTargetLabel(prevTarget), proxyTargetLabel(prepared.target))
	}

	return rt.etag, rt.cfg, nil
}

func RollbackProxyRules() (string, ProxyRulesConfig, proxyRollbackEntry, error) {
	rt := proxyRuntimeInstance()
	if rt == nil {
		return "", ProxyRulesConfig{}, proxyRollbackEntry{}, fmt.Errorf("proxy runtime is not initialized")
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if len(rt.rollbackStack) == 0 {
		return "", ProxyRulesConfig{}, proxyRollbackEntry{}, fmt.Errorf("no rollback snapshot")
	}
	entry := rt.rollbackStack[len(rt.rollbackStack)-1]
	rt.rollbackStack = rt.rollbackStack[:len(rt.rollbackStack)-1]

	prepared, err := prepareProxyRulesRaw(entry.Raw)
	if err != nil {
		rt.pushRollbackLocked(entry)
		return "", ProxyRulesConfig{}, proxyRollbackEntry{}, err
	}

	prevRaw := rt.raw
	prevTarget := rt.target

	if err := persistProxyConfigAuthoritative(rt.configPath, prepared.raw, prepared.etag); err != nil {
		rt.pushRollbackLocked(entry)
		return "", ProxyRulesConfig{}, proxyRollbackEntry{}, err
	}
	if err := rt.transport.Update(prepared.effectiveCfg); err != nil {
		_ = persistProxyConfigAuthoritative(rt.configPath, prevRaw, bypassconf.ComputeETag([]byte(prevRaw)))
		rt.pushRollbackLocked(entry)
		return "", ProxyRulesConfig{}, proxyRollbackEntry{}, err
	}

	rt.raw = prepared.raw
	rt.etag = prepared.etag
	rt.cfg = prepared.cfg
	rt.effectiveCfg = prepared.effectiveCfg
	rt.target = prepared.target
	rt.errRes = prepared.errRes
	setRuntimeProxyAccessLogMode(prepared.effectiveCfg.AccessLogMode)
	flushInterval := time.Duration(prepared.effectiveCfg.FlushIntervalMS) * time.Millisecond
	if setter, ok := rt.proxyEngine.(proxyEngineFlushIntervalSetter); ok {
		setter.SetFlushInterval(flushInterval)
	}
	if rt.health != nil {
		if err := rt.health.Update(prepared.effectiveCfg); err != nil {
			_ = persistProxyConfigAuthoritative(rt.configPath, prevRaw, bypassconf.ComputeETag([]byte(prevRaw)))
			rt.pushRollbackLocked(entry)
			return "", ProxyRulesConfig{}, proxyRollbackEntry{}, err
		}
	}

	emitProxyConfigApplied("proxy rules rollback applied", prepared.effectiveCfg)
	emitProxyTLSInsecureWarning(prepared.effectiveCfg)
	if !proxyURLSame(prevTarget, prepared.target) {
		log.Printf("[PROXY][INFO] upstream changed by rollback from=%s to=%s", proxyTargetLabel(prevTarget), proxyTargetLabel(prepared.target))
	}
	return rt.etag, rt.cfg, entry, nil
}

func ProxyProbe(raw string, upstreamName string, timeout time.Duration) (ProxyRulesConfig, string, int64, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if timeout < 100*time.Millisecond {
		timeout = 100 * time.Millisecond
	}
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}

	var cfg ProxyRulesConfig
	var effectiveCfg ProxyRulesConfig
	if strings.TrimSpace(raw) == "" {
		_, _, cfg, _, _ = ProxyRulesSnapshot()
		effectiveCfg = currentProxyConfig()
	} else {
		prepared, err := prepareProxyRulesRawWithSitesAndVhostsOptions(
			raw,
			currentSiteConfig(),
			currentVhostConfig(),
			proxyRulesValidationOptions{skipDirectUpstreamDeleteGuard: true},
		)
		if err != nil {
			return ProxyRulesConfig{}, "", 0, err
		}
		cfg = prepared.cfg
		effectiveCfg = prepared.effectiveCfg
	}

	address, latencyMS, err := probeProxyUpstream(effectiveCfg, strings.TrimSpace(upstreamName), timeout)
	return cfg, address, latencyMS, err
}

func prepareProxyRulesRaw(raw string) (proxyRulesPreparedUpdate, error) {
	return prepareProxyRulesRawWithSitesAndVhosts(raw, currentSiteConfig(), currentVhostConfig())
}

func prepareProxyRulesRawWithSites(raw string, sites SiteConfigFile) (proxyRulesPreparedUpdate, error) {
	return prepareProxyRulesRawWithSitesAndVhosts(raw, sites, currentVhostConfig())
}

func prepareProxyRulesRawWithSitesAndVhosts(raw string, sites SiteConfigFile, vhosts VhostConfigFile) (proxyRulesPreparedUpdate, error) {
	return prepareProxyRulesRawWithSitesAndVhostsOptions(raw, sites, vhosts, proxyRulesValidationOptions{})
}

func prepareProxyRulesRawWithSitesAndVhostsOptions(raw string, sites SiteConfigFile, vhosts VhostConfigFile, opts proxyRulesValidationOptions) (proxyRulesPreparedUpdate, error) {
	cfg, effectiveCfg, target, errRes, err := parseProxyRulesRawWithOptions(raw, sites, vhosts, opts)
	if err != nil {
		return proxyRulesPreparedUpdate{}, err
	}
	normalizedRaw := mustJSON(cfg)
	return proxyRulesPreparedUpdate{
		cfg:          cfg,
		effectiveCfg: effectiveCfg,
		target:       target,
		raw:          normalizedRaw,
		etag:         bypassconf.ComputeETag([]byte(normalizedRaw)),
		errRes:       errRes,
	}, nil
}

func parseProxyRulesRaw(raw string, sites SiteConfigFile, vhosts VhostConfigFile) (ProxyRulesConfig, ProxyRulesConfig, *url.URL, proxyErrorResponse, error) {
	return parseProxyRulesRawWithOptions(raw, sites, vhosts, proxyRulesValidationOptions{})
}

func parseProxyRulesRawWithOptions(raw string, sites SiteConfigFile, vhosts VhostConfigFile, opts proxyRulesValidationOptions) (ProxyRulesConfig, ProxyRulesConfig, *url.URL, proxyErrorResponse, error) {
	var in ProxyRulesConfig
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("invalid json")
	}
	return normalizeAndValidateProxyRulesWithOptions(in, sites, vhosts, opts)
}

func normalizeAndValidateProxyRules(in ProxyRulesConfig, sites SiteConfigFile, vhosts VhostConfigFile) (ProxyRulesConfig, ProxyRulesConfig, *url.URL, proxyErrorResponse, error) {
	return normalizeAndValidateProxyRulesWithOptions(in, sites, vhosts, proxyRulesValidationOptions{})
}

func normalizeAndValidateProxyRulesWithOptions(in ProxyRulesConfig, sites SiteConfigFile, vhosts VhostConfigFile, opts proxyRulesValidationOptions) (ProxyRulesConfig, ProxyRulesConfig, *url.URL, proxyErrorResponse, error) {
	cfg := normalizeProxyRulesConfig(in)
	effectiveCfg := cfg
	if !opts.skipDirectUpstreamDeleteGuard {
		if err := validateProxyDirectUpstreamDeleteGuard(cfg.Upstreams, vhosts); err != nil {
			return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
		}
	}
	linkedBoundUpstreams, err := applyVhostLinkedUpstreamBindings(effectiveCfg.Upstreams, vhosts)
	if err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	effectiveCfg.Upstreams = linkedBoundUpstreams
	mergedUpstreams, err := mergeGeneratedVhostUpstreams(effectiveCfg.Upstreams, generatedVhostUpstreams(vhosts))
	if err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	mergedUpstreams, err = mergeGeneratedVhostUpstreams(mergedUpstreams, siteGeneratedUpstreams(sites))
	if err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	effectiveCfg.Upstreams = mergedUpstreams
	effectiveCfg.Routes = append(append([]ProxyRoute(nil), effectiveCfg.Routes...), siteGeneratedRoutes(sites)...)
	effectiveCfg.routeOrder = sortedProxyRouteIndexes(effectiveCfg.Routes)

	if effectiveCfg.DialTimeout <= 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("dial_timeout must be > 0")
	}
	if effectiveCfg.ResponseHeaderTimeout <= 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("response_header_timeout must be > 0")
	}
	if effectiveCfg.IdleConnTimeout <= 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("idle_conn_timeout must be > 0")
	}
	if effectiveCfg.UpstreamKeepAliveSec <= 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("upstream_keepalive_sec must be > 0")
	}
	if effectiveCfg.MaxIdleConns <= 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("max_idle_conns must be > 0")
	}
	if effectiveCfg.MaxIdleConnsPerHost <= 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("max_idle_conns_per_host must be > 0")
	}
	if effectiveCfg.MaxConnsPerHost <= 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("max_conns_per_host must be > 0")
	}
	if effectiveCfg.ExpectContinueTimeout <= 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("expect_continue_timeout must be > 0")
	}
	if effectiveCfg.MaxResponseBufferBytes < 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("max_response_buffer_bytes must be >= 0")
	}
	if effectiveCfg.FlushIntervalMS < 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("flush_interval_ms must be >= 0")
	}
	if err := validateProxyAccessLogMode(effectiveCfg.AccessLogMode); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if err := validateProxyResponseCompressionConfig(effectiveCfg.ResponseCompression, effectiveCfg.MaxResponseBufferBytes); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if effectiveCfg.RetryAttempts < 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("retry_attempts must be >= 0")
	}
	if effectiveCfg.RetryBackoffMS < 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("retry_backoff_ms must be >= 0")
	}
	if effectiveCfg.RetryPerTryTimeoutMS < 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("retry_per_try_timeout_ms must be >= 0")
	}
	if effectiveCfg.PassiveFailureThreshold < 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("passive_failure_threshold must be >= 0")
	}
	if effectiveCfg.CircuitBreakerOpenSec < 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("circuit_breaker_open_sec must be >= 0")
	}
	if effectiveCfg.CircuitBreakerHalfOpenRequests < 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("circuit_breaker_half_open_requests must be >= 0")
	}
	if effectiveCfg.HealthCheckInterval <= 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("health_check_interval_sec must be > 0")
	}
	if effectiveCfg.HealthCheckTimeout <= 0 {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("health_check_timeout_sec must be > 0")
	}
	if effectiveCfg.HealthCheckPath != "" && !strings.HasPrefix(effectiveCfg.HealthCheckPath, "/") {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("health_check_path must start with '/'")
	}
	if effectiveCfg.HealthCheckPath == "" {
		if len(effectiveCfg.HealthCheckHeaders) > 0 {
			return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("health_check_headers requires health_check_path")
		}
		if effectiveCfg.HealthCheckExpectedBody != "" {
			return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("health_check_expected_body requires health_check_path")
		}
		if effectiveCfg.HealthCheckExpectedBodyRegex != "" {
			return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("health_check_expected_body_regex requires health_check_path")
		}
	}
	if err := validateProxyHealthCheckConfig(effectiveCfg); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if err := validateProxyUpstreams(effectiveCfg); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if effectiveCfg.ErrorHTMLFile != "" && effectiveCfg.ErrorRedirectURL != "" {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("error_html_file and error_redirect_url are mutually exclusive")
	}
	if err := validateProxyResponseHeaderSanitizeConfig(effectiveCfg.ResponseHeaderSanitize); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if err := validateProxyHashPolicy(effectiveCfg.HashPolicy, effectiveCfg.HashKey, "hash_policy"); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if err := validateProxyRetryStatusCodes(effectiveCfg.RetryStatusCodes, "retry_status_codes"); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if err := validateProxyRetryMethods(effectiveCfg.RetryMethods, "retry_methods"); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if err := validateProxyRetryConfiguration(effectiveCfg); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if err := validateProxyPassiveCircuitConfiguration(effectiveCfg); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if proxyRulesHasGlobalTLSConfig(effectiveCfg) && !proxyRulesHasHTTPSUpstream(effectiveCfg) {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, fmt.Errorf("global upstream TLS settings require at least one https upstream")
	}
	if err := validateProxyHTTP2Configuration(effectiveCfg); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if err := validateProxyRoutes(effectiveCfg); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	target, err := proxyPreparedPrimaryTarget(effectiveCfg)
	if err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if _, err := proxyTransportProfileCatalog(effectiveCfg); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	if err := precomputeProxyStaticFallbackTargets(&effectiveCfg); err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	errRes, err := newProxyErrorResponse(effectiveCfg)
	if err != nil {
		return ProxyRulesConfig{}, ProxyRulesConfig{}, nil, proxyErrorResponse{}, err
	}
	return cfg, effectiveCfg, target, errRes, nil
}

func validateProxyDirectUpstreamDeleteGuard(nextUpstreams []ProxyUpstream, vhosts VhostConfigFile) error {
	if len(vhosts.Vhosts) == 0 {
		return nil
	}
	_, _, currentCfg, _, _ := ProxyRulesSnapshot()
	if len(currentCfg.Upstreams) == 0 {
		return nil
	}
	currentDirect := make(map[string]struct{}, len(currentCfg.Upstreams))
	for _, upstream := range currentCfg.Upstreams {
		name := strings.TrimSpace(upstream.Name)
		if name == "" || !proxyUpstreamIsDirect(upstream) {
			continue
		}
		currentDirect[name] = struct{}{}
	}
	if len(currentDirect) == 0 {
		return nil
	}
	nextDirect := make(map[string]struct{}, len(nextUpstreams))
	for _, upstream := range nextUpstreams {
		name := strings.TrimSpace(upstream.Name)
		if name == "" || !proxyUpstreamIsDirect(upstream) {
			continue
		}
		nextDirect[name] = struct{}{}
	}
	for _, vhost := range vhosts.Vhosts {
		name := strings.TrimSpace(vhost.LinkedUpstreamName)
		if name == "" {
			continue
		}
		if _, bound := currentDirect[name]; !bound {
			continue
		}
		if _, stillPresent := nextDirect[name]; stillPresent {
			continue
		}
		return fmt.Errorf("upstreams removes %q while vhost %q still binds to that direct upstream", name, vhost.Name)
	}
	return nil
}

func normalizeProxyRulesConfig(in ProxyRulesConfig) ProxyRulesConfig {
	out := in
	if out.DialTimeout == 0 {
		out.DialTimeout = defaultProxyDialTimeoutSec
	}
	if out.ResponseHeaderTimeout == 0 {
		out.ResponseHeaderTimeout = defaultProxyResponseHeaderTimeoutSec
	}
	if out.IdleConnTimeout == 0 {
		out.IdleConnTimeout = defaultProxyIdleConnTimeoutSec
	}
	if out.UpstreamKeepAliveSec == 0 {
		out.UpstreamKeepAliveSec = defaultProxyUpstreamKeepAliveSec
	}
	if out.MaxIdleConns == 0 {
		out.MaxIdleConns = defaultProxyMaxIdleConns
	}
	if out.MaxIdleConnsPerHost == 0 {
		out.MaxIdleConnsPerHost = defaultProxyMaxIdleConnsPerHost
	}
	if out.MaxConnsPerHost == 0 {
		out.MaxConnsPerHost = defaultProxyMaxConnsPerHost
	}
	if out.ExpectContinueTimeout == 0 {
		out.ExpectContinueTimeout = defaultProxyExpectContinueSec
	}
	out.TLSCABundle = strings.TrimSpace(out.TLSCABundle)
	out.TLSMinVersion = normalizeProxyTLSVersion(out.TLSMinVersion)
	out.TLSMaxVersion = normalizeProxyTLSVersion(out.TLSMaxVersion)
	out.TLSClientCert = strings.TrimSpace(out.TLSClientCert)
	out.TLSClientKey = strings.TrimSpace(out.TLSClientKey)
	out.ErrorHTMLFile = strings.TrimSpace(out.ErrorHTMLFile)
	out.ErrorRedirectURL = strings.TrimSpace(out.ErrorRedirectURL)
	out.ResponseHeaderSanitize = normalizeProxyResponseHeaderSanitizeConfig(out.ResponseHeaderSanitize)
	out.ResponseCompression = normalizeProxyResponseCompressionConfig(out.ResponseCompression)
	out.AccessLogMode = normalizeProxyAccessLogMode(out.AccessLogMode)
	out.LoadBalancingStrategy = normalizeProxyLoadBalancingStrategy(out.LoadBalancingStrategy)
	out.HashPolicy = normalizeProxyHashPolicy(out.HashPolicy)
	out.HashKey = strings.TrimSpace(out.HashKey)
	out.RetryStatusCodes = normalizeProxyStatusCodeList(out.RetryStatusCodes)
	out.RetryMethods = normalizeProxyMethodList(out.RetryMethods)
	out.PassiveUnhealthyStatusCodes = normalizeProxyStatusCodeList(out.PassiveUnhealthyStatusCodes)
	out.Upstreams = normalizeProxyUpstreams(out.Upstreams)
	out.BackendPools = normalizeProxyBackendPools(out.BackendPools)
	out.Routes = normalizeProxyRoutes(out.Routes)
	out.routeOrder = sortedProxyRouteIndexes(out.Routes)
	out.DefaultRoute = normalizeProxyDefaultRoute(out.DefaultRoute)
	out.HealthCheckPath = normalizeProxyHealthCheckPath(out.HealthCheckPath)
	out.HealthCheckHeaders = normalizeProxyHealthCheckHeaders(out.HealthCheckHeaders)
	out.HealthCheckExpectedBody = strings.TrimSpace(out.HealthCheckExpectedBody)
	out.HealthCheckExpectedBodyRegex = strings.TrimSpace(out.HealthCheckExpectedBodyRegex)
	if out.HealthCheckInterval == 0 {
		out.HealthCheckInterval = defaultProxyHealthCheckIntervalSec
	}
	if out.HealthCheckTimeout == 0 {
		out.HealthCheckTimeout = defaultProxyHealthCheckTimeoutSec
	}
	out.responseHeaderSanitizePolicy = buildProxyResponseHeaderSanitizePolicy(out.ResponseHeaderSanitize)
	return out
}

func reloadProxyRuntimeWithSites(sites SiteConfigFile) error {
	return reloadProxyRuntimeWithSitesAndVhosts(sites, currentVhostConfig())
}

func reloadProxyRuntimeWithSitesAndVhosts(sites SiteConfigFile, vhosts VhostConfigFile) error {
	rt := proxyRuntimeInstance()
	if rt == nil {
		return nil
	}
	prepared, err := prepareProxyRulesRawWithSitesAndVhosts(rt.raw, sites, vhosts)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if err := rt.transport.Update(prepared.effectiveCfg); err != nil {
		return err
	}
	rt.effectiveCfg = prepared.effectiveCfg
	rt.target = prepared.target
	rt.errRes = prepared.errRes
	setRuntimeProxyAccessLogMode(prepared.effectiveCfg.AccessLogMode)
	flushInterval := time.Duration(prepared.effectiveCfg.FlushIntervalMS) * time.Millisecond
	if setter, ok := rt.proxyEngine.(proxyEngineFlushIntervalSetter); ok {
		setter.SetFlushInterval(flushInterval)
	}
	if rt.health != nil {
		if err := rt.health.Update(prepared.effectiveCfg); err != nil {
			return err
		}
	}
	emitProxyConfigApplied("proxy runtime refreshed from site config", prepared.effectiveCfg)
	emitProxyTLSInsecureWarning(prepared.effectiveCfg)
	return nil
}

func normalizeProxyHealthCheckPath(v string) string {
	x := strings.TrimSpace(v)
	if x == "" {
		return ""
	}
	if !strings.HasPrefix(x, "/") {
		x = "/" + x
	}
	return x
}

func normalizeProxyTLSVersion(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "default":
		return ""
	case "tls1.2", "1.2", "tls12", "1_2":
		return "tls1.2"
	case "tls1.3", "1.3", "tls13", "1_3":
		return "tls1.3"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func parseProxyTLSVersion(v string, field string) (uint16, error) {
	switch normalizeProxyTLSVersion(v) {
	case "":
		return 0, nil
	case "tls1.2":
		return tls.VersionTLS12, nil
	case "tls1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("%s must be tls1.2 or tls1.3", field)
	}
}

func normalizeProxyHealthCheckHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for name, value := range in {
		nextName := canonicalProxyRouteHeaderName(name)
		if nextName == "" {
			continue
		}
		out[nextName] = strings.TrimSpace(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validateProxyHealthCheckConfig(cfg ProxyRulesConfig) error {
	for name, value := range cfg.HealthCheckHeaders {
		if err := validateProxyRouteHeaderName(name, nil, "health_check_headers"); err != nil {
			return fmt.Errorf("health_check_headers.%s: %w", name, err)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("health_check_headers.%s: header value must not contain CR or LF", name)
		}
	}
	if cfg.HealthCheckExpectedBody != "" && cfg.HealthCheckExpectedBodyRegex != "" {
		return fmt.Errorf("health_check_expected_body and health_check_expected_body_regex are mutually exclusive")
	}
	if cfg.HealthCheckExpectedBodyRegex != "" {
		if _, err := regexp.Compile(cfg.HealthCheckExpectedBodyRegex); err != nil {
			return fmt.Errorf("health_check_expected_body_regex: %w", err)
		}
	}
	return nil
}

func validateProxyUpstreams(cfg ProxyRulesConfig) error {
	for i, upstream := range cfg.Upstreams {
		field := fmt.Sprintf("upstreams[%d]", i)
		if strings.TrimSpace(upstream.Name) == "" {
			return fmt.Errorf("%s.name is required", field)
		}
		if upstream.Weight <= 0 {
			return fmt.Errorf("%s.weight must be > 0", field)
		}
		hasURL := strings.TrimSpace(upstream.URL) != ""
		hasDiscovery := proxyUpstreamDiscoveryEnabled(upstream)
		switch {
		case hasURL && hasDiscovery:
			return fmt.Errorf("%s.url conflicts with %s.discovery", field, field)
		case !hasURL && !hasDiscovery:
			return fmt.Errorf("%s.url or %s.discovery is required", field, field)
		case hasURL:
			if _, err := parseProxyUpstreamURL(field+".url", upstream.URL); err != nil {
				return err
			}
		case hasDiscovery:
			if err := validateProxyDiscoveryConfig(upstream.Discovery, field+".discovery"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateProxyDiscoveryConfig(cfg ProxyDiscoveryConfig, field string) error {
	switch cfg.Type {
	case "dns":
		if err := validateProxyDiscoveryHostname(cfg.Hostname, field+".hostname"); err != nil {
			return err
		}
		if cfg.Port <= 0 || cfg.Port > 65535 {
			return fmt.Errorf("%s.port must be between 1 and 65535", field)
		}
		if len(cfg.RecordTypes) == 0 {
			return fmt.Errorf("%s.record_types must contain A or AAAA", field)
		}
		for i, recordType := range cfg.RecordTypes {
			switch strings.ToUpper(strings.TrimSpace(recordType)) {
			case "A", "AAAA":
			default:
				return fmt.Errorf("%s.record_types[%d] must be A or AAAA", field, i)
			}
		}
	case "dns_srv":
		if err := validateProxyDiscoveryToken(cfg.Service, field+".service"); err != nil {
			return err
		}
		if cfg.Proto != "tcp" {
			return fmt.Errorf("%s.proto must be tcp", field)
		}
		if err := validateProxyDiscoveryHostname(cfg.Name, field+".name"); err != nil {
			return err
		}
	case "":
		return nil
	default:
		return fmt.Errorf("%s.type must be dns or dns_srv", field)
	}
	switch cfg.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("%s.scheme must be http or https", field)
	}
	if cfg.RefreshIntervalSec < 1 || cfg.RefreshIntervalSec > maxProxyDiscoveryRefreshSec {
		return fmt.Errorf("%s.refresh_interval_sec must be between 1 and %d", field, maxProxyDiscoveryRefreshSec)
	}
	if cfg.TimeoutMS < 50 || cfg.TimeoutMS > maxProxyDiscoveryTimeoutMS {
		return fmt.Errorf("%s.timeout_ms must be between 50 and %d", field, maxProxyDiscoveryTimeoutMS)
	}
	if cfg.MaxTargets < 1 || cfg.MaxTargets > maxProxyDiscoveryTargets {
		return fmt.Errorf("%s.max_targets must be between 1 and %d", field, maxProxyDiscoveryTargets)
	}
	return nil
}

func validateProxyDiscoveryHostname(value string, field string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > 253 {
		return fmt.Errorf("%s must be <= 253 characters", field)
	}
	if strings.ContainsAny(value, " \t\r\n/\\?#:@[]") {
		return fmt.Errorf("%s must be a DNS name without whitespace, port, path, query, or fragment", field)
	}
	if strings.Contains(value, "://") {
		return fmt.Errorf("%s must not include scheme", field)
	}
	trimmed := strings.TrimSuffix(value, ".")
	if trimmed == "" {
		return fmt.Errorf("%s is required", field)
	}
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" {
			return fmt.Errorf("%s contains an empty DNS label", field)
		}
		if len(label) > 63 {
			return fmt.Errorf("%s labels must be <= 63 characters", field)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("%s labels must not start or end with hyphen", field)
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("%s contains an invalid DNS label character", field)
		}
	}
	return nil
}

func validateProxyDiscoveryToken(value string, field string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > 63 {
		return fmt.Errorf("%s must be <= 63 characters", field)
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("%s contains an invalid character", field)
	}
	return nil
}

func normalizeProxyUpstreamTLSConfig(in ProxyUpstreamTLSConfig) ProxyUpstreamTLSConfig {
	out := in
	out.ServerName = strings.TrimSpace(out.ServerName)
	out.CABundle = strings.TrimSpace(out.CABundle)
	out.MinVersion = normalizeProxyTLSVersion(out.MinVersion)
	out.MaxVersion = normalizeProxyTLSVersion(out.MaxVersion)
	out.ClientCert = strings.TrimSpace(out.ClientCert)
	out.ClientKey = strings.TrimSpace(out.ClientKey)
	return out
}

func validateProxyTransportTLSConfig(cfg proxyTransportTLSConfig, field string) error {
	if (cfg.ClientCert == "") != (cfg.ClientKey == "") {
		return fmt.Errorf("%s client_cert and client_key must be set together", field)
	}
	minVersion, err := parseProxyTLSVersion(cfg.MinVersion, field+".min_version")
	if err != nil {
		return err
	}
	maxVersion, err := parseProxyTLSVersion(cfg.MaxVersion, field+".max_version")
	if err != nil {
		return err
	}
	if minVersion != 0 && maxVersion != 0 && minVersion > maxVersion {
		return fmt.Errorf("%s min_version must be <= max_version", field)
	}
	return nil
}

func normalizeProxyLoadBalancingStrategy(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "round_robin":
		return "round_robin"
	case "least_conn":
		return "least_conn"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func normalizeProxyHTTP2Mode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", proxyHTTP2ModeDefault:
		return proxyHTTP2ModeDefault
	case proxyHTTP2ModeForceAttempt, "force_http2":
		return proxyHTTP2ModeForceAttempt
	case proxyHTTP2ModeH2C, "h2c":
		return proxyHTTP2ModeH2C
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func validateProxyHTTP2Mode(mode string, field string) error {
	switch normalizeProxyHTTP2Mode(mode) {
	case proxyHTTP2ModeDefault, proxyHTTP2ModeForceAttempt, proxyHTTP2ModeH2C:
		return nil
	default:
		return fmt.Errorf("%s must be one of default|force_attempt|h2c_prior_knowledge", field)
	}
}

func proxyGlobalHTTP2Mode(cfg ProxyRulesConfig) string {
	if cfg.H2CUpstream {
		return proxyHTTP2ModeH2C
	}
	if cfg.ForceHTTP2 {
		return proxyHTTP2ModeForceAttempt
	}
	return proxyHTTP2ModeDefault
}

func proxyConfiguredHTTP2Mode(cfg ProxyRulesConfig, explicit string) string {
	mode := normalizeProxyHTTP2Mode(explicit)
	if mode == proxyHTTP2ModeDefault {
		return proxyGlobalHTTP2Mode(cfg)
	}
	return mode
}

func normalizeProxyUpstreams(in []ProxyUpstream) []ProxyUpstream {
	if len(in) == 0 {
		return nil
	}
	out := make([]ProxyUpstream, 0, len(in))
	enabledCount := 0
	for i, upstream := range in {
		next := upstream
		next.Name = strings.TrimSpace(next.Name)
		next.URL = strings.TrimSpace(next.URL)
		next.HTTP2Mode = normalizeProxyHTTP2Mode(next.HTTP2Mode)
		next.TLS = normalizeProxyUpstreamTLSConfig(next.TLS)
		next.Discovery = normalizeProxyDiscoveryConfig(next.Discovery)
		next.ProviderClass = proxyUpstreamProviderClass(next)
		if next.ProviderClass != proxyUpstreamProviderClassVhostManaged {
			next.ManagedByVhost = ""
		}
		if next.Weight <= 0 {
			next.Weight = 1
		}
		if next.Name == "" {
			next.Name = fmt.Sprintf("upstream-%d", i+1)
		}
		if next.Enabled {
			enabledCount++
		}
		out = append(out, next)
	}
	if enabledCount == 0 {
		for i := range out {
			out[i].Enabled = true
		}
	}
	return out
}

func normalizeProxyDiscoveryConfig(in ProxyDiscoveryConfig) ProxyDiscoveryConfig {
	out := in
	out.Type = strings.ToLower(strings.TrimSpace(out.Type))
	out.Hostname = strings.TrimSpace(out.Hostname)
	out.Scheme = strings.ToLower(strings.TrimSpace(out.Scheme))
	if proxyDiscoveryEnabled(out) && out.Scheme == "" {
		out.Scheme = "http"
	}
	out.Service = strings.TrimSpace(out.Service)
	out.Proto = strings.ToLower(strings.TrimSpace(out.Proto))
	if out.Type == "dns_srv" && out.Proto == "" {
		out.Proto = "tcp"
	}
	out.Name = strings.TrimSpace(out.Name)
	out.RecordTypes = normalizeProxyDiscoveryRecordTypes(out.RecordTypes)
	if out.Type == "dns" && len(out.RecordTypes) == 0 {
		out.RecordTypes = []string{"A", "AAAA"}
	}
	if proxyDiscoveryEnabled(out) && out.RefreshIntervalSec == 0 {
		out.RefreshIntervalSec = defaultProxyDiscoveryRefreshSec
	}
	if proxyDiscoveryEnabled(out) && out.TimeoutMS == 0 {
		out.TimeoutMS = defaultProxyDiscoveryTimeoutMS
	}
	if proxyDiscoveryEnabled(out) && out.MaxTargets == 0 {
		out.MaxTargets = defaultProxyDiscoveryMaxTargets
	}
	return out
}

func normalizeProxyDiscoveryRecordTypes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		next := strings.ToUpper(strings.TrimSpace(raw))
		switch next {
		case "A", "AAAA":
		default:
			next = strings.ToUpper(strings.TrimSpace(raw))
		}
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

func proxyDiscoveryEnabled(cfg ProxyDiscoveryConfig) bool {
	return strings.TrimSpace(cfg.Type) != ""
}

func proxyUpstreamDiscoveryEnabled(upstream ProxyUpstream) bool {
	return proxyDiscoveryEnabled(upstream.Discovery)
}

func mergeGeneratedVhostUpstreams(existing []ProxyUpstream, generated []ProxyUpstream) ([]ProxyUpstream, error) {
	out := append([]ProxyUpstream(nil), existing...)
	seen := make(map[string]struct{}, len(existing))
	for _, upstream := range existing {
		if upstream.Name != "" {
			seen[upstream.Name] = struct{}{}
		}
	}
	for _, upstream := range generated {
		if upstream.Name == "" {
			continue
		}
		if _, ok := seen[upstream.Name]; ok {
			continue
		}
		upstream.Generated = true
		seen[upstream.Name] = struct{}{}
		out = append(out, upstream)
	}
	return out, nil
}

func applyVhostLinkedUpstreamBindings(existing []ProxyUpstream, vhosts VhostConfigFile) ([]ProxyUpstream, error) {
	if len(vhosts.Vhosts) == 0 {
		return append([]ProxyUpstream(nil), existing...), nil
	}
	out := append([]ProxyUpstream(nil), existing...)
	byName := make(map[string]int, len(out))
	for i, upstream := range out {
		name := strings.TrimSpace(upstream.Name)
		if name == "" {
			continue
		}
		byName[name] = i
	}
	boundNames := make(map[string]string, len(vhosts.Vhosts))
	for _, vhost := range vhosts.Vhosts {
		name := strings.TrimSpace(vhost.LinkedUpstreamName)
		if name == "" {
			continue
		}
		idx, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("vhost %q linked_upstream_name %q must reference a configured upstream", vhost.Name, name)
		}
		if owner, exists := boundNames[name]; exists && owner != vhost.Name {
			return nil, fmt.Errorf("configured upstream %q is already bound by vhost %q", name, owner)
		}
		targetURL, ok, err := vhostLinkedUpstreamTargetURL(vhost, out[idx], idx)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("vhost %q mode %q cannot bind linked upstream", vhost.Name, vhost.Mode)
		}
		next := out[idx]
		next.URL = targetURL
		next.ProviderClass = proxyUpstreamProviderClassVhostManaged
		next.GeneratedKind = proxyUpstreamGeneratedKindVhostLinkedTarget
		next.ManagedByVhost = vhost.Name
		out[idx] = next
		boundNames[name] = vhost.Name
	}
	return out, nil
}

func parseProxyUpstreamURL(field, raw string) (*url.URL, error) {
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%s parse error: %w", field, err)
	}
	scheme := strings.ToLower(strings.TrimSpace(target.Scheme))
	switch scheme {
	case "http", "https", "static":
		if target.Host == "" {
			return nil, fmt.Errorf("%s must include scheme and host", field)
		}
	case "fcgi":
		if target.Host == "" && strings.TrimSpace(target.Path) == "" {
			return nil, fmt.Errorf("%s must include host:port or /unix.sock path", field)
		}
	default:
		return nil, fmt.Errorf("%s scheme must be http, https, fcgi, or static", field)
	}
	return target, nil
}

func proxyPrimaryTarget(cfg ProxyRulesConfig) (*url.URL, error) {
	upstreams := proxyConfiguredUpstreams(cfg)
	if len(upstreams) == 0 {
		if target, ok, err := proxyRouteFallbackTarget(cfg); err != nil {
			return nil, err
		} else if ok {
			return target, nil
		}
		return nil, fmt.Errorf("no explicit upstream or route target is configured")
	}
	var firstEnabled *url.URL
	hasEnabledDiscovery := false
	for i, upstream := range upstreams {
		if proxyUpstreamDiscoveryEnabled(upstream) {
			if upstream.Enabled {
				hasEnabledDiscovery = true
			}
			continue
		}
		target, err := parseProxyUpstreamURL(fmt.Sprintf("upstreams[%d].url", i), upstream.URL)
		if err != nil {
			return nil, err
		}
		if upstream.Weight <= 0 {
			return nil, fmt.Errorf("upstreams[%d].weight must be > 0", i)
		}
		if upstream.Enabled && firstEnabled == nil {
			firstEnabled = target
		}
	}
	if firstEnabled != nil {
		return firstEnabled, nil
	}
	if hasEnabledDiscovery {
		return nil, nil
	}
	return nil, fmt.Errorf("at least one upstream must be enabled")
}

func proxyPreparedPrimaryTarget(cfg ProxyRulesConfig) (*url.URL, error) {
	if len(proxyConfiguredUpstreams(cfg)) == 0 {
		if target, ok, err := proxyRouteFallbackTarget(cfg); err != nil {
			return nil, err
		} else if ok {
			return target, nil
		}
		return nil, nil
	}
	return proxyPrimaryTarget(cfg)
}

func proxyRulesHasHTTPSUpstream(cfg ProxyRulesConfig) bool {
	for _, upstream := range cfg.Upstreams {
		if !upstream.Enabled {
			continue
		}
		if proxyUpstreamDiscoveryEnabled(upstream) {
			if strings.EqualFold(upstream.Discovery.Scheme, "https") {
				return true
			}
			continue
		}
		target, err := url.Parse(strings.TrimSpace(upstream.URL))
		if err == nil && strings.EqualFold(target.Scheme, "https") {
			return true
		}
	}
	return false
}

func proxyRulesHasGlobalTLSConfig(cfg ProxyRulesConfig) bool {
	return cfg.TLSInsecureSkipVerify ||
		strings.TrimSpace(cfg.TLSCABundle) != "" ||
		strings.TrimSpace(cfg.TLSMinVersion) != "" ||
		strings.TrimSpace(cfg.TLSMaxVersion) != "" ||
		strings.TrimSpace(cfg.TLSClientCert) != "" ||
		strings.TrimSpace(cfg.TLSClientKey) != ""
}

func proxyUpstreamHasTLSConfig(upstream ProxyUpstream) bool {
	tlsCfg := upstream.TLS
	return strings.TrimSpace(tlsCfg.ServerName) != "" ||
		strings.TrimSpace(tlsCfg.CABundle) != "" ||
		strings.TrimSpace(tlsCfg.MinVersion) != "" ||
		strings.TrimSpace(tlsCfg.MaxVersion) != "" ||
		strings.TrimSpace(tlsCfg.ClientCert) != "" ||
		strings.TrimSpace(tlsCfg.ClientKey) != ""
}

func proxyRulesConfiguredTargets(cfg ProxyRulesConfig) ([]*url.URL, error) {
	targets := make([]*url.URL, 0)
	addTarget := func(field, raw string) error {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil
		}
		target, err := parseProxyUpstreamURL(field, raw)
		if err != nil {
			return err
		}
		targets = append(targets, target)
		return nil
	}

	if len(cfg.Upstreams) > 0 {
		for i, upstream := range cfg.Upstreams {
			if !upstream.Enabled {
				continue
			}
			if proxyUpstreamDiscoveryEnabled(upstream) {
				continue
			}
			if err := addTarget(fmt.Sprintf("upstreams[%d].url", i), upstream.URL); err != nil {
				return nil, err
			}
		}
	}
	return targets, nil
}

func proxyRulesHasExplicitHTTP2Overrides(cfg ProxyRulesConfig) bool {
	for _, upstream := range cfg.Upstreams {
		if normalizeProxyHTTP2Mode(upstream.HTTP2Mode) != proxyHTTP2ModeDefault {
			return true
		}
	}
	if cfg.DefaultRoute != nil {
		if normalizeProxyHTTP2Mode(cfg.DefaultRoute.Action.UpstreamHTTP2Mode) != proxyHTTP2ModeDefault {
			return true
		}
		if normalizeProxyHTTP2Mode(cfg.DefaultRoute.Action.CanaryUpstreamHTTP2Mode) != proxyHTTP2ModeDefault {
			return true
		}
	}
	for _, route := range cfg.Routes {
		if normalizeProxyHTTP2Mode(route.Action.UpstreamHTTP2Mode) != proxyHTTP2ModeDefault {
			return true
		}
		if normalizeProxyHTTP2Mode(route.Action.CanaryUpstreamHTTP2Mode) != proxyHTTP2ModeDefault {
			return true
		}
	}
	return false
}

func resolveProxyHTTP2ValidationTarget(cfg ProxyRulesConfig, ref string, field string) (*url.URL, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, nil
	}
	matchCount := 0
	for i, upstream := range cfg.Upstreams {
		if upstream.Name != ref {
			continue
		}
		matchCount++
		if matchCount > 1 {
			return nil, fmt.Errorf("%s references duplicated upstream name %q", field, ref)
		}
		if !proxyUpstreamAllowedAsRouteTarget(upstream) {
			return nil, fmt.Errorf("%s must reference a configured upstream name", field)
		}
		if proxyUpstreamDiscoveryEnabled(upstream) {
			return &url.URL{Scheme: upstream.Discovery.Scheme}, nil
		}
		target, err := parseProxyUpstreamURL(fmt.Sprintf("upstreams[%d].url", i), upstream.URL)
		if err != nil {
			return nil, err
		}
		return target, nil
	}
	return nil, nil
}

func validateProxyHTTP2ModeTarget(cfg ProxyRulesConfig, ref string, explicitMode string, field string) error {
	mode := proxyConfiguredHTTP2Mode(cfg, explicitMode)
	if mode != proxyHTTP2ModeH2C {
		return nil
	}
	target, err := resolveProxyHTTP2ValidationTarget(cfg, ref, field)
	if err != nil {
		return err
	}
	if target == nil {
		return nil
	}
	if !strings.EqualFold(target.Scheme, "http") {
		return fmt.Errorf("%s with http2_mode=h2c_prior_knowledge requires an http upstream", field)
	}
	return nil
}

func validateProxyHTTP2Configuration(cfg ProxyRulesConfig) error {
	if err := validateProxyTransportTLSConfig(proxyTransportTLSConfig{
		InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
		CABundle:           cfg.TLSCABundle,
		MinVersion:         cfg.TLSMinVersion,
		MaxVersion:         cfg.TLSMaxVersion,
		ClientCert:         cfg.TLSClientCert,
		ClientKey:          cfg.TLSClientKey,
	}, "tls"); err != nil {
		return err
	}
	for i, upstream := range cfg.Upstreams {
		if !upstream.Enabled {
			continue
		}
		if err := validateProxyTransportTLSConfig(proxyTransportTLSConfig{
			ServerName: upstream.TLS.ServerName,
			CABundle:   upstream.TLS.CABundle,
			MinVersion: upstream.TLS.MinVersion,
			MaxVersion: upstream.TLS.MaxVersion,
			ClientCert: upstream.TLS.ClientCert,
			ClientKey:  upstream.TLS.ClientKey,
		}, fmt.Sprintf("upstreams[%d].tls", i)); err != nil {
			return err
		}
		if err := validateProxyHTTP2Mode(upstream.HTTP2Mode, fmt.Sprintf("upstreams[%d].http2_mode", i)); err != nil {
			return err
		}
		if proxyUpstreamHasTLSConfig(upstream) {
			if proxyUpstreamDiscoveryEnabled(upstream) {
				if !strings.EqualFold(upstream.Discovery.Scheme, "https") {
					return fmt.Errorf("upstreams[%d].tls requires an https upstream", i)
				}
			} else {
				target, err := parseProxyUpstreamURL(fmt.Sprintf("upstreams[%d].url", i), upstream.URL)
				if err != nil {
					return err
				}
				if !strings.EqualFold(target.Scheme, "https") {
					return fmt.Errorf("upstreams[%d].tls requires an https upstream", i)
				}
			}
		}
		mode := proxyConfiguredHTTP2Mode(cfg, upstream.HTTP2Mode)
		if mode == proxyHTTP2ModeH2C {
			if proxyUpstreamDiscoveryEnabled(upstream) {
				if !strings.EqualFold(upstream.Discovery.Scheme, "http") {
					return fmt.Errorf("upstreams[%d].http2_mode=h2c_prior_knowledge requires an http upstream", i)
				}
				continue
			}
			target, err := parseProxyUpstreamURL(fmt.Sprintf("upstreams[%d].url", i), upstream.URL)
			if err != nil {
				return err
			}
			if !strings.EqualFold(target.Scheme, "http") {
				return fmt.Errorf("upstreams[%d].http2_mode=h2c_prior_knowledge requires an http upstream", i)
			}
		}
	}
	if cfg.H2CUpstream && proxyRulesHasExplicitHTTP2Overrides(cfg) {
		return fmt.Errorf("h2c_upstream cannot be combined with per-upstream http2_mode overrides")
	}
	if cfg.DefaultRoute != nil && proxyRouteEnabled(cfg.DefaultRoute.Enabled) {
		if err := validateProxyHTTP2ModeTarget(cfg, cfg.DefaultRoute.Action.Upstream, cfg.DefaultRoute.Action.UpstreamHTTP2Mode, "default_route.action.upstream"); err != nil {
			return err
		}
		if err := validateProxyHTTP2ModeTarget(cfg, cfg.DefaultRoute.Action.CanaryUpstream, cfg.DefaultRoute.Action.CanaryUpstreamHTTP2Mode, "default_route.action.canary_upstream"); err != nil {
			return err
		}
	}
	for i, route := range cfg.Routes {
		if !proxyRouteEnabled(route.Enabled) {
			continue
		}
		if err := validateProxyHTTP2ModeTarget(cfg, route.Action.Upstream, route.Action.UpstreamHTTP2Mode, fmt.Sprintf("routes[%d].action.upstream", i)); err != nil {
			return err
		}
		if err := validateProxyHTTP2ModeTarget(cfg, route.Action.CanaryUpstream, route.Action.CanaryUpstreamHTTP2Mode, fmt.Sprintf("routes[%d].action.canary_upstream", i)); err != nil {
			return err
		}
	}
	if !cfg.H2CUpstream {
		return nil
	}
	for _, upstream := range cfg.Upstreams {
		if !upstream.Enabled || !proxyUpstreamDiscoveryEnabled(upstream) {
			continue
		}
		if !strings.EqualFold(upstream.Discovery.Scheme, "http") {
			return fmt.Errorf("h2c_upstream requires all configured upstreams to use http")
		}
		if proxyUpstreamHasTLSConfig(upstream) {
			return fmt.Errorf("h2c_upstream cannot be combined with upstream TLS settings")
		}
	}
	targets, err := proxyRulesConfiguredTargets(cfg)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if target == nil {
			continue
		}
		if !strings.EqualFold(target.Scheme, "http") {
			return fmt.Errorf("h2c_upstream requires all configured upstreams to use http")
		}
	}
	if proxyRulesHasGlobalTLSConfig(cfg) {
		return fmt.Errorf("h2c_upstream cannot be combined with upstream TLS settings")
	}
	return nil
}

func proxyUpstreamHTTP2Mode(cfg ProxyRulesConfig) string {
	return proxyGlobalHTTP2Mode(cfg)
}

func proxyGlobalTransportProfile(cfg ProxyRulesConfig, explicitMode string) proxyTransportProfile {
	return proxyConfiguredUpstreamTransportProfile(cfg, nil, explicitMode)
}

func proxyConfiguredUpstreamTransportProfile(cfg ProxyRulesConfig, upstream *ProxyUpstream, explicitMode string) proxyTransportProfile {
	mode := explicitMode
	if upstream != nil && strings.TrimSpace(mode) == "" {
		mode = upstream.HTTP2Mode
	}
	profile := proxyTransportProfile{
		HTTP2Mode: proxyConfiguredHTTP2Mode(cfg, mode),
		TLS: proxyTransportTLSConfig{
			InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
			CABundle:           cfg.TLSCABundle,
			MinVersion:         cfg.TLSMinVersion,
			MaxVersion:         cfg.TLSMaxVersion,
			ClientCert:         cfg.TLSClientCert,
			ClientKey:          cfg.TLSClientKey,
		},
	}
	if upstream == nil {
		return profile
	}
	if next := strings.TrimSpace(upstream.TLS.ServerName); next != "" {
		profile.TLS.ServerName = next
	}
	if next := strings.TrimSpace(upstream.TLS.CABundle); next != "" {
		profile.TLS.CABundle = next
	}
	if next := strings.TrimSpace(upstream.TLS.MinVersion); next != "" {
		profile.TLS.MinVersion = next
	}
	if next := strings.TrimSpace(upstream.TLS.MaxVersion); next != "" {
		profile.TLS.MaxVersion = next
	}
	if next := strings.TrimSpace(upstream.TLS.ClientCert); next != "" {
		profile.TLS.ClientCert = next
	}
	if next := strings.TrimSpace(upstream.TLS.ClientKey); next != "" {
		profile.TLS.ClientKey = next
	}
	return profile
}

func proxyTransportKey(profile proxyTransportProfile) string {
	raw, err := json.Marshal(profile)
	if err != nil {
		return normalizeProxyHTTP2Mode(profile.HTTP2Mode)
	}
	return string(raw)
}

func normalizeProxyTransportTLSConfig(cfg proxyTransportTLSConfig) proxyTransportTLSConfig {
	cfg.CABundle = strings.TrimSpace(cfg.CABundle)
	cfg.MinVersion = normalizeProxyTLSVersion(cfg.MinVersion)
	cfg.MaxVersion = normalizeProxyTLSVersion(cfg.MaxVersion)
	cfg.ServerName = strings.TrimSpace(cfg.ServerName)
	cfg.ClientCert = strings.TrimSpace(cfg.ClientCert)
	cfg.ClientKey = strings.TrimSpace(cfg.ClientKey)
	return cfg
}

func normalizeProxyTransportProfile(profile proxyTransportProfile) proxyTransportProfile {
	profile.HTTP2Mode = normalizeProxyHTTP2Mode(profile.HTTP2Mode)
	profile.TLS = normalizeProxyTransportTLSConfig(profile.TLS)
	return profile
}

func proxyTransportProfileFromKey(key string) (proxyTransportProfile, bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return proxyTransportProfile{}, false
	}
	var profile proxyTransportProfile
	if err := json.Unmarshal([]byte(key), &profile); err != nil {
		return proxyTransportProfile{}, false
	}
	return normalizeProxyTransportProfile(profile), true
}

func proxyTransportTLSSpecificity(cfg proxyTransportTLSConfig) int {
	score := 0
	if cfg.CABundle != "" {
		score++
	}
	if cfg.MinVersion != "" {
		score++
	}
	if cfg.MaxVersion != "" {
		score++
	}
	if cfg.ServerName != "" {
		score++
	}
	if cfg.ClientCert != "" {
		score++
	}
	if cfg.ClientKey != "" {
		score++
	}
	return score
}

func proxySelectTransportByMode(profiles map[string]proxyTransportProfile, transports map[string]http.RoundTripper, desired proxyTransportProfile, mode string) http.RoundTripper {
	mode = normalizeProxyHTTP2Mode(mode)
	if mode == "" {
		mode = proxyHTTP2ModeDefault
	}
	desired = normalizeProxyTransportProfile(desired)
	if rt, ok := transports[proxyTransportKey(desired)]; ok && rt != nil {
		return rt
	}
	bestKey := ""
	bestScore := -1 << 30
	keys := make([]string, 0, len(profiles))
	for key := range profiles {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		profile := normalizeProxyTransportProfile(profiles[key])
		if normalizeProxyHTTP2Mode(profile.HTTP2Mode) != mode {
			continue
		}
		rt := transports[key]
		if rt == nil {
			continue
		}
		score := 0
		if profile.TLS.InsecureSkipVerify == desired.TLS.InsecureSkipVerify {
			score += 32
		}
		if profile.TLS.CABundle == desired.TLS.CABundle {
			score += 16
		}
		if profile.TLS.MinVersion == desired.TLS.MinVersion {
			score += 8
		}
		if profile.TLS.MaxVersion == desired.TLS.MaxVersion {
			score += 8
		}
		if profile.TLS.ServerName == desired.TLS.ServerName {
			score += 16
		}
		if profile.TLS.ClientCert == desired.TLS.ClientCert {
			score += 12
		}
		if profile.TLS.ClientKey == desired.TLS.ClientKey {
			score += 12
		}
		score -= proxyTransportTLSSpecificity(profile.TLS)
		if bestKey == "" || score > bestScore {
			bestKey = key
			bestScore = score
		}
	}
	if bestKey != "" {
		return transports[bestKey]
	}
	return nil
}

func proxyTransportProfileCatalog(cfg ProxyRulesConfig) (map[string]proxyTransportProfile, error) {
	out := make(map[string]proxyTransportProfile)
	addProfile := func(profile proxyTransportProfile) {
		out[proxyTransportKey(profile)] = profile
	}
	addProfile(proxyGlobalTransportProfile(cfg, proxyHTTP2ModeDefault))
	addProfile(proxyGlobalTransportProfile(cfg, proxyHTTP2ModeForceAttempt))
	addProfile(proxyGlobalTransportProfile(cfg, proxyHTTP2ModeH2C))
	for i := range cfg.Upstreams {
		profile := proxyConfiguredUpstreamTransportProfile(cfg, &cfg.Upstreams[i], cfg.Upstreams[i].HTTP2Mode)
		addProfile(profile)
	}
	for key, profile := range out {
		if _, err := buildProxyTransportFromProfile(cfg, profile); err != nil {
			return nil, fmt.Errorf("transport profile %q: %w", key, err)
		}
	}
	return out, nil
}

func closeIdleProxyRoundTripper(rt http.RoundTripper) {
	if closer, ok := rt.(interface{ CloseIdleConnections() }); ok && closer != nil {
		closer.CloseIdleConnections()
	}
}

func closeIdleProxyTransportSet(transports map[string]http.RoundTripper) {
	if len(transports) == 0 {
		return
	}
	seen := map[http.RoundTripper]struct{}{}
	for _, rt := range transports {
		if rt == nil {
			continue
		}
		if _, ok := seen[rt]; ok {
			continue
		}
		seen[rt] = struct{}{}
		closeIdleProxyRoundTripper(rt)
	}
}

func persistProxyConfigRaw(path string, raw string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("proxy config path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return bypassconf.AtomicWriteWithBackup(path, []byte(raw))
}

func persistProxyConfigAuthoritative(path string, raw string, etag string) error {
	if store := getLogsStatsStore(); store != nil {
		if strings.TrimSpace(etag) == "" {
			etag = bypassconf.ComputeETag([]byte(raw))
		}
		return store.UpsertConfigBlob(proxyRulesConfigBlobKey, []byte(raw), etag, time.Now().UTC())
	}
	return persistProxyConfigRaw(path, raw)
}

func mustJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b) + "\n"
}

func clampProxyRollbackMax(v int) int {
	if v <= 0 {
		return 8
	}
	if v > 64 {
		return 64
	}
	return v
}

func (rt *proxyRuntime) pushRollbackLocked(entry proxyRollbackEntry) {
	if strings.TrimSpace(entry.Raw) == "" {
		return
	}
	if rt.rollbackMax <= 0 {
		return
	}
	rt.rollbackStack = append(rt.rollbackStack, entry)
	if len(rt.rollbackStack) > rt.rollbackMax {
		trim := len(rt.rollbackStack) - rt.rollbackMax
		rt.rollbackStack = append([]proxyRollbackEntry(nil), rt.rollbackStack[trim:]...)
	}
}

func proxyURLSame(a, b *url.URL) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.String() == b.String()
}

func safeProxyURL(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "-"
	}
	return v
}

func proxyTargetLabel(target *url.URL) string {
	if target == nil {
		return "-"
	}
	if value := strings.TrimSpace(target.String()); value != "" {
		return value
	}
	return "-"
}

func safeProxyValue(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "-"
	}
	return v
}

func emitProxyConfigApplied(msg string, cfg ProxyRulesConfig) {
	log.Printf("[PROXY][INFO] %s proxy_engine_mode=%s upstream=%s upstream_count=%d strategy=%s force_http2=%t h2c_upstream=%t disable_compression=%t expose_waf_debug_headers=%t emit_upstream_name_request_header=%t response_compression_enabled=%t response_compression_algorithms=%s response_compression_min_bytes=%d response_compression_mime_types=%d upstream_keepalive_sec=%d expect_continue_timeout=%ds buffer_request_body=%t max_response_buffer_bytes=%d flush_interval_ms=%d health_check_path=%s health_check_interval_sec=%d health_check_timeout_sec=%d error_html_file=%s error_redirect_url=%s response_header_sanitize_mode=%s response_header_sanitize_remove=%d response_header_sanitize_keep=%d response_header_sanitize_debug=%t tls_insecure_skip_verify=%t mtls=%t", msg, normalizeProxyEngineMode(config.ProxyEngineMode), proxyDisplayUpstream(cfg), len(proxyConfiguredUpstreams(cfg)), cfg.LoadBalancingStrategy, cfg.ForceHTTP2, cfg.H2CUpstream, cfg.DisableCompression, cfg.ExposeWAFDebugHeaders, cfg.EmitUpstreamNameRequestHeader, cfg.ResponseCompression.Enabled, strings.Join(cfg.ResponseCompression.Algorithms, ","), cfg.ResponseCompression.MinBytes, len(cfg.ResponseCompression.MIMETypes), cfg.UpstreamKeepAliveSec, cfg.ExpectContinueTimeout, cfg.BufferRequestBody, cfg.MaxResponseBufferBytes, cfg.FlushIntervalMS, cfg.HealthCheckPath, cfg.HealthCheckInterval, cfg.HealthCheckTimeout, safeProxyValue(cfg.ErrorHTMLFile), safeProxyValue(cfg.ErrorRedirectURL), cfg.ResponseHeaderSanitize.Mode, len(cfg.ResponseHeaderSanitize.CustomRemove), len(cfg.ResponseHeaderSanitize.CustomKeep), cfg.ResponseHeaderSanitize.DebugLog, cfg.TLSInsecureSkipVerify, cfg.TLSClientCert != "")
}

func emitProxyTLSInsecureWarning(cfg ProxyRulesConfig) {
	if !cfg.TLSInsecureSkipVerify {
		return
	}
	log.Printf("[PROXY][WARN] tls_insecure_skip_verify=true: backend TLS certificate verification is disabled")
}

type dynamicProxyTransport struct {
	mu         sync.RWMutex
	profiles   map[string]proxyTransportProfile
	transports map[string]http.RoundTripper
	tracker    *upstreamHealthMonitor
}

func newDynamicProxyTransport(cfg ProxyRulesConfig, tracker *upstreamHealthMonitor) (*dynamicProxyTransport, error) {
	profiles, err := proxyTransportProfileCatalog(cfg)
	if err != nil {
		return nil, err
	}
	transports, err := buildProxyTransportSet(cfg, profiles)
	if err != nil {
		return nil, err
	}
	return &dynamicProxyTransport{profiles: profiles, transports: transports, tracker: tracker}, nil
}

func cloneProxyTransportRequestWithContext(req *http.Request, ctx context.Context) *http.Request {
	out := req.WithContext(ctx)
	out.Header = cloneProxyHeaderMapForMutation(req.Header, 2)
	return out
}

func cloneProxyRetryBaseRequest(req *http.Request, ctx context.Context) *http.Request {
	if ctx == nil {
		ctx = req.Context()
	}
	if req.Form != nil || req.PostForm != nil || req.MultipartForm != nil {
		return req.Clone(ctx)
	}
	out := req.WithContext(ctx)
	out.URL = cloneURL(req.URL)
	out.Header = cloneProxyHeaderMap(req.Header)
	out.Trailer = cloneProxyHeaderMap(req.Trailer)
	if req.TransferEncoding != nil {
		out.TransferEncoding = append([]string(nil), req.TransferEncoding...)
	}
	return out
}

func cloneProxyHeaderMapForMutation(src http.Header, extra int) http.Header {
	if src == nil {
		return make(http.Header, extra)
	}
	dst := make(http.Header, len(src)+extra)
	for name, values := range src {
		dst[name] = values
	}
	return dst
}

func cloneProxyHeaderMap(src http.Header) http.Header {
	if src == nil {
		return nil
	}
	dst := make(http.Header, len(src))
	for name, values := range src {
		dst[name] = values
	}
	return dst
}

func (d *dynamicProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	d.mu.RLock()
	profiles := d.profiles
	transports := d.transports
	tracker := d.tracker
	d.mu.RUnlock()
	var metrics *proxyTransportMetrics
	if tracker != nil {
		metrics = tracker.metrics
	}
	baseCtx := req.Context()
	ctx := baseCtx
	var span oteltrace.Span
	traceUpstream := observability.TracingEnabled()
	if traceUpstream {
		tracer := otel.Tracer("tukuyomi/upstream")
		ctx, span = tracer.Start(
			baseCtx,
			"proxy.upstream",
			oteltrace.WithSpanKind(oteltrace.SpanKindClient),
			oteltrace.WithAttributes(
				attribute.String("http.request.method", req.Method),
				attribute.String("server.address", req.URL.Host),
				attribute.String("url.full", req.URL.String()),
			),
		)
	}
	classification, _ := proxyRouteClassificationFromContext(baseCtx)
	selection, _ := proxyRouteTransportSelectionFromContext(baseCtx)
	targets := selection.OrderedTargets
	if len(targets) == 0 && selection.Target != nil {
		targets = []proxyRouteTargetCandidate{{
			Key:          selection.HealthKey,
			Name:         selection.SelectedUpstream,
			Target:       cloneURL(selection.Target),
			Weight:       1,
			Managed:      selection.HealthKey != "",
			HTTP2Mode:    normalizeProxyHTTP2Mode(selection.SelectedHTTP2Mode),
			TransportKey: selection.SelectedTransportKey,
		}}
	}
	retryPolicy := classification.RetryPolicy
	maxAttempts := 1
	if retryPolicy.Enabled() && retryPolicy.AllowsMethod(req.Method) {
		maxAttempts += retryPolicy.Attempts
	}
	if len(targets) > 0 && len(targets) < maxAttempts {
		maxAttempts = len(targets)
	}
	if len(targets) == 0 {
		rt := proxyRoundTripperForCandidate(profiles, transports, "", selection.SelectedTransportKey, selection.SelectedHTTP2Mode)
		outReq := req
		if traceUpstream {
			outReq = cloneProxyTransportRequestWithContext(req, ctx)
			otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(outReq.Header))
		}
		resp, err := rt.RoundTrip(outReq)
		endProxyTransportSpan(span, resp, err)
		return resp, err
	}
	if !traceUpstream && len(targets) == 1 && maxAttempts == 1 && proxyOutgoingRequestMatchesCandidate(req, classification, targets[0]) {
		return roundTripSingleProxyTargetFast(req, targets[0], selection, profiles, transports, tracker, metrics, retryPolicy)
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		candidate := targets[attempt]
		if normalizeProxyHTTP2Mode(candidate.HTTP2Mode) == proxyHTTP2ModeDefault && selection.SelectedHTTP2Mode != "" {
			candidate.HTTP2Mode = selection.SelectedHTTP2Mode
		}
		attemptReq, cancel, err := cloneProxyRetryRequest(req, ctx, classification, candidate, attempt, retryPolicy)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			lastErr = err
			break
		}
		if tracker != nil && candidate.Key != "" && !tracker.AcquireTarget(candidate.Key) {
			if cancel != nil {
				cancel()
			}
			if metrics != nil {
				metrics.RecordError(candidate.Name, candidate.Target, candidate.Managed, proxyTransportErrorKindUnavailable)
				if attempt+1 < maxAttempts {
					metrics.RecordRetry(candidate.Name, candidate.Target, candidate.Managed, proxyTransportRetryReasonUnavailable)
				}
			}
			lastErr = fmt.Errorf("backend unavailable for retry target %q", candidate.Name)
			continue
		}

		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(attemptReq.Header))
		attemptStarted := time.Now()
		attemptRT := proxyRoundTripperForCandidate(profiles, transports, candidate.TransportKey, selection.SelectedTransportKey, candidate.HTTP2Mode)
		resp, err := attemptRT.RoundTrip(attemptReq)
		if metrics != nil {
			metrics.RecordAttempt(candidate.Name, candidate.Target, candidate.Managed, time.Since(attemptStarted))
		}
		if err != nil {
			if tracker != nil && candidate.Key != "" {
				tracker.RecordPassiveFailure(candidate.Key, 0, err)
				tracker.ReleaseTarget(candidate.Key)
			}
			if metrics != nil {
				metrics.RecordError(candidate.Name, candidate.Target, candidate.Managed, proxyTransportErrorKindTransport)
				if attempt+1 < maxAttempts && retryPolicy.Enabled() {
					metrics.RecordRetry(candidate.Name, candidate.Target, candidate.Managed, proxyTransportRetryReasonTransport)
				}
			}
			if cancel != nil {
				cancel()
			}
			lastErr = err
			if attempt+1 < maxAttempts && retryPolicy.Enabled() {
				if retryPolicy.Backoff > 0 {
					time.Sleep(retryPolicy.Backoff)
				}
				continue
			}
			endProxyTransportSpan(span, nil, err)
			return nil, err
		}

		passiveUnhealthyStatus := retryPolicy.PassiveUnhealthyStatus(resp.StatusCode)
		statusCountsAsError := retryPolicy.StatusCountsAsError(resp.StatusCode)
		shouldRetryStatus := retryPolicy.Enabled() && attempt+1 < maxAttempts && retryPolicy.RetryableStatus(resp.StatusCode)
		if shouldRetryStatus {
			if tracker != nil && candidate.Key != "" {
				if passiveUnhealthyStatus {
					tracker.RecordPassiveFailure(candidate.Key, resp.StatusCode, nil)
				} else {
					tracker.RecordPassiveSuccess(candidate.Key, resp.StatusCode)
				}
				tracker.ReleaseTarget(candidate.Key)
			}
			if metrics != nil {
				metrics.RecordError(candidate.Name, candidate.Target, candidate.Managed, proxyTransportErrorKindStatus)
				metrics.RecordRetry(candidate.Name, candidate.Target, candidate.Managed, proxyTransportRetryReasonStatus)
			}
			if resp.Body != nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
				_ = resp.Body.Close()
			}
			if cancel != nil {
				cancel()
			}
			if retryPolicy.Backoff > 0 {
				time.Sleep(retryPolicy.Backoff)
			}
			lastErr = fmt.Errorf("retryable status code: %d", resp.StatusCode)
			continue
		}

		if tracker != nil && candidate.Key != "" {
			if passiveUnhealthyStatus {
				tracker.RecordPassiveFailure(candidate.Key, resp.StatusCode, nil)
			} else {
				tracker.RecordPassiveSuccess(candidate.Key, resp.StatusCode)
			}
		}
		if metrics != nil && statusCountsAsError {
			metrics.RecordError(candidate.Name, candidate.Target, candidate.Managed, proxyTransportErrorKindStatus)
		}
		if resp == nil || resp.Body == nil {
			if tracker != nil && candidate.Key != "" {
				tracker.ReleaseTarget(candidate.Key)
			}
			if cancel != nil {
				cancel()
			}
			endProxyTransportSpan(span, resp, nil)
			return resp, nil
		}
		resp.Body = &proxyTrackedReadCloser{
			ReadCloser: resp.Body,
			release: func() {
				if tracker != nil && candidate.Key != "" {
					tracker.ReleaseTarget(candidate.Key)
				}
				if cancel != nil {
					cancel()
				}
			},
			span: span,
		}
		return resp, nil
	}
	endProxyTransportSpan(span, nil, lastErr)
	return nil, lastErr
}

func proxyOutgoingRequestMatchesCandidate(req *http.Request, classification proxyRouteClassification, candidate proxyRouteTargetCandidate) bool {
	if req == nil || req.URL == nil || candidate.Target == nil {
		return false
	}
	if classification.RewrittenPath == "" {
		return false
	}
	expectedReqURL := url.URL{
		Path:     classification.RewrittenPath,
		RawPath:  classification.RewrittenRawPath,
		RawQuery: classification.RewrittenQuery,
	}
	expectedPath, expectedRawPath := joinProxyURLPath(candidate.Target, &expectedReqURL)
	expectedQuery := expectedReqURL.RawQuery
	if candidate.Target.RawQuery != "" {
		if expectedQuery == "" {
			expectedQuery = candidate.Target.RawQuery
		} else {
			expectedQuery = candidate.Target.RawQuery + "&" + expectedQuery
		}
	}
	expectedHost := resolveProxyRouteForwardedHost(classification.OriginalHost, candidate.Target.Host, classification.RewrittenHost, classification.Source)
	return req.URL.Scheme == candidate.Target.Scheme &&
		req.URL.Host == candidate.Target.Host &&
		req.URL.Path == expectedPath &&
		req.URL.RawPath == expectedRawPath &&
		req.URL.RawQuery == expectedQuery &&
		strings.TrimSpace(req.Host) == expectedHost
}

func roundTripSingleProxyTargetFast(req *http.Request, candidate proxyRouteTargetCandidate, selection proxyRouteTransportSelection, profiles map[string]proxyTransportProfile, transports map[string]http.RoundTripper, tracker *upstreamHealthMonitor, metrics *proxyTransportMetrics, retryPolicy proxyRetryPolicy) (*http.Response, error) {
	if normalizeProxyHTTP2Mode(candidate.HTTP2Mode) == proxyHTTP2ModeDefault && selection.SelectedHTTP2Mode != "" {
		candidate.HTTP2Mode = selection.SelectedHTTP2Mode
	}
	if tracker != nil && candidate.Key != "" && !tracker.AcquireTarget(candidate.Key) {
		if metrics != nil {
			metrics.RecordError(candidate.Name, candidate.Target, candidate.Managed, proxyTransportErrorKindUnavailable)
		}
		return nil, fmt.Errorf("backend unavailable for retry target %q", candidate.Name)
	}

	attemptStarted := time.Now()
	attemptRT := proxyRoundTripperForCandidate(profiles, transports, candidate.TransportKey, selection.SelectedTransportKey, candidate.HTTP2Mode)
	resp, err := attemptRT.RoundTrip(req)
	if metrics != nil {
		metrics.RecordAttempt(candidate.Name, candidate.Target, candidate.Managed, time.Since(attemptStarted))
	}
	if err != nil {
		if tracker != nil && candidate.Key != "" {
			tracker.RecordPassiveFailure(candidate.Key, 0, err)
			tracker.ReleaseTarget(candidate.Key)
		}
		if metrics != nil {
			metrics.RecordError(candidate.Name, candidate.Target, candidate.Managed, proxyTransportErrorKindTransport)
		}
		return nil, err
	}

	passiveUnhealthyStatus := resp != nil && retryPolicy.PassiveUnhealthyStatus(resp.StatusCode)
	statusCountsAsError := resp != nil && retryPolicy.StatusCountsAsError(resp.StatusCode)
	if tracker != nil && candidate.Key != "" {
		if passiveUnhealthyStatus {
			tracker.RecordPassiveFailure(candidate.Key, resp.StatusCode, nil)
		} else if resp != nil {
			tracker.RecordPassiveSuccess(candidate.Key, resp.StatusCode)
		}
	}
	if metrics != nil && statusCountsAsError {
		metrics.RecordError(candidate.Name, candidate.Target, candidate.Managed, proxyTransportErrorKindStatus)
	}
	if resp == nil || resp.Body == nil {
		if tracker != nil && candidate.Key != "" {
			tracker.ReleaseTarget(candidate.Key)
		}
		return resp, nil
	}
	if tracker != nil && candidate.Key != "" {
		resp.Body = &proxyTrackedReadCloser{
			ReadCloser: resp.Body,
			release: func() {
				tracker.ReleaseTarget(candidate.Key)
			},
		}
	}
	return resp, nil
}

func (d *dynamicProxyTransport) Update(cfg ProxyRulesConfig) error {
	if d == nil {
		return nil
	}
	profiles, err := proxyTransportProfileCatalog(cfg)
	if err != nil {
		return err
	}
	transports, err := buildProxyTransportSet(cfg, profiles)
	if err != nil {
		return err
	}
	d.mu.Lock()
	old := d.transports
	d.profiles = profiles
	d.transports = transports
	d.mu.Unlock()
	closeIdleProxyTransportSet(old)
	return nil
}

type proxyTrackedReadCloser struct {
	io.ReadCloser
	once    sync.Once
	release func()
	span    oteltrace.Span
}

func cloneProxyRetryRequest(req *http.Request, ctx context.Context, classification proxyRouteClassification, candidate proxyRouteTargetCandidate, attempt int, retryPolicy proxyRetryPolicy) (*http.Request, context.CancelFunc, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("request is required")
	}
	out := cloneProxyRetryBaseRequest(req, ctx)
	if attempt > 0 && req.Body != nil {
		if req.GetBody == nil {
			return nil, nil, fmt.Errorf("request body is not rewindable for retry")
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, nil, err
		}
		out.Body = body
	}
	if out.URL == nil {
		out.URL = &url.URL{}
	}
	rewriteProxyOutgoingURL(out, candidate.Target, classification.RewrittenPath, classification.RewrittenRawPath, classification.RewrittenQuery)
	out.Host = resolveProxyRouteForwardedHost(classification.OriginalHost, candidate.Target.Host, classification.RewrittenHost, classification.Source)
	var cancel context.CancelFunc
	if retryPolicy.PerTryTimeout > 0 {
		ctx, nextCancel := context.WithTimeout(out.Context(), retryPolicy.PerTryTimeout)
		out = out.WithContext(ctx)
		cancel = nextCancel
	}
	return out, cancel, nil
}

func (r *proxyTrackedReadCloser) Close() error {
	if r == nil || r.ReadCloser == nil {
		return nil
	}
	err := r.ReadCloser.Close()
	r.once.Do(func() {
		if r.release != nil {
			r.release()
		}
		if r.span != nil {
			r.span.End()
		}
	})
	return err
}

func (r *proxyTrackedReadCloser) Write(p []byte) (int, error) {
	if rw, ok := r.ReadCloser.(io.Writer); ok {
		return rw.Write(p)
	}
	return 0, fmt.Errorf("response body does not support write")
}

func endProxyTransportSpan(span oteltrace.Span, resp *http.Response, err error) {
	if span == nil {
		return
	}
	if resp != nil {
		span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End()
}

func buildProxyTransport(cfg ProxyRulesConfig) http.RoundTripper {
	rt, err := buildProxyTransportFromProfile(cfg, proxyGlobalTransportProfile(cfg, proxyGlobalHTTP2Mode(cfg)))
	if err != nil || rt == nil {
		if err == nil {
			err = fmt.Errorf("nil proxy transport")
		}
		return proxyStaticErrorTransport{err: fmt.Errorf("proxy transport initialization failed: %w", err)}
	}
	return rt
}

func buildProxyTransportSet(cfg ProxyRulesConfig, profiles map[string]proxyTransportProfile) (map[string]http.RoundTripper, error) {
	out := make(map[string]http.RoundTripper, len(profiles))
	for key, profile := range profiles {
		rt, err := buildProxyTransportFromProfile(cfg, profile)
		if err != nil {
			closeIdleProxyTransportSet(out)
			return nil, err
		}
		out[key] = rt
	}
	return out, nil
}

func buildProxyTransportFromProfile(cfg ProxyRulesConfig, profile proxyTransportProfile) (http.RoundTripper, error) {
	switch normalizeProxyHTTP2Mode(profile.HTTP2Mode) {
	case proxyHTTP2ModeForceAttempt:
		return buildProxyNativeHTTP2Transport(cfg, profile, proxyHTTP2ModeForceAttempt)
	case proxyHTTP2ModeH2C:
		return buildProxyNativeHTTP2Transport(cfg, profile, proxyHTTP2ModeH2C)
	default:
		return buildProxyNativeHTTP1Transport(cfg, profile)
	}
}

func proxyRoundTripperForCandidate(profiles map[string]proxyTransportProfile, transports map[string]http.RoundTripper, transportKey string, fallbackKey string, mode string) http.RoundTripper {
	if transportKey != "" {
		if rt, ok := transports[transportKey]; ok && rt != nil {
			return rt
		}
	}
	if fallbackKey != "" {
		if rt, ok := transports[fallbackKey]; ok && rt != nil {
			return rt
		}
	}
	fallbackProfile := normalizeProxyTransportProfile(proxyTransportProfile{HTTP2Mode: normalizeProxyHTTP2Mode(mode)})
	if profile, ok := proxyTransportProfileFromKey(transportKey); ok {
		fallbackProfile = profile
	}
	if profile, ok := proxyTransportProfileFromKey(fallbackKey); ok {
		fallbackProfile = profile
	}
	if rt := proxySelectTransportByMode(profiles, transports, fallbackProfile, fallbackProfile.HTTP2Mode); rt != nil {
		return rt
	}
	for _, rt := range transports {
		if rt != nil {
			return rt
		}
	}
	return proxyStaticErrorTransport{err: fmt.Errorf("proxy transport is not available for mode %q", mode)}
}

type proxyStaticErrorTransport struct {
	err error
}

func (t proxyStaticErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if t.err != nil {
		return nil, t.err
	}
	return nil, fmt.Errorf("proxy transport is not available")
}

func proxyUpstreamKeepAliveDuration(cfg ProxyRulesConfig) time.Duration {
	sec := cfg.UpstreamKeepAliveSec
	if sec <= 0 {
		sec = defaultProxyUpstreamKeepAliveSec
	}
	return time.Duration(sec) * time.Second
}

func buildProxyTLSClientConfigForProfile(profile proxyTransportTLSConfig) (*tls.Config, error) {
	certPath := strings.TrimSpace(profile.ClientCert)
	keyPath := strings.TrimSpace(profile.ClientKey)
	if (certPath == "") != (keyPath == "") {
		return nil, fmt.Errorf("tls_client_cert and tls_client_key must be set together")
	}
	caBundle := strings.TrimSpace(profile.CABundle)
	minVersion, err := parseProxyTLSVersion(profile.MinVersion, "tls_min_version")
	if err != nil {
		return nil, err
	}
	maxVersion, err := parseProxyTLSVersion(profile.MaxVersion, "tls_max_version")
	if err != nil {
		return nil, err
	}
	serverName := strings.TrimSpace(profile.ServerName)
	if certPath == "" && caBundle == "" && minVersion == 0 && maxVersion == 0 && serverName == "" && !profile.InsecureSkipVerify {
		return nil, nil
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: profile.InsecureSkipVerify}
	if minVersion != 0 {
		tlsCfg.MinVersion = minVersion
	}
	if maxVersion != 0 {
		tlsCfg.MaxVersion = maxVersion
	}
	if serverName != "" {
		tlsCfg.ServerName = serverName
	}
	if caBundle != "" {
		raw, err := os.ReadFile(caBundle)
		if err != nil {
			return nil, fmt.Errorf("load proxy tls ca bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("load proxy tls ca bundle: no certificates found")
		}
		tlsCfg.RootCAs = pool
	}
	if certPath == "" {
		return tlsCfg, nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load proxy tls client certificate: %w", err)
	}
	tlsCfg.Certificates = []tls.Certificate{cert}
	return tlsCfg, nil
}

func maybeBufferProxyRequestBody(req *http.Request) error {
	cfg := currentProxyConfig()
	if !cfg.BufferRequestBody || req == nil || req.Body == nil {
		return nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	req.ContentLength = int64(len(body))
	return nil
}

func maybeBufferProxyResponseBody(res *http.Response) error {
	cfg := currentProxyConfig()
	if cfg.MaxResponseBufferBytes <= 0 || res == nil || res.Body == nil {
		return nil
	}
	if isDirectStaticResponse(res) {
		return nil
	}
	if res.ContentLength > cfg.MaxResponseBufferBytes && res.ContentLength > 0 {
		return fmt.Errorf("upstream response exceeds max_response_buffer_bytes")
	}
	lr := io.LimitReader(res.Body, cfg.MaxResponseBufferBytes+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		return err
	}
	if int64(len(body)) > cfg.MaxResponseBufferBytes {
		return fmt.Errorf("upstream response exceeds max_response_buffer_bytes")
	}
	_ = res.Body.Close()
	res.Body = io.NopCloser(bytes.NewReader(body))
	res.ContentLength = int64(len(body))
	if res.Header != nil {
		res.Header.Set("Content-Length", strconv.FormatInt(res.ContentLength, 10))
	}
	return nil
}

func probeProxyUpstream(in ProxyRulesConfig, upstreamName string, timeout time.Duration) (string, int64, error) {
	target, err := proxyProbeTarget(in, upstreamName)
	if err != nil {
		return "", 0, err
	}
	network, address, displayAddress, err := proxyProbeEndpoint(target)
	if err != nil {
		return displayAddress, 0, err
	}
	start := time.Now()
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return displayAddress, 0, err
	}
	_ = conn.Close()
	return displayAddress, time.Since(start).Milliseconds(), nil
}

func proxyProbeTarget(cfg ProxyRulesConfig, upstreamName string) (*url.URL, error) {
	if upstreamName != "" {
		target, ok, err := proxyRouteConfiguredTarget(cfg, upstreamName)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("configured upstream %q not found", upstreamName)
		}
		return target, nil
	}
	if cfg.DefaultRoute != nil && proxyRouteEnabled(cfg.DefaultRoute.Enabled) {
		if target, ok, err := proxyRouteConfiguredTarget(cfg, cfg.DefaultRoute.Action.Upstream); err != nil {
			return nil, err
		} else if ok {
			return target, nil
		}
	}
	return proxyPrimaryTarget(cfg)
}

func proxyProbeEndpoint(target *url.URL) (string, string, string, error) {
	if target == nil {
		return "", "", "", fmt.Errorf("upstream target is required")
	}
	scheme := strings.ToLower(strings.TrimSpace(target.Scheme))
	switch scheme {
	case "fcgi":
		if strings.TrimSpace(target.Host) == "" && strings.TrimSpace(target.Path) != "" {
			socketPath := filepath.Clean(strings.TrimSpace(target.Path))
			return "unix", socketPath, socketPath, nil
		}
	case "static":
		return "", "", target.String(), fmt.Errorf("static upstream targets do not support network probing")
	}
	address, err := proxyDialAddress(target)
	if err != nil {
		return "", "", "", err
	}
	return "tcp", address, address, nil
}

func proxyConfiguredUpstreams(cfg ProxyRulesConfig) []ProxyUpstream {
	if len(cfg.Upstreams) == 0 {
		return nil
	}
	out := make([]ProxyUpstream, 0, len(cfg.Upstreams))
	for _, upstream := range cfg.Upstreams {
		if upstream.Generated {
			continue
		}
		out = append(out, upstream)
	}
	return out
}

func proxyMaterializedBackendUpstreams(cfg ProxyRulesConfig, discovery map[string]proxyDiscoveryRuntimeState) []ProxyUpstream {
	defs := proxyConfiguredUpstreams(cfg)
	if len(defs) == 0 {
		return nil
	}
	out := make([]ProxyUpstream, 0, len(defs))
	for _, upstream := range defs {
		if !proxyUpstreamDiscoveryEnabled(upstream) {
			out = append(out, upstream)
			continue
		}
		state, ok := discovery[upstream.Name]
		if !ok || len(state.Targets) == 0 {
			continue
		}
		for _, target := range state.Targets {
			next := upstream
			next.URL = target
			next.Generated = true
			next.GeneratedKind = proxyUpstreamGeneratedKindDiscoveredTarget
			next.ProviderClass = proxyUpstreamProviderClassDiscovered
			out = append(out, next)
		}
	}
	return out
}

func proxyBackendsVisibleUpstreams(cfg ProxyRulesConfig) []ProxyUpstream {
	if len(cfg.Upstreams) == 0 {
		return nil
	}
	out := make([]ProxyUpstream, 0, len(cfg.Upstreams))
	seen := make(map[string]struct{}, len(cfg.Upstreams))
	for _, upstream := range cfg.Upstreams {
		if !proxyUpstreamVisibleInBackendsSurface(upstream) {
			continue
		}
		key := strings.TrimSpace(upstream.Name) + "\x00" + strings.TrimSpace(upstream.URL)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, upstream)
	}
	return out
}

func proxyUpstreamVisibleInBackendsSurface(upstream ProxyUpstream) bool {
	if proxyUpstreamIsDirect(upstream) {
		return true
	}
	return proxyUpstreamIsVhostManaged(upstream) && upstream.GeneratedKind == proxyUpstreamGeneratedKindVhostLinkedTarget
}

func proxyDisplayUpstream(cfg ProxyRulesConfig) string {
	upstreams := proxyConfiguredUpstreams(cfg)
	if len(upstreams) == 0 {
		return "-"
	}
	names := make([]string, 0, len(upstreams))
	for _, upstream := range upstreams {
		if !upstream.Enabled {
			continue
		}
		if proxyUpstreamDiscoveryEnabled(upstream) {
			names = append(names, "discovery:"+proxyDiscoverySource(upstream.Discovery))
			continue
		}
		names = append(names, upstream.URL)
	}
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, ",")
}

func proxyDialAddress(target *url.URL) (string, error) {
	if target == nil {
		return "", fmt.Errorf("upstream target is required")
	}
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return "", fmt.Errorf("upstream host is required")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host, nil
	}
	host = target.Hostname()
	if host == "" {
		return "", fmt.Errorf("upstream host is required")
	}
	port := target.Port()
	if port == "" {
		switch strings.ToLower(strings.TrimSpace(target.Scheme)) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("unsupported upstream scheme: %s", target.Scheme)
		}
	}
	return net.JoinHostPort(host, port), nil
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return &url.URL{}
	}
	return u
}

type upstreamHealthStatus struct {
	Enabled                                bool                      `json:"enabled"`
	Status                                 string                    `json:"status"`
	Strategy                               string                    `json:"strategy,omitempty"`
	Endpoint                               string                    `json:"endpoint,omitempty"`
	HealthCheckPath                        string                    `json:"health_check_path"`
	HealthCheckInterval                    int                       `json:"health_check_interval_sec"`
	HealthCheckTimeout                     int                       `json:"health_check_timeout_sec"`
	HealthCheckHeaders                     map[string]string         `json:"health_check_headers,omitempty"`
	HealthCheckExpectedBodyConfigured      bool                      `json:"health_check_expected_body_configured"`
	HealthCheckExpectedBodyRegexConfigured bool                      `json:"health_check_expected_body_regex_configured"`
	CheckedAt                              string                    `json:"checked_at,omitempty"`
	LastSuccessAt                          string                    `json:"last_success_at,omitempty"`
	LastFailureAt                          string                    `json:"last_failure_at,omitempty"`
	ConsecutiveFailures                    int                       `json:"consecutive_failures"`
	LastError                              string                    `json:"last_error,omitempty"`
	LastStatusCode                         int                       `json:"last_status_code,omitempty"`
	LastLatencyMS                          int64                     `json:"last_latency_ms,omitempty"`
	ActiveBackends                         int                       `json:"active_backends"`
	HealthyBackends                        int                       `json:"healthy_backends"`
	Backends                               []upstreamBackendStatus   `json:"backends,omitempty"`
	Discovery                              []upstreamDiscoveryStatus `json:"discovery,omitempty"`
}

type upstreamDiscoveryStatus struct {
	UpstreamName  string   `json:"upstream_name"`
	Type          string   `json:"type"`
	Source        string   `json:"source"`
	Targets       []string `json:"targets,omitempty"`
	TargetCount   int      `json:"target_count"`
	LastLookupAt  string   `json:"last_lookup_at,omitempty"`
	LastSuccessAt string   `json:"last_success_at,omitempty"`
	LastFailureAt string   `json:"last_failure_at,omitempty"`
	LastError     string   `json:"last_error,omitempty"`
	NextRefreshAt string   `json:"next_refresh_at,omitempty"`
}

type upstreamBackendStatus struct {
	Key                    string `json:"key"`
	Name                   string `json:"name"`
	URL                    string `json:"url"`
	ProviderClass          string `json:"provider_class,omitempty"`
	ManagedByVhost         string `json:"managed_by_vhost,omitempty"`
	DiscoveryType          string `json:"discovery_type,omitempty"`
	DiscoverySource        string `json:"discovery_source,omitempty"`
	DiscoveryLastLookupAt  string `json:"discovery_last_lookup_at,omitempty"`
	DiscoveryLastSuccessAt string `json:"discovery_last_success_at,omitempty"`
	DiscoveryLastFailureAt string `json:"discovery_last_failure_at,omitempty"`
	DiscoveryLastError     string `json:"discovery_last_error,omitempty"`
	RuntimeOpsSupported    bool   `json:"runtime_ops_supported"`
	HTTP2Mode              string `json:"http2_mode,omitempty"`
	AdminState             string `json:"admin_state,omitempty"`
	HealthState            string `json:"health_state,omitempty"`
	ConfiguredWeight       int    `json:"configured_weight,omitempty"`
	WeightOverride         int    `json:"weight_override,omitempty"`
	EffectiveWeight        int    `json:"effective_weight,omitempty"`
	EffectiveSelectable    bool   `json:"effective_selectable"`
	Enabled                bool   `json:"enabled"`
	Healthy                bool   `json:"healthy"`
	InFlight               int    `json:"inflight"`
	PassiveFailures        int    `json:"passive_failures,omitempty"`
	CircuitState           string `json:"circuit_state,omitempty"`
	CircuitOpenedAt        string `json:"circuit_opened_at,omitempty"`
	CircuitReopenAt        string `json:"circuit_reopen_at,omitempty"`
	Endpoint               string `json:"endpoint,omitempty"`
	CheckedAt              string `json:"checked_at,omitempty"`
	LastSuccessAt          string `json:"last_success_at,omitempty"`
	LastFailureAt          string `json:"last_failure_at,omitempty"`
	ConsecutiveFailures    int    `json:"consecutive_failures"`
	LastError              string `json:"last_error,omitempty"`
	LastStatusCode         int    `json:"last_status_code,omitempty"`
	LastLatencyMS          int64  `json:"last_latency_ms,omitempty"`
}

type proxyTargetSelection struct {
	Key          string
	Name         string
	Target       *url.URL
	HTTP2Mode    string
	TransportKey string
}

type proxyBackendState struct {
	Key                    string
	Name                   string
	URL                    string
	ProviderClass          string
	DiscoveryType          string
	DiscoverySource        string
	DiscoveryLastLookupAt  string
	DiscoveryLastSuccessAt string
	DiscoveryLastFailureAt string
	DiscoveryLastError     string
	HTTP2Mode              string
	TransportKey           string
	TransportProfile       proxyTransportProfile
	Target                 *url.URL
	Weight                 int
	WeightOverride         *int
	EffectiveWeight        int
	Enabled                bool
	AdminState             upstreamAdminState
	HealthState            string
	EffectiveSelectable    bool
	Healthy                bool
	InFlight               int
	PassiveFailures        int
	CircuitState           string
	CircuitOpenedAt        time.Time
	CircuitReopenAt        time.Time
	HalfOpenRequests       int
	Endpoint               string
	CheckedAt              string
	LastSuccessAt          string
	LastFailureAt          string
	ConsecutiveFailures    int
	LastError              string
	LastStatusCode         int
	LastLatencyMS          int64
}

type upstreamHealthMonitor struct {
	mu        sync.RWMutex
	cfg       ProxyRulesConfig
	status    upstreamHealthStatus
	backends  []*proxyBackendState
	discovery map[string]proxyDiscoveryRuntimeState
	metrics   *proxyTransportMetrics
	wakeCh    chan struct{}
	running   bool
	rrCursor  uint64
}

func newUpstreamHealthMonitor(initial ProxyRulesConfig) (*upstreamHealthMonitor, error) {
	cfg := normalizeProxyRulesConfig(initial)
	discovery := proxyDiscoveryStatesInitial(cfg)
	backends, err := buildProxyBackendStatesWithDiscovery(cfg, nil, discovery)
	if err != nil {
		return nil, err
	}
	m := &upstreamHealthMonitor{
		cfg:       cfg,
		metrics:   newProxyTransportMetrics(),
		wakeCh:    make(chan struct{}, 1),
		status:    upstreamHealthStatus{Status: "disabled"},
		backends:  backends,
		discovery: discovery,
	}
	m.metrics.SyncUpstreams(proxyActiveTransportMetricLabels(cfg, backends))
	m.applyConfigLocked(cfg)
	if m.status.Enabled || proxyConfigHasDiscovery(cfg) {
		m.running = true
		go m.run()
	}
	return m, nil
}

func (m *upstreamHealthMonitor) Snapshot() upstreamHealthStatus {
	if m == nil {
		return upstreamHealthStatus{Status: "disabled"}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	snapshot := m.status
	if len(snapshot.HealthCheckHeaders) > 0 {
		headers := make(map[string]string, len(snapshot.HealthCheckHeaders))
		for name, value := range snapshot.HealthCheckHeaders {
			headers[name] = value
		}
		snapshot.HealthCheckHeaders = headers
	}
	if len(snapshot.Backends) > 0 {
		cp := make([]upstreamBackendStatus, len(snapshot.Backends))
		copy(cp, snapshot.Backends)
		snapshot.Backends = cp
	}
	if len(snapshot.Discovery) > 0 {
		cp := make([]upstreamDiscoveryStatus, len(snapshot.Discovery))
		copy(cp, snapshot.Discovery)
		for i := range cp {
			cp[i].Targets = append([]string(nil), cp[i].Targets...)
		}
		snapshot.Discovery = cp
	}
	return snapshot
}

func (m *upstreamHealthMonitor) TransportMetricsSnapshot() proxyTransportMetricsSnapshot {
	if m == nil {
		return proxyTransportMetricsSnapshot{
			BucketBounds: append([]float64(nil), proxyTransportLatencyBucketsSeconds...),
		}
	}
	return m.metrics.Snapshot()
}

func (m *upstreamHealthMonitor) Update(next ProxyRulesConfig) error {
	if m == nil {
		return nil
	}
	next = normalizeProxyRulesConfig(next)
	m.mu.RLock()
	prevDiscovery := copyProxyDiscoveryStates(m.discovery)
	prevBackends := make([]*proxyBackendState, 0, len(m.backends))
	for _, backend := range m.backends {
		if backend == nil {
			continue
		}
		cp := *backend
		cp.Target = cloneURL(backend.Target)
		prevBackends = append(prevBackends, &cp)
	}
	m.mu.RUnlock()
	nextDiscovery := refreshProxyDiscoveryStates(next, prevDiscovery, time.Now().UTC(), true)
	nextBackends, err := buildProxyBackendStatesWithDiscovery(next, prevBackends, nextDiscovery)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.cfg = next
	prevLiveBackends := m.backends
	m.backends = nextBackends
	m.discovery = nextDiscovery
	if proxyBackendSetChanged(prevLiveBackends, m.backends) {
		m.metrics.ResetUpstreams(proxyActiveTransportMetricLabels(next, m.backends))
	} else {
		m.metrics.SyncUpstreams(proxyActiveTransportMetricLabels(next, m.backends))
	}
	m.applyConfigLocked(next)
	shouldStart := !m.running && (m.status.Enabled || proxyConfigHasDiscovery(next))
	if shouldStart {
		m.running = true
	}
	m.mu.Unlock()
	if shouldStart {
		go m.run()
	}
	m.triggerWake()
	return nil
}

func (m *upstreamHealthMonitor) SelectTarget() (proxyTargetSelection, bool) {
	if m == nil {
		return proxyTargetSelection{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	idx, ok := m.selectBackendIndexLocked()
	if !ok {
		return proxyTargetSelection{}, false
	}
	backend := m.backends[idx]
	backend.InFlight++
	m.refreshStatusLocked()
	return proxyTargetSelection{
		Key:          backend.Key,
		Name:         backend.Name,
		Target:       cloneURL(backend.Target),
		HTTP2Mode:    backend.HTTP2Mode,
		TransportKey: backend.TransportKey,
	}, true
}

func (m *upstreamHealthMonitor) ReleaseTarget(key string) {
	if m == nil || strings.TrimSpace(key) == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, backend := range m.backends {
		if backend.Key != key {
			continue
		}
		if backend.InFlight > 0 {
			backend.InFlight--
		}
		if backend.HalfOpenRequests > 0 {
			backend.HalfOpenRequests--
		}
		break
	}
	m.refreshStatusLocked()
}

func (m *upstreamHealthMonitor) RouteCandidatesForUpstream(cfg ProxyRulesConfig, upstream ProxyUpstream, weight int, explicitMode string) []proxyRouteTargetCandidate {
	if m == nil || strings.TrimSpace(upstream.Name) == "" {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]proxyRouteTargetCandidate, 0)
	for _, backend := range m.backends {
		if backend == nil || backend.Name != upstream.Name || backend.ProviderClass != proxyUpstreamProviderClassDiscovered {
			continue
		}
		mode := explicitMode
		if normalizeProxyHTTP2Mode(mode) == proxyHTTP2ModeDefault {
			mode = upstream.HTTP2Mode
		}
		out = append(out, proxyRouteTargetCandidate{
			Key:          backend.Key,
			Name:         backend.Name,
			Target:       cloneURL(backend.Target),
			Weight:       proxyPositiveWeight(weight),
			Managed:      true,
			HTTP2Mode:    proxyConfiguredHTTP2Mode(cfg, mode),
			TransportKey: backend.TransportKey,
			StickyID:     backend.Key,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Target.String() < out[j].Target.String()
	})
	return out
}

func (m *upstreamHealthMonitor) AcquireTarget(key string) bool {
	if m == nil || strings.TrimSpace(key) == "" {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, backend := range m.backends {
		if backend == nil || backend.Key != key {
			continue
		}
		if !proxyBackendSelectableLocked(m.cfg, backend, now) {
			return false
		}
		if m.cfg.CircuitBreakerEnabled && backend.CircuitState == "open" && !backend.CircuitReopenAt.IsZero() && !now.Before(backend.CircuitReopenAt) {
			backend.CircuitState = "half_open"
			m.metrics.RecordCircuitTransition(backend.Name, backend.Target, true, proxyTransportCircuitStateHalfOpen)
		}
		backend.InFlight++
		if backend.CircuitState == "half_open" {
			backend.HalfOpenRequests++
		}
		m.refreshStatusLocked()
		return true
	}
	return true
}

func (m *upstreamHealthMonitor) RecordPassiveFailure(key string, statusCode int, err error) {
	if m == nil || strings.TrimSpace(key) == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, backend := range m.backends {
		if backend == nil || backend.Key != key {
			continue
		}
		backend.LastFailureAt = now.Format(time.RFC3339Nano)
		backend.LastStatusCode = statusCode
		if err != nil {
			backend.LastError = err.Error()
			m.metrics.RecordPassiveFailure(backend.Name, backend.Target, true, proxyTransportPassiveFailureReasonTransport)
		} else if statusCode > 0 {
			backend.LastError = fmt.Sprintf("unexpected status code: %d", statusCode)
			m.metrics.RecordPassiveFailure(backend.Name, backend.Target, true, proxyTransportPassiveFailureReasonStatus)
		}
		backend.PassiveFailures++
		if m.cfg.PassiveHealthEnabled && backend.PassiveFailures >= proxyPassiveFailureThreshold(m.cfg) {
			backend.Healthy = false
		}
		if m.cfg.CircuitBreakerEnabled && backend.PassiveFailures >= proxyPassiveFailureThreshold(m.cfg) && backend.CircuitState != "open" {
			backend.CircuitState = "open"
			backend.CircuitOpenedAt = now
			backend.CircuitReopenAt = now.Add(proxyCircuitOpenDuration(m.cfg))
			m.metrics.RecordCircuitTransition(backend.Name, backend.Target, true, proxyTransportCircuitStateOpen)
		}
		m.refreshStatusLocked()
		return
	}
}

func (m *upstreamHealthMonitor) RecordPassiveSuccess(key string, statusCode int) {
	if m == nil || strings.TrimSpace(key) == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, backend := range m.backends {
		if backend == nil || backend.Key != key {
			continue
		}
		backend.LastSuccessAt = now.Format(time.RFC3339Nano)
		backend.LastStatusCode = statusCode
		backend.LastError = ""
		backend.PassiveFailures = 0
		backend.Healthy = true
		if backend.CircuitState != "" {
			m.metrics.RecordCircuitTransition(backend.Name, backend.Target, true, proxyTransportCircuitStateClosed)
		}
		backend.CircuitState = ""
		backend.CircuitOpenedAt = time.Time{}
		backend.CircuitReopenAt = time.Time{}
		backend.HalfOpenRequests = 0
		m.refreshStatusLocked()
		return
	}
}

func (m *upstreamHealthMonitor) run() {
	for {
		cfg := m.currentConfig()
		discoveryWait := m.refreshDiscoveryIfDue(false)
		healthEnabled := proxyHealthCheckEnabled(cfg)
		if !healthEnabled && discoveryWait == 0 {
			m.awaitWake()
			continue
		}
		if healthEnabled {
			backends := m.backendsSnapshot()
			for _, backend := range backends {
				if backend == nil || !backend.Enabled {
					continue
				}
				if !proxyBackendSupportsHTTPHealth(backend.Target) {
					continue
				}
				checkedAt := time.Now().UTC()
				statusCode, latencyMS, err := checkProxyBackendHealth(cfg, backend.Target, backend.TransportProfile)
				m.recordResult(backend.Key, checkedAt, statusCode, latencyMS, err)
			}
		}
		wait := proxyHealthCheckInterval(cfg)
		if !healthEnabled || (discoveryWait > 0 && discoveryWait < wait) {
			wait = discoveryWait
		}
		m.waitOrWake(wait)
	}
}

func (m *upstreamHealthMonitor) refreshDiscoveryIfDue(force bool) time.Duration {
	if m == nil {
		return 0
	}
	cfg := m.currentConfig()
	if !proxyConfigHasDiscovery(cfg) {
		return 0
	}
	now := time.Now().UTC()
	m.mu.RLock()
	prev := copyProxyDiscoveryStates(m.discovery)
	m.mu.RUnlock()
	next := refreshProxyDiscoveryStates(cfg, prev, now, force)
	wait := proxyDiscoveryNextRefreshDelay(next, now)
	if !force && proxyDiscoveryStatesEqual(prev, next) {
		return wait
	}
	nextBackends, err := buildProxyBackendStatesWithDiscovery(cfg, m.backendsSnapshot(), next)
	if err != nil {
		return wait
	}
	m.mu.Lock()
	m.cfg = cfg
	prevBackends := m.backends
	m.backends = nextBackends
	m.discovery = next
	if proxyBackendSetChanged(prevBackends, m.backends) {
		m.metrics.ResetUpstreams(proxyActiveTransportMetricLabels(cfg, m.backends))
	} else {
		m.metrics.SyncUpstreams(proxyActiveTransportMetricLabels(cfg, m.backends))
	}
	m.applyConfigLocked(cfg)
	m.mu.Unlock()
	return wait
}

func copyProxyDiscoveryStates(in map[string]proxyDiscoveryRuntimeState) map[string]proxyDiscoveryRuntimeState {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]proxyDiscoveryRuntimeState, len(in))
	for key, value := range in {
		value.Targets = append([]string(nil), value.Targets...)
		out[key] = value
	}
	return out
}

func proxyDiscoveryStatesEqual(left map[string]proxyDiscoveryRuntimeState, right map[string]proxyDiscoveryRuntimeState) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftState := range left {
		rightState, ok := right[key]
		if !ok {
			return false
		}
		if leftState.LastLookupAt != rightState.LastLookupAt ||
			leftState.LastSuccessAt != rightState.LastSuccessAt ||
			leftState.LastFailureAt != rightState.LastFailureAt ||
			leftState.LastError != rightState.LastError ||
			leftState.NextRefreshAt != rightState.NextRefreshAt ||
			strings.Join(leftState.Targets, "\x00") != strings.Join(rightState.Targets, "\x00") {
			return false
		}
	}
	return true
}

func (m *upstreamHealthMonitor) currentConfig() ProxyRulesConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *upstreamHealthMonitor) applyConfigLocked(cfg ProxyRulesConfig) {
	enabled := proxyHealthCheckEnabled(cfg)
	endpoint := ""
	if len(m.backends) > 0 {
		endpoint = m.backends[0].Endpoint
	}

	m.status.Enabled = enabled
	m.status.Strategy = cfg.LoadBalancingStrategy
	m.status.HealthCheckPath = cfg.HealthCheckPath
	m.status.HealthCheckInterval = cfg.HealthCheckInterval
	m.status.HealthCheckTimeout = cfg.HealthCheckTimeout
	m.status.HealthCheckHeaders = normalizeProxyHealthCheckHeaders(cfg.HealthCheckHeaders)
	m.status.HealthCheckExpectedBodyConfigured = strings.TrimSpace(cfg.HealthCheckExpectedBody) != ""
	m.status.HealthCheckExpectedBodyRegexConfigured = strings.TrimSpace(cfg.HealthCheckExpectedBodyRegex) != ""
	m.status.Endpoint = endpoint
	if !enabled {
		m.status.Status = "disabled"
		m.status.ConsecutiveFailures = 0
		m.status.LastError = ""
		m.status.LastStatusCode = 0
		m.status.LastLatencyMS = 0
		m.refreshStatusLocked()
		return
	}
	m.refreshStatusLocked()
}

func (m *upstreamHealthMonitor) recordResult(key string, checkedAt time.Time, statusCode int, latencyMS int64, err error) {
	m.mu.Lock()
	for _, backend := range m.backends {
		if backend.Key != key {
			continue
		}
		backend.CheckedAt = checkedAt.Format(time.RFC3339Nano)
		backend.LastStatusCode = statusCode
		backend.LastLatencyMS = latencyMS
		if err == nil {
			backend.Healthy = true
			backend.LastSuccessAt = backend.CheckedAt
			backend.ConsecutiveFailures = 0
			backend.LastError = ""
			backend.PassiveFailures = 0
			if backend.CircuitState != "" {
				m.metrics.RecordCircuitTransition(backend.Name, backend.Target, true, proxyTransportCircuitStateClosed)
			}
			backend.CircuitState = ""
			backend.CircuitOpenedAt = time.Time{}
			backend.CircuitReopenAt = time.Time{}
			backend.HalfOpenRequests = 0
		} else {
			backend.Healthy = false
			backend.LastFailureAt = backend.CheckedAt
			backend.ConsecutiveFailures++
			backend.LastError = err.Error()
		}
		break
	}
	m.refreshStatusLocked()
	m.mu.Unlock()
}

func (m *upstreamHealthMonitor) backendsSnapshot() []*proxyBackendState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*proxyBackendState, 0, len(m.backends))
	for _, backend := range m.backends {
		if backend == nil {
			continue
		}
		cp := *backend
		cp.Target = cloneURL(backend.Target)
		out = append(out, &cp)
	}
	return out
}

func (m *upstreamHealthMonitor) selectBackendIndexLocked() (int, bool) {
	if len(m.backends) == 0 {
		return -1, false
	}
	now := time.Now().UTC()
	candidates := make([]int, 0, len(m.backends))
	for i, backend := range m.backends {
		if backend == nil {
			continue
		}
		refreshProxyBackendDerivedStateLocked(m.cfg, backend, now)
		if !proxyBackendSelectableLocked(m.cfg, backend, now) {
			continue
		}
		candidates = append(candidates, i)
	}
	if len(candidates) == 0 {
		return -1, false
	}
	switch m.cfg.LoadBalancingStrategy {
	case "least_conn":
		best := candidates[0]
		for _, idx := range candidates[1:] {
			if proxyBackendLessLoaded(m.backends[idx], m.backends[best]) {
				best = idx
			}
		}
		return best, true
	default:
		totalWeight := 0
		for _, idx := range candidates {
			totalWeight += proxyBackendEffectiveWeight(m.backends[idx])
		}
		if totalWeight <= 0 {
			return candidates[0], true
		}
		selected := int(m.rrCursor % uint64(totalWeight))
		m.rrCursor++
		acc := 0
		for _, idx := range candidates {
			acc += proxyBackendEffectiveWeight(m.backends[idx])
			if selected < acc {
				return idx, true
			}
		}
		return candidates[0], true
	}
}

func (m *upstreamHealthMonitor) refreshStatusLocked() {
	backends := make([]upstreamBackendStatus, 0, len(m.backends))
	activeCount := 0
	healthyCount := 0
	now := time.Now().UTC()
	var aggregate upstreamBackendStatus
	var aggregateSet bool

	for _, backend := range m.backends {
		if backend == nil {
			continue
		}
		refreshProxyBackendDerivedStateLocked(m.cfg, backend, now)
		if backend.Enabled {
			activeCount++
		}
		if backend.Enabled && backend.Healthy {
			healthyCount++
		}
		weightOverride := 0
		if backend.WeightOverride != nil {
			weightOverride = *backend.WeightOverride
		}
		entry := upstreamBackendStatus{
			Key:                    backend.Key,
			Name:                   backend.Name,
			URL:                    backend.URL,
			ProviderClass:          backend.ProviderClass,
			DiscoveryType:          backend.DiscoveryType,
			DiscoverySource:        backend.DiscoverySource,
			DiscoveryLastLookupAt:  backend.DiscoveryLastLookupAt,
			DiscoveryLastSuccessAt: backend.DiscoveryLastSuccessAt,
			DiscoveryLastFailureAt: backend.DiscoveryLastFailureAt,
			DiscoveryLastError:     backend.DiscoveryLastError,
			RuntimeOpsSupported:    true,
			HTTP2Mode:              backend.HTTP2Mode,
			AdminState:             string(backend.AdminState),
			HealthState:            backend.HealthState,
			ConfiguredWeight:       backend.Weight,
			WeightOverride:         weightOverride,
			EffectiveWeight:        backend.EffectiveWeight,
			EffectiveSelectable:    backend.EffectiveSelectable,
			Enabled:                backend.Enabled,
			Healthy:                backend.Healthy,
			InFlight:               backend.InFlight,
			PassiveFailures:        backend.PassiveFailures,
			CircuitState:           backend.CircuitState,
			CircuitOpenedAt:        formatProxyTime(backend.CircuitOpenedAt),
			CircuitReopenAt:        formatProxyTime(backend.CircuitReopenAt),
			Endpoint:               backend.Endpoint,
			CheckedAt:              backend.CheckedAt,
			LastSuccessAt:          backend.LastSuccessAt,
			LastFailureAt:          backend.LastFailureAt,
			ConsecutiveFailures:    backend.ConsecutiveFailures,
			LastError:              backend.LastError,
			LastStatusCode:         backend.LastStatusCode,
			LastLatencyMS:          backend.LastLatencyMS,
		}
		backends = append(backends, entry)
		if !aggregateSet && backend.Enabled {
			aggregate = entry
			aggregateSet = true
		}
	}

	m.status.Backends = backends
	m.status.Discovery = proxyDiscoveryStatusSnapshot(m.discovery)
	m.status.ActiveBackends = activeCount
	m.status.HealthyBackends = healthyCount
	m.status.Endpoint = aggregate.Endpoint
	m.status.CheckedAt = aggregate.CheckedAt
	m.status.LastSuccessAt = aggregate.LastSuccessAt
	m.status.LastFailureAt = aggregate.LastFailureAt
	m.status.ConsecutiveFailures = aggregate.ConsecutiveFailures
	m.status.LastError = aggregate.LastError
	m.status.LastStatusCode = aggregate.LastStatusCode
	m.status.LastLatencyMS = aggregate.LastLatencyMS

	switch {
	case !m.status.Enabled:
		m.status.Status = "disabled"
	case healthyCount > 0 && healthyCount == activeCount:
		m.status.Status = "healthy"
	case healthyCount > 0:
		m.status.Status = "degraded"
	case activeCount > 0:
		checked := false
		for _, backend := range backends {
			if backend.CheckedAt != "" {
				checked = true
				break
			}
		}
		if checked {
			m.status.Status = "unhealthy"
		} else {
			m.status.Status = "unknown"
		}
	default:
		m.status.Status = "unknown"
	}
}

func (m *upstreamHealthMonitor) triggerWake() {
	if m == nil {
		return
	}
	select {
	case m.wakeCh <- struct{}{}:
	default:
	}
}

func (m *upstreamHealthMonitor) awaitWake() {
	if m == nil {
		return
	}
	<-m.wakeCh
}

func (m *upstreamHealthMonitor) waitOrWake(wait time.Duration) {
	if wait <= 0 {
		wait = time.Duration(defaultProxyHealthCheckIntervalSec) * time.Second
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-m.wakeCh:
	}
}

func proxyHealthCheckEnabled(cfg ProxyRulesConfig) bool {
	return strings.TrimSpace(cfg.HealthCheckPath) != ""
}

func proxyBackendSupportsHTTPHealth(target *url.URL) bool {
	if target == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(target.Scheme)) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func proxyHealthCheckInterval(cfg ProxyRulesConfig) time.Duration {
	sec := cfg.HealthCheckInterval
	if sec <= 0 {
		sec = defaultProxyHealthCheckIntervalSec
	}
	return time.Duration(sec) * time.Second
}

func proxyHealthCheckTimeout(cfg ProxyRulesConfig) time.Duration {
	sec := cfg.HealthCheckTimeout
	if sec <= 0 {
		sec = defaultProxyHealthCheckTimeoutSec
	}
	return time.Duration(sec) * time.Second
}

func proxyPassiveFailureThreshold(cfg ProxyRulesConfig) int {
	if cfg.PassiveFailureThreshold > 0 {
		return cfg.PassiveFailureThreshold
	}
	return 3
}

func proxyCircuitOpenDuration(cfg ProxyRulesConfig) time.Duration {
	if cfg.CircuitBreakerOpenSec > 0 {
		return time.Duration(cfg.CircuitBreakerOpenSec) * time.Second
	}
	return 30 * time.Second
}

func proxyCircuitHalfOpenRequests(cfg ProxyRulesConfig) int {
	if cfg.CircuitBreakerHalfOpenRequests > 0 {
		return cfg.CircuitBreakerHalfOpenRequests
	}
	return 1
}

func proxyBackendSelectableLocked(cfg ProxyRulesConfig, backend *proxyBackendState, now time.Time) bool {
	if backend == nil || !backend.Enabled {
		return false
	}
	if backend.AdminState != upstreamAdminStateEnabled {
		return false
	}
	if cfg.CircuitBreakerEnabled {
		switch backend.CircuitState {
		case "open":
			if !backend.CircuitReopenAt.IsZero() && now.Before(backend.CircuitReopenAt) {
				return false
			}
		case "half_open":
			if backend.HalfOpenRequests >= proxyCircuitHalfOpenRequests(cfg) {
				return false
			}
		}
	}
	if proxyHealthCheckEnabled(cfg) || cfg.PassiveHealthEnabled {
		return backend.Healthy
	}
	return true
}

func proxyBackendEffectiveWeight(backend *proxyBackendState) int {
	if backend == nil {
		return 1
	}
	if backend.WeightOverride != nil {
		return proxyPositiveWeight(*backend.WeightOverride)
	}
	return proxyPositiveWeight(backend.Weight)
}

func refreshProxyBackendDerivedStateLocked(cfg ProxyRulesConfig, backend *proxyBackendState, now time.Time) {
	if backend == nil {
		return
	}
	backend.EffectiveWeight = proxyBackendEffectiveWeight(backend)
	backend.HealthState = proxyBackendHealthState(cfg, backend)
	backend.EffectiveSelectable = proxyBackendSelectableLocked(cfg, backend, now)
}

func formatProxyTime(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339Nano)
}

func proxyHealthEndpoint(cfg ProxyRulesConfig, target *url.URL) (string, error) {
	if target == nil {
		return "", fmt.Errorf("upstream target is required")
	}
	if !proxyBackendSupportsHTTPHealth(target) {
		return "", fmt.Errorf("health checks require an http or https upstream")
	}
	endpoint := *target
	endpoint.Path = cfg.HealthCheckPath
	endpoint.RawPath = ""
	endpoint.RawQuery = ""
	endpoint.Fragment = ""
	return endpoint.String(), nil
}

func checkProxyBackendHealth(cfg ProxyRulesConfig, target *url.URL, profile proxyTransportProfile) (statusCode int, latencyMS int64, err error) {
	endpoint, err := proxyHealthEndpoint(cfg, target)
	if err != nil {
		return 0, 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), proxyHealthCheckTimeout(cfg))
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, 0, err
	}
	for name, value := range cfg.HealthCheckHeaders {
		req.Header.Set(name, value)
	}

	transport, err := buildProxyTransportFromProfile(cfg, profile)
	if err != nil {
		return 0, 0, err
	}
	defer closeIdleProxyRoundTripper(transport)

	client := &http.Client{Transport: transport}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	latency := time.Since(start).Milliseconds()
	if err := validateProxyHealthCheckResponse(cfg, resp); err != nil {
		return resp.StatusCode, latency, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return resp.StatusCode, latency, nil
	}
	return resp.StatusCode, latency, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

func validateProxyHealthCheckResponse(cfg ProxyRulesConfig, resp *http.Response) error {
	if strings.TrimSpace(cfg.HealthCheckExpectedBody) == "" && strings.TrimSpace(cfg.HealthCheckExpectedBodyRegex) == "" {
		return nil
	}
	if resp == nil || resp.Body == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultProxyHealthCheckBodyLimit))
	if err != nil {
		return err
	}
	if cfg.HealthCheckExpectedBody != "" {
		if !strings.Contains(string(body), cfg.HealthCheckExpectedBody) {
			return fmt.Errorf("health check body did not contain expected text")
		}
		return nil
	}
	if cfg.HealthCheckExpectedBodyRegex != "" {
		re, err := regexp.Compile(cfg.HealthCheckExpectedBodyRegex)
		if err != nil {
			return err
		}
		if !re.Match(body) {
			return fmt.Errorf("health check body did not match expected regex")
		}
		return nil
	}
	return nil
}

func buildProxyBackendStates(cfg ProxyRulesConfig, prev []*proxyBackendState) ([]*proxyBackendState, error) {
	return buildProxyBackendStatesWithDiscovery(cfg, prev, nil)
}

func buildProxyBackendStatesWithDiscovery(cfg ProxyRulesConfig, prev []*proxyBackendState, discovery map[string]proxyDiscoveryRuntimeState) ([]*proxyBackendState, error) {
	prevMap := make(map[string]*proxyBackendState, len(prev))
	for _, backend := range prev {
		if backend == nil {
			continue
		}
		prevMap[backend.Key] = backend
	}

	runtimeOverrides, err := loadUpstreamRuntimeOverrides(cfg)
	if err != nil {
		return nil, err
	}
	defs := proxyMaterializedBackendUpstreams(cfg, discovery)
	out := make([]*proxyBackendState, 0, len(defs))
	now := time.Now().UTC()
	for i, upstream := range defs {
		target, err := parseProxyUpstreamURL(fmt.Sprintf("upstreams[%d].url", i), upstream.URL)
		if err != nil {
			continue
		}
		key := proxyBackendLookupKey(upstream.Name, target.String())
		state := &proxyBackendState{
			Key:              key,
			Name:             upstream.Name,
			URL:              target.String(),
			ProviderClass:    proxyUpstreamProviderClass(upstream),
			HTTP2Mode:        proxyConfiguredHTTP2Mode(cfg, upstream.HTTP2Mode),
			TransportProfile: proxyConfiguredUpstreamTransportProfile(cfg, &upstream, upstream.HTTP2Mode),
			Target:           target,
			Weight:           upstream.Weight,
			EffectiveWeight:  upstream.Weight,
			Enabled:          upstream.Enabled,
			AdminState:       upstreamAdminStateEnabled,
			Healthy:          true,
		}
		if proxyUpstreamProviderClass(upstream) == proxyUpstreamProviderClassDiscovered {
			state.DiscoveryType = upstream.Discovery.Type
			state.DiscoverySource = proxyDiscoverySource(upstream.Discovery)
			if discoveryState, ok := discovery[upstream.Name]; ok {
				state.DiscoveryLastLookupAt = formatProxyTime(discoveryState.LastLookupAt)
				state.DiscoveryLastSuccessAt = formatProxyTime(discoveryState.LastSuccessAt)
				state.DiscoveryLastFailureAt = formatProxyTime(discoveryState.LastFailureAt)
				state.DiscoveryLastError = discoveryState.LastError
			}
		}
		state.TransportKey = proxyTransportKey(state.TransportProfile)
		if state.Weight <= 0 {
			state.Weight = 1
			state.EffectiveWeight = 1
		}
		if override, ok := runtimeOverrides.Backends[key]; ok {
			if override.AdminState != nil {
				state.AdminState = *override.AdminState
			}
			if override.WeightOverride != nil {
				weight := *override.WeightOverride
				state.WeightOverride = &weight
				state.EffectiveWeight = weight
			}
		}
		if prevState, ok := prevMap[key]; ok {
			state.Healthy = prevState.Healthy
			state.InFlight = prevState.InFlight
			state.CheckedAt = prevState.CheckedAt
			state.LastSuccessAt = prevState.LastSuccessAt
			state.LastFailureAt = prevState.LastFailureAt
			state.ConsecutiveFailures = prevState.ConsecutiveFailures
			state.LastError = prevState.LastError
			state.LastStatusCode = prevState.LastStatusCode
			state.LastLatencyMS = prevState.LastLatencyMS
			state.PassiveFailures = prevState.PassiveFailures
			state.CircuitState = prevState.CircuitState
			state.CircuitOpenedAt = prevState.CircuitOpenedAt
			state.CircuitReopenAt = prevState.CircuitReopenAt
			state.HalfOpenRequests = prevState.HalfOpenRequests
		}
		if endpoint, err := proxyHealthEndpoint(cfg, target); err == nil {
			state.Endpoint = endpoint
		}
		state.HealthState = proxyBackendHealthState(cfg, state)
		state.EffectiveSelectable = proxyBackendSelectableLocked(cfg, state, now)
		out = append(out, state)
	}
	return out, nil
}

func proxyBackendMetricLabels(backends []*proxyBackendState) []string {
	labels := make([]string, 0, len(backends))
	for _, backend := range backends {
		if backend == nil {
			continue
		}
		labels = append(labels, proxyTransportMetricsUpstreamLabel(backend.Name, backend.Target, true))
	}
	return labels
}

func proxyActiveTransportMetricLabels(cfg ProxyRulesConfig, backends []*proxyBackendState) []string {
	active := proxyTransportMetricLabelsSet(proxyBackendMetricLabels(backends))
	appendRouteTargets := func(action ProxyRouteAction) {
		for _, ref := range []string{action.Upstream, action.CanaryUpstream} {
			candidate, err := proxyRouteTargetCandidateFromRef(cfg, ref, 1)
			if err != nil || candidate.Target == nil {
				continue
			}
			label := proxyTransportMetricsUpstreamLabel(candidate.Name, candidate.Target, candidate.Managed)
			if strings.TrimSpace(label) == "" {
				continue
			}
			active[label] = struct{}{}
		}
	}
	if cfg.DefaultRoute != nil && proxyRouteEnabled(cfg.DefaultRoute.Enabled) {
		appendRouteTargets(cfg.DefaultRoute.Action)
	}
	for _, route := range cfg.Routes {
		if !proxyRouteEnabled(route.Enabled) {
			continue
		}
		appendRouteTargets(route.Action)
	}
	labels := make([]string, 0, len(active))
	for label := range active {
		labels = append(labels, label)
	}
	return labels
}

func proxyBackendSetChanged(prev []*proxyBackendState, next []*proxyBackendState) bool {
	if len(prev) != len(next) {
		return true
	}
	if len(prev) == 0 {
		return false
	}

	prevKeys := make(map[string]int, len(prev))
	for _, backend := range prev {
		if backend == nil {
			continue
		}
		prevKeys[backend.Key]++
	}
	nextKeys := make(map[string]int, len(next))
	for _, backend := range next {
		if backend == nil {
			continue
		}
		nextKeys[backend.Key]++
	}
	if len(prevKeys) != len(nextKeys) {
		return true
	}
	for key, count := range prevKeys {
		if nextKeys[key] != count {
			return true
		}
	}
	return false
}

func proxyBackendLessLoaded(a, b *proxyBackendState) bool {
	if a == nil {
		return false
	}
	if b == nil {
		return true
	}
	left := int64(a.InFlight) * int64(b.Weight)
	right := int64(b.InFlight) * int64(a.Weight)
	if left == right {
		return a.Name < b.Name
	}
	return left < right
}

func cloneURL(in *url.URL) *url.URL {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func asProxyRulesConflict(err error, target *proxyRulesConflictError) bool {
	if err == nil || target == nil {
		return false
	}
	var c proxyRulesConflictError
	if !errors.As(err, &c) {
		return false
	}
	*target = c
	return true
}
