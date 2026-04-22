package handler

import (
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var proxyTransportLatencyBucketsSeconds = []float64{
	0.005,
	0.01,
	0.025,
	0.05,
	0.1,
	0.25,
	0.5,
	1,
	2.5,
	5,
	10,
}

const (
	proxyTransportErrorKindTransport   = "transport"
	proxyTransportErrorKindStatus      = "status"
	proxyTransportErrorKindUnavailable = "unavailable"

	proxyTransportRetryReasonTransport   = "transport"
	proxyTransportRetryReasonStatus      = "status"
	proxyTransportRetryReasonUnavailable = "unavailable"

	proxyTransportPassiveFailureReasonTransport = "transport"
	proxyTransportPassiveFailureReasonStatus    = "status"

	proxyTransportCircuitStateClosed   = "closed"
	proxyTransportCircuitStateHalfOpen = "half_open"
	proxyTransportCircuitStateOpen     = "open"
)

type proxyTransportMetrics struct {
	mu         sync.Mutex
	bounds     []float64
	active     map[string]struct{}
	configured bool
	upstreams  map[string]*proxyTransportUpstreamMetrics
}

type proxyTransportUpstreamMetrics struct {
	latencyBucketCounts []atomic.Uint64
	latencyMicrosTotal  atomic.Uint64
	requestsTotal       atomic.Uint64

	errorsTransportTotal   atomic.Uint64
	errorsStatusTotal      atomic.Uint64
	errorsUnavailableTotal atomic.Uint64

	retriesTransportTotal   atomic.Uint64
	retriesStatusTotal      atomic.Uint64
	retriesUnavailableTotal atomic.Uint64

	passiveFailuresTransportTotal atomic.Uint64
	passiveFailuresStatusTotal    atomic.Uint64

	circuitOpenTransitionsTotal     atomic.Uint64
	circuitHalfOpenTransitionsTotal atomic.Uint64
	circuitClosedTransitionsTotal   atomic.Uint64
}

type proxyTransportMetricsSnapshot struct {
	BucketBounds []float64
	Upstreams    []proxyTransportUpstreamMetricsSnapshot
}

type proxyTransportUpstreamMetricsSnapshot struct {
	Upstream             string
	LatencyBucketCounts  []uint64
	LatencySecondsSum    float64
	RequestsTotal        uint64
	ErrorsTransportTotal uint64
	ErrorsStatusTotal    uint64
	ErrorsUnavailable    uint64

	RetriesTransportTotal uint64
	RetriesStatusTotal    uint64
	RetriesUnavailable    uint64

	PassiveFailuresTransportTotal uint64
	PassiveFailuresStatusTotal    uint64

	CircuitOpenTransitionsTotal     uint64
	CircuitHalfOpenTransitionsTotal uint64
	CircuitClosedTransitionsTotal   uint64
}

func newProxyTransportMetrics() *proxyTransportMetrics {
	return &proxyTransportMetrics{
		bounds:    append([]float64(nil), proxyTransportLatencyBucketsSeconds...),
		active:    make(map[string]struct{}),
		upstreams: make(map[string]*proxyTransportUpstreamMetrics),
	}
}

func (m *proxyTransportMetrics) Snapshot() proxyTransportMetricsSnapshot {
	if m == nil {
		return proxyTransportMetricsSnapshot{
			BucketBounds: append([]float64(nil), proxyTransportLatencyBucketsSeconds...),
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	upstreams := make([]string, 0, len(m.upstreams))
	for upstream := range m.upstreams {
		upstreams = append(upstreams, upstream)
	}
	slices.Sort(upstreams)

	snapshot := proxyTransportMetricsSnapshot{
		BucketBounds: append([]float64(nil), m.bounds...),
		Upstreams:    make([]proxyTransportUpstreamMetricsSnapshot, 0, len(upstreams)),
	}
	for _, upstream := range upstreams {
		entry := m.upstreams[upstream]
		if entry == nil {
			continue
		}
		bucketCounts := make([]uint64, len(entry.latencyBucketCounts))
		for i := range entry.latencyBucketCounts {
			bucketCounts[i] = entry.latencyBucketCounts[i].Load()
		}
		snapshot.Upstreams = append(snapshot.Upstreams, proxyTransportUpstreamMetricsSnapshot{
			Upstream:                        upstream,
			LatencyBucketCounts:             bucketCounts,
			LatencySecondsSum:               float64(entry.latencyMicrosTotal.Load()) / 1_000_000,
			RequestsTotal:                   entry.requestsTotal.Load(),
			ErrorsTransportTotal:            entry.errorsTransportTotal.Load(),
			ErrorsStatusTotal:               entry.errorsStatusTotal.Load(),
			ErrorsUnavailable:               entry.errorsUnavailableTotal.Load(),
			RetriesTransportTotal:           entry.retriesTransportTotal.Load(),
			RetriesStatusTotal:              entry.retriesStatusTotal.Load(),
			RetriesUnavailable:              entry.retriesUnavailableTotal.Load(),
			PassiveFailuresTransportTotal:   entry.passiveFailuresTransportTotal.Load(),
			PassiveFailuresStatusTotal:      entry.passiveFailuresStatusTotal.Load(),
			CircuitOpenTransitionsTotal:     entry.circuitOpenTransitionsTotal.Load(),
			CircuitHalfOpenTransitionsTotal: entry.circuitHalfOpenTransitionsTotal.Load(),
			CircuitClosedTransitionsTotal:   entry.circuitClosedTransitionsTotal.Load(),
		})
	}
	return snapshot
}

func (m *proxyTransportMetrics) RecordAttempt(name string, target *url.URL, managed bool, latency time.Duration) {
	if m == nil {
		return
	}
	entry := m.entry(proxyTransportMetricsUpstreamLabel(name, target, managed))
	if entry == nil {
		return
	}
	micros := latency.Microseconds()
	if micros < 0 {
		micros = 0
	}
	entry.requestsTotal.Add(1)
	entry.latencyMicrosTotal.Add(uint64(micros))
	seconds := float64(micros) / 1_000_000
	for i, upper := range m.bounds {
		if seconds <= upper {
			entry.latencyBucketCounts[i].Add(1)
			return
		}
	}
}

func (m *proxyTransportMetrics) RecordError(name string, target *url.URL, managed bool, kind string) {
	entry := m.entry(proxyTransportMetricsUpstreamLabel(name, target, managed))
	if entry == nil {
		return
	}
	switch kind {
	case proxyTransportErrorKindTransport:
		entry.errorsTransportTotal.Add(1)
	case proxyTransportErrorKindStatus:
		entry.errorsStatusTotal.Add(1)
	case proxyTransportErrorKindUnavailable:
		entry.errorsUnavailableTotal.Add(1)
	}
}

func (m *proxyTransportMetrics) RecordRetry(name string, target *url.URL, managed bool, reason string) {
	entry := m.entry(proxyTransportMetricsUpstreamLabel(name, target, managed))
	if entry == nil {
		return
	}
	switch reason {
	case proxyTransportRetryReasonTransport:
		entry.retriesTransportTotal.Add(1)
	case proxyTransportRetryReasonStatus:
		entry.retriesStatusTotal.Add(1)
	case proxyTransportRetryReasonUnavailable:
		entry.retriesUnavailableTotal.Add(1)
	}
}

func (m *proxyTransportMetrics) RecordPassiveFailure(name string, target *url.URL, managed bool, reason string) {
	entry := m.entry(proxyTransportMetricsUpstreamLabel(name, target, managed))
	if entry == nil {
		return
	}
	switch reason {
	case proxyTransportPassiveFailureReasonTransport:
		entry.passiveFailuresTransportTotal.Add(1)
	case proxyTransportPassiveFailureReasonStatus:
		entry.passiveFailuresStatusTotal.Add(1)
	}
}

func (m *proxyTransportMetrics) RecordCircuitTransition(name string, target *url.URL, managed bool, state string) {
	entry := m.entry(proxyTransportMetricsUpstreamLabel(name, target, managed))
	if entry == nil {
		return
	}
	switch state {
	case proxyTransportCircuitStateOpen:
		entry.circuitOpenTransitionsTotal.Add(1)
	case proxyTransportCircuitStateHalfOpen:
		entry.circuitHalfOpenTransitionsTotal.Add(1)
	case proxyTransportCircuitStateClosed:
		entry.circuitClosedTransitionsTotal.Add(1)
	}
}

func (m *proxyTransportMetrics) SyncUpstreams(labels []string) {
	if m == nil {
		return
	}
	nextActive := proxyTransportMetricLabelsSet(labels)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = nextActive
	m.configured = true
	for label := range m.upstreams {
		if _, ok := m.active[label]; ok {
			continue
		}
		delete(m.upstreams, label)
	}
}

func (m *proxyTransportMetrics) ResetUpstreams(labels []string) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = proxyTransportMetricLabelsSet(labels)
	m.configured = true
	if len(m.upstreams) == 0 {
		m.upstreams = make(map[string]*proxyTransportUpstreamMetrics)
		return
	}
	preserved := make(map[string]*proxyTransportUpstreamMetrics, len(m.active))
	for label := range m.active {
		if entry, ok := m.upstreams[label]; ok {
			preserved[label] = entry
		}
	}
	m.upstreams = preserved
}

func (m *proxyTransportMetrics) entry(label string) *proxyTransportUpstreamMetrics {
	if m == nil {
		return nil
	}
	label = strings.TrimSpace(label)
	if label == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.configured {
		if _, ok := m.active[label]; !ok {
			return nil
		}
	}
	if entry, ok := m.upstreams[label]; ok {
		return entry
	}
	entry := &proxyTransportUpstreamMetrics{
		latencyBucketCounts: make([]atomic.Uint64, len(m.bounds)),
	}
	m.upstreams[label] = entry
	return entry
}

func proxyTransportMetricLabelsSet(labels []string) map[string]struct{} {
	out := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		trimmed := strings.TrimSpace(label)
		if trimmed == "" {
			continue
		}
		out[trimmed] = struct{}{}
	}
	return out
}

// Managed backends keep a stable, path-safe backend key label, while direct
// absolute route targets fall back to the normalized absolute URL itself.
// SyncUpstreams constrains both cases to the active config set so direct
// targets stay bounded.
func proxyTransportMetricsUpstreamLabel(name string, target *url.URL, managed bool) string {
	trimmedName := strings.TrimSpace(name)
	trimmedTarget := ""
	if target != nil {
		trimmedTarget = strings.TrimSpace(target.String())
	}
	if managed {
		if trimmedName != "" && trimmedTarget != "" {
			return proxyBackendLookupKey(trimmedName, trimmedTarget)
		}
		if trimmedName != "" {
			return trimmedName
		}
	}
	if trimmedTarget != "" {
		return trimmedTarget
	}
	if trimmedName != "" {
		return trimmedName
	}
	return "direct"
}
