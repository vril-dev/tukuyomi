package handler

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/config"
	"tukuyomi/internal/middleware"
	"tukuyomi/internal/overloadstate"
	"tukuyomi/internal/proxycompression"
	"tukuyomi/internal/serverruntime"
)

func MetricsHandler(c *gin.Context) {
	semantic := GetSemanticStats()
	rate := GetRateLimitStats()
	notify := GetNotificationStatus()
	ipReputation := IPReputationStatus()
	adminRate := AdminRateLimitStatsSnapshot()
	requestSecurityEvents := RequestSecurityEventStatsSnapshot()
	tlsStatus := ServerTLSRuntimeStatusSnapshot()
	http3Status := serverruntime.HTTP3StatusSnapshot()
	nativeHTTP1Status := NativeHTTP1ServerMetricsSnapshot()
	securityAudit := SecurityAuditStatusSnapshot()
	wafEventAsync := WAFEventAsyncStatusSnapshot()
	globalOverload := overloadstate.Snapshot("global")
	proxyOverload := overloadstate.Snapshot("proxy")
	_, _, proxyCfg, proxyHealth, _ := ProxyRulesSnapshot()
	siteStatuses := SiteStatusSnapshot()
	proxyCompressionStatus := proxyResponseCompressionStatusSnapshot()
	transportMetrics := ProxyTransportMetricsSnapshot()
	proxyRuntimeReady := proxyRuntimeInstance() != nil
	proxyCompressionEnabled := proxyRuntimeReady && proxycompression.Enabled(proxyCfg.ResponseCompression)

	var b strings.Builder
	writePromCounter(&b, "tukuyomi_rate_limit_requests_total", rate.Requests)
	writePromCounter(&b, "tukuyomi_rate_limit_allowed_total", rate.Allowed)
	writePromCounter(&b, "tukuyomi_rate_limit_blocked_total", rate.Blocked)
	writePromCounter(&b, "tukuyomi_rate_limit_adaptive_total", rate.AdaptiveDecisions)
	writePromCounter(&b, "tukuyomi_request_security_events_published_total", requestSecurityEvents.PublishedTotal)
	writePromCounter(&b, "tukuyomi_bot_challenge_failures_total", requestSecurityEvents.BotChallengeFailuresTotal)
	writePromCounter(&b, "tukuyomi_bot_challenge_penalties_total", requestSecurityEvents.BotChallengePenaltiesTotal)
	writePromCounter(&b, "tukuyomi_rate_limit_quarantine_promotions_total", requestSecurityEvents.RateLimitPromotionsTotal)
	writePromCounter(&b, "tukuyomi_rate_limit_quarantine_promotion_dry_run_total", requestSecurityEvents.RateLimitPromotionDryRunTotal)
	writePromCounter(&b, "tukuyomi_semantic_inspected_requests_total", semantic.InspectedRequests)
	writePromCounter(&b, "tukuyomi_semantic_scored_requests_total", semantic.ScoredRequests)
	writePromCounter(&b, "tukuyomi_semantic_log_only_actions_total", semantic.LogOnlyActions)
	writePromCounter(&b, "tukuyomi_semantic_challenge_actions_total", semantic.ChallengeActions)
	writePromCounter(&b, "tukuyomi_semantic_block_actions_total", semantic.BlockActions)
	writePromCounter(&b, "tukuyomi_notifications_attempted_total", notify.Attempted)
	writePromCounter(&b, "tukuyomi_notifications_sent_total", notify.Sent)
	writePromCounter(&b, "tukuyomi_notifications_failed_total", notify.Failed)
	writePromGauge(&b, "tukuyomi_notifications_active_alerts", notify.ActiveAlerts)
	writePromGauge(&b, "tukuyomi_ip_reputation_effective_allow_count", ipReputation.EffectiveAllowCount)
	writePromGauge(&b, "tukuyomi_ip_reputation_effective_block_count", ipReputation.EffectiveBlockCount)
	writePromGauge(&b, "tukuyomi_ip_reputation_feed_allow_count", ipReputation.FeedAllowCount)
	writePromGauge(&b, "tukuyomi_ip_reputation_feed_block_count", ipReputation.FeedBlockCount)
	writePromGauge(&b, "tukuyomi_ip_reputation_dynamic_penalty_count", ipReputation.DynamicPenaltyCount)
	writePromCounter(&b, "tukuyomi_admin_rate_limit_requests_total", adminRate.Requests)
	writePromCounter(&b, "tukuyomi_admin_rate_limit_allowed_total", adminRate.Allowed)
	writePromCounter(&b, "tukuyomi_admin_rate_limit_blocked_total", adminRate.Blocked)
	writePromGauge(&b, "tukuyomi_security_audit_enabled", boolGauge(securityAudit.Enabled))
	writePromCounter(&b, "tukuyomi_security_audit_records_total", securityAudit.RecordsTotal)
	writePromCounter(&b, "tukuyomi_security_audit_captures_total", securityAudit.CapturesTotal)
	writePromCounter(&b, "tukuyomi_security_audit_verify_failures_total", securityAudit.VerifyFailuresTotal)
	writePromGauge(&b, "tukuyomi_security_audit_last_integrity_sequence", int(securityAudit.LastIntegritySequence))
	writePromGauge(&b, "tukuyomi_security_audit_last_verify_ok", boolGauge(securityAudit.LastVerifyOK))
	writePromGauge(&b, "tukuyomi_security_audit_last_verification_anchored", boolGauge(securityAudit.LastVerificationAnchor))
	writePromCounter(&b, "tukuyomi_waf_event_async_enqueued_total", wafEventAsync.EnqueuedTotal)
	writePromCounter(&b, "tukuyomi_waf_event_async_written_total", wafEventAsync.WrittenTotal)
	writePromCounter(&b, "tukuyomi_waf_event_async_dropped_total", wafEventAsync.DroppedTotal)
	writePromCounter(&b, "tukuyomi_waf_event_async_write_failures_total", wafEventAsync.WriteFailuresTotal)
	writePromGauge(&b, "tukuyomi_waf_event_async_queue_current", wafEventAsync.QueueCurrent)
	writePromGauge(&b, "tukuyomi_waf_event_async_queue_capacity", wafEventAsync.QueueCapacity)
	writePromGauge(&b, "tukuyomi_server_tls_enabled", boolGauge(tlsStatus.Enabled))
	writePromGauge(&b, "tukuyomi_server_tls_source_manual", boolGauge(tlsStatus.Source == "manual" || tlsStatus.Source == "composite"))
	writePromGauge(&b, "tukuyomi_server_tls_source_acme", boolGauge(tlsStatus.Source == "acme" || tlsStatus.Source == "composite"))
	writePromGauge(&b, "tukuyomi_server_tls_source_composite", boolGauge(tlsStatus.Source == "composite"))
	writePromGauge(&b, "tukuyomi_server_tls_acme_enabled", boolGauge(tlsStatus.Source == "acme" || tlsStatus.Source == "composite"))
	writePromGauge(&b, "tukuyomi_server_tls_cert_not_after_unix", optionalUnixGauge(tlsStatus.CertNotAfter))
	writePromCounter(&b, "tukuyomi_server_tls_acme_success_total", tlsStatus.ACMESuccessTotal)
	writePromCounter(&b, "tukuyomi_server_tls_acme_failure_total", tlsStatus.ACMEFailureTotal)
	writePromGauge(&b, "tukuyomi_server_http3_enabled", boolGauge(config.ServerHTTP3Enabled))
	writePromGauge(&b, "tukuyomi_server_http3_advertised", boolGauge(http3Status.Advertised))
	writePromGaugeLabeled(&b, "tukuyomi_server_engine_mode", map[string]string{"mode": "native_http1"}, 1)
	writePromCounter(&b, "tukuyomi_native_http1_accepted_connections_total", nativeHTTP1Status.AcceptedConnections)
	writePromCounter(&b, "tukuyomi_native_http1_rejected_connections_total", nativeHTTP1Status.RejectedConnections)
	writePromCounter(&b, "tukuyomi_native_http1_keepalive_reuses_total", nativeHTTP1Status.KeepAliveReuses)
	writePromCounter(&b, "tukuyomi_native_http1_parse_errors_total", nativeHTTP1Status.ParseErrors)
	writePromCounter(&b, "tukuyomi_native_http1_scrubbed_headers_total", nativeHTTP1Status.ScrubbedHeaders)
	writePromCounter(&b, "tukuyomi_native_http1_tls_handshake_failures_total", nativeHTTP1Status.TLSHandshakeFailures)
	writePromGauge(&b, "tukuyomi_native_http1_active_connections", int(nativeHTTP1Status.ActiveConnections))
	writePromGauge(&b, "tukuyomi_native_http1_idle_connections", int(nativeHTTP1Status.IdleConnections))
	writeOverloadMetrics(&b, globalOverload)
	writeOverloadMetrics(&b, proxyOverload)
	writePromGauge(&b, "tukuyomi_proxy_response_compression_enabled", boolGauge(proxyCompressionEnabled))
	writePromCounter(&b, "tukuyomi_proxy_response_compression_compressed_total", uint64(proxyCompressionStatus.CompressedTotal))
	writePromCounter(&b, "tukuyomi_proxy_response_compression_bytes_in_total", uint64(proxyCompressionStatus.CompressedBytesIn))
	writePromCounter(&b, "tukuyomi_proxy_response_compression_bytes_out_total", uint64(proxyCompressionStatus.CompressedBytesOut))
	writePromCounter(&b, "tukuyomi_proxy_response_compression_skipped_client_total", uint64(proxyCompressionStatus.SkippedClientTotal))
	writePromCounter(&b, "tukuyomi_proxy_response_compression_skipped_encoded_total", uint64(proxyCompressionStatus.SkippedEncodedTotal))
	writePromCounter(&b, "tukuyomi_proxy_response_compression_skipped_bodyless_total", uint64(proxyCompressionStatus.SkippedBodylessTotal))
	writePromCounter(&b, "tukuyomi_proxy_response_compression_skipped_small_total", uint64(proxyCompressionStatus.SkippedSmallTotal))
	writePromCounter(&b, "tukuyomi_proxy_response_compression_skipped_mime_total", uint64(proxyCompressionStatus.SkippedMimeTotal))
	writePromCounter(&b, "tukuyomi_proxy_response_compression_skipped_transform_total", uint64(proxyCompressionStatus.SkippedTransformTotal))
	writePromCounter(&b, "tukuyomi_proxy_response_compression_skipped_upgrade_total", uint64(proxyCompressionStatus.SkippedUpgradeTotal))
	for _, algorithm := range supportedProxyResponseCompressionAlgorithms {
		writePromGaugeLabeled(&b, "tukuyomi_proxy_response_compression_algorithm_enabled", map[string]string{"algorithm": algorithm}, boolGauge(proxyRuntimeReady && proxycompression.AllowsAlgorithm(proxyCfg.ResponseCompression, algorithm)))
		writePromCounterLabeled(&b, "tukuyomi_proxy_response_compression_compressed_by_algorithm_total", map[string]string{"algorithm": algorithm}, uint64(proxyCompressionStatus.CompressedByAlgorithm[algorithm]))
	}
	writePromGauge(&b, "tukuyomi_upstream_active_backends", proxyHealth.ActiveBackends)
	writePromGauge(&b, "tukuyomi_upstream_healthy_backends", proxyHealth.HealthyBackends)
	writePromGauge(&b, "tukuyomi_proxy_transport_max_idle_conns", proxyCfg.MaxIdleConns)
	writePromGauge(&b, "tukuyomi_proxy_transport_max_idle_conns_per_host", proxyCfg.MaxIdleConnsPerHost)
	writePromGauge(&b, "tukuyomi_proxy_transport_max_conns_per_host", proxyCfg.MaxConnsPerHost)
	for _, backend := range proxyHealth.Backends {
		upstream := proxyTransportMetricsUpstreamLabel(backend.Name, mustURL(backend.URL), true)
		labels := map[string]string{"upstream": upstream}
		writePromGaugeLabeled(&b, "tukuyomi_upstream_backend_healthy", labels, boolGauge(backend.Enabled && backend.Healthy))
		writePromGaugeLabeled(&b, "tukuyomi_upstream_inflight_requests", labels, backend.InFlight)
		writePromGaugeLabeled(&b, "tukuyomi_upstream_passive_failures", labels, backend.PassiveFailures)
		circuitState := backend.CircuitState
		if strings.TrimSpace(circuitState) == "" {
			circuitState = proxyTransportCircuitStateClosed
		}
		for _, state := range []string{proxyTransportCircuitStateClosed, proxyTransportCircuitStateHalfOpen, proxyTransportCircuitStateOpen} {
			writePromGaugeLabeled(&b, "tukuyomi_upstream_circuit_state", map[string]string{
				"state":    state,
				"upstream": upstream,
			}, boolGauge(circuitState == state))
		}
	}
	for _, upstream := range transportMetrics.Upstreams {
		labels := map[string]string{"upstream": upstream.Upstream}
		writePromHistogramLabeled(&b, "tukuyomi_upstream_request_duration_seconds", labels, transportMetrics.BucketBounds, upstream.LatencyBucketCounts, upstream.LatencySecondsSum, upstream.RequestsTotal)
		writePromCounterLabeled(&b, "tukuyomi_upstream_errors_total", map[string]string{
			"kind":     proxyTransportErrorKindTransport,
			"upstream": upstream.Upstream,
		}, upstream.ErrorsTransportTotal)
		writePromCounterLabeled(&b, "tukuyomi_upstream_errors_total", map[string]string{
			"kind":     proxyTransportErrorKindStatus,
			"upstream": upstream.Upstream,
		}, upstream.ErrorsStatusTotal)
		writePromCounterLabeled(&b, "tukuyomi_upstream_errors_total", map[string]string{
			"kind":     proxyTransportErrorKindUnavailable,
			"upstream": upstream.Upstream,
		}, upstream.ErrorsUnavailable)
		writePromCounterLabeled(&b, "tukuyomi_upstream_retries_total", map[string]string{
			"reason":   proxyTransportRetryReasonTransport,
			"upstream": upstream.Upstream,
		}, upstream.RetriesTransportTotal)
		writePromCounterLabeled(&b, "tukuyomi_upstream_retries_total", map[string]string{
			"reason":   proxyTransportRetryReasonStatus,
			"upstream": upstream.Upstream,
		}, upstream.RetriesStatusTotal)
		writePromCounterLabeled(&b, "tukuyomi_upstream_retries_total", map[string]string{
			"reason":   proxyTransportRetryReasonUnavailable,
			"upstream": upstream.Upstream,
		}, upstream.RetriesUnavailable)
		writePromCounterLabeled(&b, "tukuyomi_upstream_passive_failures_total", map[string]string{
			"reason":   proxyTransportPassiveFailureReasonTransport,
			"upstream": upstream.Upstream,
		}, upstream.PassiveFailuresTransportTotal)
		writePromCounterLabeled(&b, "tukuyomi_upstream_passive_failures_total", map[string]string{
			"reason":   proxyTransportPassiveFailureReasonStatus,
			"upstream": upstream.Upstream,
		}, upstream.PassiveFailuresStatusTotal)
		writePromCounterLabeled(&b, "tukuyomi_upstream_circuit_transitions_total", map[string]string{
			"state":    proxyTransportCircuitStateOpen,
			"upstream": upstream.Upstream,
		}, upstream.CircuitOpenTransitionsTotal)
		writePromCounterLabeled(&b, "tukuyomi_upstream_circuit_transitions_total", map[string]string{
			"state":    proxyTransportCircuitStateHalfOpen,
			"upstream": upstream.Upstream,
		}, upstream.CircuitHalfOpenTransitionsTotal)
		writePromCounterLabeled(&b, "tukuyomi_upstream_circuit_transitions_total", map[string]string{
			"state":    proxyTransportCircuitStateClosed,
			"upstream": upstream.Upstream,
		}, upstream.CircuitClosedTransitionsTotal)
	}
	writePromGauge(&b, "tukuyomi_sites_total", len(siteStatuses))
	writePromGauge(&b, "tukuyomi_sites_enabled_total", countEnabledSiteStatuses(siteStatuses))
	writePromGauge(&b, "tukuyomi_sites_tls_covered_total", countSiteStatuses(siteStatuses, "covered"))
	for _, site := range siteStatuses {
		name := sanitizePromLabel(site.Name)
		fmt.Fprintf(&b, "# TYPE tukuyomi_site_tls_covered gauge\ntukuyomi_site_tls_covered{site=%q,mode=%q} %d\n", name, site.TLSMode, boolGauge(site.Enabled && site.TLSStatus == "covered"))
		fmt.Fprintf(&b, "# TYPE tukuyomi_site_enabled gauge\ntukuyomi_site_enabled{site=%q,mode=%q} %d\n", name, site.TLSMode, boolGauge(site.Enabled))
	}

	c.Data(200, "text/plain; version=0.0.4; charset=utf-8", []byte(b.String()))
}

func writePromCounter(b *strings.Builder, name string, value uint64) {
	fmt.Fprintf(b, "# TYPE %s counter\n%s %d\n", name, name, value)
}

func writePromGauge(b *strings.Builder, name string, value int) {
	fmt.Fprintf(b, "# TYPE %s gauge\n%s %d\n", name, name, value)
}

func writePromGaugeUInt64Labeled(b *strings.Builder, name string, labels map[string]string, value uint64) {
	fmt.Fprintf(b, "# TYPE %s gauge\n%s%s %d\n", name, name, formatPromLabels(labels), value)
}

func writePromCounterLabeled(b *strings.Builder, name string, labels map[string]string, value uint64) {
	fmt.Fprintf(b, "# TYPE %s counter\n%s%s %d\n", name, name, formatPromLabels(labels), value)
}

func writePromGaugeLabeled(b *strings.Builder, name string, labels map[string]string, value int) {
	fmt.Fprintf(b, "# TYPE %s gauge\n%s%s %d\n", name, name, formatPromLabels(labels), value)
}

func writePromHistogramLabeled(b *strings.Builder, name string, labels map[string]string, bounds []float64, bucketCounts []uint64, sum float64, count uint64) {
	cumulative := uint64(0)
	for i, upper := range bounds {
		if i < len(bucketCounts) {
			cumulative += bucketCounts[i]
		}
		nextLabels := clonePromLabels(labels)
		nextLabels["le"] = strconv.FormatFloat(upper, 'f', -1, 64)
		fmt.Fprintf(b, "# TYPE %s histogram\n%s_bucket%s %d\n", name, name, formatPromLabels(nextLabels), cumulative)
	}
	infLabels := clonePromLabels(labels)
	infLabels["le"] = "+Inf"
	fmt.Fprintf(b, "# TYPE %s histogram\n%s_bucket%s %d\n", name, name, formatPromLabels(infLabels), count)
	fmt.Fprintf(b, "# TYPE %s histogram\n%s_sum%s %.6f\n", name, name, formatPromLabels(labels), sum)
	fmt.Fprintf(b, "# TYPE %s histogram\n%s_count%s %d\n", name, name, formatPromLabels(labels), count)
}

func formatPromLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	order := make([]string, 0, len(labels))
	for key := range labels {
		order = append(order, key)
	}
	slices.Sort(order)
	parts := make([]string, 0, len(order))
	for _, key := range order {
		parts = append(parts, fmt.Sprintf(`%s=%q`, key, sanitizePromLabel(labels[key])))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func clonePromLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func writeOverloadMetrics(b *strings.Builder, snapshot middleware.ConcurrencyGuardSnapshot) {
	labels := map[string]string{"scope": snapshot.Name}
	writePromGaugeLabeled(b, "tukuyomi_overload_guard_enabled", labels, boolGauge(snapshot.Enabled))
	writePromGaugeLabeled(b, "tukuyomi_overload_limit", labels, snapshot.Limit)
	writePromGaugeLabeled(b, "tukuyomi_overload_inflight_requests", labels, snapshot.InFlight)
	writePromGaugeLabeled(b, "tukuyomi_overload_queue_enabled", labels, boolGauge(snapshot.QueueEnabled))
	writePromGaugeLabeled(b, "tukuyomi_overload_queue_capacity", labels, snapshot.QueueCapacity)
	writePromGaugeLabeled(b, "tukuyomi_overload_queue_current", labels, snapshot.QueueCurrent)
	writePromGaugeLabeled(b, "tukuyomi_overload_queue_peak", labels, snapshot.QueuePeak)
	writePromGaugeLabeled(b, "tukuyomi_overload_queue_timeout_ms", labels, snapshot.QueueTimeoutMS)
	writePromCounterLabeled(b, "tukuyomi_overload_queue_entered_total", labels, snapshot.QueueEnteredTotal)
	writePromCounterLabeled(b, "tukuyomi_overload_admitted_total", map[string]string{
		"mode":  "immediate",
		"scope": snapshot.Name,
	}, snapshot.AdmittedImmediateTotal)
	writePromCounterLabeled(b, "tukuyomi_overload_admitted_total", map[string]string{
		"mode":  "queued",
		"scope": snapshot.Name,
	}, snapshot.AdmittedQueuedTotal)
	writePromCounterLabeled(b, "tukuyomi_overload_rejected_total", map[string]string{
		"reason": "limit_reached",
		"scope":  snapshot.Name,
	}, snapshot.RejectedLimitReachedTotal)
	writePromCounterLabeled(b, "tukuyomi_overload_rejected_total", map[string]string{
		"reason": "queue_full",
		"scope":  snapshot.Name,
	}, snapshot.RejectedQueueFullTotal)
	writePromCounterLabeled(b, "tukuyomi_overload_rejected_total", map[string]string{
		"reason": "queue_timeout",
		"scope":  snapshot.Name,
	}, snapshot.RejectedQueueTimeoutTotal)
	writePromCounterLabeled(b, "tukuyomi_overload_rejected_total", map[string]string{
		"reason": "request_canceled",
		"scope":  snapshot.Name,
	}, snapshot.RejectedCanceledTotal)
	writePromCounterLabeled(b, "tukuyomi_overload_queue_wait_total_ms", labels, snapshot.QueueWaitTotalMS)
	writePromGaugeUInt64Labeled(b, "tukuyomi_overload_queue_wait_max_ms", labels, snapshot.QueueWaitMaxMS)
	writePromGaugeUInt64Labeled(b, "tukuyomi_overload_queue_wait_last_ms", labels, snapshot.LastQueueWaitMS)
}

func boolGauge(v bool) int {
	if v {
		return 1
	}
	return 0
}

func optionalUnixGauge(ts string) int {
	if strings.TrimSpace(ts) == "" {
		return 0
	}
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return 0
	}
	return int(parsed.Unix())
}

func countEnabledSiteStatuses(statuses []SiteRuntimeStatus) int {
	total := 0
	for _, status := range statuses {
		if status.Enabled {
			total++
		}
	}
	return total
}

func countSiteStatuses(statuses []SiteRuntimeStatus, want string) int {
	total := 0
	for _, status := range statuses {
		if status.TLSStatus == want {
			total++
		}
	}
	return total
}

func sanitizePromLabel(v string) string {
	if strings.TrimSpace(v) == "" {
		return "site"
	}
	return strings.TrimSpace(v)
}
