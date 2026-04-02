package handler

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

func MetricsHandler(c *gin.Context) {
	semantic := GetSemanticStats()
	rate := GetRateLimitStats()
	notify := GetNotificationStatus()
	ipReputation := IPReputationStatus()

	var b strings.Builder
	writePromCounter(&b, "tukuyomi_rate_limit_requests_total", rate.Requests)
	writePromCounter(&b, "tukuyomi_rate_limit_allowed_total", rate.Allowed)
	writePromCounter(&b, "tukuyomi_rate_limit_blocked_total", rate.Blocked)
	writePromCounter(&b, "tukuyomi_rate_limit_adaptive_total", rate.AdaptiveDecisions)
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

	c.Data(200, "text/plain; version=0.0.4; charset=utf-8", []byte(b.String()))
}

func writePromCounter(b *strings.Builder, name string, value uint64) {
	fmt.Fprintf(b, "# TYPE %s counter\n%s %d\n", name, name, value)
}

func writePromGauge(b *strings.Builder, name string, value int) {
	fmt.Fprintf(b, "# TYPE %s gauge\n%s %d\n", name, name, value)
}
