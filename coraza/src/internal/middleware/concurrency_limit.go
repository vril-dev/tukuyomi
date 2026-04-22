package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	defaultConcurrencyRetryAfterSeconds = 1

	overloadRejectReasonLimitReached    = "limit_reached"
	overloadRejectReasonQueueFull       = "queue_full"
	overloadRejectReasonQueueTimeout    = "queue_timeout"
	overloadRejectReasonRequestCanceled = "request_canceled"

	overloadHeaderScope       = "X-Tukuyomi-Overload-Scope"
	overloadHeaderQueued      = "X-Tukuyomi-Overload-Queued"
	overloadHeaderQueueWaitMS = "X-Tukuyomi-Overload-Queue-Wait-Ms"
	overloadHeaderReason      = "X-Tukuyomi-Overload-Reason"
)

type ConcurrencyAcquireResult struct {
	Allowed      bool
	Queued       bool
	QueueWait    time.Duration
	RejectReason string
}

type ConcurrencyGuardSnapshot struct {
	Name                      string `json:"name"`
	Enabled                   bool   `json:"enabled"`
	Limit                     int    `json:"limit"`
	InFlight                  int    `json:"inflight"`
	QueueEnabled              bool   `json:"queue_enabled"`
	QueueCapacity             int    `json:"queue_capacity"`
	QueueCurrent              int    `json:"queue_current"`
	QueuePeak                 int    `json:"queue_peak"`
	QueueTimeoutMS            int    `json:"queue_timeout_ms"`
	RetryAfterSeconds         int    `json:"retry_after_seconds"`
	AdmittedImmediateTotal    uint64 `json:"admitted_immediate_total"`
	AdmittedQueuedTotal       uint64 `json:"admitted_queued_total"`
	QueueEnteredTotal         uint64 `json:"queue_entered_total"`
	RejectedTotal             uint64 `json:"rejected_total"`
	RejectedLimitReachedTotal uint64 `json:"rejected_limit_reached_total"`
	RejectedQueueFullTotal    uint64 `json:"rejected_queue_full_total"`
	RejectedQueueTimeoutTotal uint64 `json:"rejected_queue_timeout_total"`
	RejectedCanceledTotal     uint64 `json:"rejected_canceled_total"`
	QueueWaitTotalMS          uint64 `json:"queue_wait_total_ms"`
	QueueWaitMaxMS            uint64 `json:"queue_wait_max_ms"`
	LastQueueWaitMS           uint64 `json:"last_queue_wait_ms"`
}

type requestQueueState struct {
	queued    bool
	queueWait time.Duration
}

type requestQueueStateKey struct{}

type concurrencyWaiter struct {
	granted bool
	ready   chan struct{}
}

type ConcurrencyGuard struct {
	name              string
	max               int
	maxQueue          int
	queueTimeout      time.Duration
	retryAfterSeconds int

	mu       sync.Mutex
	inflight int
	queue    []*concurrencyWaiter
	stats    ConcurrencyGuardSnapshot
}

func NewConcurrencyGuard(max int, name string) *ConcurrencyGuard {
	return NewQueuedConcurrencyGuard(max, 0, 0, name)
}

func NewQueuedConcurrencyGuard(max, maxQueue int, queueTimeout time.Duration, name string) *ConcurrencyGuard {
	if max <= 0 {
		return nil
	}
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		trimmed = "global"
	}
	return &ConcurrencyGuard{
		name:              trimmed,
		max:               max,
		maxQueue:          maxQueue,
		queueTimeout:      queueTimeout,
		retryAfterSeconds: defaultConcurrencyRetryAfterSeconds,
		stats: ConcurrencyGuardSnapshot{
			Name:              trimmed,
			Enabled:           true,
			Limit:             max,
			QueueEnabled:      maxQueue > 0 && queueTimeout > 0,
			QueueCapacity:     maxQueue,
			QueueTimeoutMS:    int(queueTimeout / time.Millisecond),
			RetryAfterSeconds: defaultConcurrencyRetryAfterSeconds,
		},
	}
}

func (g *ConcurrencyGuard) Name() string {
	if g == nil {
		return "global"
	}
	return g.name
}

func (g *ConcurrencyGuard) Acquire() bool {
	return g.AcquireContext(context.Background()).Allowed
}

func (g *ConcurrencyGuard) AcquireContext(ctx context.Context) ConcurrencyAcquireResult {
	return g.acquireContext(ctx, true)
}

func (g *ConcurrencyGuard) AcquireContextNoQueue(ctx context.Context) ConcurrencyAcquireResult {
	return g.acquireContext(ctx, false)
}

func (g *ConcurrencyGuard) acquireContext(ctx context.Context, allowQueue bool) ConcurrencyAcquireResult {
	if g == nil {
		return ConcurrencyAcquireResult{Allowed: true}
	}
	start := time.Now()
	waiter, notify, result := g.acquireOrEnqueue(allowQueue)
	closeGrantedWaiters(notify)
	if waiter == nil {
		return result
	}

	timer := time.NewTimer(g.queueTimeout)
	defer timer.Stop()

	select {
	case <-waiter.ready:
		wait := time.Since(start)
		g.recordQueueWait(wait)
		return ConcurrencyAcquireResult{Allowed: true, Queued: true, QueueWait: wait}
	case <-ctx.Done():
		if g.resolveQueuedWaiter(waiter, overloadRejectReasonRequestCanceled) {
			wait := time.Since(start)
			g.recordQueueWait(wait)
			return ConcurrencyAcquireResult{Allowed: true, Queued: true, QueueWait: wait}
		}
		return ConcurrencyAcquireResult{
			Queued:       true,
			QueueWait:    time.Since(start),
			RejectReason: overloadRejectReasonRequestCanceled,
		}
	case <-timer.C:
		if g.resolveQueuedWaiter(waiter, overloadRejectReasonQueueTimeout) {
			wait := time.Since(start)
			g.recordQueueWait(wait)
			return ConcurrencyAcquireResult{Allowed: true, Queued: true, QueueWait: wait}
		}
		return ConcurrencyAcquireResult{
			Queued:       true,
			QueueWait:    time.Since(start),
			RejectReason: overloadRejectReasonQueueTimeout,
		}
	}
}

func (g *ConcurrencyGuard) Release() {
	if g == nil {
		return
	}
	var notify []*concurrencyWaiter
	g.mu.Lock()
	if g.inflight > 0 {
		g.inflight--
	}
	notify = g.dispatchLocked()
	g.stats.InFlight = g.inflight
	g.mu.Unlock()
	closeGrantedWaiters(notify)
}

func (g *ConcurrencyGuard) Reject(c *gin.Context) {
	g.RejectWithResult(c, ConcurrencyAcquireResult{RejectReason: overloadRejectReasonLimitReached})
}

func (g *ConcurrencyGuard) AnnotateQueuedResponse(c *gin.Context, result ConcurrencyAcquireResult) {
	if g == nil || !result.Queued || !result.Allowed {
		return
	}
	c.Header(overloadHeaderScope, g.Name())
	c.Header(overloadHeaderQueued, "true")
	c.Header(overloadHeaderQueueWaitMS, strconv.FormatUint(queueWaitMilliseconds(result.QueueWait), 10))
}

func (g *ConcurrencyGuard) RejectWithResult(c *gin.Context, result ConcurrencyAcquireResult) {
	scope := "global"
	if g != nil {
		scope = g.name
	}
	retryAfterSeconds := defaultConcurrencyRetryAfterSeconds
	if g != nil {
		retryAfterSeconds = g.retryAfterSeconds
	}
	reason := strings.TrimSpace(result.RejectReason)
	if reason == "" {
		reason = overloadRejectReasonLimitReached
	}
	c.Header("Retry-After", strconv.Itoa(retryAfterSeconds))
	c.Header(overloadHeaderScope, scope)
	c.Header(overloadHeaderQueued, strconv.FormatBool(result.Queued))
	c.Header(overloadHeaderReason, reason)
	if result.QueueWait > 0 {
		c.Header(overloadHeaderQueueWaitMS, strconv.FormatUint(queueWaitMilliseconds(result.QueueWait), 10))
	}
	c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
		"error":         "server busy",
		"scope":         scope,
		"queued":        result.Queued,
		"queue_wait_ms": queueWaitMilliseconds(result.QueueWait),
		"reason":        reason,
	})
}

func (g *ConcurrencyGuard) Snapshot() ConcurrencyGuardSnapshot {
	if g == nil {
		return DisabledConcurrencyGuardSnapshot("global", 0, 0, 0)
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	snapshot := g.stats
	snapshot.InFlight = g.inflight
	snapshot.QueueCurrent = len(g.queue)
	return snapshot
}

func DisabledConcurrencyGuardSnapshot(name string, limit, queueCapacity int, queueTimeout time.Duration) ConcurrencyGuardSnapshot {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		trimmed = "global"
	}
	return ConcurrencyGuardSnapshot{
		Name:              trimmed,
		Enabled:           limit > 0,
		Limit:             limit,
		QueueEnabled:      limit > 0 && queueCapacity > 0 && queueTimeout > 0,
		QueueCapacity:     queueCapacity,
		QueueTimeoutMS:    int(queueTimeout / time.Millisecond),
		RetryAfterSeconds: defaultConcurrencyRetryAfterSeconds,
	}
}

func SnapshotOrDisabled(guard *ConcurrencyGuard, name string, limit, queueCapacity int, queueTimeout time.Duration) ConcurrencyGuardSnapshot {
	if guard == nil {
		return DisabledConcurrencyGuardSnapshot(name, limit, queueCapacity, queueTimeout)
	}
	return guard.Snapshot()
}

func ConcurrencyGuardMiddleware(guard *ConcurrencyGuard) gin.HandlerFunc {
	if guard == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		result := guard.AcquireContext(c.Request.Context())
		if !result.Allowed {
			guard.RejectWithResult(c, result)
			return
		}
		c.Request = c.Request.WithContext(withRequestQueueResult(c.Request.Context(), result))
		guard.AnnotateQueuedResponse(c, result)
		defer guard.Release()
		c.Next()
	}
}

func ConcurrencyLimit(max int, name string) gin.HandlerFunc {
	return ConcurrencyGuardMiddleware(NewConcurrencyGuard(max, name))
}

func (g *ConcurrencyGuard) acquireOrEnqueue(allowQueue bool) (*concurrencyWaiter, []*concurrencyWaiter, ConcurrencyAcquireResult) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.inflight < g.max && len(g.queue) == 0 {
		g.inflight++
		g.stats.InFlight = g.inflight
		g.stats.AdmittedImmediateTotal++
		return nil, nil, ConcurrencyAcquireResult{Allowed: true}
	}

	if !allowQueue || !g.queueEnabled() {
		g.recordRejectLocked(overloadRejectReasonLimitReached)
		return nil, nil, ConcurrencyAcquireResult{RejectReason: overloadRejectReasonLimitReached}
	}
	if len(g.queue) >= g.maxQueue {
		g.recordRejectLocked(overloadRejectReasonQueueFull)
		return nil, nil, ConcurrencyAcquireResult{RejectReason: overloadRejectReasonQueueFull}
	}

	waiter := &concurrencyWaiter{ready: make(chan struct{})}
	g.queue = append(g.queue, waiter)
	g.stats.QueueEnteredTotal++
	if len(g.queue) > g.stats.QueuePeak {
		g.stats.QueuePeak = len(g.queue)
	}
	g.stats.QueueCurrent = len(g.queue)

	notify := g.dispatchLocked()
	return waiter, notify, ConcurrencyAcquireResult{Queued: true}
}

func (g *ConcurrencyGuard) dispatchLocked() []*concurrencyWaiter {
	if g.max <= 0 {
		return nil
	}
	notify := make([]*concurrencyWaiter, 0, 1)
	for g.inflight < g.max && len(g.queue) > 0 {
		waiter := g.queue[0]
		g.queue[0] = nil
		g.queue = g.queue[1:]
		waiter.granted = true
		g.inflight++
		g.stats.AdmittedQueuedTotal++
		notify = append(notify, waiter)
	}
	g.stats.InFlight = g.inflight
	g.stats.QueueCurrent = len(g.queue)
	return notify
}

func (g *ConcurrencyGuard) resolveQueuedWaiter(waiter *concurrencyWaiter, reason string) bool {
	var notify []*concurrencyWaiter

	g.mu.Lock()
	if waiter.granted {
		g.mu.Unlock()
		<-waiter.ready
		return true
	}

	idx := -1
	for i, queued := range g.queue {
		if queued == waiter {
			idx = i
			break
		}
	}
	if idx >= 0 {
		copy(g.queue[idx:], g.queue[idx+1:])
		g.queue[len(g.queue)-1] = nil
		g.queue = g.queue[:len(g.queue)-1]
		g.recordRejectLocked(reason)
	}
	notify = g.dispatchLocked()
	g.mu.Unlock()

	closeGrantedWaiters(notify)
	return false
}

func (g *ConcurrencyGuard) recordQueueWait(wait time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()

	waitMS := queueWaitMilliseconds(wait)
	g.stats.QueueWaitTotalMS += waitMS
	g.stats.LastQueueWaitMS = waitMS
	if waitMS > g.stats.QueueWaitMaxMS {
		g.stats.QueueWaitMaxMS = waitMS
	}
}

func queueWaitMilliseconds(wait time.Duration) uint64 {
	if wait <= 0 {
		return 0
	}
	if wait < time.Millisecond {
		return 1
	}
	return uint64(wait / time.Millisecond)
}

func (g *ConcurrencyGuard) recordRejectLocked(reason string) {
	g.stats.RejectedTotal++
	switch reason {
	case overloadRejectReasonLimitReached:
		g.stats.RejectedLimitReachedTotal++
	case overloadRejectReasonQueueFull:
		g.stats.RejectedQueueFullTotal++
	case overloadRejectReasonQueueTimeout:
		g.stats.RejectedQueueTimeoutTotal++
	case overloadRejectReasonRequestCanceled:
		g.stats.RejectedCanceledTotal++
	}
}

func (g *ConcurrencyGuard) queueEnabled() bool {
	return g.maxQueue > 0 && g.queueTimeout > 0
}

func closeGrantedWaiters(waiters []*concurrencyWaiter) {
	for _, waiter := range waiters {
		close(waiter.ready)
	}
}

func RequestAlreadyQueued(ctx context.Context) bool {
	return requestQueueStateFromContext(ctx).queued
}

func MergeRequestQueueResult(ctx context.Context, result ConcurrencyAcquireResult) ConcurrencyAcquireResult {
	state := requestQueueStateFromContext(ctx)
	if !state.queued {
		return result
	}
	result.Queued = true
	result.QueueWait += state.queueWait
	return result
}

func withRequestQueueResult(ctx context.Context, result ConcurrencyAcquireResult) context.Context {
	if ctx == nil || !result.Allowed || !result.Queued {
		return ctx
	}
	state := requestQueueStateFromContext(ctx)
	state.queued = true
	state.queueWait += result.QueueWait
	return context.WithValue(ctx, requestQueueStateKey{}, state)
}

func requestQueueStateFromContext(ctx context.Context) requestQueueState {
	if ctx == nil {
		return requestQueueState{}
	}
	state, ok := ctx.Value(requestQueueStateKey{}).(requestQueueState)
	if !ok {
		return requestQueueState{}
	}
	return state
}
