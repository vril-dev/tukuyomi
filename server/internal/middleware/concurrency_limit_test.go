package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestConcurrencyGuardAcquireRelease(t *testing.T) {
	guard := NewConcurrencyGuard(1, "proxy")
	if guard == nil {
		t.Fatal("expected guard")
	}
	if !guard.Acquire() {
		t.Fatal("expected first acquire to succeed")
	}
	if guard.Acquire() {
		t.Fatal("expected second acquire to fail while full")
	}
	guard.Release()
	if !guard.Acquire() {
		t.Fatal("expected acquire to succeed after release")
	}
	guard.Release()
}

func TestQueuedConcurrencyGuardWaitsThenSucceeds(t *testing.T) {
	guard := NewQueuedConcurrencyGuard(1, 1, 250*time.Millisecond, "proxy")
	if guard == nil {
		t.Fatal("expected guard")
	}
	if !guard.Acquire() {
		t.Fatal("expected initial acquire")
	}

	go func() {
		time.Sleep(30 * time.Millisecond)
		guard.Release()
	}()

	start := time.Now()
	result := guard.AcquireContext(context.Background())
	elapsed := time.Since(start)
	if !result.Allowed {
		t.Fatalf("expected queued request to succeed, got %#v", result)
	}
	if !result.Queued {
		t.Fatalf("expected queued result, got %#v", result)
	}
	if elapsed < 20*time.Millisecond {
		t.Fatalf("elapsed=%s want >=20ms", elapsed)
	}

	snapshot := guard.Snapshot()
	if got := snapshot.QueueEnteredTotal; got != 1 {
		t.Fatalf("QueueEnteredTotal=%d want=1", got)
	}
	if got := snapshot.AdmittedQueuedTotal; got != 1 {
		t.Fatalf("AdmittedQueuedTotal=%d want=1", got)
	}
	if got := snapshot.LastQueueWaitMS; got == 0 {
		t.Fatalf("LastQueueWaitMS=%d want > 0", got)
	}

	guard.Release()
}

func TestQueuedConcurrencyGuardRejectsWhenQueueFull(t *testing.T) {
	guard := NewQueuedConcurrencyGuard(1, 1, time.Second, "proxy")
	if !guard.Acquire() {
		t.Fatal("expected initial acquire")
	}

	done := make(chan ConcurrencyAcquireResult, 1)
	go func() {
		done <- guard.AcquireContext(context.Background())
	}()

	waitForSnapshot(t, 250*time.Millisecond, func(snapshot ConcurrencyGuardSnapshot) bool {
		return snapshot.QueueCurrent == 1
	}, guard)

	result := guard.AcquireContext(context.Background())
	if result.Allowed {
		t.Fatalf("expected queue-full rejection, got %#v", result)
	}
	if result.Queued {
		t.Fatalf("expected queue-full rejection without queue admission, got %#v", result)
	}
	if result.RejectReason != overloadRejectReasonQueueFull {
		t.Fatalf("RejectReason=%q want=%q", result.RejectReason, overloadRejectReasonQueueFull)
	}

	guard.Release()
	queuedResult := <-done
	if !queuedResult.Allowed || !queuedResult.Queued {
		t.Fatalf("queuedResult=%#v want allowed queued request", queuedResult)
	}
	guard.Release()

	snapshot := guard.Snapshot()
	if got := snapshot.RejectedQueueFullTotal; got != 1 {
		t.Fatalf("RejectedQueueFullTotal=%d want=1", got)
	}
}

func TestQueuedConcurrencyGuardTimesOutInQueue(t *testing.T) {
	guard := NewQueuedConcurrencyGuard(1, 1, 30*time.Millisecond, "proxy")
	if !guard.Acquire() {
		t.Fatal("expected initial acquire")
	}

	start := time.Now()
	result := guard.AcquireContext(context.Background())
	elapsed := time.Since(start)
	if result.Allowed {
		t.Fatalf("expected timeout rejection, got %#v", result)
	}
	if !result.Queued {
		t.Fatalf("expected queued timeout rejection, got %#v", result)
	}
	if result.RejectReason != overloadRejectReasonQueueTimeout {
		t.Fatalf("RejectReason=%q want=%q", result.RejectReason, overloadRejectReasonQueueTimeout)
	}
	if elapsed < 20*time.Millisecond {
		t.Fatalf("elapsed=%s want >=20ms", elapsed)
	}

	snapshot := guard.Snapshot()
	if got := snapshot.RejectedQueueTimeoutTotal; got != 1 {
		t.Fatalf("RejectedQueueTimeoutTotal=%d want=1", got)
	}
	if got := snapshot.QueueCurrent; got != 0 {
		t.Fatalf("QueueCurrent=%d want=0", got)
	}

	guard.Release()
}

func TestConcurrencyGuardMiddlewareRejectsWhenBusy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	guard := NewConcurrencyGuard(1, "global")
	if !guard.Acquire() {
		t.Fatal("expected pre-acquire success")
	}
	defer guard.Release()

	r := gin.New()
	r.Use(ConcurrencyGuardMiddleware(guard))
	r.GET("/ok", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d", w.Code, http.StatusServiceUnavailable)
	}
	if got := w.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After=%q want=1", got)
	}
	if got := w.Header().Get("X-Tukuyomi-Overload-Reason"); got != overloadRejectReasonLimitReached {
		t.Fatalf("X-Tukuyomi-Overload-Reason=%q want=%q", got, overloadRejectReasonLimitReached)
	}
	if got := w.Header().Get("X-Tukuyomi-Overload-Queued"); got != "false" {
		t.Fatalf("X-Tukuyomi-Overload-Queued=%q want=false", got)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got := body["reason"]; got != overloadRejectReasonLimitReached {
		t.Fatalf("reason=%v want=%q", got, overloadRejectReasonLimitReached)
	}
	if got := body["queued"]; got != false {
		t.Fatalf("queued=%v want=false", got)
	}
}

func TestConcurrencyGuardMiddlewareAnnotatesQueuedSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	guard := NewQueuedConcurrencyGuard(1, 1, 250*time.Millisecond, "proxy")
	if !guard.Acquire() {
		t.Fatal("expected initial acquire")
	}

	r := gin.New()
	r.Use(ConcurrencyGuardMiddleware(guard))
	r.GET("/ok", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	go func() {
		time.Sleep(30 * time.Millisecond)
		guard.Release()
	}()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", w.Code, http.StatusOK)
	}
	if got := w.Header().Get("X-Tukuyomi-Overload-Queued"); got != "true" {
		t.Fatalf("X-Tukuyomi-Overload-Queued=%q want=true", got)
	}
	if got := w.Header().Get("X-Tukuyomi-Overload-Scope"); got != "proxy" {
		t.Fatalf("X-Tukuyomi-Overload-Scope=%q want=proxy", got)
	}
	if got := w.Header().Get("X-Tukuyomi-Overload-Queue-Wait-Ms"); got == "" {
		t.Fatal("missing X-Tukuyomi-Overload-Queue-Wait-Ms header")
	}
}

func TestQueuedProxyRequestDoesNotQueueTwiceAfterGlobalQueue(t *testing.T) {
	gin.SetMode(gin.TestMode)

	global := NewQueuedConcurrencyGuard(1, 1, 250*time.Millisecond, "global")
	proxy := NewQueuedConcurrencyGuard(1, 1, 250*time.Millisecond, "proxy")
	if !global.Acquire() {
		t.Fatal("expected initial global acquire")
	}
	if !proxy.Acquire() {
		t.Fatal("expected initial proxy acquire")
	}
	defer proxy.Release()

	r := gin.New()
	r.Use(ConcurrencyGuardMiddleware(global))
	r.GET("/proxy", func(c *gin.Context) {
		alreadyQueued := RequestAlreadyQueued(c.Request.Context())
		var result ConcurrencyAcquireResult
		if alreadyQueued {
			result = proxy.AcquireContextNoQueue(c.Request.Context())
		} else {
			result = proxy.AcquireContext(c.Request.Context())
		}
		if !result.Allowed {
			if alreadyQueued {
				result = MergeRequestQueueResult(c.Request.Context(), result)
			}
			proxy.RejectWithResult(c, result)
			return
		}
		proxy.AnnotateQueuedResponse(c, result)
		defer proxy.Release()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/proxy", nil)
	done := make(chan struct{})
	go func() {
		r.ServeHTTP(w, req)
		close(done)
	}()

	waitForSnapshot(t, 250*time.Millisecond, func(snapshot ConcurrencyGuardSnapshot) bool {
		return snapshot.QueueCurrent == 1
	}, global)
	global.Release()

	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("request did not complete after releasing global guard")
	}

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d", w.Code, http.StatusServiceUnavailable)
	}
	if got := w.Header().Get("X-Tukuyomi-Overload-Queued"); got != "true" {
		t.Fatalf("X-Tukuyomi-Overload-Queued=%q want=true", got)
	}
	if got := w.Header().Get("X-Tukuyomi-Overload-Scope"); got != "proxy" {
		t.Fatalf("X-Tukuyomi-Overload-Scope=%q want=proxy", got)
	}
	if got := w.Header().Get("X-Tukuyomi-Overload-Reason"); got != overloadRejectReasonLimitReached {
		t.Fatalf("X-Tukuyomi-Overload-Reason=%q want=%q", got, overloadRejectReasonLimitReached)
	}
	if got := w.Header().Get("X-Tukuyomi-Overload-Queue-Wait-Ms"); got == "" || got == "0" {
		t.Fatalf("X-Tukuyomi-Overload-Queue-Wait-Ms=%q want > 0", got)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got := body["queued"]; got != true {
		t.Fatalf("queued=%v want=true", got)
	}
	if got := body["reason"]; got != overloadRejectReasonLimitReached {
		t.Fatalf("reason=%v want=%q", got, overloadRejectReasonLimitReached)
	}
	if got := body["queue_wait_ms"].(float64); got <= 0 {
		t.Fatalf("queue_wait_ms=%v want > 0", got)
	}

	globalSnapshot := global.Snapshot()
	if got := globalSnapshot.QueueEnteredTotal; got != 1 {
		t.Fatalf("global QueueEnteredTotal=%d want=1", got)
	}

	proxySnapshot := proxy.Snapshot()
	if got := proxySnapshot.QueueEnteredTotal; got != 0 {
		t.Fatalf("proxy QueueEnteredTotal=%d want=0", got)
	}
	if got := proxySnapshot.RejectedLimitReachedTotal; got != 1 {
		t.Fatalf("proxy RejectedLimitReachedTotal=%d want=1", got)
	}
}

func waitForSnapshot(t *testing.T, timeout time.Duration, pred func(ConcurrencyGuardSnapshot) bool, guard *ConcurrencyGuard) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred(guard.Snapshot()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met before timeout; snapshot=%#v", guard.Snapshot())
}
