package handler

import (
	"context"
	"testing"
	"time"
)

func TestProxyAccessLogAsyncFlushWritesQueuedAccessLog(t *testing.T) {
	initConfigDBStoreForTest(t)
	restoreConfig := saveWAFLogArchiveConfigForTest()
	defer restoreConfig()

	prevSink := runtimeProxyAccessLogSink
	writer := newProxyAccessLogAsyncWriter(8, 4)
	runtimeProxyAccessLogSink = writer
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = writer.Shutdown(ctx)
		runtimeProxyAccessLogSink = prevSink
	}()

	emitProxyAccessLogEvent(map[string]any{
		"event":  "proxy_access",
		"path":   "/bench",
		"status": 200,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := writer.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	evt := findLastProxyLogEvent(t, readProxyLogEvents(t), "proxy_access")
	if got := anyToString(evt["path"]); got != "/bench" {
		t.Fatalf("proxy_access path=%q want=/bench", got)
	}
}

func TestProxyAccessLogAsyncEnqueueFailureFallsBackToSyncAppend(t *testing.T) {
	initConfigDBStoreForTest(t)
	restoreConfig := saveWAFLogArchiveConfigForTest()
	defer restoreConfig()

	prevSink := runtimeProxyAccessLogSink
	runtimeProxyAccessLogSink = proxyAccessLogFullSink{}
	defer func() {
		runtimeProxyAccessLogSink = prevSink
	}()

	emitProxyAccessLogEvent(map[string]any{
		"event":  "proxy_access",
		"path":   "/fallback",
		"status": 200,
	})

	evt := findLastProxyLogEvent(t, readProxyLogEvents(t), "proxy_access")
	if got := anyToString(evt["path"]); got != "/fallback" {
		t.Fatalf("proxy_access path=%q want=/fallback", got)
	}
}

func TestProxyAccessLogAsyncAfterShutdownFallsBackToSyncAppend(t *testing.T) {
	initConfigDBStoreForTest(t)
	restoreConfig := saveWAFLogArchiveConfigForTest()
	defer restoreConfig()

	prevSink := runtimeProxyAccessLogSink
	writer := newProxyAccessLogAsyncWriter(8, 4)
	runtimeProxyAccessLogSink = writer
	defer func() {
		runtimeProxyAccessLogSink = prevSink
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := writer.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	emitProxyAccessLogEvent(map[string]any{
		"event":  "proxy_access",
		"path":   "/after-shutdown",
		"status": 200,
	})

	evt := findLastProxyLogEvent(t, readProxyLogEvents(t), "proxy_access")
	if got := anyToString(evt["path"]); got != "/after-shutdown" {
		t.Fatalf("proxy_access path=%q want=/after-shutdown", got)
	}
}

type proxyAccessLogFullSink struct{}

func (proxyAccessLogFullSink) Enqueue(map[string]any) bool {
	return false
}

func (proxyAccessLogFullSink) Flush(context.Context) error {
	return nil
}

func (proxyAccessLogFullSink) Shutdown(context.Context) error {
	return nil
}
