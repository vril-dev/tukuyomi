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

	prevSink := runtimeWAFEventAsyncSink
	writer := newWAFEventAsyncWriter(8, 4)
	runtimeWAFEventAsyncSink = writer
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = writer.Shutdown(ctx)
		runtimeWAFEventAsyncSink = prevSink
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

func TestProxyAccessLogAsyncEnqueueFailureDropsWithoutSyncAppend(t *testing.T) {
	initConfigDBStoreForTest(t)
	restoreConfig := saveWAFLogArchiveConfigForTest()
	defer restoreConfig()

	before := WAFEventAsyncStatusSnapshot()
	prevSink := runtimeWAFEventAsyncSink
	runtimeWAFEventAsyncSink = wafEventFullSink{}
	defer func() {
		runtimeWAFEventAsyncSink = prevSink
	}()

	emitProxyAccessLogEvent(map[string]any{
		"event":  "proxy_access",
		"path":   "/dropped",
		"status": 200,
	})

	events := readProxyLogEvents(t)
	for _, evt := range events {
		if anyToString(evt["path"]) == "/dropped" {
			t.Fatalf("dropped proxy_access event should not be synchronously appended: %#v", evt)
		}
	}
	after := WAFEventAsyncStatusSnapshot()
	if after.DroppedTotal != before.DroppedTotal+1 {
		t.Fatalf("dropped_total=%d want %d", after.DroppedTotal, before.DroppedTotal+1)
	}
}

func TestProxyAccessLogAsyncAfterShutdownDropsWithoutSyncAppend(t *testing.T) {
	initConfigDBStoreForTest(t)
	restoreConfig := saveWAFLogArchiveConfigForTest()
	defer restoreConfig()

	before := WAFEventAsyncStatusSnapshot()
	prevSink := runtimeWAFEventAsyncSink
	writer := newWAFEventAsyncWriter(8, 4)
	runtimeWAFEventAsyncSink = writer
	defer func() {
		runtimeWAFEventAsyncSink = prevSink
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

	events := readProxyLogEvents(t)
	for _, evt := range events {
		if anyToString(evt["path"]) == "/after-shutdown" {
			t.Fatalf("post-shutdown proxy_access event should not be synchronously appended: %#v", evt)
		}
	}
	after := WAFEventAsyncStatusSnapshot()
	if after.DroppedTotal != before.DroppedTotal+1 {
		t.Fatalf("dropped_total=%d want %d", after.DroppedTotal, before.DroppedTotal+1)
	}
}

func TestWAFEventAsyncFlushWritesSecurityEvent(t *testing.T) {
	initConfigDBStoreForTest(t)
	restoreConfig := saveWAFLogArchiveConfigForTest()
	defer restoreConfig()

	prevSink := runtimeWAFEventAsyncSink
	writer := newWAFEventAsyncWriter(8, 4)
	runtimeWAFEventAsyncSink = writer
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = writer.Shutdown(ctx)
		runtimeWAFEventAsyncSink = prevSink
	}()

	emitJSONLogAndAppendEvent(map[string]any{
		"event": "semantic_anomaly",
		"path":  "/search",
		"score": 7,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := writer.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	evt := findLastProxyLogEvent(t, readProxyLogEvents(t), "semantic_anomaly")
	if got := anyToString(evt["path"]); got != "/search" {
		t.Fatalf("semantic_anomaly path=%q want=/search", got)
	}
}

type wafEventFullSink struct{}

func (wafEventFullSink) Enqueue([]byte) bool {
	return false
}

func (wafEventFullSink) Flush(context.Context) error {
	return nil
}

func (wafEventFullSink) Shutdown(context.Context) error {
	return nil
}
