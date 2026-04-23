package handler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tukuyomi/internal/config"
)

func TestProxyAccessLogAsyncFlushWritesQueuedAccessLog(t *testing.T) {
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

	config.FileRotateBytes = 0
	config.FileMaxBytes = 0
	config.FileRetention = 0
	config.LogFile = filepath.Join(t.TempDir(), "waf-events.ndjson")

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

	got, err := os.ReadFile(config.LogFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(got), `"event":"proxy_access"`) {
		t.Fatalf("log line missing proxy_access event: %s", string(got))
	}
	if !strings.HasSuffix(string(got), "\n") {
		t.Fatalf("log line missing newline: %q", string(got))
	}
}

func TestProxyAccessLogAsyncEnqueueFailureFallsBackToSyncAppend(t *testing.T) {
	restoreConfig := saveWAFLogArchiveConfigForTest()
	defer restoreConfig()

	prevSink := runtimeProxyAccessLogSink
	runtimeProxyAccessLogSink = proxyAccessLogFullSink{}
	defer func() {
		runtimeProxyAccessLogSink = prevSink
	}()

	config.FileRotateBytes = 0
	config.FileMaxBytes = 0
	config.FileRetention = 0
	config.LogFile = filepath.Join(t.TempDir(), "waf-events.ndjson")

	emitProxyAccessLogEvent(map[string]any{
		"event":  "proxy_access",
		"path":   "/fallback",
		"status": 200,
	})

	got, err := os.ReadFile(config.LogFile)
	if err != nil {
		t.Fatalf("read fallback log: %v", err)
	}
	if !strings.Contains(string(got), `"path":"/fallback"`) {
		t.Fatalf("fallback log missing event: %s", string(got))
	}
}

func TestProxyAccessLogAsyncAfterShutdownFallsBackToSyncAppend(t *testing.T) {
	restoreConfig := saveWAFLogArchiveConfigForTest()
	defer restoreConfig()

	prevSink := runtimeProxyAccessLogSink
	writer := newProxyAccessLogAsyncWriter(8, 4)
	runtimeProxyAccessLogSink = writer
	defer func() {
		runtimeProxyAccessLogSink = prevSink
	}()

	config.FileRotateBytes = 0
	config.FileMaxBytes = 0
	config.FileRetention = 0
	config.LogFile = filepath.Join(t.TempDir(), "waf-events.ndjson")

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

	got, err := os.ReadFile(config.LogFile)
	if err != nil {
		t.Fatalf("read shutdown fallback log: %v", err)
	}
	if !strings.Contains(string(got), `"path":"/after-shutdown"`) {
		t.Fatalf("shutdown fallback log missing event: %s", string(got))
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
