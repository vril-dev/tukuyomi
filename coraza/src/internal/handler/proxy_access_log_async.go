package handler

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const (
	proxyAccessLogAsyncQueueSize = 8192
	proxyAccessLogAsyncBatchSize = 64
)

type proxyAccessLogSink interface {
	Enqueue(map[string]any) bool
	Flush(context.Context) error
	Shutdown(context.Context) error
}

var runtimeProxyAccessLogSink proxyAccessLogSink = newProxyAccessLogAsyncWriter(proxyAccessLogAsyncQueueSize, proxyAccessLogAsyncBatchSize)

type proxyAccessLogAsyncWriter struct {
	events   chan map[string]any
	controls chan proxyAccessLogControl
	batchCap int
	closed   atomic.Bool
}

type proxyAccessLogControl struct {
	kind string
	ack  chan struct{}
}

func newProxyAccessLogAsyncWriter(queueSize int, batchSize int) *proxyAccessLogAsyncWriter {
	if queueSize < 1 {
		queueSize = 1
	}
	if batchSize < 1 {
		batchSize = 1
	}
	w := &proxyAccessLogAsyncWriter{
		events:   make(chan map[string]any, queueSize),
		controls: make(chan proxyAccessLogControl),
		batchCap: batchSize,
	}
	go w.run()
	return w
}

func (w *proxyAccessLogAsyncWriter) Enqueue(evt map[string]any) bool {
	if w == nil || len(evt) == 0 {
		return false
	}
	if w.closed.Load() {
		return false
	}
	select {
	case w.events <- evt:
		return true
	default:
		return false
	}
}

func (w *proxyAccessLogAsyncWriter) Flush(ctx context.Context) error {
	return w.control(ctx, "flush")
}

func (w *proxyAccessLogAsyncWriter) Shutdown(ctx context.Context) error {
	return w.control(ctx, "shutdown")
}

func (w *proxyAccessLogAsyncWriter) control(ctx context.Context, kind string) error {
	if w == nil {
		return nil
	}
	if kind == "shutdown" {
		if !w.closed.CompareAndSwap(false, true) {
			return nil
		}
	} else if w.closed.Load() {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ack := make(chan struct{})
	select {
	case w.controls <- proxyAccessLogControl{kind: kind, ack: ack}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *proxyAccessLogAsyncWriter) run() {
	batch := make([]map[string]any, 0, w.batchCap)
	for {
		select {
		case evt := <-w.events:
			batch = append(batch, evt)
			batch = w.drainReady(batch)
			writeProxyAccessLogBatch(batch)
			batch = batch[:0]
		case control := <-w.controls:
			batch = w.drainAll(batch)
			writeProxyAccessLogBatch(batch)
			batch = batch[:0]
			close(control.ack)
			if control.kind == "shutdown" {
				return
			}
		}
	}
}

func (w *proxyAccessLogAsyncWriter) drainReady(batch []map[string]any) []map[string]any {
	for len(batch) < w.batchCap {
		select {
		case evt := <-w.events:
			batch = append(batch, evt)
		default:
			return batch
		}
	}
	return batch
}

func (w *proxyAccessLogAsyncWriter) drainAll(batch []map[string]any) []map[string]any {
	for {
		select {
		case evt := <-w.events:
			batch = append(batch, evt)
		default:
			return batch
		}
	}
}

func writeProxyAccessLogBatch(events []map[string]any) {
	if len(events) == 0 {
		return
	}
	raws := make([][]byte, 0, len(events))
	for _, evt := range events {
		raw, err := json.Marshal(evt)
		if err != nil {
			continue
		}
		log.Println(string(raw))
		ObserveNotificationLogEvent(evt)
		raws = append(raws, raw)
	}
	if err := appendEncodedEventsToDB(raws); err != nil {
		logProxyAccessLogAsyncWarning(err)
	}
}

var (
	proxyAccessLogAsyncWarningMu   sync.Mutex
	lastProxyAccessLogAsyncWarning time.Time
)

func logProxyAccessLogAsyncWarning(err error) {
	proxyAccessLogAsyncWarningMu.Lock()
	defer proxyAccessLogAsyncWarningMu.Unlock()

	now := time.Now()
	if now.Sub(lastProxyAccessLogAsyncWarning) < time.Second {
		return
	}
	lastProxyAccessLogAsyncWarning = now
	log.Printf("[PROXY][WARN] async access log append failed: %v", err)
}

func emitProxyAccessLogEvent(evt map[string]any) {
	if runtimeProxyAccessLogSink == nil || !runtimeProxyAccessLogSink.Enqueue(evt) {
		emitJSONLogAndAppendEvent(evt)
	}
}

func FlushProxyAccessLogAsync(ctx context.Context) error {
	if runtimeProxyAccessLogSink == nil {
		return nil
	}
	return runtimeProxyAccessLogSink.Flush(ctx)
}

func ShutdownProxyAccessLogAsync(ctx context.Context) error {
	if runtimeProxyAccessLogSink == nil {
		return nil
	}
	return runtimeProxyAccessLogSink.Shutdown(ctx)
}
