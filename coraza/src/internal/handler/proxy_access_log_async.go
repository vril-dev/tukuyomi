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
	wafEventAsyncQueueSize = 8192
	wafEventAsyncBatchSize = 64
)

type wafEventAsyncSink interface {
	Enqueue([]byte) bool
	Flush(context.Context) error
	Shutdown(context.Context) error
}

var runtimeWAFEventAsyncSink wafEventAsyncSink = newWAFEventAsyncWriter(wafEventAsyncQueueSize, wafEventAsyncBatchSize)

type wafEventAsyncWriter struct {
	events   chan []byte
	controls chan wafEventAsyncControl
	batchCap int
	closed   atomic.Bool
}

type wafEventAsyncControl struct {
	kind string
	ack  chan struct{}
}

type wafEventAsyncStatusSnapshot struct {
	EnqueuedTotal      uint64 `json:"enqueued_total"`
	WrittenTotal       uint64 `json:"written_total"`
	DroppedTotal       uint64 `json:"dropped_total"`
	WriteFailuresTotal uint64 `json:"write_failures_total"`
	QueueCurrent       int    `json:"queue_current"`
	QueueCapacity      int    `json:"queue_capacity"`
}

var (
	wafEventAsyncEnqueuedTotal      atomic.Uint64
	wafEventAsyncWrittenTotal       atomic.Uint64
	wafEventAsyncDroppedTotal       atomic.Uint64
	wafEventAsyncWriteFailuresTotal atomic.Uint64
)

func newWAFEventAsyncWriter(queueSize int, batchSize int) *wafEventAsyncWriter {
	if queueSize < 1 {
		queueSize = 1
	}
	if batchSize < 1 {
		batchSize = 1
	}
	w := &wafEventAsyncWriter{
		events:   make(chan []byte, queueSize),
		controls: make(chan wafEventAsyncControl),
		batchCap: batchSize,
	}
	go w.run()
	return w
}

func (w *wafEventAsyncWriter) Enqueue(raw []byte) bool {
	if w == nil || len(raw) == 0 {
		return false
	}
	if w.closed.Load() {
		return false
	}
	raw = append([]byte(nil), raw...)
	select {
	case w.events <- raw:
		wafEventAsyncEnqueuedTotal.Add(1)
		return true
	default:
		return false
	}
}

func (w *wafEventAsyncWriter) Flush(ctx context.Context) error {
	return w.control(ctx, "flush")
}

func (w *wafEventAsyncWriter) Shutdown(ctx context.Context) error {
	return w.control(ctx, "shutdown")
}

func (w *wafEventAsyncWriter) control(ctx context.Context, kind string) error {
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
	case w.controls <- wafEventAsyncControl{kind: kind, ack: ack}:
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

func (w *wafEventAsyncWriter) run() {
	batch := make([][]byte, 0, w.batchCap)
	for {
		select {
		case evt := <-w.events:
			batch = append(batch, evt)
			batch = w.drainReady(batch)
			writeWAFEventAsyncBatch(batch)
			batch = batch[:0]
		case control := <-w.controls:
			batch = w.drainAll(batch)
			writeWAFEventAsyncBatch(batch)
			batch = batch[:0]
			close(control.ack)
			if control.kind == "shutdown" {
				return
			}
		}
	}
}

func (w *wafEventAsyncWriter) drainReady(batch [][]byte) [][]byte {
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

func (w *wafEventAsyncWriter) drainAll(batch [][]byte) [][]byte {
	for {
		select {
		case evt := <-w.events:
			batch = append(batch, evt)
		default:
			return batch
		}
	}
}

func writeWAFEventAsyncBatch(raws [][]byte) {
	if len(raws) == 0 {
		return
	}
	for _, raw := range raws {
		log.Println(string(raw))
		var evt map[string]any
		if err := json.Unmarshal(raw, &evt); err == nil {
			ObserveNotificationLogEvent(evt)
		}
	}
	if err := appendEncodedEventsToDB(raws); err != nil {
		wafEventAsyncWriteFailuresTotal.Add(1)
		logWAFEventAsyncWriteWarning(err)
		return
	}
	wafEventAsyncWrittenTotal.Add(uint64(len(raws)))
}

var (
	wafEventAsyncWarningMu        sync.Mutex
	lastWAFEventAsyncWriteWarning time.Time
	lastWAFEventAsyncDropWarning  time.Time
)

func logWAFEventAsyncWriteWarning(err error) {
	wafEventAsyncWarningMu.Lock()
	defer wafEventAsyncWarningMu.Unlock()

	now := time.Now()
	if now.Sub(lastWAFEventAsyncWriteWarning) < time.Second {
		return
	}
	lastWAFEventAsyncWriteWarning = now
	log.Printf("[WAF_EVENT][WARN] async event append failed: %v", err)
}

func logWAFEventAsyncDropWarning() {
	wafEventAsyncWarningMu.Lock()
	defer wafEventAsyncWarningMu.Unlock()

	now := time.Now()
	if now.Sub(lastWAFEventAsyncDropWarning) < time.Second {
		return
	}
	lastWAFEventAsyncDropWarning = now
	log.Printf("[WAF_EVENT][WARN] async event queue full; dropped event")
}

func enqueueEncodedWAFEvent(raw []byte) {
	if len(raw) == 0 {
		return
	}
	if runtimeWAFEventAsyncSink != nil && runtimeWAFEventAsyncSink.Enqueue(raw) {
		return
	}
	wafEventAsyncDroppedTotal.Add(1)
	logWAFEventAsyncDropWarning()
}

func emitProxyAccessLogEvent(evt map[string]any) {
	emitJSONLogAndAppendEvent(evt)
}

func WAFEventAsyncStatusSnapshot() wafEventAsyncStatusSnapshot {
	out := wafEventAsyncStatusSnapshot{
		EnqueuedTotal:      wafEventAsyncEnqueuedTotal.Load(),
		WrittenTotal:       wafEventAsyncWrittenTotal.Load(),
		DroppedTotal:       wafEventAsyncDroppedTotal.Load(),
		WriteFailuresTotal: wafEventAsyncWriteFailuresTotal.Load(),
	}
	if writer, ok := runtimeWAFEventAsyncSink.(*wafEventAsyncWriter); ok && writer != nil {
		out.QueueCurrent = len(writer.events)
		out.QueueCapacity = cap(writer.events)
	}
	return out
}

func FlushWAFEventAsync(ctx context.Context) error {
	if runtimeWAFEventAsyncSink == nil {
		return nil
	}
	return runtimeWAFEventAsyncSink.Flush(ctx)
}

func ShutdownWAFEventAsync(ctx context.Context) error {
	if runtimeWAFEventAsyncSink == nil {
		return nil
	}
	return runtimeWAFEventAsyncSink.Shutdown(ctx)
}

func FlushProxyAccessLogAsync(ctx context.Context) error {
	return FlushWAFEventAsync(ctx)
}

func ShutdownProxyAccessLogAsync(ctx context.Context) error {
	return ShutdownWAFEventAsync(ctx)
}
