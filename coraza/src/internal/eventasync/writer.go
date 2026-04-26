package eventasync

import (
	"context"
	"sync/atomic"
)

type Sink interface {
	Enqueue([]byte) bool
	Flush(context.Context) error
	Shutdown(context.Context) error
}

type BatchWriter func([][]byte) error
type FailureHandler func(error)

type Stats struct {
	enqueuedTotal      atomic.Uint64
	writtenTotal       atomic.Uint64
	droppedTotal       atomic.Uint64
	writeFailuresTotal atomic.Uint64
}

type StatusSnapshot struct {
	EnqueuedTotal      uint64 `json:"enqueued_total"`
	WrittenTotal       uint64 `json:"written_total"`
	DroppedTotal       uint64 `json:"dropped_total"`
	WriteFailuresTotal uint64 `json:"write_failures_total"`
	QueueCurrent       int    `json:"queue_current"`
	QueueCapacity      int    `json:"queue_capacity"`
}

type Writer struct {
	events    chan []byte
	controls  chan control
	batchCap  int
	closed    atomic.Bool
	stats     *Stats
	write     BatchWriter
	onFailure FailureHandler
}

type control struct {
	kind string
	ack  chan struct{}
}

func NewStats() *Stats {
	return &Stats{}
}

func (s *Stats) Snapshot(queueCurrent int, queueCapacity int) StatusSnapshot {
	if s == nil {
		return StatusSnapshot{
			QueueCurrent:  queueCurrent,
			QueueCapacity: queueCapacity,
		}
	}
	return StatusSnapshot{
		EnqueuedTotal:      s.enqueuedTotal.Load(),
		WrittenTotal:       s.writtenTotal.Load(),
		DroppedTotal:       s.droppedTotal.Load(),
		WriteFailuresTotal: s.writeFailuresTotal.Load(),
		QueueCurrent:       queueCurrent,
		QueueCapacity:      queueCapacity,
	}
}

func (s *Stats) AddDropped() {
	if s == nil {
		return
	}
	s.droppedTotal.Add(1)
}

func NewWriter(queueSize int, batchSize int, stats *Stats, write BatchWriter, onFailure FailureHandler) *Writer {
	if queueSize < 1 {
		queueSize = 1
	}
	if batchSize < 1 {
		batchSize = 1
	}
	w := &Writer{
		events:    make(chan []byte, queueSize),
		controls:  make(chan control),
		batchCap:  batchSize,
		stats:     stats,
		write:     write,
		onFailure: onFailure,
	}
	go w.run()
	return w
}

func (w *Writer) Enqueue(raw []byte) bool {
	if w == nil || len(raw) == 0 {
		return false
	}
	if w.closed.Load() {
		return false
	}
	raw = append([]byte(nil), raw...)
	select {
	case w.events <- raw:
		if w.stats != nil {
			w.stats.enqueuedTotal.Add(1)
		}
		return true
	default:
		return false
	}
}

func (w *Writer) Flush(ctx context.Context) error {
	return w.control(ctx, "flush")
}

func (w *Writer) Shutdown(ctx context.Context) error {
	return w.control(ctx, "shutdown")
}

func (w *Writer) QueueCurrent() int {
	if w == nil {
		return 0
	}
	return len(w.events)
}

func (w *Writer) QueueCapacity() int {
	if w == nil {
		return 0
	}
	return cap(w.events)
}

func (w *Writer) control(ctx context.Context, kind string) error {
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
	case w.controls <- control{kind: kind, ack: ack}:
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

func (w *Writer) run() {
	batch := make([][]byte, 0, w.batchCap)
	for {
		select {
		case evt := <-w.events:
			batch = append(batch, evt)
			batch = w.drainReady(batch)
			w.writeBatch(batch)
			batch = batch[:0]
		case control := <-w.controls:
			batch = w.drainAll(batch)
			w.writeBatch(batch)
			batch = batch[:0]
			close(control.ack)
			if control.kind == "shutdown" {
				return
			}
		}
	}
}

func (w *Writer) drainReady(batch [][]byte) [][]byte {
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

func (w *Writer) drainAll(batch [][]byte) [][]byte {
	for {
		select {
		case evt := <-w.events:
			batch = append(batch, evt)
		default:
			return batch
		}
	}
}

func (w *Writer) writeBatch(raws [][]byte) {
	if len(raws) == 0 || w.write == nil {
		return
	}
	if err := w.write(raws); err != nil {
		if w.stats != nil {
			w.stats.writeFailuresTotal.Add(1)
		}
		if w.onFailure != nil {
			w.onFailure(err)
		}
		return
	}
	if w.stats != nil {
		w.stats.writtenTotal.Add(uint64(len(raws)))
	}
}
