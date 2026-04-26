package eventasync

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestWriterFlushWritesQueuedBatches(t *testing.T) {
	stats := NewStats()
	var mu sync.Mutex
	var batches [][][]byte
	writer := NewWriter(8, 4, stats, func(raws [][]byte) error {
		mu.Lock()
		defer mu.Unlock()
		clone := make([][]byte, len(raws))
		for i := range raws {
			clone[i] = append([]byte(nil), raws[i]...)
		}
		batches = append(batches, clone)
		return nil
	}, nil)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = writer.Shutdown(ctx)
	})

	raw := []byte("one")
	if !writer.Enqueue(raw) {
		t.Fatal("enqueue failed")
	}
	raw[0] = 'x'
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := writer.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(batches) != 1 || len(batches[0]) != 1 || string(batches[0][0]) != "one" {
		t.Fatalf("batches=%q", batches)
	}
	snapshot := stats.Snapshot(writer.QueueCurrent(), writer.QueueCapacity())
	if snapshot.EnqueuedTotal != 1 || snapshot.WrittenTotal != 1 {
		t.Fatalf("snapshot=%#v", snapshot)
	}
}

func TestWriterFailureStatsAndShutdownDrop(t *testing.T) {
	stats := NewStats()
	writeErr := errors.New("write failed")
	failures := 0
	writer := NewWriter(1, 1, stats, func([][]byte) error {
		return writeErr
	}, func(err error) {
		if errors.Is(err, writeErr) {
			failures++
		}
	})

	if !writer.Enqueue([]byte("one")) {
		t.Fatal("enqueue failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := writer.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if failures != 1 {
		t.Fatalf("failures=%d want=1", failures)
	}
	if got := stats.Snapshot(0, 0).WriteFailuresTotal; got != 1 {
		t.Fatalf("write failures=%d want=1", got)
	}
	if err := writer.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if writer.Enqueue([]byte("after")) {
		t.Fatal("enqueue after shutdown should fail")
	}
}
