package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type managedServerLifecycle struct {
	shutdownTimeout time.Duration
	errCh           chan error
	wg              sync.WaitGroup
	mu              sync.Mutex
	shutdowns       []namedShutdown
	drains          []namedShutdown
	forceCloses     []namedClose
	shuttingDown    atomic.Bool
}

type namedShutdown struct {
	name string
	fn   func(context.Context) error
}

type namedClose struct {
	name string
	fn   func() error
}

func newManagedServerLifecycle(timeout time.Duration) *managedServerLifecycle {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &managedServerLifecycle{
		shutdownTimeout: timeout,
		errCh:           make(chan error, 8),
	}
}

func (l *managedServerLifecycle) TrackListener(name string, ln net.Listener) net.Listener {
	if ln == nil {
		return nil
	}
	tracker := newConnTracker()
	l.mu.Lock()
	l.drains = append(l.drains, namedShutdown{name: name + " connections", fn: tracker.Wait})
	l.forceCloses = append(l.forceCloses, namedClose{name: name + " connections", fn: tracker.CloseAll})
	l.mu.Unlock()
	return &connTrackingListener{Listener: ln, tracker: tracker}
}

func (l *managedServerLifecycle) Go(name string, serve func() error, shutdown func(context.Context) error, forceClose func() error) {
	l.mu.Lock()
	if shutdown != nil {
		l.shutdowns = append(l.shutdowns, namedShutdown{name: name, fn: shutdown})
	}
	if forceClose != nil {
		l.forceCloses = append(l.forceCloses, namedClose{name: name, fn: forceClose})
	}
	l.mu.Unlock()

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		err := serve()
		if l.shuttingDown.Load() {
			return
		}
		if err == nil {
			err = fmt.Errorf("stopped unexpectedly")
		}
		if !errors.Is(err, http.ErrServerClosed) {
			select {
			case l.errCh <- fmt.Errorf("%s server stopped: %w", name, err):
			default:
			}
		}
	}()
}

func (l *managedServerLifecycle) Wait() error {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	return l.wait(sigCh)
}

func (l *managedServerLifecycle) WaitWithSignals(sigCh <-chan os.Signal) error {
	if sigCh == nil {
		return fmt.Errorf("signal channel is required")
	}
	return l.wait(sigCh)
}

func (l *managedServerLifecycle) wait(sigCh <-chan os.Signal) error {
	select {
	case err := <-l.errCh:
		_ = l.shutdown()
		return err
	case sig := <-sigCh:
		log.Printf("[SERVER] received %s; starting graceful shutdown", sig)
		return l.shutdown()
	}
}

func (l *managedServerLifecycle) shutdown() error {
	l.shuttingDown.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), l.shutdownTimeout)
	defer cancel()

	l.mu.Lock()
	shutdowns := append([]namedShutdown(nil), l.shutdowns...)
	drains := append([]namedShutdown(nil), l.drains...)
	forceCloses := append([]namedClose(nil), l.forceCloses...)
	l.mu.Unlock()

	var shutdownWG sync.WaitGroup
	errCh := make(chan error, len(shutdowns))
	for _, item := range shutdowns {
		item := item
		shutdownWG.Add(1)
		go func() {
			defer shutdownWG.Done()
			if err := item.fn(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s shutdown: %w", item.name, err)
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		shutdownWG.Wait()
		close(done)
	}()

	timedOut := false
	select {
	case <-done:
	case <-ctx.Done():
		timedOut = true
	}
	if !timedOut {
		timedOut = !runLifecycleDrains(ctx, drains)
	}
	if timedOut {
		log.Printf("[SERVER][WARN] graceful shutdown timed out after %s; forcing close", l.shutdownTimeout)
		for _, item := range forceCloses {
			if err := item.fn(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[SERVER][WARN] force close %s: %v", item.name, err)
			}
		}
		<-done
	}
	close(errCh)

	l.wg.Wait()
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	log.Printf("[SERVER] graceful shutdown completed")
	return nil
}

func runLifecycleDrains(ctx context.Context, drains []namedShutdown) bool {
	for _, item := range drains {
		if err := item.fn(ctx); err != nil {
			return false
		}
	}
	return true
}

type connTrackingListener struct {
	net.Listener
	tracker *connTracker
}

func (l *connTrackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.tracker.Track(conn), nil
}

type connTracker struct {
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
	done  chan struct{}
}

func newConnTracker() *connTracker {
	return &connTracker{
		conns: make(map[*trackedConn]struct{}),
		done:  make(chan struct{}),
	}
}

func (t *connTracker) Track(conn net.Conn) net.Conn {
	tracked := &trackedConn{Conn: conn, tracker: t}
	t.mu.Lock()
	t.conns[tracked] = struct{}{}
	t.resetDoneLocked()
	t.mu.Unlock()
	return tracked
}

func (t *connTracker) Wait(ctx context.Context) error {
	t.mu.Lock()
	if len(t.conns) == 0 {
		t.mu.Unlock()
		return nil
	}
	done := t.done
	t.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *connTracker) CloseAll() error {
	t.mu.Lock()
	conns := make([]*trackedConn, 0, len(t.conns))
	for conn := range t.conns {
		conns = append(conns, conn)
	}
	t.mu.Unlock()
	var firstErr error
	for _, conn := range conns {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (t *connTracker) remove(conn *trackedConn) {
	t.mu.Lock()
	delete(t.conns, conn)
	if len(t.conns) == 0 {
		close(t.done)
		t.done = make(chan struct{})
	}
	t.mu.Unlock()
}

func (t *connTracker) resetDoneLocked() {
	select {
	case <-t.done:
		t.done = make(chan struct{})
	default:
	}
}

type trackedConn struct {
	net.Conn
	tracker *connTracker
	once    sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.tracker.remove(c)
	})
	return err
}
