package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type workerActivationGate struct {
	done chan struct{}

	activated atomic.Bool
	mu        sync.RWMutex
	err       error
}

type activationGateListener struct {
	net.Listener
	gate *workerActivationGate
}

var (
	workerActivationGateOnce sync.Once
	workerActivationGateInst *workerActivationGate
	workerActivationGateErr  error
)

func wrapWorkerActivationListenerIfNeeded(ln net.Listener) (net.Listener, error) {
	if ln == nil {
		return nil, fmt.Errorf("listener is required")
	}
	gate, err := currentWorkerActivationGate()
	if err != nil || gate == nil {
		return ln, err
	}
	return &activationGateListener{Listener: ln, gate: gate}, nil
}

func currentWorkerActivationGate() (*workerActivationGate, error) {
	if internalProcessRoleFromEnv(os.Environ()) != internalProcessRoleWorker {
		return nil, nil
	}
	workerActivationGateOnce.Do(func() {
		workerActivationGateInst, workerActivationGateErr = newWorkerActivationGateFromEnv(os.Getenv)
	})
	return workerActivationGateInst, workerActivationGateErr
}

func newWorkerActivationGateFromEnv(getenv func(string) string) (*workerActivationGate, error) {
	raw := strings.TrimSpace(getenv(workerActivateFDEnv))
	if raw == "" {
		return nil, nil
	}
	fd, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", workerActivateFDEnv, err)
	}
	if fd < 3 {
		return nil, fmt.Errorf("%s must be >= 3", workerActivateFDEnv)
	}
	file := os.NewFile(uintptr(fd), "tukuyomi-worker-activate")
	if file == nil {
		return nil, fmt.Errorf("open worker activation fd %d", fd)
	}
	gate := newWorkerActivationGate()
	go gate.watch(file)
	return gate, nil
}

func newWorkerActivationGate() *workerActivationGate {
	return &workerActivationGate{done: make(chan struct{})}
}

func (g *workerActivationGate) watch(file *os.File) {
	defer file.Close()
	var buf [1]byte
	_, err := io.ReadFull(file, buf[:])
	if err != nil {
		g.fail(fmt.Errorf("worker activation read failed: %w", err))
		return
	}
	if buf[0] != '1' {
		g.fail(fmt.Errorf("worker activation token is invalid"))
		return
	}
	g.activate()
}

func (g *workerActivationGate) activate() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.done:
		return
	default:
		g.activated.Store(true)
		close(g.done)
	}
}

func (g *workerActivationGate) fail(err error) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.err = err
	select {
	case <-g.done:
	default:
		close(g.done)
	}
	g.mu.Unlock()
}

func (g *workerActivationGate) wait() error {
	if g == nil {
		return nil
	}
	if g.activated.Load() {
		return nil
	}
	<-g.done
	if g.activated.Load() {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.err
}

func (l *activationGateListener) Accept() (net.Conn, error) {
	if l == nil || l.Listener == nil {
		return nil, fmt.Errorf("listener is required")
	}
	if l.gate != nil {
		if err := l.gate.wait(); err != nil {
			return nil, err
		}
	}
	return l.Listener.Accept()
}

func runAfterWorkerActivation(name string, start func()) error {
	if start == nil {
		return nil
	}
	gate, err := currentWorkerActivationGate()
	if err != nil {
		return err
	}
	if gate == nil {
		start()
		return nil
	}
	go func() {
		if err := gate.wait(); err != nil {
			log.Printf("[WORKER][ACTIVATION][WARN] %s not started: %v", name, err)
			return
		}
		start()
	}()
	return nil
}
