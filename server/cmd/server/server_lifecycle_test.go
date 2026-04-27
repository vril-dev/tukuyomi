package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestServerLifecycleSignalWaitsForAcceptedRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(started)
			<-release
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	lifecycle := newManagedServerLifecycle(2 * time.Second)
	ln = lifecycle.TrackListener("public", ln)
	lifecycle.Go("public", func() error { return srv.Serve(ln) }, srv.Shutdown, srv.Close)

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String())
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()
	<-started

	sigCh := make(chan os.Signal, 1)
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- lifecycle.wait(sigCh)
	}()
	sigCh <- syscall.SIGTERM
	time.Sleep(50 * time.Millisecond)
	close(release)

	select {
	case err := <-waitCh:
		if err != nil {
			t.Fatalf("wait: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle wait timed out")
	}
	select {
	case err := <-errCh:
		t.Fatalf("client request failed: %v", err)
	case resp := <-respCh:
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status=%d want %d", resp.StatusCode, http.StatusNoContent)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client response timed out")
	}
}

func TestServerLifecycleWaitsForHijackedConnectionDrain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	hijacked := make(chan struct{})
	release := make(chan struct{})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("response writer does not support hijack")
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				t.Errorf("Hijack: %v", err)
				return
			}
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
			_ = rw.Flush()
			close(hijacked)
			<-release
			_ = conn.Close()
		}),
	}
	lifecycle := newManagedServerLifecycle(2 * time.Second)
	ln = lifecycle.TrackListener("public", ln)
	lifecycle.Go("public", func() error { return srv.Serve(ln) }, srv.Shutdown, srv.Close)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if !strings.Contains(line, "101") {
		t.Fatalf("status line=%q want 101", line)
	}
	<-hijacked

	sigCh := make(chan os.Signal, 1)
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- lifecycle.wait(sigCh)
	}()
	sigCh <- syscall.SIGHUP

	select {
	case err := <-waitCh:
		t.Fatalf("shutdown returned before hijacked connection drained: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-waitCh:
		if err != nil {
			t.Fatalf("wait: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle wait timed out")
	}
}

func TestServerLifecycleReturnsServeErrorAndRunsShutdown(t *testing.T) {
	lifecycle := newManagedServerLifecycle(time.Second)
	shutdownCalled := make(chan struct{})
	lifecycle.Go(
		"broken",
		func() error { return io.ErrUnexpectedEOF },
		func(_ context.Context) error {
			close(shutdownCalled)
			return nil
		},
		nil,
	)
	err := lifecycle.wait(make(chan os.Signal))
	if err == nil {
		t.Fatal("expected serve error")
	}
	select {
	case <-shutdownCalled:
	case <-time.After(time.Second):
		t.Fatal("shutdown was not called")
	}
}

func TestServerLifecycleReturnsUnexpectedNilServeExit(t *testing.T) {
	lifecycle := newManagedServerLifecycle(time.Second)
	shutdownCalled := make(chan struct{})
	lifecycle.Go(
		"empty",
		func() error { return nil },
		func(_ context.Context) error {
			close(shutdownCalled)
			return nil
		},
		nil,
	)
	err := lifecycle.wait(make(chan os.Signal))
	if err == nil {
		t.Fatal("expected nil serve exit to be treated as unexpected")
	}
	if !strings.Contains(err.Error(), "stopped unexpectedly") {
		t.Fatalf("err=%v want unexpected stop", err)
	}
	select {
	case <-shutdownCalled:
	case <-time.After(time.Second):
		t.Fatal("shutdown was not called")
	}
}
