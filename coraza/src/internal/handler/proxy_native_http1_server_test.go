package handler

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNativeHTTP1ServerRoundTripAndKeepAlive(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Path", r.URL.Path)
		_, _ = w.Write([]byte("ok:" + r.URL.Path))
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	if _, err := io.WriteString(conn, "GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("write first request: %v", err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse first: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok:/one" || resp.Header.Get("X-Path") != "/one" {
		t.Fatalf("first response body=%q header=%q", string(body), resp.Header.Get("X-Path"))
	}

	if _, err := io.WriteString(conn, "GET /two HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("write second request: %v", err)
	}
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse second: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok:/two" {
		t.Fatalf("second response body=%q", string(body))
	}
	if got := srv.keepAliveReuses.Load(); got != 1 {
		t.Fatalf("keepAliveReuses=%d want 1", got)
	}
}

func TestNativeHTTP1ServerConnectionClose(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("bye"))
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := br.Peek(1); err == nil {
		t.Fatal("connection remained readable; want close")
	}
}

func TestNativeHTTP1ServerShutdownDrainsInFlight(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = w.Write([]byte("done"))
	}))
	defer srv.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
			done <- err
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			done <- err
			return
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			done <- err
			return
		}
		if string(body) != "done" {
			done <- errors.New("unexpected body")
			return
		}
		done <- nil
	}()
	<-entered
	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutdownDone <- srv.Shutdown(ctx)
	}()
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned before in-flight request drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := <-shutdownDone; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestNativeHTTP1ServerShutdownTimeout(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = w.Write([]byte("late"))
	}))
	defer func() {
		close(release)
		_ = srv.Close()
	}()
	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		_, _ = http.ReadResponse(bufio.NewReader(conn), nil)
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := srv.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown err=%v want deadline exceeded", err)
	}
}

func TestNativeHTTP1ServerShutdownClosesIdleWithoutGaugeLeak(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("idle"))
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	deadline := time.Now().Add(time.Second)
	for srv.idleConnections.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("idleConnections=%d want 1 before shutdown", srv.idleConnections.Load())
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if got := srv.idleConnections.Load(); got != 0 {
		t.Fatalf("idleConnections=%d want 0 after shutdown", got)
	}
}

func TestNativeHTTP1ServerParseError(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not run for parse error")
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\n folded: no\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if got := srv.parseErrors.Load(); got != 1 {
		t.Fatalf("parseErrors=%d want 1", got)
	}
}

func TestNativeHTTP1ServerScrubsInvalidResponseHeader(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Good", "ok")
		w.Header()["X-Bad"] = []string{"bad\nvalue"}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.Header.Get("X-Good") != "ok" {
		t.Fatalf("X-Good=%q", resp.Header.Get("X-Good"))
	}
	if strings.TrimSpace(resp.Header.Get("X-Bad")) != "" {
		t.Fatalf("X-Bad leaked: %q", resp.Header.Get("X-Bad"))
	}
}

func TestNativeHTTP1ServerReaderReuseDoesNotLeakHeadersAcrossConnections(t *testing.T) {
	seen := make(chan string, 2)
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("X-Leak")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	nativeHTTP1WriteSingleRequest(t, addr, "GET /first HTTP/1.1\r\nHost: example.com\r\nX-Leak: first\r\nConnection: close\r\n\r\n")
	nativeHTTP1WriteSingleRequest(t, addr, "GET /second HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

	first := <-seen
	second := <-seen
	if first != "first" {
		t.Fatalf("first X-Leak=%q want first", first)
	}
	if second != "" {
		t.Fatalf("second X-Leak leaked from pooled reader: %q", second)
	}
}

func nativeHTTP1WriteSingleRequest(t *testing.T, addr string, raw string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
}

func nativeHTTP1StartTestServer(t *testing.T, handler http.Handler) (*nativeHTTP1Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv := &nativeHTTP1Server{Handler: handler}
	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	}()
	return srv, ln.Addr().String()
}
