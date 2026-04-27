package handler

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tukuyomi/internal/config"
)

func TestNativeHTTP1HijackRawRoundTrip(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		defer conn.Close()
		if _, err := io.WriteString(brw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n"); err != nil {
			t.Errorf("write upgrade: %v", err)
			return
		}
		if err := brw.Flush(); err != nil {
			t.Errorf("flush upgrade: %v", err)
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(brw, buf); err != nil {
			t.Errorf("read tunnel: %v", err)
			return
		}
		_, _ = brw.WriteString("echo:" + string(buf))
		_ = brw.Flush()
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
	status, _ := nativeHTTP1ReadRawResponseHead(t, br)
	if status != "HTTP/1.1 101 Switching Protocols" {
		t.Fatalf("status=%q want 101", status)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	out := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(br, out); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if string(out) != "echo:ping" {
		t.Fatalf("tunnel response=%q want echo:ping", string(out))
	}
}

func TestNativeHTTP1HijackBufferedRequestBodyVisible(t *testing.T) {
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		defer conn.Close()
		body := make([]byte, 5)
		if _, err := io.ReadFull(brw, body); err != nil {
			t.Errorf("read buffered body: %v", err)
			return
		}
		_, _ = brw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n")
		_, _ = brw.Write(body)
		_ = brw.Flush()
	}))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nabcde")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll body: %v", err)
	}
	if string(body) != "abcde" {
		t.Fatalf("body=%q want abcde", string(body))
	}
}

func TestNativeHTTP1HijackErrorPaths(t *testing.T) {
	t.Run("after write", func(t *testing.T) {
		srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("started"))
			_, _, err := http.NewResponseController(w).Hijack()
			if !errors.Is(err, http.ErrHijacked) {
				t.Errorf("Hijack err=%v want http.ErrHijacked", err)
			}
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
	})

	t.Run("double hijack", func(t *testing.T) {
		srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("first Hijack: %v", err)
				return
			}
			defer conn.Close()
			_, _, err = http.NewResponseController(w).Hijack()
			if !errors.Is(err, http.ErrHijacked) {
				t.Errorf("second Hijack err=%v want http.ErrHijacked", err)
			}
			_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
		}))
		defer srv.Close()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("ReadResponse: %v", err)
		}
		_ = resp.Body.Close()
	})
}

func TestNativeHTTP1HijackShutdownDoesNotDrain(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		close(entered)
		<-release
		_ = conn.Close()
	}))
	defer func() {
		close(release)
		_ = srv.Close()
	}()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown waited on hijacked connection: %v", err)
	}
}

func TestNativeHTTP1HijackAfterShutdownStarts(t *testing.T) {
	block := make(chan struct{})
	srv, addr := nativeHTTP1StartTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block
		_, _, err := http.NewResponseController(w).Hijack()
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Hijack err=%v want http.ErrServerClosed", err)
		}
	}))
	defer srv.Close()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		shutdownDone <- srv.Shutdown(ctx)
	}()
	time.Sleep(20 * time.Millisecond)
	close(block)
	if err := <-shutdownDone; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestServeProxyTukuyomiEngineNativeHTTP1ServerUpgradeTunnel(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)
	upstream := newRawUpgradeServer(t, "websocket", func(conn net.Conn) {
		_, _ = io.Copy(conn, conn)
	})
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	srv, addr := nativeHTTP1StartTestServer(t, httpHandlerFunc(ServeProxy))
	defer srv.Close()

	res := doUpgradeRequestWithClient(t, "http://"+addr+"/ws/socket", "websocket", &http.Client{})
	body, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("upgrade response body type=%T does not support write", res.Body)
	}
	defer body.Close()
	if res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status=%d want=101", res.StatusCode)
	}
	if _, err := body.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	buf := make([]byte, len("ping"))
	if _, err := io.ReadFull(body, buf); err != nil {
		t.Fatalf("read tunnel echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo=%q want ping", string(buf))
	}
}

func TestServeProxyTukuyomiEngineNativeHTTP1ServerForwardsInformationalResponses(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</early.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		w.Header().Set("Server", "upstream-leak")
		w.Header().Set("X-Upstream-Final", "ok")
		_, _ = w.Write([]byte("final response"))
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	srv, addr := nativeHTTP1StartTestServer(t, httpHandlerFunc(ServeProxy))
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET /early-hints HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	status, header := nativeHTTP1ReadRawResponseHead(t, br)
	if status != "HTTP/1.1 103 Early Hints" {
		t.Fatalf("status=%q want 103", status)
	}
	if got := header.Get("Link"); got != "</early.css>; rel=preload" {
		t.Fatalf("early Link=%q want preload", got)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse final: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll final body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if string(body) != "final response" {
		t.Fatalf("body=%q want final response", string(body))
	}
	if got := resp.Header.Get("X-Upstream-Final"); got != "ok" {
		t.Fatalf("X-Upstream-Final=%q want ok", got)
	}
	if got := resp.Header.Get("Link"); got != "" {
		t.Fatalf("final Link header=%q should not include informational-only header", got)
	}
	if got := resp.Header.Get("Server"); got != "" {
		t.Fatalf("final Server header=%q should be sanitized after informational response", got)
	}
}
