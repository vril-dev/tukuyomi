package handler

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"tukuyomi/internal/config"
)

func TestServeProxyWebSocketPassthrough(t *testing.T) {
	for _, mode := range []string{config.ProxyEngineModeNetHTTP, config.ProxyEngineModeTukuyomiProxy} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			setProxyEngineModeForTest(t, mode)

			upstream := httptest.NewServer(websocket.Handler(func(conn *websocket.Conn) {
				defer conn.Close()

				var in string
				if err := websocket.Message.Receive(conn, &in); err != nil {
					t.Errorf("upstream receive failed: %v", err)
					return
				}
				if err := websocket.Message.Send(conn, "echo:"+in); err != nil {
					t.Errorf("upstream send failed: %v", err)
				}
			}))
			defer upstream.Close()

			initWebSocketProxyRuntime(t, upstream.URL)

			srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
			defer srv.Close()

			wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/echo"
			conn, err := websocket.Dial(wsURL, "", srv.URL)
			if err != nil {
				t.Fatalf("websocket dial failed: %v", err)
			}
			defer conn.Close()

			if err := websocket.Message.Send(conn, "hello"); err != nil {
				t.Fatalf("websocket send failed: %v", err)
			}

			var out string
			if err := websocket.Message.Receive(conn, &out); err != nil {
				t.Fatalf("websocket receive failed: %v", err)
			}
			if out != "echo:hello" {
				t.Fatalf("unexpected websocket response: %q", out)
			}
		})
	}
}

func TestServeProxyTukuyomiWebSocketConcurrentStress(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)

	const clients = 32
	const messagesPerClient = 20
	payloadBlock := strings.Repeat("x", 8192)
	upstreamErrs := make(chan error, clients)
	reportUpstreamErr := func(err error) {
		select {
		case upstreamErrs <- err:
		default:
		}
	}

	upstream := httptest.NewServer(websocket.Handler(func(conn *websocket.Conn) {
		defer conn.Close()
		for {
			var in string
			if err := websocket.Message.Receive(conn, &in); err != nil {
				if err != io.EOF {
					reportUpstreamErr(fmt.Errorf("upstream receive failed: %w", err))
				}
				return
			}
			if err := websocket.Message.Send(conn, "echo:"+in); err != nil {
				reportUpstreamErr(fmt.Errorf("upstream send failed: %w", err))
				return
			}
		}
	}))
	defer upstream.Close()

	initWebSocketProxyRuntime(t, upstream.URL)

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/stress"
	start := make(chan struct{})
	results := make(chan error, clients)
	var wg sync.WaitGroup
	for clientID := 0; clientID < clients; clientID++ {
		clientID := clientID
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			conn, err := websocket.Dial(wsURL, "", srv.URL)
			if err != nil {
				results <- fmt.Errorf("client %d dial failed: %w", clientID, err)
				return
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
				results <- fmt.Errorf("client %d set deadline failed: %w", clientID, err)
				return
			}
			for messageID := 0; messageID < messagesPerClient; messageID++ {
				payloadLen := 2048 + (messageID%4)*1536
				payload := fmt.Sprintf("client=%02d message=%02d %s", clientID, messageID, payloadBlock[:payloadLen])
				if err := websocket.Message.Send(conn, payload); err != nil {
					results <- fmt.Errorf("client %d message %d send failed: %w", clientID, messageID, err)
					return
				}
				var out string
				if err := websocket.Message.Receive(conn, &out); err != nil {
					results <- fmt.Errorf("client %d message %d receive failed: %w", clientID, messageID, err)
					return
				}
				if want := "echo:" + payload; out != want {
					results <- fmt.Errorf("client %d message %d response mismatch len=%d want=%d", clientID, messageID, len(out), len(want))
					return
				}
			}
			results <- nil
		}()
	}

	close(start)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("websocket stress test timed out")
	}

	close(results)
	failed := false
	for err := range results {
		if err != nil {
			t.Error(err)
			failed = true
		}
	}
	select {
	case err := <-upstreamErrs:
		t.Error(err)
		failed = true
	default:
	}
	if failed {
		t.FailNow()
	}

	waitForWebSocketBackendInFlightZero(t, "primary", upstream.URL)
}

func initWebSocketProxyRuntime(t *testing.T, upstreamURL string) {
	t.Helper()

	tmpDir := t.TempDir()
	proxyPath := filepath.Join(tmpDir, "proxy.json")
	raw := fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ],
  "dial_timeout": 5,
  "response_header_timeout": 10,
  "idle_conn_timeout": 90,
  "max_idle_conns": 100,
  "max_idle_conns_per_host": 100,
  "max_conns_per_host": 200,
  "force_http2": false,
  "disable_compression": false,
  "expect_continue_timeout": 1,
  "tls_insecure_skip_verify": false,
  "tls_client_cert": "",
  "tls_client_key": "",
  "buffer_request_body": false,
  "max_response_buffer_bytes": 0,
  "flush_interval_ms": 0,
  "health_check_path": "",
  "health_check_interval_sec": 15,
  "health_check_timeout_sec": 2
}`, upstreamURL)
	if err := os.WriteFile(proxyPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}
}

func waitForWebSocketBackendInFlightZero(t *testing.T, name, upstreamURL string) {
	t.Helper()

	key := proxyBackendLookupKey(name, upstreamURL)
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, ok := ProxyBackendStatusByKey(key)
		if ok && status.InFlight == 0 {
			return
		}
		if time.Now().After(deadline) {
			if ok {
				t.Fatalf("backend inflight=%d want=0", status.InFlight)
			}
			t.Fatalf("backend status for key %q not found", key)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type httpHandlerFunc func(http.ResponseWriter, *http.Request)

func (f httpHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f(w, r)
}
