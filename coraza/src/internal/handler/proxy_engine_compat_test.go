package handler

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
)

func TestServeProxyTukuyomiEnginePreservesHEAD(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Upstream-Head", "ok")
		w.Header().Set("Content-Length", strconv.Itoa(len("ignored-body")))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ignored-body"))
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodHead, srv.URL+"/head", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do HEAD: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read HEAD body: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want=%d", res.StatusCode, http.StatusOK)
	}
	if got := res.Header.Get("X-Upstream-Head"); got != "ok" {
		t.Fatalf("X-Upstream-Head=%q want=ok", got)
	}
	if len(body) != 0 {
		t.Fatalf("HEAD body length=%d want=0", len(body))
	}
}

func TestServeProxyTukuyomiEnginePreservesTrailers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("payload"))
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/trailers")
	if err != nil {
		t.Fatalf("GET trailers: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "payload" {
		t.Fatalf("body=%q want=payload", string(body))
	}
	if got := res.Trailer.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("X-Upstream-Trailer=%q want=done", got)
	}
}

func TestServeProxyTukuyomiEngineStreamsBeforeUpstreamCompletes(t *testing.T) {
	allowSecond := make(chan struct{})
	var releaseSecondOnce sync.Once
	releaseSecond := func() {
		releaseSecondOnce.Do(func() {
			close(allowSecond)
		})
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "missing flusher", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("first\n"))
		flusher.Flush()
		<-allowSecond
		_, _ = w.Write([]byte("second\n"))
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, `"flush_interval_ms": 1,`)

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()
	defer releaseSecond()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	defer res.Body.Close()

	reader := bufio.NewReader(res.Body)
	firstLine := make(chan string, 1)
	firstErr := make(chan error, 1)
	go func() {
		line, err := reader.ReadString('\n')
		if err != nil {
			firstErr <- err
			return
		}
		firstLine <- line
	}()

	select {
	case line := <-firstLine:
		if line != "first\n" {
			t.Fatalf("first stream line=%q want first", line)
		}
	case err := <-firstErr:
		t.Fatalf("read first stream line: %v", err)
	case <-time.After(time.Second):
		t.Fatal("proxy did not flush first streaming chunk before upstream completed")
	}

	releaseSecond()
	second, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read second stream line: %v", err)
	}
	if second != "second\n" {
		t.Fatalf("second stream line=%q want second", second)
	}
}

func TestServeProxyTukuyomiEngineSupportsTLSUpstream(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-TLS", "ok")
		_, _ = w.Write([]byte("secure upstream"))
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, `"tls_insecure_skip_verify": true,`)

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/tls")
	if err != nil {
		t.Fatalf("GET TLS upstream: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read TLS upstream body: %v", err)
	}
	if got := res.Header.Get("X-Upstream-TLS"); got != "ok" {
		t.Fatalf("X-Upstream-TLS=%q want=ok", got)
	}
	if string(body) != "secure upstream" {
		t.Fatalf("body=%q want secure upstream", string(body))
	}
}

func TestServeProxyTukuyomiEngineForwardsLargeBodies(t *testing.T) {
	const bodySize = 2 * 1024 * 1024
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Upstream-Body-Bytes", strconv.FormatInt(n, 10))
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	res, err := http.Post(srv.URL+"/large", "application/octet-stream", strings.NewReader(strings.Repeat("x", bodySize)))
	if err != nil {
		t.Fatalf("POST large body: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read large body response: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%q", res.StatusCode, http.StatusOK, string(body))
	}
	if got := res.Header.Get("X-Upstream-Body-Bytes"); got != strconv.Itoa(bodySize) {
		t.Fatalf("X-Upstream-Body-Bytes=%q want=%d", got, bodySize)
	}
}

func TestServeProxyTukuyomiEnginePropagatesClientAbort(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/abort", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		res, err := http.DefaultClient.Do(req)
		if res != nil {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("upstream request did not start")
	}
	cancel()

	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream context was not canceled after client abort")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("client request did not finish after abort")
	}
}

func TestServeProxyTukuyomiEngineReturnsErrorForUnavailableUpstream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	initProxyEngineCompatRuntime(t, "http://"+addr, "")

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/unavailable")
	if err != nil {
		t.Fatalf("GET unavailable upstream: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read unavailable body: %v", err)
	}
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d want=%d body=%q", res.StatusCode, http.StatusBadGateway, string(body))
	}
	if len(body) == 0 {
		t.Fatal("unavailable upstream response body should not be empty")
	}
}

func TestServeProxyTukuyomiEngineForwardsBasicHTTP(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Upstream-Body-Bytes", strconv.Itoa(len(body)))
		w.Header().Set("X-Upstream-Forwarded-Host", r.Header.Get("X-Forwarded-Host"))
		_, _ = w.Write([]byte("tukuyomi proxy ok"))
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	res, err := http.Post(srv.URL+"/tukuyomi", "text/plain", strings.NewReader("tukuyomi-body"))
	if err != nil {
		t.Fatalf("POST tukuyomi_proxy: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read tukuyomi_proxy response: %v", err)
	}
	if string(body) != "tukuyomi proxy ok" {
		t.Fatalf("body=%q want tukuyomi proxy ok", string(body))
	}
	if got := res.Header.Get("X-Upstream-Body-Bytes"); got != strconv.Itoa(len("tukuyomi-body")) {
		t.Fatalf("X-Upstream-Body-Bytes=%q want=%d", got, len("tukuyomi-body"))
	}
	if got := res.Header.Get("X-Upstream-Forwarded-Host"); got == "" {
		t.Fatal("tukuyomi_proxy engine did not set X-Forwarded-Host")
	}
}

func TestCopyProxyHeaderPreservesDuplicateValues(t *testing.T) {
	dst := http.Header{}
	src := http.Header{
		"x-test": []string{"one", "two"},
		"X-Add":  []string{"first"},
	}
	dst.Set("X-Add", "existing")

	copyProxyHeader(dst, src)

	if got := dst.Values("X-Test"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("X-Test values=%v want [one two]", got)
	}
	if got := dst.Values("X-Add"); len(got) != 2 || got[0] != "existing" || got[1] != "first" {
		t.Fatalf("X-Add values=%v want [existing first]", got)
	}
}

func TestServeProxyTukuyomiEngineClearsInboundCloseForUpstream(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)

	seenClose := make(chan bool, 1)
	seenConnection := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenClose <- r.Close
		seenConnection <- r.Header.Get("Connection")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/tukuyomi-close", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Close = true
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET tukuyomi_proxy close: %v", err)
	}
	_ = res.Body.Close()

	if closeFlag := <-seenClose; closeFlag {
		t.Fatal("tukuyomi_proxy engine forwarded inbound Request.Close to upstream")
	}
	if connection := <-seenConnection; connection != "" {
		t.Fatalf("tukuyomi_proxy engine forwarded Connection header %q", connection)
	}
}

func TestTukuyomiProxyXForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.test/app", nil)
	req.Host = "proxy.example.test"
	req.RemoteAddr = "192.0.2.44:54321"
	req.TLS = &tls.ConnectionState{}
	header := http.Header{
		"X-Forwarded-For": []string{"198.51.100.10", "203.0.113.20"},
	}

	setTukuyomiProxyXForwarded(header, req)

	if got, want := header.Get("X-Forwarded-For"), "198.51.100.10, 203.0.113.20, 192.0.2.44"; got != want {
		t.Fatalf("X-Forwarded-For=%q want=%q", got, want)
	}
	if got := header.Get("X-Forwarded-Host"); got != "proxy.example.test" {
		t.Fatalf("X-Forwarded-Host=%q want proxy.example.test", got)
	}
	if got := header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("X-Forwarded-Proto=%q want https", got)
	}
}

func TestTukuyomiProxyXForwardedClearsInvalidRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.example.test/app", nil)
	req.Host = "proxy.example.test"
	req.RemoteAddr = "not-a-host-port"
	header := http.Header{
		"X-Forwarded-For": []string{"198.51.100.10"},
	}

	setTukuyomiProxyXForwarded(header, req)

	if got := header.Get("X-Forwarded-For"); got != "" {
		t.Fatalf("X-Forwarded-For=%q want empty for invalid RemoteAddr", got)
	}
	if got := header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("X-Forwarded-Proto=%q want http", got)
	}
}

func TestServeProxyTukuyomiEnginePreservesRouteResponseHeaderContext(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "origin")
		_, _ = w.Write([]byte("route response"))
	}))
	defer upstream.Close()

	proxyPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "service-a",
      "priority": 10,
      "match": {
        "hosts": ["api.example.test"],
        "path": { "type": "prefix", "value": "/service-a/" }
      },
      "action": {
        "upstream": "primary",
        "response_headers": {
          "set": {
            "X-Route-Response": "applied"
          }
        }
      }
    }
  ]
}`, upstream.URL)
	if err := os.WriteFile(proxyPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/service-a/users", nil)
	req.Host = "api.example.test"
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolve route decision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))

	rec := httptest.NewRecorder()
	ServeProxy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-Route-Response"); got != "applied" {
		t.Fatalf("X-Route-Response=%q want=applied", got)
	}
	if got := rec.Header().Get("X-Upstream"); got != "origin" {
		t.Fatalf("X-Upstream=%q want=origin", got)
	}
}

func TestServeProxyTukuyomiEngineForwardsInformationalResponses(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</early.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		w.Header().Set("Server", "upstream-leak")
		w.Header().Set("X-Upstream-Final", "ok")
		_, _ = w.Write([]byte("final response"))
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	var mu sync.Mutex
	var gotCodes []int
	var gotEarlyLink string
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/early-hints", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			mu.Lock()
			defer mu.Unlock()
			gotCodes = append(gotCodes, code)
			gotEarlyLink = header.Get("Link")
			return nil
		},
	}))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET early hints: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read early hints body: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want=%d", res.StatusCode, http.StatusOK)
	}
	if string(body) != "final response" {
		t.Fatalf("body=%q want final response", string(body))
	}
	if got := res.Header.Get("X-Upstream-Final"); got != "ok" {
		t.Fatalf("X-Upstream-Final=%q want=ok", got)
	}
	if got := res.Header.Get("Link"); got != "" {
		t.Fatalf("final Link header=%q should not include informational-only header", got)
	}
	if got := res.Header.Get("Server"); got != "" {
		t.Fatalf("final Server header=%q should be sanitized after informational response", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(gotCodes) != 1 || gotCodes[0] != http.StatusEarlyHints {
		t.Fatalf("1xx codes=%v want [%d]", gotCodes, http.StatusEarlyHints)
	}
	if gotEarlyLink != "</early.css>; rel=preload" {
		t.Fatalf("early Link=%q want preload link", gotEarlyLink)
	}
}

func TestTukuyomiProxyResponseBodyNegativeFlushesImmediately(t *testing.T) {
	writer := &flushCountingResponseWriter{header: make(http.Header)}

	if err := copyTukuyomiProxyResponseBody(writer, strings.NewReader("immediate"), -time.Millisecond); err != nil {
		t.Fatalf("copy body: %v", err)
	}
	if writer.body.String() != "immediate" {
		t.Fatalf("body=%q want immediate", writer.body.String())
	}
	if got := writer.flushes.Load(); got == 0 {
		t.Fatal("negative flush interval should flush immediately after body writes")
	}
}

func TestServeProxyTukuyomiEngineStreamsUnknownLengthImmediately(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)

	allowSecond := make(chan struct{})
	var releaseSecondOnce sync.Once
	releaseSecond := func() {
		releaseSecondOnce.Do(func() {
			close(allowSecond)
		})
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "missing flusher", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("first\n"))
		flusher.Flush()
		<-allowSecond
		_, _ = w.Write([]byte("second\n"))
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, `"flush_interval_ms": 0,`)

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()
	defer releaseSecond()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/tukuyomi-stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET tukuyomi stream: %v", err)
	}
	defer res.Body.Close()

	reader := bufio.NewReader(res.Body)
	firstLine := make(chan string, 1)
	firstErr := make(chan error, 1)
	go func() {
		line, err := reader.ReadString('\n')
		if err != nil {
			firstErr <- err
			return
		}
		firstLine <- line
	}()

	select {
	case line := <-firstLine:
		if line != "first\n" {
			t.Fatalf("first stream line=%q want first", line)
		}
	case err := <-firstErr:
		t.Fatalf("read first stream line: %v", err)
	case <-time.After(time.Second):
		t.Fatal("tukuyomi_proxy did not immediately flush unknown-length streaming response")
	}

	releaseSecond()
	second, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read second stream line: %v", err)
	}
	if second != "second\n" {
		t.Fatalf("second stream line=%q want second", second)
	}
}

func TestServeProxyTukuyomiEnginePreservesResponseCache(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)
	gin.SetMode(gin.TestMode)

	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("cacheable"))
	}))
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	cacheStoreDir := t.TempDir()
	cacheStoreCfgPath := filepath.Join(t.TempDir(), "cache-store.json")
	if err := os.WriteFile(cacheStoreCfgPath, []byte(`{"enabled":true,"store_dir":`+strconv.Quote(cacheStoreDir)+`,"max_bytes":1048576}`), 0o600); err != nil {
		t.Fatalf("write cache store config: %v", err)
	}
	if err := InitResponseCacheRuntime(cacheStoreCfgPath); err != nil {
		t.Fatalf("init response cache runtime: %v", err)
	}
	rules, err := cacheconf.LoadFromString(`ALLOW prefix=/static methods=GET ttl=60`)
	if err != nil {
		t.Fatalf("load cache rules: %v", err)
	}
	previousRules := cacheconf.Get()
	t.Cleanup(func() {
		if previousRules != nil {
			cacheconf.Set(previousRules)
			return
		}
		emptyRules, _ := cacheconf.LoadFromString("")
		cacheconf.Set(emptyRules)
	})
	cacheconf.Set(rules)

	router := gin.New()
	router.NoRoute(ProxyHandler)
	srv := httptest.NewServer(router)
	defer srv.Close()

	for i, want := range []string{"MISS", "HIT"} {
		res, err := http.Get(srv.URL + "/static/app.js")
		if err != nil {
			t.Fatalf("GET cache request %d: %v", i+1, err)
		}
		_ = res.Body.Close()
		if got := res.Header.Get(proxyResponseCacheHeader); got != want {
			t.Fatalf("cache request %d header=%q want=%q", i+1, got, want)
		}
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests=%d want=1", got)
	}
}

func TestProxyEngineTukuyomiDoesNotRequireStandardFallback(t *testing.T) {
	engine, err := newProxyEngine(testRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("unused")
	}), config.ProxyEngineModeTukuyomiProxy, 0)
	if err != nil {
		t.Fatalf("newProxyEngine: %v", err)
	}
	if _, ok := engine.(*tukuyomiProxyEngine); !ok {
		t.Fatalf("engine type=%T want *tukuyomiProxyEngine", engine)
	}
}

func TestProxyEngineDefaultModeIsTukuyomiProxy(t *testing.T) {
	engine, err := newProxyEngine(testRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("unused")
	}), "", 0)
	if err != nil {
		t.Fatalf("newProxyEngine: %v", err)
	}
	if _, ok := engine.(*tukuyomiProxyEngine); !ok {
		t.Fatalf("engine type=%T want *tukuyomiProxyEngine", engine)
	}
}

func TestServeProxyTukuyomiEngineNativeUpgradeAppliesRouteResponseHeaders(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)
	upstream := newRawUpgradeServer(t, "websocket", nil)
	defer upstream.Close()

	proxyPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "ws",
      "priority": 10,
      "match": { "path": { "type": "prefix", "value": "/ws" } },
      "action": {
        "upstream": "primary",
        "response_headers": {
          "set": { "X-Route-Upgrade": "applied" }
        }
      }
    }
  ]
}`, upstream.URL)
	if err := os.WriteFile(proxyPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	srv := httptest.NewServer(httpHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decision, err := resolveProxyRouteDecision(r, currentProxyConfig(), proxyRuntimeHealth())
		if err != nil {
			t.Fatalf("resolveProxyRouteDecision: %v", err)
		}
		ServeProxy(w, r.WithContext(withProxyRouteDecision(r.Context(), decision)))
	}))
	defer srv.Close()

	res := doUpgradeRequest(t, srv.URL+"/ws/socket", "websocket")
	defer res.Body.Close()
	if res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status=%d want=101", res.StatusCode)
	}
	if got := res.Header.Get("X-Route-Upgrade"); got != "applied" {
		t.Fatalf("X-Route-Upgrade=%q want=applied", got)
	}
}

func TestServeProxyTukuyomiEngineRejectsUpgradeProtocolMismatch(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)
	upstream := newRawUpgradeServer(t, "h2c", nil)
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	res := doUpgradeRequest(t, srv.URL+"/ws/socket", "websocket")
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d want=502", res.StatusCode)
	}
}

func TestServeProxyTukuyomiEngineNativeUpgradeReleasesBackend(t *testing.T) {
	setProxyEngineModeForTest(t, config.ProxyEngineModeTukuyomiProxy)
	upstream := newRawUpgradeServer(t, "websocket", func(conn net.Conn) {
		_, _ = io.Copy(conn, conn)
	})
	defer upstream.Close()
	initProxyEngineCompatRuntime(t, upstream.URL, "")

	srv := httptest.NewServer(httpHandlerFunc(ServeProxy))
	defer srv.Close()

	res := doUpgradeRequestWithClient(t, srv.URL+"/ws/socket", "websocket", &http.Client{})
	body, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("upgrade response body type=%T does not support write", res.Body)
	}
	if _, err := body.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	buf := make([]byte, len("ping"))
	if _, err := io.ReadFull(body, buf); err != nil {
		t.Fatalf("read tunnel echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo=%q want=ping", string(buf))
	}
	_ = body.Close()

	key := proxyBackendLookupKey("primary", upstream.URL)
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

func TestCopyTukuyomiProxyTunnelReturnsWhenHalfCloseUnavailable(t *testing.T) {
	client := eofTunnelConn{}
	backend := newBlockingTunnelConn()
	defer backend.Close()

	done := make(chan error, 1)
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	go func() {
		done <- copyTukuyomiProxyTunnel(req, client, nil, backend)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("copy tunnel returned error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("copy tunnel blocked when CloseWrite was unavailable")
	}
}

func TestProxyEngineRejectsInvalidRuntimeMode(t *testing.T) {
	setProxyEngineModeForTest(t, "invalid")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("unused"))
	}))
	defer upstream.Close()

	proxyPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ]
}`, upstream.URL)
	if err := os.WriteFile(proxyPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	err := InitProxyRuntime(proxyPath, 2)
	if err == nil {
		t.Fatal("InitProxyRuntime should reject invalid proxy engine mode")
	}
	if !strings.Contains(err.Error(), "proxy.engine.mode") {
		t.Fatalf("error=%q should mention proxy.engine.mode", err.Error())
	}
}

func TestProxyEngineRejectsRemovedNetHTTPMode(t *testing.T) {
	setProxyEngineModeForTest(t, "net_http")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("unused"))
	}))
	defer upstream.Close()

	proxyPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ]
}`, upstream.URL)
	if err := os.WriteFile(proxyPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	err := InitProxyRuntime(proxyPath, 2)
	if err == nil {
		t.Fatal("InitProxyRuntime should reject removed net_http proxy engine mode")
	}
	if !strings.Contains(err.Error(), "proxy.engine.mode") || !strings.Contains(err.Error(), config.ProxyEngineModeTukuyomiProxy) {
		t.Fatalf("error=%q should require %s", err.Error(), config.ProxyEngineModeTukuyomiProxy)
	}
}

func newRawUpgradeServer(t *testing.T, upgrade string, afterSwitch func(net.Conn)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !proxyHeaderValuesContainToken(r.Header.Values("Connection"), "upgrade") {
			http.Error(w, "missing connection upgrade", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(r.Header.Get("Upgrade")) == "" {
			http.Error(w, "missing upgrade", http.StatusBadRequest)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack upstream: %v", err)
			return
		}
		if afterSwitch == nil {
			defer conn.Close()
		}
		_, _ = fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\nX-Upstream-Upgrade: ok\r\n\r\n", upgrade)
		if err := brw.Flush(); err != nil {
			t.Errorf("flush upstream upgrade: %v", err)
			_ = conn.Close()
			return
		}
		if afterSwitch != nil {
			afterSwitch(conn)
			_ = conn.Close()
		}
	}))
}

func doUpgradeRequest(t *testing.T, target string, upgrade string) *http.Response {
	t.Helper()
	return doUpgradeRequestWithClient(t, target, upgrade, &http.Client{Timeout: 3 * time.Second})
}

func doUpgradeRequestWithClient(t *testing.T, target string, upgrade string, client *http.Client) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("new upgrade request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", upgrade)
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("do upgrade request: %v", err)
	}
	return res
}

type eofTunnelConn struct{}

func (eofTunnelConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (eofTunnelConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (eofTunnelConn) Close() error {
	return nil
}

type blockingTunnelConn struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingTunnelConn() *blockingTunnelConn {
	return &blockingTunnelConn{closed: make(chan struct{})}
}

func (c *blockingTunnelConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *blockingTunnelConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *blockingTunnelConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}

func initProxyEngineCompatRuntime(t *testing.T, upstreamURL string, extraFields string) {
	t.Helper()

	proxyPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := fmt.Sprintf(`{
  %s
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ]
}`, extraFields, upstreamURL)
	if err := os.WriteFile(proxyPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}
}

func setProxyEngineModeForTest(t *testing.T, mode string) {
	t.Helper()
	prev := config.ProxyEngineMode
	config.ProxyEngineMode = mode
	t.Cleanup(func() {
		config.ProxyEngineMode = prev
	})
}

type flushCountingResponseWriter struct {
	header  http.Header
	body    strings.Builder
	flushes atomic.Int32
}

func (w *flushCountingResponseWriter) Header() http.Header {
	return w.header
}

func (w *flushCountingResponseWriter) Write(p []byte) (int, error) {
	return w.body.Write(p)
}

func (w *flushCountingResponseWriter) WriteHeader(statusCode int) {}

func (w *flushCountingResponseWriter) Flush() {
	w.flushes.Add(1)
}
