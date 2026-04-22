package handler

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeHTTP1TransportRoundTripPreservesRequestAndTrailers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Method; got != http.MethodPost {
			t.Fatalf("method=%q want POST", got)
		}
		if got := r.Host; got == "" {
			t.Fatal("missing upstream host")
		}
		if got := r.Header.Get("X-Test"); got != "ok" {
			t.Fatalf("X-Test=%q want ok", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream request body: %v", err)
		}
		if got := string(body); got != "payload" {
			t.Fatalf("body=%q want payload", got)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Trailer", "X-Upstream-Trailer")
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte("created")); err != nil {
			t.Fatalf("write upstream response: %v", err)
		}
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	defer upstream.Close()

	rt, err := buildProxyNativeHTTP1Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{})
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP1Transport: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, upstream.URL+"/submit?q=1", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Test", "ok")
	req.ContentLength = int64(len("payload"))

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.StatusCode; got != http.StatusCreated {
		t.Fatalf("status=%d want=201", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if got := string(body); got != "created" {
		t.Fatalf("response body=%q want created", got)
	}
	if got := resp.Trailer.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("trailer=%q want done", got)
	}
}

func TestTukuyomiProxyUpgradeResponseDoesNotInjectConnectionClose(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Status:     "101 Switching Protocols",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Connection":           []string{"Upgrade"},
			"Upgrade":              []string{"websocket"},
			"Sec-Websocket-Accept": []string{"ok"},
		},
		Close: false,
	}
	var out bytes.Buffer
	if err := writeTukuyomiProxyUpgradeResponse(&out, resp, "websocket"); err != nil {
		t.Fatalf("writeTukuyomiProxyUpgradeResponse: %v", err)
	}
	raw := out.String()
	if strings.Contains(raw, "Connection: close\r\n") {
		t.Fatalf("upgrade response injected Connection: close:\n%s", raw)
	}
	if !strings.Contains(raw, "Connection: Upgrade\r\n") {
		t.Fatalf("upgrade response missing Connection: Upgrade:\n%s", raw)
	}
}

func TestNativeHTTP1TransportReusesDrainedConnection(t *testing.T) {
	var newConns atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("ok"))
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()

	rt, err := buildProxyNativeHTTP1Transport(normalizeProxyRulesConfig(ProxyRulesConfig{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     10,
	}), proxyTransportProfile{})
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP1Transport: %v", err)
	}
	defer rt.CloseIdleConnections()

	for i := 0; i < 3; i++ {
		req, err := http.NewRequest(http.MethodGet, upstream.URL+"/reuse", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body %d: %v", i, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close body %d: %v", i, err)
		}
		if string(body) != "ok" {
			t.Fatalf("body %d=%q want ok", i, string(body))
		}
	}
	if got := newConns.Load(); got != 1 {
		t.Fatalf("new connections=%d want 1", got)
	}
}

func TestNativeHTTP1TransportDoesNotReuseUndrainedBody(t *testing.T) {
	var newConns atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "6")
		_, _ = w.Write([]byte("abcdef"))
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()

	rt, err := buildProxyNativeHTTP1Transport(normalizeProxyRulesConfig(ProxyRulesConfig{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     10,
	}), proxyTransportProfile{})
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP1Transport: %v", err)
	}
	defer rt.CloseIdleConnections()

	first, err := http.NewRequest(http.MethodGet, upstream.URL+"/partial", nil)
	if err != nil {
		t.Fatalf("NewRequest first: %v", err)
	}
	resp, err := rt.RoundTrip(first)
	if err != nil {
		t.Fatalf("RoundTrip first: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatalf("read first byte: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close first body: %v", err)
	}

	second, err := http.NewRequest(http.MethodGet, upstream.URL+"/second", nil)
	if err != nil {
		t.Fatalf("NewRequest second: %v", err)
	}
	resp, err = rt.RoundTrip(second)
	if err != nil {
		t.Fatalf("RoundTrip second: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if got := newConns.Load(); got != 2 {
		t.Fatalf("new connections=%d want 2", got)
	}
}

func TestNativeHTTP1TransportHonorsMaxConnsPerHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	rt, err := buildProxyNativeHTTP1Transport(normalizeProxyRulesConfig(ProxyRulesConfig{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     1,
	}), proxyTransportProfile{})
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP1Transport: %v", err)
	}
	defer rt.CloseIdleConnections()

	firstReq, err := http.NewRequest(http.MethodGet, upstream.URL+"/first", nil)
	if err != nil {
		t.Fatalf("NewRequest first: %v", err)
	}
	firstResp, err := rt.RoundTrip(firstReq)
	if err != nil {
		t.Fatalf("RoundTrip first: %v", err)
	}
	defer firstResp.Body.Close()

	secondDone := make(chan error, 1)
	go func() {
		secondReq, err := http.NewRequest(http.MethodGet, upstream.URL+"/second", nil)
		if err != nil {
			secondDone <- err
			return
		}
		secondResp, err := rt.RoundTrip(secondReq)
		if err != nil {
			secondDone <- err
			return
		}
		_, _ = io.Copy(io.Discard, secondResp.Body)
		_ = secondResp.Body.Close()
		secondDone <- nil
	}()

	select {
	case err := <-secondDone:
		t.Fatalf("second request completed before first body was released: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := firstResp.Body.Close(); err != nil {
		t.Fatalf("close first body: %v", err)
	}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("second request after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second request did not proceed after first body was released")
	}
}

func TestNativeHTTP1TransportUsesConfiguredTLSServerName(t *testing.T) {
	sni := make(chan string, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	upstream.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni <- hello.ServerName
			return upstream.TLS, nil
		},
	}
	upstream.StartTLS()
	defer upstream.Close()

	rt, err := buildProxyNativeHTTP1Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{
		TLS: proxyTransportTLSConfig{
			InsecureSkipVerify: true,
			ServerName:         "backend.internal",
		},
	})
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP1Transport: %v", err)
	}
	defer rt.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/tls", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	select {
	case got := <-sni:
		if got != "backend.internal" {
			t.Fatalf("SNI=%q want backend.internal", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe TLS ClientHello")
	}
}

func TestNativeHTTP1ReadResponseRejectsOversizedHeaders(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("a", nativeHTTP1MaxResponseHeaderBytes) + "\r\n\r\n"
	req := httptest.NewRequest(http.MethodGet, "http://backend.example/", nil)
	_, err := nativeHTTP1ReadResponse(bufio.NewReader(strings.NewReader(raw)), req)
	if err == nil {
		t.Fatal("nativeHTTP1ReadResponse succeeded for oversized headers")
	}
}

func TestBuildProxyTransportDefaultProfileUsesNativeHTTP1(t *testing.T) {
	rt, err := buildProxyTransportFromProfile(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{})
	if err != nil {
		t.Fatalf("buildProxyTransportFromProfile: %v", err)
	}
	if _, ok := rt.(*nativeHTTP1Transport); !ok {
		t.Fatalf("transport=%T want *nativeHTTP1Transport", rt)
	}
}
