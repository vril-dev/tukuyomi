package handler

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/net/http2/hpack"
)

func TestNativeHTTP2TransportH2CRoundTripBodiesAndTrailers(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), 8192)
	upstream := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Proto; !strings.HasPrefix(got, "HTTP/2") {
			t.Fatalf("upstream proto=%q want HTTP/2", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if !bytes.Equal(body, payload) {
			t.Fatalf("request body length=%d want=%d", len(body), len(payload))
		}
		if got := r.Trailer.Get("X-Client-Trailer"); got != "done" {
			t.Fatalf("request trailer=%q want done", got)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Trailer", "X-Upstream-Trailer")
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte("created")); err != nil {
			t.Fatalf("write response: %v", err)
		}
		w.Header().Set("X-Upstream-Trailer", "ok")
	}), &http2.Server{}))
	defer upstream.Close()

	rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
	}
	defer rt.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodPost, upstream.URL+"/upload?q=1", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.ContentLength = int64(len(payload))
	req.Trailer = http.Header{"X-Client-Trailer": []string{"done"}}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.StatusCode; got != http.StatusCreated {
		t.Fatalf("status=%d want=%d", got, http.StatusCreated)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if got := string(body); got != "created" {
		t.Fatalf("response body=%q want created", got)
	}
	if got := resp.Trailer.Get("X-Upstream-Trailer"); got != "ok" {
		t.Fatalf("response trailer=%q want ok", got)
	}
}

func TestNativeHTTP2TransportTLSALPNAndHTTP1Fallback(t *testing.T) {
	t.Run("negotiates h2", func(t *testing.T) {
		upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Upstream-Proto", r.Proto)
			w.WriteHeader(http.StatusNoContent)
		}))
		upstream.EnableHTTP2 = true
		upstream.StartTLS()
		defer upstream.Close()

		rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{
			TLSInsecureSkipVerify: true,
		}), proxyTransportProfile{HTTP2Mode: proxyHTTP2ModeForceAttempt, TLS: proxyTransportTLSConfig{InsecureSkipVerify: true}}, proxyHTTP2ModeForceAttempt)
		if err != nil {
			t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
		}
		defer rt.CloseIdleConnections()

		req, err := http.NewRequest(http.MethodGet, upstream.URL+"/h2", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("X-Upstream-Proto"); !strings.HasPrefix(got, "HTTP/2") {
			t.Fatalf("upstream proto=%q want HTTP/2", got)
		}
	})

	t.Run("falls back to native h1 when ALPN does not select h2", func(t *testing.T) {
		upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Upstream-Proto", r.Proto)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer upstream.Close()

		rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{
			TLSInsecureSkipVerify: true,
		}), proxyTransportProfile{HTTP2Mode: proxyHTTP2ModeForceAttempt, TLS: proxyTransportTLSConfig{InsecureSkipVerify: true}}, proxyHTTP2ModeForceAttempt)
		if err != nil {
			t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
		}
		defer rt.CloseIdleConnections()

		req, err := http.NewRequest(http.MethodGet, upstream.URL+"/h1", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("X-Upstream-Proto"); got != "HTTP/1.1" {
			t.Fatalf("upstream proto=%q want HTTP/1.1 fallback", got)
		}
	})
}

func TestNativeHTTP2TransportRejectsConnectionSpecificRequestHeaders(t *testing.T) {
	upstream := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not receive invalid HTTP/2 request")
	}), &http2.Server{}))
	defer upstream.Close()

	rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
	}
	defer rt.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/bad", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Connection", "close")
	if _, err := rt.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "forbidden HTTP/2 request header") {
		t.Fatalf("RoundTrip err=%v want forbidden header error", err)
	}
}

func TestNativeHTTP2TransportRejectsInvalidResponseFraming(t *testing.T) {
	t.Run("content-length mismatch", func(t *testing.T) {
		rawURL := nativeHTTP2RawServerURL(t, func(fr *http2.Framer, streamID uint32) {
			nativeHTTP2RawWriteHeaders(t, fr, streamID, false,
				hpack.HeaderField{Name: ":status", Value: "200"},
				hpack.HeaderField{Name: "content-length", Value: "5"},
			)
			if err := fr.WriteData(streamID, true, []byte("abc")); err != nil {
				t.Errorf("WriteData: %v", err)
			}
		})
		rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
		if err != nil {
			t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
		}
		defer rt.CloseIdleConnections()

		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err == nil || !strings.Contains(err.Error(), "Content-Length mismatch") {
			t.Fatalf("ReadAll body=%q err=%v want Content-Length mismatch", string(body), err)
		}
	})

	t.Run("switching protocols", func(t *testing.T) {
		rawURL := nativeHTTP2RawServerURL(t, func(fr *http2.Framer, streamID uint32) {
			nativeHTTP2RawWriteHeaders(t, fr, streamID, true,
				hpack.HeaderField{Name: ":status", Value: "101"},
			)
		})
		rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
		if err != nil {
			t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
		}
		defer rt.CloseIdleConnections()

		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if _, err := rt.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "101 Switching Protocols") {
			t.Fatalf("RoundTrip err=%v want 101 rejection", err)
		}
	})
}

func TestNativeHTTP2SessionCapacityZeroDrainsPool(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fr := nativeHTTP2RawHandshake(t, conn)
		streamID := nativeHTTP2RawReadRequestStream(t, fr)
		nativeHTTP2RawWriteHeaders(t, fr, streamID, false, hpack.HeaderField{Name: ":status", Value: "200"})
		if err := fr.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 0}); err != nil {
			t.Errorf("write max concurrent zero settings: %v", err)
			return
		}
		if err := fr.WriteData(streamID, true, nil); err != nil {
			t.Errorf("write first response data: %v", err)
			return
		}

		conn, err = ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fr = nativeHTTP2RawHandshake(t, conn)
		streamID = nativeHTTP2RawReadRequestStream(t, fr)
		nativeHTTP2RawWriteHeaders(t, fr, streamID, true, hpack.HeaderField{Name: ":status", Value: "204"})
	}()

	rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{
		MaxConnsPerHost:       1,
		ResponseHeaderTimeout: 1,
	}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
	}
	defer rt.CloseIdleConnections()

	body := nativeHTTP2RoundTripBody(t, rt, "http://"+ln.Addr().String()+"/one")
	if len(body) != 0 {
		t.Fatalf("first body length=%d want 0", len(body))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ln.Addr().String()+"/two", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("second RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.StatusCode; got != http.StatusNoContent {
		t.Fatalf("second status=%d want 204", got)
	}
}

func TestNativeHTTP2TrailerStateRejectsTrailingHeadersWithoutEndStream(t *testing.T) {
	rawURL := nativeHTTP2RawServerURL(t, func(fr *http2.Framer, streamID uint32) {
		nativeHTTP2RawWriteHeaders(t, fr, streamID, false,
			hpack.HeaderField{Name: ":status", Value: "200"},
		)
		nativeHTTP2RawWriteHeaders(t, fr, streamID, false,
			hpack.HeaderField{Name: "x-upstream-trailer", Value: "late"},
		)
	})
	rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
	}
	defer rt.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if !strings.Contains(err.Error(), "trailing HEADERS without END_STREAM") {
			t.Fatalf("RoundTrip err=%v want trailing HEADERS rejection", err)
		}
		return
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	if err == nil || !strings.Contains(err.Error(), "trailing HEADERS without END_STREAM") {
		t.Fatalf("ReadAll err=%v want trailing HEADERS rejection", err)
	}
}

func TestNativeHTTP2RapidResetBurstClosesSession(t *testing.T) {
	rawURL := nativeHTTP2RawServerURL(t, func(fr *http2.Framer, streamID uint32) {
		if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
			t.Errorf("WriteRSTStream: %v", err)
			return
		}
		for i := 1; i < nativeHTTP2RapidResetLimit+1; i++ {
			nextID := nativeHTTP2RawReadRequestStream(t, fr)
			if err := fr.WriteRSTStream(nextID, http2.ErrCodeCancel); err != nil {
				t.Errorf("WriteRSTStream %d: %v", i, err)
				return
			}
		}
	})
	rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
	}
	defer rt.CloseIdleConnections()

	var lastErr error
	for i := 0; i < nativeHTTP2RapidResetLimit+1; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL+"?n="+strconv.Itoa(i), nil)
		if err != nil {
			cancel()
			t.Fatalf("NewRequestWithContext: %v", err)
		}
		resp, err := rt.RoundTrip(req)
		cancel()
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Fatalf("RoundTrip %d succeeded; want reset error", i)
		}
		lastErr = err
	}
	var rapid nativeHTTP2RapidResetError
	if !errors.As(lastErr, &rapid) {
		t.Fatalf("last err=%v want nativeHTTP2RapidResetError", lastErr)
	}
}

func TestNativeHTTP2RequestHeaderListSizeRejectsBeforeStreamID(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	streamIDCh := make(chan uint32, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		fr := nativeHTTP2RawHandshakeWithSettings(t, conn, http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 512})
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		for {
			frame, err := fr.ReadFrame()
			if err != nil {
				_ = conn.Close()
				break
			}
			if _, ok := frame.(*http2.HeadersFrame); ok {
				t.Errorf("oversized request reached upstream as HEADERS on stream %d", frame.Header().StreamID)
				_ = conn.Close()
				return
			}
		}

		conn, err = ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fr = nativeHTTP2RawHandshakeWithSettings(t, conn, http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 512})
		streamID := nativeHTTP2RawReadRequestStream(t, fr)
		streamIDCh <- streamID
		nativeHTTP2RawWriteHeaders(t, fr, streamID, true, hpack.HeaderField{Name: ":status", Value: "204"})
	}()

	rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{
		ResponseHeaderTimeout: 1,
	}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
	}
	defer rt.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/oversized", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Large", strings.Repeat("a", 1024))
	if resp, err := rt.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "header list size") {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		t.Fatalf("oversized RoundTrip err=%v want header list size rejection", err)
	}

	req, err = http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/small", nil)
	if err != nil {
		t.Fatalf("NewRequest small: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("small RoundTrip: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.StatusCode; got != http.StatusNoContent {
		t.Fatalf("small status=%d want 204", got)
	}
	select {
	case streamID := <-streamIDCh:
		if streamID != 1 {
			t.Fatalf("small request streamID=%d want 1; rejected request consumed a stream ID", streamID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive small request")
	}
}

func TestNativeHTTP2ReadDeadlineClosesSilentUpstream(t *testing.T) {
	rawURL := nativeHTTP2RawServerURL(t, func(_ *http2.Framer, _ uint32) {
		time.Sleep(500 * time.Millisecond)
	})
	rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
	}
	rt.headerWait = 50 * time.Millisecond
	defer rt.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	_, err = rt.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("RoundTrip err=%v want read timeout", err)
	}
}

func TestNativeHTTP2GoAwayBoundary(t *testing.T) {
	t.Run("oversized debug data", func(t *testing.T) {
		rawURL := nativeHTTP2RawServerURL(t, func(fr *http2.Framer, _ uint32) {
			if err := fr.WriteGoAway(0, http2.ErrCodeEnhanceYourCalm, bytes.Repeat([]byte("x"), nativeHTTP2MaxGoAwayDebugBytes+1)); err != nil {
				t.Errorf("WriteGoAway: %v", err)
			}
		})
		rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
		if err != nil {
			t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
		}
		defer rt.CloseIdleConnections()

		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		_, err = rt.RoundTrip(req)
		if err == nil || !strings.Contains(err.Error(), "GOAWAY debug data") {
			t.Fatalf("RoundTrip err=%v want oversized GOAWAY debug rejection", err)
		}
	})

	t.Run("increasing last stream id", func(t *testing.T) {
		rawURL := nativeHTTP2RawServerURL(t, func(fr *http2.Framer, streamID uint32) {
			if err := fr.WriteGoAway(streamID, http2.ErrCodeNo, nil); err != nil {
				t.Errorf("WriteGoAway first: %v", err)
				return
			}
			if err := fr.WriteGoAway(streamID+2, http2.ErrCodeNo, nil); err != nil {
				t.Errorf("WriteGoAway second: %v", err)
			}
		})
		rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
		if err != nil {
			t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
		}
		defer rt.CloseIdleConnections()

		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		_, err = rt.RoundTrip(req)
		if err == nil || !strings.Contains(err.Error(), "increased last_stream_id") {
			t.Fatalf("RoundTrip err=%v want increasing GOAWAY rejection", err)
		}
	})
}

func TestNativeHTTP2IdleStreamAndFrameSizeViolations(t *testing.T) {
	cases := []struct {
		name    string
		write   func(*testing.T, *http2.Framer, uint32)
		wantErr string
	}{
		{
			name: "even response headers",
			write: func(t *testing.T, fr *http2.Framer, _ uint32) {
				nativeHTTP2RawWriteHeaders(t, fr, 2, true, hpack.HeaderField{Name: ":status", Value: "200"})
			},
			wantErr: "HEADERS on even stream",
		},
		{
			name: "data on idle stream",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				if err := fr.WriteData(streamID+2, true, []byte("idle")); err != nil {
					t.Errorf("WriteData: %v", err)
				}
			},
			wantErr: "DATA on idle stream",
		},
		{
			name: "oversized unknown frame",
			write: func(t *testing.T, fr *http2.Framer, _ uint32) {
				if err := fr.WriteRawFrame(0xff, 0, 0, bytes.Repeat([]byte("x"), int(nativeHTTP2DefaultMaxFrameSize)+1)); err != nil {
					t.Errorf("WriteRawFrame: %v", err)
				}
			},
			wantErr: "frame length",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawURL := nativeHTTP2RawServerURL(t, func(fr *http2.Framer, streamID uint32) {
				tc.write(t, fr, streamID)
			})
			rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
			if err != nil {
				t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
			}
			defer rt.CloseIdleConnections()

			req, err := http.NewRequest(http.MethodGet, rawURL, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			_, err = rt.RoundTrip(req)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("RoundTrip err=%v want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNativeHTTP2RequestBoundaryRejection(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*http.Request)
		wantErr string
	}{
		{
			name: "empty method",
			mutate: func(req *http.Request) {
				req.Method = ""
			},
			wantErr: "invalid request method",
		},
		{
			name: "host header duplicate",
			mutate: func(req *http.Request) {
				req.Header.Set("Host", "evil.example")
			},
			wantErr: "duplicate HTTP/2 authority",
		},
		{
			name: "non ascii opaque path",
			mutate: func(req *http.Request) {
				req.URL = &url.URL{Scheme: "http", Host: req.URL.Host, Opaque: "//" + req.URL.Host + "/é"}
			},
			wantErr: "invalid upstream :path",
		},
		{
			name: "raw query newline",
			mutate: func(req *http.Request) {
				req.URL.RawQuery = "x=\n"
			},
			wantErr: "invalid upstream :path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nativeHTTP2AssertInvalidRequestDoesNotWriteHeaders(t, tc.mutate, tc.wantErr)
		})
	}
}

func nativeHTTP2RawServerURL(t *testing.T, writeResponse func(*http2.Framer, uint32)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fr := nativeHTTP2RawHandshake(t, conn)
		streamID := nativeHTTP2RawReadRequestStream(t, fr)
		writeResponse(fr, streamID)
	}()
	return "http://" + ln.Addr().String() + "/"
}

func nativeHTTP2RawHandshake(t *testing.T, conn net.Conn) *http2.Framer {
	return nativeHTTP2RawHandshakeWithSettings(t, conn)
}

func nativeHTTP2RawHandshakeWithSettings(t *testing.T, conn net.Conn, settings ...http2.Setting) *http2.Framer {
	t.Helper()
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		t.Errorf("read preface: %v", err)
		return http2.NewFramer(conn, conn)
	}
	if string(preface) != http2.ClientPreface {
		t.Errorf("preface=%q", string(preface))
		return http2.NewFramer(conn, conn)
	}
	fr := http2.NewFramer(conn, conn)
	frame, err := fr.ReadFrame()
	if err != nil {
		t.Errorf("read client settings: %v", err)
		return fr
	}
	if _, ok := frame.(*http2.SettingsFrame); !ok {
		t.Errorf("first frame=%T want SETTINGS", frame)
		return fr
	}
	if err := fr.WriteSettings(settings...); err != nil {
		t.Errorf("write settings: %v", err)
		return fr
	}
	if err := fr.WriteSettingsAck(); err != nil {
		t.Errorf("write settings ack: %v", err)
	}
	return fr
}

func nativeHTTP2RawReadRequestStream(t *testing.T, fr *http2.Framer) uint32 {
	t.Helper()
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Errorf("read request frame: %v", err)
			return 0
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			continue
		case *http2.WindowUpdateFrame:
			continue
		case *http2.HeadersFrame:
			return f.StreamID
		}
	}
}

func nativeHTTP2RoundTripBody(t *testing.T, rt http.RoundTripper, rawURL string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return body
}

func nativeHTTP2AssertInvalidRequestDoesNotWriteHeaders(t *testing.T, mutate func(*http.Request), wantErr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	streamIDCh := make(chan uint32, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		fr := nativeHTTP2RawHandshake(t, conn)
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		for {
			frame, err := fr.ReadFrame()
			if err != nil {
				_ = conn.Close()
				break
			}
			if _, ok := frame.(*http2.HeadersFrame); ok {
				t.Errorf("invalid request reached upstream as HEADERS on stream %d", frame.Header().StreamID)
				_ = conn.Close()
				return
			}
		}

		conn, err = ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fr = nativeHTTP2RawHandshake(t, conn)
		streamID := nativeHTTP2RawReadRequestStream(t, fr)
		streamIDCh <- streamID
		nativeHTTP2RawWriteHeaders(t, fr, streamID, true, hpack.HeaderField{Name: ":status", Value: "204"})
	}()

	rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{
		ResponseHeaderTimeout: 1,
	}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
	}
	defer rt.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/invalid", nil)
	if err != nil {
		t.Fatalf("NewRequest invalid: %v", err)
	}
	mutate(req)
	if resp, err := rt.RoundTrip(req); err == nil || !strings.Contains(err.Error(), wantErr) {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		t.Fatalf("invalid RoundTrip err=%v want %q", err, wantErr)
	}

	req, err = http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/small", nil)
	if err != nil {
		t.Fatalf("NewRequest small: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("small RoundTrip: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.StatusCode; got != http.StatusNoContent {
		t.Fatalf("small status=%d want 204", got)
	}
	select {
	case streamID := <-streamIDCh:
		if streamID != 1 {
			t.Fatalf("small request streamID=%d want 1; invalid request consumed a stream ID", streamID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive small request")
	}
}

func nativeHTTP2RawWriteHeaders(t *testing.T, fr *http2.Framer, streamID uint32, endStream bool, fields ...hpack.HeaderField) {
	t.Helper()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, field := range fields {
		if err := enc.WriteField(field); err != nil {
			t.Fatalf("encode header: %v", err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: block.Bytes(),
		EndStream:     endStream,
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
}
