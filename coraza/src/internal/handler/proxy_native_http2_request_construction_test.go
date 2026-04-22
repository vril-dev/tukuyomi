package handler

import (
	"net"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestNativeHTTP2RequestConstruction(t *testing.T) {
	t.Run("wire capture uses canonical pseudo headers and Request.Host authority", func(t *testing.T) {
		rawURL, captures := nativeHTTP2CaptureRequestServerURL(t)
		rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
		if err != nil {
			t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
		}
		defer rt.CloseIdleConnections()

		req, err := http.NewRequest(http.MethodPatch, rawURL+"api/items?q=1", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Host = "app.example:8443"
		req.Header.Set("X-Custom", "ok")
		req.Header.Set("TE", "trailers")

		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		_ = resp.Body.Close()

		capture := <-captures
		fields := nativeHTTP2FieldMap(capture.Fields)
		if fields[":method"] != http.MethodPatch {
			t.Fatalf(":method=%q want PATCH", fields[":method"])
		}
		if fields[":scheme"] != "http" {
			t.Fatalf(":scheme=%q want http", fields[":scheme"])
		}
		if fields[":authority"] != "app.example:8443" {
			t.Fatalf(":authority=%q want Request.Host override", fields[":authority"])
		}
		if fields[":path"] != "/api/items?q=1" {
			t.Fatalf(":path=%q want /api/items?q=1", fields[":path"])
		}
		if fields["x-custom"] != "ok" {
			t.Fatalf("x-custom=%q want ok", fields["x-custom"])
		}
		if fields["te"] != "trailers" {
			t.Fatalf("te=%q want trailers", fields["te"])
		}
	})

	invalid := []struct {
		name    string
		mutate  func(*http.Request)
		wantErr string
	}{
		{
			name: "method contains space",
			mutate: func(req *http.Request) {
				req.Method = "BAD METHOD"
			},
			wantErr: "invalid request method",
		},
		{
			name: "method contains control",
			mutate: func(req *http.Request) {
				req.Method = "GET\x00"
			},
			wantErr: "invalid request method",
		},
		{
			name: "path contains nul",
			mutate: func(req *http.Request) {
				req.URL.RawQuery = "x=\x00"
			},
			wantErr: "invalid upstream :path",
		},
		{
			name: "pseudo header injection",
			mutate: func(req *http.Request) {
				req.Header.Set(":path", "/evil")
			},
			wantErr: "invalid HTTP/2 request header",
		},
		{
			name: "keep-alive header rejected",
			mutate: func(req *http.Request) {
				req.Header.Set("Keep-Alive", "timeout=5")
			},
			wantErr: "forbidden HTTP/2 request header",
		},
		{
			name: "proxy-connection header rejected",
			mutate: func(req *http.Request) {
				req.Header.Set("Proxy-Connection", "keep-alive")
			},
			wantErr: "forbidden HTTP/2 request header",
		},
		{
			name: "transfer-encoding header rejected",
			mutate: func(req *http.Request) {
				req.Header.Set("Transfer-Encoding", "chunked")
			},
			wantErr: "forbidden HTTP/2 request header",
		},
		{
			name: "upgrade header rejected",
			mutate: func(req *http.Request) {
				req.Header.Set("Upgrade", "websocket")
			},
			wantErr: "forbidden HTTP/2 request header",
		},
		{
			name: "invalid TE value rejected",
			mutate: func(req *http.Request) {
				req.Header.Set("TE", "gzip")
			},
			wantErr: "forbidden HTTP/2 TE request value",
		},
		{
			name: "header value newline rejected",
			mutate: func(req *http.Request) {
				req.Header.Set("X-Bad", "a\nb")
			},
			wantErr: "invalid HTTP/2 request header value",
		},
		{
			name: "duplicate Host header rejected",
			mutate: func(req *http.Request) {
				req.Header.Set("Host", "other.example")
			},
			wantErr: "duplicate HTTP/2 authority",
		},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			nativeHTTP2AssertInvalidRequestDoesNotWriteHeaders(t, tc.mutate, tc.wantErr)
		})
	}

	t.Run("empty scheme rejected before connect", func(t *testing.T) {
		rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
		if err != nil {
			t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
		}
		defer rt.CloseIdleConnections()
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.URL.Scheme = ""
		if _, err := rt.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "requires http upstream") {
			t.Fatalf("RoundTrip err=%v want scheme rejection", err)
		}
	})

}

type nativeHTTP2RequestCapture struct {
	StreamID uint32
	Fields   []hpack.HeaderField
}

func nativeHTTP2CaptureRequestServerURL(t *testing.T) (string, <-chan nativeHTTP2RequestCapture) {
	t.Helper()
	captures := make(chan nativeHTTP2RequestCapture, 1)
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
		fr.ReadMetaHeaders = hpack.NewDecoder(nativeHTTP2MaxHeaderListBytes, nil)
		fr.MaxHeaderListSize = nativeHTTP2MaxHeaderListBytes
		var mh *http2.MetaHeadersFrame
		for mh == nil {
			frame, err := fr.ReadFrame()
			if err != nil {
				t.Errorf("read request frame: %v", err)
				return
			}
			switch f := frame.(type) {
			case *http2.MetaHeadersFrame:
				mh = f
			case *http2.SettingsFrame, *http2.WindowUpdateFrame:
				continue
			default:
				t.Errorf("unexpected request frame %T", frame)
				return
			}
		}
		fields := append([]hpack.HeaderField(nil), mh.Fields...)
		captures <- nativeHTTP2RequestCapture{StreamID: mh.StreamID, Fields: fields}
		nativeHTTP2RawWriteHeaders(t, fr, mh.StreamID, true, hpack.HeaderField{Name: ":status", Value: "204"})
	}()
	return "http://" + ln.Addr().String() + "/", captures
}

func nativeHTTP2FieldMap(fields []hpack.HeaderField) map[string]string {
	out := make(map[string]string, len(fields))
	for _, field := range fields {
		out[field.Name] = field.Value
	}
	return out
}
