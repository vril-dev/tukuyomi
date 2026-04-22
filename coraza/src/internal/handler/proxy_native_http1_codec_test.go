package handler

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestNativeHTTP1ParseRequestLine(t *testing.T) {
	valid := []struct {
		name   string
		line   string
		method string
		target string
		proto  string
	}{
		{name: "origin form", line: "GET /index.html?q=1 HTTP/1.1\r\n", method: "GET", target: "/index.html?q=1", proto: "HTTP/1.1"},
		{name: "absolute form", line: "GET http://example.com/a HTTP/1.1\r\n", method: "GET", target: "http://example.com/a", proto: "HTTP/1.1"},
		{name: "authority form", line: "CONNECT example.com:443 HTTP/1.1\r\n", method: "CONNECT", target: "example.com:443", proto: "HTTP/1.1"},
		{name: "asterisk form", line: "OPTIONS * HTTP/1.0\r\n", method: "OPTIONS", target: "*", proto: "HTTP/1.0"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			method, target, proto, err := nativeHTTP1ParseRequestLine([]byte(tc.line))
			if err != nil {
				t.Fatalf("nativeHTTP1ParseRequestLine: %v", err)
			}
			if string(method) != tc.method || string(target) != tc.target || string(proto) != tc.proto {
				t.Fatalf("got method=%q target=%q proto=%q", method, target, proto)
			}
		})
	}

	invalid := []string{
		"BAD METHOD / HTTP/1.1\r\n",
		"GET / HTTP/2.0\r\n",
		"GET http:// HTTP/1.1\r\n",
		"GET example.com:443 HTTP/1.1\r\n",
		"GET /bad\x00 HTTP/1.1\r\n",
	}
	for _, line := range invalid {
		t.Run("invalid", func(t *testing.T) {
			if _, _, _, err := nativeHTTP1ParseRequestLine([]byte(line)); err == nil {
				t.Fatalf("line %q parsed successfully", line)
			}
		})
	}
}

func TestNativeHTTP1BuildRequest(t *testing.T) {
	t.Run("content length", func(t *testing.T) {
		req := nativeHTTP1BuildRequestFromString(t, "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello")
		if req.Method != http.MethodPost || req.Host != "example.com" || req.URL.Path != "/submit" {
			t.Fatalf("unexpected request: method=%s host=%s path=%s", req.Method, req.Host, req.URL.Path)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if string(body) != "hello" || req.ContentLength != 5 {
			t.Fatalf("body=%q content_length=%d", string(body), req.ContentLength)
		}
	})

	t.Run("chunked with trailers and expect", func(t *testing.T) {
		req := nativeHTTP1BuildRequestFromString(t, "POST /chunk HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n5\r\nhello\r\n0\r\nX-Trailer: ok\r\n\r\n")
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if string(body) != "hello" {
			t.Fatalf("body=%q want hello", string(body))
		}
		if got := req.Header.Get("Expect"); got != "100-continue" {
			t.Fatalf("Expect=%q", got)
		}
		if len(req.TransferEncoding) != 1 || req.TransferEncoding[0] != "chunked" {
			t.Fatalf("TransferEncoding=%v", req.TransferEncoding)
		}
	})

	t.Run("tls and remote addr", func(t *testing.T) {
		tlsState := &tls.ConnectionState{ServerName: "example.com"}
		req, err := nativeHTTP1BuildRequest(
			bufio.NewReader(strings.NewReader("GET / HTTP/1.0\r\n\r\n")),
			nativeHTTP1MaxRequestHeaderBytes,
			&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
			tlsState,
		)
		if err != nil {
			t.Fatalf("nativeHTTP1BuildRequest: %v", err)
		}
		if req.RemoteAddr != "192.0.2.10:12345" || req.TLS != tlsState {
			t.Fatalf("remote=%q tls=%v", req.RemoteAddr, req.TLS)
		}
	})

	invalid := []struct {
		name string
		raw  string
	}{
		{name: "missing host", raw: "GET / HTTP/1.1\r\n\r\n"},
		{name: "conflicting host", raw: "GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n"},
		{name: "te cl conflict", raw: "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
		{name: "bad te", raw: "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip\r\n\r\n"},
		{name: "conflicting cl", raw: "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx"},
		{name: "folded header", raw: "GET / HTTP/1.1\r\nHost: example.com\r\n X-Folded: no\r\n\r\n"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := nativeHTTP1BuildRequest(bufio.NewReader(strings.NewReader(tc.raw)), nativeHTTP1MaxRequestHeaderBytes, nil, nil); err == nil {
				t.Fatal("nativeHTTP1BuildRequest succeeded; want error")
			}
		})
	}

	t.Run("oversized line", func(t *testing.T) {
		if _, err := nativeHTTP1BuildRequest(bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")), 8, nil, nil); err == nil {
			t.Fatal("nativeHTTP1BuildRequest succeeded; want header limit error")
		}
	})
}

func nativeHTTP1BuildRequestFromString(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := nativeHTTP1BuildRequest(bufio.NewReader(strings.NewReader(raw)), nativeHTTP1MaxRequestHeaderBytes, nil, nil)
	if err != nil {
		t.Fatalf("nativeHTTP1BuildRequest: %v", err)
	}
	return req
}
