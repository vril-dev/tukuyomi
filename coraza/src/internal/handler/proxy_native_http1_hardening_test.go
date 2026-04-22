package handler

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func FuzzNativeHTTP1ParseStatusLine(f *testing.F) {
	for _, seed := range []string{
		"HTTP/1.1 200 OK\r\n",
		"HTTP/1.1 200 \r\n",
		"HTTP/1.0 404 Not Found\r\n",
		"HTTP/1.1 101 Switching Protocols\r\n",
		"HTTP/1.1 999 Weird\r\n",
		"HTTP/2.0 200 OK\r\n",
		" HTTP/1.1 200 OK\r\n",
		"HTTP/1.1 abc Nope\r\n",
		"HTTP/1.1 200 OK\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		major, minor, code, _, err := nativeHTTP1ParseStatusLine(line)
		if err != nil {
			return
		}
		if major != 1 || (minor != 0 && minor != 1) {
			t.Fatalf("accepted unsupported version %d.%d for %q", major, minor, line)
		}
		if code < 100 || code > 999 {
			t.Fatalf("accepted invalid status code %d for %q", code, line)
		}
	})
}

func FuzzNativeHTTP1ReadHeaderBlock(f *testing.F) {
	for _, seed := range []string{
		"X-Test: ok\r\n\r\n",
		"X-Test: one\r\nX-Test: two\r\n\r\n",
		" Folded: no\r\n more\r\n\r\n",
		"Bad(Name): no\r\n\r\n",
		"X-Test: bad\x00value\r\n\r\n",
		"X-Test: lf-only\n\n",
		strings.Repeat("A", 1024) + ": ok\r\n\r\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			raw = raw[:4096]
		}
		header, err := nativeHTTP1ReadHeaderBlock(bufio.NewReader(strings.NewReader(raw)), 4096)
		if err != nil {
			return
		}
		for name, values := range header {
			if !nativeHTTP1SafeHeaderName(name) {
				t.Fatalf("accepted invalid header name %q", name)
			}
			for _, value := range values {
				if !nativeHTTP1SafeHeaderValue(value) {
					t.Fatalf("accepted invalid header value %q=%q", name, value)
				}
			}
		}
	})
}

func FuzzNativeHTTP1ChunkedRead(f *testing.F) {
	for _, seed := range []string{
		"2\r\nok\r\n0\r\n\r\n",
		"2;ext=value\r\nok\r\n0\r\nX-T: done\r\n\r\n",
		"A\r\n0123456789\r\n0\r\n\r\n",
		"ffffffffffffffff\r\n",
		"2\nok\n0\n\n",
		"2;bad\rvalue\r\nok\r\n0\r\n\r\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 8192 {
			raw = raw[:8192]
		}
		reader := &nativeHTTP1ChunkedReader{
			br:      bufio.NewReader(strings.NewReader(raw)),
			trailer: make(http.Header),
		}
		_, _ = io.CopyN(io.Discard, reader, 8192)
	})
}

func FuzzNativeHTTP1ReadResponse(f *testing.F) {
	for _, seed := range []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n2\r\nok\r\n0\r\nX-T: done\r\n\r\n",
		"HTTP/1.1 204 No Content\r\n\r\n",
		"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		"HTTP/1.1 200 OK\nContent-Length: 2\n\nok",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 8192 {
			raw = raw[:8192]
		}
		req := httptest.NewRequest(http.MethodGet, "http://backend.example/", nil)
		resp, err := nativeHTTP1ReadResponse(bufio.NewReader(strings.NewReader(raw)), req)
		if err != nil {
			return
		}
		if resp.StatusCode < 100 || resp.StatusCode > 999 {
			t.Fatalf("accepted invalid status code %d", resp.StatusCode)
		}
		if resp.ProtoMajor != 1 || (resp.ProtoMinor != 0 && resp.ProtoMinor != 1) {
			t.Fatalf("accepted invalid protocol %s", resp.Proto)
		}
	})
}

func FuzzNativeHTTP1WriteRequest(f *testing.F) {
	for _, seed := range []struct {
		method string
		host   string
		name   string
		value  string
	}{
		{http.MethodGet, "backend.example", "X-Test", "ok"},
		{"BAD METHOD", "backend.example", "X-Test", "ok"},
		{http.MethodGet, "bad\r\nhost", "X-Test", "ok"},
		{http.MethodGet, "backend.example", "Bad(Name)", "ok"},
		{http.MethodGet, "backend.example", "X-Test", "bad\r\nvalue"},
	} {
		f.Add(seed.method, seed.host, seed.name, seed.value)
	}
	f.Fuzz(func(t *testing.T, method string, host string, name string, value string) {
		req := httptest.NewRequest(http.MethodGet, "http://backend.example/path?q=1", nil)
		req.Method = method
		req.Host = host
		req.Header.Set(name, value)
		var out bytes.Buffer
		err := nativeHTTP1WriteRequest(&out, req)
		if err != nil {
			return
		}
		raw := out.String()
		if strings.Contains(raw, "\r\n\r\n\r\n") {
			t.Fatalf("serialized unexpected blank header injection: %q", raw)
		}
		if strings.Contains(raw, "\nX-Injected:") || strings.Contains(raw, "\rX-Injected:") {
			t.Fatalf("serialized injected header: %q", raw)
		}
	})
}

func TestNativeHTTP1WriteRequestSerializationHardening(t *testing.T) {
	t.Run("post content length", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://backend.example/submit?q=1", strings.NewReader("abc"))
		req.Host = "app.example"
		req.Header.Set("Content-Length", "999")
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("X-Test", "ok")
		req.ContentLength = 3
		var out bytes.Buffer
		if err := nativeHTTP1WriteRequest(&out, req); err != nil {
			t.Fatalf("nativeHTTP1WriteRequest: %v", err)
		}
		got := out.String()
		want := "POST /submit?q=1 HTTP/1.1\r\nHost: app.example\r\nX-Test: ok\r\nContent-Length: 3\r\n\r\nabc"
		if got != want {
			t.Fatalf("wire mismatch\ngot  %q\nwant %q", got, want)
		}
	})

	t.Run("unknown length chunked with trailer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://backend.example/chunked", io.NopCloser(strings.NewReader("hello")))
		req.ContentLength = -1
		req.Trailer = http.Header{"X-Trailer": []string{"done"}}
		var out bytes.Buffer
		if err := nativeHTTP1WriteRequest(&out, req); err != nil {
			t.Fatalf("nativeHTTP1WriteRequest: %v", err)
		}
		got := out.String()
		if !strings.Contains(got, "Transfer-Encoding: chunked\r\n\r\n") {
			t.Fatalf("missing generated chunked framing: %q", got)
		}
		if !strings.Contains(got, "\r\n0\r\nX-Trailer: done\r\n\r\n") {
			t.Fatalf("missing generated trailer: %q", got)
		}
	})

	t.Run("upgrade does not add close", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend.example/ws", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Close = true
		var out bytes.Buffer
		if err := nativeHTTP1WriteRequest(&out, req); err != nil {
			t.Fatalf("nativeHTTP1WriteRequest: %v", err)
		}
		got := out.String()
		if strings.Contains(got, "Connection: close\r\n") {
			t.Fatalf("upgrade request emitted close: %q", got)
		}
		if !strings.Contains(got, "Connection: Upgrade\r\n") || !strings.Contains(got, "Upgrade: websocket\r\n") {
			t.Fatalf("upgrade headers missing: %q", got)
		}
	})

	rejects := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"bad method", func(r *http.Request) { r.Method = "BAD METHOD" }},
		{"bad host crlf", func(r *http.Request) { r.Host = "backend.example\r\nX-Injected: 1" }},
		{"bad host blank", func(r *http.Request) {
			r.Host = ""
			r.URL.Host = ""
		}},
		{"bad header name", func(r *http.Request) { r.Header.Set("Bad(Name)", "x") }},
		{"bad header value", func(r *http.Request) { r.Header.Set("X-Test", "ok\r\nX-Injected: 1") }},
		{"bad trailer name", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("x"))
			r.ContentLength = -1
			r.Trailer = http.Header{"Bad(Name)": []string{"x"}}
		}},
		{"bad trailer value", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("x"))
			r.ContentLength = -1
			r.Trailer = http.Header{"X-Trailer": []string{"ok\r\nX-Injected: 1"}}
		}},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://backend.example/path", nil)
			tc.mutate(req)
			if err := nativeHTTP1WriteRequest(io.Discard, req); err == nil {
				t.Fatal("nativeHTTP1WriteRequest accepted invalid request")
			}
		})
	}
}

func TestNativeHTTP1WriteRequestPreflightRejectsBeforeWrite(t *testing.T) {
	rejects := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"bad method", func(r *http.Request) { r.Method = "BAD METHOD" }},
		{"bad host", func(r *http.Request) { r.Host = "backend.example\r\nX-Injected: 1" }},
		{"bad header after large header", func(r *http.Request) {
			r.Header.Set("X-Large", strings.Repeat("a", 8192))
			r.Header.Set("Bad(Name)", "x")
		}},
		{"bad trailer after body", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("body"))
			r.ContentLength = -1
			r.Trailer = http.Header{"X-Trailer": []string{"ok\r\nX-Injected: 1"}}
		}},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://backend.example/path", nil)
			tc.mutate(req)
			var out bytes.Buffer
			err := nativeHTTP1WriteRequest(&out, req)
			if err == nil {
				t.Fatal("nativeHTTP1WriteRequest accepted invalid request")
			}
			if out.Len() != 0 {
				t.Fatalf("wrote partial request before validation failed: %q", out.String())
			}
		})
	}
}

func TestTukuyomiProxyUpgradeResponsePreflightRejectsBeforeWrite(t *testing.T) {
	rejects := []struct {
		name string
		res  *http.Response
	}{
		{
			name: "bad header after large header",
			res: &http.Response{
				StatusCode: http.StatusSwitchingProtocols,
				Proto:      "HTTP/1.1",
				Header: http.Header{
					"Connection": []string{"Upgrade"},
					"Upgrade":    []string{"websocket"},
					"X-Large":    []string{strings.Repeat("a", 8192)},
					"X-Bad":      []string{"ok\r\nX-Injected: 1"},
				},
			},
		},
		{
			name: "bad proto",
			res: &http.Response{
				StatusCode: http.StatusSwitchingProtocols,
				Proto:      "HTTP/2.0",
				Header: http.Header{
					"Connection": []string{"Upgrade"},
					"Upgrade":    []string{"websocket"},
				},
			},
		},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := writeTukuyomiProxyUpgradeResponse(&out, tc.res, "websocket")
			if err == nil {
				t.Fatal("writeTukuyomiProxyUpgradeResponse accepted invalid response")
			}
			if out.Len() != 0 {
				t.Fatalf("wrote partial upgrade response before validation failed: %q", out.String())
			}
		})
	}
}

type nativeHTTP1DifferentialCapture struct {
	StatusCode       int
	Status           string
	Header           http.Header
	Body             string
	Trailer          http.Header
	Close            bool
	ContentLength    int64
	TransferEncoding []string
	BodyReadWrite    bool
}

func TestNativeHTTP1Differential(t *testing.T) {
	cases := []struct {
		name   string
		script string
		mutate func(*http.Request)
	}{
		{
			name:   "content length",
			script: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: ok\r\n\r\nok",
		},
		{
			name:   "chunked trailer",
			script: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n2\r\nok\r\n0\r\nX-T: done\r\n\r\n",
		},
		{
			name:   "204 no body",
			script: "HTTP/1.1 204 No Content\r\n\r\n",
		},
		{
			name:   "304 no body",
			script: "HTTP/1.1 304 Not Modified\r\n\r\n",
		},
		{
			name:   "connection close body",
			script: "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbye",
		},
		{
			name:   "empty reason",
			script: "HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n",
		},
		{
			name:   "101 upgrade",
			script: "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ok\r\n\r\n",
			mutate: func(r *http.Request) {
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stock, err := nativeHTTP1RunScriptRoundTrip(t, tc.script, false, tc.mutate)
			if err != nil {
				t.Fatalf("stock transport: %v", err)
			}
			native, err := nativeHTTP1RunScriptRoundTrip(t, tc.script, true, tc.mutate)
			if err != nil {
				t.Fatalf("native transport: %v", err)
			}
			if !reflect.DeepEqual(native, stock) {
				t.Fatalf("native response differs\nnative=%#v\nstock =%#v", native, stock)
			}
		})
	}
}

func TestNativeHTTP1Smuggling(t *testing.T) {
	parserRejects := []struct {
		name string
		raw  string
	}{
		{"te cl", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
		{"conflicting cl", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nok"},
		{"unsupported te", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"},
		{"duplicate chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n"},
		{"lf only", "HTTP/1.1 200 OK\nContent-Length: 2\n\nok"},
		{"obs fold", "HTTP/1.1 200 OK\r\nX-Test: ok\r\n folded\r\n\r\n"},
		{"bad header name", "HTTP/1.1 200 OK\r\nBad(Name): x\r\n\r\n"},
		{"bad header value nul", "HTTP/1.1 200 OK\r\nX-Test: bad\x00value\r\n\r\n"},
	}
	for _, tc := range parserRejects {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://backend.example/", nil)
			if _, err := nativeHTTP1ReadResponse(bufio.NewReader(strings.NewReader(tc.raw)), req); err == nil {
				t.Fatal("nativeHTTP1ReadResponse accepted ambiguous response")
			}
		})
	}

	t.Run("matching duplicate content length", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://backend.example/", nil)
		resp, err := nativeHTTP1ReadResponse(bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok")), req)
		if err != nil {
			t.Fatalf("matching duplicate CL rejected: %v", err)
		}
		if resp.ContentLength != 2 {
			t.Fatalf("ContentLength=%d want 2", resp.ContentLength)
		}
	})

	bodyRejects := []struct {
		name string
		raw  string
	}{
		{"oversized chunk line", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + strings.Repeat("1", nativeHTTP1MaxChunkLineBytes+1) + "\r\n"},
		{"chunk extension cr", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;bad\rvalue\r\nok\r\n0\r\n\r\n"},
	}
	for _, tc := range bodyRejects {
		t.Run(tc.name, func(t *testing.T) {
			resp, rt, err := nativeHTTP1RoundTripRawScript(t, tc.raw, nil, nil)
			if err != nil {
				t.Fatalf("RoundTrip setup failed before body read: %v", err)
			}
			if _, err := io.ReadAll(resp.Body); err == nil {
				t.Fatal("body read accepted malformed chunked response")
			}
			_ = resp.Body.Close()
			nativeHTTP1AssertPoolEmpty(t, rt)
		})
	}
}

func TestTukuyomiProxyUpgradeAdversarial(t *testing.T) {
	rejects := []struct {
		name string
		res  *http.Response
		up   string
	}{
		{
			name: "non 101",
			up:   "websocket",
			res:  &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1", Header: http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}}},
		},
		{
			name: "empty upgrade type",
			up:   "",
			res:  &http.Response{StatusCode: http.StatusSwitchingProtocols, Status: "101 Switching Protocols", Proto: "HTTP/1.1", Header: http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}}},
		},
		{
			name: "content length on 101",
			up:   "websocket",
			res:  &http.Response{StatusCode: http.StatusSwitchingProtocols, Status: "101 Switching Protocols", Proto: "HTTP/1.1", Header: http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}, "Content-Length": []string{"1"}}},
		},
		{
			name: "transfer encoding on 101",
			up:   "websocket",
			res:  &http.Response{StatusCode: http.StatusSwitchingProtocols, Status: "101 Switching Protocols", Proto: "HTTP/1.1", Header: http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}, "Transfer-Encoding": []string{"chunked"}}},
		},
		{
			name: "header injection",
			up:   "websocket",
			res:  &http.Response{StatusCode: http.StatusSwitchingProtocols, Status: "101 Switching Protocols", Proto: "HTTP/1.1", Header: http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}, "X-Test": []string{"ok\r\nX-Injected: 1"}}},
		},
		{
			name: "bad proto",
			up:   "websocket",
			res:  &http.Response{StatusCode: http.StatusSwitchingProtocols, Status: "101 Switching Protocols", Proto: "HTTP/2.0", Header: http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}}},
		},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeTukuyomiProxyUpgradeResponse(&out, tc.res, tc.up); err == nil {
				t.Fatalf("writeTukuyomiProxyUpgradeResponse accepted adversarial response: %q", out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("wrote partial bytes before rejecting: %q", out.String())
			}
		})
	}
}

func TestNativeHTTP1MalformedUpstream(t *testing.T) {
	t.Run("oversized trailer", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Big\r\n\r\n0\r\nX-Big: " + strings.Repeat("a", nativeHTTP1MaxTrailerBytes) + "\r\n\r\n"
		resp, rt, err := nativeHTTP1RoundTripRawScript(t, raw, nil, nil)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if _, err := io.ReadAll(resp.Body); err == nil {
			t.Fatal("accepted oversized trailer")
		}
		_ = resp.Body.Close()
		nativeHTTP1AssertPoolEmpty(t, rt)
	})

	premature := []struct {
		name string
		raw  string
	}{
		{"status line", "HTTP/1.1"},
		{"header block", "HTTP/1.1 200 OK\r\nContent-Length: 2"},
		{"chunk size", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"},
		{"chunk body", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nab"},
		{"trailer block", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: done"},
	}
	for _, tc := range premature {
		t.Run("premature "+tc.name, func(t *testing.T) {
			resp, rt, err := nativeHTTP1RoundTripRawScript(t, tc.raw, nil, nil)
			if err == nil {
				_, err = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
			}
			if err == nil {
				t.Fatal("accepted premature upstream close")
			}
			nativeHTTP1AssertPoolEmpty(t, rt)
		})
	}

	t.Run("invalid chunk size", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nnot-hex\r\n"
		resp, rt, err := nativeHTTP1RoundTripRawScript(t, raw, nil, nil)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if _, err := io.ReadAll(resp.Body); err == nil {
			t.Fatal("accepted invalid chunk size")
		}
		_ = resp.Body.Close()
		nativeHTTP1AssertPoolEmpty(t, rt)
	})

	t.Run("slow drip honors context", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		rt := nativeHTTP1NewTestTransport(t)
		defer rt.CloseIdleConnections()
		_, err := nativeHTTP1RoundTripWithRawServer(t, rt, func(conn net.Conn) {
			for _, b := range []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") {
				_, _ = conn.Write([]byte{b})
				time.Sleep(25 * time.Millisecond)
			}
		}, func(req *http.Request) {
			*req = *req.WithContext(ctx)
		})
		if err == nil {
			t.Fatal("slow drip response completed despite request context timeout")
		}
		nativeHTTP1AssertPoolEmpty(t, rt)
	})
}

func nativeHTTP1RunScriptRoundTrip(t *testing.T, script string, native bool, mutate func(*http.Request)) (nativeHTTP1DifferentialCapture, error) {
	t.Helper()
	if native {
		rt := nativeHTTP1NewTestTransport(t)
		defer rt.CloseIdleConnections()
		resp, err := nativeHTTP1RoundTripWithRawServer(t, rt, func(conn net.Conn) {
			_, _ = io.WriteString(conn, script)
		}, mutate)
		if err != nil {
			return nativeHTTP1DifferentialCapture{}, err
		}
		return nativeHTTP1CaptureResponse(resp)
	}

	tr := &http.Transport{DisableKeepAlives: true, ForceAttemptHTTP2: false}
	defer tr.CloseIdleConnections()
	resp, err := nativeHTTP1RoundTripWithRoundTripper(t, tr, func(conn net.Conn) {
		_, _ = io.WriteString(conn, script)
	}, mutate)
	if err != nil {
		return nativeHTTP1DifferentialCapture{}, err
	}
	return nativeHTTP1CaptureResponse(resp)
}

func nativeHTTP1RoundTripRawScript(t *testing.T, script string, mutate func(*http.Request), cfg *ProxyRulesConfig) (*http.Response, *nativeHTTP1Transport, error) {
	t.Helper()
	rt := nativeHTTP1NewTestTransport(t)
	if cfg != nil {
		var err error
		rt, err = buildProxyNativeHTTP1Transport(normalizeProxyRulesConfig(*cfg), proxyTransportProfile{})
		if err != nil {
			t.Fatalf("buildProxyNativeHTTP1Transport: %v", err)
		}
	}
	resp, err := nativeHTTP1RoundTripWithRawServer(t, rt, func(conn net.Conn) {
		_, _ = io.WriteString(conn, script)
	}, mutate)
	return resp, rt, err
}

func nativeHTTP1RoundTripWithRawServer(t *testing.T, rt *nativeHTTP1Transport, write func(net.Conn), mutate func(*http.Request)) (*http.Response, error) {
	t.Helper()
	return nativeHTTP1RoundTripWithRoundTripper(t, rt, write, mutate)
}

func nativeHTTP1RoundTripWithRoundTripper(t *testing.T, rt http.RoundTripper, write func(net.Conn), mutate func(*http.Request)) (*http.Response, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw upstream: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		write(conn)
	}()
	defer func() {
		_ = ln.Close()
		<-done
	}()

	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/demo?q=1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if mutate != nil {
		mutate(req)
	}
	return rt.RoundTrip(req)
}

func nativeHTTP1CaptureResponse(resp *http.Response) (nativeHTTP1DifferentialCapture, error) {
	defer resp.Body.Close()
	cap := nativeHTTP1DifferentialCapture{
		StatusCode:       resp.StatusCode,
		Status:           resp.Status,
		Header:           cloneProxyHeader(resp.Header),
		Trailer:          make(http.Header),
		Close:            resp.Close,
		ContentLength:    resp.ContentLength,
		TransferEncoding: append([]string(nil), resp.TransferEncoding...),
	}
	if _, ok := resp.Body.(io.ReadWriteCloser); ok {
		cap.BodyReadWrite = true
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return cap, err
		}
		cap.Body = string(body)
	}
	cap.Trailer = cloneProxyHeader(resp.Trailer)
	return cap, nil
}

func nativeHTTP1NewTestTransport(t *testing.T) *nativeHTTP1Transport {
	t.Helper()
	rt, err := buildProxyNativeHTTP1Transport(normalizeProxyRulesConfig(ProxyRulesConfig{
		DialTimeout:           1,
		ResponseHeaderTimeout: 1,
		IdleConnTimeout:       1,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       10,
	}), proxyTransportProfile{})
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP1Transport: %v", err)
	}
	return rt
}

func nativeHTTP1AssertPoolEmpty(t *testing.T, rt *nativeHTTP1Transport) {
	t.Helper()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.totalIdle != 0 || len(rt.idle) != 0 || len(rt.active) != 0 || len(rt.waiters) != 0 {
		t.Fatalf("pool not empty: totalIdle=%d idle=%d active=%d waiters=%d", rt.totalIdle, len(rt.idle), len(rt.active), len(rt.waiters))
	}
}
