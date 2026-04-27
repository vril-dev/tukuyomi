package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/net/http2/hpack"
)

func TestNativeHTTP2Differential(t *testing.T) {
	upstream := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cl":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "2")
			_, _ = w.Write([]byte("ok"))
		case "/post-trailer":
			body, _ := io.ReadAll(r.Body)
			if string(body) != "payload" || r.Trailer.Get("X-Client-Trailer") != "done" {
				http.Error(w, "bad request trailer", http.StatusBadRequest)
				return
			}
			w.Header().Set("Trailer", "X-Upstream-Trailer")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("posted"))
			w.Header().Set("X-Upstream-Trailer", "ok")
		case "/stream":
			w.Header().Set("Content-Type", "text/plain")
			flusher, _ := w.(http.Flusher)
			for _, part := range []string{"a", "b", "c"} {
				_, _ = w.Write([]byte(part))
				if flusher != nil {
					flusher.Flush()
				}
			}
		case "/nocontent":
			w.WriteHeader(http.StatusNoContent)
		case "/flow":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(bytes.Repeat([]byte("z"), 96<<10))
		default:
			http.NotFound(w, r)
		}
	}), &http2.Server{}))
	defer upstream.Close()

	nativeRT, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
	}
	defer nativeRT.CloseIdleConnections()
	stockRT := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, addr)
		},
	}
	defer stockRT.CloseIdleConnections()

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		mutate func(*http.Request)
	}{
		{name: "get content length", method: http.MethodGet, path: "/cl"},
		{
			name:   "post trailers",
			method: http.MethodPost,
			path:   "/post-trailer",
			body:   "payload",
			mutate: func(req *http.Request) {
				req.Trailer = http.Header{"X-Client-Trailer": []string{"done"}}
			},
		},
		{name: "streaming", method: http.MethodGet, path: "/stream"},
		{name: "no content", method: http.MethodGet, path: "/nocontent"},
		{name: "flow body", method: http.MethodGet, path: "/flow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stock := nativeHTTP2DifferentialRoundTrip(t, stockRT, tc.method, upstream.URL+tc.path, tc.body, tc.mutate)
			native := nativeHTTP2DifferentialRoundTrip(t, nativeRT, tc.method, upstream.URL+tc.path, tc.body, tc.mutate)
			if !reflect.DeepEqual(native, stock) {
				t.Fatalf("differential mismatch\nstock:  %#v\nnative: %#v", stock, native)
			}
		})
	}
}

func FuzzNativeHTTP2FrameReader(f *testing.F) {
	for _, seed := range [][]byte{
		nativeHTTP2FuzzFrame(http2.FrameSettings, 0, 0, []byte{}),
		nativeHTTP2FuzzFrame(http2.FrameSettings, 0, 0, []byte{0, 1, 0}),
		nativeHTTP2FuzzFrame(http2.FrameWindowUpdate, 0, 0, []byte{0, 0, 0, 0}),
		nativeHTTP2FuzzFrame(http2.FrameRSTStream, 0, 1, []byte{0, 0, 0, byte(http2.ErrCodeCancel)}),
		nativeHTTP2FuzzFrame(http2.FrameGoAway, 0, 0, []byte{0, 0, 0, 1, 0, 0, 0, byte(http2.ErrCodeNo), 'd', 'b', 'g'}),
		nativeHTTP2FuzzFrame(0xff, 0, 0, []byte("unknown")),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			raw = raw[:64<<10]
		}
		fr := http2.NewFramer(io.Discard, bytes.NewReader(raw))
		fr.ReadMetaHeaders = hpack.NewDecoder(nativeHTTP2MaxHeaderListBytes, nil)
		fr.MaxHeaderListSize = nativeHTTP2MaxHeaderListBytes
		fr.SetMaxReadFrameSize(nativeHTTP2MaxFrameSizeLimit)
		req := httptest.NewRequest(http.MethodGet, "http://backend.example/", nil)
		for i := 0; i < 128; i++ {
			frame, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if mh, ok := frame.(*http2.MetaHeadersFrame); ok {
				_, _, _ = nativeHTTP2DecodeResponseHeaders(mh, req)
				_, _ = nativeHTTP2DecodeTrailers(mh)
			}
		}
	})
}

type nativeHTTP2DifferentialCapture struct {
	StatusCode    int
	ContentLength int64
	Header        [][2]string
	Body          string
	Trailer       [][2]string
	Err           string
}

func nativeHTTP2DifferentialRoundTrip(t *testing.T, rt http.RoundTripper, method string, rawURL string, body string, mutate func(*http.Request)) nativeHTTP2DifferentialCapture {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != "" {
		req.ContentLength = int64(len(body))
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nativeHTTP2DifferentialCapture{Err: nativeHTTP2NormalizeError(err)}
	}
	defer resp.Body.Close()
	rawBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		err = readErr
	}
	return nativeHTTP2DifferentialCapture{
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		Header:        nativeHTTP2CanonicalHeaderPairs(resp.Header),
		Body:          string(rawBody),
		Trailer:       nativeHTTP2CanonicalHeaderPairs(resp.Trailer),
		Err:           nativeHTTP2NormalizeError(err),
	}
}

func nativeHTTP2NormalizeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "context canceled") {
		return "context canceled"
	}
	if strings.Contains(msg, "Content-Length") {
		return "content-length"
	}
	return msg
}

func nativeHTTP2CanonicalHeaderPairs(header http.Header) [][2]string {
	out := make([][2]string, 0, len(header))
	for name, values := range header {
		if strings.EqualFold(name, "Date") {
			continue
		}
		canonical := http.CanonicalHeaderKey(name)
		copied := append([]string(nil), values...)
		sort.Strings(copied)
		out = append(out, [2]string{canonical, strings.Join(copied, "\x00")})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] == out[j][0] {
			return out[i][1] < out[j][1]
		}
		return out[i][0] < out[j][0]
	})
	return out
}

func FuzzNativeHTTP2HPACKDecode(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		nativeHTTP2FuzzHPACK(
			hpack.HeaderField{Name: ":status", Value: "200"},
			hpack.HeaderField{Name: "content-type", Value: "text/plain"},
		),
		nativeHTTP2FuzzHPACK(
			hpack.HeaderField{Name: ":status", Value: "200"},
			hpack.HeaderField{Name: "set-cookie", Value: "a=b"},
			hpack.HeaderField{Name: "set-cookie", Value: "c=d"},
		),
		{0x3f, 0xe1, 0x1f},
		bytes.Repeat([]byte{0x80}, 128),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			raw = raw[:64<<10]
		}
		var fields []hpack.HeaderField
		dec := hpack.NewDecoder(4096, func(field hpack.HeaderField) {
			if len(fields) < 4096 {
				fields = append(fields, field)
			}
		})
		dec.SetMaxStringLength(8192)
		dec.SetAllowedMaxDynamicTableSize(4096)
		_, _ = dec.Write(raw)
	})
}

func FuzzNativeHTTP2StreamState(f *testing.F) {
	for _, seed := range [][]byte{
		{0, 5, 1, 5, 2},
		{0, 0, 2},
		{1, 1, 2, 4},
		{0, 3, 1, 4, 2},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, script []byte) {
		if len(script) > 1024 {
			script = script[:1024]
		}
		st := &nativeHTTP2Stream{
			id:     1,
			req:    httptest.NewRequest(http.MethodGet, "http://backend.example/", nil),
			done:   make(chan struct{}),
			bodyCh: make(chan nativeHTTP2BodyEvent, nativeHTTP2BodyEventBuffer),
		}
		for i := 0; i < len(script); i++ {
			switch script[i] % 6 {
			case 0:
				length := int64(-1)
				if i+1 < len(script) {
					i++
					length = int64(script[i])
				}
				st.markResponseStarted(&http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: length,
					Request:       st.req,
				})
			case 1:
				_ = st.acceptData(int(script[i]%31) + 1)
			case 2:
				_ = st.validateEndStream()
				st.markRemoteClosed()
			case 3:
				st.markLocalClosed()
			case 4:
				st.setTerminalError(nativeHTTP2StreamError{StreamID: st.id, Code: http2.ErrCodeCancel})
			case 5:
				st.mergeTrailers(http.Header{"X-Fuzz": []string{"ok"}})
			}
			if st.state > nativeHTTP2StreamReset {
				t.Fatalf("illegal stream state %d", st.state)
			}
		}
	})
}

func FuzzNativeHTTP2FlowControlAccounting(f *testing.F) {
	for _, seed := range [][]byte{
		{2, 10, 2, 10, 0, 5},
		{0, 255, 1, 255, 2, 1},
		{2, 255, 2, 255, 2, 255},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, script []byte) {
		if len(script) > 1024 {
			script = script[:1024]
		}
		s := &nativeHTTP2Session{
			done:                make(chan struct{}),
			streams:             make(map[uint32]*nativeHTTP2Stream),
			remoteMaxFrameSize:  nativeHTTP2DefaultMaxFrameSize,
			remoteInitialWindow: nativeHTTP2InitialWindowSize,
			connSendWindow:      nativeHTTP2InitialWindowSize,
			windowNotify:        make(chan struct{}),
		}
		st := &nativeHTTP2Stream{id: 1, sendWindow: nativeHTTP2InitialWindowSize, done: make(chan struct{})}
		s.streams[st.id] = st
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		for i := 0; i+1 < len(script); i += 2 {
			op := script[i] % 3
			n := int(script[i+1]) + 1
			switch op {
			case 0:
				s.mu.Lock()
				if s.connSendWindow+int64(n) <= 1<<31-1 {
					s.connSendWindow += int64(n)
					s.notifyWindowLocked()
				}
				s.mu.Unlock()
			case 1:
				s.mu.Lock()
				if st.sendWindow+int64(n) <= 1<<31-1 {
					st.sendWindow += int64(n)
					s.notifyWindowLocked()
				}
				s.mu.Unlock()
			case 2:
				s.mu.Lock()
				canReserve := s.connSendWindow > 0 && st.sendWindow > 0
				s.mu.Unlock()
				if canReserve {
					_, _ = s.reserveSendWindow(ctx, st, n)
				}
			}
			s.mu.Lock()
			connWindow := s.connSendWindow
			streamWindow := st.sendWindow
			s.mu.Unlock()
			if connWindow < 0 || streamWindow < 0 {
				t.Fatalf("negative windows conn=%d stream=%d", connWindow, streamWindow)
			}
			if connWindow > 1<<31-1 || streamWindow > 1<<31-1 {
				t.Fatalf("overflow windows conn=%d stream=%d", connWindow, streamWindow)
			}
		}
	})
}

func nativeHTTP2FuzzFrame(typ http2.FrameType, flags http2.Flags, streamID uint32, payload []byte) []byte {
	out := make([]byte, 9+len(payload))
	out[0] = byte(len(payload) >> 16)
	out[1] = byte(len(payload) >> 8)
	out[2] = byte(len(payload))
	out[3] = byte(typ)
	out[4] = byte(flags)
	binary.BigEndian.PutUint32(out[5:9], streamID&0x7fffffff)
	copy(out[9:], payload)
	return out
}

func nativeHTTP2FuzzHPACK(fields ...hpack.HeaderField) []byte {
	var out bytes.Buffer
	enc := hpack.NewEncoder(&out)
	for _, field := range fields {
		_ = enc.WriteField(field)
	}
	return out.Bytes()
}
