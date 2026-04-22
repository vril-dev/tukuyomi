package handler

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestNativeHTTP2ProtocolViolation is the adversarial H2 taxonomy for hostile
// upstream framing. Each case documents whether the proxy must fail the stream
// or close the session according to RFC 9113 section 5.4.
func TestNativeHTTP2ProtocolViolation(t *testing.T) {
	t.Run("DATA on half-closed remote stream fails stream", func(t *testing.T) {
		s := &nativeHTTP2Session{
			streams:      make(map[uint32]*nativeHTTP2Stream),
			done:         make(chan struct{}),
			windowNotify: make(chan struct{}),
		}
		st := &nativeHTTP2Stream{
			session: s,
			id:      1,
			req:     httptest.NewRequest(http.MethodGet, "http://backend.example/", nil),
			state:   nativeHTTP2StreamHalfClosedRemote,
			done:    make(chan struct{}),
			errCh:   make(chan error, 1),
			bodyCh:  make(chan nativeHTTP2BodyEvent, 1),
		}
		st.markResponseStarted(&http.Response{StatusCode: http.StatusOK, Request: st.req})
		st.markRemoteClosed()
		s.streams[st.id] = st
		s.nextStreamID = 3
		s.activeStreams = 1

		err := s.handleData(&http2.DataFrame{FrameHeader: http2.FrameHeader{StreamID: st.id}})
		if err != nil {
			t.Fatalf("handleData returned connection error: %v", err)
		}
		select {
		case got := <-st.errCh:
			if got == nil || !strings.Contains(got.Error(), "DATA after remote close") {
				t.Fatalf("stream err=%v want DATA after remote close", got)
			}
		default:
			t.Fatal("stream was not failed for DATA after remote close")
		}
	})

	t.Run("HEADERS after trailers fails stream", func(t *testing.T) {
		s := &nativeHTTP2Session{
			streams:      make(map[uint32]*nativeHTTP2Stream),
			done:         make(chan struct{}),
			windowNotify: make(chan struct{}),
		}
		st := &nativeHTTP2Stream{
			session: s,
			id:      1,
			req:     httptest.NewRequest(http.MethodGet, "http://backend.example/", nil),
			state:   nativeHTTP2StreamHalfClosedRemote,
			done:    make(chan struct{}),
			errCh:   make(chan error, 1),
			bodyCh:  make(chan nativeHTTP2BodyEvent, 1),
		}
		st.markResponseStarted(&http.Response{StatusCode: http.StatusOK, Request: st.req})
		if err := st.markTrailers(http.Header{"X-Trailer": []string{"one"}}); err != nil {
			t.Fatalf("markTrailers: %v", err)
		}
		s.streams[st.id] = st
		s.nextStreamID = 3
		s.activeStreams = 1

		err := s.handleMetaHeaders(&http2.MetaHeadersFrame{
			HeadersFrame: &http2.HeadersFrame{FrameHeader: http2.FrameHeader{StreamID: st.id, Flags: http2.FlagHeadersEndStream}},
			Fields:       []hpack.HeaderField{{Name: "x-trailer", Value: "two"}},
		})
		if err != nil {
			t.Fatalf("handleMetaHeaders returned connection error: %v", err)
		}
		select {
		case got := <-st.errCh:
			if got == nil || !strings.Contains(got.Error(), "HEADERS after trailers") {
				t.Fatalf("stream err=%v want HEADERS after trailers", got)
			}
		default:
			t.Fatal("stream was not failed for HEADERS after trailers")
		}
	})

	cases := []struct {
		name    string
		write   func(*testing.T, *http2.Framer, uint32)
		wantErr string
	}{
		{
			name: "HPACK/header-list bomb closes session",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				nativeHTTP2RawWriteHeaderBlock(t, fr, streamID, true, nativeHTTP2BombHeaderFields()...)
			},
			wantErr: "headers exceed limit",
		},
		{
			name: "CONTINUATION flood without END_HEADERS times out",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				if err := fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      streamID,
					BlockFragment: []byte{0x88},
					EndHeaders:    false,
				}); err != nil {
					t.Errorf("WriteHeaders: %v", err)
					return
				}
				for i := 0; i < 32; i++ {
					if err := fr.WriteContinuation(streamID, false, nil); err != nil {
						t.Errorf("WriteContinuation %d: %v", i, err)
						return
					}
				}
				time.Sleep(300 * time.Millisecond)
			},
			wantErr: "timeout",
		},
		{
			name: "stream ID reuse fails affected stream",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				nativeHTTP2RawWriteHeaders(t, fr, streamID, false, hpack.HeaderField{Name: ":status", Value: "200"})
				nativeHTTP2RawWriteHeaders(t, fr, streamID, false, hpack.HeaderField{Name: ":status", Value: "200"})
			},
			wantErr: "trailing HEADERS without END_STREAM",
		},
		{
			name: "even server initiated HEADERS closes session",
			write: func(t *testing.T, fr *http2.Framer, _ uint32) {
				nativeHTTP2RawWriteHeaders(t, fr, 2, true, hpack.HeaderField{Name: ":status", Value: "200"})
			},
			wantErr: "HEADERS on even stream",
		},
		{
			name: "DATA before response HEADERS fails stream",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				if err := fr.WriteData(streamID, true, []byte("body")); err != nil {
					t.Errorf("WriteData: %v", err)
				}
			},
			wantErr: "DATA before response headers",
		},
		{
			name: "DATA on idle stream closes session",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				if err := fr.WriteData(streamID+2, true, []byte("idle")); err != nil {
					t.Errorf("WriteData: %v", err)
				}
			},
			wantErr: "DATA on idle stream",
		},
		{
			name: "pseudo-header after regular header closes session",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				nativeHTTP2RawWriteHeaders(t, fr, streamID, true,
					hpack.HeaderField{Name: "content-type", Value: "text/plain"},
					hpack.HeaderField{Name: ":status", Value: "200"},
				)
			},
			wantErr: "pseudo",
		},
		{
			name: "missing status fails stream",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				nativeHTTP2RawWriteHeaders(t, fr, streamID, true, hpack.HeaderField{Name: "content-type", Value: "text/plain"})
			},
			wantErr: "missing HTTP/2 response :status",
		},
		{
			name: "SETTINGS on non-zero stream closes session",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				if err := fr.WriteRawFrame(http2.FrameSettings, 0, streamID, nil); err != nil {
					t.Errorf("WriteRawFrame SETTINGS: %v", err)
				}
			},
			wantErr: "PROTOCOL_ERROR",
		},
		{
			name: "connection WINDOW_UPDATE zero closes session",
			write: func(t *testing.T, fr *http2.Framer, _ uint32) {
				if err := fr.WriteRawFrame(http2.FrameWindowUpdate, 0, 0, []byte{0, 0, 0, 0}); err != nil {
					t.Errorf("WriteRawFrame WINDOW_UPDATE: %v", err)
				}
			},
			wantErr: "PROTOCOL_ERROR",
		},
		{
			name: "padded DATA with invalid pad length closes session",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				if err := fr.WriteRawFrame(http2.FrameData, http2.FlagDataPadded, streamID, []byte{8, 'x'}); err != nil {
					t.Errorf("WriteRawFrame DATA padded: %v", err)
				}
			},
			wantErr: "PROTOCOL_ERROR",
		},
		{
			name: "HEADERS requiring CONTINUATION with END_STREAM times out",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				if err := fr.WriteRawFrame(http2.FrameHeaders, http2.FlagHeadersEndStream, streamID, []byte{0x88}); err != nil {
					t.Errorf("WriteRawFrame HEADERS: %v", err)
				}
				time.Sleep(300 * time.Millisecond)
			},
			wantErr: "timeout",
		},
		{
			name: "oversized unknown frame closes session",
			write: func(t *testing.T, fr *http2.Framer, _ uint32) {
				if err := fr.WriteRawFrame(0xff, 0, 0, bytes.Repeat([]byte("x"), int(nativeHTTP2DefaultMaxFrameSize)+1)); err != nil {
					t.Errorf("WriteRawFrame unknown: %v", err)
				}
			},
			wantErr: "frame length",
		},
		{
			name: "PUSH_PROMISE closes session",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				var block bytes.Buffer
				enc := hpack.NewEncoder(&block)
				if err := enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"}); err != nil {
					t.Fatalf("encode push header: %v", err)
				}
				if err := fr.WritePushPromise(http2.PushPromiseParam{
					StreamID:      streamID,
					PromiseID:     streamID + 2,
					BlockFragment: block.Bytes(),
					EndHeaders:    true,
				}); err != nil {
					t.Errorf("WritePushPromise: %v", err)
				}
			},
			wantErr: "PUSH_PROMISE",
		},
		{
			name: "extended CONNECT protocol pseudo-header closes session",
			write: func(t *testing.T, fr *http2.Framer, streamID uint32) {
				nativeHTTP2RawWriteHeaders(t, fr, streamID, true,
					hpack.HeaderField{Name: ":status", Value: "200"},
					hpack.HeaderField{Name: ":protocol", Value: "websocket"},
				)
			},
			wantErr: "pseudo",
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
			rt.headerWait = 50 * time.Millisecond
			defer rt.CloseIdleConnections()

			err = nativeHTTP2RoundTripDrainError(t, rt, rawURL)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("RoundTrip/drain err=%v want substring %q", err, tc.wantErr)
			}
		})
	}
}

func nativeHTTP2RoundTripDrainError(t *testing.T, rt http.RoundTripper, rawURL string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	if resp == nil || resp.Body == nil {
		return nil
	}
	_, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return readErr
	}
	return closeErr
}

func nativeHTTP2BombHeaderFields() []hpack.HeaderField {
	fields := []hpack.HeaderField{{Name: ":status", Value: "200"}}
	value := strings.Repeat("a", 1024)
	for i := 0; i < 1100; i++ {
		fields = append(fields, hpack.HeaderField{Name: "x-bomb", Value: value})
	}
	return fields
}

func nativeHTTP2RawWriteHeaderBlock(t *testing.T, fr *http2.Framer, streamID uint32, endStream bool, fields ...hpack.HeaderField) {
	t.Helper()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, field := range fields {
		if err := enc.WriteField(field); err != nil {
			t.Fatalf("encode header: %v", err)
		}
	}
	raw := block.Bytes()
	first := raw
	if len(first) > int(nativeHTTP2DefaultMaxFrameSize) {
		first = raw[:nativeHTTP2DefaultMaxFrameSize]
	}
	rest := raw[len(first):]
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: first,
		EndStream:     endStream,
		EndHeaders:    len(rest) == 0,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	for len(rest) > 0 {
		part := rest
		if len(part) > int(nativeHTTP2DefaultMaxFrameSize) {
			part = rest[:nativeHTTP2DefaultMaxFrameSize]
		}
		rest = rest[len(part):]
		if err := fr.WriteContinuation(streamID, len(rest) == 0, part); err != nil {
			t.Fatalf("WriteContinuation: %v", err)
		}
	}
}
