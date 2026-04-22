package handler

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestNativeHTTP2MalformedUpstream(t *testing.T) {
	t.Run("settings ack timeout", func(t *testing.T) {
		rawURL := nativeHTTP2CustomServerURL(t, func(t *testing.T, conn net.Conn) {
			defer conn.Close()
			fr := nativeHTTP2RawReadClientPrefaceAndSettings(t, conn)
			if err := fr.WriteSettings(); err != nil {
				t.Errorf("WriteSettings: %v", err)
			}
			time.Sleep(200 * time.Millisecond)
		})
		err := nativeHTTP2MalformedRoundTripError(t, rawURL, func(rt *nativeHTTP2Transport) {
			rt.headerWait = 50 * time.Millisecond
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "settings ack timeout") {
			t.Fatalf("err=%v want settings ack timeout", err)
		}
	})

	t.Run("invalid SETTINGS_MAX_FRAME_SIZE below minimum", func(t *testing.T) {
		err := nativeHTTP2SettingsError(t, http2.Setting{ID: http2.SettingMaxFrameSize, Val: 1})
		if err == nil || !strings.Contains(err.Error(), "PROTOCOL_ERROR") {
			t.Fatalf("err=%v want PROTOCOL_ERROR", err)
		}
	})

	t.Run("invalid SETTINGS_MAX_FRAME_SIZE above maximum", func(t *testing.T) {
		err := nativeHTTP2SettingsError(t, http2.Setting{ID: http2.SettingMaxFrameSize, Val: nativeHTTP2MaxFrameSizeLimit + 1})
		if err == nil || !strings.Contains(err.Error(), "PROTOCOL_ERROR") {
			t.Fatalf("err=%v want PROTOCOL_ERROR", err)
		}
	})

	t.Run("invalid SETTINGS_INITIAL_WINDOW_SIZE", func(t *testing.T) {
		err := nativeHTTP2SettingsError(t, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 31})
		if err == nil || !strings.Contains(err.Error(), "FLOW_CONTROL_ERROR") {
			t.Fatalf("err=%v want FLOW_CONTROL_ERROR", err)
		}
	})

	t.Run("premature close mid-preface", func(t *testing.T) {
		rawURL := nativeHTTP2CustomServerURL(t, func(_ *testing.T, conn net.Conn) {
			_ = conn.Close()
		})
		err := nativeHTTP2MalformedRoundTripError(t, rawURL, func(rt *nativeHTTP2Transport) {
			rt.headerWait = 50 * time.Millisecond
		}, nil)
		if err == nil {
			t.Fatal("err=nil want premature close error")
		}
	})

	t.Run("premature close mid-headers", func(t *testing.T) {
		rawURL := nativeHTTP2RawServerURL(t, func(fr *http2.Framer, streamID uint32) {
			if err := fr.WriteRawFrame(http2.FrameHeaders, 0, streamID, []byte{0x88}); err != nil {
				t.Errorf("WriteRawFrame HEADERS: %v", err)
			}
		})
		err := nativeHTTP2MalformedRoundTripError(t, rawURL, func(rt *nativeHTTP2Transport) {
			rt.headerWait = 50 * time.Millisecond
		}, nil)
		if err == nil {
			t.Fatal("err=nil want mid-headers close error")
		}
	})

	t.Run("slow data timeout", func(t *testing.T) {
		rawURL := nativeHTTP2RawServerURL(t, func(fr *http2.Framer, streamID uint32) {
			nativeHTTP2RawWriteHeaders(t, fr, streamID, false, hpack.HeaderField{Name: ":status", Value: "200"})
			time.Sleep(150 * time.Millisecond)
			_ = fr.WriteData(streamID, true, []byte("late"))
		})
		err := nativeHTTP2MalformedRoundTripError(t, rawURL, func(rt *nativeHTTP2Transport) {
			rt.idleWait = 50 * time.Millisecond
		}, func(resp *http.Response) error {
			_, err := io.ReadAll(resp.Body)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("err=%v want slow data timeout", err)
		}
	})

	t.Run("window starvation timeout", func(t *testing.T) {
		rawURL := nativeHTTP2RawServerURL(t, func(fr *http2.Framer, _ uint32) {
			deadline := time.Now().Add(300 * time.Millisecond)
			for time.Now().Before(deadline) {
				_, err := fr.ReadFrame()
				if err != nil {
					return
				}
			}
		})
		body := bytes.Repeat([]byte("x"), int(nativeHTTP2InitialWindowSize)+8192)
		err := nativeHTTP2MalformedRoundTripError(t, rawURL, func(rt *nativeHTTP2Transport) {
			rt.headerWait = 50 * time.Millisecond
		}, func(req *http.Request) {
			req.Method = http.MethodPost
			req.Body = io.NopCloser(bytes.NewReader(body))
			req.ContentLength = int64(len(body))
		})
		if err == nil || !strings.Contains(err.Error(), "flow-control window timeout") {
			t.Fatalf("err=%v want flow-control window timeout", err)
		}
	})

	t.Run("ping ack timeout closes session", func(t *testing.T) {
		rawURL := nativeHTTP2RawServerURL(t, func(fr *http2.Framer, streamID uint32) {
			nativeHTTP2RawWriteHeaders(t, fr, streamID, true, hpack.HeaderField{Name: ":status", Value: "204"})
			deadline := time.Now().Add(300 * time.Millisecond)
			for time.Now().Before(deadline) {
				frame, err := fr.ReadFrame()
				if err != nil {
					return
				}
				if _, ok := frame.(*http2.PingFrame); ok {
					continue
				}
			}
		})
		rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
		if err != nil {
			t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
		}
		rt.idleWait = 20 * time.Millisecond
		rt.pingWait = 40 * time.Millisecond
		defer rt.CloseIdleConnections()
		if err := nativeHTTP2MalformedDoRoundTrip(t, rt, rawURL, nil, nil); err != nil {
			t.Fatalf("initial RoundTrip: %v", err)
		}
		time.Sleep(120 * time.Millisecond)
		nativeHTTP2AssertNoPooledSessions(t, rt)
	})
}

func nativeHTTP2SettingsError(t *testing.T, setting http2.Setting) error {
	t.Helper()
	rawURL := nativeHTTP2CustomServerURL(t, func(t *testing.T, conn net.Conn) {
		defer conn.Close()
		fr := nativeHTTP2RawReadClientPrefaceAndSettings(t, conn)
		if err := fr.WriteSettings(setting); err != nil {
			t.Errorf("WriteSettings: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	})
	return nativeHTTP2MalformedRoundTripError(t, rawURL, func(rt *nativeHTTP2Transport) {
		rt.headerWait = 50 * time.Millisecond
	}, nil)
}

func nativeHTTP2MalformedRoundTripError(t *testing.T, rawURL string, tune func(*nativeHTTP2Transport), mutateOrRead any) error {
	t.Helper()
	rt, err := buildProxyNativeHTTP2Transport(normalizeProxyRulesConfig(ProxyRulesConfig{}), proxyTransportProfile{}, proxyHTTP2ModeH2C)
	if err != nil {
		t.Fatalf("buildProxyNativeHTTP2Transport: %v", err)
	}
	if tune != nil {
		tune(rt)
	}
	defer rt.CloseIdleConnections()
	err = nativeHTTP2MalformedDoRoundTrip(t, rt, rawURL, mutateOrRead, mutateOrRead)
	nativeHTTP2AssertNoPooledSessions(t, rt)
	return err
}

func nativeHTTP2MalformedDoRoundTrip(t *testing.T, rt *nativeHTTP2Transport, rawURL string, mutate any, read any) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	if fn, ok := mutate.(func(*http.Request)); ok && fn != nil {
		fn(req)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if fn, ok := read.(func(*http.Response) error); ok && fn != nil {
		return fn(resp)
	}
	_, err = io.ReadAll(resp.Body)
	return err
}

func nativeHTTP2CustomServerURL(t *testing.T, serve func(*testing.T, net.Conn)) string {
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
		serve(t, conn)
	}()
	return "http://" + ln.Addr().String() + "/"
}

func nativeHTTP2RawReadClientPrefaceAndSettings(t *testing.T, conn net.Conn) *http2.Framer {
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
	}
	return fr
}

func nativeHTTP2AssertNoPooledSessions(t *testing.T, rt *nativeHTTP2Transport) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		rt.mu.Lock()
		sessionCount := 0
		activeCount := 0
		for _, list := range rt.sessions {
			sessionCount += len(list)
		}
		for _, n := range rt.active {
			activeCount += n
		}
		rt.mu.Unlock()
		if sessionCount == 0 && activeCount == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("native h2 session pool not drained: sessions=%d active=%d", sessionCount, activeCount)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
