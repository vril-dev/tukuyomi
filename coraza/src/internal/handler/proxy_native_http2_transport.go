package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	nativeHTTP2InitialWindowSize    int64  = 65535
	nativeHTTP2DefaultMaxFrameSize  uint32 = 16384
	nativeHTTP2MaxFrameSizeLimit    uint32 = 1<<24 - 1
	nativeHTTP2DefaultMaxConcurrent uint32 = 100
	nativeHTTP2LocalMaxConcurrent   uint32 = 256
	nativeHTTP2MaxHeaderListBytes   uint32 = 1 << 20
	nativeHTTP2BodyEventBuffer             = 32
	nativeHTTP2WriteQueueBuffer            = 128
	nativeHTTP2DefaultSettingsWait         = 5 * time.Second
	nativeHTTP2PingWait                    = 5 * time.Second
	nativeHTTP2RapidResetWindow            = 1 * time.Second
	nativeHTTP2RapidResetLimit             = 64
	nativeHTTP2MaxGoAwayDebugBytes         = 1024
)

var (
	errNativeHTTP2UseHTTP1Fallback = errors.New("native http2 requires explicit http1 fallback")
	errNativeHTTP2StreamClosed     = errors.New("native http2 stream is closed")
)

type nativeHTTP2Mode int

const (
	nativeHTTP2ModeALPN nativeHTTP2Mode = iota
	nativeHTTP2ModePriorKnowledge
)

type nativeHTTP2Transport struct {
	cfg        ProxyRulesConfig
	profile    proxyTransportProfile
	mode       nativeHTTP2Mode
	tlsConfig  *tls.Config
	fallbackH1 *nativeHTTP1Transport
	dialer     net.Dialer
	headerWait time.Duration
	tlsWait    time.Duration
	idleWait   time.Duration
	pingWait   time.Duration
	maxConns   int

	mu       sync.Mutex
	sessions map[nativeHTTP2ConnKey][]*nativeHTTP2Session
	active   map[nativeHTTP2ConnKey]int
	waiters  map[nativeHTTP2ConnKey][]chan struct{}
	closed   bool
}

type nativeHTTP2ConnKey struct {
	scheme     string
	address    string
	serverName string
	mode       nativeHTTP2Mode
}

func buildProxyNativeHTTP2Transport(cfg ProxyRulesConfig, profile proxyTransportProfile, mode string) (*nativeHTTP2Transport, error) {
	tlsCfg, err := buildProxyTLSClientConfigForProfile(profile.TLS)
	if err != nil {
		return nil, err
	}
	h2Mode := nativeHTTP2ModeALPN
	var fallback *nativeHTTP1Transport
	if normalizeProxyHTTP2Mode(mode) == proxyHTTP2ModeH2C {
		h2Mode = nativeHTTP2ModePriorKnowledge
	} else {
		fallback, err = buildProxyNativeHTTP1Transport(cfg, profile)
		if err != nil {
			return nil, err
		}
	}
	return &nativeHTTP2Transport{
		cfg:        cfg,
		profile:    profile,
		mode:       h2Mode,
		tlsConfig:  tlsCfg,
		fallbackH1: fallback,
		dialer: net.Dialer{
			Timeout:   time.Duration(cfg.DialTimeout) * time.Second,
			KeepAlive: proxyUpstreamKeepAliveDuration(cfg),
		},
		headerWait: time.Duration(cfg.ResponseHeaderTimeout) * time.Second,
		tlsWait:    5 * time.Second,
		idleWait:   time.Duration(cfg.IdleConnTimeout) * time.Second,
		pingWait:   nativeHTTP2PingWait,
		maxConns:   cfg.MaxConnsPerHost,
		sessions:   make(map[nativeHTTP2ConnKey][]*nativeHTTP2Session),
		active:     make(map[nativeHTTP2ConnKey]int),
		waiters:    make(map[nativeHTTP2ConnKey][]chan struct{}),
	}, nil
}

func (t *nativeHTTP2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil {
		return nil, fmt.Errorf("native http2 transport is nil")
	}
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("request URL is required")
	}
	if proxyUpgradeType(req.Header) != "" {
		if t.fallbackH1 != nil {
			return t.fallbackH1.RoundTrip(req)
		}
		return nil, fmt.Errorf("native http2 transport does not support HTTP/1.1 Upgrade for h2c upstreams")
	}
	scheme := strings.ToLower(strings.TrimSpace(req.URL.Scheme))
	switch t.mode {
	case nativeHTTP2ModePriorKnowledge:
		if scheme != "http" {
			return nil, fmt.Errorf("native h2c transport requires http upstream, got %q", req.URL.Scheme)
		}
	case nativeHTTP2ModeALPN:
		if scheme != "https" {
			if t.fallbackH1 != nil {
				return t.fallbackH1.RoundTrip(req)
			}
			return nil, fmt.Errorf("native http2 ALPN transport requires https upstream, got %q", req.URL.Scheme)
		}
	default:
		return nil, fmt.Errorf("unknown native http2 mode")
	}
	address, err := proxyDialAddress(req.URL)
	if err != nil {
		return nil, err
	}
	key := nativeHTTP2ConnKey{
		scheme:     scheme,
		address:    address,
		serverName: nativeHTTP1ServerName(t.tlsConfig, req.URL.Hostname()),
		mode:       t.mode,
	}
	st, err := t.acquireStream(req.Context(), key, req.URL.Hostname(), req)
	if errors.Is(err, errNativeHTTP2UseHTTP1Fallback) && t.fallbackH1 != nil {
		return t.fallbackH1.RoundTrip(req)
	}
	if err != nil {
		return nil, err
	}
	return st.session.roundTrip(req, st)
}

func (t *nativeHTTP2Transport) CloseIdleConnections() {
	if t == nil {
		return
	}
	var sessions []*nativeHTTP2Session
	t.mu.Lock()
	for _, list := range t.sessions {
		for _, s := range list {
			if s.idle() {
				sessions = append(sessions, s)
			}
		}
	}
	if t.fallbackH1 != nil {
		t.fallbackH1.CloseIdleConnections()
	}
	t.mu.Unlock()
	for _, s := range sessions {
		s.closeWithError(fmt.Errorf("native http2 idle close"))
	}
}

func (t *nativeHTTP2Transport) acquireStream(ctx context.Context, key nativeHTTP2ConnKey, hostname string, req *http.Request) (*nativeHTTP2Stream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		for _, s := range t.snapshotSessions(key) {
			st, ok, err := s.tryOpenStream(req)
			if err != nil {
				return nil, err
			}
			if ok {
				return st, nil
			}
		}
		waiter, canDial, err := t.reserveSessionOrWait(ctx, key)
		if err != nil {
			return nil, err
		}
		if canDial {
			s, err := t.openSession(ctx, key, hostname)
			if err != nil {
				t.releaseSessionSlot(key)
				return nil, err
			}
			if !t.addSession(key, s) {
				t.releaseSessionSlot(key)
				continue
			}
			st, ok, err := s.tryOpenStream(req)
			if err != nil {
				s.closeWithError(err)
				return nil, err
			}
			if !ok {
				s.closeWithError(fmt.Errorf("native http2 new session has no stream capacity"))
				return nil, fmt.Errorf("native http2 new session has no stream capacity")
			}
			return st, nil
		}
		select {
		case <-ctx.Done():
			t.removeSessionWaiter(key, waiter)
			return nil, ctx.Err()
		case <-waiter:
		}
	}
}

func (t *nativeHTTP2Transport) snapshotSessions(key nativeHTTP2ConnKey) []*nativeHTTP2Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	list := t.sessions[key]
	out := make([]*nativeHTTP2Session, len(list))
	copy(out, list)
	return out
}

func (t *nativeHTTP2Transport) reserveSessionOrWait(ctx context.Context, key nativeHTTP2ConnKey) (chan struct{}, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, false, fmt.Errorf("native http2 transport is closed")
	}
	if t.maxConns <= 0 || t.active[key] < t.maxConns {
		t.active[key]++
		return nil, true, nil
	}
	waiter := make(chan struct{})
	t.waiters[key] = append(t.waiters[key], waiter)
	return waiter, false, nil
}

func (t *nativeHTTP2Transport) releaseSessionSlot(key nativeHTTP2ConnKey) {
	t.mu.Lock()
	t.active[key]--
	if t.active[key] <= 0 {
		delete(t.active, key)
	}
	t.signalWaiterLocked(key)
	t.mu.Unlock()
}

func (t *nativeHTTP2Transport) removeSessionWaiter(key nativeHTTP2ConnKey, waiter chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	waiters := t.waiters[key]
	for i, candidate := range waiters {
		if candidate == waiter {
			copy(waiters[i:], waiters[i+1:])
			waiters = waiters[:len(waiters)-1]
			break
		}
	}
	if len(waiters) == 0 {
		delete(t.waiters, key)
	} else {
		t.waiters[key] = waiters
	}
}

func (t *nativeHTTP2Transport) addSession(key nativeHTTP2ConnKey, s *nativeHTTP2Session) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.registered = true
	t.sessions[key] = append(t.sessions[key], s)
	return true
}

func (t *nativeHTTP2Transport) removeSession(s *nativeHTTP2Session) {
	if t == nil || s == nil {
		return
	}
	t.mu.Lock()
	list := t.sessions[s.key]
	for i, candidate := range list {
		if candidate == s {
			copy(list[i:], list[i+1:])
			list = list[:len(list)-1]
			break
		}
	}
	if len(list) == 0 {
		delete(t.sessions, s.key)
	} else {
		t.sessions[s.key] = list
	}
	t.active[s.key]--
	if t.active[s.key] <= 0 {
		delete(t.active, s.key)
	}
	t.signalWaiterLocked(s.key)
	t.mu.Unlock()
}

func (t *nativeHTTP2Transport) signalWaiter(key nativeHTTP2ConnKey) {
	t.mu.Lock()
	t.signalWaiterLocked(key)
	t.mu.Unlock()
}

func (t *nativeHTTP2Transport) signalWaiterLocked(key nativeHTTP2ConnKey) {
	waiters := t.waiters[key]
	if len(waiters) == 0 {
		return
	}
	waiter := waiters[0]
	copy(waiters[0:], waiters[1:])
	waiters = waiters[:len(waiters)-1]
	if len(waiters) == 0 {
		delete(t.waiters, key)
	} else {
		t.waiters[key] = waiters
	}
	close(waiter)
}

func (t *nativeHTTP2Transport) openSession(ctx context.Context, key nativeHTTP2ConnKey, hostname string) (*nativeHTTP2Session, error) {
	conn, err := t.dialSessionConn(ctx, key, hostname)
	if err != nil {
		return nil, err
	}
	s := newNativeHTTP2Session(t, key, conn)
	if err := s.start(ctx); err != nil {
		s.closeWithError(err)
		return nil, err
	}
	return s, nil
}

func (t *nativeHTTP2Transport) dialSessionConn(ctx context.Context, key nativeHTTP2ConnKey, hostname string) (net.Conn, error) {
	raw, err := t.dialer.DialContext(ctx, "tcp", key.address)
	if err != nil {
		return nil, err
	}
	if t.mode == nativeHTTP2ModePriorKnowledge {
		return raw, nil
	}
	cfg := &tls.Config{ServerName: hostname, NextProtos: []string{"h2", "http/1.1"}}
	if t.tlsConfig != nil {
		cfg = t.tlsConfig.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = hostname
		}
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	conn := tls.Client(raw, cfg)
	if t.tlsWait > 0 {
		_ = conn.SetDeadline(time.Now().Add(t.tlsWait))
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	if proto := conn.ConnectionState().NegotiatedProtocol; proto != "h2" {
		_ = conn.Close()
		return nil, errNativeHTTP2UseHTTP1Fallback
	}
	return conn, nil
}

type nativeHTTP2Session struct {
	transport *nativeHTTP2Transport
	key       nativeHTTP2ConnKey
	conn      net.Conn
	readFr    *http2.Framer
	writeFr   *http2.Framer
	writeCh   chan nativeHTTP2Write
	closeCh   chan struct{}
	done      chan struct{}
	wg        sync.WaitGroup

	closeOnce sync.Once
	hpackMu   sync.Mutex
	hpackBuf  bytes.Buffer
	hpackEnc  *hpack.Encoder

	settingsOnce sync.Once
	settingsCh   chan struct{}
	ackOnce      sync.Once
	ackCh        chan struct{}
	pingAckCh    chan [8]byte

	mu                  sync.Mutex
	streams             map[uint32]*nativeHTTP2Stream
	nextStreamID        uint32
	activeStreams       uint32
	remoteMaxStreams    uint32
	remoteMaxFrameSize  uint32
	remoteMaxHeaderList uint32
	remoteInitialWindow int64
	connSendWindow      int64
	reusable            bool
	closed              bool
	lastErr             error
	sawGoAway           bool
	lastGoAwayID        uint32
	lastGoAwayCode      http2.ErrCode
	windowNotify        chan struct{}
	registered          bool
	rstWindowStart      time.Time
	rstWindowCount      int
}

type nativeHTTP2Write struct {
	ctx  context.Context
	fn   func(*http2.Framer) error
	done chan error
}

func newNativeHTTP2Session(t *nativeHTTP2Transport, key nativeHTTP2ConnKey, conn net.Conn) *nativeHTTP2Session {
	readFr := http2.NewFramer(io.Discard, conn)
	readFr.ReadMetaHeaders = hpack.NewDecoder(nativeHTTP2MaxHeaderListBytes, nil)
	readFr.MaxHeaderListSize = nativeHTTP2MaxHeaderListBytes
	readFr.SetMaxReadFrameSize(nativeHTTP2MaxFrameSizeLimit)

	s := &nativeHTTP2Session{
		transport:           t,
		key:                 key,
		conn:                conn,
		readFr:              readFr,
		writeFr:             http2.NewFramer(conn, bytes.NewReader(nil)),
		writeCh:             make(chan nativeHTTP2Write, nativeHTTP2WriteQueueBuffer),
		closeCh:             make(chan struct{}),
		done:                make(chan struct{}),
		settingsCh:          make(chan struct{}),
		ackCh:               make(chan struct{}),
		pingAckCh:           make(chan [8]byte, 1),
		streams:             make(map[uint32]*nativeHTTP2Stream),
		nextStreamID:        1,
		remoteMaxStreams:    nativeHTTP2DefaultMaxConcurrent,
		remoteMaxFrameSize:  nativeHTTP2DefaultMaxFrameSize,
		remoteInitialWindow: nativeHTTP2InitialWindowSize,
		connSendWindow:      nativeHTTP2InitialWindowSize,
		reusable:            true,
		windowNotify:        make(chan struct{}),
	}
	s.hpackEnc = hpack.NewEncoder(&s.hpackBuf)
	s.hpackEnc.SetMaxDynamicTableSizeLimit(4096)
	return s
}

func (s *nativeHTTP2Session) start(ctx context.Context) error {
	s.wg.Add(2)
	go s.writerLoop()
	go s.readerLoop()
	go func() {
		s.wg.Wait()
		close(s.done)
	}()

	if err := s.writeFrame(ctx, func(fr *http2.Framer) error {
		if _, err := io.WriteString(s.conn, http2.ClientPreface); err != nil {
			return err
		}
		return fr.WriteSettings(
			http2.Setting{ID: http2.SettingEnablePush, Val: 0},
			http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: nativeHTTP2LocalMaxConcurrent},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(nativeHTTP2InitialWindowSize)},
			http2.Setting{ID: http2.SettingMaxFrameSize, Val: nativeHTTP2DefaultMaxFrameSize},
			http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: nativeHTTP2MaxHeaderListBytes},
		)
	}); err != nil {
		return err
	}
	wait := s.transport.headerWait
	if wait <= 0 {
		wait = nativeHTTP2DefaultSettingsWait
	}
	if err := s.waitStartupSignal(ctx, s.settingsCh, wait, "settings"); err != nil {
		return err
	}
	return s.waitStartupSignal(ctx, s.ackCh, wait, "settings ack")
}

func (s *nativeHTTP2Session) waitStartupSignal(ctx context.Context, ch <-chan struct{}, wait time.Duration, name string) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-timer.C:
		return fmt.Errorf("native http2 upstream %s timeout", name)
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.error()
	}
}

func (s *nativeHTTP2Session) writerLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.closeCh:
			return
		case req := <-s.writeCh:
			if req.fn == nil {
				if req.done != nil {
					req.done <- nil
				}
				continue
			}
			err := req.fn(s.writeFr)
			if req.done != nil {
				req.done <- err
			}
			if err != nil {
				s.closeWithError(err)
				return
			}
		}
	}
}

func (s *nativeHTTP2Session) readerLoop() {
	defer s.wg.Done()
	if s.transport.idleWait > 0 {
		go s.keepAliveLoop(s.transport.idleWait)
	}
	for {
		s.applyReadDeadline()
		frame, err := s.readFr.ReadFrame()
		if err != nil {
			if !s.isClosed() {
				s.closeWithError(err)
			}
			return
		}
		if err := s.handleFrame(frame); err != nil {
			s.writeFrameBestEffort(func(fr *http2.Framer) error {
				return fr.WriteGoAway(0, http2.ErrCodeProtocol, []byte(err.Error()))
			})
			s.closeWithError(err)
			return
		}
	}
}

func (s *nativeHTTP2Session) keepAliveLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
		var payload [8]byte
		binaryTime := uint64(time.Now().UnixNano())
		for i := 7; i >= 0; i-- {
			payload[i] = byte(binaryTime)
			binaryTime >>= 8
		}
		if err := s.writeFrame(context.Background(), func(fr *http2.Framer) error {
			return fr.WritePing(false, payload)
		}); err != nil {
			s.closeWithError(err)
			return
		}
		timer := time.NewTimer(s.pingAckWait())
		select {
		case got := <-s.pingAckCh:
			timer.Stop()
			if got != payload {
				s.closeWithError(fmt.Errorf("native http2 ping ack payload mismatch"))
				return
			}
		case <-timer.C:
			s.closeWithError(fmt.Errorf("native http2 ping ack timeout"))
			return
		case <-s.done:
			timer.Stop()
			return
		}
	}
}

func (s *nativeHTTP2Session) handleFrame(frame http2.Frame) error {
	if frame.Header().Length > nativeHTTP2DefaultMaxFrameSize {
		return fmt.Errorf("native http2 upstream frame length %d exceeds local max %d", frame.Header().Length, nativeHTTP2DefaultMaxFrameSize)
	}
	switch f := frame.(type) {
	case *http2.SettingsFrame:
		return s.handleSettings(f)
	case *http2.PingFrame:
		if f.IsAck() {
			select {
			case s.pingAckCh <- f.Data:
			default:
			}
			return nil
		}
		data := f.Data
		return s.writeFrame(context.Background(), func(fr *http2.Framer) error {
			return fr.WritePing(true, data)
		})
	case *http2.GoAwayFrame:
		return s.handleGoAway(f)
	case *http2.WindowUpdateFrame:
		return s.handleWindowUpdate(f)
	case *http2.MetaHeadersFrame:
		return s.handleMetaHeaders(f)
	case *http2.DataFrame:
		return s.handleData(f)
	case *http2.RSTStreamFrame:
		if err := s.recordInboundRSTStream(time.Now()); err != nil {
			return err
		}
		s.failStream(f.StreamID, nativeHTTP2StreamError{StreamID: f.StreamID, Code: f.ErrCode})
		return nil
	case *http2.PushPromiseFrame:
		return fmt.Errorf("native http2 upstream sent forbidden PUSH_PROMISE")
	default:
		return nil
	}
}

func (s *nativeHTTP2Session) handleSettings(f *http2.SettingsFrame) error {
	if f.IsAck() {
		s.ackOnce.Do(func() { close(s.ackCh) })
		return nil
	}
	if f.HasDuplicates() {
		return fmt.Errorf("native http2 upstream sent duplicate SETTINGS")
	}
	var initialDelta int64
	var headerTableSize *uint32
	var closeAfterAck bool
	if err := f.ForeachSetting(func(setting http2.Setting) error {
		if err := setting.Valid(); err != nil {
			return err
		}
		switch setting.ID {
		case http2.SettingMaxConcurrentStreams:
			s.mu.Lock()
			s.remoteMaxStreams = setting.Val
			if setting.Val == 0 {
				s.reusable = false
				closeAfterAck = s.registered && s.activeStreams == 0 && !s.closed
			}
			s.notifyWindowLocked()
			s.mu.Unlock()
		case http2.SettingInitialWindowSize:
			s.mu.Lock()
			initialDelta = int64(setting.Val) - s.remoteInitialWindow
			s.remoteInitialWindow = int64(setting.Val)
			for _, st := range s.streams {
				st.sendWindow += initialDelta
			}
			s.notifyWindowLocked()
			s.mu.Unlock()
		case http2.SettingMaxFrameSize:
			s.mu.Lock()
			s.remoteMaxFrameSize = setting.Val
			s.mu.Unlock()
		case http2.SettingMaxHeaderListSize:
			s.mu.Lock()
			s.remoteMaxHeaderList = setting.Val
			s.mu.Unlock()
		case http2.SettingHeaderTableSize:
			v := setting.Val
			headerTableSize = &v
		}
		return nil
	}); err != nil {
		return err
	}
	if headerTableSize != nil {
		s.hpackMu.Lock()
		s.hpackEnc.SetMaxDynamicTableSizeLimit(*headerTableSize)
		s.hpackEnc.SetMaxDynamicTableSize(*headerTableSize)
		s.hpackMu.Unlock()
	}
	if err := s.writeFrame(context.Background(), func(fr *http2.Framer) error {
		return fr.WriteSettingsAck()
	}); err != nil {
		return err
	}
	s.settingsOnce.Do(func() { close(s.settingsCh) })
	if closeAfterAck {
		s.closeWithError(fmt.Errorf("native http2 upstream disabled concurrent streams"))
	}
	return nil
}

func (s *nativeHTTP2Session) handleGoAway(f *http2.GoAwayFrame) error {
	if debugLen := len(f.DebugData()); debugLen > nativeHTTP2MaxGoAwayDebugBytes {
		return fmt.Errorf("native http2 GOAWAY debug data length %d exceeds limit %d", debugLen, nativeHTTP2MaxGoAwayDebugBytes)
	}
	s.mu.Lock()
	if s.sawGoAway && f.LastStreamID > s.lastGoAwayID {
		prev := s.lastGoAwayID
		s.mu.Unlock()
		return fmt.Errorf("native http2 GOAWAY increased last_stream_id from %d to %d", prev, f.LastStreamID)
	}
	s.sawGoAway = true
	s.reusable = false
	s.lastGoAwayID = f.LastStreamID
	s.lastGoAwayCode = f.ErrCode
	var failed []*nativeHTTP2Stream
	for id, st := range s.streams {
		if id > f.LastStreamID {
			failed = append(failed, st)
		}
	}
	s.mu.Unlock()
	for _, st := range failed {
		s.releaseStream(st, nativeHTTP2StreamError{StreamID: st.id, Code: f.ErrCode})
	}
	return nil
}

func (s *nativeHTTP2Session) handleWindowUpdate(f *http2.WindowUpdateFrame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.StreamID == 0 {
		next := s.connSendWindow + int64(f.Increment)
		if next > 1<<31-1 {
			return fmt.Errorf("native http2 connection flow-control window overflow")
		}
		s.connSendWindow = next
		s.notifyWindowLocked()
		return nil
	}
	st := s.streams[f.StreamID]
	if st == nil {
		return nil
	}
	next := st.sendWindow + int64(f.Increment)
	if next > 1<<31-1 {
		return fmt.Errorf("native http2 stream %d flow-control window overflow", f.StreamID)
	}
	st.sendWindow = next
	s.notifyWindowLocked()
	return nil
}

func (s *nativeHTTP2Session) handleMetaHeaders(f *http2.MetaHeadersFrame) error {
	if f.Truncated {
		return fmt.Errorf("native http2 upstream response headers exceed limit")
	}
	if f.StreamID%2 == 0 {
		return fmt.Errorf("native http2 upstream HEADERS on even stream %d", f.StreamID)
	}
	st := s.stream(f.StreamID)
	if st == nil {
		if s.isUnopenedStream(f.StreamID) {
			return fmt.Errorf("native http2 upstream HEADERS on idle stream %d", f.StreamID)
		}
		return fmt.Errorf("native http2 upstream HEADERS on closed stream %d", f.StreamID)
	}
	if !st.responseStarted() {
		resp, informational, err := nativeHTTP2DecodeResponseHeaders(f, st.req)
		if err != nil {
			s.releaseStream(st, err)
			s.resetStream(f.StreamID, http2.ErrCodeProtocol)
			return nil
		}
		if informational {
			if trace := httptrace.ContextClientTrace(st.req.Context()); trace != nil && trace.Got1xxResponse != nil {
				if err := trace.Got1xxResponse(resp.StatusCode, textproto.MIMEHeader(resp.Header)); err != nil {
					s.releaseStream(st, err)
				}
			}
			return nil
		}
		st.markResponseStarted(resp)
		if f.StreamEnded() {
			if err := st.validateEndStream(); err != nil {
				s.releaseStream(st, err)
				s.resetStream(f.StreamID, http2.ErrCodeProtocol)
				return nil
			}
			st.markRemoteClosed()
			st.sendBodyEvent(nativeHTTP2BodyEvent{eof: true})
		}
		st.queueResponse(resp)
		return nil
	}
	if st.remoteClosedSeen() {
		s.releaseStream(st, fmt.Errorf("native http2 HEADERS after remote close on stream %d", f.StreamID))
		s.resetStream(f.StreamID, http2.ErrCodeProtocol)
		return nil
	}
	if st.trailersObserved() {
		s.releaseStream(st, fmt.Errorf("native http2 HEADERS after trailers on stream %d", f.StreamID))
		s.resetStream(f.StreamID, http2.ErrCodeProtocol)
		return nil
	}
	if !f.StreamEnded() {
		s.releaseStream(st, fmt.Errorf("native http2 trailing HEADERS without END_STREAM on stream %d", f.StreamID))
		s.resetStream(f.StreamID, http2.ErrCodeProtocol)
		return nil
	}
	trailer, err := nativeHTTP2DecodeTrailers(f)
	if err != nil {
		s.releaseStream(st, err)
		s.resetStream(f.StreamID, http2.ErrCodeProtocol)
		return nil
	}
	if err := st.markTrailers(trailer); err != nil {
		s.releaseStream(st, err)
		s.resetStream(f.StreamID, http2.ErrCodeProtocol)
		return nil
	}
	if err := st.validateEndStream(); err != nil {
		s.releaseStream(st, err)
		s.resetStream(f.StreamID, http2.ErrCodeProtocol)
		return nil
	}
	st.markRemoteClosed()
	st.sendBodyEvent(nativeHTTP2BodyEvent{eof: true})
	return nil
}

func (s *nativeHTTP2Session) recordInboundRSTStream(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rstWindowStart.IsZero() || now.Sub(s.rstWindowStart) >= nativeHTTP2RapidResetWindow {
		s.rstWindowStart = now
		s.rstWindowCount = 0
	}
	s.rstWindowCount++
	if s.rstWindowCount <= nativeHTTP2RapidResetLimit {
		return nil
	}
	s.reusable = false
	return nativeHTTP2RapidResetError{Count: s.rstWindowCount, Window: nativeHTTP2RapidResetWindow}
}

func (s *nativeHTTP2Session) nextReadTimeout() time.Duration {
	if s == nil || s.transport == nil {
		return 0
	}
	s.mu.Lock()
	streams := make([]*nativeHTTP2Stream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.mu.Unlock()
	for _, st := range streams {
		if !st.responseStarted() && s.transport.headerWait > 0 {
			return s.transport.headerWait
		}
	}
	if len(streams) > 0 && s.transport.idleWait > 0 {
		return s.transport.idleWait
	}
	return 0
}

func (s *nativeHTTP2Session) pingAckWait() time.Duration {
	if s != nil && s.transport != nil && s.transport.pingWait > 0 {
		return s.transport.pingWait
	}
	return nativeHTTP2PingWait
}

func (s *nativeHTTP2Session) applyReadDeadline() {
	if wait := s.nextReadTimeout(); wait > 0 {
		_ = s.conn.SetReadDeadline(time.Now().Add(wait))
	} else {
		_ = s.conn.SetReadDeadline(time.Time{})
	}
}

func (s *nativeHTTP2Session) isUnopenedStream(streamID uint32) bool {
	if streamID == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.streams[streamID]; ok {
		return false
	}
	return streamID >= s.nextStreamID
}

func (s *nativeHTTP2Session) handleData(f *http2.DataFrame) error {
	if f.StreamID%2 == 0 {
		return fmt.Errorf("native http2 upstream DATA on even stream %d", f.StreamID)
	}
	st := s.stream(f.StreamID)
	if st == nil {
		if s.isUnopenedStream(f.StreamID) {
			return fmt.Errorf("native http2 upstream DATA on idle stream %d", f.StreamID)
		}
		return fmt.Errorf("native http2 upstream DATA on closed stream %d", f.StreamID)
	}
	if st.remoteClosedSeen() {
		s.releaseStream(st, fmt.Errorf("native http2 DATA after remote close on stream %d", f.StreamID))
		s.resetStream(f.StreamID, http2.ErrCodeProtocol)
		return nil
	}
	if !st.responseStarted() {
		s.releaseStream(st, fmt.Errorf("native http2 DATA before response headers on stream %d", f.StreamID))
		s.resetStream(f.StreamID, http2.ErrCodeProtocol)
		return nil
	}
	data := f.Data()
	connWindowCredit := 0
	var buf []byte
	if len(data) > 0 {
		if err := st.acceptData(len(data)); err != nil {
			s.releaseStream(st, err)
			s.resetStream(f.StreamID, http2.ErrCodeProtocol)
			return nil
		}
		buf = make([]byte, len(data))
		copy(buf, data)
		connWindowCredit = len(buf)
	}
	if f.StreamEnded() {
		if err := st.validateEndStream(); err != nil {
			s.releaseStream(st, err)
			s.resetStream(f.StreamID, http2.ErrCodeProtocol)
			return nil
		}
	}
	if len(buf) > 0 {
		if !st.sendBodyEvent(nativeHTTP2BodyEvent{data: buf}) {
			return nil
		}
	}
	if f.StreamEnded() {
		st.markRemoteClosed()
		st.sendBodyEvent(nativeHTTP2BodyEvent{eof: true})
	}
	if connWindowCredit > 0 {
		if err := s.writeWindowUpdate(0, uint32(connWindowCredit)); err != nil {
			return err
		}
	}
	return nil
}

func (s *nativeHTTP2Session) tryOpenStream(req *http.Request) (*nativeHTTP2Stream, bool, error) {
	fields, err := nativeHTTP2RequestHeaderFields(req)
	if err != nil {
		return nil, false, err
	}
	if err := s.validateOutboundHeaderList(fields); err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	if s.closed || !s.reusable || s.nextStreamID > (1<<31-1) {
		s.mu.Unlock()
		return nil, false, nil
	}
	if s.activeStreams >= s.remoteMaxStreams {
		s.mu.Unlock()
		return nil, false, nil
	}
	id := s.nextStreamID
	s.nextStreamID += 2
	st := &nativeHTTP2Stream{
		session:    s,
		id:         id,
		req:        req,
		state:      nativeHTTP2StreamOpen,
		sendWindow: s.remoteInitialWindow,
		responseCh: make(chan *http.Response, 1),
		errCh:      make(chan error, 1),
		bodyCh:     make(chan nativeHTTP2BodyEvent, nativeHTTP2BodyEventBuffer),
		done:       make(chan struct{}),
	}
	s.streams[id] = st
	s.activeStreams++
	s.mu.Unlock()
	s.applyReadDeadline()
	return st, true, nil
}

func (s *nativeHTTP2Session) roundTrip(req *http.Request, st *nativeHTTP2Stream) (*http.Response, error) {
	ctx := req.Context()
	hasBody := req.Body != nil && req.Body != http.NoBody
	if err := s.sendRequestHeaders(ctx, st, !hasBody); err != nil {
		s.releaseStream(st, err)
		return nil, err
	}
	bodyErrCh := make(chan error, 1)
	if hasBody {
		go func() {
			err := s.sendRequestBody(ctx, st, req)
			if err != nil {
				s.resetStream(st.id, http2.ErrCodeCancel)
				if nativeHTTP2IsFlowControlWindowTimeout(err) {
					s.closeWithError(err)
				} else {
					s.releaseStream(st, err)
				}
			}
			bodyErrCh <- err
		}()
	} else {
		bodyErrCh <- nil
	}
	for {
		select {
		case resp := <-st.responseCh:
			if resp != nil {
				return nativeHTTP2ResponseForCaller(resp, st), nil
			}
		case err := <-st.errCh:
			if err == nil {
				err = errNativeHTTP2StreamClosed
			}
			return nil, err
		case err := <-bodyErrCh:
			if err != nil {
				s.resetStream(st.id, http2.ErrCodeCancel)
				s.releaseStream(st, err)
				return nil, err
			}
		case <-ctx.Done():
			s.resetStream(st.id, http2.ErrCodeCancel)
			s.releaseStream(st, ctx.Err())
			return nil, ctx.Err()
		case <-s.done:
			select {
			case resp := <-st.responseCh:
				if resp != nil {
					return nativeHTTP2ResponseForCaller(resp, st), nil
				}
			default:
			}
			return nil, s.error()
		}
	}
}

func nativeHTTP2ResponseForCaller(resp *http.Response, st *nativeHTTP2Stream) *http.Response {
	resp.Body = &nativeHTTP2ResponseBody{stream: st}
	return resp
}

func (s *nativeHTTP2Session) sendRequestHeaders(ctx context.Context, st *nativeHTTP2Stream, endStream bool) error {
	block, err := s.encodeRequestHeaders(st.req)
	if err != nil {
		return err
	}
	if err := s.writeHeaderBlock(ctx, st.id, block, endStream); err != nil {
		return err
	}
	if endStream {
		st.markLocalClosed()
	}
	return nil
}

func (s *nativeHTTP2Session) sendRequestBody(ctx context.Context, st *nativeHTTP2Stream, req *http.Request) error {
	defer req.Body.Close()
	buf := proxyReverseCopyBufferPool.Get()
	defer proxyReverseCopyBufferPool.Put(buf)
	for {
		n, readErr := req.Body.Read(buf)
		if n > 0 {
			if err := s.sendData(ctx, st, buf[:n], false); err != nil {
				return err
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return readErr
			}
			break
		}
	}
	trailer, err := nativeHTTP2RequestTrailerFields(req.Trailer)
	if err != nil {
		return err
	}
	if len(trailer) > 0 {
		if err := s.validateOutboundHeaderList(trailer); err != nil {
			return err
		}
		block, err := s.encodeHeaderFields(trailer)
		if err != nil {
			return err
		}
		if err := s.writeHeaderBlock(ctx, st.id, block, true); err != nil {
			return err
		}
	} else if err := s.sendData(ctx, st, nil, true); err != nil {
		return err
	}
	st.markLocalClosed()
	return nil
}

func (s *nativeHTTP2Session) encodeRequestHeaders(req *http.Request) ([]byte, error) {
	fields, err := nativeHTTP2RequestHeaderFields(req)
	if err != nil {
		return nil, err
	}
	if err := s.validateOutboundHeaderList(fields); err != nil {
		return nil, err
	}
	return s.encodeHeaderFields(fields)
}

func nativeHTTP2RequestHeaderFields(req *http.Request) ([]hpack.HeaderField, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("request URL is required")
	}
	method := req.Method
	if method == "" || strings.TrimSpace(method) != method {
		return nil, fmt.Errorf("invalid request method %q", req.Method)
	}
	if !nativeHTTP1SafeToken(method) {
		return nil, fmt.Errorf("invalid request method %q", method)
	}
	scheme := strings.ToLower(strings.TrimSpace(req.URL.Scheme))
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("native http2 unsupported scheme %q", req.URL.Scheme)
	}
	authority := strings.TrimSpace(req.Host)
	if authority == "" {
		authority = strings.TrimSpace(req.URL.Host)
	}
	if authority == "" || strings.ContainsAny(authority, "\r\n\x00") {
		return nil, fmt.Errorf("invalid upstream :authority")
	}
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	if !nativeHTTP2SafePath(path) {
		return nil, fmt.Errorf("invalid upstream :path")
	}
	fields := []hpack.HeaderField{
		{Name: ":method", Value: method},
		{Name: ":scheme", Value: scheme},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}
	if req.ContentLength > 0 && req.Body != nil && req.Body != http.NoBody {
		fields = append(fields, hpack.HeaderField{Name: "content-length", Value: strconv.FormatInt(req.ContentLength, 10)})
	}
	trailerNames, err := nativeHTTP2RequestTrailerDeclaration(req.Trailer)
	if err != nil {
		return nil, err
	}
	if trailerNames != "" {
		fields = append(fields, hpack.HeaderField{Name: "trailer", Value: trailerNames})
	}
	for name, values := range req.Header {
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "host" {
			return nil, fmt.Errorf("duplicate HTTP/2 authority via Host header")
		}
		if lower == "" || lower == "content-length" || lower == "trailer" {
			continue
		}
		if nativeHTTP2ForbiddenHeader(lower) {
			return nil, fmt.Errorf("forbidden HTTP/2 request header %q", name)
		}
		if lower == "te" {
			for _, value := range values {
				if strings.ToLower(strings.TrimSpace(value)) != "trailers" {
					return nil, fmt.Errorf("forbidden HTTP/2 TE request value %q", value)
				}
			}
		}
		if !nativeHTTP2SafeHeaderName(lower) {
			return nil, fmt.Errorf("invalid HTTP/2 request header %q", name)
		}
		for _, value := range values {
			if !nativeHTTP1SafeHeaderValue(value) {
				return nil, fmt.Errorf("invalid HTTP/2 request header value for %q", name)
			}
			fields = append(fields, hpack.HeaderField{Name: lower, Value: value})
		}
	}
	return fields, nil
}

func nativeHTTP2RequestTrailerDeclaration(trailer http.Header) (string, error) {
	if len(trailer) == 0 {
		return "", nil
	}
	names := make([]string, 0, len(trailer))
	for name := range trailer {
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "" {
			continue
		}
		if nativeHTTP2ForbiddenHeader(lower) || lower == "te" || lower == "content-length" {
			return "", fmt.Errorf("forbidden HTTP/2 request trailer %q", name)
		}
		if !nativeHTTP2SafeHeaderName(lower) {
			return "", fmt.Errorf("invalid HTTP/2 request trailer %q", name)
		}
		names = append(names, lower)
	}
	if len(names) == 0 {
		return "", nil
	}
	sort.Strings(names)
	return strings.Join(names, ", "), nil
}

func nativeHTTP2RequestTrailerFields(trailer http.Header) ([]hpack.HeaderField, error) {
	if len(trailer) == 0 {
		return nil, nil
	}
	var fields []hpack.HeaderField
	for name, values := range trailer {
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "" {
			continue
		}
		if nativeHTTP2ForbiddenHeader(lower) || lower == "te" || lower == "content-length" {
			return nil, fmt.Errorf("forbidden HTTP/2 request trailer %q", name)
		}
		if !nativeHTTP2SafeHeaderName(lower) {
			return nil, fmt.Errorf("invalid HTTP/2 request trailer %q", name)
		}
		for _, value := range values {
			if value == "" {
				continue
			}
			if !nativeHTTP1SafeHeaderValue(value) {
				return nil, fmt.Errorf("invalid HTTP/2 request trailer value for %q", name)
			}
			fields = append(fields, hpack.HeaderField{Name: lower, Value: value})
		}
	}
	return fields, nil
}

func (s *nativeHTTP2Session) encodeHeaderFields(fields []hpack.HeaderField) ([]byte, error) {
	s.hpackMu.Lock()
	defer s.hpackMu.Unlock()
	s.hpackBuf.Reset()
	for _, field := range fields {
		if err := s.hpackEnc.WriteField(field); err != nil {
			return nil, err
		}
	}
	out := make([]byte, s.hpackBuf.Len())
	copy(out, s.hpackBuf.Bytes())
	return out, nil
}

func (s *nativeHTTP2Session) validateOutboundHeaderList(fields []hpack.HeaderField) error {
	limit := s.maxHeaderListSize()
	if limit == 0 {
		return nil
	}
	var total uint64
	for _, field := range fields {
		total += uint64(len(field.Name) + len(field.Value) + 32)
		if total > uint64(limit) {
			return fmt.Errorf("native http2 outbound header list size %d exceeds peer limit %d", total, limit)
		}
	}
	return nil
}

func (s *nativeHTTP2Session) maxHeaderListSize() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remoteMaxHeaderList
}

func (s *nativeHTTP2Session) writeHeaderBlock(ctx context.Context, streamID uint32, block []byte, endStream bool) error {
	maxFrame := s.maxFrameSize()
	return s.writeFrame(ctx, func(fr *http2.Framer) error {
		first := block
		if uint32(len(first)) > maxFrame {
			first = block[:maxFrame]
		}
		rest := block[len(first):]
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: first,
			EndStream:     endStream,
			EndHeaders:    len(rest) == 0,
		}); err != nil {
			return err
		}
		for len(rest) > 0 {
			part := rest
			if uint32(len(part)) > maxFrame {
				part = rest[:maxFrame]
			}
			rest = rest[len(part):]
			if err := fr.WriteContinuation(streamID, len(rest) == 0, part); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *nativeHTTP2Session) sendData(ctx context.Context, st *nativeHTTP2Stream, data []byte, endStream bool) error {
	for len(data) > 0 {
		n, err := s.reserveSendWindow(ctx, st, len(data))
		if err != nil {
			return err
		}
		part := data[:n]
		if err := s.writeFrame(ctx, func(fr *http2.Framer) error {
			return fr.WriteData(st.id, false, part)
		}); err != nil {
			return err
		}
		data = data[n:]
	}
	if endStream {
		if err := s.writeFrame(ctx, func(fr *http2.Framer) error {
			return fr.WriteData(st.id, true, nil)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *nativeHTTP2Session) reserveSendWindow(ctx context.Context, st *nativeHTTP2Stream, want int) (int, error) {
	if want <= 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		if s.closed {
			err := s.lastErr
			s.mu.Unlock()
			if err == nil {
				err = errNativeHTTP2StreamClosed
			}
			return 0, err
		}
		if _, ok := s.streams[st.id]; !ok {
			s.mu.Unlock()
			return 0, errNativeHTTP2StreamClosed
		}
		allowed := int64(want)
		if maxFrame := int64(s.remoteMaxFrameSize); allowed > maxFrame {
			allowed = maxFrame
		}
		if allowed > s.connSendWindow {
			allowed = s.connSendWindow
		}
		if allowed > st.sendWindow {
			allowed = st.sendWindow
		}
		if allowed > 0 {
			s.connSendWindow -= allowed
			st.sendWindow -= allowed
			s.mu.Unlock()
			return int(allowed), nil
		}
		notify := s.windowNotify
		s.mu.Unlock()
		if err := s.waitSendWindow(ctx, st, notify); err != nil {
			return 0, err
		}
	}
}

func (s *nativeHTTP2Session) waitSendWindow(ctx context.Context, st *nativeHTTP2Stream, notify <-chan struct{}) error {
	wait := s.flowControlWait()
	if wait <= 0 {
		select {
		case <-notify:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-st.done:
			return errNativeHTTP2StreamClosed
		case <-s.done:
			return s.error()
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-notify:
		return nil
	case <-timer.C:
		return nativeHTTP2FlowControlWindowTimeoutError{Wait: wait}
	case <-ctx.Done():
		return ctx.Err()
	case <-st.done:
		return errNativeHTTP2StreamClosed
	case <-s.done:
		return s.error()
	}
}

func (s *nativeHTTP2Session) flowControlWait() time.Duration {
	if s != nil && s.transport != nil && s.transport.headerWait > 0 {
		return s.transport.headerWait
	}
	return nativeHTTP2DefaultSettingsWait
}

func (s *nativeHTTP2Session) writeFrame(ctx context.Context, fn func(*http2.Framer) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan error, 1)
	req := nativeHTTP2Write{ctx: ctx, fn: fn, done: done}
	select {
	case s.writeCh <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.error()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.error()
	}
}

func (s *nativeHTTP2Session) writeFrameBestEffort(fn func(*http2.Framer) error) {
	if fn == nil {
		return
	}
	select {
	case s.writeCh <- nativeHTTP2Write{ctx: context.Background(), fn: fn}:
	case <-s.done:
	default:
	}
}

func (s *nativeHTTP2Session) writeWindowUpdate(streamID uint32, n uint32) error {
	if n == 0 {
		return nil
	}
	return s.writeFrame(context.Background(), func(fr *http2.Framer) error {
		return fr.WriteWindowUpdate(streamID, n)
	})
}

func (s *nativeHTTP2Session) resetStream(streamID uint32, code http2.ErrCode) {
	s.writeFrameBestEffort(func(fr *http2.Framer) error {
		return fr.WriteRSTStream(streamID, code)
	})
}

func (s *nativeHTTP2Session) stream(id uint32) *nativeHTTP2Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *nativeHTTP2Session) failStream(id uint32, err error) {
	if st := s.stream(id); st != nil {
		s.releaseStream(st, err)
	}
}

func (s *nativeHTTP2Session) releaseStream(st *nativeHTTP2Stream, err error) {
	if st == nil {
		return
	}
	st.closeOnce.Do(func() {
		var closeDrainedSession bool
		responseQueued := st.responseQueuedForCaller()
		st.setTerminalError(err)
		s.mu.Lock()
		if _, ok := s.streams[st.id]; ok {
			delete(s.streams, st.id)
			if s.activeStreams > 0 {
				s.activeStreams--
			}
		}
		st.state = nativeHTTP2StreamClosed
		closeDrainedSession = s.registered && !s.closed && s.activeStreams == 0 && s.remoteMaxStreams == 0
		s.notifyWindowLocked()
		s.mu.Unlock()
		if err != nil && !responseQueued {
			select {
			case st.errCh <- err:
			default:
			}
		}
		close(st.done)
		if s.transport != nil {
			s.transport.signalWaiter(s.key)
		}
		if closeDrainedSession {
			s.closeWithError(fmt.Errorf("native http2 upstream disabled concurrent streams"))
		}
	})
}

func (s *nativeHTTP2Session) closeWithError(err error) {
	if err == nil {
		err = errNativeHTTP2StreamClosed
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		registered := s.registered
		s.closed = true
		s.reusable = false
		s.lastErr = err
		streams := make([]*nativeHTTP2Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.streams = make(map[uint32]*nativeHTTP2Stream)
		s.activeStreams = 0
		s.notifyWindowLocked()
		s.mu.Unlock()
		close(s.closeCh)
		_ = s.conn.Close()
		for _, st := range streams {
			responseQueued := st.responseQueuedForCaller()
			remoteClosed := st.remoteClosedSeen()
			if !responseQueued || !remoteClosed {
				st.setTerminalError(err)
			}
			if !responseQueued {
				select {
				case st.errCh <- err:
				default:
				}
			}
			st.closeOnce.Do(func() { close(st.done) })
		}
		if s.transport != nil {
			if registered {
				s.transport.removeSession(s)
			}
		}
	})
}

func (s *nativeHTTP2Session) notifyWindowLocked() {
	close(s.windowNotify)
	s.windowNotify = make(chan struct{})
}

func (s *nativeHTTP2Session) maxFrameSize() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.remoteMaxFrameSize == 0 {
		return nativeHTTP2DefaultMaxFrameSize
	}
	return s.remoteMaxFrameSize
}

func (s *nativeHTTP2Session) idle() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeStreams == 0
}

func (s *nativeHTTP2Session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *nativeHTTP2Session) error() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastErr != nil {
		return s.lastErr
	}
	return errNativeHTTP2StreamClosed
}

type nativeHTTP2StreamState uint8

const (
	nativeHTTP2StreamIdle nativeHTTP2StreamState = iota
	nativeHTTP2StreamOpen
	nativeHTTP2StreamHalfClosedLocal
	nativeHTTP2StreamHalfClosedRemote
	nativeHTTP2StreamClosed
	nativeHTTP2StreamReset
)

type nativeHTTP2Stream struct {
	session *nativeHTTP2Session
	id      uint32
	req     *http.Request

	mu              sync.Mutex
	state           nativeHTTP2StreamState
	sendWindow      int64
	recvLength      int64
	expectedLength  int64
	localClosed     bool
	remoteClosed    bool
	startedResponse bool
	hasExpectedLen  bool
	noBodyExpected  bool
	trailersSeen    bool
	response        *http.Response
	terminalErr     error
	responseQueued  bool

	responseCh chan *http.Response
	errCh      chan error
	bodyCh     chan nativeHTTP2BodyEvent
	done       chan struct{}
	closeOnce  sync.Once
}

type nativeHTTP2BodyEvent struct {
	data []byte
	eof  bool
}

type nativeHTTP2StreamError struct {
	StreamID uint32
	Code     http2.ErrCode
}

func (e nativeHTTP2StreamError) Error() string {
	return fmt.Sprintf("native http2 stream %d reset by upstream: %s", e.StreamID, e.Code)
}

type nativeHTTP2RapidResetError struct {
	Count  int
	Window time.Duration
}

func (e nativeHTTP2RapidResetError) Error() string {
	return fmt.Sprintf("native http2 upstream rapid reset limit exceeded: %d RST_STREAM frames within %s", e.Count, e.Window)
}

type nativeHTTP2FlowControlWindowTimeoutError struct {
	Wait time.Duration
}

func (e nativeHTTP2FlowControlWindowTimeoutError) Error() string {
	return fmt.Sprintf("native http2 flow-control window timeout after %s", e.Wait)
}

func nativeHTTP2IsFlowControlWindowTimeout(err error) bool {
	var target nativeHTTP2FlowControlWindowTimeoutError
	return errors.As(err, &target)
}

func (st *nativeHTTP2Stream) responseStarted() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.startedResponse
}

func (st *nativeHTTP2Stream) remoteClosedSeen() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.remoteClosed
}

func (st *nativeHTTP2Stream) trailersObserved() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.trailersSeen
}

func (st *nativeHTTP2Stream) markResponseStarted(resp *http.Response) {
	st.mu.Lock()
	st.startedResponse = true
	st.response = resp
	st.noBodyExpected = resp != nil && resp.Request != nil && (resp.Request.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified)
	if resp != nil && resp.ContentLength >= 0 && !st.noBodyExpected {
		st.hasExpectedLen = true
		st.expectedLength = resp.ContentLength
	}
	st.mu.Unlock()
}

func (st *nativeHTTP2Stream) responseQueuedForCaller() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.responseQueued
}

func (st *nativeHTTP2Stream) queueResponse(resp *http.Response) {
	st.mu.Lock()
	st.responseQueued = true
	st.mu.Unlock()
	select {
	case st.responseCh <- resp:
	case <-st.done:
	}
}

func (st *nativeHTTP2Stream) markLocalClosed() {
	st.mu.Lock()
	st.localClosed = true
	if st.remoteClosed {
		st.state = nativeHTTP2StreamClosed
	} else {
		st.state = nativeHTTP2StreamHalfClosedLocal
	}
	st.mu.Unlock()
}

func (st *nativeHTTP2Stream) markRemoteClosed() {
	st.mu.Lock()
	st.remoteClosed = true
	if st.localClosed {
		st.state = nativeHTTP2StreamClosed
	} else {
		st.state = nativeHTTP2StreamHalfClosedRemote
	}
	st.mu.Unlock()
}

func (st *nativeHTTP2Stream) markTrailers(trailer http.Header) error {
	st.mu.Lock()
	if st.trailersSeen {
		st.mu.Unlock()
		return fmt.Errorf("native http2 duplicate response trailers")
	}
	st.trailersSeen = true
	resp := st.response
	st.mu.Unlock()
	if len(trailer) == 0 {
		return nil
	}
	if resp == nil {
		return nil
	}
	if resp.Trailer == nil {
		resp.Trailer = make(http.Header)
	}
	for name, values := range trailer {
		for _, value := range values {
			resp.Trailer.Add(name, value)
		}
	}
	return nil
}

func (st *nativeHTTP2Stream) mergeTrailers(trailer http.Header) {
	_ = st.markTrailers(trailer)
}

func (st *nativeHTTP2Stream) sendBodyEvent(ev nativeHTTP2BodyEvent) bool {
	select {
	case st.bodyCh <- ev:
		return true
	case <-st.done:
		return false
	case <-st.session.done:
		return false
	}
}

func (st *nativeHTTP2Stream) acceptData(n int) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.noBodyExpected {
		return fmt.Errorf("native http2 upstream sent DATA for response without a body")
	}
	if st.hasExpectedLen {
		st.recvLength += int64(n)
		if st.recvLength > st.expectedLength {
			return fmt.Errorf("native http2 upstream response exceeded Content-Length")
		}
	}
	return nil
}

func (st *nativeHTTP2Stream) validateEndStream() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.hasExpectedLen && st.recvLength != st.expectedLength {
		return fmt.Errorf("native http2 upstream response Content-Length mismatch")
	}
	return nil
}

func (st *nativeHTTP2Stream) setTerminalError(err error) {
	if err == nil {
		return
	}
	st.mu.Lock()
	if st.terminalErr == nil {
		st.terminalErr = err
	}
	st.mu.Unlock()
}

func (st *nativeHTTP2Stream) terminalError() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.terminalErr
}

type nativeHTTP2ResponseBody struct {
	stream *nativeHTTP2Stream
	buf    []byte
	eof    bool
	once   sync.Once
}

func (b *nativeHTTP2ResponseBody) Read(p []byte) (int, error) {
	if b == nil || b.stream == nil {
		return 0, io.EOF
	}
	for len(b.buf) == 0 {
		if b.eof {
			return 0, io.EOF
		}
		select {
		case ev := <-b.stream.bodyCh:
			if len(ev.data) > 0 {
				b.buf = ev.data
				break
			}
			if ev.eof {
				b.eof = true
				b.stream.session.releaseStream(b.stream, nil)
				return 0, io.EOF
			}
		case <-b.stream.done:
			if err := b.stream.terminalError(); err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	if err := b.stream.session.writeWindowUpdate(b.stream.id, uint32(n)); err != nil {
		b.stream.session.releaseStream(b.stream, err)
		return n, err
	}
	return n, nil
}

func (b *nativeHTTP2ResponseBody) Close() error {
	if b == nil || b.stream == nil {
		return nil
	}
	b.once.Do(func() {
		if !b.eof {
			b.stream.session.resetStream(b.stream.id, http2.ErrCodeCancel)
		}
		b.stream.session.releaseStream(b.stream, nil)
	})
	return nil
}

func nativeHTTP2DecodeResponseHeaders(f *http2.MetaHeadersFrame, req *http.Request) (*http.Response, bool, error) {
	statusRaw := ""
	header := make(http.Header)
	declaredTrailers := make(http.Header)
	for _, field := range f.Fields {
		name := strings.ToLower(field.Name)
		if field.IsPseudo() {
			if name != ":status" {
				return nil, false, fmt.Errorf("forbidden HTTP/2 response pseudo-header %q", field.Name)
			}
			if statusRaw != "" {
				return nil, false, fmt.Errorf("duplicate HTTP/2 response :status")
			}
			statusRaw = field.Value
			continue
		}
		if name == "trailer" {
			for _, part := range strings.Split(field.Value, ",") {
				trailerName := http.CanonicalHeaderKey(strings.TrimSpace(part))
				if trailerName == "" {
					continue
				}
				if !nativeHTTP1SafeHeaderName(trailerName) {
					return nil, false, fmt.Errorf("invalid HTTP/2 response trailer declaration %q", trailerName)
				}
				declaredTrailers[trailerName] = nil
			}
			continue
		}
		if err := nativeHTTP2AddDecodedHeader(header, name, field.Value); err != nil {
			return nil, false, err
		}
	}
	if statusRaw == "" {
		return nil, false, fmt.Errorf("missing HTTP/2 response :status")
	}
	code, err := strconv.Atoi(statusRaw)
	if err != nil || code < 100 || code > 999 {
		return nil, false, fmt.Errorf("invalid HTTP/2 response :status %q", statusRaw)
	}
	if code == http.StatusSwitchingProtocols {
		return nil, false, fmt.Errorf("HTTP/2 upstream response cannot use 101 Switching Protocols")
	}
	resp := &http.Response{
		StatusCode:    code,
		Status:        fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        header,
		Trailer:       make(http.Header),
		ContentLength: -1,
		Request:       req,
	}
	for name := range declaredTrailers {
		resp.Trailer[name] = nil
	}
	if req != nil && (req.Method == http.MethodHead || code == http.StatusNoContent || code == http.StatusNotModified) {
		resp.ContentLength = 0
		return resp, code >= 100 && code < 200, nil
	}
	if rawLength, ok, err := nativeHTTP1ContentLength(header); err != nil {
		return nil, false, err
	} else if ok {
		length, err := strconv.ParseInt(rawLength, 10, 64)
		if err != nil || length < 0 {
			return nil, false, fmt.Errorf("invalid HTTP/2 response Content-Length %q", rawLength)
		}
		resp.ContentLength = length
	}
	return resp, code >= 100 && code < 200 && code != http.StatusSwitchingProtocols, nil
}

func nativeHTTP2DecodeTrailers(f *http2.MetaHeadersFrame) (http.Header, error) {
	trailer := make(http.Header)
	for _, field := range f.Fields {
		name := strings.ToLower(field.Name)
		if field.IsPseudo() {
			return nil, fmt.Errorf("forbidden HTTP/2 trailer pseudo-header %q", field.Name)
		}
		if err := nativeHTTP2AddDecodedHeader(trailer, name, field.Value); err != nil {
			return nil, err
		}
	}
	return trailer, nil
}

func nativeHTTP2AddDecodedHeader(header http.Header, lowerName string, value string) error {
	if nativeHTTP2ForbiddenHeader(lowerName) {
		return fmt.Errorf("forbidden HTTP/2 response header %q", lowerName)
	}
	if lowerName == "te" && strings.ToLower(strings.TrimSpace(value)) != "trailers" {
		return fmt.Errorf("forbidden HTTP/2 TE response value %q", value)
	}
	if !nativeHTTP2SafeHeaderName(lowerName) || !nativeHTTP1SafeHeaderValue(value) {
		return fmt.Errorf("invalid HTTP/2 response header %q", lowerName)
	}
	canonical := http.CanonicalHeaderKey(lowerName)
	if strings.EqualFold(canonical, "Set-Cookie") {
		header.Add(canonical, value)
		return nil
	}
	if existing := header.Get(canonical); existing != "" {
		header.Set(canonical, existing+", "+value)
	} else {
		header.Set(canonical, value)
	}
	return nil
}

func nativeHTTP2ForbiddenHeader(lowerName string) bool {
	switch strings.ToLower(strings.TrimSpace(lowerName)) {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func nativeHTTP2SafeHeaderName(name string) bool {
	if name == "" || strings.ContainsAny(name, "\r\n\x00") {
		return false
	}
	if name != strings.ToLower(name) {
		return false
	}
	return nativeHTTP1SafeHeaderName(name)
}

func nativeHTTP2SafePath(path string) bool {
	if path == "" {
		return false
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c < 0x20 || c == 0x7f || c >= 0x80 {
			return false
		}
	}
	return true
}
