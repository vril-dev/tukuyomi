package handler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"
)

type nativeHTTP1Transport struct {
	cfg        ProxyRulesConfig
	profile    proxyTransportProfile
	tlsConfig  *tls.Config
	dialer     net.Dialer
	headerWait time.Duration
	tlsWait    time.Duration
	idleWait   time.Duration
	maxIdle    int
	maxIdleKey int
	maxConns   int

	mu         sync.Mutex
	idle       map[nativeHTTP1ConnKey][]*nativeHTTP1PooledConn
	active     map[nativeHTTP1ConnKey]int
	waiters    map[nativeHTTP1ConnKey][]chan struct{}
	totalIdle  int
	poolClosed bool
}

type nativeHTTP1ConnKey struct {
	scheme     string
	address    string
	serverName string
}

type nativeHTTP1PooledConn struct {
	key    nativeHTTP1ConnKey
	conn   net.Conn
	br     *bufio.Reader
	idleAt time.Time
}

func buildProxyNativeHTTP1Transport(cfg ProxyRulesConfig, profile proxyTransportProfile) (*nativeHTTP1Transport, error) {
	tlsCfg, err := buildProxyTLSClientConfigForProfile(profile.TLS)
	if err != nil {
		return nil, err
	}
	return &nativeHTTP1Transport{
		cfg:       cfg,
		profile:   profile,
		tlsConfig: tlsCfg,
		dialer: net.Dialer{
			Timeout:   time.Duration(cfg.DialTimeout) * time.Second,
			KeepAlive: proxyUpstreamKeepAliveDuration(cfg),
		},
		headerWait: time.Duration(cfg.ResponseHeaderTimeout) * time.Second,
		tlsWait:    5 * time.Second,
		idleWait:   time.Duration(cfg.IdleConnTimeout) * time.Second,
		maxIdle:    cfg.MaxIdleConns,
		maxIdleKey: cfg.MaxIdleConnsPerHost,
		maxConns:   cfg.MaxConnsPerHost,
		idle:       make(map[nativeHTTP1ConnKey][]*nativeHTTP1PooledConn),
		active:     make(map[nativeHTTP1ConnKey]int),
		waiters:    make(map[nativeHTTP1ConnKey][]chan struct{}),
	}, nil
}

func (t *nativeHTTP1Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil {
		return nil, fmt.Errorf("native http1 transport is nil")
	}
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("request URL is required")
	}
	scheme := strings.ToLower(strings.TrimSpace(req.URL.Scheme))
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("native http1 transport unsupported scheme %q", req.URL.Scheme)
	}
	address, err := proxyDialAddress(req.URL)
	if err != nil {
		return nil, err
	}
	key := nativeHTTP1ConnKey{
		scheme:     scheme,
		address:    address,
		serverName: nativeHTTP1ServerName(t.tlsConfig, req.URL.Hostname()),
	}

	ctx := req.Context()
	pc, err := t.acquireConn(ctx, key, req.URL.Hostname())
	if err != nil {
		return nil, err
	}
	releaseConn := true
	defer func() {
		if releaseConn {
			t.releaseConn(pc, false)
		}
	}()

	stopContextWatch := nativeHTTP1CloseOnContextDone(ctx, pc.conn)
	if err := nativeHTTP1WriteRequest(pc.conn, req); err != nil {
		stopContextWatch()
		return nil, err
	}
	if t.headerWait > 0 {
		_ = pc.conn.SetReadDeadline(time.Now().Add(t.headerWait))
	}
	if pc.br == nil {
		pc.br = bufio.NewReader(pc.conn)
	}
	resp, err := nativeHTTP1ReadFinalResponse(pc.br, req)
	if err != nil {
		stopContextWatch()
		return nil, err
	}
	_ = pc.conn.SetReadDeadline(time.Time{})

	if resp.StatusCode == http.StatusSwitchingProtocols {
		resp.Body = &nativeHTTP1UpgradeBody{transport: t, pc: pc, br: pc.br, stopContextWatch: stopContextWatch}
		releaseConn = false
		return resp, nil
	}

	resp.Body = nativeHTTP1ResponseBody(t, resp, pc, stopContextWatch)
	releaseConn = false
	return resp, nil
}

func (t *nativeHTTP1Transport) CloseIdleConnections() {
	if t == nil {
		return
	}
	var closing []*nativeHTTP1PooledConn
	t.mu.Lock()
	for key, conns := range t.idle {
		closing = append(closing, conns...)
		t.active[key] -= len(conns)
		if t.active[key] <= 0 {
			delete(t.active, key)
		}
		delete(t.idle, key)
		t.signalWaiterLocked(key)
	}
	t.totalIdle = 0
	t.mu.Unlock()
	for _, pc := range closing {
		_ = pc.conn.Close()
	}
}

func nativeHTTP1ServerName(tlsCfg *tls.Config, hostname string) string {
	if tlsCfg != nil && strings.TrimSpace(tlsCfg.ServerName) != "" {
		return strings.TrimSpace(tlsCfg.ServerName)
	}
	return strings.TrimSpace(hostname)
}

func (t *nativeHTTP1Transport) acquireConn(ctx context.Context, key nativeHTTP1ConnKey, hostname string) (*nativeHTTP1PooledConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if pc := t.takeIdleConn(key); pc != nil {
			return pc, nil
		}

		waiter, canDial, err := t.reserveConnOrWait(ctx, key)
		if err != nil {
			return nil, err
		}
		if canDial {
			conn, err := t.dialConn(ctx, key, hostname)
			if err != nil {
				t.releaseConnSlot(key)
				return nil, err
			}
			return &nativeHTTP1PooledConn{key: key, conn: conn, br: bufio.NewReader(conn)}, nil
		}
		select {
		case <-ctx.Done():
			t.removeConnWaiter(key, waiter)
			return nil, ctx.Err()
		case <-waiter:
		}
	}
}

func (t *nativeHTTP1Transport) takeIdleConn(key nativeHTTP1ConnKey) *nativeHTTP1PooledConn {
	var expired []*nativeHTTP1PooledConn
	defer func() {
		for _, pc := range expired {
			_ = pc.conn.Close()
		}
	}()

	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		conns := t.idle[key]
		if len(conns) == 0 {
			delete(t.idle, key)
			return nil
		}
		pc := conns[len(conns)-1]
		conns = conns[:len(conns)-1]
		if len(conns) == 0 {
			delete(t.idle, key)
		} else {
			t.idle[key] = conns
		}
		t.totalIdle--
		if t.idleConnExpiredLocked(pc) {
			t.active[key]--
			if t.active[key] <= 0 {
				delete(t.active, key)
			}
			expired = append(expired, pc)
			continue
		}
		return pc
	}
}

func (t *nativeHTTP1Transport) idleConnExpiredLocked(pc *nativeHTTP1PooledConn) bool {
	if pc == nil || pc.conn == nil {
		return true
	}
	if t.poolClosed {
		return true
	}
	if pc.br != nil && pc.br.Buffered() > 0 {
		return true
	}
	return t.idleWait > 0 && !pc.idleAt.IsZero() && time.Since(pc.idleAt) > t.idleWait
}

func (t *nativeHTTP1Transport) reserveConnOrWait(ctx context.Context, key nativeHTTP1ConnKey) (chan struct{}, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.poolClosed {
		return nil, false, fmt.Errorf("native http1 transport is closed")
	}
	if t.maxConns <= 0 || t.active[key] < t.maxConns {
		t.active[key]++
		return nil, true, nil
	}
	waiter := make(chan struct{})
	t.waiters[key] = append(t.waiters[key], waiter)
	return waiter, false, nil
}

func (t *nativeHTTP1Transport) removeConnWaiter(key nativeHTTP1ConnKey, waiter chan struct{}) {
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

func (t *nativeHTTP1Transport) dialConn(ctx context.Context, key nativeHTTP1ConnKey, hostname string) (net.Conn, error) {
	conn, err := t.dialer.DialContext(ctx, "tcp", key.address)
	if err != nil {
		return nil, err
	}
	if key.scheme != "https" {
		return conn, nil
	}
	tlsConn, err := t.handshakeTLS(ctx, conn, hostname)
	if err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func (t *nativeHTTP1Transport) releaseConn(pc *nativeHTTP1PooledConn, reusable bool) {
	if pc == nil || pc.conn == nil {
		return
	}
	var closeConn bool
	t.mu.Lock()
	if reusable && !t.poolClosed && (t.maxIdle <= 0 || t.totalIdle < t.maxIdle) && (t.maxIdleKey <= 0 || len(t.idle[pc.key]) < t.maxIdleKey) {
		pc.idleAt = time.Now()
		t.idle[pc.key] = append(t.idle[pc.key], pc)
		t.totalIdle++
		t.signalWaiterLocked(pc.key)
		t.mu.Unlock()
		return
	}
	closeConn = true
	t.active[pc.key]--
	if t.active[pc.key] <= 0 {
		delete(t.active, pc.key)
	}
	t.signalWaiterLocked(pc.key)
	t.mu.Unlock()
	if closeConn {
		_ = pc.conn.Close()
	}
}

func (t *nativeHTTP1Transport) releaseConnSlot(key nativeHTTP1ConnKey) {
	t.mu.Lock()
	t.active[key]--
	if t.active[key] <= 0 {
		delete(t.active, key)
	}
	t.signalWaiterLocked(key)
	t.mu.Unlock()
}

func (t *nativeHTTP1Transport) signalWaiterLocked(key nativeHTTP1ConnKey) {
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

func (t *nativeHTTP1Transport) handshakeTLS(ctx context.Context, raw net.Conn, hostname string) (*tls.Conn, error) {
	cfg := &tls.Config{ServerName: hostname, NextProtos: []string{"http/1.1"}}
	if t.tlsConfig != nil {
		cfg = t.tlsConfig.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = hostname
		}
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{"http/1.1"}
		}
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
	return conn, nil
}

func nativeHTTP1CloseOnContextDone(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() {
		once.Do(func() {
			close(done)
		})
	}
}

func nativeHTTP1WriteRequest(w io.Writer, req *http.Request) error {
	plan, err := nativeHTTP1PrepareRequestWrite(req)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(w)
	if _, err := fmt.Fprintf(bw, "%s %s HTTP/1.1\r\n", plan.method, plan.uri); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(bw, "Host: %s\r\n", plan.host); err != nil {
		return err
	}
	for _, header := range plan.headers {
		if _, err := fmt.Fprintf(bw, "%s: %s\r\n", header.name, header.value); err != nil {
			return err
		}
	}
	if plan.writeClose {
		if _, err := io.WriteString(bw, "Connection: close\r\n"); err != nil {
			return err
		}
	}
	if plan.contentLength >= 0 {
		if _, err := fmt.Fprintf(bw, "Content-Length: %d\r\n", plan.contentLength); err != nil {
			return err
		}
	}
	if plan.useChunked {
		if _, err := io.WriteString(bw, "Transfer-Encoding: chunked\r\n"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(bw, "\r\n"); err != nil {
		return err
	}
	if plan.hasBody {
		if plan.useChunked {
			if err := nativeHTTP1WriteChunkedBody(bw, req.Body, plan.trailers); err != nil {
				return err
			}
		} else if plan.contentLength > 0 {
			if _, err := io.CopyN(bw, req.Body, plan.contentLength); err != nil {
				return err
			}
		}
	}
	return bw.Flush()
}

type nativeHTTP1HeaderLine struct {
	name  string
	value string
}

type nativeHTTP1RequestWritePlan struct {
	method        string
	uri           string
	host          string
	headers       []nativeHTTP1HeaderLine
	trailers      http.Header
	hasBody       bool
	useChunked    bool
	writeClose    bool
	contentLength int64
}

func nativeHTTP1PrepareRequestWrite(req *http.Request) (nativeHTTP1RequestWritePlan, error) {
	if req == nil || req.URL == nil {
		return nativeHTTP1RequestWritePlan{}, fmt.Errorf("request URL is required")
	}
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	if strings.ContainsAny(uri, "\r\n") || strings.ContainsAny(uri, " \t") {
		return nativeHTTP1RequestWritePlan{}, fmt.Errorf("invalid upstream request URI")
	}
	method := strings.TrimSpace(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	if !nativeHTTP1SafeToken(method) {
		return nativeHTTP1RequestWritePlan{}, fmt.Errorf("invalid request method %q", method)
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		host = strings.TrimSpace(req.URL.Host)
	}
	if host == "" || strings.ContainsAny(host, "\r\n \t") {
		return nativeHTTP1RequestWritePlan{}, fmt.Errorf("invalid upstream Host header")
	}

	hasUpgrade := proxyUpgradeType(req.Header) != ""
	hasBody := req.Body != nil && req.Body != http.NoBody
	plan := nativeHTTP1RequestWritePlan{
		method:        method,
		uri:           uri,
		host:          host,
		hasBody:       hasBody,
		useChunked:    hasBody && req.ContentLength < 0,
		writeClose:    req.Close && !hasUpgrade,
		contentLength: -1,
	}
	if hasBody && req.ContentLength >= 0 {
		plan.contentLength = req.ContentLength
	}
	for name, values := range req.Header {
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "Host" || canonical == "Content-Length" || canonical == "Transfer-Encoding" {
			continue
		}
		if !nativeHTTP1SafeHeaderName(canonical) {
			return nativeHTTP1RequestWritePlan{}, fmt.Errorf("invalid upstream request header %q", name)
		}
		for _, value := range values {
			if !nativeHTTP1SafeHeaderValue(value) {
				return nativeHTTP1RequestWritePlan{}, fmt.Errorf("invalid upstream request header value for %q", name)
			}
			plan.headers = append(plan.headers, nativeHTTP1HeaderLine{name: canonical, value: value})
		}
	}
	trailers, err := nativeHTTP1ValidateTrailers(req.Trailer)
	if err != nil {
		return nativeHTTP1RequestWritePlan{}, err
	}
	plan.trailers = trailers
	return plan, nil
}

func nativeHTTP1ValidateTrailers(trailer http.Header) (http.Header, error) {
	if len(trailer) == 0 {
		return nil, nil
	}
	out := make(http.Header, len(trailer))
	for name, values := range trailer {
		canonical := http.CanonicalHeaderKey(name)
		if !nativeHTTP1SafeHeaderName(canonical) {
			return nil, fmt.Errorf("invalid upstream request trailer %q", name)
		}
		for _, value := range values {
			if !nativeHTTP1SafeHeaderValue(value) {
				return nil, fmt.Errorf("invalid upstream request trailer value for %q", name)
			}
			out.Add(canonical, value)
		}
	}
	return out, nil
}

func nativeHTTP1WriteChunkedBody(w *bufio.Writer, body io.Reader, trailer http.Header) error {
	buf := proxyReverseCopyBufferPool.Get()
	defer proxyReverseCopyBufferPool.Put(buf)
	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			if _, err := fmt.Fprintf(w, "%x\r\n", n); err != nil {
				return err
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return err
			}
			if _, err := io.WriteString(w, "\r\n"); err != nil {
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
	if _, err := io.WriteString(w, "0\r\n"); err != nil {
		return err
	}
	for name, values := range trailer {
		for _, value := range values {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", name, value); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func nativeHTTP1ReadFinalResponse(br *bufio.Reader, req *http.Request) (*http.Response, error) {
	for {
		resp, err := nativeHTTP1ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, nil
		}
		if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.Got1xxResponse != nil {
			if err := trace.Got1xxResponse(resp.StatusCode, textproto.MIMEHeader(resp.Header)); err != nil {
				return nil, err
			}
		}
	}
}

func nativeHTTP1ReadResponse(br *bufio.Reader, req *http.Request) (*http.Response, error) {
	line, err := nativeHTTP1ReadLineLimited(br, nativeHTTP1MaxResponseHeaderBytes)
	if err != nil {
		return nil, err
	}
	major, minor, code, statusText, err := nativeHTTP1ParseStatusLine(line)
	if err != nil {
		return nil, err
	}
	header, err := nativeHTTP1ReadHeaderBlock(br, nativeHTTP1MaxResponseHeaderBytes)
	if err != nil {
		return nil, err
	}
	resp := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, strings.TrimSpace(statusText)),
		Proto:      fmt.Sprintf("HTTP/%d.%d", major, minor),
		ProtoMajor: major,
		ProtoMinor: minor,
		Header:     header,
		Trailer:    make(http.Header),
		Request:    req,
		Close:      nativeHTTP1ResponseWantsClose(header, major, minor),
	}
	if code == http.StatusSwitchingProtocols {
		resp.Close = false
		resp.ContentLength = 0
		return resp, nil
	}
	header.Del("Connection")
	if values := header.Values("Transfer-Encoding"); len(values) > 0 {
		if header.Get("Content-Length") != "" {
			return nil, fmt.Errorf("ambiguous upstream response framing: Transfer-Encoding with Content-Length")
		}
		seenChunked := false
		for _, value := range values {
			for _, part := range strings.Split(value, ",") {
				encoding := strings.ToLower(strings.TrimSpace(part))
				if encoding == "" {
					continue
				}
				if encoding != "chunked" {
					return nil, fmt.Errorf("unsupported upstream transfer encoding %q", encoding)
				}
				if seenChunked {
					return nil, fmt.Errorf("duplicate upstream chunked transfer encoding")
				}
				seenChunked = true
			}
		}
		if !seenChunked {
			return nil, fmt.Errorf("empty upstream transfer encoding")
		}
		for _, value := range header.Values("Trailer") {
			for _, part := range strings.Split(value, ",") {
				name := http.CanonicalHeaderKey(strings.TrimSpace(part))
				if name == "" {
					continue
				}
				if !nativeHTTP1SafeHeaderName(name) {
					return nil, fmt.Errorf("invalid upstream trailer header %q", name)
				}
				resp.Trailer[name] = nil
			}
		}
		header.Del("Transfer-Encoding")
		header.Del("Trailer")
		resp.TransferEncoding = []string{"chunked"}
		resp.ContentLength = -1
		return resp, nil
	}
	if req != nil && (req.Method == http.MethodHead || code == http.StatusNoContent || code == http.StatusNotModified) {
		resp.ContentLength = 0
		return resp, nil
	}
	if rawLength, ok, err := nativeHTTP1ContentLength(header); err != nil {
		return nil, err
	} else if ok {
		length, err := strconv.ParseInt(rawLength, 10, 64)
		if err != nil || length < 0 {
			return nil, fmt.Errorf("invalid upstream Content-Length %q", rawLength)
		}
		resp.ContentLength = length
	} else {
		resp.ContentLength = -1
	}
	return resp, nil
}

func nativeHTTP1ContentLength(header http.Header) (string, bool, error) {
	values := header.Values("Content-Length")
	if len(values) == 0 {
		return "", false, nil
	}
	var selected string
	for _, raw := range values {
		for _, part := range strings.Split(raw, ",") {
			value := strings.TrimSpace(part)
			if value == "" {
				return "", false, fmt.Errorf("invalid upstream Content-Length %q", raw)
			}
			if selected == "" {
				selected = value
				continue
			}
			if value != selected {
				return "", false, fmt.Errorf("conflicting upstream Content-Length values")
			}
		}
	}
	return selected, true, nil
}

func nativeHTTP1ResponseWantsClose(header http.Header, major int, minor int) bool {
	if proxyHeaderValuesContainToken(header.Values("Connection"), "close") {
		return true
	}
	if major < 1 || (major == 1 && minor == 0) {
		return !proxyHeaderValuesContainToken(header.Values("Connection"), "keep-alive")
	}
	return false
}

func nativeHTTP1ParseStatusLine(line string) (int, int, int, string, error) {
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "HTTP/") {
		return 0, 0, 0, "", fmt.Errorf("invalid upstream status line %q", line)
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, 0, 0, "", fmt.Errorf("invalid upstream status line %q", line)
	}
	version := strings.TrimPrefix(parts[0], "HTTP/")
	vparts := strings.SplitN(version, ".", 2)
	if len(vparts) != 2 {
		return 0, 0, 0, "", fmt.Errorf("invalid upstream HTTP version %q", version)
	}
	major, err := strconv.Atoi(vparts[0])
	if err != nil {
		return 0, 0, 0, "", fmt.Errorf("invalid upstream HTTP major version %q", vparts[0])
	}
	minor, err := strconv.Atoi(vparts[1])
	if err != nil {
		return 0, 0, 0, "", fmt.Errorf("invalid upstream HTTP minor version %q", vparts[1])
	}
	if major != 1 || (minor != 0 && minor != 1) {
		return 0, 0, 0, "", fmt.Errorf("unsupported upstream HTTP version %d.%d", major, minor)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 100 || code > 999 {
		return 0, 0, 0, "", fmt.Errorf("invalid upstream status code %q", parts[1])
	}
	statusText := http.StatusText(code)
	if len(parts) == 3 {
		statusText = strings.TrimSpace(parts[2])
	}
	return major, minor, code, statusText, nil
}

func nativeHTTP1ResponseBody(t *nativeHTTP1Transport, resp *http.Response, pc *nativeHTTP1PooledConn, stopContextWatch func()) io.ReadCloser {
	if resp == nil || resp.Request == nil || resp.Request.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return &nativeHTTP1Body{
			reader:           bytes.NewReader(nil),
			transport:        t,
			pc:               pc,
			stopContextWatch: stopContextWatch,
			reusable:         nativeHTTP1CanReuseResponse(resp),
			exhausted:        true,
		}
	}
	if len(resp.TransferEncoding) > 0 && resp.TransferEncoding[0] == "chunked" {
		return &nativeHTTP1Body{reader: &nativeHTTP1ChunkedReader{br: pc.br, trailer: resp.Trailer}, transport: t, pc: pc, stopContextWatch: stopContextWatch, reusable: nativeHTTP1CanReuseResponse(resp)}
	}
	if resp.ContentLength >= 0 {
		return &nativeHTTP1Body{
			reader:           &io.LimitedReader{R: pc.br, N: resp.ContentLength},
			transport:        t,
			pc:               pc,
			stopContextWatch: stopContextWatch,
			reusable:         nativeHTTP1CanReuseResponse(resp),
			exhausted:        resp.ContentLength == 0,
		}
	}
	return &nativeHTTP1Body{reader: pc.br, transport: t, pc: pc, stopContextWatch: stopContextWatch}
}

func nativeHTTP1CanReuseResponse(resp *http.Response) bool {
	if resp == nil || resp.Request == nil {
		return false
	}
	if resp.Close || resp.Request.Close {
		return false
	}
	if resp.ProtoMajor != 1 || resp.ProtoMinor < 1 {
		return false
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return false
	}
	if resp.Request.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return true
	}
	return resp.ContentLength >= 0 || (len(resp.TransferEncoding) == 1 && resp.TransferEncoding[0] == "chunked")
}

type nativeHTTP1Body struct {
	reader           io.Reader
	transport        *nativeHTTP1Transport
	pc               *nativeHTTP1PooledConn
	stopContextWatch func()
	reusable         bool
	exhausted        bool
	once             sync.Once
}

func (b *nativeHTTP1Body) Read(p []byte) (int, error) {
	if b == nil || b.reader == nil {
		return 0, io.EOF
	}
	n, err := b.reader.Read(p)
	if err == io.EOF {
		b.exhausted = true
		b.release()
	}
	return n, err
}

func (b *nativeHTTP1Body) Close() error {
	if b == nil {
		return nil
	}
	b.release()
	return nil
}

func (b *nativeHTTP1Body) release() {
	b.once.Do(func() {
		if b.stopContextWatch != nil {
			b.stopContextWatch()
		}
		if b.transport != nil {
			b.transport.releaseConn(b.pc, b.reusable && b.exhausted)
			return
		}
	})
}

type nativeHTTP1UpgradeBody struct {
	transport        *nativeHTTP1Transport
	pc               *nativeHTTP1PooledConn
	br               *bufio.Reader
	stopContextWatch func()
	once             sync.Once
}

func (b *nativeHTTP1UpgradeBody) Read(p []byte) (int, error) {
	if b == nil || b.pc == nil || b.pc.conn == nil {
		return 0, io.EOF
	}
	if b.br != nil && b.br.Buffered() > 0 {
		return b.br.Read(p)
	}
	return b.pc.conn.Read(p)
}

func (b *nativeHTTP1UpgradeBody) Write(p []byte) (int, error) {
	if b == nil || b.pc == nil || b.pc.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return b.pc.conn.Write(p)
}

func (b *nativeHTTP1UpgradeBody) Close() error {
	if b == nil {
		return nil
	}
	b.once.Do(func() {
		if b.stopContextWatch != nil {
			b.stopContextWatch()
		}
		if b.transport != nil {
			b.transport.releaseConn(b.pc, false)
		}
	})
	return nil
}
