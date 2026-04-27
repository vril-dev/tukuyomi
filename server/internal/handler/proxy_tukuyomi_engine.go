package handler

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tukuyomi/internal/config"
	"tukuyomi/internal/proxybuffer"
)

type proxyEngineFlushIntervalSetter interface {
	SetFlushInterval(time.Duration)
}

type tukuyomiProxyEngine struct {
	transport       http.RoundTripper
	flushIntervalNS atomic.Int64
}

func newProxyEngine(transport http.RoundTripper, mode string, flushInterval time.Duration) (http.Handler, error) {
	mode = normalizeProxyEngineMode(mode)
	switch mode {
	case config.ProxyEngineModeTukuyomiProxy:
		if transport == nil {
			return nil, fmt.Errorf("proxy.engine.mode=%q requires initialized upstream transport", config.ProxyEngineModeTukuyomiProxy)
		}
		engine := &tukuyomiProxyEngine{transport: transport}
		engine.SetFlushInterval(flushInterval)
		return engine, nil
	default:
		return nil, fmt.Errorf("proxy.engine.mode must be %q", config.ProxyEngineModeTukuyomiProxy)
	}
}

func normalizeProxyEngineMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return config.DefaultProxyEngineMode
	}
	return mode
}

func (e *tukuyomiProxyEngine) SetFlushInterval(interval time.Duration) {
	e.flushIntervalNS.Store(int64(interval))
}

func (e *tukuyomiProxyEngine) flushInterval() time.Duration {
	if e == nil {
		return 0
	}
	return time.Duration(e.flushIntervalNS.Load())
}

func (e *tukuyomiProxyEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e == nil || e.transport == nil {
		handleProxyRoundTripError(w, r, fmt.Errorf("tukuyomi_proxy engine is not initialized"))
		return
	}

	outReq, reqUpType, err := prepareTukuyomiProxyRequest(r)
	if err != nil {
		handleProxyRoundTripError(w, r, err)
		return
	}
	baseHeader := cloneProxyHeader(w.Header())
	var writeMu sync.Mutex
	outReq = outReq.WithContext(httptrace.WithClientTrace(outReq.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			if code == http.StatusSwitchingProtocols {
				return nil
			}
			writeMu.Lock()
			defer writeMu.Unlock()
			writeTukuyomiProxyInformationalResponse(w, baseHeader, code, header)
			return nil
		},
	}))

	res, err := e.transport.RoundTrip(outReq)
	if err != nil {
		handleProxyRoundTripError(w, r, err)
		return
	}
	if res.StatusCode == http.StatusSwitchingProtocols {
		e.serveUpgradeResponse(w, r, outReq, res, reqUpType)
		return
	}
	defer closeProxyResponseBody(res)

	if err := onProxyResponse(res); err != nil {
		handleProxyRoundTripError(w, r, err)
		return
	}
	trailers := proxyResponseTrailerKeys(res)
	removeProxyHopByHopHeaders(res.Header)
	writeMu.Lock()
	copyProxyHeader(w.Header(), res.Header)
	for _, trailer := range trailers {
		w.Header().Add("Trailer", trailer)
	}
	w.WriteHeader(res.StatusCode)
	writeMu.Unlock()
	if err := copyTukuyomiProxyResponseBody(w, res.Body, tukuyomiProxyFlushInterval(res, e.flushInterval())); err != nil {
		logTukuyomiProxyCopyError(r, err)
		return
	}
	copyProxyHeader(w.Header(), res.Trailer)
}

func prepareTukuyomiProxyRequest(r *http.Request) (*http.Request, string, error) {
	if r == nil {
		return nil, "", fmt.Errorf("request is required")
	}
	reqUpType := proxyUpgradeType(r.Header)
	if strings.TrimSpace(r.Header.Get("Upgrade")) != "" && reqUpType == "" {
		return nil, "", fmt.Errorf("upgrade request missing Connection: Upgrade")
	}
	if reqUpType != "" && !proxyASCIIIsPrint(reqUpType) {
		return nil, "", fmt.Errorf("client tried to switch to invalid protocol %q", reqUpType)
	}

	outReq := cloneTukuyomiProxyOutboundRequest(r)
	outReq.RequestURI = ""
	outReq.Close = false
	if outReq.Body == nil {
		outReq.Body = http.NoBody
	}
	outReq = rewriteTukuyomiProxyRequest(r, outReq)
	removeProxyHopByHopHeaders(outReq.Header)
	if proxyHeaderValuesContainToken(r.Header.Values("Te"), "trailers") {
		outReq.Header.Set("Te", "trailers")
	}
	if reqUpType != "" {
		outReq.Header.Set("Connection", "Upgrade")
		outReq.Header.Set("Upgrade", reqUpType)
	}
	if _, ok := outReq.Header["User-Agent"]; !ok {
		outReq.Header.Set("User-Agent", "")
	}
	return outReq, reqUpType, nil
}

func cloneTukuyomiProxyOutboundRequest(r *http.Request) *http.Request {
	if r == nil {
		return nil
	}
	if r.Form != nil || r.PostForm != nil || r.MultipartForm != nil {
		return r.Clone(r.Context())
	}
	out := new(http.Request)
	*out = *r
	out.URL = cloneURL(r.URL)
	out.Header = cloneProxyHeaderMapForMutation(r.Header, 4)
	out.Trailer = cloneProxyHeaderMap(r.Trailer)
	if r.TransferEncoding != nil {
		out.TransferEncoding = append([]string(nil), r.TransferEncoding...)
	}
	return out
}

func setTukuyomiProxyXForwarded(header http.Header, in *http.Request) {
	if header == nil || in == nil {
		return
	}
	clientIP, _, err := net.SplitHostPort(in.RemoteAddr)
	if err == nil {
		if prior := header["X-Forwarded-For"]; len(prior) > 0 {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		header.Set("X-Forwarded-For", clientIP)
	} else {
		header.Del("X-Forwarded-For")
	}
	header.Set("X-Forwarded-Host", in.Host)
	if in.TLS == nil {
		header.Set("X-Forwarded-Proto", "http")
	} else {
		header.Set("X-Forwarded-Proto", "https")
	}
}

func closeProxyResponseBody(res *http.Response) {
	if res != nil && res.Body != nil {
		_ = res.Body.Close()
	}
}

func proxyUpgradeType(header http.Header) string {
	if header == nil || !proxyHeaderValuesContainToken(header.Values("Connection"), "upgrade") {
		return ""
	}
	return strings.TrimSpace(header.Get("Upgrade"))
}

func proxyHeaderValuesContainToken(values []string, token string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func proxyASCIIIsPrint(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func (e *tukuyomiProxyEngine) serveUpgradeResponse(w http.ResponseWriter, r *http.Request, outReq *http.Request, res *http.Response, reqUpType string) {
	if strings.TrimSpace(reqUpType) == "" {
		closeProxyResponseBody(res)
		handleProxyRoundTripError(w, r, fmt.Errorf("upstream switched protocols without a valid client upgrade request"))
		return
	}
	resUpType := proxyUpgradeType(res.Header)
	if !proxyASCIIIsPrint(resUpType) {
		closeProxyResponseBody(res)
		handleProxyRoundTripError(w, r, fmt.Errorf("backend tried to switch to invalid protocol %q", resUpType))
		return
	}
	if !strings.EqualFold(reqUpType, resUpType) {
		closeProxyResponseBody(res)
		handleProxyRoundTripError(w, r, fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType))
		return
	}
	if err := onProxyUpgradeResponse(res); err != nil {
		closeProxyResponseBody(res)
		handleProxyRoundTripError(w, r, err)
		return
	}
	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		closeProxyResponseBody(res)
		handleProxyRoundTripError(w, r, fmt.Errorf("internal error: 101 switching protocols response with non-writable body"))
		return
	}

	clientConn, brw, hijackErr := http.NewResponseController(w).Hijack()
	if hijackErr != nil {
		closeProxyResponseBody(res)
		if errors.Is(hijackErr, http.ErrNotSupported) {
			handleProxyRoundTripError(w, r, fmt.Errorf("can't switch protocols using non-Hijacker ResponseWriter type %T", w))
			return
		}
		handleProxyRoundTripError(w, r, fmt.Errorf("hijack failed on protocol switch: %v", hijackErr))
		return
	}
	defer func() {
		_ = clientConn.Close()
	}()
	defer func() {
		_ = backConn.Close()
	}()

	backendCloseCh := make(chan struct{})
	go func() {
		select {
		case <-outReq.Context().Done():
			_ = backConn.Close()
		case <-backendCloseCh:
		}
	}()
	defer close(backendCloseCh)

	res.Body = nil
	if err := writeTukuyomiProxyUpgradeResponse(brw, res, resUpType); err != nil {
		logTukuyomiProxyTunnelError(r, "write upgrade response", err)
		return
	}
	if err := brw.Flush(); err != nil {
		logTukuyomiProxyTunnelError(r, "flush upgrade response", err)
		return
	}

	if err := copyTukuyomiProxyTunnel(r, clientConn, brw, backConn); err != nil {
		logTukuyomiProxyTunnelError(r, "copy tunnel", err)
	}
}

func writeTukuyomiProxyUpgradeResponse(w io.Writer, res *http.Response, upgradeType string) error {
	plan, err := prepareTukuyomiProxyUpgradeResponseWrite(res, upgradeType)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(w)
	if _, err := fmt.Fprintf(bw, "%s 101 Switching Protocols\r\n", plan.proto); err != nil {
		return err
	}
	for _, header := range plan.headers {
		if _, err := fmt.Fprintf(bw, "%s: %s\r\n", header.name, header.value); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(bw, "\r\n"); err != nil {
		return err
	}
	return bw.Flush()
}

type tukuyomiProxyUpgradeResponseWritePlan struct {
	proto   string
	headers []nativeHTTP1HeaderLine
}

func prepareTukuyomiProxyUpgradeResponseWrite(res *http.Response, upgradeType string) (tukuyomiProxyUpgradeResponseWritePlan, error) {
	if res == nil {
		return tukuyomiProxyUpgradeResponseWritePlan{}, fmt.Errorf("upgrade response is required")
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		return tukuyomiProxyUpgradeResponseWritePlan{}, fmt.Errorf("upgrade response status=%d want 101", res.StatusCode)
	}
	if strings.TrimSpace(upgradeType) == "" || !proxyASCIIIsPrint(upgradeType) || strings.ContainsAny(upgradeType, "\r\n") {
		return tukuyomiProxyUpgradeResponseWritePlan{}, fmt.Errorf("invalid upgrade protocol %q", upgradeType)
	}
	if res.Header.Get("Content-Length") != "" || len(res.Header.Values("Transfer-Encoding")) > 0 {
		return tukuyomiProxyUpgradeResponseWritePlan{}, fmt.Errorf("upgrade response must not carry body framing headers")
	}
	proto := strings.TrimSpace(res.Proto)
	if proto == "" {
		proto = "HTTP/1.1"
	}
	if proto != "HTTP/1.0" && proto != "HTTP/1.1" {
		return tukuyomiProxyUpgradeResponseWritePlan{}, fmt.Errorf("invalid upgrade response protocol %q", proto)
	}
	header := cloneProxyHeader(res.Header)
	header.Del("Content-Length")
	header.Del("Transfer-Encoding")
	header.Set("Connection", "Upgrade")
	header.Set("Upgrade", upgradeType)
	plan := tukuyomiProxyUpgradeResponseWritePlan{proto: proto}
	for name, values := range header {
		canonical := http.CanonicalHeaderKey(name)
		if !nativeHTTP1SafeHeaderName(canonical) {
			return tukuyomiProxyUpgradeResponseWritePlan{}, fmt.Errorf("invalid upstream upgrade response header %q", name)
		}
		for _, value := range values {
			if !nativeHTTP1SafeHeaderValue(value) {
				return tukuyomiProxyUpgradeResponseWritePlan{}, fmt.Errorf("invalid upstream upgrade response header value for %q", name)
			}
			plan.headers = append(plan.headers, nativeHTTP1HeaderLine{name: canonical, value: value})
		}
	}
	return plan, nil
}

func onProxyUpgradeResponse(res *http.Response) error {
	annotateWAFHit(res)
	applyRouteResponseHeaders(res)
	applyProxyStickySessionCookie(res)
	sanitizeProxyLiveResponseHeaders(res)
	return nil
}

func copyTukuyomiProxyTunnel(r *http.Request, clientConn io.ReadWriteCloser, clientBuffer *bufio.ReadWriter, backendConn io.ReadWriteCloser) error {
	errc := make(chan error, 2)
	clientReader := io.Reader(clientConn)
	if clientBuffer != nil && clientBuffer.Reader != nil && clientBuffer.Reader.Buffered() > 0 {
		clientReader = clientBuffer.Reader
	}
	go tukuyomiProxyTunnelCopy(errc, "client_to_backend", backendConn, clientReader, backendConn)
	go tukuyomiProxyTunnelCopy(errc, "backend_to_client", clientConn, backendConn, clientConn)

	err := <-errc
	if err == nil {
		second := <-errc
		if second != nil && !errors.Is(second, errTukuyomiProxyTunnelDone) {
			return second
		}
		return nil
	}
	if errors.Is(err, errTukuyomiProxyTunnelDone) {
		return nil
	}
	if isExpectedTukuyomiProxyCopyAbort(r, err) {
		return nil
	}
	return err
}

var errTukuyomiProxyTunnelDone = errors.New("tukuyomi proxy tunnel copy complete")

func tukuyomiProxyTunnelCopy(errc chan<- error, direction string, dst io.Writer, src io.Reader, closeWriteTarget any) {
	buf := proxybuffer.GetCopyBuffer()
	_, err := io.CopyBuffer(dst, src, buf)
	proxybuffer.PutCopyBuffer(buf)
	if err != nil {
		errc <- fmt.Errorf("%s: %w", direction, err)
		return
	}
	if closeWriter, ok := closeWriteTarget.(interface{ CloseWrite() error }); ok {
		errc <- closeWriter.CloseWrite()
		return
	}
	errc <- errTukuyomiProxyTunnelDone
}

func logTukuyomiProxyTunnelError(r *http.Request, stage string, err error) {
	if err == nil {
		return
	}
	if isExpectedTukuyomiProxyCopyAbort(r, err) {
		log.Printf("[PROXY][INFO] tukuyomi_proxy upgrade tunnel aborted stage=%s method=%s path=%s err=%v", stage, r.Method, r.URL.Path, err)
		return
	}
	log.Printf("[PROXY][ERROR] tukuyomi_proxy upgrade tunnel failed stage=%s method=%s path=%s err=%v", stage, r.Method, r.URL.Path, err)
}

var proxyHopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeProxyHopByHopHeaders(header http.Header) {
	if header == nil {
		return
	}
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if key := strings.TrimSpace(token); key != "" {
				header.Del(key)
			}
		}
	}
	for _, key := range proxyHopByHopHeaders {
		header.Del(key)
	}
}

func copyProxyHeader(dst http.Header, src http.Header) {
	if dst == nil || src == nil {
		return
	}
	for key, values := range src {
		if len(values) == 0 {
			continue
		}
		name := http.CanonicalHeaderKey(strings.TrimSpace(key))
		if name == "" {
			continue
		}
		dst[name] = append(dst[name], values...)
	}
}

func clearProxyHeader(header http.Header) {
	for key := range header {
		delete(header, key)
	}
}

func writeTukuyomiProxyInformationalResponse(w http.ResponseWriter, baseHeader http.Header, code int, header textproto.MIMEHeader) {
	dst := w.Header()
	clearProxyHeader(dst)
	copyProxyHeader(dst, http.Header(header))
	removeProxyHopByHopHeaders(dst)
	w.WriteHeader(code)
	clearProxyHeader(dst)
	copyProxyHeader(dst, baseHeader)
}

func proxyResponseTrailerKeys(res *http.Response) []string {
	if res == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(res.Trailer))
	out := make([]string, 0, len(res.Trailer))
	add := func(key string) {
		key = http.CanonicalHeaderKey(strings.TrimSpace(key))
		if key == "" {
			return
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	for _, value := range res.Header.Values("Trailer") {
		for _, token := range strings.Split(value, ",") {
			add(token)
		}
	}
	for key := range res.Trailer {
		add(key)
	}
	return out
}

func copyTukuyomiProxyResponseBody(w http.ResponseWriter, src io.Reader, flushInterval time.Duration) error {
	if src == nil {
		return nil
	}
	var dst io.Writer = w
	if flushInterval != 0 {
		mlw := &tukuyomiProxyMaxLatencyWriter{
			dst:     w,
			flush:   http.NewResponseController(w).Flush,
			latency: flushInterval,
		}
		mlw.flushPending = true
		mlw.t = time.AfterFunc(flushInterval, mlw.delayedFlush)
		defer mlw.stop()
		dst = mlw
	}

	buf := proxybuffer.GetCopyBuffer()
	defer proxybuffer.PutCopyBuffer(buf)

	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[:nr])
			if writeErr != nil {
				return writeErr
			}
			if nw != nr {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

func tukuyomiProxyFlushInterval(res *http.Response, configured time.Duration) time.Duration {
	if res == nil {
		return configured
	}
	if baseCT, _, err := mime.ParseMediaType(res.Header.Get("Content-Type")); err == nil && baseCT == "text/event-stream" {
		return -1
	}
	if res.ContentLength == -1 {
		return -1
	}
	return configured
}

type tukuyomiProxyMaxLatencyWriter struct {
	dst     io.Writer
	flush   func() error
	latency time.Duration

	mu           sync.Mutex
	t            *time.Timer
	flushPending bool
}

func (m *tukuyomiProxyMaxLatencyWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	n, err := m.dst.Write(p)
	if m.latency < 0 {
		_ = m.flush()
		return n, err
	}
	if m.flushPending {
		return n, err
	}
	if m.t == nil {
		m.t = time.AfterFunc(m.latency, m.delayedFlush)
	} else {
		m.t.Reset(m.latency)
	}
	m.flushPending = true
	return n, err
}

func (m *tukuyomiProxyMaxLatencyWriter) delayedFlush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.flushPending {
		return
	}
	_ = m.flush()
	m.flushPending = false
}

func (m *tukuyomiProxyMaxLatencyWriter) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushPending = false
	if m.t != nil {
		m.t.Stop()
	}
}

func logTukuyomiProxyCopyError(r *http.Request, err error) {
	if isExpectedTukuyomiProxyCopyAbort(r, err) {
		log.Printf("[PROXY][INFO] tukuyomi_proxy response copy aborted method=%s path=%s err=%v", r.Method, r.URL.Path, err)
		return
	}
	log.Printf("[PROXY][ERROR] tukuyomi_proxy response copy failed method=%s path=%s err=%v", r.Method, r.URL.Path, err)
}

func isExpectedTukuyomiProxyCopyAbort(r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, http.ErrAbortHandler) {
		return true
	}
	if r != nil && errors.Is(r.Context().Err(), context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "transport endpoint is not connected")
}
