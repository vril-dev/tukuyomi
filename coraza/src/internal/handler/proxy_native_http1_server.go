package handler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type nativeHTTP1Server struct {
	Handler             http.Handler
	MaxHeaderBytes      int
	BaseContext         func(net.Listener) context.Context
	ReadTimeout         time.Duration
	ReadHeaderTimeout   time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	TLSHandshakeTimeout time.Duration

	mu       sync.Mutex
	listener net.Listener
	closing  bool
	conns    map[*nativeHTTP1ServerConn]struct{}
	wg       sync.WaitGroup

	acceptedConnections  atomic.Uint64
	rejectedConnections  atomic.Uint64
	keepAliveReuses      atomic.Uint64
	parseErrors          atomic.Uint64
	scrubbedHeaders      atomic.Uint64
	tlsHandshakeFailures atomic.Uint64
	activeConnections    atomic.Int64
	idleConnections      atomic.Int64
}

type NativeHTTP1Server = nativeHTTP1Server

type NativeHTTP1ServerMetrics struct {
	AcceptedConnections  uint64
	RejectedConnections  uint64
	KeepAliveReuses      uint64
	ParseErrors          uint64
	ScrubbedHeaders      uint64
	TLSHandshakeFailures uint64
	ActiveConnections    int64
	IdleConnections      int64
}

var nativeHTTP1ServerReaderPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 4096)
	},
}

var nativeHTTP1ServerMetricsSource atomic.Pointer[nativeHTTP1Server]

func RegisterNativeHTTP1ServerMetricsSource(server *NativeHTTP1Server) {
	nativeHTTP1ServerMetricsSource.Store(server)
}

func NativeHTTP1ServerMetricsSnapshot() NativeHTTP1ServerMetrics {
	server := nativeHTTP1ServerMetricsSource.Load()
	if server == nil {
		return NativeHTTP1ServerMetrics{}
	}
	return NativeHTTP1ServerMetrics{
		AcceptedConnections:  server.acceptedConnections.Load(),
		RejectedConnections:  server.rejectedConnections.Load(),
		KeepAliveReuses:      server.keepAliveReuses.Load(),
		ParseErrors:          server.parseErrors.Load(),
		ScrubbedHeaders:      server.scrubbedHeaders.Load(),
		TLSHandshakeFailures: server.tlsHandshakeFailures.Load(),
		ActiveConnections:    server.activeConnections.Load(),
		IdleConnections:      server.idleConnections.Load(),
	}
}

type nativeHTTP1ServerConn struct {
	conn   net.Conn
	cancel context.CancelFunc

	mu     sync.Mutex
	idle   bool
	closed bool
	hijack bool
}

func (s *nativeHTTP1Server) Serve(ln net.Listener) error {
	return s.serve(ln, nil)
}

func (s *nativeHTTP1Server) ServeTLS(ln net.Listener, tlsConfig *tls.Config) error {
	if tlsConfig == nil {
		return fmt.Errorf("native http1 TLS config is required")
	}
	return s.serve(ln, nativeHTTP1ServerTLSConfig(tlsConfig))
}

func (s *nativeHTTP1Server) serve(ln net.Listener, tlsConfig *tls.Config) error {
	if ln == nil {
		return fmt.Errorf("native http1 listener is nil")
	}
	if s.Handler == nil {
		s.Handler = http.DefaultServeMux
	}
	s.mu.Lock()
	if s.conns == nil {
		s.conns = make(map[*nativeHTTP1ServerConn]struct{})
	}
	if s.closing {
		s.mu.Unlock()
		_ = ln.Close()
		return http.ErrServerClosed
	}
	s.listener = ln
	s.mu.Unlock()

	baseCtx := context.Background()
	if s.BaseContext != nil {
		baseCtx = s.BaseContext(ln)
		if baseCtx == nil {
			baseCtx = context.Background()
		}
	}
	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isClosing() || errors.Is(err, net.ErrClosed) {
				return http.ErrServerClosed
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0
		if s.isClosing() {
			s.rejectedConnections.Add(1)
			_ = conn.Close()
			continue
		}
		s.acceptedConnections.Add(1)
		s.wg.Add(1)
		go s.serveConn(baseCtx, conn, tlsConfig)
	}
}

func (s *nativeHTTP1Server) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	ln := s.listener
	var idle []*nativeHTTP1ServerConn
	for sc := range s.conns {
		if sc.isIdle() {
			idle = append(idle, sc)
		}
	}
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	for _, sc := range idle {
		sc.setIdle(false, &s.idleConnections)
		sc.close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *nativeHTTP1Server) Close() error {
	s.mu.Lock()
	s.closing = true
	ln := s.listener
	var conns []*nativeHTTP1ServerConn
	for sc := range s.conns {
		conns = append(conns, sc)
	}
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	for _, sc := range conns {
		sc.setIdle(false, &s.idleConnections)
		sc.close()
	}
	return nil
}

func (s *nativeHTTP1Server) serveConn(baseCtx context.Context, conn net.Conn, tlsConfig *tls.Config) {
	ctx, cancel := context.WithCancel(baseCtx)
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, conn.LocalAddr())
	var releaseWGOnce sync.Once
	releaseWG := func() {
		releaseWGOnce.Do(func() {
			s.wg.Done()
		})
	}
	var tlsState *tls.ConnectionState
	if tlsConfig != nil {
		tlsConn := tls.Server(conn, tlsConfig)
		handshakeCtx := ctx
		var handshakeCancel context.CancelFunc
		if timeout := s.tlsHandshakeTimeout(); timeout > 0 {
			handshakeCtx, handshakeCancel = context.WithTimeout(ctx, timeout)
		}
		err := tlsConn.HandshakeContext(handshakeCtx)
		if handshakeCancel != nil {
			handshakeCancel()
		}
		if err != nil {
			s.tlsHandshakeFailures.Add(1)
			cancel()
			_ = conn.Close()
			releaseWG()
			return
		}
		state := tlsConn.ConnectionState()
		tlsState = &state
		conn = tlsConn
	}
	sc := &nativeHTTP1ServerConn{conn: conn, cancel: cancel}
	s.addConn(sc)
	var releaseConnOnce sync.Once
	release := func() {
		releaseConnOnce.Do(func() {
			s.removeConn(sc)
			releaseWG()
		})
	}
	defer func() {
		sc.setIdle(false, &s.idleConnections)
		if !sc.isHijacked() {
			sc.close()
		}
		release()
	}()

	br := nativeHTTP1AcquireServerReader(conn)
	defer func() {
		if !sc.isHijacked() {
			nativeHTTP1ReleaseServerReader(br)
		}
	}()
	reused := false
	for {
		if s.isClosing() {
			return
		}
		sc.setIdle(true, &s.idleConnections)
		if reused && s.IdleTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.IdleTimeout))
			if _, err := br.Peek(1); err != nil {
				return
			}
		}
		readStart := time.Now()
		s.setHeaderReadDeadline(conn, readStart)
		req, err := nativeHTTP1BuildRequest(br, s.maxHeaderBytes(), conn.RemoteAddr(), tlsState)
		sc.setIdle(false, &s.idleConnections)
		if err != nil {
			if err != io.EOF {
				if nativeHTTP1IsTimeoutError(err) {
					nativeHTTP1WriteRequestTimeout(conn)
				} else {
					s.parseErrors.Add(1)
					nativeHTTP1WriteParseError(conn, err)
				}
			}
			return
		}
		s.setBodyReadDeadline(conn, readStart)
		if reused {
			s.keepAliveReuses.Add(1)
		}
		if s.WriteTimeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		} else {
			_ = conn.SetWriteDeadline(time.Time{})
		}
		var rw *nativeHTTP1ResponseWriter
		body := &nativeHTTP1ServerRequestBody{
			ReadCloser:     req.Body,
			expectContinue: strings.EqualFold(strings.TrimSpace(req.Header.Get("Expect")), "100-continue"),
			sendContinue: func() error {
				if rw == nil {
					return nil
				}
				return rw.writeBareContinue()
			},
		}
		req.Body = body
		reqCtx, _ := withNewProxyRequestContextState(ctx)
		req = req.WithContext(reqCtx)
		rw = newNativeHTTP1ResponseWriter(conn, br, req, &s.scrubbedHeaders, cancel, s.isClosing, func() {
			sc.setIdle(false, &s.idleConnections)
			if sc.markHijacked() {
				release()
			}
		})
		s.Handler.ServeHTTP(rw, req)
		if body.timedOut() {
			return
		}
		if err := rw.finish(); err != nil {
			return
		}
		_ = conn.SetWriteDeadline(time.Time{})
		_ = conn.SetReadDeadline(time.Time{})
		if rw.isHijacked() {
			return
		}
		if !rw.keepAlive() || s.isClosing() {
			return
		}
		reused = true
	}
}

func nativeHTTP1AcquireServerReader(conn net.Conn) *bufio.Reader {
	br, _ := nativeHTTP1ServerReaderPool.Get().(*bufio.Reader)
	if br == nil {
		return bufio.NewReaderSize(conn, 4096)
	}
	br.Reset(conn)
	return br
}

func nativeHTTP1ReleaseServerReader(br *bufio.Reader) {
	if br == nil {
		return
	}
	br.Reset(nil)
	nativeHTTP1ServerReaderPool.Put(br)
}

func (s *nativeHTTP1Server) addConn(sc *nativeHTTP1ServerConn) {
	s.mu.Lock()
	if s.conns == nil {
		s.conns = make(map[*nativeHTTP1ServerConn]struct{})
	}
	s.conns[sc] = struct{}{}
	s.mu.Unlock()
	s.activeConnections.Add(1)
}

func (s *nativeHTTP1Server) removeConn(sc *nativeHTTP1ServerConn) {
	s.mu.Lock()
	delete(s.conns, sc)
	s.mu.Unlock()
	s.activeConnections.Add(-1)
}

func (s *nativeHTTP1Server) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

func (s *nativeHTTP1Server) maxHeaderBytes() int {
	if s.MaxHeaderBytes > 0 {
		return s.MaxHeaderBytes
	}
	return nativeHTTP1MaxRequestHeaderBytes
}

func (s *nativeHTTP1Server) tlsHandshakeTimeout() time.Duration {
	if s.TLSHandshakeTimeout > 0 {
		return s.TLSHandshakeTimeout
	}
	return 10 * time.Second
}

func (s *nativeHTTP1Server) setHeaderReadDeadline(conn net.Conn, start time.Time) {
	switch {
	case s.ReadHeaderTimeout > 0:
		_ = conn.SetReadDeadline(start.Add(s.ReadHeaderTimeout))
	case s.ReadTimeout > 0:
		_ = conn.SetReadDeadline(start.Add(s.ReadTimeout))
	default:
		_ = conn.SetReadDeadline(time.Time{})
	}
}

func (s *nativeHTTP1Server) setBodyReadDeadline(conn net.Conn, start time.Time) {
	if s.ReadTimeout > 0 {
		_ = conn.SetReadDeadline(start.Add(s.ReadTimeout))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
}

func (c *nativeHTTP1ServerConn) setIdle(idle bool, gauge *atomic.Int64) {
	c.mu.Lock()
	if c.closed || c.idle == idle {
		c.mu.Unlock()
		return
	}
	c.idle = idle
	c.mu.Unlock()
	if gauge != nil {
		if idle {
			gauge.Add(1)
		} else {
			gauge.Add(-1)
		}
	}
}

func (c *nativeHTTP1ServerConn) isIdle() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.idle && !c.closed
}

func (c *nativeHTTP1ServerConn) markHijacked() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.hijack {
		return false
	}
	c.hijack = true
	c.idle = false
	return true
}

func (c *nativeHTTP1ServerConn) isHijacked() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hijack
}

func (c *nativeHTTP1ServerConn) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	cancel := c.cancel
	conn := c.conn
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		_ = conn.Close()
	}
}

type nativeHTTP1ResponseWriter struct {
	conn            net.Conn
	br              *bufio.Reader
	req             *http.Request
	header          http.Header
	scrubbedHeaders *atomic.Uint64
	cancel          context.CancelFunc
	isClosing       func() bool
	onHijack        func()

	status        int
	contentLength int64
	written       int64
	wroteHeader   bool
	bodyAllowed   bool
	chunked       bool
	closeAfter    bool
	closed        bool
	writeErr      error
	trailers      []string
	sentHeaders   map[string]struct{}
	hijacked      bool
}

var (
	errNativeHTTP1ResponseContentLengthExceeded = errors.New("native http1 response exceeded declared Content-Length")
	errNativeHTTP1ResponseContentLengthShort    = errors.New("native http1 response ended before declared Content-Length")
)

func newNativeHTTP1ResponseWriter(conn net.Conn, br *bufio.Reader, req *http.Request, scrubbedHeaders *atomic.Uint64, cancel context.CancelFunc, isClosing func() bool, onHijack func()) *nativeHTTP1ResponseWriter {
	return &nativeHTTP1ResponseWriter{
		conn:            conn,
		br:              br,
		req:             req,
		header:          make(http.Header),
		contentLength:   -1,
		scrubbedHeaders: scrubbedHeaders,
		cancel:          cancel,
		isClosing:       isClosing,
		onHijack:        onHijack,
	}
}

func (w *nativeHTTP1ResponseWriter) Header() http.Header {
	return w.header
}

func (w *nativeHTTP1ResponseWriter) Status() int {
	if w == nil {
		return 0
	}
	return w.status
}

func (w *nativeHTTP1ResponseWriter) Size() int {
	if w == nil || w.written <= 0 {
		return 0
	}
	if w.written > int64(^uint(0)>>1) {
		return int(^uint(0) >> 1)
	}
	return int(w.written)
}

func (w *nativeHTTP1ResponseWriter) WriteHeader(status int) {
	if w.hijacked {
		w.writeErr = http.ErrHijacked
		return
	}
	if w.wroteHeader {
		return
	}
	if status < 100 || status > 999 {
		status = http.StatusInternalServerError
	}
	if nativeHTTP1InformationalStatus(status) {
		if err := w.writeInformationalHeader(status); err != nil {
			w.writeErr = err
		}
		return
	}
	if err := w.writeHeader(status); err != nil {
		w.writeErr = err
	}
}

func (w *nativeHTTP1ResponseWriter) Write(p []byte) (int, error) {
	if w.hijacked {
		return 0, http.ErrHijacked
	}
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if !w.bodyAllowed {
		return len(p), nil
	}
	if len(p) == 0 {
		return 0, nil
	}
	if w.contentLength >= 0 {
		remaining := w.contentLength - w.written
		if remaining <= 0 {
			w.closeAfter = true
			w.writeErr = errNativeHTTP1ResponseContentLengthExceeded
			return 0, w.writeErr
		}
		writep := p
		var retErr error
		if int64(len(writep)) > remaining {
			writep = writep[:remaining]
			retErr = errNativeHTTP1ResponseContentLengthExceeded
			w.closeAfter = true
		}
		n, err := w.conn.Write(writep)
		w.written += int64(n)
		if err != nil {
			w.writeErr = err
			return n, err
		}
		if retErr != nil {
			w.writeErr = retErr
			return n, retErr
		}
		return n, nil
	}
	if w.chunked {
		n, err := nativeHTTP1WriteChunkedResponseBody(w.conn, p)
		w.written += int64(n)
		if err != nil {
			w.writeErr = err
			return n, err
		}
		if n != len(p) {
			w.writeErr = io.ErrShortWrite
			return n, io.ErrShortWrite
		}
		return n, nil
	}
	n, err := w.conn.Write(p)
	w.written += int64(n)
	if err != nil {
		w.writeErr = err
	}
	return n, err
}

func nativeHTTP1WriteChunkedResponseBody(conn net.Conn, p []byte) (int, error) {
	var chunkLine [32]byte
	line := strconv.AppendInt(chunkLine[:0], int64(len(p)), 16)
	line = append(line, '\r', '\n')
	buffers := net.Buffers{line, p, nativeHTTP1CRLFBytes}
	written, err := buffers.WriteTo(conn)
	bodyWritten := written - int64(len(line))
	if bodyWritten < 0 {
		bodyWritten = 0
	}
	if bodyWritten > int64(len(p)) {
		bodyWritten = int64(len(p))
	}
	if err != nil {
		return int(bodyWritten), err
	}
	if bodyWritten != int64(len(p)) {
		return int(bodyWritten), io.ErrShortWrite
	}
	return len(p), nil
}

func (w *nativeHTTP1ResponseWriter) Flush() {
	if w.hijacked {
		return
	}
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
}

func (w *nativeHTTP1ResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if r == nil {
		return 0, nil
	}
	buf := proxyReverseCopyBufferPool.Get()
	defer proxyReverseCopyBufferPool.Put(buf)
	var total int64
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total, ew
			}
			if nw != nr {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

func (w *nativeHTTP1ResponseWriter) finish() error {
	if w.hijacked {
		return nil
	}
	if w.closed {
		return w.writeErr
	}
	w.closed = true
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.writeErr != nil {
		return w.writeErr
	}
	if w.bodyAllowed && w.contentLength >= 0 && w.written < w.contentLength {
		w.closeAfter = true
		w.writeErr = errNativeHTTP1ResponseContentLengthShort
		return w.writeErr
	}
	if w.chunked {
		if _, err := io.WriteString(w.conn, "0\r\n"); err != nil {
			w.writeErr = err
			return err
		}
		if err := w.writeTrailers(); err != nil {
			w.writeErr = err
			return err
		}
		if _, err := io.WriteString(w.conn, "\r\n"); err != nil {
			w.writeErr = err
			return err
		}
	}
	return nil
}

func (w *nativeHTTP1ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w == nil {
		return nil, nil, http.ErrHijacked
	}
	if w.hijacked {
		return nil, nil, http.ErrHijacked
	}
	if w.closed || w.wroteHeader || w.written > 0 {
		return nil, nil, http.ErrHijacked
	}
	if w.isClosing != nil && w.isClosing() {
		return nil, nil, http.ErrServerClosed
	}
	if w.conn == nil || w.br == nil {
		return nil, nil, http.ErrNotSupported
	}
	w.hijacked = true
	if w.onHijack != nil {
		w.onHijack()
	}
	conn := &nativeHTTP1HijackedConn{Conn: w.conn, cancel: w.cancel}
	return conn, bufio.NewReadWriter(w.br, bufio.NewWriter(conn)), nil
}

func (w *nativeHTTP1ResponseWriter) isHijacked() bool {
	return w != nil && w.hijacked
}

type nativeHTTP1HijackedConn struct {
	net.Conn
	cancel context.CancelFunc
	once   sync.Once
}

func (c *nativeHTTP1HijackedConn) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
	})
	return err
}

func (w *nativeHTTP1ResponseWriter) writeHeader(status int) error {
	w.status = status
	w.wroteHeader = true
	w.trailers = nativeHTTP1ResponseTrailerNames(w.header, w.scrubbedHeaders)
	header := w.sanitizedHeader()
	w.bodyAllowed = nativeHTTP1ResponseAllowsBody(w.req, w.status)
	header.Del("Connection")
	header.Del("Keep-Alive")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
	header.Del("Te")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")
	rawLength, hasLength, lengthErr := nativeHTTP1ContentLength(header)
	header.Del("Content-Length")
	if !w.bodyAllowed {
		w.contentLength = 0
		w.trailers = nil
	} else if hasLength && lengthErr == nil {
		length, err := strconv.ParseInt(rawLength, 10, 64)
		if err == nil && length >= 0 {
			w.contentLength = length
			header.Set("Content-Length", strconv.FormatInt(length, 10))
		} else {
			w.countScrubbedHeader()
			w.planImplicitFraming(header)
		}
	} else {
		if lengthErr != nil {
			w.countScrubbedHeader()
		}
		w.planImplicitFraming(header)
	}
	if len(w.trailers) > 0 && w.chunked {
		header.Set("Trailer", strings.Join(w.trailers, ", "))
	} else {
		header.Del("Trailer")
	}
	if !w.keepAlive() {
		header.Set("Connection", "close")
	}
	w.sentHeaders = nativeHTTP1HeaderNameSet(header)
	var out bytes.Buffer
	reason := http.StatusText(w.status)
	if reason == "" {
		reason = "status"
	}
	nativeHTTP1BufferWriteStatusLine(&out, w.status, reason)
	for name, values := range header {
		if !nativeHTTP1SafeHeaderName(name) {
			continue
		}
		for _, value := range values {
			if !nativeHTTP1SafeHeaderValue(value) {
				continue
			}
			nativeHTTP1BufferWriteHeaderField(&out, name, value)
		}
	}
	out.WriteString("\r\n")
	_, w.writeErr = w.conn.Write(out.Bytes())
	return w.writeErr
}

func (w *nativeHTTP1ResponseWriter) writeInformationalHeader(status int) error {
	if w == nil || w.hijacked || w.closed || w.wroteHeader {
		return nil
	}
	header := w.sanitizedHeader()
	header.Del("Connection")
	header.Del("Keep-Alive")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
	header.Del("Te")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")
	header.Del("Content-Length")
	header.Del("Trailer")
	var out bytes.Buffer
	reason := http.StatusText(status)
	if reason == "" {
		reason = "status"
	}
	nativeHTTP1BufferWriteStatusLine(&out, status, reason)
	for name, values := range header {
		if !nativeHTTP1SafeHeaderName(name) {
			continue
		}
		for _, value := range values {
			if !nativeHTTP1SafeHeaderValue(value) {
				continue
			}
			nativeHTTP1BufferWriteHeaderField(&out, name, value)
		}
	}
	out.WriteString("\r\n")
	_, err := w.conn.Write(out.Bytes())
	return err
}

func (w *nativeHTTP1ResponseWriter) writeBareContinue() error {
	if w == nil || w.hijacked || w.closed || w.wroteHeader {
		return nil
	}
	_, err := io.WriteString(w.conn, "HTTP/1.1 100 Continue\r\n\r\n")
	return err
}

var nativeHTTP1CRLFBytes = []byte("\r\n")

func nativeHTTP1BufferWriteStatusLine(out *bytes.Buffer, status int, reason string) {
	out.WriteString("HTTP/1.1 ")
	var code [4]byte
	out.Write(strconv.AppendInt(code[:0], int64(status), 10))
	out.WriteByte(' ')
	out.WriteString(reason)
	out.WriteString("\r\n")
}

func nativeHTTP1BufferWriteHeaderField(out *bytes.Buffer, name string, value string) {
	out.WriteString(name)
	out.WriteString(": ")
	out.WriteString(value)
	out.WriteString("\r\n")
}

func nativeHTTP1InformationalStatus(status int) bool {
	return status >= 100 && status < 200 && status != http.StatusSwitchingProtocols
}

func (w *nativeHTTP1ResponseWriter) planImplicitFraming(header http.Header) {
	w.contentLength = -1
	if w.req != nil && w.req.ProtoMajor == 1 && w.req.ProtoMinor >= 1 {
		w.chunked = true
		header.Set("Transfer-Encoding", "chunked")
		return
	}
	w.closeAfter = true
}

func (w *nativeHTTP1ResponseWriter) sanitizedHeader() http.Header {
	if w == nil || w.header == nil {
		return make(http.Header)
	}
	if !w.responseHeaderNeedsCloneForSanitize() {
		w.sanitizeHeaderInPlace()
		return w.header
	}
	return w.cloneSanitizedHeader()
}

func (w *nativeHTTP1ResponseWriter) responseHeaderNeedsCloneForSanitize() bool {
	if len(w.trailers) > 0 {
		return true
	}
	for name, values := range w.header {
		if strings.HasPrefix(name, http.TrailerPrefix) {
			return true
		}
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical != name {
			return true
		}
		if !nativeHTTP1SafeHeaderName(canonical) {
			continue
		}
		if len(values) == 0 {
			continue
		}
	}
	return false
}

func (w *nativeHTTP1ResponseWriter) sanitizeHeaderInPlace() {
	for name, values := range w.header {
		if !nativeHTTP1SafeHeaderName(name) {
			delete(w.header, name)
			w.countScrubbedHeader()
			continue
		}
		safeValues := values[:0]
		for _, value := range values {
			if nativeHTTP1SafeHeaderValue(value) {
				safeValues = append(safeValues, value)
			} else {
				w.countScrubbedHeader()
			}
		}
		if len(safeValues) == 0 {
			delete(w.header, name)
			continue
		}
		w.header[name] = safeValues
	}
}

func (w *nativeHTTP1ResponseWriter) cloneSanitizedHeader() http.Header {
	out := make(http.Header, len(w.header)+1)
	for name, values := range w.header {
		if strings.HasPrefix(name, http.TrailerPrefix) {
			continue
		}
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if !nativeHTTP1SafeHeaderName(canonical) {
			w.countScrubbedHeader()
			continue
		}
		for _, value := range values {
			if nativeHTTP1SafeHeaderValue(value) {
				nativeHTTP1AppendHeaderValue(out, canonical, value)
			} else {
				w.countScrubbedHeader()
			}
		}
	}
	return out
}

func (w *nativeHTTP1ResponseWriter) keepAlive() bool {
	if w == nil || w.req == nil {
		return false
	}
	if w.closeAfter || w.writeErr != nil || w.req.Close || proxyHeaderValuesContainToken(w.req.Header.Values("Connection"), "close") {
		return false
	}
	return w.req.ProtoMajor == 1 && w.req.ProtoMinor >= 1
}

func nativeHTTP1ResponseAllowsBody(req *http.Request, status int) bool {
	if req != nil && req.Method == http.MethodHead {
		return false
	}
	return status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified
}

func (w *nativeHTTP1ResponseWriter) writeTrailers() error {
	var out bytes.Buffer
	for _, name := range w.trailers {
		values := nativeHTTP1TrailerPrefixValues(w.header, name, w.scrubbedHeaders)
		if _, sent := w.sentHeaders[name]; !sent {
			for _, value := range w.header.Values(name) {
				values = append(values, value)
			}
		}
		for _, value := range values {
			if !nativeHTTP1SafeHeaderValue(value) {
				w.countScrubbedHeader()
				continue
			}
			nativeHTTP1BufferWriteHeaderField(&out, name, value)
		}
	}
	if out.Len() == 0 {
		return nil
	}
	_, err := w.conn.Write(out.Bytes())
	return err
}

func nativeHTTP1ResponseTrailerNames(header http.Header, scrubbed *atomic.Uint64) []string {
	seen := make(map[string]struct{})
	var names []string
	add := func(raw string) {
		name := http.CanonicalHeaderKey(strings.TrimSpace(raw))
		if name == "" {
			return
		}
		if !nativeHTTP1SafeHeaderName(name) {
			if scrubbed != nil {
				scrubbed.Add(1)
			}
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	for _, value := range header.Values("Trailer") {
		for _, part := range strings.Split(value, ",") {
			add(part)
		}
	}
	for name := range header {
		if strings.HasPrefix(name, http.TrailerPrefix) {
			add(strings.TrimPrefix(name, http.TrailerPrefix))
		}
	}
	return names
}

func nativeHTTP1HeaderNameSet(header http.Header) map[string]struct{} {
	if len(header) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(header))
	for name := range header {
		out[name] = struct{}{}
	}
	return out
}

func nativeHTTP1TrailerPrefixValues(header http.Header, canonicalName string, scrubbed *atomic.Uint64) []string {
	var values []string
	for rawName, rawValues := range header {
		if !strings.HasPrefix(rawName, http.TrailerPrefix) {
			continue
		}
		name := http.CanonicalHeaderKey(strings.TrimSpace(strings.TrimPrefix(rawName, http.TrailerPrefix)))
		if name != canonicalName {
			continue
		}
		for _, value := range rawValues {
			if nativeHTTP1SafeHeaderValue(value) {
				values = append(values, value)
			} else if scrubbed != nil {
				scrubbed.Add(1)
			}
		}
	}
	return values
}

func (w *nativeHTTP1ResponseWriter) countScrubbedHeader() {
	if w != nil && w.scrubbedHeaders != nil {
		w.scrubbedHeaders.Add(1)
	}
}

func nativeHTTP1WriteParseError(conn net.Conn, err error) {
	status := http.StatusBadRequest
	if strings.Contains(err.Error(), "exceed limit") {
		status = http.StatusRequestURITooLong
	}
	reason := http.StatusText(status)
	body := reason + "\n"
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: %d\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s", status, reason, len(body), body)
}

func nativeHTTP1WriteRequestTimeout(conn net.Conn) {
	const body = "Request Timeout\n"
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: %d\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s", len(body), body)
}

type nativeHTTP1ServerRequestBody struct {
	io.ReadCloser
	timeout        atomic.Bool
	expectContinue bool
	continueOnce   sync.Once
	sendContinue   func() error
	continueErr    error
}

func (b *nativeHTTP1ServerRequestBody) Read(p []byte) (int, error) {
	if b == nil || b.ReadCloser == nil {
		return 0, io.EOF
	}
	if b.expectContinue && b.sendContinue != nil {
		b.continueOnce.Do(func() {
			b.continueErr = b.sendContinue()
		})
		if b.continueErr != nil {
			return 0, b.continueErr
		}
	}
	n, err := b.ReadCloser.Read(p)
	if nativeHTTP1IsTimeoutError(err) {
		b.timeout.Store(true)
	}
	return n, err
}

func (b *nativeHTTP1ServerRequestBody) timedOut() bool {
	return b != nil && b.timeout.Load()
}

func nativeHTTP1IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func nativeHTTP1ServerTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return nil
	}
	out := cfg.Clone()
	out.NextProtos = []string{"http/1.1"}
	baseGetConfigForClient := out.GetConfigForClient
	out.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if nativeHTTP1ClientOfferedUnsupportedOnlyALPN(hello) {
			return nil, fmt.Errorf("native http1 server does not accept requested ALPN protocols")
		}
		if baseGetConfigForClient == nil {
			return nil, nil
		}
		next, err := baseGetConfigForClient(hello)
		if next == nil || err != nil {
			return next, err
		}
		cloned := next.Clone()
		cloned.NextProtos = []string{"http/1.1"}
		return cloned, nil
	}
	return out
}

func nativeHTTP1ClientOfferedUnsupportedOnlyALPN(hello *tls.ClientHelloInfo) bool {
	if hello == nil || len(hello.SupportedProtos) == 0 {
		return false
	}
	for _, proto := range hello.SupportedProtos {
		if proto == "http/1.1" {
			return false
		}
	}
	return true
}
