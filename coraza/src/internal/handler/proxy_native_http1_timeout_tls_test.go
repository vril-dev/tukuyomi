package handler

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestNativeHTTP1ReadHeaderTimeout(t *testing.T) {
	srv, addr := nativeHTTP1StartConfiguredTestServer(t, &nativeHTTP1Server{
		ReadHeaderTimeout: 40 * time.Millisecond,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("handler should not run after header timeout")
		}),
	})
	defer srv.Close()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHo"); err != nil {
		t.Fatalf("write partial headers: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status=%d want 408", resp.StatusCode)
	}
}

func TestNativeHTTP1ReadTimeoutMidBodyClosesWithoutResponse(t *testing.T) {
	bodyErr := make(chan error, 1)
	srv, addr := nativeHTTP1StartConfiguredTestServer(t, &nativeHTTP1Server{
		ReadTimeout: 50 * time.Millisecond,
		Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, err := io.ReadAll(r.Body)
			bodyErr <- err
		}),
	})
	defer srv.Close()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nab"); err != nil {
		t.Fatalf("write partial body: %v", err)
	}
	select {
	case err := <-bodyErr:
		if !nativeHTTP1IsTimeoutError(err) {
			t.Fatalf("body read err=%v want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not observe body read timeout")
	}
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := http.ReadResponse(bufio.NewReader(conn), nil); err == nil {
		t.Fatal("unexpected response after mid-body read timeout")
	}
}

func TestNativeHTTP1WriteTimeoutClosesSlowClient(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	errCh := make(chan error, 1)
	ln := &nativeHTTP1SingleConnListener{conn: serverConn, addr: nativeHTTP1StaticAddr("pipe-listener")}
	srv := &nativeHTTP1Server{
		WriteTimeout: 30 * time.Millisecond,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, err := w.Write([]byte("blocked"))
			errCh <- err
		}),
	}
	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	}()
	defer srv.Close()

	if _, err := io.WriteString(clientConn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	select {
	case err := <-errCh:
		if !nativeHTTP1IsTimeoutError(err) {
			t.Fatalf("write err=%v want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler write did not time out")
	}
}

func TestNativeHTTP1IdleTimeoutClosesKeepAlive(t *testing.T) {
	srv, addr := nativeHTTP1StartConfiguredTestServer(t, &nativeHTTP1Server{
		IdleTimeout: 50 * time.Millisecond,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}),
	})
	defer srv.Close()

	conn, br := nativeHTTP1DialRaw(t, addr)
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := br.Peek(1); err == nil {
		t.Fatal("idle keep-alive connection stayed open")
	}
}

func TestNativeHTTP1ServeTLSPopulatesRequestState(t *testing.T) {
	cert := nativeHTTP1TestCertificate(t)
	got := make(chan struct {
		tlsOK  bool
		host   string
		remote string
		local  bool
	}, 1)
	srv, addr := nativeHTTP1StartConfiguredTLSServer(t, &nativeHTTP1Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, localOK := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
			got <- struct {
				tlsOK  bool
				host   string
				remote string
				local  bool
			}{
				tlsOK:  r.TLS != nil,
				host:   r.Host,
				remote: r.RemoteAddr,
				local:  localOK,
			}
			_, _ = w.Write([]byte("ok"))
		}),
	}, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer srv.Close()

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("tls Dial: %v", err)
	}
	defer conn.Close()
	expectedRemote := conn.LocalAddr().String()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	state := <-got
	if !state.tlsOK {
		t.Fatal("Request.TLS was nil")
	}
	if state.host != "app.example" {
		t.Fatalf("Host=%q want app.example", state.host)
	}
	if state.remote != expectedRemote {
		t.Fatalf("RemoteAddr=%q want %q", state.remote, expectedRemote)
	}
	if !state.local {
		t.Fatal("LocalAddrContextKey was not populated")
	}
}

func TestNativeHTTP1TLSHandshakeTimeoutAndH2ALPNRefusal(t *testing.T) {
	cert := nativeHTTP1TestCertificate(t)
	var handlerCalls atomicCounter
	srv, addr := nativeHTTP1StartConfiguredTLSServer(t, &nativeHTTP1Server{
		TLSHandshakeTimeout: 40 * time.Millisecond,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			handlerCalls.Add(1)
		}),
	}, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer srv.Close()

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("raw Dial: %v", err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := raw.Read(buf); err == nil {
		t.Fatal("stalled TLS handshake stayed readable")
	}
	_ = raw.Close()
	if got := srv.tlsHandshakeFailures.Load(); got == 0 {
		t.Fatal("tlsHandshakeFailures was not incremented")
	}

	_, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err == nil {
		t.Fatal("h2-only ALPN client unexpectedly connected")
	}
	if got := handlerCalls.Load(); got != 0 {
		t.Fatalf("handlerCalls=%d want 0", got)
	}
}

func TestNativeHTTP1ListenerWrappedRemoteAddr(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	announced := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 4242}
	wrapped := &nativeHTTP1AddrConn{Conn: serverConn, remote: announced, local: nativeHTTP1StaticAddr("proxy-local")}
	ln := &nativeHTTP1SingleConnListener{conn: wrapped, addr: nativeHTTP1StaticAddr("proxy-listener")}
	remoteCh := make(chan string, 1)
	srv := &nativeHTTP1Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteCh <- r.RemoteAddr
		_, _ = w.Write([]byte("ok"))
	})}
	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	}()
	defer srv.Close()

	if _, err := io.WriteString(clientConn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got := <-remoteCh; got != announced.String() {
		t.Fatalf("RemoteAddr=%q want %q", got, announced.String())
	}
}

func nativeHTTP1StartConfiguredTestServer(t *testing.T, srv *nativeHTTP1Server) (*nativeHTTP1Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if srv == nil {
		srv = &nativeHTTP1Server{}
	}
	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	}()
	return srv, ln.Addr().String()
}

func nativeHTTP1StartConfiguredTLSServer(t *testing.T, srv *nativeHTTP1Server, tlsConfig *tls.Config) (*nativeHTTP1Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if srv == nil {
		srv = &nativeHTTP1Server{}
	}
	go func() {
		err := srv.ServeTLS(ln, tlsConfig)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("ServeTLS: %v", err)
		}
	}()
	return srv, ln.Addr().String()
}

func nativeHTTP1TestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}

type nativeHTTP1SingleConnListener struct {
	conn net.Conn
	addr net.Addr
	once sync.Once
	done chan struct{}
}

func (l *nativeHTTP1SingleConnListener) Accept() (net.Conn, error) {
	if l.done == nil {
		l.done = make(chan struct{})
	}
	var out net.Conn
	l.once.Do(func() {
		out = l.conn
	})
	if out != nil {
		return out, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *nativeHTTP1SingleConnListener) Close() error {
	if l.done == nil {
		l.done = make(chan struct{})
	}
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *nativeHTTP1SingleConnListener) Addr() net.Addr {
	if l.addr != nil {
		return l.addr
	}
	return nativeHTTP1StaticAddr("single-conn")
}

type nativeHTTP1StaticAddr string

func (a nativeHTTP1StaticAddr) Network() string { return "test" }
func (a nativeHTTP1StaticAddr) String() string  { return string(a) }

type nativeHTTP1AddrConn struct {
	net.Conn
	remote net.Addr
	local  net.Addr
}

func (c *nativeHTTP1AddrConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

func (c *nativeHTTP1AddrConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.Conn.LocalAddr()
}

type atomicCounter struct {
	mu sync.Mutex
	n  int
}

func (c *atomicCounter) Add(n int) {
	c.mu.Lock()
	c.n += n
	c.mu.Unlock()
}

func (c *atomicCounter) Load() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
