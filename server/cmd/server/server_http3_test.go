package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"tukuyomi/internal/config"
	"tukuyomi/internal/serverruntime"
)

func TestServerHTTP3AltSvcHeader(t *testing.T) {
	t.Parallel()

	got, err := serverHTTP3AltSvcHeader(":9443", 86400)
	if err != nil {
		t.Fatalf("serverHTTP3AltSvcHeader: %v", err)
	}
	if got != `h3=":9443"; ma=86400` {
		t.Fatalf("unexpected alt-svc header: %q", got)
	}
}

func TestWrapHTTP3AltSvcHandlerAddsHeader(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodGet, "https://proxy.example.test/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	rec := httptest.NewRecorder()
	wrapHTTP3AltSvcHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), `h3=":443"; ma=86400`).ServeHTTP(rec, req)
	if got := rec.Header().Get("Alt-Svc"); got != `h3=":443"; ma=86400` {
		t.Fatalf("unexpected Alt-Svc header: %q", got)
	}
}

func TestHTTP3ServerStartsAndAdvertisesAltSvc(t *testing.T) {
	restore := setServerTLSGlobalsForTest(t)
	defer restore()
	serverruntime.ResetHTTP3Status()

	certFile, keyFile := writeServerTLSFiles(t, []string{"127.0.0.1", "localhost"})
	tlsConfig, err := config.BuildServerTLSConfig(certFile, keyFile, "tls1.2")
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}

	port := reserveLocalPort(t)
	addr := net.JoinHostPort("127.0.0.1", port)
	config.ListenAddr = addr
	config.ServerTLSEnabled = true
	config.ServerHTTP3Enabled = true
	config.ServerHTTP3AltSvcMaxAgeSec = 86400
	config.ServerMaxHeaderBytes = 1 << 20
	config.ServerIdleTimeout = 30 * time.Second

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	http3Srv, altSvc, err := buildManagedServerHTTP3Server(tlsConfig, baseHandler)
	if err != nil {
		t.Fatalf("buildManagedServerHTTP3Server: %v", err)
	}
	if altSvc == "" {
		t.Fatal("expected Alt-Svc header value")
	}
	http3Lifecycle := newManagedServerLifecycle(2 * time.Second)
	if err := runHTTP3Server(http3Lifecycle, nil, http3Srv); err != nil {
		t.Fatalf("runHTTP3Server: %v", err)
	}
	defer func() {
		if err := http3Lifecycle.shutdown(); err != nil {
			t.Fatalf("http3 shutdown: %v", err)
		}
	}()

	httpsSrv := &http.Server{
		Addr:      addr,
		Handler:   wrapHTTP3AltSvcHandler(baseHandler, altSvc),
		TLSConfig: tlsConfig,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpsSrv.ListenAndServeTLS("", "")
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpsSrv.Shutdown(ctx)
		select {
		case err := <-errCh:
			if err != nil && err != http.ErrServerClosed {
				t.Fatalf("https server exit: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for https server shutdown")
		}
	}()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = client.Get("https://" + addr + "/")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("https request failed: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Alt-Svc"); !strings.Contains(got, `h3=":`) || !strings.Contains(got, `ma=86400`) {
		t.Fatalf("unexpected Alt-Svc header: %q", got)
	}
	if !serverruntime.HTTP3StatusSnapshot().Advertised {
		t.Fatal("expected advertised http3 runtime status")
	}

	http3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer http3Transport.Close()
	http3Client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: http3Transport,
	}
	http3Resp, err := http3Client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("http3 request failed: %v", err)
	}
	defer http3Resp.Body.Close()
	http3Body, err := io.ReadAll(http3Resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(http3): %v", err)
	}
	if http3Resp.StatusCode != http.StatusOK || string(http3Body) != "ok" {
		t.Fatalf("unexpected http3 response: status=%d body=%q", http3Resp.StatusCode, string(http3Body))
	}
}

func reserveLocalPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return port
}
