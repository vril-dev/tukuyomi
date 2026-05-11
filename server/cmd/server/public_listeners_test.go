package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"tukuyomi/internal/config"
	"tukuyomi/internal/serverruntime"
)

func TestRunConfiguredPublicListenersKeepsHTTPSetupWhenTLSUnavailable(t *testing.T) {
	restore := saveSupervisorListenerConfig()
	defer restore()

	config.ServerPublicListeners = []config.ServerPublicListener{
		{Name: "setup", ListenAddr: "127.0.0.1:0", Protocol: config.PublicListenerProtocolHTTP, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
		{Name: "https", ListenAddr: "127.0.0.1:0", Protocol: config.PublicListenerProtocolHTTPS, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
		{Name: "http", ListenAddr: "127.0.0.1:0", Protocol: config.PublicListenerProtocolHTTP, HTTPBehavior: config.PublicListenerHTTPBehaviorRedirect, RedirectTo: "https", Enabled: true},
	}
	config.ServerReadHeaderTimeout = time.Second
	config.ServerIdleTimeout = time.Second

	lifecycle := newManagedServerLifecycle(time.Second)
	err := runConfiguredPublicListeners(
		lifecycle,
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		nil,
		listenerProxyProtocolRuntime{},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("runConfiguredPublicListeners() error = %v", err)
	}
	if got := len(lifecycle.shutdowns); got != 1 {
		t.Fatalf("started servers=%d want only the HTTP setup listener", got)
	}
	if err := lifecycle.shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestRunConfiguredPublicListenersRejectsNoStartableListener(t *testing.T) {
	restore := saveSupervisorListenerConfig()
	defer restore()

	config.ServerPublicListeners = []config.ServerPublicListener{
		{Name: "https", ListenAddr: "127.0.0.1:0", Protocol: config.PublicListenerProtocolHTTPS, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
	}

	lifecycle := newManagedServerLifecycle(time.Second)
	err := runConfiguredPublicListeners(
		lifecycle,
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		nil,
		listenerProxyProtocolRuntime{},
		nil,
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "no enabled public listener could start") {
		t.Fatalf("error=%v want no startable listener error", err)
	}
}

func TestRunConfiguredPublicListenersStartsHTTP3ForHTTPSRows(t *testing.T) {
	restoreTLS := setServerTLSGlobalsForTest(t)
	defer restoreTLS()
	restoreListener := saveSupervisorListenerConfig()
	defer restoreListener()
	serverruntime.ResetHTTP3Status()
	oldHTTP3Enabled := config.ServerHTTP3Enabled
	oldHTTP3MaxAge := config.ServerHTTP3AltSvcMaxAgeSec
	oldMaxHeaderBytes := config.ServerMaxHeaderBytes
	oldIdleTimeout := config.ServerIdleTimeout
	t.Cleanup(func() {
		config.ServerHTTP3Enabled = oldHTTP3Enabled
		config.ServerHTTP3AltSvcMaxAgeSec = oldHTTP3MaxAge
		config.ServerMaxHeaderBytes = oldMaxHeaderBytes
		config.ServerIdleTimeout = oldIdleTimeout
	})

	certFile, keyFile := writeServerTLSFiles(t, []string{"127.0.0.1", "localhost"})
	tlsConfig, err := config.BuildServerTLSConfig(certFile, keyFile, "tls1.2")
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}
	port := reserveLocalPort(t)
	addr := "127.0.0.1:" + port
	config.ServerTLSEnabled = true
	config.ServerHTTP3Enabled = true
	config.ServerHTTP3AltSvcMaxAgeSec = 123
	config.ServerMaxHeaderBytes = 1 << 20
	config.ServerIdleTimeout = 30 * time.Second
	config.ServerPublicListeners = []config.ServerPublicListener{
		{Name: "https", ListenAddr: addr, Protocol: config.PublicListenerProtocolHTTPS, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
	}

	lifecycle := newManagedServerLifecycle(2 * time.Second)
	if err := runConfiguredPublicListeners(
		lifecycle,
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
		nil,
		listenerProxyProtocolRuntime{},
		tlsConfig,
		nil,
	); err != nil {
		t.Fatalf("runConfiguredPublicListeners: %v", err)
	}
	defer func() {
		if err := lifecycle.shutdown(); err != nil {
			t.Fatalf("shutdown: %v", err)
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
	if got := resp.Header.Get("Alt-Svc"); got != `h3=":`+port+`"; ma=123` {
		t.Fatalf("unexpected Alt-Svc header: %q", got)
	}

	http3Transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer http3Transport.Close()
	http3Client := &http.Client{Timeout: 5 * time.Second, Transport: http3Transport}
	http3Resp, err := http3Client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("http3 request failed: %v", err)
	}
	defer http3Resp.Body.Close()
	body, err := io.ReadAll(http3Resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(http3): %v", err)
	}
	if http3Resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("unexpected http3 response: status=%d body=%q", http3Resp.StatusCode, string(body))
	}
}
