package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"tukuyomi/internal/config"
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
