package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidatePprofListenAddrAllowsOnlyLoopback(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{name: "localhost", addr: "localhost:6060"},
		{name: "ipv4 loopback", addr: "127.0.0.1:6060"},
		{name: "ipv6 loopback", addr: "[::1]:6060"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := validatePprofListenAddr(tt.addr); err != nil {
				t.Fatalf("validatePprofListenAddr(%q) error = %v", tt.addr, err)
			}
		})
	}
}

func TestValidatePprofListenAddrRejectsPublicOrAmbiguousBinds(t *testing.T) {
	tests := []string{
		":6060",
		"0.0.0.0:6060",
		"[::]:6060",
		"192.0.2.10:6060",
		"127.0.0.1:0",
		"127.0.0.1:not-a-port",
	}
	for _, addr := range tests {
		t.Run(addr, func(t *testing.T) {
			if _, err := validatePprofListenAddr(addr); err == nil {
				t.Fatalf("validatePprofListenAddr(%q) expected error", addr)
			}
		})
	}
}

func TestPprofMuxServesProfilesWithoutDefaultMux(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)

	newPprofMux().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Types of profiles available") {
		t.Fatalf("pprof index response missing profile list: %s", rec.Body.String())
	}
}
