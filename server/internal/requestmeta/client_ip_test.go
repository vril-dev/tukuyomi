package requestmeta

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestClientAddrFromTrustedProxies(t *testing.T) {
	trust := TrustedProxies{
		Header:   HeaderXForwardedFor,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8:ffff::/48")},
	}
	longChain := strings.TrimSuffix(strings.Repeat("10.0.0.9, ", maxForwardedForEntries+3), ", ")
	tests := []struct {
		name        string
		remoteAddr  string
		trust       TrustedProxies
		headers     map[string][]string
		want        string
		peerTrusted bool
	}{
		{name: "untrusted peer ignores headers", remoteAddr: "203.0.113.5:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"198.51.100.1"}, "X-Real-IP": {"198.51.100.2"}}, want: "203.0.113.5"},
		{name: "no trusted proxies", remoteAddr: "10.0.0.2:4000", headers: map[string][]string{"X-Forwarded-For": {"198.51.100.1"}}, want: "10.0.0.2"},
		{name: "trusted peer without header", remoteAddr: "10.0.0.2:4000", trust: trust, want: "10.0.0.2", peerTrusted: true},
		{name: "trusted peer single entry", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"198.51.100.1"}}, want: "198.51.100.1", peerTrusted: true},
		{name: "appending proxy keeps the spoofed entry on the left", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"10.0.0.5, 198.51.100.1"}}, want: "198.51.100.1", peerTrusted: true},
		{name: "trusted hops are skipped", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"192.0.2.1, 198.51.100.1, 10.0.0.3"}}, want: "198.51.100.1", peerTrusted: true},
		{name: "every entry trusted gives the leftmost", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"10.0.0.7, 10.0.0.3"}}, want: "10.0.0.7", peerTrusted: true},
		{name: "header lines are joined in order", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"192.0.2.1", "198.51.100.1"}}, want: "198.51.100.1", peerTrusted: true},
		{name: "entry with port", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"198.51.100.1:443"}}, want: "198.51.100.1", peerTrusted: true},
		{name: "bracketed IPv6 with port", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"[2001:db8::1]:443"}}, want: "2001:db8::1", peerTrusted: true},
		{name: "bracketed IPv6", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"[2001:db8::1]"}}, want: "2001:db8::1", peerTrusted: true},
		{name: "zone is dropped", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"fe80::1%eth0"}}, want: "fe80::1", peerTrusted: true},
		{name: "IPv4-mapped IPv6 is unmapped", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"::ffff:198.51.100.1"}}, want: "198.51.100.1", peerTrusted: true},
		{name: "IPv6 peer in a trusted prefix", remoteAddr: "[2001:db8:ffff::2]:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"198.51.100.1"}}, want: "198.51.100.1", peerTrusted: true},
		{name: "garbage entry gives the peer", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"198.51.100.1, not-an-ip"}}, want: "10.0.0.2", peerTrusted: true},
		{name: "empty entry gives the peer", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"198.51.100.1, "}}, want: "10.0.0.2", peerTrusted: true},
		{name: "X-Real-IP ignored when the header is X-Forwarded-For", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Real-IP": {"198.51.100.2"}}, want: "10.0.0.2", peerTrusted: true},
		{name: "chain longer than the bound", remoteAddr: "10.0.0.2:4000", trust: trust, headers: map[string][]string{"X-Forwarded-For": {"198.51.100.1, " + longChain}}, want: "10.0.0.9", peerTrusted: true},
		{name: "X-Real-IP header", remoteAddr: "10.0.0.2:4000", trust: TrustedProxies{Header: HeaderXRealIP, Prefixes: trust.Prefixes}, headers: map[string][]string{"X-Real-IP": {"198.51.100.2"}, "X-Forwarded-For": {"198.51.100.1"}}, want: "198.51.100.2", peerTrusted: true},
		{name: "two X-Real-IP lines give the peer", remoteAddr: "10.0.0.2:4000", trust: TrustedProxies{Header: HeaderXRealIP, Prefixes: trust.Prefixes}, headers: map[string][]string{"X-Real-IP": {"198.51.100.2", "198.51.100.3"}}, want: "10.0.0.2", peerTrusted: true},
		{name: "invalid X-Real-IP gives the peer", remoteAddr: "10.0.0.2:4000", trust: TrustedProxies{Header: HeaderXRealIP, Prefixes: trust.Prefixes}, headers: map[string][]string{"X-Real-IP": {"bad"}}, want: "10.0.0.2", peerTrusted: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://example.test/", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.RemoteAddr = tc.remoteAddr
			for name, values := range tc.headers {
				for _, value := range values {
					req.Header.Add(name, value)
				}
			}
			got, peerTrusted, ok := ClientAddr(req, tc.trust)
			if !ok || got.String() != tc.want || peerTrusted != tc.peerTrusted {
				t.Fatalf("ClientAddr=%s peerTrusted=%v ok=%v want %s peerTrusted=%v", got, peerTrusted, ok, tc.want, tc.peerTrusted)
			}
		})
	}
}

func TestClientIPFromRequestKeepsUnparsedRemoteAddr(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.RemoteAddr = "pipe"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got, trusted := ClientIPFromRequest(req, TrustedProxies{Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}); got != "pipe" || trusted {
		t.Fatalf("ClientIPFromRequest=%q trusted=%v want pipe false", got, trusted)
	}
}

func TestNormalizeForwardedHeader(t *testing.T) {
	for raw, want := range map[string]string{"": HeaderXForwardedFor, " x-forwarded-for ": HeaderXForwardedFor, "X-REAL-IP": HeaderXRealIP, "Forwarded": ""} {
		if got := NormalizeForwardedHeader(raw); got != want {
			t.Fatalf("NormalizeForwardedHeader(%q)=%q want %q", raw, got, want)
		}
	}
}
