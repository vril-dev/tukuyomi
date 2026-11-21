package policyhost

import (
	"reflect"
	"testing"
)

func TestNormalizePattern(t *testing.T) {
	t.Run("host only", func(t *testing.T) {
		got, err := NormalizePattern("Example.COM")
		if err != nil {
			t.Fatalf("NormalizePattern() error = %v", err)
		}
		if got != "example.com" {
			t.Fatalf("NormalizePattern() = %q want %q", got, "example.com")
		}
	})

	t.Run("host and port", func(t *testing.T) {
		got, err := NormalizePattern("Example.COM:8080")
		if err != nil {
			t.Fatalf("NormalizePattern() error = %v", err)
		}
		if got != "example.com:8080" {
			t.Fatalf("NormalizePattern() = %q want %q", got, "example.com:8080")
		}
	})

	t.Run("ipv6 host and port", func(t *testing.T) {
		got, err := NormalizePattern("[2001:db8::1]:8443")
		if err != nil {
			t.Fatalf("NormalizePattern() error = %v", err)
		}
		if got != "[2001:db8::1]:8443" {
			t.Fatalf("NormalizePattern() = %q want %q", got, "[2001:db8::1]:8443")
		}
	})

	t.Run("trailing dot", func(t *testing.T) {
		got, err := NormalizePattern("Example.COM.")
		if err != nil {
			t.Fatalf("NormalizePattern() error = %v", err)
		}
		if got != "example.com" {
			t.Fatalf("NormalizePattern() = %q want %q", got, "example.com")
		}
	})

	t.Run("trailing dot and port", func(t *testing.T) {
		got, err := NormalizePattern("example.com.:8080")
		if err != nil {
			t.Fatalf("NormalizePattern() error = %v", err)
		}
		if got != "example.com:8080" {
			t.Fatalf("NormalizePattern() = %q want %q", got, "example.com:8080")
		}
	})
}

func TestNormalizePatternInvalid(t *testing.T) {
	cases := []string{
		"",
		"*.example.com",
		"example.com/path",
		"example.com:99999",
		"example.com:abc",
		".",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, err := NormalizePattern(tc); err == nil {
				t.Fatalf("NormalizePattern(%q) expected error", tc)
			}
		})
	}
}

func TestCandidates(t *testing.T) {
	cases := []struct {
		name string
		host string
		tls  bool
		want []string
	}{
		{
			name: "http host without port",
			host: "example.com",
			tls:  false,
			want: []string{"example.com:80", "example.com"},
		},
		{
			name: "https host without port",
			host: "example.com",
			tls:  true,
			want: []string{"example.com:443", "example.com"},
		},
		{
			name: "explicit non default port",
			host: "example.com:8080",
			tls:  false,
			want: []string{"example.com:8080", "example.com"},
		},
		{
			name: "explicit default port",
			host: "example.com:443",
			tls:  true,
			want: []string{"example.com:443", "example.com"},
		},
		{
			name: "upper case",
			host: "Example.COM",
			tls:  true,
			want: []string{"example.com:443", "example.com"},
		},
		{
			name: "ipv6 host and port",
			host: "[2001:db8::1]:8443",
			tls:  true,
			want: []string{"[2001:db8::1]:8443", "2001:db8::1"},
		},
		{
			name: "trailing dot",
			host: "example.com.",
			tls:  true,
			want: []string{"example.com:443", "example.com"},
		},
		{
			name: "trailing dot and port",
			host: "example.com.:8080",
			tls:  false,
			want: []string{"example.com:8080", "example.com"},
		},
		{
			name: "non numeric port is ignored like route matching",
			host: "example.com:abc",
			tls:  true,
			want: []string{"example.com:443", "example.com"},
		},
		{
			name: "out of range port is ignored like route matching",
			host: "example.com:99999",
			tls:  false,
			want: []string{"example.com:80", "example.com"},
		},
		{
			name: "userinfo is ignored like route matching",
			host: "user@example.com",
			tls:  true,
			want: []string{"example.com:443", "example.com"},
		},
		{
			name: "path suffix is ignored like route matching",
			host: "example.com/x",
			tls:  true,
			want: []string{"example.com:443", "example.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Candidates(tc.host, tc.tls); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Candidates() = %v want %v", got, tc.want)
			}
		})
	}
}

func TestCandidatesEmptyHost(t *testing.T) {
	for _, host := range []string{"", "  ", ".", ":8080"} {
		if got := Candidates(host, true); got != nil {
			t.Fatalf("Candidates(%q) = %v want nil", host, got)
		}
	}
}
