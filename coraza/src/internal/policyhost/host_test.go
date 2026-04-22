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
}

func TestNormalizePatternInvalid(t *testing.T) {
	cases := []string{
		"",
		"*.example.com",
		"example.com/path",
		"example.com:99999",
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Candidates(tc.host, tc.tls); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Candidates() = %v want %v", got, tc.want)
			}
		})
	}
}
