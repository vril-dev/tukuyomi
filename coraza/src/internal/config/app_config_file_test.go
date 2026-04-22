package config

import (
	"strings"
	"testing"
)

func TestValidateAppAdminListenerConfig(t *testing.T) {
	t.Run("empty admin listen addr preserves single listener mode", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Admin.ListenAddr = ""

		if err := validateAppAdminListenerConfig(cfg); err != nil {
			t.Fatalf("validateAppAdminListenerConfig() error = %v", err)
		}
	})

	t.Run("rejects collision with public listener", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Server.ListenAddr = ":9090"
		cfg.Admin.ListenAddr = "127.0.0.1:9090"

		err := validateAppAdminListenerConfig(cfg)
		if err == nil {
			t.Fatal("expected collision error")
		}
		if got := err.Error(); got != "admin.listen_addr must be different from server.listen_addr" {
			t.Fatalf("error=%q want collision with server.listen_addr", got)
		}
	})

	t.Run("rejects collision with redirect listener", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Server.ListenAddr = ":443"
		cfg.Server.TLS.HTTPRedirectAddr = ":80"
		cfg.Admin.ListenAddr = "0.0.0.0:80"

		err := validateAppAdminListenerConfig(cfg)
		if err == nil {
			t.Fatal("expected collision error")
		}
		if got := err.Error(); got != "admin.listen_addr must be different from server.tls.http_redirect_addr" {
			t.Fatalf("error=%q want collision with server.tls.http_redirect_addr", got)
		}
	})

	t.Run("accepts distinct admin listener", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Server.ListenAddr = ":443"
		cfg.Server.TLS.HTTPRedirectAddr = ":80"
		cfg.Admin.ListenAddr = "127.0.0.1:9091"

		if err := validateAppAdminListenerConfig(cfg); err != nil {
			t.Fatalf("validateAppAdminListenerConfig() error = %v", err)
		}
	})

	t.Run("rejects invalid admin listener syntax", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Admin.ListenAddr = "bad::addr::value"

		err := validateAppAdminListenerConfig(cfg)
		if err == nil {
			t.Fatal("expected syntax error")
		}
		if got := err.Error(); !strings.HasPrefix(got, "admin.listen_addr invalid:") {
			t.Fatalf("error=%q want admin.listen_addr invalid prefix", got)
		}
	})
}

func TestValidateAppListenerProxyProtocolConfig(t *testing.T) {
	t.Run("rejects enabled server proxy protocol without trust list", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Server.ProxyProtocol.Enabled = true

		err := validateAppConfigFile(cfg)
		if err == nil {
			t.Fatal("expected server proxy protocol validation error")
		}
		if got := err.Error(); got != "server.proxy_protocol.trusted_cidrs is required when enabled=true" {
			t.Fatalf("error=%q want server proxy protocol trust-list error", got)
		}
	})

	t.Run("rejects admin proxy protocol without split admin listener", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Admin.ProxyProtocol.Enabled = true
		cfg.Admin.ProxyProtocol.TrustedCIDRs = []string{"127.0.0.1/32"}

		err := validateAppConfigFile(cfg)
		if err == nil {
			t.Fatal("expected admin proxy protocol listener error")
		}
		if got := err.Error(); got != "admin.proxy_protocol requires admin.listen_addr" {
			t.Fatalf("error=%q want admin proxy protocol split-listener error", got)
		}
	})

	t.Run("accepts public and split-admin proxy protocol trust lists", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Server.ProxyProtocol.Enabled = true
		cfg.Server.ProxyProtocol.TrustedCIDRs = []string{"10.0.0.0/8"}
		cfg.Admin.ListenAddr = ":9091"
		cfg.Admin.ProxyProtocol.Enabled = true
		cfg.Admin.ProxyProtocol.TrustedCIDRs = []string{"127.0.0.1/32"}

		if err := validateAppConfigFile(cfg); err != nil {
			t.Fatalf("validateAppConfigFile() error = %v", err)
		}
	})
}

func TestListenAddrsCollide(t *testing.T) {
	cases := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "wildcard collides with loopback on same port",
			a:    ":9090",
			b:    "127.0.0.1:9090",
			want: true,
		},
		{
			name: "different ports do not collide",
			a:    ":9090",
			b:    "127.0.0.1:9091",
			want: false,
		},
		{
			name: "different specific hosts on same port do not collide",
			a:    "127.0.0.1:9090",
			b:    "127.0.0.2:9090",
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := listenAddrsCollide(tc.a, tc.b); got != tc.want {
				t.Fatalf("listenAddrsCollide(%q, %q)=%v want=%v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
