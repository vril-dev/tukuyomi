package config

import (
	"strings"
	"testing"
)

const testRemoteSSHCenterSigningPublicKey = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

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

func TestValidateAppEdgeDeviceStatusRefreshInterval(t *testing.T) {
	t.Run("accepts zero to disable polling", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Edge.DeviceAuth.StatusRefreshIntervalSec = 0

		if err := validateAppConfigFile(cfg); err != nil {
			t.Fatalf("validateAppConfigFile() error = %v", err)
		}
	})

	t.Run("rejects negative interval", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Edge.DeviceAuth.StatusRefreshIntervalSec = -1

		err := validateAppConfigFile(cfg)
		if err == nil {
			t.Fatal("expected edge device status refresh interval error")
		}
		if got := err.Error(); got != "edge.device_auth.status_refresh_interval_sec must be between 0 and 3600" {
			t.Fatalf("error=%q want edge status refresh interval error", got)
		}
	})

	t.Run("rejects excessive interval", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Edge.DeviceAuth.StatusRefreshIntervalSec = MaxEdgeDeviceStatusRefreshSec + 1

		err := validateAppConfigFile(cfg)
		if err == nil {
			t.Fatal("expected edge device status refresh interval error")
		}
		if got := err.Error(); got != "edge.device_auth.status_refresh_interval_sec must be between 0 and 3600" {
			t.Fatalf("error=%q want edge status refresh interval error", got)
		}
	})
}

func TestValidateAppRemoteSSHConfig(t *testing.T) {
	t.Run("defaults are disabled and valid", func(t *testing.T) {
		cfg := defaultAppConfigFile()

		if err := validateAppConfigFile(cfg); err != nil {
			t.Fatalf("validateAppConfigFile() error = %v", err)
		}
		if cfg.RemoteSSH.Center.Enabled || cfg.RemoteSSH.Gateway.Enabled || cfg.RemoteSSH.Gateway.EmbeddedServer.Enabled {
			t.Fatal("remote ssh defaults must be disabled")
		}
		if cfg.RemoteSSH.Center.MaxTTLSec != DefaultRemoteSSHMaxTTLSec {
			t.Fatalf("max ttl=%d want=%d", cfg.RemoteSSH.Center.MaxTTLSec, DefaultRemoteSSHMaxTTLSec)
		}
	})

	t.Run("rejects center enable without edge", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.RemoteSSH.Center.Enabled = true

		err := validateAppConfigFile(cfg)
		if err == nil {
			t.Fatal("expected remote ssh center edge dependency error")
		}
		if got := err.Error(); got != "remote_ssh.center.enabled requires edge.enabled=true" {
			t.Fatalf("error=%q want center edge dependency error", got)
		}
	})

	t.Run("accepts explicit center and gateway enable with edge", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Edge.Enabled = true
		cfg.RemoteSSH.Center.Enabled = true
		cfg.RemoteSSH.Gateway.Enabled = true
		cfg.RemoteSSH.Gateway.EmbeddedServer.Enabled = true
		cfg.RemoteSSH.Gateway.CenterSigningPublicKey = testRemoteSSHCenterSigningPublicKey
		cfg.RemoteSSH.Gateway.CenterTLSCABundleFile = " conf/center-ca.pem "
		cfg.RemoteSSH.Gateway.CenterTLSServerName = " center.example.local "
		normalizeAppConfigFile(&cfg)

		if err := validateAppConfigFile(cfg); err != nil {
			t.Fatalf("validateAppConfigFile() error = %v", err)
		}
		if cfg.RemoteSSH.Gateway.CenterTLSCABundleFile != "conf/center-ca.pem" || cfg.RemoteSSH.Gateway.CenterTLSServerName != "center.example.local" {
			t.Fatalf("remote ssh tls settings not normalized: %+v", cfg.RemoteSSH.Gateway)
		}
	})

	t.Run("rejects embedded gateway without pinned center signing key", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Edge.Enabled = true
		cfg.RemoteSSH.Gateway.Enabled = true
		cfg.RemoteSSH.Gateway.EmbeddedServer.Enabled = true

		err := validateAppConfigFile(cfg)
		if err == nil {
			t.Fatal("expected remote ssh center signing key error")
		}
		if got := err.Error(); got != "remote_ssh.gateway.center_signing_public_key is required when remote_ssh.gateway.embedded_server.enabled=true" {
			t.Fatalf("error=%q want center signing key error", got)
		}
	})

	t.Run("rejects embedded server without gateway", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Edge.Enabled = true
		cfg.RemoteSSH.Gateway.EmbeddedServer.Enabled = true

		err := validateAppConfigFile(cfg)
		if err == nil {
			t.Fatal("expected embedded server gateway dependency error")
		}
		if got := err.Error(); got != "remote_ssh.gateway.embedded_server.enabled requires remote_ssh.gateway.enabled=true" {
			t.Fatalf("error=%q want embedded server gateway dependency error", got)
		}
	})

	t.Run("rejects idle timeout beyond ttl", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.RemoteSSH.Center.MaxTTLSec = 120
		cfg.RemoteSSH.Center.IdleTimeoutSec = 121

		err := validateAppConfigFile(cfg)
		if err == nil {
			t.Fatal("expected remote ssh idle timeout error")
		}
		if got := err.Error(); got != "remote_ssh.center.idle_timeout_sec must be between 30 and min(3600, remote_ssh.center.max_ttl_sec)" {
			t.Fatalf("error=%q want idle timeout error", got)
		}
	})

	t.Run("rejects relative embedded shell", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.RemoteSSH.Gateway.EmbeddedServer.Shell = "sh"

		err := validateAppConfigFile(cfg)
		if err == nil {
			t.Fatal("expected remote ssh shell path error")
		}
		if got := err.Error(); got != "remote_ssh.gateway.embedded_server.shell must be an absolute path" {
			t.Fatalf("error=%q want shell path error", got)
		}
	})

	t.Run("rejects invalid center tls server name", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.RemoteSSH.Gateway.CenterTLSServerName = "https://center.example.local"

		err := validateAppConfigFile(cfg)
		if err == nil {
			t.Fatal("expected remote ssh center tls server name error")
		}
		if got := err.Error(); got != "remote_ssh.gateway.center_tls_server_name contains invalid characters" {
			t.Fatalf("error=%q want center tls server name error", got)
		}
	})
}

func TestValidateAppRuntimeProcessModel(t *testing.T) {
	t.Run("accepts supported models", func(t *testing.T) {
		for _, model := range []string{RuntimeProcessModelSingle, RuntimeProcessModelSupervised} {
			cfg := defaultAppConfigFile()
			cfg.Runtime.ProcessModel = model

			if err := validateAppConfigFile(cfg); err != nil {
				t.Fatalf("validateAppConfigFile(%s) error = %v", model, err)
			}
		}
	})

	t.Run("rejects unsupported model", func(t *testing.T) {
		cfg := defaultAppConfigFile()
		cfg.Runtime.ProcessModel = "forking"

		err := validateAppConfigFile(cfg)
		if err == nil {
			t.Fatal("expected runtime process model error")
		}
		if got := err.Error(); got != "runtime.process_model must be single or supervised" {
			t.Fatalf("error=%q want runtime process model error", got)
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
