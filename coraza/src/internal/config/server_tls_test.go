package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadAppConfigFileAcceptsServerTLSConfig(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeTestTLSFiles(t)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"server": {
			"listen_addr": ":9443",
			"http3": {
				"enabled": true,
				"alt_svc_max_age_sec": 86400
			},
			"tls": {
				"enabled": true,
				"cert_file": ` + jsonString(certFile) + `,
				"key_file": ` + jsonString(keyFile) + `,
				"min_version": "1.3",
				"redirect_http": true,
				"http_redirect_addr": ":9080"
			}
		},
		"admin": {
			"api_base_path": "/tukuyomi-api",
			"ui_base_path": "/tukuyomi-ui",
			"api_key_primary": "very-strong-random-api-key-12345"
		},
		"paths": {
			"proxy_config_file": "conf/proxy.json",
			"rules_file": "rules/tukuyomi.conf"
		},
		"proxy": {"rollback_history_size": 8},
		"fp_tuner": {"timeout_sec": 15, "approval_ttl_sec": 600},
		"storage": {"db_driver": "sqlite"}
	}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadAppConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("loadAppConfigFile returned error: %v", err)
	}
	if !cfg.Server.TLS.Enabled {
		t.Fatal("expected server.tls.enabled=true")
	}
	if cfg.Server.TLS.MinVersion != "tls1.3" {
		t.Fatalf("unexpected server.tls.min_version: %q", cfg.Server.TLS.MinVersion)
	}
	if cfg.Server.TLS.HTTPRedirectAddr != ":9080" {
		t.Fatalf("unexpected server.tls.http_redirect_addr: %q", cfg.Server.TLS.HTTPRedirectAddr)
	}
	if !cfg.Server.HTTP3.Enabled {
		t.Fatal("expected server.http3.enabled=true")
	}
	if cfg.Server.HTTP3.AltSvcMaxAgeSec != 86400 {
		t.Fatalf("unexpected server.http3.alt_svc_max_age_sec: %d", cfg.Server.HTTP3.AltSvcMaxAgeSec)
	}
}

func TestLoadAppConfigFileRejectsInvalidServerTLSConfig(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeTestTLSFiles(t)
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing cert file",
			body: `{"enabled": true, "key_file": ` + jsonString(keyFile) + `}`,
			want: "server.tls.cert_file and server.tls.key_file must be set together when server.tls.enabled=true",
		},
		{
			name: "invalid min version",
			body: `{"enabled": true, "cert_file": ` + jsonString(certFile) + `, "key_file": ` + jsonString(keyFile) + `, "min_version": "tls1.1"}`,
			want: "server.tls min_version must be tls1.2 or tls1.3",
		},
		{
			name: "redirect without address",
			body: `{"enabled": true, "cert_file": ` + jsonString(certFile) + `, "key_file": ` + jsonString(keyFile) + `, "redirect_http": true}`,
			want: "server.tls.http_redirect_addr is required when server.tls.redirect_http=true",
		},
		{
			name: "http3 without tls",
			body: `{"enabled": false}`,
			want: "server.http3.enabled requires server.tls.enabled=true",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfgPath := filepath.Join(t.TempDir(), "config.json")
			http3Body := `{"enabled": false}`
			if tc.name == "http3 without tls" {
				http3Body = `{"enabled": true}`
			}
			raw := `{
				"server": {
					"listen_addr": ":9443",
					"http3": ` + http3Body + `,
					"tls": ` + tc.body + `
				},
				"admin": {
					"api_base_path": "/tukuyomi-api",
					"ui_base_path": "/tukuyomi-ui",
					"api_key_primary": "very-strong-random-api-key-12345"
				},
				"paths": {
					"proxy_config_file": "conf/proxy.json",
					"rules_file": "rules/tukuyomi.conf"
				},
				"proxy": {"rollback_history_size": 8},
				"fp_tuner": {"timeout_sec": 15, "approval_ttl_sec": 600},
				"storage": {"db_driver": "sqlite"}
			}`
			if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			_, err := loadAppConfigFile(cfgPath)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestLoadAppConfigFileAcceptsServerTLSCompositeFallbackConfig(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeTestTLSFiles(t)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"server": {
			"listen_addr": ":9443",
			"tls": {
				"enabled": true,
				"cert_file": ` + jsonString(certFile) + `,
				"key_file": ` + jsonString(keyFile) + `,
				"min_version": "1.2",
				"acme": {
					"enabled": true,
					"email": "ops@example.com",
					"domains": ["proxy.example.com"],
					"cache_dir": "/tmp/acme"
				}
			}
		},
		"admin": {
			"api_base_path": "/tukuyomi-api",
			"ui_base_path": "/tukuyomi-ui",
			"api_key_primary": "very-strong-random-api-key-12345"
		},
		"paths": {
			"proxy_config_file": "conf/proxy.json",
			"rules_file": "rules/tukuyomi.conf"
		},
		"proxy": {"rollback_history_size": 8},
		"fp_tuner": {"timeout_sec": 15, "approval_ttl_sec": 600},
		"storage": {"db_driver": "sqlite"}
	}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadAppConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("loadAppConfigFile returned error: %v", err)
	}
	if !cfg.Server.TLS.ACME.Enabled {
		t.Fatal("expected acme enabled")
	}
	if cfg.Server.TLS.CertFile != certFile || cfg.Server.TLS.KeyFile != keyFile {
		t.Fatalf("unexpected legacy fallback cert config: %#v", cfg.Server.TLS)
	}
}

func writeTestTLSFiles(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	certFile := filepath.Join(t.TempDir(), "server.crt")
	keyFile := filepath.Join(t.TempDir(), "server.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return certFile, keyFile
}

func jsonString(v string) string {
	return `"` + strings.ReplaceAll(v, `\`, `\\`) + `"`
}
