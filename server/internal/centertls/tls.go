package centertls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

type Config struct {
	CABundleFile string
	ServerName   string
}

func BuildTLSConfig(cfg Config) (*tls.Config, error) {
	caBundleFile := strings.TrimSpace(cfg.CABundleFile)
	serverName := strings.TrimSpace(cfg.ServerName)
	if err := ValidateConfig(Config{CABundleFile: caBundleFile, ServerName: serverName}); err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if caBundleFile == "" {
		return tlsCfg, nil
	}
	raw, err := os.ReadFile(caBundleFile)
	if err != nil {
		return nil, fmt.Errorf("read center tls ca bundle: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("center tls ca bundle does not contain a valid PEM certificate")
	}
	tlsCfg.RootCAs = roots
	return tlsCfg, nil
}

func ValidateConfig(cfg Config) error {
	if strings.Contains(strings.TrimSpace(cfg.CABundleFile), "\x00") {
		return fmt.Errorf("center tls ca bundle file contains invalid NUL byte")
	}
	return validateServerName(strings.TrimSpace(cfg.ServerName))
}

func HTTPClient(cfg Config) (*http.Client, error) {
	tlsCfg, err := BuildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	return &http.Client{Transport: transport}, nil
}

func validateServerName(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 253 {
		return fmt.Errorf("center tls server name must be 253 bytes or less")
	}
	if net.ParseIP(value) != nil {
		return nil
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f || r == '/' || r == '\\' || r == ':' {
			return fmt.Errorf("center tls server name contains invalid characters")
		}
	}
	return nil
}
