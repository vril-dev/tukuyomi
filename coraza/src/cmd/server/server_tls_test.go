package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

func TestACMEHTTPRedirectServerPreservesChallengePath(t *testing.T) {
	t.Parallel()

	manager := &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(t.TempDir())}
	runtime := &managedServerTLSRuntime{}
	runtime.mu.Lock()
	runtime.acmeManager = manager
	runtime.mu.Unlock()
	srv := newDynamicHTTPRedirectServer(":8080", ":9443", runtime)

	challengeReq := httptest.NewRequest(http.MethodGet, "http://proxy.example.com/.well-known/acme-challenge/token", nil)
	challengeRes := httptest.NewRecorder()
	srv.Handler.ServeHTTP(challengeRes, challengeReq)
	if challengeRes.Code == http.StatusPermanentRedirect {
		t.Fatal("acme challenge path should not redirect")
	}

	appReq := httptest.NewRequest(http.MethodGet, "http://proxy.example.com/app", nil)
	appRes := httptest.NewRecorder()
	srv.Handler.ServeHTTP(appRes, appReq)
	if appRes.Code != http.StatusPermanentRedirect {
		t.Fatalf("unexpected app redirect status: %d", appRes.Code)
	}
	if location := appRes.Header().Get("Location"); location != "https://proxy.example.com:9443/app" {
		t.Fatalf("unexpected redirect location: %q", location)
	}
}

func TestBuildManagedServerTLSConfigPrefersSiteCertificateForMatchingSNI(t *testing.T) {
	restore := setServerTLSGlobalsForTest(t)
	defer restore()

	config.ServerTLSEnabled = true
	config.ServerTLSMinVersion = "tls1.2"

	legacyCertFile, legacyKeyFile := writeServerTLSFiles(t, []string{"legacy.example.com"})
	siteCertFile, siteKeyFile := writeServerTLSFiles(t, []string{"app.example.com"})
	config.ServerTLSCertFile = legacyCertFile
	config.ServerTLSKeyFile = legacyKeyFile

	tmp := t.TempDir()
	sitesPath := filepath.Join(tmp, "sites.json")
	raw := `{
  "sites": [
    {
      "name": "app",
      "hosts": ["app.example.com"],
      "default_upstream": "http://app.internal:8080",
      "tls": {
        "mode": "manual",
        "cert_file": ` + jsonStringForServerTLS(siteCertFile) + `,
        "key_file": ` + jsonStringForServerTLS(siteKeyFile) + `
      }
    }
  ]
}`
	if err := os.WriteFile(sitesPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile(sites): %v", err)
	}
	if err := handler.InitSiteRuntime(sitesPath, 2); err != nil {
		t.Fatalf("InitSiteRuntime: %v", err)
	}

	tlsConfig, _, err := buildManagedServerTLSConfig()
	if err != nil {
		t.Fatalf("buildManagedServerTLSConfig: %v", err)
	}

	siteCert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate(app): %v", err)
	}
	legacyCert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "legacy.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate(legacy): %v", err)
	}

	siteLeaf, err := x509.ParseCertificate(siteCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate(site): %v", err)
	}
	legacyLeaf, err := x509.ParseCertificate(legacyCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate(legacy): %v", err)
	}

	if siteLeaf.Subject.CommonName != "app.example.com" {
		t.Fatalf("site CN=%q want=%q", siteLeaf.Subject.CommonName, "app.example.com")
	}
	if legacyLeaf.Subject.CommonName != "legacy.example.com" {
		t.Fatalf("legacy CN=%q want=%q", legacyLeaf.Subject.CommonName, "legacy.example.com")
	}
}

func setServerTLSGlobalsForTest(t *testing.T) func() {
	t.Helper()

	prevEnabled := config.ServerTLSEnabled
	prevMinVersion := config.ServerTLSMinVersion
	prevCertFile := config.ServerTLSCertFile
	prevKeyFile := config.ServerTLSKeyFile
	prevACMEEnabled := config.ServerTLSACMEEnabled
	prevACMEEmail := config.ServerTLSACMEEmail
	prevACMEDomains := append([]string(nil), config.ServerTLSACMEDomains...)
	prevACMECacheDir := config.ServerTLSACMECacheDir
	prevACMEStaging := config.ServerTLSACMEStaging
	prevRedirect := config.ServerTLSRedirectHTTP
	prevRedirectAddr := config.ServerTLSHTTPRedirectAddr
	prevListenAddr := config.ListenAddr
	handler.SetServerTLSReloadHook(nil)

	return func() {
		config.ServerTLSEnabled = prevEnabled
		config.ServerTLSMinVersion = prevMinVersion
		config.ServerTLSCertFile = prevCertFile
		config.ServerTLSKeyFile = prevKeyFile
		config.ServerTLSACMEEnabled = prevACMEEnabled
		config.ServerTLSACMEEmail = prevACMEEmail
		config.ServerTLSACMEDomains = prevACMEDomains
		config.ServerTLSACMECacheDir = prevACMECacheDir
		config.ServerTLSACMEStaging = prevACMEStaging
		config.ServerTLSRedirectHTTP = prevRedirect
		config.ServerTLSHTTPRedirectAddr = prevRedirectAddr
		config.ListenAddr = prevListenAddr
		handler.SetServerTLSReloadHook(nil)
	}
}

func writeServerTLSFiles(t *testing.T, dnsNames []string) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	commonName := "localhost"
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              append([]string(nil), dnsNames...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
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

func jsonStringForServerTLS(v string) string {
	return `"` + filepath.ToSlash(v) + `"`
}
