package centertls

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
	"testing"
	"time"
)

func TestBuildTLSConfigLoadsCABundleAndServerName(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, testCAPEM(t), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := BuildTLSConfig(Config{
		CABundleFile: caFile,
		ServerName:   "center.example.local",
	})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil")
	}
	if cfg.ServerName != "center.example.local" {
		t.Fatalf("ServerName=%q", cfg.ServerName)
	}
}

func TestBuildTLSConfigRejectsInvalidInputs(t *testing.T) {
	if _, err := BuildTLSConfig(Config{ServerName: "bad/name"}); err == nil {
		t.Fatal("expected invalid server name error")
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := BuildTLSConfig(Config{CABundleFile: caFile}); err == nil {
		t.Fatal("expected invalid bundle error")
	}
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tukuyomi-test-center-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
