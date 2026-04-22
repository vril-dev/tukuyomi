package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
)

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value must not be empty")
	}
	*f = append(*f, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "gen-cert":
		if err := runGenCert(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "[http3smoke][ERROR] %v\n", err)
			os.Exit(1)
		}
	case "check":
		if err := runCheck(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "[http3smoke][ERROR] %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  http3smoke gen-cert --cert-file <path> --key-file <path> --host localhost --host 127.0.0.1")
	fmt.Fprintln(os.Stderr, "  http3smoke check --url <https-url> [--host override] [--expect-status 200] [--expect-substring text] [--insecure]")
}

func runGenCert(args []string) error {
	fs := flag.NewFlagSet("gen-cert", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var certFile string
	var keyFile string
	var hosts stringListFlag
	fs.StringVar(&certFile, "cert-file", "", "certificate output path")
	fs.StringVar(&keyFile, "key-file", "", "private key output path")
	fs.Var(&hosts, "host", "dns name or ip address to include in SAN")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" {
		return fmt.Errorf("both --cert-file and --key-file are required")
	}
	if len(hosts) == 0 {
		return fmt.Errorf("at least one --host is required")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hosts[0],
		},
		NotBefore:             time.Now().Add(-1 * time.Hour).UTC(),
		NotAfter:              time.Now().Add(24 * time.Hour).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o755); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	certOut, err := os.OpenFile(certFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("write cert pem: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyOut, err := os.OpenFile(keyFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open key file: %w", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("write key pem: %w", err)
	}

	fmt.Printf("[http3smoke] wrote self-signed cert: %s, %s\n", certFile, keyFile)
	return nil
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var url string
	var host string
	var timeoutSec int
	var insecure bool
	var expectStatus int
	var expectSubstrings stringListFlag
	fs.StringVar(&url, "url", "", "https url to request")
	fs.StringVar(&host, "host", "", "optional Host header override")
	fs.IntVar(&timeoutSec, "timeout-sec", 5, "request timeout in seconds")
	fs.BoolVar(&insecure, "insecure", false, "skip certificate verification")
	fs.IntVar(&expectStatus, "expect-status", http.StatusOK, "expected HTTP status code")
	fs.Var(&expectSubstrings, "expect-substring", "body substring that must be present")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(url) == "" {
		return fmt.Errorf("--url is required")
	}
	if timeoutSec <= 0 {
		return fmt.Errorf("--timeout-sec must be > 0")
	}

	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	defer transport.Close()

	client := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if strings.TrimSpace(host) != "" {
		req.Host = strings.TrimSpace(host)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http3 request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != expectStatus {
		return fmt.Errorf("unexpected status: got=%d want=%d body=%q", resp.StatusCode, expectStatus, string(body))
	}
	for _, needle := range expectSubstrings {
		if !strings.Contains(string(body), needle) {
			return fmt.Errorf("response body missing substring %q: %s", needle, string(body))
		}
	}

	fmt.Printf("[http3smoke] HTTP/3 request ok status=%d url=%s\n", resp.StatusCode, url)
	return nil
}
