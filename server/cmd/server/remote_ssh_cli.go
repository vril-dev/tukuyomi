package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"tukuyomi/internal/centertls"
	"tukuyomi/internal/remotestream"
)

type remoteSSHCommandConfig struct {
	CenterURL         string
	APIBase           string
	DeviceID          string
	LocalAddr         string
	TTLSec            int64
	Reason            string
	Token             string
	AllowInsecureHTTP bool
	CenterCABundle    string
	CenterServerName  string
}

type remoteSSHSessionCreateResponse struct {
	Session struct {
		SessionID   string `json:"session_id"`
		AttachToken string `json:"attach_token"`
		ExpiresAt   int64  `json:"expires_at_unix"`
	} `json:"session"`
}

type remoteSSHDeviceViewResponse struct {
	Sessions []remoteSSHSessionViewRecord `json:"sessions"`
}

type remoteSSHSessionViewRecord struct {
	SessionID              string `json:"session_id"`
	GatewayHostPublicKey   string `json:"gateway_host_public_key"`
	GatewayConnectedAtUnix int64  `json:"gateway_connected_at_unix"`
}

func runRemoteSSHCommand(args []string) {
	cfg, err := parseRemoteSSHCommandConfig(args, os.Environ())
	if err != nil {
		logFatalRemoteSSH(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runRemoteSSH(ctx, cfg); err != nil {
		logFatalRemoteSSH(err)
	}
}

func parseRemoteSSHCommandConfig(args []string, env []string) (remoteSSHCommandConfig, error) {
	fs := flag.NewFlagSet("remote-ssh", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := remoteSSHCommandConfig{}
	fs.StringVar(&cfg.CenterURL, "center", envValue(env, "TUKUYOMI_REMOTE_SSH_CENTER_URL"), "Center base URL")
	fs.StringVar(&cfg.APIBase, "api-base", "/center-api", "Center admin API base path")
	fs.StringVar(&cfg.DeviceID, "device", "", "device id")
	fs.StringVar(&cfg.LocalAddr, "local", "127.0.0.1:0", "local listen address")
	fs.Int64Var(&cfg.TTLSec, "ttl", 900, "session TTL seconds")
	fs.StringVar(&cfg.Reason, "reason", "", "audit reason")
	fs.StringVar(&cfg.Token, "token", envValue(env, "TUKUYOMI_ADMIN_TOKEN"), "admin bearer token")
	fs.BoolVar(&cfg.AllowInsecureHTTP, "allow-insecure-http", parseBoolEnv(envValue(env, "TUKUYOMI_REMOTE_SSH_ALLOW_INSECURE_HTTP")), "allow http:// Center URL for local testing only")
	fs.StringVar(&cfg.CenterCABundle, "center-ca-bundle", envValue(env, "TUKUYOMI_REMOTE_SSH_CENTER_CA_BUNDLE"), "PEM CA bundle for private Center TLS")
	fs.StringVar(&cfg.CenterServerName, "center-server-name", envValue(env, "TUKUYOMI_REMOTE_SSH_CENTER_SERVER_NAME"), "TLS server name for Center certificate verification")
	if err := fs.Parse(args); err != nil {
		return remoteSSHCommandConfig{}, err
	}
	cfg.CenterURL = strings.TrimRight(strings.TrimSpace(cfg.CenterURL), "/")
	cfg.APIBase = "/" + strings.Trim(strings.TrimSpace(cfg.APIBase), "/")
	cfg.DeviceID = strings.TrimSpace(cfg.DeviceID)
	cfg.LocalAddr = strings.TrimSpace(cfg.LocalAddr)
	cfg.Reason = strings.TrimSpace(cfg.Reason)
	cfg.Token = strings.TrimSpace(cfg.Token)
	cfg.CenterCABundle = strings.TrimSpace(cfg.CenterCABundle)
	cfg.CenterServerName = strings.TrimSpace(cfg.CenterServerName)
	if cfg.CenterURL == "" || cfg.DeviceID == "" || cfg.LocalAddr == "" || cfg.Token == "" {
		return remoteSSHCommandConfig{}, fmt.Errorf("remote-ssh requires --center, --device, --local, and --token or TUKUYOMI_ADMIN_TOKEN")
	}
	if cfg.TTLSec < 60 || cfg.TTLSec > 86400 {
		return remoteSSHCommandConfig{}, fmt.Errorf("remote-ssh --ttl must be between 60 and 86400 seconds")
	}
	if cfg.Reason == "" {
		return remoteSSHCommandConfig{}, fmt.Errorf("remote-ssh --reason is required")
	}
	u, err := url.Parse(cfg.CenterURL)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return remoteSSHCommandConfig{}, fmt.Errorf("remote-ssh --center must be an http(s) base URL without credentials, query, or fragment")
	}
	if u.Scheme != "https" && !cfg.AllowInsecureHTTP {
		return remoteSSHCommandConfig{}, fmt.Errorf("remote-ssh --center must use https unless --allow-insecure-http is set for local testing")
	}
	if err := centertls.ValidateConfig(centertls.Config{CABundleFile: cfg.CenterCABundle, ServerName: cfg.CenterServerName}); err != nil {
		return remoteSSHCommandConfig{}, err
	}
	return cfg, nil
}

func runRemoteSSH(ctx context.Context, cfg remoteSSHCommandConfig) error {
	publicKey, keyPath, knownHostsPath, cleanup, err := createRemoteSSHEphemeralKey()
	if err != nil {
		return err
	}
	defer cleanup()
	session, err := createRemoteSSHCenterSession(ctx, cfg, publicKey)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.LocalAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	localAddr := ln.Addr().String()
	sshHost, port := remoteSSHLocalHostPort(localAddr)
	hostPublicKey, err := waitRemoteSSHGatewayHostKey(ctx, cfg, session.Session.SessionID, session.Session.ExpiresAt)
	if err != nil {
		return err
	}
	if err := writeRemoteSSHKnownHosts(knownHostsPath, sshHost, port, hostPublicKey); err != nil {
		return err
	}
	fmt.Printf("remote ssh session %s ready until %s\n", session.Session.SessionID, time.Unix(session.Session.ExpiresAt, 0).UTC().Format(time.RFC3339))
	fmt.Printf("ssh -i %s -p %s -o IdentitiesOnly=yes -o UserKnownHostsFile=%s -o StrictHostKeyChecking=yes tukuyomi@%s\n", shellQuote(keyPath), port, shellQuote(knownHostsPath), sshHost)
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		connCh <- conn
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	case localConn := <-connCh:
		defer localConn.Close()
		streamURL, err := remoteSSHOperatorStreamURL(cfg.CenterURL)
		if err != nil {
			return err
		}
		headers := http.Header{}
		headers.Set("Authorization", "Bearer "+cfg.Token)
		headers.Set("X-Tukuyomi-Remote-SSH-Session-ID", session.Session.SessionID)
		headers.Set("X-Tukuyomi-Remote-SSH-Attach-Token", session.Session.AttachToken)
		tlsConfig, err := remoteSSHCenterTLSConfig(cfg)
		if err != nil {
			return err
		}
		remoteConn, err := remotestream.DialUpgradeWithOptions(ctx, streamURL, headers, remotestream.DialOptions{TLSConfig: tlsConfig})
		if err != nil {
			return err
		}
		defer remoteConn.Close()
		return proxyRemoteSSHConns(localConn, remoteConn)
	}
}

func waitRemoteSSHGatewayHostKey(ctx context.Context, cfg remoteSSHCommandConfig, sessionID string, expiresAtUnix int64) (string, error) {
	wait := 30 * time.Second
	if expiresAtUnix > 0 {
		remaining := time.Until(time.Unix(expiresAtUnix, 0))
		if remaining < wait {
			wait = remaining
		}
	}
	if wait <= 0 {
		return "", fmt.Errorf("remote ssh session expired before gateway attached")
	}
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		hostKey, err := fetchRemoteSSHGatewayHostKey(waitCtx, cfg, sessionID)
		if err == nil && hostKey != "" {
			return hostKey, nil
		}
		select {
		case <-waitCtx.Done():
			if err != nil {
				return "", fmt.Errorf("gateway did not attach remote ssh host key: %w", err)
			}
			return "", fmt.Errorf("gateway did not attach remote ssh host key before timeout")
		case <-ticker.C:
		}
	}
}

func fetchRemoteSSHGatewayHostKey(ctx context.Context, cfg remoteSSHCommandConfig, sessionID string) (string, error) {
	endpoint, err := remoteSSHDeviceViewURL(cfg.CenterURL, cfg.APIBase, cfg.DeviceID)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	client, err := remoteSSHHTTPClient(cfg)
	if err != nil {
		return "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64*1024))
	if err != nil {
		return "", err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("load remote ssh session status failed: HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	var view remoteSSHDeviceViewResponse
	if err := json.Unmarshal(raw, &view); err != nil {
		return "", err
	}
	for _, session := range view.Sessions {
		if session.SessionID == sessionID && session.GatewayConnectedAtUnix > 0 && strings.TrimSpace(session.GatewayHostPublicKey) != "" {
			return strings.TrimSpace(session.GatewayHostPublicKey), nil
		}
	}
	return "", nil
}

func createRemoteSSHCenterSession(ctx context.Context, cfg remoteSSHCommandConfig, publicKey string) (remoteSSHSessionCreateResponse, error) {
	endpoint, err := remoteSSHSessionCreateURL(cfg.CenterURL, cfg.APIBase, cfg.DeviceID)
	if err != nil {
		return remoteSSHSessionCreateResponse{}, err
	}
	body, err := json.Marshal(map[string]any{
		"operator_public_key": publicKey,
		"ttl_sec":             cfg.TTLSec,
		"reason":              cfg.Reason,
	})
	if err != nil {
		return remoteSSHSessionCreateResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return remoteSSHSessionCreateResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	client, err := remoteSSHHTTPClient(cfg)
	if err != nil {
		return remoteSSHSessionCreateResponse{}, err
	}
	res, err := client.Do(req)
	if err != nil {
		return remoteSSHSessionCreateResponse{}, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64*1024))
	if err != nil {
		return remoteSSHSessionCreateResponse{}, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return remoteSSHSessionCreateResponse{}, fmt.Errorf("create remote ssh session failed: HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out remoteSSHSessionCreateResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return remoteSSHSessionCreateResponse{}, err
	}
	if out.Session.SessionID == "" || out.Session.AttachToken == "" {
		return remoteSSHSessionCreateResponse{}, fmt.Errorf("create remote ssh session response is missing session token")
	}
	return out, nil
}

func remoteSSHCenterTLSConfig(cfg remoteSSHCommandConfig) (*tls.Config, error) {
	return centertls.BuildTLSConfig(centertls.Config{
		CABundleFile: cfg.CenterCABundle,
		ServerName:   cfg.CenterServerName,
	})
}

func remoteSSHHTTPClient(cfg remoteSSHCommandConfig) (*http.Client, error) {
	return centertls.HTTPClient(centertls.Config{
		CABundleFile: cfg.CenterCABundle,
		ServerName:   cfg.CenterServerName,
	})
}

func createRemoteSSHEphemeralKey() (string, string, string, func(), error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", nil, err
	}
	sshPrivateBlock, err := ssh.MarshalPrivateKey(privateKey, "tukuyomi-remote-ssh")
	if err != nil {
		return "", "", "", nil, err
	}
	sshPublic, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return "", "", "", nil, err
	}
	dir, err := os.MkdirTemp("", "tukuyomi-remote-ssh-*")
	if err != nil {
		return "", "", "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(sshPrivateBlock), 0600); err != nil {
		cleanup()
		return "", "", "", nil, err
	}
	knownHostsPath := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(knownHostsPath, nil, 0600); err != nil {
		cleanup()
		return "", "", "", nil, err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic))), keyPath, knownHostsPath, cleanup, nil
}

func remoteSSHSessionCreateURL(centerURL string, apiBase string, deviceID string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(centerURL), "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("center URL is invalid")
	}
	u.Path = strings.TrimRight(apiBase, "/") + "/devices/" + url.PathEscape(deviceID) + "/remote-ssh/sessions"
	u.RawPath = ""
	return u.String(), nil
}

func remoteSSHDeviceViewURL(centerURL string, apiBase string, deviceID string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(centerURL), "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("center URL is invalid")
	}
	u.Path = strings.TrimRight(apiBase, "/") + "/devices/" + url.PathEscape(deviceID) + "/remote-ssh"
	u.RawQuery = "limit=20"
	u.RawPath = ""
	return u.String(), nil
}

func writeRemoteSSHKnownHosts(path string, host string, port string, hostPublicKey string) error {
	hostPublicKey = strings.TrimSpace(hostPublicKey)
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostPublicKey)); err != nil {
		return fmt.Errorf("gateway remote ssh host key is invalid: %w", err)
	}
	line := remoteSSHKnownHostsHost(host, port) + " " + hostPublicKey + "\n"
	return os.WriteFile(path, []byte(line), 0600)
}

func remoteSSHKnownHostsHost(host string, port string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" || port == "22" {
		return host
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return "[" + host + "]:" + port
}

func remoteSSHOperatorStreamURL(centerURL string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(centerURL), "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("center URL is invalid")
	}
	u.Path = "/v1/remote-ssh/operator-stream"
	u.RawPath = ""
	return u.String(), nil
}

func proxyRemoteSSHConns(left net.Conn, right net.Conn) error {
	var once sync.Once
	closeBoth := func() {
		_ = left.Close()
		_ = right.Close()
	}
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(left, right)
		once.Do(closeBoth)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(right, left)
		once.Do(closeBoth)
		errCh <- err
	}()
	err := <-errCh
	if err != nil && !isRemoteSSHClosedConnErr(err) {
		return err
	}
	return nil
}

func isRemoteSSHClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "use of closed network connection") || strings.Contains(text, "closed pipe") || strings.Contains(text, "connection reset by peer")
}

func envValue(env []string, key string) string {
	for _, item := range env {
		name, value, ok := strings.Cut(item, "=")
		if ok && name == key {
			return value
		}
	}
	return ""
}

func parseBoolEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func remoteSSHLocalHostPort(addr string) (string, string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1", "0"
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host, port
}

func logFatalRemoteSSH(err error) {
	fmt.Fprintf(os.Stderr, "remote-ssh: %v\n", err)
	os.Exit(2)
}
