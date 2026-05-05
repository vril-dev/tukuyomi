package remotestream

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const Protocol = "tukuyomi-remote-ssh"

type DialOptions struct {
	TLSConfig *tls.Config
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func DialUpgrade(ctx context.Context, rawURL string, headers http.Header) (net.Conn, error) {
	return DialUpgradeWithOptions(ctx, rawURL, headers, DialOptions{})
}

func DialUpgradeWithOptions(ctx context.Context, rawURL string, headers http.Header, opts DialOptions) (net.Conn, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("remote stream URL must be absolute")
	}
	if u.User != nil {
		return nil, fmt.Errorf("remote stream URL must not include credentials")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("remote stream URL scheme must be http or https")
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	address := u.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		if u.Scheme == "https" {
			address = net.JoinHostPort(u.Host, "443")
		} else {
			address = net.JoinHostPort(u.Host, "80")
		}
	}
	var conn net.Conn
	if u.Scheme == "https" {
		host := u.Hostname()
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
		if opts.TLSConfig != nil {
			tlsConfig = opts.TLSConfig.Clone()
			if tlsConfig.MinVersion == 0 {
				tlsConfig.MinVersion = tls.VersionTLS12
			}
			if strings.TrimSpace(tlsConfig.ServerName) == "" {
				tlsConfig.ServerName = host
			}
		}
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: tlsConfig}
		conn, err = tlsDialer.DialContext(ctx, "tcp", address)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", Protocol)
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(strings.TrimSpace(res.Header.Get("Upgrade")), Protocol) {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
		_ = conn.Close()
		if text := strings.TrimSpace(string(body)); text != "" {
			return nil, fmt.Errorf("remote stream upgrade failed: HTTP %d: %s", res.StatusCode, text)
		}
		return nil, fmt.Errorf("remote stream upgrade failed: HTTP %d", res.StatusCode)
	}
	if br.Buffered() > 0 {
		return bufferedConn{Conn: conn, reader: br}, nil
	}
	return conn, nil
}
