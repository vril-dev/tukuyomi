package remotestream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDialUpgradeRelaysBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != Protocol {
			t.Errorf("Upgrade=%q want %q", r.Header.Get("Upgrade"), Protocol)
			http.Error(w, "missing upgrade", http.StatusUpgradeRequired)
			return
		}
		h, ok := w.(http.Hijacker)
		if !ok {
			t.Error("response writer is not hijackable")
			return
		}
		conn, rw, err := h.Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = rw.Writer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + Protocol + "\r\n\r\n")
		if err := rw.Writer.Flush(); err != nil {
			t.Errorf("Flush: %v", err)
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("ReadFull: %v", err)
			return
		}
		if string(buf) != "ping" {
			t.Errorf("payload=%q want ping", string(buf))
			return
		}
		_, _ = conn.Write([]byte("pong"))
	}))
	defer server.Close()

	conn, err := DialUpgrade(context.Background(), server.URL+"/stream", nil)
	if err != nil {
		t.Fatalf("DialUpgrade: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("response=%q want pong", string(got))
	}
}

func TestDialUpgradeRejectsBadScheme(t *testing.T) {
	if _, err := DialUpgrade(context.Background(), "ftp://127.0.0.1/stream", nil); err == nil {
		t.Fatal("expected bad scheme error")
	}
}

func TestDialUpgradeWithOptionsTrustsPrivateCA(t *testing.T) {
	server := httptest.NewTLSServer(remoteStreamEchoHandler(t))
	defer server.Close()

	if _, err := DialUpgrade(context.Background(), server.URL+"/stream", nil); err == nil {
		t.Fatal("expected default trust store to reject test server certificate")
	}

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	conn, err := DialUpgradeWithOptions(context.Background(), server.URL+"/stream", nil, DialOptions{
		TLSConfig: &tls.Config{RootCAs: roots},
	})
	if err != nil {
		t.Fatalf("DialUpgradeWithOptions: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("response=%q want pong", string(got))
	}
}

func remoteStreamEchoHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != Protocol {
			t.Errorf("Upgrade=%q want %q", r.Header.Get("Upgrade"), Protocol)
			http.Error(w, "missing upgrade", http.StatusUpgradeRequired)
			return
		}
		h, ok := w.(http.Hijacker)
		if !ok {
			t.Error("response writer is not hijackable")
			return
		}
		conn, rw, err := h.Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = rw.Writer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + Protocol + "\r\n\r\n")
		if err := rw.Writer.Flush(); err != nil {
			t.Errorf("Flush: %v", err)
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("ReadFull: %v", err)
			return
		}
		if string(buf) != "ping" {
			t.Errorf("payload=%q want ping", string(buf))
			return
		}
		_, _ = conn.Write([]byte("pong"))
	})
}
