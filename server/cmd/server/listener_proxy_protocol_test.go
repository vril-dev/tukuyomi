package main

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type listenerReadResult struct {
	remoteAddr string
	payload    string
	err        error
}

func TestWrapManagedTCPListenerProxyProtocol(t *testing.T) {
	t.Run("trusted peer proxy header rewrites remote addr", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		defer ln.Close()

		wrapped, err := wrapManagedTCPListener(ln, listenerProxyProtocolRuntime{
			enabled:           true,
			trustedCIDRs:      []string{"127.0.0.1/32"},
			readHeaderTimeout: time.Second,
		})
		if err != nil {
			t.Fatalf("wrapManagedTCPListener: %v", err)
		}

		results := make(chan listenerReadResult, 1)
		go acceptAndReadOnce(wrapped, results)

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "PROXY TCP4 198.51.100.10 203.0.113.5 45678 80\r\nPING"); err != nil {
			t.Fatalf("write trusted proxy header: %v", err)
		}

		result := <-results
		if result.err != nil {
			t.Fatalf("accept/read err: %v", result.err)
		}
		if result.payload != "PING" {
			t.Fatalf("payload=%q want=PONG", result.payload)
		}
		if result.remoteAddr != "198.51.100.10:45678" {
			t.Fatalf("remoteAddr=%q want=198.51.100.10:45678", result.remoteAddr)
		}
	})

	t.Run("untrusted peer proxy header is rejected", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		defer ln.Close()

		wrapped, err := wrapManagedTCPListener(ln, listenerProxyProtocolRuntime{
			enabled:           true,
			trustedCIDRs:      []string{"10.0.0.0/8"},
			readHeaderTimeout: time.Second,
		})
		if err != nil {
			t.Fatalf("wrapManagedTCPListener: %v", err)
		}

		results := make(chan listenerReadResult, 1)
		go acceptAndReadOnce(wrapped, results)

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "PROXY TCP4 198.51.100.10 203.0.113.5 45678 80\r\nPING"); err != nil {
			t.Fatalf("write untrusted proxy header: %v", err)
		}

		result := <-results
		if result.err == nil {
			t.Fatal("expected proxy header rejection error")
		}
		if !strings.Contains(result.err.Error(), "isn't allowed to send one") {
			t.Fatalf("unexpected err=%v", result.err)
		}
	})

	t.Run("direct client without proxy header remains accepted", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		defer ln.Close()

		wrapped, err := wrapManagedTCPListener(ln, listenerProxyProtocolRuntime{
			enabled:           true,
			trustedCIDRs:      []string{"10.0.0.0/8"},
			readHeaderTimeout: time.Second,
		})
		if err != nil {
			t.Fatalf("wrapManagedTCPListener: %v", err)
		}

		results := make(chan listenerReadResult, 1)
		go acceptAndReadOnce(wrapped, results)

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "PING"); err != nil {
			t.Fatalf("write direct payload: %v", err)
		}

		result := <-results
		if result.err != nil {
			t.Fatalf("accept/read err: %v", result.err)
		}
		if result.payload != "PING" {
			t.Fatalf("payload=%q want=PING", result.payload)
		}
		if !strings.HasPrefix(result.remoteAddr, "127.0.0.1:") {
			t.Fatalf("remoteAddr=%q want loopback peer", result.remoteAddr)
		}
	})
}

func TestWrapManagedTCPListenerRejectsEmptyTrustList(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	if _, err := wrapManagedTCPListener(ln, listenerProxyProtocolRuntime{enabled: true}); err == nil {
		t.Fatal("expected empty trust list error")
	}
}

func acceptAndReadOnce(ln net.Listener, out chan<- listenerReadResult) {
	conn, err := ln.Accept()
	if err != nil {
		out <- listenerReadResult{err: err}
		return
	}
	defer conn.Close()
	buf := make([]byte, 4)
	n, readErr := conn.Read(buf)
	out <- listenerReadResult{
		remoteAddr: conn.RemoteAddr().String(),
		payload:    string(buf[:n]),
		err:        readErr,
	}
}
