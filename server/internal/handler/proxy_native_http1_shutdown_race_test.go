package handler

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestNativeHTTP1ServerRejectsConnectionReturnedAfterShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	release := make(chan struct{})
	releaseAccept := sync.OnceFunc(func() { close(release) })
	delayed := &nativeHTTP1DelayedAcceptListener{
		Listener: ln,
		accepted: make(chan struct{}),
		release:  release,
	}
	srv := &nativeHTTP1Server{Handler: http.NotFoundHandler()}
	serveDone := make(chan struct{})
	var serveErr error
	go func() {
		serveErr = srv.Serve(delayed)
		close(serveDone)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		releaseAccept()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not exit during cleanup")
		}
	})

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	select {
	case <-delayed.accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not accept the connection")
	}

	// The listener owns this connection until Accept returns it to Serve.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown while Accept is returning: %v", err)
	}
	releaseAccept()
	select {
	case <-serveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit after rejecting the connection")
	}
	if !errors.Is(serveErr, http.ErrServerClosed) {
		t.Fatalf("Serve error=%v, want ErrServerClosed", serveErr)
	}
	if got := srv.acceptedConnections.Load(); got != 0 {
		t.Errorf("acceptedConnections=%d, want 0", got)
	}
	if got := srv.rejectedConnections.Load(); got != 1 {
		t.Errorf("rejectedConnections=%d, want 1", got)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var buf [1]byte
	if _, err := conn.Read(buf[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("rejected connection read error=%v, want EOF", err)
	}
}

type nativeHTTP1DelayedAcceptListener struct {
	net.Listener
	accepted chan struct{}
	release  <-chan struct{}
}

func (ln *nativeHTTP1DelayedAcceptListener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err == nil {
		close(ln.accepted)
		<-ln.release
	}
	return conn, err
}
