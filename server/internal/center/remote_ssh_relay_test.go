package center

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func TestRemoteSSHRelayHubPairsGatewayAndOperator(t *testing.T) {
	hub := newRemoteSSHRelayHub()
	gatewayClient, gatewayServer := net.Pipe()
	operatorClient, operatorServer := net.Pipe()
	defer gatewayClient.Close()
	defer operatorClient.Close()

	errCh := make(chan error, 2)
	go func() {
		errCh <- hub.attach(context.Background(), "session-1", "gateway", gatewayServer)
	}()
	go func() {
		errCh <- hub.attach(context.Background(), "session-1", "operator", operatorServer)
	}()

	if _, err := operatorClient.Write([]byte("ping")); err != nil {
		t.Fatalf("operator write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(gatewayClient, got); err != nil {
		t.Fatalf("gateway read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("gateway got %q want ping", string(got))
	}
	if _, err := gatewayClient.Write([]byte("pong")); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
	if _, err := io.ReadFull(operatorClient, got); err != nil {
		t.Fatalf("operator read: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("operator got %q want pong", string(got))
	}
	_ = gatewayClient.Close()
	_ = operatorClient.Close()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("attach returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("relay attach did not return")
		}
	}
}

func TestRemoteSSHRelayHubClosesIdlePair(t *testing.T) {
	oldIdleTimeout := config.RemoteSSHIdleTimeout
	config.RemoteSSHIdleTimeout = 30 * time.Millisecond
	t.Cleanup(func() {
		config.RemoteSSHIdleTimeout = oldIdleTimeout
	})

	hub := newRemoteSSHRelayHub()
	gatewayClient, gatewayServer := net.Pipe()
	operatorClient, operatorServer := net.Pipe()
	defer gatewayClient.Close()
	defer operatorClient.Close()

	errCh := make(chan error, 2)
	go func() {
		errCh <- hub.attach(context.Background(), "idle-session-1", "gateway", gatewayServer)
	}()
	go func() {
		errCh <- hub.attach(context.Background(), "idle-session-1", "operator", operatorServer)
	}()

	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err == nil || !strings.Contains(err.Error(), "idle timeout") {
				t.Fatalf("attach error=%v want idle timeout", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("idle relay attach did not return")
		}
	}
}

func TestRemoteSSHRelayHubTerminatesStartedPair(t *testing.T) {
	hub := newRemoteSSHRelayHub()
	gatewayClient, gatewayServer := net.Pipe()
	operatorClient, operatorServer := net.Pipe()
	defer gatewayClient.Close()
	defer operatorClient.Close()

	errCh := make(chan error, 2)
	go func() {
		errCh <- hub.attach(context.Background(), "terminate-started", "gateway", gatewayServer)
	}()
	go func() {
		errCh <- hub.attach(context.Background(), "terminate-started", "operator", operatorServer)
	}()
	if _, err := operatorClient.Write([]byte("ping")); err != nil {
		t.Fatalf("operator write before terminate: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(gatewayClient, got); err != nil {
		t.Fatalf("gateway read before terminate: %v", err)
	}
	if !hub.terminate("terminate-started", "operator terminated") {
		t.Fatal("terminate should find started relay pair")
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err == nil || !strings.Contains(err.Error(), "operator terminated") {
				t.Fatalf("attach error=%v want operator terminated", err)
			}
		case <-time.After(time.Second):
			t.Fatal("terminated relay attach did not return")
		}
	}
}

func TestRemoteSSHRelayHubTerminatesWaitingPair(t *testing.T) {
	hub := newRemoteSSHRelayHub()
	gatewayClient, gatewayServer := net.Pipe()
	defer gatewayClient.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- hub.attach(context.Background(), "terminate-waiting", "gateway", gatewayServer)
	}()
	deadline := time.After(time.Second)
	for {
		hub.mu.Lock()
		_, registered := hub.sessions["terminate-waiting"]
		hub.mu.Unlock()
		if registered {
			break
		}
		select {
		case <-deadline:
			t.Fatal("waiting relay pair was not registered")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if !hub.terminate("terminate-waiting", "operator terminated") {
		t.Fatal("terminate should find waiting relay pair")
	}
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "operator terminated") {
			t.Fatalf("attach error=%v want operator terminated", err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminated waiting relay attach did not return")
	}
}

func TestRemoteSSHOperatorStreamRequiresAdminAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	registerDeviceEnrollmentRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/v1/remote-ssh/operator-stream", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", remoteSSHUpgradeProtocol)
	req.Header.Set("X-Tukuyomi-Remote-SSH-Session-ID", "session-1")
	req.Header.Set("X-Tukuyomi-Remote-SSH-Attach-Token", "attach-token")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%q", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}
