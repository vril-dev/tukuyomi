package center

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"tukuyomi/internal/adminauth"
)

func TestRemoteSSHWebTerminalCreateHidesAttachTokenAndChecksOwner(t *testing.T) {
	setupRemoteSSHStoreTest(t)
	insertRemoteSSHApprovedDeviceForTest(t, "edge-remote-web-terminal")
	oldManager := remoteSSHWebTerminals
	remoteSSHWebTerminals = newRemoteSSHWebTerminalManager()
	t.Cleanup(func() {
		remoteSSHWebTerminals = oldManager
	})

	ctx := context.Background()
	if _, err := UpsertRemoteSSHPolicy(ctx, RemoteSSHPolicyUpdate{
		DeviceID:      "edge-remote-web-terminal",
		Enabled:       true,
		MaxTTLSec:     120,
		RequireReason: true,
		UpdatedAtUnix: 1000,
	}); err != nil {
		t.Fatalf("UpsertRemoteSSHPolicy: %v", err)
	}
	principal := adminauth.Principal{
		UserID:   42,
		Username: "owner",
		Role:     adminauth.AdminRoleOwner,
		AuthKind: adminauth.AuthKindSession,
	}
	out, err := remoteSSHWebTerminals.create(ctx, "edge-remote-web-terminal", remoteSSHWebTerminalCreateRequest{
		Reason: "web terminal",
		TTLSec: 300,
		Rows:   1,
		Cols:   999,
	}, principal, "203.0.113.10", "test-browser")
	if err != nil {
		t.Fatalf("create web terminal: %v", err)
	}
	if out.TerminalID == "" || out.Session.SessionID == "" {
		t.Fatalf("web terminal response missing identifiers: %+v", out)
	}
	if out.Session.AttachToken != "" {
		t.Fatalf("web terminal response leaked attach token")
	}
	if out.Session.OperatorMode != RemoteSSHOperatorModeWeb {
		t.Fatalf("operator_mode=%q want %q", out.Session.OperatorMode, RemoteSSHOperatorModeWeb)
	}
	if _, err := remoteSSHWebTerminals.claim(out.TerminalID, adminauth.Principal{
		UserID:   43,
		Username: "other",
		Role:     adminauth.AdminRoleOwner,
		AuthKind: adminauth.AuthKindSession,
	}); !errors.Is(err, ErrRemoteSSHSessionNotFound) {
		t.Fatalf("claim by different owner error=%v want ErrRemoteSSHSessionNotFound", err)
	}
	rec, err := remoteSSHWebTerminals.claim(out.TerminalID, principal)
	if err != nil {
		t.Fatalf("claim by owner: %v", err)
	}
	if rec.AttachToken == "" {
		t.Fatalf("manager record must retain attach token for one-time operator attach")
	}
	if rec.Rows != remoteSSHWebTerminalMinRows || rec.Cols != remoteSSHWebTerminalMaxCols {
		t.Fatalf("terminal size clamp rows=%d cols=%d", rec.Rows, rec.Cols)
	}
}

func TestRemoteSSHWebTerminalAcceptClearsHTTPServerReadDeadline(t *testing.T) {
	errCh := make(chan error, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := acceptRemoteSSHWebTerminal(w, r)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "closed")
		time.Sleep(160 * time.Millisecond)
		readCtx, cancelRead := context.WithTimeout(context.Background(), time.Second)
		defer cancelRead()
		_, payload, err := conn.Read(readCtx)
		if err != nil {
			errCh <- err
			return
		}
		if string(payload) != "ping" {
			errCh <- errors.New("unexpected websocket payload")
			return
		}
		errCh <- conn.Write(readCtx, websocket.MessageText, []byte("pong"))
	}))
	srv.Config.ReadTimeout = 50 * time.Millisecond
	srv.Start()
	defer srv.Close()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDial()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{remoteSSHWebTerminalSubprotocol},
	})
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "closed")
	time.Sleep(120 * time.Millisecond)
	if err := conn.Write(dialCtx, websocket.MessageText, []byte("ping")); err != nil {
		t.Fatalf("write websocket after server read timeout: %v", err)
	}
	_, payload, err := conn.Read(dialCtx)
	if err != nil {
		t.Fatalf("read websocket response: %v", err)
	}
	if string(payload) != "pong" {
		t.Fatalf("websocket response=%q want pong", payload)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server websocket error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server websocket handler did not finish")
	}
}
