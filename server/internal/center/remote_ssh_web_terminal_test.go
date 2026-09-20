package center

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

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

func TestRemoteSSHWebTerminalAcceptOriginAndProtocol(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := acceptRemoteSSHWebTerminal(w, r)
		if err == nil {
			defer conn.CloseNow()
			_, _, _ = conn.Read(r.Context())
		}
	}))
	defer srv.Close()
	for _, tc := range []struct {
		name   string
		origin string
		accept bool
	}{
		{name: "same origin", origin: srv.URL, accept: true},
		{name: "cross origin", origin: "https://untrusted.example"},
		{name: "malformed origin", origin: "://invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), &websocket.DialOptions{
				HTTPHeader:      http.Header{"Origin": []string{tc.origin}},
				Subprotocols:    []string{remoteSSHWebTerminalSubprotocol},
				CompressionMode: websocket.CompressionContextTakeover,
			})
			if conn != nil {
				defer conn.CloseNow()
			}
			if !tc.accept {
				if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
					t.Fatalf("unauthorized origin: response=%v error=%v", resp, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("accept same origin: %v", err)
			}
			if conn.Subprotocol() != remoteSSHWebTerminalSubprotocol {
				t.Fatalf("subprotocol=%q", conn.Subprotocol())
			}
			if got := resp.Header.Get("Sec-WebSocket-Extensions"); got != "" {
				t.Fatalf("compression must remain disabled, negotiated extensions=%q", got)
			}
		})
	}
}

func TestRemoteSSHWebTerminalReadInputLimit(t *testing.T) {
	// Preserve the existing 32 KiB message limit across WebSocket implementations.
	const readLimit = 32 * 1024
	minimalInput, err := json.Marshal(remoteSSHWebTerminalMessage{Type: "input", Data: "x"})
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{readLimit, readLimit + 1} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, done, stdin := startRemoteSSHWebTerminalInputForTest(t, ctx)
			input := strings.Repeat("x", size-len(minimalInput)+1)
			payload, err := json.Marshal(remoteSSHWebTerminalMessage{Type: "input", Data: input})
			if err != nil {
				t.Fatal(err)
			}
			if len(payload) != size {
				t.Fatalf("payload length=%d want %d", len(payload), size)
			}
			if err := conn.Write(ctx, websocket.MessageText, payload); err != nil {
				t.Fatalf("write input: %v", err)
			}
			if size <= readLimit {
				if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"close"}`)); err != nil {
					t.Fatalf("close input: %v", err)
				}
			} else {
				_, _, err := conn.Read(ctx)
				if websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
					t.Fatalf("oversized message close status=%v error=%v", websocket.CloseStatus(err), err)
				}
			}
			select {
			case err := <-done:
				if size <= readLimit {
					if err != nil || stdin.String() != input {
						t.Fatalf("input at limit: forwarded=%d bytes error=%v", stdin.Len(), err)
					}
				} else if err == nil || stdin.Len() != 0 {
					t.Fatalf("oversized input: forwarded=%d bytes error=%v", stdin.Len(), err)
				}
			case <-ctx.Done():
				t.Fatal("input reader did not finish")
			}
		})
	}
}

func TestRemoteSSHWebTerminalReadInputStops(t *testing.T) {
	for _, stop := range []string{"cancel", "close", "disconnect"} {
		t.Run(stop, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn, done, _ := startRemoteSSHWebTerminalInputForTest(t, ctx)
			if stop == "cancel" {
				cancel()
			} else if stop == "close" {
				if err := conn.Close(websocket.StatusNormalClosure, "closed"); err != nil {
					t.Fatalf("close websocket: %v", err)
				}
			} else if err := conn.CloseNow(); err != nil {
				t.Fatalf("disconnect websocket: %v", err)
			}
			select {
			case err := <-done:
				if stop == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled input error=%v", err)
				}
				if stop == "close" && websocket.CloseStatus(err) != websocket.StatusNormalClosure {
					t.Fatalf("closed input error=%v", err)
				}
				if stop == "disconnect" && err == nil {
					t.Fatal("abrupt disconnect must return a read error")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("input reader remained blocked")
			}
		})
	}
}

func startRemoteSSHWebTerminalInputForTest(t *testing.T, ctx context.Context) (*websocket.Conn, <-chan error, *bytes.Buffer) {
	t.Helper()
	done := make(chan error, 1)
	stdin := new(bytes.Buffer)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := acceptRemoteSSHWebTerminal(w, r)
		if err != nil {
			done <- err
			return
		}
		defer conn.CloseNow()
		remoteSSHWebTerminalReadInput(ctx, conn, nil, stdin, nil, done)
	}))
	t.Cleanup(srv.Close)
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(dialCtx, "ws"+strings.TrimPrefix(srv.URL, "http"), &websocket.DialOptions{
		Subprotocols: []string{remoteSSHWebTerminalSubprotocol},
	})
	if err != nil {
		t.Fatalf("dial input websocket: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn, done, stdin
}
