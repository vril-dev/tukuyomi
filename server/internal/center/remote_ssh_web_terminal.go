package center

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
	"nhooyr.io/websocket"

	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
)

const (
	remoteSSHWebTerminalConnectTTL  = 60 * time.Second
	remoteSSHWebTerminalMinRows     = 10
	remoteSSHWebTerminalMaxRows     = 80
	remoteSSHWebTerminalMinCols     = 20
	remoteSSHWebTerminalMaxCols     = 240
	remoteSSHWebTerminalDefaultRows = 24
	remoteSSHWebTerminalDefaultCols = 80
	remoteSSHWebTerminalSubprotocol = "tukuyomi.remote-ssh.web-terminal.v1"
	remoteSSHWebTerminalOutputChunk = 4 * 1024
)

type remoteSSHWebTerminalCreateRequest struct {
	Reason string `json:"reason"`
	TTLSec int64  `json:"ttl_sec"`
	Rows   int    `json:"rows"`
	Cols   int    `json:"cols"`
}

type remoteSSHWebTerminalCreateResponse struct {
	TerminalID    string                 `json:"terminal_id"`
	WebSocketPath string                 `json:"websocket_path"`
	Session       RemoteSSHSessionRecord `json:"session"`
	ExpiresAtUnix int64                  `json:"expires_at_unix"`
}

type remoteSSHWebTerminalMessage struct {
	Type    string `json:"type"`
	Data    string `json:"data,omitempty"`
	Rows    int    `json:"rows,omitempty"`
	Cols    int    `json:"cols,omitempty"`
	Message string `json:"message,omitempty"`
}

type remoteSSHWebTerminalRecord struct {
	TerminalID           string
	OwnerKey             string
	DeviceID             string
	SessionID            string
	AttachToken          string
	PrivateKey           ed25519.PrivateKey
	Rows                 int
	Cols                 int
	SessionExpiresAtUnix int64
	ConnectExpiresAtUnix int64
	Claimed              bool
	Cancel               context.CancelFunc
}

type remoteSSHWebTerminalManager struct {
	mu        sync.Mutex
	terminals map[string]*remoteSSHWebTerminalRecord
	bySession map[string]*remoteSSHWebTerminalRecord
}

var remoteSSHWebTerminals = newRemoteSSHWebTerminalManager()

func newRemoteSSHWebTerminalManager() *remoteSSHWebTerminalManager {
	return &remoteSSHWebTerminalManager{
		terminals: map[string]*remoteSSHWebTerminalRecord{},
		bySession: map[string]*remoteSSHWebTerminalRecord{},
	}
}

func postCenterDeviceRemoteSSHWebTerminal(c *gin.Context) {
	if config.AdminReadOnly {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin is read-only"})
		return
	}
	deviceID, ok := parseDeviceIDParam(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req remoteSSHWebTerminalCreateRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid remote ssh web terminal payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid remote ssh web terminal payload"})
		return
	}
	principal := centerAdminPrincipal(c)
	out, err := remoteSSHWebTerminals.create(c.Request.Context(), deviceID, req, principal, requestRemoteAddr(c.Request), c.Request.UserAgent())
	if err != nil {
		respondRemoteSSHError(c, err)
		return
	}
	out.WebSocketPath = centerAPIPathFromRequest(c.Request.URL.Path) + "/remote-ssh/web-terminals/" + url.PathEscape(out.TerminalID) + "/ws"
	c.JSON(http.StatusCreated, out)
}

func getCenterRemoteSSHWebTerminalWS(c *gin.Context) {
	terminalID := strings.TrimSpace(c.Param("terminal_id"))
	principal := centerAdminPrincipal(c)
	rec, err := remoteSSHWebTerminals.claim(terminalID, principal)
	if err != nil {
		respondRemoteSSHError(c, err)
		return
	}
	conn, err := acceptRemoteSSHWebTerminal(c.Writer, c.Request)
	if err != nil {
		remoteSSHWebTerminals.releaseClaim(rec.TerminalID)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "closed")
	err = remoteSSHWebTerminals.run(c.Request.Context(), conn, rec, requestRemoteAddr(c.Request), c.Request.UserAgent())
	if err != nil && !errors.Is(err, context.Canceled) {
		_ = conn.Close(websocket.StatusInternalError, "remote ssh web terminal closed")
	}
}

func acceptRemoteSSHWebTerminal(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	return websocket.Accept(remoteSSHDeadlineClearingResponseWriter{ResponseWriter: w}, r, &websocket.AcceptOptions{
		Subprotocols:    []string{remoteSSHWebTerminalSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
}

type remoteSSHDeadlineClearingResponseWriter struct {
	http.ResponseWriter
}

func (w remoteSSHDeadlineClearingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("remote ssh websocket response writer does not support hijack")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	clearRemoteSSHConnDeadlines(conn)
	return conn, rw, nil
}

func (w remoteSSHDeadlineClearingResponseWriter) WriteHeaderNow() {
	if writer, ok := w.ResponseWriter.(interface{ WriteHeaderNow() }); ok {
		writer.WriteHeaderNow()
	}
}

func postCenterRemoteSSHSessionClose(c *gin.Context) {
	if config.AdminReadOnly {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin is read-only"})
		return
	}
	sessionID := strings.TrimSpace(c.Param("session_id"))
	remoteSSHWebTerminals.closeSession(sessionID)
	if err := CloseRemoteSSHSession(c.Request.Context(), sessionID, "operator closed", time.Now().UTC().Unix()); err != nil {
		respondRemoteSSHError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "closed"})
}

func postCenterRemoteSSHSessionTerminate(c *gin.Context) {
	if config.AdminReadOnly {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin is read-only"})
		return
	}
	sessionID := strings.TrimSpace(c.Param("session_id"))
	session, err := TerminateRemoteSSHSession(c.Request.Context(), sessionID, "operator terminated", time.Now().UTC().Unix())
	if err != nil {
		respondRemoteSSHError(c, err)
		return
	}
	remoteSSHWebTerminals.closeSession(sessionID)
	remoteSSHRelayHub.terminate(sessionID, "operator terminated")
	c.JSON(http.StatusOK, gin.H{"status": RemoteSSHSessionStatusTerminated, "session": session})
}

func (m *remoteSSHWebTerminalManager) create(ctx context.Context, deviceID string, req remoteSSHWebTerminalCreateRequest, principal adminauth.Principal, operatorIP, userAgent string) (remoteSSHWebTerminalCreateResponse, error) {
	ownerKey := remoteSSHWebTerminalOwnerKey(principal)
	if ownerKey == "" {
		return remoteSSHWebTerminalCreateResponse{}, ErrRemoteSSHInvalid
	}
	rows := clampRemoteSSHWebTerminalSize(req.Rows, remoteSSHWebTerminalDefaultRows, remoteSSHWebTerminalMinRows, remoteSSHWebTerminalMaxRows)
	cols := clampRemoteSSHWebTerminalSize(req.Cols, remoteSSHWebTerminalDefaultCols, remoteSSHWebTerminalMinCols, remoteSSHWebTerminalMaxCols)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return remoteSSHWebTerminalCreateResponse{}, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return remoteSSHWebTerminalCreateResponse{}, err
	}
	now := time.Now().UTC()
	session, err := CreateRemoteSSHSession(ctx, RemoteSSHSessionCreate{
		DeviceID:          deviceID,
		Reason:            req.Reason,
		OperatorMode:      RemoteSSHOperatorModeWeb,
		OperatorPublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
		TTLSec:            req.TTLSec,
		RequestedByUserID: principal.UserID,
		RequestedBy:       centerAdminActorFromPrincipal(principal),
		OperatorIP:        operatorIP,
		OperatorUserAgent: userAgent,
		CreatedAtUnix:     now.Unix(),
	})
	if err != nil {
		return remoteSSHWebTerminalCreateResponse{}, err
	}
	terminalID, err := remoteSSHRandomToken(18)
	if err != nil {
		return remoteSSHWebTerminalCreateResponse{}, err
	}
	connectExpiresAtUnix := now.Add(remoteSSHWebTerminalConnectTTL).Unix()
	if session.ExpiresAtUnix < connectExpiresAtUnix {
		connectExpiresAtUnix = session.ExpiresAtUnix
	}
	rec := &remoteSSHWebTerminalRecord{
		TerminalID:           terminalID,
		OwnerKey:             ownerKey,
		DeviceID:             deviceID,
		SessionID:            session.SessionID,
		AttachToken:          session.AttachToken,
		PrivateKey:           priv,
		Rows:                 rows,
		Cols:                 cols,
		SessionExpiresAtUnix: session.ExpiresAtUnix,
		ConnectExpiresAtUnix: connectExpiresAtUnix,
	}
	m.mu.Lock()
	m.purgeExpiredLocked(now.Unix())
	m.terminals[terminalID] = rec
	m.bySession[session.SessionID] = rec
	m.mu.Unlock()
	session.AttachToken = ""
	return remoteSSHWebTerminalCreateResponse{
		TerminalID:    terminalID,
		Session:       session,
		ExpiresAtUnix: session.ExpiresAtUnix,
	}, nil
}

func (m *remoteSSHWebTerminalManager) claim(terminalID string, principal adminauth.Principal) (*remoteSSHWebTerminalRecord, error) {
	terminalID = strings.TrimSpace(terminalID)
	ownerKey := remoteSSHWebTerminalOwnerKey(principal)
	if terminalID == "" || ownerKey == "" {
		return nil, ErrRemoteSSHInvalid
	}
	nowUnix := time.Now().UTC().Unix()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeExpiredLocked(nowUnix)
	rec := m.terminals[terminalID]
	if rec == nil || rec.OwnerKey != ownerKey || rec.Claimed || rec.ConnectExpiresAtUnix <= nowUnix || rec.SessionExpiresAtUnix <= nowUnix {
		return nil, ErrRemoteSSHSessionNotFound
	}
	rec.Claimed = true
	return rec, nil
}

func (m *remoteSSHWebTerminalManager) releaseClaim(terminalID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec := m.terminals[terminalID]; rec != nil && rec.Cancel == nil {
		rec.Claimed = false
	}
}

func (m *remoteSSHWebTerminalManager) setCancel(terminalID string, cancel context.CancelFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec := m.terminals[terminalID]; rec != nil {
		rec.Cancel = cancel
	}
}

func (m *remoteSSHWebTerminalManager) finish(terminalID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec := m.terminals[terminalID]; rec != nil {
		delete(m.bySession, rec.SessionID)
		delete(m.terminals, terminalID)
	}
}

func (m *remoteSSHWebTerminalManager) closeSession(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	m.mu.Lock()
	rec := m.bySession[sessionID]
	cancel := context.CancelFunc(nil)
	if rec != nil {
		cancel = rec.Cancel
	}
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (m *remoteSSHWebTerminalManager) purgeExpiredLocked(nowUnix int64) {
	for terminalID, rec := range m.terminals {
		if rec == nil || rec.SessionExpiresAtUnix <= nowUnix || (!rec.Claimed && rec.ConnectExpiresAtUnix <= nowUnix) {
			if rec != nil {
				delete(m.bySession, rec.SessionID)
				if rec.Cancel != nil {
					rec.Cancel()
				}
			}
			delete(m.terminals, terminalID)
		}
	}
}

func (m *remoteSSHWebTerminalManager) run(parent context.Context, ws *websocket.Conn, rec *remoteSSHWebTerminalRecord, operatorIP, userAgent string) error {
	defer m.finish(rec.TerminalID)
	deadlineCtx, cancel := remoteSSHRelayContext(parent, rec.SessionExpiresAtUnix)
	defer cancel()
	m.setCancel(rec.TerminalID, cancel)

	session, err := AttachRemoteSSHOperator(deadlineCtx, RemoteSSHOperatorAttach{
		SessionID:      rec.SessionID,
		AttachToken:    rec.AttachToken,
		OperatorIP:     operatorIP,
		UserAgent:      userAgent,
		AttachedAtUnix: time.Now().UTC().Unix(),
	})
	if err != nil {
		_ = writeRemoteSSHWebTerminalJSON(deadlineCtx, ws, nil, remoteSSHWebTerminalMessage{Type: "error", Message: "remote ssh operator attach failed"})
		return err
	}

	operatorConn, relayConn := net.Pipe()
	defer operatorConn.Close()
	defer relayConn.Close()
	go func() {
		<-deadlineCtx.Done()
		_ = operatorConn.Close()
		_ = relayConn.Close()
	}()
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- remoteSSHRelayHub.attach(deadlineCtx, session.SessionID, "operator", relayConn)
	}()

	client, err := newRemoteSSHWebTerminalSSHClient(deadlineCtx, operatorConn, session.SessionID, rec.PrivateKey)
	if err != nil {
		_ = CloseRemoteSSHSession(context.Background(), session.SessionID, err.Error(), time.Now().UTC().Unix())
		_ = writeRemoteSSHWebTerminalJSON(deadlineCtx, ws, nil, remoteSSHWebTerminalMessage{Type: "error", Message: "remote ssh handshake failed"})
		return err
	}
	defer client.Close()

	sshSession, err := client.NewSession()
	if err != nil {
		_ = CloseRemoteSSHSession(context.Background(), session.SessionID, err.Error(), time.Now().UTC().Unix())
		return err
	}
	defer sshSession.Close()

	stdin, err := sshSession.StdinPipe()
	if err != nil {
		_ = CloseRemoteSSHSession(context.Background(), session.SessionID, err.Error(), time.Now().UTC().Unix())
		return err
	}
	stdout, err := sshSession.StdoutPipe()
	if err != nil {
		_ = CloseRemoteSSHSession(context.Background(), session.SessionID, err.Error(), time.Now().UTC().Unix())
		return err
	}
	if err := sshSession.RequestPty("xterm-256color", rec.Rows, rec.Cols, ssh.TerminalModes{}); err != nil {
		_ = CloseRemoteSSHSession(context.Background(), session.SessionID, err.Error(), time.Now().UTC().Unix())
		return err
	}
	if err := sshSession.Shell(); err != nil {
		_ = CloseRemoteSSHSession(context.Background(), session.SessionID, err.Error(), time.Now().UTC().Unix())
		return err
	}

	var writeMu sync.Mutex
	_ = writeRemoteSSHWebTerminalJSON(deadlineCtx, ws, &writeMu, remoteSSHWebTerminalMessage{Type: "status", Message: "connected"})
	copyDone := make(chan error, 1)
	go remoteSSHWebTerminalCopyOutput(deadlineCtx, ws, &writeMu, stdout, copyDone)
	inputDone := make(chan error, 1)
	go remoteSSHWebTerminalReadInput(deadlineCtx, ws, &writeMu, stdin, sshSession, inputDone)

	var runErr error
	select {
	case runErr = <-inputDone:
	case runErr = <-copyDone:
	case runErr = <-relayDone:
	case <-deadlineCtx.Done():
		runErr = deadlineCtx.Err()
	}
	_ = stdin.Close()
	_ = sshSession.Close()
	_ = client.Close()
	cancel()
	terminatedByOperator := errors.Is(runErr, errRemoteSSHRelayTerminated)
	if terminatedByOperator {
		runErr = nil
	}
	if runErr == nil || errors.Is(runErr, io.EOF) || errors.Is(runErr, net.ErrClosed) || websocket.CloseStatus(runErr) != -1 {
		runErr = nil
	}
	closeReason := "web terminal closed"
	if terminatedByOperator {
		closeReason = errRemoteSSHRelayTerminated.Error()
	} else if runErr != nil && !errors.Is(runErr, context.Canceled) {
		closeReason = truncateRemoteSSHField(runErr.Error(), 256)
	}
	_ = CloseRemoteSSHSession(context.Background(), session.SessionID, closeReason, time.Now().UTC().Unix())
	writeCtx, cancelWrite := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelWrite()
	_ = writeRemoteSSHWebTerminalJSON(writeCtx, ws, &writeMu, remoteSSHWebTerminalMessage{Type: "closed", Message: closeReason})
	return runErr
}

func newRemoteSSHWebTerminalSSHClient(ctx context.Context, conn net.Conn, sessionID string, privateKey ed25519.PrivateKey) (*ssh.Client, error) {
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}
	hostKeyCallback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		session, found, err := RemoteSSHSessionByID(ctx, sessionID)
		if err != nil {
			return err
		}
		if !found || session.GatewayHostKeyFingerprintSHA256 == "" {
			return fmt.Errorf("remote ssh gateway host key is not registered")
		}
		if !strings.EqualFold(remoteSSHPublicKeyFingerprintHex(key), session.GatewayHostKeyFingerprintSHA256) {
			return fmt.Errorf("remote ssh gateway host key mismatch")
		}
		return nil
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, "tukuyomi-remote-ssh-web", &ssh.ClientConfig{
		User:            "tukuyomi",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
	})
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}

func remoteSSHWebTerminalCopyOutput(ctx context.Context, ws *websocket.Conn, writeMu *sync.Mutex, r io.Reader, done chan<- error) {
	buf := make([]byte, remoteSSHWebTerminalOutputChunk)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if writeErr := writeRemoteSSHWebTerminalBinary(ctx, ws, writeMu, buf[:n]); writeErr != nil {
				done <- writeErr
				return
			}
		}
		if err != nil {
			done <- err
			return
		}
	}
}

func remoteSSHWebTerminalReadInput(ctx context.Context, ws *websocket.Conn, writeMu *sync.Mutex, stdin io.Writer, sshSession *ssh.Session, done chan<- error) {
	for {
		msgType, payload, err := ws.Read(ctx)
		if err != nil {
			done <- err
			return
		}
		if msgType != websocket.MessageText {
			continue
		}
		var msg remoteSSHWebTerminalMessage
		if err := json.Unmarshal(payload, &msg); err != nil {
			done <- ErrRemoteSSHInvalid
			return
		}
		switch strings.TrimSpace(msg.Type) {
		case "input":
			if msg.Data != "" {
				if _, err := io.WriteString(stdin, msg.Data); err != nil {
					done <- err
					return
				}
			}
		case "resize":
			rows := clampRemoteSSHWebTerminalSize(msg.Rows, remoteSSHWebTerminalDefaultRows, remoteSSHWebTerminalMinRows, remoteSSHWebTerminalMaxRows)
			cols := clampRemoteSSHWebTerminalSize(msg.Cols, remoteSSHWebTerminalDefaultCols, remoteSSHWebTerminalMinCols, remoteSSHWebTerminalMaxCols)
			if err := sshSession.WindowChange(rows, cols); err != nil {
				done <- err
				return
			}
		case "ping":
			if err := writeRemoteSSHWebTerminalJSON(ctx, ws, writeMu, remoteSSHWebTerminalMessage{Type: "pong"}); err != nil {
				done <- err
				return
			}
			continue
		case "close":
			done <- nil
			return
		default:
			done <- ErrRemoteSSHInvalid
			return
		}
	}
}

func writeRemoteSSHWebTerminalBinary(ctx context.Context, ws *websocket.Conn, writeMu *sync.Mutex, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	if writeMu != nil {
		writeMu.Lock()
		defer writeMu.Unlock()
	}
	return ws.Write(ctx, websocket.MessageBinary, payload)
}

func writeRemoteSSHWebTerminalJSON(ctx context.Context, ws *websocket.Conn, writeMu *sync.Mutex, msg remoteSSHWebTerminalMessage) error {
	if writeMu != nil {
		writeMu.Lock()
		defer writeMu.Unlock()
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return ws.Write(ctx, websocket.MessageText, payload)
}

func centerAPIPathFromRequest(path string) string {
	path = strings.TrimSpace(path)
	if idx := strings.Index(path, "/devices/"); idx > 0 {
		return path[:idx]
	}
	return ""
}

func centerAdminActorFromPrincipal(principal adminauth.Principal) string {
	if username := strings.TrimSpace(principal.Username); username != "" {
		return username
	}
	return "unknown"
}

func remoteSSHWebTerminalOwnerKey(principal adminauth.Principal) string {
	if principal.UserID > 0 {
		return fmt.Sprintf("u:%d", principal.UserID)
	}
	if username := strings.TrimSpace(principal.Username); username != "" {
		return "n:" + strings.ToLower(username)
	}
	return ""
}

func clampRemoteSSHWebTerminalSize(value, fallback, minValue, maxValue int) int {
	if value <= 0 {
		value = fallback
	}
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
