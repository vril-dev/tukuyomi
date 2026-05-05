package center

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"

	"tukuyomi/internal/config"
)

const (
	remoteSSHUpgradeProtocol = "tukuyomi-remote-ssh"
	remoteSSHRelayPairWait   = 24 * time.Hour
)

var errRemoteSSHRelayTerminated = errors.New("operator terminated")

type remoteSSHGatewayStreamRequest struct {
	DeviceID                   string
	KeyID                      string
	PublicKeyFingerprintSHA256 string
	SessionID                  string
	HostKeyFingerprintSHA256   string
	HostPublicKey              string
	Timestamp                  string
	Nonce                      string
	BodyHash                   string
	SignatureB64               string
}

var remoteSSHRelayHub = newRemoteSSHRelayHub()

func getRemoteSSHGatewayStream(c *gin.Context) {
	req, err := verifyRemoteSSHGatewayStreamRequest(c.Request, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid remote ssh gateway stream"})
		return
	}
	session, err := AttachRemoteSSHGateway(c.Request.Context(), RemoteSSHGatewayAttach{
		SessionID:                       req.SessionID,
		DeviceID:                        req.DeviceID,
		GatewayHostKeyFingerprintSHA256: req.HostKeyFingerprintSHA256,
		GatewayHostPublicKey:            req.HostPublicKey,
		AttachedAtUnix:                  time.Now().UTC().Unix(),
	})
	if err != nil {
		respondRemoteSSHStreamError(c, err)
		return
	}
	conn, err := hijackRemoteSSHUpgrade(c)
	if err != nil {
		return
	}
	relayCtx, cancel := remoteSSHRelayContext(c.Request.Context(), session.ExpiresAtUnix)
	defer cancel()
	err = remoteSSHRelayHub.attach(relayCtx, session.SessionID, "gateway", conn)
	if err != nil {
		_ = CloseRemoteSSHSession(context.Background(), session.SessionID, err.Error(), time.Now().UTC().Unix())
		return
	}
	_ = CloseRemoteSSHSession(context.Background(), session.SessionID, "relay closed", time.Now().UTC().Unix())
}

func getRemoteSSHOperatorStream(c *gin.Context) {
	sessionID := strings.TrimSpace(c.GetHeader("X-Tukuyomi-Remote-SSH-Session-ID"))
	attachToken := strings.TrimSpace(c.GetHeader("X-Tukuyomi-Remote-SSH-Attach-Token"))
	session, err := AttachRemoteSSHOperator(c.Request.Context(), RemoteSSHOperatorAttach{
		SessionID:      sessionID,
		AttachToken:    attachToken,
		OperatorIP:     requestRemoteAddr(c.Request),
		UserAgent:      c.Request.UserAgent(),
		AttachedAtUnix: time.Now().UTC().Unix(),
	})
	if err != nil {
		respondRemoteSSHStreamError(c, err)
		return
	}
	conn, err := hijackRemoteSSHUpgrade(c)
	if err != nil {
		return
	}
	relayCtx, cancel := remoteSSHRelayContext(c.Request.Context(), session.ExpiresAtUnix)
	defer cancel()
	err = remoteSSHRelayHub.attach(relayCtx, session.SessionID, "operator", conn)
	if err != nil {
		_ = CloseRemoteSSHSession(context.Background(), session.SessionID, err.Error(), time.Now().UTC().Unix())
		return
	}
	_ = CloseRemoteSSHSession(context.Background(), session.SessionID, "relay closed", time.Now().UTC().Unix())
}

func remoteSSHRelayContext(parent context.Context, expiresAtUnix int64) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if expiresAtUnix <= 0 {
		return context.WithCancel(parent)
	}
	deadline := time.Unix(expiresAtUnix, 0).UTC()
	if !time.Now().UTC().Before(deadline) {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, func() {}
	}
	return context.WithDeadline(parent, deadline)
}

func respondRemoteSSHStreamError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrRemoteSSHSessionNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "remote ssh session not found"})
	case errors.Is(err, ErrRemoteSSHInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid remote ssh stream"})
	default:
		c.JSON(http.StatusConflict, gin.H{"error": "remote ssh stream unavailable"})
	}
}

func hijackRemoteSSHUpgrade(c *gin.Context) (net.Conn, error) {
	if !remoteSSHUpgradeRequested(c.Request) {
		c.JSON(http.StatusUpgradeRequired, gin.H{"error": "remote ssh stream requires upgrade"})
		return nil, fmt.Errorf("remote ssh stream requires upgrade")
	}
	hijacker, ok := c.Writer.(http.Hijacker)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "remote ssh upgrade unavailable"})
		return nil, fmt.Errorf("remote ssh upgrade unavailable")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}
	clearRemoteSSHConnDeadlines(conn)
	if rw != nil {
		if rw.Reader != nil && rw.Reader.Buffered() > 0 {
			_ = conn.Close()
			return nil, fmt.Errorf("remote ssh upgrade had buffered request data")
		}
		if rw.Writer != nil {
			_, _ = rw.Writer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + remoteSSHUpgradeProtocol + "\r\n\r\n")
			if err := rw.Writer.Flush(); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		}
	}
	_, err = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+remoteSSHUpgradeProtocol+"\r\n\r\n")
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func clearRemoteSSHConnDeadlines(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})
}

func remoteSSHUpgradeRequested(r *http.Request) bool {
	if r == nil || !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), remoteSSHUpgradeProtocol) {
		return false
	}
	for _, part := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(part), "upgrade") {
			return true
		}
	}
	return false
}

func verifyRemoteSSHGatewayStreamRequest(r *http.Request, now time.Time) (remoteSSHGatewayStreamRequest, error) {
	if r == nil {
		return remoteSSHGatewayStreamRequest{}, ErrInvalidEnrollment
	}
	req := remoteSSHGatewayStreamRequest{
		DeviceID:                   strings.TrimSpace(r.Header.Get("X-Tukuyomi-Device-ID")),
		KeyID:                      strings.TrimSpace(r.Header.Get("X-Tukuyomi-Key-ID")),
		PublicKeyFingerprintSHA256: strings.ToLower(strings.TrimSpace(r.Header.Get("X-Tukuyomi-Public-Key-Fingerprint-SHA256"))),
		SessionID:                  strings.TrimSpace(r.Header.Get("X-Tukuyomi-Remote-SSH-Session-ID")),
		HostKeyFingerprintSHA256:   strings.ToLower(strings.TrimSpace(r.Header.Get("X-Tukuyomi-Remote-SSH-Host-Key-Fingerprint-SHA256"))),
		HostPublicKey:              strings.TrimSpace(r.Header.Get("X-Tukuyomi-Remote-SSH-Host-Public-Key")),
		Timestamp:                  strings.TrimSpace(r.Header.Get("X-Tukuyomi-Timestamp")),
		Nonce:                      strings.TrimSpace(r.Header.Get("X-Tukuyomi-Nonce")),
		BodyHash:                   strings.ToLower(strings.TrimSpace(r.Header.Get("X-Tukuyomi-Body-Hash"))),
		SignatureB64:               strings.TrimSpace(r.Header.Get("X-Tukuyomi-Signature")),
	}
	if !deviceIDPattern.MatchString(req.DeviceID) || req.KeyID == "" || !hex64Pattern.MatchString(req.PublicKeyFingerprintSHA256) ||
		req.SessionID == "" || !hex64Pattern.MatchString(req.HostKeyFingerprintSHA256) || !hex64Pattern.MatchString(req.BodyHash) ||
		req.HostPublicKey == "" || len(req.HostPublicKey) > MaxRemoteSSHPublicKeyBytes ||
		req.SignatureB64 == "" || len(req.SignatureB64) > 4096 || len(req.Nonce) < 8 || len(req.Nonce) > 128 {
		return remoteSSHGatewayStreamRequest{}, ErrInvalidEnrollment
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.HostPublicKey))
	if err != nil || remoteSSHPublicKeyFingerprintHex(hostKey) != req.HostKeyFingerprintSHA256 {
		return remoteSSHGatewayStreamRequest{}, ErrInvalidEnrollment
	}
	if req.BodyHash != remoteSSHGatewayStreamBodyHash(req.SessionID, req.HostKeyFingerprintSHA256, req.HostPublicKey) {
		return remoteSSHGatewayStreamRequest{}, ErrInvalidEnrollment
	}
	record, err := LookupDeviceStatus(r.Context(), req.DeviceID, req.KeyID, req.PublicKeyFingerprintSHA256)
	if err != nil {
		return remoteSSHGatewayStreamRequest{}, err
	}
	if !record.FromApprovedDevice || record.Status != DeviceStatusApproved {
		return remoteSSHGatewayStreamRequest{}, ErrInvalidEnrollment
	}
	_, publicKey, err := parseStoredEnrollmentPublicKey(record.PublicKeyPEM)
	if err != nil {
		return remoteSSHGatewayStreamRequest{}, err
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return remoteSSHGatewayStreamRequest{}, ErrInvalidEnrollment
	}
	if !ed25519.Verify(publicKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		return remoteSSHGatewayStreamRequest{}, ErrInvalidEnrollment
	}
	ts, err := time.Parse(time.RFC3339Nano, req.Timestamp)
	if err != nil {
		return remoteSSHGatewayStreamRequest{}, ErrInvalidEnrollment
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ts.After(now.Add(enrollmentFreshness)) || ts.Before(now.Add(-enrollmentFreshness)) {
		return remoteSSHGatewayStreamRequest{}, ErrInvalidEnrollment
	}
	return req, nil
}

func remoteSSHGatewayStreamBodyHash(sessionID string, hostKeyFingerprint string, hostPublicKey string) string {
	sum := sha256.Sum256([]byte("remote-ssh-gateway-stream\n" + strings.TrimSpace(sessionID) + "\n" + strings.ToLower(strings.TrimSpace(hostKeyFingerprint)) + "\n" + strings.TrimSpace(hostPublicKey)))
	return hex.EncodeToString(sum[:])
}

type remoteSSHRelayHubState struct {
	mu       sync.Mutex
	sessions map[string]*remoteSSHRelayPair
}

type remoteSSHRelayPair struct {
	gateway              net.Conn
	operator             net.Conn
	ready                chan struct{}
	done                 chan struct{}
	doneOnce             sync.Once
	lastActivityUnixNano atomic.Int64
	errMu                sync.Mutex
	err                  error
	started              bool
}

func newRemoteSSHRelayHub() *remoteSSHRelayHubState {
	return &remoteSSHRelayHubState{sessions: map[string]*remoteSSHRelayPair{}}
}

func (h *remoteSSHRelayHubState) attach(ctx context.Context, sessionID string, role string, conn net.Conn) error {
	if conn == nil {
		return fmt.Errorf("remote ssh relay missing connection")
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		_ = conn.Close()
		return ErrRemoteSSHInvalid
	}
	pair, err := h.add(sessionID, role, conn)
	if err != nil {
		_ = conn.Close()
		return err
	}
	timer := time.NewTimer(remoteSSHRelayPairWait)
	defer timer.Stop()
	select {
	case <-pair.ready:
	case <-pair.done:
		return pair.closeErr()
	case <-ctx.Done():
		h.removeSide(sessionID, role, conn)
		_ = conn.Close()
		return ctx.Err()
	case <-timer.C:
		h.removeSide(sessionID, role, conn)
		_ = conn.Close()
		return fmt.Errorf("remote ssh relay pair timeout")
	}
	select {
	case <-pair.done:
		return pair.closeErr()
	case <-ctx.Done():
		_ = conn.Close()
		return ctx.Err()
	}
}

func (h *remoteSSHRelayHubState) add(sessionID string, role string, conn net.Conn) (*remoteSSHRelayPair, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	pair := h.sessions[sessionID]
	if pair == nil {
		pair = &remoteSSHRelayPair{
			ready: make(chan struct{}),
			done:  make(chan struct{}),
		}
		pair.markActivity()
		h.sessions[sessionID] = pair
	}
	switch role {
	case "gateway":
		if pair.gateway != nil {
			return nil, fmt.Errorf("remote ssh gateway already attached")
		}
		pair.gateway = conn
	case "operator":
		if pair.operator != nil {
			return nil, fmt.Errorf("remote ssh operator already attached")
		}
		pair.operator = conn
	default:
		return nil, ErrRemoteSSHInvalid
	}
	if pair.gateway != nil && pair.operator != nil && !pair.started {
		pair.started = true
		close(pair.ready)
		go h.run(sessionID, pair)
	}
	return pair, nil
}

func (h *remoteSSHRelayHubState) removeSide(sessionID string, role string, conn net.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	pair := h.sessions[sessionID]
	if pair == nil || pair.started {
		return
	}
	if role == "gateway" && pair.gateway == conn {
		pair.gateway = nil
	}
	if role == "operator" && pair.operator == conn {
		pair.operator = nil
	}
	if pair.gateway == nil && pair.operator == nil {
		delete(h.sessions, sessionID)
	}
}

func (h *remoteSSHRelayHubState) run(sessionID string, pair *remoteSSHRelayPair) {
	defer func() {
		_ = pair.gateway.Close()
		_ = pair.operator.Close()
		h.mu.Lock()
		if h.sessions[sessionID] == pair {
			delete(h.sessions, sessionID)
		}
		h.mu.Unlock()
		pair.closeDone()
	}()
	var once sync.Once
	closeBoth := func() {
		_ = pair.gateway.Close()
		_ = pair.operator.Close()
	}
	idleTimeout := config.RemoteSSHIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = time.Duration(config.DefaultRemoteSSHIdleTimeoutSec) * time.Second
	}
	tick := idleTimeout / 2
	if tick < time.Second {
		tick = time.Second
	}
	activityGateway := remoteSSHActivityConn{Conn: pair.gateway, mark: pair.markActivity}
	activityOperator := remoteSSHActivityConn{Conn: pair.operator, mark: pair.markActivity}
	go func() {
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for {
			select {
			case <-pair.done:
				return
			case <-ticker.C:
				last := time.Unix(0, pair.lastActivityUnixNano.Load())
				if time.Since(last) >= idleTimeout {
					pair.setCloseErr(fmt.Errorf("idle timeout"))
					once.Do(closeBoth)
					return
				}
			}
		}
	}()
	go func() {
		_, _ = io.Copy(activityGateway, activityOperator)
		once.Do(closeBoth)
	}()
	_, _ = io.Copy(activityOperator, activityGateway)
	once.Do(closeBoth)
}

func (h *remoteSSHRelayHubState) terminate(sessionID string, reason string) bool {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return false
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "operator terminated"
	}
	h.mu.Lock()
	pair := h.sessions[sessionID]
	if pair != nil {
		delete(h.sessions, sessionID)
	}
	h.mu.Unlock()
	if pair == nil {
		return false
	}
	if reason == errRemoteSSHRelayTerminated.Error() {
		pair.setCloseErr(errRemoteSSHRelayTerminated)
	} else {
		pair.setCloseErr(fmt.Errorf("%s", reason))
	}
	if pair.gateway != nil {
		_ = pair.gateway.Close()
	}
	if pair.operator != nil {
		_ = pair.operator.Close()
	}
	pair.closeDone()
	return true
}

type remoteSSHActivityConn struct {
	net.Conn
	mark func()
}

func (c remoteSSHActivityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.mark != nil {
		c.mark()
	}
	return n, err
}

func (c remoteSSHActivityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 && c.mark != nil {
		c.mark()
	}
	return n, err
}

func (p *remoteSSHRelayPair) markActivity() {
	p.lastActivityUnixNano.Store(time.Now().UTC().UnixNano())
}

func (p *remoteSSHRelayPair) setCloseErr(err error) {
	if err == nil {
		return
	}
	p.errMu.Lock()
	defer p.errMu.Unlock()
	if p.err == nil {
		p.err = err
	}
}

func (p *remoteSSHRelayPair) closeErr() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.err
}

func (p *remoteSSHRelayPair) closeDone() {
	p.doneOnce.Do(func() {
		close(p.done)
	})
}
