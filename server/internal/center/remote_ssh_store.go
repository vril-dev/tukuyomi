package center

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"tukuyomi/internal/config"
)

type execQueryer interface {
	queryer
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

const (
	RemoteSSHSessionStatusPending          = "pending"
	RemoteSSHSessionStatusGatewayAttached  = "gateway_attached"
	RemoteSSHSessionStatusOperatorAttached = "operator_attached"
	RemoteSSHSessionStatusActive           = "active"
	RemoteSSHSessionStatusClosed           = "closed"
	RemoteSSHSessionStatusExpired          = "expired"
	RemoteSSHSessionStatusCanceled         = "canceled"

	MaxRemoteSSHReasonBytes      = 1024
	MaxRemoteSSHPublicKeyBytes   = 8192
	MaxRemoteSSHUsernameBytes    = 191
	MaxRemoteSSHAttachTokenBytes = 32

	remoteSSHCenterSigningKeyBlobKey = "center_remote_ssh_signing_key"
	remoteSSHCenterSigningKeyPrefix  = "ed25519:"
)

var (
	ErrRemoteSSHDisabled        = errors.New("remote ssh is disabled")
	ErrRemoteSSHInvalid         = errors.New("invalid remote ssh request")
	ErrRemoteSSHSessionNotFound = errors.New("remote ssh session not found")
	ErrRemoteSSHPolicyDisabled  = errors.New("remote ssh policy is disabled")
	ErrRemoteSSHSessionLimit    = errors.New("remote ssh session limit exceeded")

	remoteSSHCenterSigningKeyMu sync.Mutex
)

type RemoteSSHSessionCreate struct {
	DeviceID          string
	Reason            string
	OperatorPublicKey string
	TTLSec            int64
	RequestedByUserID int64
	RequestedBy       string
	OperatorIP        string
	OperatorUserAgent string
	CreatedAtUnix     int64
}

type RemoteSSHGatewayAttach struct {
	SessionID                       string
	DeviceID                        string
	GatewayHostKeyFingerprintSHA256 string
	GatewayHostPublicKey            string
	AttachedAtUnix                  int64
}

type RemoteSSHOperatorAttach struct {
	SessionID      string
	AttachToken    string
	OperatorIP     string
	UserAgent      string
	AttachedAtUnix int64
}

type RemoteSSHSessionRecord struct {
	SessionID                          string `json:"session_id"`
	DeviceID                           string `json:"device_id"`
	Status                             string `json:"status"`
	Reason                             string `json:"reason"`
	RequestedByUserID                  int64  `json:"requested_by_user_id,omitempty"`
	RequestedByUsername                string `json:"requested_by_username"`
	OperatorPublicKey                  string `json:"operator_public_key,omitempty"`
	OperatorPublicKeyFingerprintSHA256 string `json:"operator_public_key_fingerprint_sha256"`
	AttachToken                        string `json:"attach_token,omitempty"`
	GatewayHostKeyFingerprintSHA256    string `json:"gateway_host_key_fingerprint_sha256,omitempty"`
	GatewayHostPublicKey               string `json:"gateway_host_public_key,omitempty"`
	TTLSec                             int64  `json:"ttl_sec"`
	ExpiresAtUnix                      int64  `json:"expires_at_unix"`
	CreatedAtUnix                      int64  `json:"created_at_unix"`
	GatewayConnectedAtUnix             int64  `json:"gateway_connected_at_unix,omitempty"`
	OperatorConnectedAtUnix            int64  `json:"operator_connected_at_unix,omitempty"`
	StartedAtUnix                      int64  `json:"started_at_unix,omitempty"`
	EndedAtUnix                        int64  `json:"ended_at_unix,omitempty"`
	CloseReason                        string `json:"close_reason,omitempty"`
	OperatorIP                         string `json:"operator_ip,omitempty"`
	OperatorUserAgent                  string `json:"operator_user_agent,omitempty"`
}

type RemoteSSHDeviceSession struct {
	DeviceID                           string `json:"device_id"`
	SessionID                          string `json:"session_id"`
	OperatorPublicKey                  string `json:"operator_public_key"`
	OperatorPublicKeyFingerprintSHA256 string `json:"operator_public_key_fingerprint_sha256"`
	ExpiresAtUnix                      int64  `json:"expires_at_unix"`
	CreatedAtUnix                      int64  `json:"created_at_unix"`
	Nonce                              string `json:"nonce"`
	CenterSigningPublicKey             string `json:"center_signing_public_key"`
	Signature                          string `json:"signature"`
}

type RemoteSSHPolicyUpdate struct {
	DeviceID          string
	Enabled           bool
	MaxTTLSec         int64
	AllowedRunAsUser  string
	RequireReason     bool
	UpdatedByUserID   int64
	UpdatedByUsername string
	UpdatedAtUnix     int64
}

type RemoteSSHPolicyRecord struct {
	DeviceID          string `json:"device_id"`
	Enabled           bool   `json:"enabled"`
	MaxTTLSec         int64  `json:"max_ttl_sec"`
	AllowedRunAsUser  string `json:"allowed_run_as_user"`
	RequireReason     bool   `json:"require_reason"`
	UpdatedByUserID   int64  `json:"updated_by_user_id,omitempty"`
	UpdatedByUsername string `json:"updated_by_username"`
	UpdatedAtUnix     int64  `json:"updated_at_unix"`
}

type RemoteSSHDeviceView struct {
	CenterEnabled bool                     `json:"center_enabled"`
	Device        DeviceRecord             `json:"device"`
	Policy        RemoteSSHPolicyRecord    `json:"policy"`
	Sessions      []RemoteSSHSessionRecord `json:"sessions"`
}

func CreateRemoteSSHSession(ctx context.Context, in RemoteSSHSessionCreate) (RemoteSSHSessionRecord, error) {
	if !config.RemoteSSHCenterEnabled {
		return RemoteSSHSessionRecord{}, ErrRemoteSSHDisabled
	}
	normalized, fp, err := normalizeRemoteSSHSessionCreate(in)
	if err != nil {
		return RemoteSSHSessionRecord{}, err
	}
	if normalized.CreatedAtUnix <= 0 {
		normalized.CreatedAtUnix = time.Now().UTC().Unix()
	}
	var out RemoteSSHSessionRecord
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := expireRemoteSSHSessionsTx(ctx, tx, driver, normalized.CreatedAtUnix); err != nil {
			return err
		}
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, normalized.DeviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		policy, found, err := loadRemoteSSHPolicyTx(ctx, tx, driver, normalized.DeviceID)
		if err != nil {
			return err
		}
		if !found || !policy.Enabled {
			return ErrRemoteSSHPolicyDisabled
		}
		ttlSec := normalized.TTLSec
		if ttlSec <= 0 {
			ttlSec = int64(config.RemoteSSHMaxTTL / time.Second)
		}
		if policy.MaxTTLSec > 0 && ttlSec > policy.MaxTTLSec {
			ttlSec = policy.MaxTTLSec
		}
		maxTTLSec := int64(config.RemoteSSHMaxTTL / time.Second)
		if maxTTLSec <= 0 {
			maxTTLSec = config.DefaultRemoteSSHMaxTTLSec
		}
		if ttlSec > maxTTLSec {
			ttlSec = maxTTLSec
		}
		if ttlSec < config.MinRemoteSSHMaxTTLSec || ttlSec > config.MaxRemoteSSHMaxTTLSec {
			return ErrRemoteSSHInvalid
		}
		if policy.RequireReason && normalized.Reason == "" {
			return ErrRemoteSSHInvalid
		}
		total, perDevice, err := countActiveRemoteSSHSessionsTx(ctx, tx, driver, normalized.DeviceID, normalized.CreatedAtUnix)
		if err != nil {
			return err
		}
		maxSessionsTotal := config.RemoteSSHMaxSessionsTotal
		if maxSessionsTotal <= 0 {
			maxSessionsTotal = config.DefaultRemoteSSHMaxSessionsTotal
		}
		maxSessionsPerDevice := config.RemoteSSHMaxSessionsPerDevice
		if maxSessionsPerDevice <= 0 {
			maxSessionsPerDevice = config.DefaultRemoteSSHMaxSessionsPerDevice
		}
		if total >= int64(maxSessionsTotal) {
			return ErrRemoteSSHSessionLimit
		}
		if perDevice >= int64(maxSessionsPerDevice) {
			return ErrRemoteSSHSessionLimit
		}
		sessionID, err := remoteSSHRandomToken(18)
		if err != nil {
			return err
		}
		attachToken, err := remoteSSHRandomToken(MaxRemoteSSHAttachTokenBytes)
		if err != nil {
			return err
		}
		rec := RemoteSSHSessionRecord{
			SessionID:                          sessionID,
			DeviceID:                           normalized.DeviceID,
			Status:                             RemoteSSHSessionStatusPending,
			Reason:                             normalized.Reason,
			RequestedByUserID:                  normalized.RequestedByUserID,
			RequestedByUsername:                normalized.RequestedBy,
			OperatorPublicKey:                  normalized.OperatorPublicKey,
			OperatorPublicKeyFingerprintSHA256: fp,
			AttachToken:                        attachToken,
			TTLSec:                             ttlSec,
			ExpiresAtUnix:                      normalized.CreatedAtUnix + ttlSec,
			CreatedAtUnix:                      normalized.CreatedAtUnix,
			OperatorIP:                         normalized.OperatorIP,
			OperatorUserAgent:                  normalized.OperatorUserAgent,
		}
		if err := insertRemoteSSHSessionTx(ctx, tx, driver, rec); err != nil {
			return err
		}
		if err := insertRemoteSSHEventTx(ctx, tx, driver, rec.SessionID, rec.DeviceID, "created", "", normalized.CreatedAtUnix); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		out = rec
		return nil
	})
	return out, err
}

func RemoteSSHViewForDevice(ctx context.Context, deviceID string, limit int) (RemoteSSHDeviceView, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return RemoteSSHDeviceView{}, ErrDeviceStatusNotFound
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var out RemoteSSHDeviceView
	out.CenterEnabled = config.RemoteSSHCenterEnabled
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		out.Device = device
		policy, found, err := loadRemoteSSHPolicyTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		if found {
			out.Policy = policy
		} else {
			out.Policy = defaultRemoteSSHPolicy(deviceID)
		}
		sessions, err := listRemoteSSHSessionsTx(ctx, db, driver, deviceID, limit)
		if err != nil {
			return err
		}
		out.Sessions = sessions
		return nil
	})
	return out, err
}

func UpsertRemoteSSHPolicy(ctx context.Context, in RemoteSSHPolicyUpdate) (RemoteSSHPolicyRecord, error) {
	normalized, err := normalizeRemoteSSHPolicyUpdate(in)
	if err != nil {
		return RemoteSSHPolicyRecord{}, err
	}
	if normalized.UpdatedAtUnix <= 0 {
		normalized.UpdatedAtUnix = time.Now().UTC().Unix()
	}
	var out RemoteSSHPolicyRecord
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, normalized.DeviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		if err := upsertRemoteSSHPolicyTx(ctx, tx, driver, normalized); err != nil {
			return err
		}
		policy, found, err := loadRemoteSSHPolicyTx(ctx, tx, driver, normalized.DeviceID)
		if err != nil {
			return err
		}
		if !found {
			return ErrRemoteSSHInvalid
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		out = policy
		return nil
	})
	return out, err
}

func PendingRemoteSSHSessionForDevice(ctx context.Context, deviceID string, nowUnix int64) (*RemoteSSHDeviceSession, error) {
	if !config.RemoteSSHCenterEnabled {
		return nil, nil
	}
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return nil, ErrDeviceStatusNotFound
	}
	if nowUnix <= 0 {
		nowUnix = time.Now().UTC().Unix()
	}
	var out *RemoteSSHDeviceSession
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		if err := expireRemoteSSHSessionsTx(ctx, db, driver, nowUnix); err != nil {
			return err
		}
		policy, found, err := loadRemoteSSHPolicyTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		if !found || !policy.Enabled {
			return nil
		}
		row := db.QueryRowContext(ctx, `
SELECT device_id, session_id, operator_public_key, operator_public_key_fingerprint_sha256, expires_at_unix, created_at_unix
  FROM center_remote_ssh_sessions
 WHERE device_id = `+placeholder(driver, 1)+`
   AND status IN (`+placeholder(driver, 2)+`, `+placeholder(driver, 3)+`)
   AND gateway_connected_at_unix = 0
   AND expires_at_unix > `+placeholder(driver, 4)+`
 ORDER BY created_at_unix ASC
 LIMIT 1`, deviceID, RemoteSSHSessionStatusPending, RemoteSSHSessionStatusOperatorAttached, nowUnix)
		var rec RemoteSSHDeviceSession
		if err := row.Scan(&rec.DeviceID, &rec.SessionID, &rec.OperatorPublicKey, &rec.OperatorPublicKeyFingerprintSHA256, &rec.ExpiresAtUnix, &rec.CreatedAtUnix); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		out = &rec
		return nil
	})
	if err != nil || out == nil {
		return out, err
	}
	if err := signRemoteSSHDeviceSession(ctx, out); err != nil {
		return nil, err
	}
	return out, err
}

type remoteSSHCenterSigningKeyBlob struct {
	PrivateKeyPEM string `json:"private_key_pem"`
	PublicKey     string `json:"public_key"`
}

func RemoteSSHCenterSigningPublicKey(ctx context.Context) (string, error) {
	_, publicKey, err := ensureRemoteSSHCenterSigningKey(ctx)
	return publicKey, err
}

func RotateRemoteSSHCenterSigningKey(ctx context.Context) (string, error) {
	remoteSSHCenterSigningKeyMu.Lock()
	defer remoteSSHCenterSigningKeyMu.Unlock()

	var publicKey string
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()

		found, err := remoteSSHCenterSigningKeyBlobExistsTx(ctx, tx, driver)
		if err != nil {
			return err
		}
		_, raw, encoded, err := newRemoteSSHCenterSigningKeyBlob()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		etagSum := sha256.Sum256(encoded)
		if found {
			_, err = tx.ExecContext(ctx, `
UPDATE config_blobs
   SET raw_text = `+placeholder(driver, 1)+`,
       etag = `+placeholder(driver, 2)+`,
       updated_at_unix = `+placeholder(driver, 3)+`,
       updated_at = `+placeholder(driver, 4)+`
 WHERE config_key = `+placeholder(driver, 5),
				string(encoded),
				hex.EncodeToString(etagSum[:]),
				now.Unix(),
				now.Format(time.RFC3339Nano),
				remoteSSHCenterSigningKeyBlobKey,
			)
			if err != nil {
				return err
			}
		} else {
			_, err = tx.ExecContext(ctx, `
INSERT INTO config_blobs (config_key, raw_text, etag, updated_at_unix, updated_at)
VALUES (`+placeholders(driver, 5, 1)+`)`,
				remoteSSHCenterSigningKeyBlobKey,
				string(encoded),
				hex.EncodeToString(etagSum[:]),
				now.Unix(),
				now.Format(time.RFC3339Nano),
			)
			if err != nil {
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		publicKey = raw.PublicKey
		return nil
	})
	return publicKey, err
}

func signRemoteSSHDeviceSession(ctx context.Context, session *RemoteSSHDeviceSession) error {
	if session == nil {
		return ErrRemoteSSHInvalid
	}
	privateKey, publicKey, err := ensureRemoteSSHCenterSigningKey(ctx)
	if err != nil {
		return err
	}
	nonce, err := remoteSSHRandomToken(18)
	if err != nil {
		return err
	}
	session.Nonce = nonce
	session.CenterSigningPublicKey = publicKey
	signature := ed25519.Sign(privateKey, []byte(remoteSSHDeviceSessionSignedMessage(*session)))
	session.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func ensureRemoteSSHCenterSigningKey(ctx context.Context) (ed25519.PrivateKey, string, error) {
	remoteSSHCenterSigningKeyMu.Lock()
	defer remoteSSHCenterSigningKeyMu.Unlock()

	var privateKey ed25519.PrivateKey
	var publicKey string
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		loadedPrivate, loadedPublic, found, err := loadRemoteSSHCenterSigningKeyTx(ctx, tx, driver)
		if err != nil {
			return err
		}
		if found {
			privateKey = loadedPrivate
			publicKey = loadedPublic
			return tx.Commit()
		}
		priv, raw, encoded, err := newRemoteSSHCenterSigningKeyBlob()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		etagSum := sha256.Sum256(encoded)
		_, err = tx.ExecContext(ctx, `
INSERT INTO config_blobs (config_key, raw_text, etag, updated_at_unix, updated_at)
VALUES (`+placeholders(driver, 5, 1)+`)`,
			remoteSSHCenterSigningKeyBlobKey,
			string(encoded),
			hex.EncodeToString(etagSum[:]),
			now.Unix(),
			now.Format(time.RFC3339Nano),
		)
		if err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		privateKey = priv
		publicKey = raw.PublicKey
		return nil
	})
	return privateKey, publicKey, err
}

func newRemoteSSHCenterSigningKeyBlob() (ed25519.PrivateKey, remoteSSHCenterSigningKeyBlob, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, remoteSSHCenterSigningKeyBlob{}, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, remoteSSHCenterSigningKeyBlob{}, nil, err
	}
	raw := remoteSSHCenterSigningKeyBlob{
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
		PublicKey:     remoteSSHCenterSigningPublicKeyString(pub),
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, remoteSSHCenterSigningKeyBlob{}, nil, err
	}
	return priv, raw, encoded, nil
}

func remoteSSHCenterSigningKeyBlobExistsTx(ctx context.Context, q queryer, driver string) (bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT raw_text
  FROM config_blobs
 WHERE config_key = `+placeholder(driver, 1), remoteSSHCenterSigningKeyBlobKey)
	var ignored string
	if err := row.Scan(&ignored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func loadRemoteSSHCenterSigningKeyTx(ctx context.Context, q queryer, driver string) (ed25519.PrivateKey, string, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT raw_text
  FROM config_blobs
 WHERE config_key = `+placeholder(driver, 1), remoteSSHCenterSigningKeyBlobKey)
	var rawText string
	if err := row.Scan(&rawText); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", false, nil
		}
		return nil, "", false, err
	}
	var blob remoteSSHCenterSigningKeyBlob
	decoder := json.NewDecoder(strings.NewReader(rawText))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&blob); err != nil {
		return nil, "", false, err
	}
	key, err := parseRemoteSSHCenterSigningPrivateKey(blob.PrivateKeyPEM)
	if err != nil {
		return nil, "", false, err
	}
	publicKey := remoteSSHCenterSigningPublicKeyString(key.Public().(ed25519.PublicKey))
	if blob.PublicKey != "" && blob.PublicKey != publicKey {
		return nil, "", false, ErrRemoteSSHInvalid
	}
	return key, publicKey, true, nil
}

func parseRemoteSSHCenterSigningPrivateKey(raw string) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode([]byte(strings.TrimSpace(raw)))
	if block == nil || block.Type != "PRIVATE KEY" || strings.TrimSpace(string(rest)) != "" {
		return nil, ErrRemoteSSHInvalid
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok || len(edKey) != ed25519.PrivateKeySize {
		return nil, ErrRemoteSSHInvalid
	}
	return edKey, nil
}

func remoteSSHCenterSigningPublicKeyString(key ed25519.PublicKey) string {
	return remoteSSHCenterSigningKeyPrefix + base64.StdEncoding.EncodeToString(key)
}

func remoteSSHDeviceSessionSignedMessage(session RemoteSSHDeviceSession) string {
	return strings.Join([]string{
		"tukuyomi-remote-ssh-pending-v1",
		strings.TrimSpace(session.DeviceID),
		strings.TrimSpace(session.SessionID),
		strings.TrimSpace(session.OperatorPublicKey),
		strings.ToLower(strings.TrimSpace(session.OperatorPublicKeyFingerprintSHA256)),
		strconv.FormatInt(session.ExpiresAtUnix, 10),
		strconv.FormatInt(session.CreatedAtUnix, 10),
		strings.TrimSpace(session.Nonce),
	}, "\n")
}

func AttachRemoteSSHGateway(ctx context.Context, in RemoteSSHGatewayAttach) (RemoteSSHSessionRecord, error) {
	in.SessionID = strings.TrimSpace(in.SessionID)
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.GatewayHostKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(in.GatewayHostKeyFingerprintSHA256))
	in.GatewayHostPublicKey = strings.TrimSpace(in.GatewayHostPublicKey)
	if in.SessionID == "" || !deviceIDPattern.MatchString(in.DeviceID) || !hex64Pattern.MatchString(in.GatewayHostKeyFingerprintSHA256) {
		return RemoteSSHSessionRecord{}, ErrRemoteSSHInvalid
	}
	if in.GatewayHostPublicKey == "" || len(in.GatewayHostPublicKey) > MaxRemoteSSHPublicKeyBytes {
		return RemoteSSHSessionRecord{}, ErrRemoteSSHInvalid
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(in.GatewayHostPublicKey))
	if err != nil || remoteSSHPublicKeyFingerprintHex(hostKey) != in.GatewayHostKeyFingerprintSHA256 {
		return RemoteSSHSessionRecord{}, ErrRemoteSSHInvalid
	}
	if in.AttachedAtUnix <= 0 {
		in.AttachedAtUnix = time.Now().UTC().Unix()
	}
	var out RemoteSSHSessionRecord
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := expireRemoteSSHSessionsTx(ctx, tx, driver, in.AttachedAtUnix); err != nil {
			return err
		}
		rec, _, found, err := loadRemoteSSHSessionByIDTx(ctx, tx, driver, in.SessionID)
		if err != nil {
			return err
		}
		if !found || rec.DeviceID != in.DeviceID {
			return ErrRemoteSSHSessionNotFound
		}
		if !remoteSSHSessionAttachable(rec.Status) || rec.ExpiresAtUnix <= in.AttachedAtUnix {
			return ErrRemoteSSHSessionNotFound
		}
		if rec.GatewayConnectedAtUnix > 0 {
			return ErrRemoteSSHSessionNotFound
		}
		rec.GatewayHostKeyFingerprintSHA256 = in.GatewayHostKeyFingerprintSHA256
		rec.GatewayHostPublicKey = in.GatewayHostPublicKey
		rec.GatewayConnectedAtUnix = in.AttachedAtUnix
		if rec.OperatorConnectedAtUnix > 0 {
			rec.Status = RemoteSSHSessionStatusActive
			rec.StartedAtUnix = in.AttachedAtUnix
		} else {
			rec.Status = RemoteSSHSessionStatusGatewayAttached
		}
		if err := updateRemoteSSHSessionAttachStateTx(ctx, tx, driver, rec); err != nil {
			return err
		}
		if err := insertRemoteSSHEventTx(ctx, tx, driver, rec.SessionID, rec.DeviceID, "gateway_attached", "", in.AttachedAtUnix); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		out = rec
		return nil
	})
	return out, err
}

func AttachRemoteSSHOperator(ctx context.Context, in RemoteSSHOperatorAttach) (RemoteSSHSessionRecord, error) {
	in.SessionID = strings.TrimSpace(in.SessionID)
	in.AttachToken = strings.TrimSpace(in.AttachToken)
	in.OperatorIP = truncateRemoteSSHField(strings.TrimSpace(in.OperatorIP), 191)
	in.UserAgent = truncateRemoteSSHField(strings.TrimSpace(in.UserAgent), 512)
	if in.SessionID == "" || in.AttachToken == "" {
		return RemoteSSHSessionRecord{}, ErrRemoteSSHInvalid
	}
	if in.AttachedAtUnix <= 0 {
		in.AttachedAtUnix = time.Now().UTC().Unix()
	}
	var out RemoteSSHSessionRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := expireRemoteSSHSessionsTx(ctx, tx, driver, in.AttachedAtUnix); err != nil {
			return err
		}
		rec, attachHash, found, err := loadRemoteSSHSessionByIDTx(ctx, tx, driver, in.SessionID)
		if err != nil {
			return err
		}
		if !found || attachHash != remoteSSHAttachTokenHash(in.AttachToken) {
			return ErrRemoteSSHSessionNotFound
		}
		if !remoteSSHSessionAttachable(rec.Status) || rec.ExpiresAtUnix <= in.AttachedAtUnix {
			return ErrRemoteSSHSessionNotFound
		}
		if rec.OperatorConnectedAtUnix > 0 {
			return ErrRemoteSSHSessionNotFound
		}
		rec.OperatorConnectedAtUnix = in.AttachedAtUnix
		rec.OperatorIP = in.OperatorIP
		rec.OperatorUserAgent = in.UserAgent
		if rec.GatewayConnectedAtUnix > 0 {
			rec.Status = RemoteSSHSessionStatusActive
			rec.StartedAtUnix = in.AttachedAtUnix
		} else {
			rec.Status = RemoteSSHSessionStatusOperatorAttached
		}
		if err := updateRemoteSSHSessionAttachStateTx(ctx, tx, driver, rec); err != nil {
			return err
		}
		if err := insertRemoteSSHEventTx(ctx, tx, driver, rec.SessionID, rec.DeviceID, "operator_attached", "", in.AttachedAtUnix); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		out = rec
		return nil
	})
	return out, err
}

func CloseRemoteSSHSession(ctx context.Context, sessionID string, reason string, endedAtUnix int64) error {
	sessionID = strings.TrimSpace(sessionID)
	reason = truncateRemoteSSHField(strings.TrimSpace(reason), 256)
	if sessionID == "" {
		return ErrRemoteSSHInvalid
	}
	if endedAtUnix <= 0 {
		endedAtUnix = time.Now().UTC().Unix()
	}
	return withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		rec, _, found, err := loadRemoteSSHSessionByIDTx(ctx, tx, driver, sessionID)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		if !remoteSSHSessionAttachable(rec.Status) {
			return nil
		}
		_, err = tx.ExecContext(ctx, `
UPDATE center_remote_ssh_sessions
   SET status = `+placeholder(driver, 1)+`,
       ended_at_unix = `+placeholder(driver, 2)+`,
       close_reason = `+placeholder(driver, 3)+`
 WHERE session_id = `+placeholder(driver, 4),
			RemoteSSHSessionStatusClosed,
			endedAtUnix,
			reason,
			sessionID,
		)
		if err != nil {
			return err
		}
		if err := insertRemoteSSHEventTx(ctx, tx, driver, rec.SessionID, rec.DeviceID, "closed", reason, endedAtUnix); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func normalizeRemoteSSHSessionCreate(in RemoteSSHSessionCreate) (RemoteSSHSessionCreate, string, error) {
	out := in
	out.DeviceID = strings.TrimSpace(out.DeviceID)
	out.Reason = strings.TrimSpace(out.Reason)
	out.OperatorPublicKey = strings.TrimSpace(out.OperatorPublicKey)
	out.RequestedBy = truncateRemoteSSHField(strings.TrimSpace(out.RequestedBy), MaxRemoteSSHUsernameBytes)
	out.OperatorIP = truncateRemoteSSHField(strings.TrimSpace(out.OperatorIP), 191)
	out.OperatorUserAgent = truncateRemoteSSHField(strings.TrimSpace(out.OperatorUserAgent), 512)
	if !deviceIDPattern.MatchString(out.DeviceID) {
		return RemoteSSHSessionCreate{}, "", ErrRemoteSSHInvalid
	}
	if out.Reason != "" && len(out.Reason) > MaxRemoteSSHReasonBytes {
		return RemoteSSHSessionCreate{}, "", ErrRemoteSSHInvalid
	}
	if out.OperatorPublicKey == "" || len(out.OperatorPublicKey) > MaxRemoteSSHPublicKeyBytes {
		return RemoteSSHSessionCreate{}, "", ErrRemoteSSHInvalid
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(out.OperatorPublicKey))
	if err != nil {
		return RemoteSSHSessionCreate{}, "", ErrRemoteSSHInvalid
	}
	return out, remoteSSHPublicKeyFingerprintHex(pub), nil
}

func remoteSSHPublicKeyFingerprintHex(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return hex.EncodeToString(sum[:])
}

func normalizeRemoteSSHPolicyUpdate(in RemoteSSHPolicyUpdate) (RemoteSSHPolicyUpdate, error) {
	out := in
	out.DeviceID = strings.TrimSpace(out.DeviceID)
	out.AllowedRunAsUser = strings.TrimSpace(out.AllowedRunAsUser)
	out.UpdatedByUsername = truncateRemoteSSHField(strings.TrimSpace(out.UpdatedByUsername), MaxRemoteSSHUsernameBytes)
	if !deviceIDPattern.MatchString(out.DeviceID) {
		return RemoteSSHPolicyUpdate{}, ErrRemoteSSHInvalid
	}
	if out.MaxTTLSec <= 0 {
		out.MaxTTLSec = config.DefaultRemoteSSHMaxTTLSec
	}
	if out.MaxTTLSec < config.MinRemoteSSHMaxTTLSec || out.MaxTTLSec > config.MaxRemoteSSHMaxTTLSec {
		return RemoteSSHPolicyUpdate{}, ErrRemoteSSHInvalid
	}
	if err := validateRemoteSSHRunAsUser(out.AllowedRunAsUser); err != nil {
		return RemoteSSHPolicyUpdate{}, err
	}
	return out, nil
}

func validateRemoteSSHRunAsUser(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 64 {
		return ErrRemoteSSHInvalid
	}
	for i, r := range value {
		if r >= 128 {
			return ErrRemoteSSHInvalid
		}
		if i == 0 && !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return ErrRemoteSSHInvalid
		}
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			continue
		}
		if r == '$' && i == len(value)-1 {
			continue
		}
		return ErrRemoteSSHInvalid
	}
	return nil
}

func defaultRemoteSSHPolicy(deviceID string) RemoteSSHPolicyRecord {
	maxTTL := int64(config.RemoteSSHMaxTTL / time.Second)
	if maxTTL <= 0 {
		maxTTL = config.DefaultRemoteSSHMaxTTLSec
	}
	return RemoteSSHPolicyRecord{
		DeviceID:      deviceID,
		Enabled:       false,
		MaxTTLSec:     maxTTL,
		RequireReason: true,
	}
}

func loadRemoteSSHPolicyTx(ctx context.Context, q queryer, driver string, deviceID string) (RemoteSSHPolicyRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT device_id, enabled, max_ttl_sec, allowed_run_as_user, require_reason, updated_by_user_id, updated_by_username, updated_at_unix
  FROM center_device_remote_ssh_policy
 WHERE device_id = `+placeholder(driver, 1), deviceID)
	var rec RemoteSSHPolicyRecord
	var enabled anyBool
	var requireReason anyBool
	var updatedBy sql.NullInt64
	if err := row.Scan(&rec.DeviceID, &enabled, &rec.MaxTTLSec, &rec.AllowedRunAsUser, &requireReason, &updatedBy, &rec.UpdatedByUsername, &rec.UpdatedAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RemoteSSHPolicyRecord{}, false, nil
		}
		return RemoteSSHPolicyRecord{}, false, err
	}
	rec.Enabled = bool(enabled)
	rec.RequireReason = bool(requireReason)
	if updatedBy.Valid {
		rec.UpdatedByUserID = updatedBy.Int64
	}
	return rec, true, nil
}

func upsertRemoteSSHPolicyTx(ctx context.Context, tx *sql.Tx, driver string, in RemoteSSHPolicyUpdate) error {
	args := []any{
		in.DeviceID,
		boolInt(in.Enabled),
		in.MaxTTLSec,
		in.AllowedRunAsUser,
		boolInt(in.RequireReason),
		nullInt64(in.UpdatedByUserID),
		in.UpdatedByUsername,
		in.UpdatedAtUnix,
	}
	switch driver {
	case "mysql":
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_remote_ssh_policy
    (device_id, enabled, max_ttl_sec, allowed_run_as_user, require_reason, updated_by_user_id, updated_by_username, updated_at_unix)
VALUES
    (`+placeholders(driver, 8, 1)+`)
ON DUPLICATE KEY UPDATE
    enabled = VALUES(enabled),
    max_ttl_sec = VALUES(max_ttl_sec),
    allowed_run_as_user = VALUES(allowed_run_as_user),
    require_reason = VALUES(require_reason),
    updated_by_user_id = VALUES(updated_by_user_id),
    updated_by_username = VALUES(updated_by_username),
    updated_at_unix = VALUES(updated_at_unix)`, args...)
		return err
	default:
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_remote_ssh_policy
    (device_id, enabled, max_ttl_sec, allowed_run_as_user, require_reason, updated_by_user_id, updated_by_username, updated_at_unix)
VALUES
    (`+placeholders(driver, 8, 1)+`)
ON CONFLICT(device_id) DO UPDATE SET
    enabled = excluded.enabled,
    max_ttl_sec = excluded.max_ttl_sec,
    allowed_run_as_user = excluded.allowed_run_as_user,
    require_reason = excluded.require_reason,
    updated_by_user_id = excluded.updated_by_user_id,
    updated_by_username = excluded.updated_by_username,
    updated_at_unix = excluded.updated_at_unix`, args...)
		return err
	}
}

func insertRemoteSSHSessionTx(ctx context.Context, tx *sql.Tx, driver string, rec RemoteSSHSessionRecord) error {
	attachHash := remoteSSHAttachTokenHash(rec.AttachToken)
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_remote_ssh_sessions
    (session_id, device_id, status, reason, requested_by_user_id, requested_by_username, operator_public_key,
     operator_public_key_fingerprint_sha256, attach_token_hash, gateway_host_key_fingerprint_sha256, gateway_host_public_key,
     ttl_sec, expires_at_unix, created_at_unix,
     operator_ip, operator_user_agent)
VALUES
    (`+placeholders(driver, 16, 1)+`)`,
		rec.SessionID,
		rec.DeviceID,
		rec.Status,
		rec.Reason,
		nullInt64(rec.RequestedByUserID),
		rec.RequestedByUsername,
		rec.OperatorPublicKey,
		rec.OperatorPublicKeyFingerprintSHA256,
		attachHash,
		rec.GatewayHostKeyFingerprintSHA256,
		rec.GatewayHostPublicKey,
		rec.TTLSec,
		rec.ExpiresAtUnix,
		rec.CreatedAtUnix,
		rec.OperatorIP,
		rec.OperatorUserAgent,
	)
	return err
}

func loadRemoteSSHSessionByIDTx(ctx context.Context, q queryer, driver string, sessionID string) (RemoteSSHSessionRecord, string, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT session_id, device_id, status, reason, requested_by_user_id, requested_by_username,
       operator_public_key, operator_public_key_fingerprint_sha256, attach_token_hash,
       gateway_host_key_fingerprint_sha256, gateway_host_public_key, ttl_sec, expires_at_unix, created_at_unix,
       gateway_connected_at_unix, operator_connected_at_unix, started_at_unix, ended_at_unix,
       close_reason, operator_ip, operator_user_agent
  FROM center_remote_ssh_sessions
 WHERE session_id = `+placeholder(driver, 1), sessionID)
	var rec RemoteSSHSessionRecord
	var requestedBy sql.NullInt64
	var attachHash string
	if err := row.Scan(
		&rec.SessionID,
		&rec.DeviceID,
		&rec.Status,
		&rec.Reason,
		&requestedBy,
		&rec.RequestedByUsername,
		&rec.OperatorPublicKey,
		&rec.OperatorPublicKeyFingerprintSHA256,
		&attachHash,
		&rec.GatewayHostKeyFingerprintSHA256,
		&rec.GatewayHostPublicKey,
		&rec.TTLSec,
		&rec.ExpiresAtUnix,
		&rec.CreatedAtUnix,
		&rec.GatewayConnectedAtUnix,
		&rec.OperatorConnectedAtUnix,
		&rec.StartedAtUnix,
		&rec.EndedAtUnix,
		&rec.CloseReason,
		&rec.OperatorIP,
		&rec.OperatorUserAgent,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RemoteSSHSessionRecord{}, "", false, nil
		}
		return RemoteSSHSessionRecord{}, "", false, err
	}
	if requestedBy.Valid {
		rec.RequestedByUserID = requestedBy.Int64
	}
	return rec, attachHash, true, nil
}

func updateRemoteSSHSessionAttachStateTx(ctx context.Context, tx *sql.Tx, driver string, rec RemoteSSHSessionRecord) error {
	_, err := tx.ExecContext(ctx, `
UPDATE center_remote_ssh_sessions
   SET status = `+placeholder(driver, 1)+`,
       gateway_host_key_fingerprint_sha256 = `+placeholder(driver, 2)+`,
       gateway_host_public_key = `+placeholder(driver, 3)+`,
       gateway_connected_at_unix = `+placeholder(driver, 4)+`,
       operator_connected_at_unix = `+placeholder(driver, 5)+`,
       started_at_unix = `+placeholder(driver, 6)+`,
       operator_ip = `+placeholder(driver, 7)+`,
       operator_user_agent = `+placeholder(driver, 8)+`
 WHERE session_id = `+placeholder(driver, 9),
		rec.Status,
		rec.GatewayHostKeyFingerprintSHA256,
		rec.GatewayHostPublicKey,
		rec.GatewayConnectedAtUnix,
		rec.OperatorConnectedAtUnix,
		rec.StartedAtUnix,
		rec.OperatorIP,
		rec.OperatorUserAgent,
		rec.SessionID,
	)
	return err
}

func listRemoteSSHSessionsTx(ctx context.Context, q queryerWithRows, driver string, deviceID string, limit int) ([]RemoteSSHSessionRecord, error) {
	rows, err := q.QueryContext(ctx, `
SELECT session_id, device_id, status, reason, requested_by_user_id, requested_by_username,
       operator_public_key_fingerprint_sha256, gateway_host_key_fingerprint_sha256, gateway_host_public_key, ttl_sec,
       expires_at_unix, created_at_unix, gateway_connected_at_unix, operator_connected_at_unix,
       started_at_unix, ended_at_unix, close_reason, operator_ip, operator_user_agent
  FROM center_remote_ssh_sessions
 WHERE device_id = `+placeholder(driver, 1)+`
 ORDER BY created_at_unix DESC
 LIMIT `+placeholder(driver, 2), deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RemoteSSHSessionRecord{}
	for rows.Next() {
		var rec RemoteSSHSessionRecord
		var requestedBy sql.NullInt64
		if err := rows.Scan(
			&rec.SessionID,
			&rec.DeviceID,
			&rec.Status,
			&rec.Reason,
			&requestedBy,
			&rec.RequestedByUsername,
			&rec.OperatorPublicKeyFingerprintSHA256,
			&rec.GatewayHostKeyFingerprintSHA256,
			&rec.GatewayHostPublicKey,
			&rec.TTLSec,
			&rec.ExpiresAtUnix,
			&rec.CreatedAtUnix,
			&rec.GatewayConnectedAtUnix,
			&rec.OperatorConnectedAtUnix,
			&rec.StartedAtUnix,
			&rec.EndedAtUnix,
			&rec.CloseReason,
			&rec.OperatorIP,
			&rec.OperatorUserAgent,
		); err != nil {
			return nil, err
		}
		if requestedBy.Valid {
			rec.RequestedByUserID = requestedBy.Int64
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func countActiveRemoteSSHSessionsTx(ctx context.Context, q queryer, driver string, deviceID string, nowUnix int64) (int64, int64, error) {
	statuses := activeRemoteSSHSessionStatuses()
	args := make([]any, 0, len(statuses)+1)
	query := `
SELECT COUNT(*)
  FROM center_remote_ssh_sessions
 WHERE status IN (` + placeholders(driver, len(statuses), 1) + `)
   AND expires_at_unix > ` + placeholder(driver, len(statuses)+1)
	for _, status := range statuses {
		args = append(args, status)
	}
	args = append(args, nowUnix)
	var total int64
	if err := q.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, 0, err
	}
	args = make([]any, 0, len(statuses)+2)
	query = `
SELECT COUNT(*)
  FROM center_remote_ssh_sessions
 WHERE device_id = ` + placeholder(driver, 1) + `
   AND status IN (` + placeholders(driver, len(statuses), 2) + `)
   AND expires_at_unix > ` + placeholder(driver, len(statuses)+2)
	args = append(args, deviceID)
	for _, status := range statuses {
		args = append(args, status)
	}
	args = append(args, nowUnix)
	var perDevice int64
	if err := q.QueryRowContext(ctx, query, args...).Scan(&perDevice); err != nil {
		return 0, 0, err
	}
	return total, perDevice, nil
}

func expireRemoteSSHSessionsTx(ctx context.Context, q execQueryer, driver string, nowUnix int64) error {
	statuses := activeRemoteSSHSessionStatuses()
	args := make([]any, 0, len(statuses)+2)
	query := `
UPDATE center_remote_ssh_sessions
   SET status = ` + placeholder(driver, 1) + `,
       ended_at_unix = ` + placeholder(driver, 2) + `,
       close_reason = 'expired'
 WHERE status IN (` + placeholders(driver, len(statuses), 3) + `)
   AND expires_at_unix <= ` + placeholder(driver, len(statuses)+3)
	args = append(args, RemoteSSHSessionStatusExpired, nowUnix)
	for _, status := range statuses {
		args = append(args, status)
	}
	args = append(args, nowUnix)
	_, err := q.ExecContext(ctx, query, args...)
	return err
}

func insertRemoteSSHEventTx(ctx context.Context, tx *sql.Tx, driver, sessionID, deviceID, eventType, message string, createdAtUnix int64) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_remote_ssh_events
    (session_id, device_id, event_type, message, metadata_json, created_at_unix)
VALUES
    (`+placeholders(driver, 6, 1)+`)`,
		sessionID,
		deviceID,
		eventType,
		truncateRemoteSSHField(message, 1024),
		"{}",
		createdAtUnix,
	)
	return err
}

func activeRemoteSSHSessionStatuses() []string {
	return []string{
		RemoteSSHSessionStatusPending,
		RemoteSSHSessionStatusGatewayAttached,
		RemoteSSHSessionStatusOperatorAttached,
		RemoteSSHSessionStatusActive,
	}
}

func remoteSSHSessionAttachable(status string) bool {
	switch status {
	case RemoteSSHSessionStatusPending, RemoteSSHSessionStatusGatewayAttached, RemoteSSHSessionStatusOperatorAttached, RemoteSSHSessionStatusActive:
		return true
	default:
		return false
	}
}

func remoteSSHAttachTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func remoteSSHRandomToken(size int) (string, error) {
	if size <= 0 || size > 64 {
		return "", fmt.Errorf("remote ssh random token size out of range")
	}
	var raw [64]byte
	if _, err := rand.Read(raw[:size]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:size]), nil
}

func nullInt64(v int64) sql.NullInt64 {
	return sql.NullInt64{Int64: v, Valid: v > 0}
}

func truncateRemoteSSHField(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

type anyBool bool

func (b *anyBool) Scan(src any) error {
	switch v := src.(type) {
	case bool:
		*b = anyBool(v)
		return nil
	case int64:
		*b = anyBool(v != 0)
		return nil
	case int:
		*b = anyBool(v != 0)
		return nil
	case []byte:
		s := strings.TrimSpace(string(v))
		*b = anyBool(s == "1" || strings.EqualFold(s, "true"))
		return nil
	case string:
		s := strings.TrimSpace(v)
		*b = anyBool(s == "1" || strings.EqualFold(s, "true"))
		return nil
	default:
		return fmt.Errorf("cannot scan bool from %T", src)
	}
}
