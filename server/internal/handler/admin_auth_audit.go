package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"
)

const (
	adminAuthAuditEventMFASetupCreated             = "mfa_setup_created"
	adminAuthAuditEventMFAEnabled                  = "mfa_enabled"
	adminAuthAuditEventMFAVerified                 = "mfa_verified"
	adminAuthAuditEventMFARecoveryCodesRegenerated = "mfa_recovery_codes_regenerated"
	adminAuthAuditEventMFADisabled                 = "mfa_disabled"
	adminAuthAuditEventMFAEmergencyDisabled        = "mfa_emergency_disabled"

	adminMFAEmergencyActor = "cli"
	maxAdminMFAReasonBytes = 512
)

var (
	ErrAdminMFAEmergencySelector = errors.New("exactly one of username or email is required")
	ErrAdminMFAEmergencyReason   = errors.New("reason is required")
	ErrAdminMFAEmergencyNotFound = errors.New("admin user not found")
)

type AdminMFAEmergencyDisableRequest struct {
	Username string
	Email    string
	Reason   string
	Actor    string
	Now      time.Time
}

type AdminMFAEmergencyDisableResult struct {
	UserID     int64
	Username   string
	WasEnabled bool
}

func DisableAdminMFAForUser(req AdminMFAEmergencyDisableRequest) (AdminMFAEmergencyDisableResult, error) {
	store := getLogsStatsStore()
	if store == nil {
		return AdminMFAEmergencyDisableResult{}, errAdminAuthStoreUnavailable
	}
	return store.disableAdminMFAForUser(req)
}

func recordAdminAuthAuditBestEffort(store *wafEventStore, eventType string, user adminUserRecord, authKind string, credentialID string, success bool, ip string, userAgent string, metadata map[string]any, now time.Time) {
	if store == nil {
		return
	}
	if err := store.recordAdminAuthAudit(eventType, user, authKind, credentialID, success, ip, userAgent, metadata, now); err != nil {
		log.Printf("[ADMIN][AUTH][AUDIT][WARN] event=%s user_id=%d: %v", eventType, user.UserID, err)
	}
}

func (s *wafEventStore) disableAdminMFAForUser(req AdminMFAEmergencyDisableRequest) (AdminMFAEmergencyDisableResult, error) {
	if s == nil || s.db == nil {
		return AdminMFAEmergencyDisableResult{}, errAdminAuthStoreUnavailable
	}
	username := strings.TrimSpace(req.Username)
	email := strings.TrimSpace(req.Email)
	if (username == "") == (email == "") {
		return AdminMFAEmergencyDisableResult{}, ErrAdminMFAEmergencySelector
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" || len(reason) > maxAdminMFAReasonBytes || strings.ContainsAny(reason, "\x00\r\n") {
		return AdminMFAEmergencyDisableResult{}, ErrAdminMFAEmergencyReason
	}
	actor := strings.TrimSpace(req.Actor)
	if actor == "" {
		actor = adminMFAEmergencyActor
	}
	now := normalizedAdminMFATime(req.Now)

	user, found, err := s.loadAdminUserByEmergencySelector(username, email)
	if err != nil {
		return AdminMFAEmergencyDisableResult{}, err
	}
	if !found {
		return AdminMFAEmergencyDisableResult{}, ErrAdminMFAEmergencyNotFound
	}
	enabled, err := s.adminMFAEnabled(user.UserID)
	if err != nil {
		return AdminMFAEmergencyDisableResult{}, err
	}
	if err := s.disableAdminMFA(user.UserID); err != nil {
		return AdminMFAEmergencyDisableResult{}, err
	}
	if err := s.recordAdminAuthAudit(adminAuthAuditEventMFAEmergencyDisabled, user, actor, "", true, "", "", map[string]any{
		"reason":      reason,
		"was_enabled": enabled,
	}, now); err != nil {
		return AdminMFAEmergencyDisableResult{}, err
	}
	return AdminMFAEmergencyDisableResult{
		UserID:     user.UserID,
		Username:   user.Username,
		WasEnabled: enabled,
	}, nil
}

func (s *wafEventStore) loadAdminUserByEmergencySelector(username string, email string) (adminUserRecord, bool, error) {
	var row adminUserScanner
	if strings.TrimSpace(username) != "" {
		_, value, err := normalizeAdminUsername(username)
		if err != nil || value == "" {
			return adminUserRecord{}, false, err
		}
		row = s.queryRow(
			`SELECT user_id, username, COALESCE(email, ''), role, password_hash,
		        must_change_password, session_version, COALESCE(disabled_at_unix, 0),
		        COALESCE(last_login_at, ''), created_at, updated_at
		   FROM admin_users
		  WHERE username_normalized = ?`,
			value,
		)
	} else {
		_, value, err := normalizeAdminEmail(email)
		if err != nil || value == "" {
			return adminUserRecord{}, false, err
		}
		row = s.queryRow(
			`SELECT user_id, username, COALESCE(email, ''), role, password_hash,
		        must_change_password, session_version, COALESCE(disabled_at_unix, 0),
		        COALESCE(last_login_at, ''), created_at, updated_at
		   FROM admin_users
		  WHERE email_normalized = ?`,
			value,
		)
	}
	user, err := scanAdminUserRecord(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminUserRecord{}, false, nil
		}
		return adminUserRecord{}, false, err
	}
	return user, true, nil
}

func (s *wafEventStore) recordAdminAuthAudit(eventType string, user adminUserRecord, authKind string, credentialID string, success bool, ip string, userAgent string, metadata map[string]any, now time.Time) error {
	if s == nil || s.db == nil {
		return errAdminAuthStoreUnavailable
	}
	eventType = strings.TrimSpace(eventType)
	if eventType == "" || len(eventType) > 128 || strings.ContainsAny(eventType, "\x00\r\n\t") {
		return errors.New("invalid admin auth audit event")
	}
	authKind = strings.TrimSpace(authKind)
	if authKind == "" {
		authKind = "unknown"
	}
	if len(authKind) > 64 || strings.ContainsAny(authKind, "\x00\r\n\t") {
		return errors.New("invalid admin auth audit auth kind")
	}
	credentialID = strings.TrimSpace(credentialID)
	if len(credentialID) > 128 || strings.ContainsAny(credentialID, "\x00\r\n\t") {
		return errors.New("invalid admin auth audit credential")
	}
	if len(ip) > 128 {
		ip = ip[:128]
	}
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	rawMetadata, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	if len(rawMetadata) > 4096 {
		return errors.New("admin auth audit metadata is too large")
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var userID any
	var username any
	if user.UserID > 0 {
		userID = user.UserID
		username = user.Username
	}
	_, err = s.exec(
		`INSERT INTO admin_auth_audit (
			event_type, user_id, username, auth_kind, auth_credential_id,
			success, ip, user_agent, metadata_json, created_at_unix, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		eventType,
		userID,
		username,
		authKind,
		nullableStringValue(credentialID),
		boolToDB(success),
		nullableStringValue(strings.TrimSpace(ip)),
		nullableStringValue(strings.TrimSpace(userAgent)),
		string(rawMetadata),
		now.Unix(),
		now.Format(time.RFC3339Nano),
	)
	return err
}

func nullableStringValue(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}
