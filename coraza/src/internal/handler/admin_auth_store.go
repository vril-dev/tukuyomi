package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
	"tukuyomi/internal/middleware"
)

const (
	defaultAdminSessionTTL        = 8 * time.Hour
	maxAdminSessionTokenBytes     = 256
	maxAdminCSRFCookieBytes       = 256
	adminAuthHashPrefixSHA256     = "sha256:"
	adminAuthHashPrefixHMACSHA256 = "hmac-sha256:"
)

var (
	errAdminAuthStoreUnavailable  = errors.New("admin auth store is not initialized")
	errAdminAuthInvalidCredential = errors.New("invalid admin credential")
	errAdminAuthDisabledUser      = errors.New("admin user is disabled")
)

func init() {
	middleware.SetAdminAuthResolver(resolveDBAdminAuth)
}

type adminUserRecord struct {
	UserID             int64
	Username           string
	Email              string
	Role               adminauth.AdminRole
	PasswordHash       string
	MustChangePassword bool
	SessionVersion     int64
	Disabled           bool
	LastLoginAt        time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type adminSessionRecord struct {
	SessionID     int64
	Principal     adminauth.Principal
	ExpiresAt     time.Time
	CSRFTokenHash string
}

func resolveDBAdminAuth(c *gin.Context) (middleware.AdminAuthResult, bool, error) {
	if c == nil || c.Request == nil {
		return middleware.AdminAuthResult{}, false, nil
	}
	store := getLogsStatsStore()
	if store == nil {
		return middleware.AdminAuthResult{}, false, nil
	}

	now := time.Now().UTC()
	if token, presented := adminPersonalAccessTokenFromRequest(c.Request); presented {
		principal, ok, err := store.authenticateAdminPersonalAccessToken(token, config.AdminSessionSecret, now)
		if err != nil {
			return middleware.AdminAuthResult{}, false, err
		}
		if !ok {
			return middleware.AdminAuthResult{}, false, errAdminAuthInvalidCredential
		}
		return middleware.AdminAuthResult{
			Principal:     principal,
			Mode:          string(adminauth.AuthKindToken),
			FallbackActor: principal.Username,
		}, true, nil
	}

	sessionToken, presented := adminSessionTokenFromRequest(c.Request)
	if !presented {
		return middleware.AdminAuthResult{}, false, nil
	}
	session, ok, err := store.authenticateAdminSessionRequest(c.Request, sessionToken, now)
	if err != nil {
		return middleware.AdminAuthResult{}, false, err
	}
	if !ok {
		return middleware.AdminAuthResult{}, false, nil
	}
	return middleware.AdminAuthResult{
		Principal:     session.Principal,
		Mode:          string(adminauth.AuthKindSession),
		FallbackActor: session.Principal.Username,
	}, true, nil
}

func (s *wafEventStore) createAdminUser(username string, email string, role adminauth.AdminRole, passwordHash string, mustChangePassword bool, now time.Time) (adminUserRecord, error) {
	if s == nil || s.db == nil {
		return adminUserRecord{}, errAdminAuthStoreUnavailable
	}
	username, usernameNormalized, err := normalizeAdminUsername(username)
	if err != nil {
		return adminUserRecord{}, err
	}
	email, emailNormalized, err := normalizeAdminEmail(email)
	if err != nil {
		return adminUserRecord{}, err
	}
	passwordHash = strings.TrimSpace(passwordHash)
	if !validAdminPasswordHash(passwordHash) {
		return adminUserRecord{}, adminauth.ErrInvalidPasswordHash
	}
	if !role.Valid() {
		return adminUserRecord{}, fmt.Errorf("invalid admin role")
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	rec := adminUserRecord{
		Username:           username,
		Email:              email,
		Role:               role,
		PasswordHash:       passwordHash,
		MustChangePassword: mustChangePassword,
		SessionVersion:     1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	createdAt := now.Format(time.RFC3339Nano)
	var nullableEmail any
	var nullableEmailNormalized any
	if email != "" {
		nullableEmail = email
		nullableEmailNormalized = emailNormalized
	}
	if s.dbDriver == logStatsDBDriverPostgres {
		row := s.queryRow(
			`INSERT INTO admin_users (
				username, username_normalized, email, email_normalized, role,
				password_hash, password_algo, must_change_password, session_version,
				created_at_unix, created_at, updated_at_unix, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, 'argon2id', ?, 1, ?, ?, ?, ?) RETURNING user_id`,
			username,
			usernameNormalized,
			nullableEmail,
			nullableEmailNormalized,
			string(role),
			passwordHash,
			mustChangePassword,
			now.Unix(),
			createdAt,
			now.Unix(),
			createdAt,
		)
		if err := row.Scan(&rec.UserID); err != nil {
			return adminUserRecord{}, err
		}
		return rec, nil
	}
	result, err := s.exec(
		`INSERT INTO admin_users (
			username, username_normalized, email, email_normalized, role,
			password_hash, password_algo, must_change_password, session_version,
			created_at_unix, created_at, updated_at_unix, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, 'argon2id', ?, 1, ?, ?, ?, ?)`,
		username,
		usernameNormalized,
		nullableEmail,
		nullableEmailNormalized,
		string(role),
		passwordHash,
		boolToDB(mustChangePassword),
		now.Unix(),
		createdAt,
		now.Unix(),
		createdAt,
	)
	if err != nil {
		return adminUserRecord{}, err
	}
	rec.UserID, err = result.LastInsertId()
	if err != nil {
		return adminUserRecord{}, err
	}
	return rec, nil
}

func (s *wafEventStore) authenticateAdminPassword(identifier string, password string, now time.Time) (adminauth.Principal, bool, error) {
	if s == nil || s.db == nil {
		return adminauth.Principal{}, false, errAdminAuthStoreUnavailable
	}
	identifier = adminauth.NormalizeAdminIdentifier(identifier)
	if identifier == "" || password == "" {
		return adminauth.Principal{}, false, nil
	}
	user, ok, err := s.loadAdminUserForLogin(identifier)
	if err != nil || !ok {
		return adminauth.Principal{}, false, err
	}
	if user.Disabled {
		return adminauth.Principal{}, false, errAdminAuthDisabledUser
	}
	matched, err := adminauth.VerifyPassword(user.PasswordHash, password)
	if err != nil {
		return adminauth.Principal{}, false, err
	}
	if !matched {
		return adminauth.Principal{}, false, nil
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if _, err := s.exec(
		`UPDATE admin_users SET last_login_at_unix = ?, last_login_at = ?, updated_at_unix = ?, updated_at = ? WHERE user_id = ?`,
		now.Unix(),
		now.Format(time.RFC3339Nano),
		now.Unix(),
		now.Format(time.RFC3339Nano),
		user.UserID,
	); err != nil {
		return adminauth.Principal{}, false, err
	}
	return adminPrincipalForUser(user, adminauth.AuthKindSession, ""), true, nil
}

func (s *wafEventStore) createAdminSession(principal adminauth.Principal, ttl time.Duration, now time.Time) (sessionToken string, csrfToken string, expiresAt time.Time, sessionID int64, err error) {
	if s == nil || s.db == nil {
		return "", "", time.Time{}, 0, errAdminAuthStoreUnavailable
	}
	if !principal.Authenticated() {
		return "", "", time.Time{}, 0, errAdminAuthInvalidCredential
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ttl <= 0 {
		ttl = defaultAdminSessionTTL
	}
	sessionVersion, err := s.loadAdminUserSessionVersion(principal.UserID)
	if err != nil {
		return "", "", time.Time{}, 0, err
	}
	sessionToken, err = randomAdminOpaqueToken(32)
	if err != nil {
		return "", "", time.Time{}, 0, err
	}
	csrfToken, err = randomAdminOpaqueToken(32)
	if err != nil {
		return "", "", time.Time{}, 0, err
	}
	expiresAt = now.Add(ttl).UTC()
	sessionHash := adminAuthSecretHash(sessionToken, config.AdminSessionSecret)
	csrfHash := adminAuthSecretHash(csrfToken, config.AdminSessionSecret)
	if s.dbDriver == logStatsDBDriverPostgres {
		row := s.queryRow(
			`INSERT INTO admin_sessions (
				user_id, session_token_hash, csrf_token_hash, session_version,
				expires_at_unix, expires_at, last_seen_at_unix, last_seen_at,
				created_at_unix, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING session_id`,
			principal.UserID,
			sessionHash,
			csrfHash,
			sessionVersion,
			expiresAt.Unix(),
			expiresAt.Format(time.RFC3339Nano),
			now.Unix(),
			now.Format(time.RFC3339Nano),
			now.Unix(),
			now.Format(time.RFC3339Nano),
		)
		if err := row.Scan(&sessionID); err != nil {
			return "", "", time.Time{}, 0, err
		}
		return sessionToken, csrfToken, expiresAt, sessionID, nil
	}
	result, err := s.exec(
		`INSERT INTO admin_sessions (
			user_id, session_token_hash, csrf_token_hash, session_version,
			expires_at_unix, expires_at, last_seen_at_unix, last_seen_at,
			created_at_unix, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		principal.UserID,
		sessionHash,
		csrfHash,
		sessionVersion,
		expiresAt.Unix(),
		expiresAt.Format(time.RFC3339Nano),
		now.Unix(),
		now.Format(time.RFC3339Nano),
		now.Unix(),
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return "", "", time.Time{}, 0, err
	}
	sessionID, err = result.LastInsertId()
	return sessionToken, csrfToken, expiresAt, sessionID, err
}

func (s *wafEventStore) createAdminPersonalAccessToken(userID int64, label string, scopes []string, expiresAt *time.Time, pepper string, now time.Time) (adminauth.PersonalAccessToken, int64, error) {
	if s == nil || s.db == nil {
		return adminauth.PersonalAccessToken{}, 0, errAdminAuthStoreUnavailable
	}
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 128 {
		return adminauth.PersonalAccessToken{}, 0, fmt.Errorf("invalid token label")
	}
	if _, err := s.loadAdminUserSessionVersion(userID); err != nil {
		return adminauth.PersonalAccessToken{}, 0, err
	}
	scopes, err := normalizeAdminTokenScopes(scopes)
	if err != nil {
		return adminauth.PersonalAccessToken{}, 0, err
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	pat, err := adminauth.GeneratePersonalAccessToken()
	if err != nil {
		return adminauth.PersonalAccessToken{}, 0, err
	}
	tokenHash, err := adminauth.HashPersonalAccessToken(pat.Token, pepper)
	if err != nil {
		return adminauth.PersonalAccessToken{}, 0, err
	}
	scopesRaw, err := json.Marshal(scopes)
	if err != nil {
		return adminauth.PersonalAccessToken{}, 0, err
	}
	var expiresUnix any
	var expiresText any
	if expiresAt != nil {
		expires := expiresAt.UTC()
		if !expires.After(now) {
			return adminauth.PersonalAccessToken{}, 0, fmt.Errorf("token expiration must be in the future")
		}
		expiresUnix = expires.Unix()
		expiresText = expires.Format(time.RFC3339Nano)
	}
	var tokenID int64
	if s.dbDriver == logStatsDBDriverPostgres {
		row := s.queryRow(
			`INSERT INTO admin_api_tokens (
				user_id, label, token_prefix, token_hash, scopes_json,
				expires_at_unix, expires_at, created_at_unix, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING token_id`,
			userID,
			label,
			pat.Prefix,
			tokenHash,
			string(scopesRaw),
			expiresUnix,
			expiresText,
			now.Unix(),
			now.Format(time.RFC3339Nano),
		)
		if err := row.Scan(&tokenID); err != nil {
			return adminauth.PersonalAccessToken{}, 0, err
		}
		return pat, tokenID, nil
	}
	result, err := s.exec(
		`INSERT INTO admin_api_tokens (
			user_id, label, token_prefix, token_hash, scopes_json,
			expires_at_unix, expires_at, created_at_unix, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID,
		label,
		pat.Prefix,
		tokenHash,
		string(scopesRaw),
		expiresUnix,
		expiresText,
		now.Unix(),
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return adminauth.PersonalAccessToken{}, 0, err
	}
	tokenID, err = result.LastInsertId()
	return pat, tokenID, err
}

func (s *wafEventStore) authenticateAdminPersonalAccessToken(token string, pepper string, now time.Time) (adminauth.Principal, bool, error) {
	if s == nil || s.db == nil {
		return adminauth.Principal{}, false, errAdminAuthStoreUnavailable
	}
	parts, err := adminauth.ParsePersonalAccessToken(token)
	if err != nil {
		return adminauth.Principal{}, false, err
	}
	row := s.queryRow(
		`SELECT t.token_id, t.token_hash, t.scopes_json,
		        COALESCE(t.expires_at_unix, 0), COALESCE(t.revoked_at_unix, 0),
		        u.user_id, u.username, u.role, u.session_version, COALESCE(u.disabled_at_unix, 0)
		   FROM admin_api_tokens t
		   JOIN admin_users u ON u.user_id = t.user_id
		  WHERE t.token_prefix = ?`,
		parts.Prefix,
	)
	var (
		tokenID        int64
		tokenHash      string
		scopesRaw      string
		expiresAtUnix  int64
		revokedAtUnix  int64
		user           adminUserRecord
		disabledAtUnix int64
	)
	if err := row.Scan(&tokenID, &tokenHash, &scopesRaw, &expiresAtUnix, &revokedAtUnix, &user.UserID, &user.Username, &user.Role, &user.SessionVersion, &disabledAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminauth.Principal{}, false, nil
		}
		return adminauth.Principal{}, false, err
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if disabledAtUnix > 0 || revokedAtUnix > 0 || (expiresAtUnix > 0 && !now.Before(time.Unix(expiresAtUnix, 0).UTC())) {
		return adminauth.Principal{}, false, nil
	}
	ok, err := adminauth.VerifyPersonalAccessToken(token, tokenHash, pepper)
	if err != nil || !ok {
		return adminauth.Principal{}, false, err
	}
	scopes, err := parseAdminTokenScopes(scopesRaw)
	if err != nil {
		return adminauth.Principal{}, false, err
	}
	if _, err := s.exec(
		`UPDATE admin_api_tokens SET last_used_at_unix = ?, last_used_at = ? WHERE token_id = ?`,
		now.Unix(),
		now.Format(time.RFC3339Nano),
		tokenID,
	); err != nil {
		return adminauth.Principal{}, false, err
	}
	principal := adminPrincipalForUser(user, adminauth.AuthKindToken, strconv.FormatInt(tokenID, 10))
	principal.Scopes = scopes
	return principal, true, nil
}

func (s *wafEventStore) authenticateAdminSessionRequest(r *http.Request, sessionToken string, now time.Time) (adminSessionRecord, bool, error) {
	session, ok, err := s.loadAdminSession(sessionToken, now)
	if err != nil || !ok {
		return adminSessionRecord{}, ok, err
	}
	if err := s.validateAdminSessionCSRF(r, session); err != nil {
		return adminSessionRecord{}, false, err
	}
	if _, err := s.exec(
		`UPDATE admin_sessions SET last_seen_at_unix = ?, last_seen_at = ? WHERE session_id = ?`,
		now.Unix(),
		now.Format(time.RFC3339Nano),
		session.SessionID,
	); err != nil {
		return adminSessionRecord{}, false, err
	}
	return session, true, nil
}

func (s *wafEventStore) loadAdminSession(sessionToken string, now time.Time) (adminSessionRecord, bool, error) {
	if s == nil || s.db == nil {
		return adminSessionRecord{}, false, errAdminAuthStoreUnavailable
	}
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" || len(sessionToken) > maxAdminSessionTokenBytes {
		return adminSessionRecord{}, false, nil
	}
	sessionHash := adminAuthSecretHash(sessionToken, config.AdminSessionSecret)
	row := s.queryRow(
		`SELECT s.session_id, s.user_id, s.session_version, s.expires_at_unix, s.csrf_token_hash,
		        u.username, u.role, u.session_version, COALESCE(u.disabled_at_unix, 0), COALESCE(s.revoked_at_unix, 0)
		   FROM admin_sessions s
		   JOIN admin_users u ON u.user_id = s.user_id
		  WHERE s.session_token_hash = ?`,
		sessionHash,
	)
	var (
		sessionVersion int64
		expiresAtUnix  int64
		user           adminUserRecord
		userVersion    int64
		disabledAtUnix int64
		revokedAtUnix  int64
		session        adminSessionRecord
	)
	if err := row.Scan(&session.SessionID, &user.UserID, &sessionVersion, &expiresAtUnix, &session.CSRFTokenHash, &user.Username, &user.Role, &userVersion, &disabledAtUnix, &revokedAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminSessionRecord{}, false, nil
		}
		return adminSessionRecord{}, false, err
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresAt := time.Unix(expiresAtUnix, 0).UTC()
	if disabledAtUnix > 0 || revokedAtUnix > 0 || sessionVersion != userVersion || !now.Before(expiresAt) {
		return adminSessionRecord{}, false, nil
	}
	session.Principal = adminPrincipalForUser(user, adminauth.AuthKindSession, strconv.FormatInt(session.SessionID, 10))
	session.ExpiresAt = expiresAt
	return session, true, nil
}

func (s *wafEventStore) ensureAdminSessionCSRFCookie(c *gin.Context, session adminSessionRecord, now time.Time) (string, error) {
	if c == nil || c.Request == nil {
		return "", nil
	}
	current, err := c.Request.Cookie(adminauth.CSRFCookieName)
	if err == nil && current != nil {
		value := strings.TrimSpace(current.Value)
		if value != "" && len(value) <= maxAdminCSRFCookieBytes && secureHashEqual(adminAuthSecretHash(value, config.AdminSessionSecret), session.CSRFTokenHash) {
			return value, nil
		}
	}
	next, err := randomAdminOpaqueToken(32)
	if err != nil {
		return "", err
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if _, err := s.exec(
		`UPDATE admin_sessions SET csrf_token_hash = ?, last_seen_at_unix = ?, last_seen_at = ? WHERE session_id = ?`,
		adminAuthSecretHash(next, config.AdminSessionSecret),
		now.Unix(),
		now.Format(time.RFC3339Nano),
		session.SessionID,
	); err != nil {
		return "", err
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     adminauth.CSRFCookieName,
		Value:    next,
		Path:     "/",
		HttpOnly: false,
		Secure:   requestIsHTTPS(c),
		SameSite: http.SameSiteLaxMode,
		Expires:  session.ExpiresAt.UTC(),
		MaxAge:   int(time.Until(session.ExpiresAt.UTC()).Seconds()),
	})
	return next, nil
}

func (s *wafEventStore) revokeAdminSession(sessionToken string, now time.Time) error {
	if s == nil || s.db == nil {
		return errAdminAuthStoreUnavailable
	}
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" || len(sessionToken) > maxAdminSessionTokenBytes {
		return nil
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.exec(
		`UPDATE admin_sessions
		    SET revoked_at_unix = ?, revoked_at = ?
		  WHERE session_token_hash = ? AND revoked_at_unix IS NULL`,
		now.Unix(),
		now.Format(time.RFC3339Nano),
		adminAuthSecretHash(sessionToken, config.AdminSessionSecret),
	)
	return err
}

func (s *wafEventStore) validateAdminSessionCSRF(r *http.Request, session adminSessionRecord) error {
	if r == nil || adminAuthSafeMethod(r.Method) {
		return nil
	}
	cookie, err := r.Cookie(adminauth.CSRFCookieName)
	if err != nil || cookie == nil {
		return adminauth.ErrCSRFRequired
	}
	csrf := strings.TrimSpace(cookie.Value)
	if csrf == "" || len(csrf) > maxAdminCSRFCookieBytes {
		return adminauth.ErrCSRFMismatch
	}
	if !secureHashEqual(adminAuthSecretHash(csrf, config.AdminSessionSecret), session.CSRFTokenHash) {
		return adminauth.ErrCSRFMismatch
	}
	return adminauth.ValidateCSRF(r, adminauth.Session{ExpiresAt: session.ExpiresAt, CSRFToken: csrf})
}

func (s *wafEventStore) loadAdminUserForLogin(identifier string) (adminUserRecord, bool, error) {
	row := s.queryRow(
		`SELECT user_id, username, COALESCE(email, ''), role, password_hash,
		        must_change_password, session_version, COALESCE(disabled_at_unix, 0),
		        COALESCE(last_login_at, ''), created_at, updated_at
		   FROM admin_users
		  WHERE username_normalized = ? OR email_normalized = ?`,
		identifier,
		identifier,
	)
	var (
		user           adminUserRecord
		mustChange     any
		disabledAtUnix int64
		lastLoginAt    string
		createdAt      string
		updatedAt      string
	)
	if err := row.Scan(&user.UserID, &user.Username, &user.Email, &user.Role, &user.PasswordHash, &mustChange, &user.SessionVersion, &disabledAtUnix, &lastLoginAt, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminUserRecord{}, false, nil
		}
		return adminUserRecord{}, false, err
	}
	user.Disabled = disabledAtUnix > 0
	user.MustChangePassword = dbBoolValue(mustChange)
	user.LastLoginAt, _ = time.Parse(time.RFC3339Nano, lastLoginAt)
	user.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	if !user.Role.Valid() {
		return adminUserRecord{}, false, fmt.Errorf("invalid admin role in db")
	}
	return user, true, nil
}

func (s *wafEventStore) loadAdminUserSessionVersion(userID int64) (int64, error) {
	row := s.queryRow(`SELECT session_version FROM admin_users WHERE user_id = ? AND disabled_at_unix IS NULL`, userID)
	var version int64
	if err := row.Scan(&version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errAdminAuthInvalidCredential
		}
		return 0, err
	}
	if version <= 0 {
		return 0, errAdminAuthInvalidCredential
	}
	return version, nil
}

func adminPrincipalForUser(user adminUserRecord, kind adminauth.AuthKind, credentialID string) adminauth.Principal {
	return adminauth.Principal{
		UserID:       user.UserID,
		Username:     user.Username,
		Role:         user.Role,
		AuthKind:     kind,
		CredentialID: credentialID,
	}
}

func adminSessionTokenFromRequest(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	cookie, err := r.Cookie(adminauth.SessionCookieName)
	if err != nil || cookie == nil {
		return "", false
	}
	token := strings.TrimSpace(cookie.Value)
	return token, token != ""
}

func adminPersonalAccessTokenFromRequest(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, token, ok := strings.Cut(auth, " ")
	if ok && strings.EqualFold(strings.TrimSpace(scheme), "Bearer") {
		token = strings.TrimSpace(token)
		if strings.HasPrefix(token, adminauth.PersonalAccessTokenPrefix) {
			return token, true
		}
	}
	return "", false
}

func adminAuthSafeMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func normalizeAdminUsername(username string) (string, string, error) {
	username = strings.TrimSpace(username)
	normalized := adminauth.NormalizeAdminIdentifier(username)
	if username == "" || len(username) > 64 || strings.ContainsAny(username, "\x00\r\n\t") {
		return "", "", fmt.Errorf("invalid admin username")
	}
	return username, normalized, nil
}

func normalizeAdminEmail(email string) (string, string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", "", nil
	}
	normalized := adminauth.NormalizeAdminIdentifier(email)
	if len(email) > 254 || strings.ContainsAny(email, "\x00\r\n\t") || !strings.Contains(normalized, "@") {
		return "", "", fmt.Errorf("invalid admin email")
	}
	return email, normalized, nil
}

func validAdminPasswordHash(passwordHash string) bool {
	return strings.HasPrefix(passwordHash, "$argon2id$v=19$") && len(passwordHash) <= 255
}

func dbBoolValue(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case int64:
		return v != 0
	case int:
		return v != 0
	case int32:
		return v != 0
	case []byte:
		return string(v) == "1" || strings.EqualFold(string(v), "true")
	case string:
		return v == "1" || strings.EqualFold(v, "true")
	default:
		return false
	}
}

func normalizeAdminTokenScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return []string{"admin:read"}, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		switch scope {
		case "admin:read", "admin:write":
		default:
			return nil, fmt.Errorf("invalid token scope")
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	if len(out) == 0 {
		return []string{"admin:read"}, nil
	}
	return out, nil
}

func parseAdminTokenScopes(raw string) ([]string, error) {
	var scopes []string
	if err := json.Unmarshal([]byte(raw), &scopes); err != nil {
		return nil, err
	}
	return normalizeAdminTokenScopes(scopes)
}

func randomAdminOpaqueToken(n int) (string, error) {
	if n < 16 || n > 64 {
		return "", fmt.Errorf("invalid token length")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func adminAuthSecretHash(secret string, pepper string) string {
	if strings.TrimSpace(pepper) == "" {
		sum := sha256.Sum256([]byte(secret))
		return adminAuthHashPrefixSHA256 + hex.EncodeToString(sum[:])
	}
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(secret))
	return adminAuthHashPrefixHMACSHA256 + hex.EncodeToString(mac.Sum(nil))
}

func secureHashEqual(a, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
