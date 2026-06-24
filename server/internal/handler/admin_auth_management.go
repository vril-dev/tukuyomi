package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
)

const (
	minManagedAdminPasswordBytes = 12
	maxManagedAdminTokens        = 100
)

var (
	errAdminAuthSessionRequired  = errors.New("admin browser session required")
	errAdminAuthInvalidUsername  = errors.New("invalid admin username")
	errAdminAuthInvalidEmail     = errors.New("invalid admin email")
	errAdminAuthDuplicateName    = errors.New("admin username already exists")
	errAdminAuthDuplicateEmail   = errors.New("admin email already exists")
	errAdminAuthCurrentPassword  = errors.New("invalid current password")
	errAdminAuthPasswordTooShort = errors.New("admin password must be at least 12 bytes")
)

type adminAccountResponse struct {
	UserID             int64               `json:"user_id"`
	Username           string              `json:"username"`
	Email              string              `json:"email,omitempty"`
	Role               adminauth.AdminRole `json:"role"`
	MustChangePassword bool                `json:"must_change_password"`
}

type adminAccountUpdateRequest struct {
	Username        string `json:"username"`
	Email           string `json:"email"`
	CurrentPassword string `json:"current_password"`
}

type adminPasswordUpdateRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type adminAPITokenRecord struct {
	TokenID    int64    `json:"token_id"`
	Label      string   `json:"label"`
	Prefix     string   `json:"prefix"`
	Scopes     []string `json:"scopes"`
	CreatedAt  string   `json:"created_at"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	LastUsedAt string   `json:"last_used_at,omitempty"`
	RevokedAt  string   `json:"revoked_at,omitempty"`
	Active     bool     `json:"active"`
}

type adminAPITokenListResponse struct {
	Tokens []adminAPITokenRecord `json:"tokens"`
}

type adminAPITokenCreateRequest struct {
	Label           string   `json:"label"`
	Scopes          []string `json:"scopes"`
	ExpiresAt       string   `json:"expires_at"`
	CurrentPassword string   `json:"current_password"`
}

type adminAPITokenCreateResponse struct {
	Token  string              `json:"token"`
	Record adminAPITokenRecord `json:"record"`
}

func GetAdminAccount(c *gin.Context) {
	principal, ok := currentAdminSessionPrincipal(c)
	if !ok {
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	user, found, err := store.loadAdminUserByID(principal.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load admin account"})
		return
	}
	if !found || user.Disabled {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin account is unavailable"})
		return
	}
	c.JSON(http.StatusOK, adminAccountResponseForUser(user))
}

func PutAdminAccount(c *gin.Context) {
	principal, ok := currentAdminSessionPrincipal(c)
	if !ok {
		return
	}
	var req adminAccountUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid admin account payload"})
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	if _, ok, err := store.verifyAdminCurrentPassword(principal.UserID, req.CurrentPassword); err != nil {
		writeAdminCurrentPasswordCheckError(c, err)
		return
	} else if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": errAdminAuthCurrentPassword.Error()})
		return
	}
	user, err := store.updateAdminUserIdentity(principal.UserID, req.Username, req.Email, time.Now().UTC())
	if err != nil {
		writeAdminAccountMutationError(c, err)
		return
	}
	c.JSON(http.StatusOK, adminAccountResponseForUser(user))
}

func PutAdminPassword(c *gin.Context) {
	principal, ok := currentAdminSessionPrincipal(c)
	if !ok {
		return
	}
	var req adminPasswordUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid admin password payload"})
		return
	}
	if err := validateManagedAdminPassword(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	user, ok, err := store.verifyAdminCurrentPassword(principal.UserID, req.CurrentPassword)
	if err != nil {
		writeAdminCurrentPasswordCheckError(c, err)
		return
	}
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": errAdminAuthCurrentPassword.Error()})
		return
	}
	same, err := adminauth.VerifyPassword(user.PasswordHash, req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify new password"})
		return
	}
	if same {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new password must differ from current password"})
		return
	}
	passwordHash, err := adminauth.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := store.changeAdminUserPassword(principal.UserID, passwordHash, time.Now().UTC()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update admin password"})
		return
	}
	clearAdminAuthCookies(c)
	c.JSON(http.StatusOK, gin.H{"ok": true, "reauth_required": true})
}

func GetAdminAPITokens(c *gin.Context) {
	principal, ok := currentAdminSessionPrincipal(c)
	if !ok {
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	tokens, err := store.listAdminPersonalAccessTokens(principal.UserID, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load admin API tokens"})
		return
	}
	c.JSON(http.StatusOK, adminAPITokenListResponse{Tokens: tokens})
}

func PostAdminAPIToken(c *gin.Context) {
	principal, ok := currentAdminSessionPrincipal(c)
	if !ok {
		return
	}
	var req adminAPITokenCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid admin API token payload"})
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	if _, ok, err := store.verifyAdminCurrentPassword(principal.UserID, req.CurrentPassword); err != nil {
		writeAdminCurrentPasswordCheckError(c, err)
		return
	} else if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": errAdminAuthCurrentPassword.Error()})
		return
	}
	expiresAt, err := parseAdminAPITokenExpiresAt(req.ExpiresAt, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	label, scopes, err := validateAdminAPITokenCreateRequest(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pat, tokenID, err := store.createAdminPersonalAccessToken(principal.UserID, label, scopes, expiresAt, config.AdminSessionSecret, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create admin API token"})
		return
	}
	record, found, err := store.loadAdminPersonalAccessToken(principal.UserID, tokenID, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load created admin API token"})
		return
	}
	if !found {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "created admin API token was not found"})
		return
	}
	c.JSON(http.StatusCreated, adminAPITokenCreateResponse{
		Token:  pat.Token,
		Record: record,
	})
}

func PostAdminAPITokenRevoke(c *gin.Context) {
	principal, ok := currentAdminSessionPrincipal(c)
	if !ok {
		return
	}
	tokenID, err := parsePositiveInt64(c.Param("token_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid admin API token id"})
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	if revoked, err := store.revokeAdminPersonalAccessToken(principal.UserID, tokenID, time.Now().UTC()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke admin API token"})
		return
	} else if !revoked {
		c.JSON(http.StatusNotFound, gin.H{"error": "admin API token not found"})
		return
	}
	tokens, err := store.listAdminPersonalAccessTokens(principal.UserID, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load admin API tokens"})
		return
	}
	c.JSON(http.StatusOK, adminAPITokenListResponse{Tokens: tokens})
}

func currentAdminSessionPrincipal(c *gin.Context) (adminauth.Principal, bool) {
	value, ok := c.Get("tukuyomi.admin_principal")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin authentication required"})
		return adminauth.Principal{}, false
	}
	principal, ok := value.(adminauth.Principal)
	if !ok || !principal.Authenticated() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin authentication required"})
		return adminauth.Principal{}, false
	}
	if principal.AuthKind != adminauth.AuthKindSession {
		c.JSON(http.StatusForbidden, gin.H{"error": errAdminAuthSessionRequired.Error()})
		return adminauth.Principal{}, false
	}
	return principal, true
}

func adminAccountResponseForUser(user adminUserRecord) adminAccountResponse {
	return adminAccountResponse{
		UserID:             user.UserID,
		Username:           user.Username,
		Email:              user.Email,
		Role:               user.Role,
		MustChangePassword: user.MustChangePassword,
	}
}

func validateManagedAdminPassword(password string) error {
	if len(password) < minManagedAdminPasswordBytes {
		return errAdminAuthPasswordTooShort
	}
	if len(password) > 1024 || strings.ContainsAny(password, "\x00\r\n") {
		return adminauth.ErrInvalidPassword
	}
	return nil
}

func parseAdminAPITokenExpiresAt(raw string, now time.Time) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	expiresAt, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("expires_at must be RFC3339")
	}
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now.UTC()) {
		return nil, fmt.Errorf("expires_at must be in the future")
	}
	return &expiresAt, nil
}

func validateAdminAPITokenCreateRequest(req adminAPITokenCreateRequest) (string, []string, error) {
	label := strings.TrimSpace(req.Label)
	if label == "" || len(label) > 128 || strings.ContainsAny(label, "\x00\r\n") {
		return "", nil, fmt.Errorf("invalid token label")
	}
	scopes, err := normalizeAdminTokenScopes(req.Scopes)
	if err != nil {
		return "", nil, err
	}
	return label, scopes, nil
}

func parsePositiveInt64(raw string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid positive integer")
	}
	return value, nil
}

func writeAdminCurrentPasswordCheckError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, adminauth.ErrInvalidPassword):
		c.JSON(http.StatusForbidden, gin.H{"error": errAdminAuthCurrentPassword.Error()})
	case errors.Is(err, errAdminAuthDisabledUser), errors.Is(err, errAdminAuthInvalidCredential):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin account is unavailable"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify current password"})
	}
}

func writeAdminAccountMutationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errAdminAuthInvalidUsername), errors.Is(err, errAdminAuthInvalidEmail):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, errAdminAuthDuplicateName), errors.Is(err, errAdminAuthDuplicateEmail):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, errAdminAuthInvalidCredential), errors.Is(err, errAdminAuthDisabledUser):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin account is unavailable"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update admin account"})
	}
}

type adminUserScanner interface {
	Scan(dest ...any) error
}

func scanAdminUserRecord(scanner adminUserScanner) (adminUserRecord, error) {
	var (
		user           adminUserRecord
		mustChange     any
		disabledAtUnix int64
		lastLoginAt    string
		createdAt      string
		updatedAt      string
	)
	if err := scanner.Scan(&user.UserID, &user.Username, &user.Email, &user.Role, &user.PasswordHash, &mustChange, &user.SessionVersion, &disabledAtUnix, &lastLoginAt, &createdAt, &updatedAt); err != nil {
		return adminUserRecord{}, err
	}
	user.Disabled = disabledAtUnix > 0
	user.MustChangePassword = dbBoolValue(mustChange)
	user.LastLoginAt, _ = time.Parse(time.RFC3339Nano, lastLoginAt)
	user.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	if !user.Role.Valid() {
		return adminUserRecord{}, fmt.Errorf("invalid admin role in db")
	}
	return user, nil
}

func (s *wafEventStore) loadAdminUserByID(userID int64) (adminUserRecord, bool, error) {
	if s == nil || s.db == nil {
		return adminUserRecord{}, false, errAdminAuthStoreUnavailable
	}
	if userID <= 0 {
		return adminUserRecord{}, false, nil
	}
	row := s.queryRow(
		`SELECT user_id, username, COALESCE(email, ''), role, password_hash,
		        must_change_password, session_version, COALESCE(disabled_at_unix, 0),
		        COALESCE(last_login_at, ''), created_at, updated_at
		   FROM admin_users
		  WHERE user_id = ?`,
		userID,
	)
	user, err := scanAdminUserRecord(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminUserRecord{}, false, nil
		}
		return adminUserRecord{}, false, err
	}
	return user, true, nil
}

func (s *wafEventStore) verifyAdminCurrentPassword(userID int64, password string) (adminUserRecord, bool, error) {
	if strings.TrimSpace(password) == "" {
		return adminUserRecord{}, false, nil
	}
	user, ok, err := s.loadAdminUserByID(userID)
	if err != nil || !ok {
		return adminUserRecord{}, false, err
	}
	if user.Disabled {
		return adminUserRecord{}, false, errAdminAuthDisabledUser
	}
	matched, err := adminauth.VerifyPassword(user.PasswordHash, password)
	if err != nil || !matched {
		return adminUserRecord{}, matched, err
	}
	return user, true, nil
}

func (s *wafEventStore) updateAdminUserIdentity(userID int64, username string, email string, now time.Time) (adminUserRecord, error) {
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
	if err := s.ensureAdminIdentityAvailable(userID, usernameNormalized, emailNormalized); err != nil {
		return adminUserRecord{}, err
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var emailValue any
	var emailNormalizedValue any
	if email != "" {
		emailValue = email
		emailNormalizedValue = emailNormalized
	}
	if _, err := s.exec(
		`UPDATE admin_users
		    SET username = ?, username_normalized = ?, email = ?, email_normalized = ?,
		        updated_at_unix = ?, updated_at = ?
		  WHERE user_id = ? AND disabled_at_unix IS NULL`,
		username,
		usernameNormalized,
		emailValue,
		emailNormalizedValue,
		now.Unix(),
		now.Format(time.RFC3339Nano),
		userID,
	); err != nil {
		return adminUserRecord{}, err
	}
	user, ok, err := s.loadAdminUserByID(userID)
	if err != nil {
		return adminUserRecord{}, err
	}
	if !ok || user.Disabled {
		return adminUserRecord{}, errAdminAuthInvalidCredential
	}
	return user, nil
}

func (s *wafEventStore) ensureAdminIdentityAvailable(userID int64, usernameNormalized string, emailNormalized string) error {
	var existingID int64
	if err := s.queryRow(
		`SELECT user_id FROM admin_users WHERE username_normalized = ? AND user_id <> ? LIMIT 1`,
		usernameNormalized,
		userID,
	).Scan(&existingID); err == nil {
		return errAdminAuthDuplicateName
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if emailNormalized == "" {
		return nil
	}
	if err := s.queryRow(
		`SELECT user_id FROM admin_users WHERE email_normalized = ? AND user_id <> ? LIMIT 1`,
		emailNormalized,
		userID,
	).Scan(&existingID); err == nil {
		return errAdminAuthDuplicateEmail
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func (s *wafEventStore) changeAdminUserPassword(userID int64, passwordHash string, now time.Time) error {
	if s == nil || s.db == nil {
		return errAdminAuthStoreUnavailable
	}
	if !validAdminPasswordHash(passwordHash) {
		return adminauth.ErrInvalidPasswordHash
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.exec(
		`UPDATE admin_users
		    SET password_hash = ?, password_algo = 'argon2id', must_change_password = 0,
		        session_version = session_version + 1,
		        updated_at_unix = ?, updated_at = ?
		  WHERE user_id = ? AND disabled_at_unix IS NULL`,
		passwordHash,
		now.Unix(),
		now.Format(time.RFC3339Nano),
		userID,
	)
	return err
}

func (s *wafEventStore) listAdminPersonalAccessTokens(userID int64, now time.Time) ([]adminAPITokenRecord, error) {
	if s == nil || s.db == nil {
		return nil, errAdminAuthStoreUnavailable
	}
	rows, err := s.query(
		`SELECT token_id, label, token_prefix, scopes_json,
		        COALESCE(expires_at_unix, 0), COALESCE(expires_at, ''),
		        COALESCE(revoked_at_unix, 0), COALESCE(revoked_at, ''),
		        COALESCE(last_used_at, ''), created_at
		   FROM admin_api_tokens
		  WHERE user_id = ?
		  ORDER BY created_at_unix DESC, token_id DESC
		  LIMIT ?`,
		userID,
		maxManagedAdminTokens,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tokens := make([]adminAPITokenRecord, 0)
	for rows.Next() {
		token, err := scanAdminAPITokenRecord(rows, now)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

func (s *wafEventStore) loadAdminPersonalAccessToken(userID int64, tokenID int64, now time.Time) (adminAPITokenRecord, bool, error) {
	if s == nil || s.db == nil {
		return adminAPITokenRecord{}, false, errAdminAuthStoreUnavailable
	}
	row := s.queryRow(
		`SELECT token_id, label, token_prefix, scopes_json,
		        COALESCE(expires_at_unix, 0), COALESCE(expires_at, ''),
		        COALESCE(revoked_at_unix, 0), COALESCE(revoked_at, ''),
		        COALESCE(last_used_at, ''), created_at
		   FROM admin_api_tokens
		  WHERE user_id = ? AND token_id = ?`,
		userID,
		tokenID,
	)
	token, err := scanAdminAPITokenRecord(row, now)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminAPITokenRecord{}, false, nil
		}
		return adminAPITokenRecord{}, false, err
	}
	return token, true, nil
}

func (s *wafEventStore) revokeAdminPersonalAccessToken(userID int64, tokenID int64, now time.Time) (bool, error) {
	if s == nil || s.db == nil {
		return false, errAdminAuthStoreUnavailable
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.exec(
		`UPDATE admin_api_tokens
		    SET revoked_at_unix = ?, revoked_at = ?
		  WHERE user_id = ? AND token_id = ? AND revoked_at_unix IS NULL`,
		now.Unix(),
		now.Format(time.RFC3339Nano),
		userID,
		tokenID,
	)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return true, nil
	}
	return affected > 0, nil
}

type adminAPITokenScanner interface {
	Scan(dest ...any) error
}

func scanAdminAPITokenRecord(scanner adminAPITokenScanner, now time.Time) (adminAPITokenRecord, error) {
	var (
		token         adminAPITokenRecord
		scopesRaw     string
		expiresAtUnix int64
		expiresAt     string
		revokedAtUnix int64
		revokedAt     string
		lastUsedAt    string
	)
	if err := scanner.Scan(
		&token.TokenID,
		&token.Label,
		&token.Prefix,
		&scopesRaw,
		&expiresAtUnix,
		&expiresAt,
		&revokedAtUnix,
		&revokedAt,
		&lastUsedAt,
		&token.CreatedAt,
	); err != nil {
		return adminAPITokenRecord{}, err
	}
	scopes, err := parseAdminTokenScopes(scopesRaw)
	if err != nil {
		return adminAPITokenRecord{}, err
	}
	token.Scopes = scopes
	token.ExpiresAt = strings.TrimSpace(expiresAt)
	token.LastUsedAt = strings.TrimSpace(lastUsedAt)
	token.RevokedAt = strings.TrimSpace(revokedAt)
	token.Active = revokedAtUnix == 0 && (expiresAtUnix == 0 || now.Before(time.Unix(expiresAtUnix, 0).UTC()))
	return token, nil
}

type adminMFAVerifyRequest struct {
	ChallengeToken string `json:"challenge_token"`
	Code           string `json:"code"`
}

type adminMFASetupRequest struct {
	CurrentPassword string `json:"current_password"`
}

type adminMFAEnableRequest struct {
	SetupID string `json:"setup_id"`
	Code    string `json:"code"`
}

type adminMFAProtectedMutationRequest struct {
	CurrentPassword string `json:"current_password"`
	Code            string `json:"code"`
}

type adminMFAStatusResponse struct {
	Enabled                bool   `json:"enabled"`
	EnabledAt              string `json:"enabled_at,omitempty"`
	RecoveryCodesRemaining int    `json:"recovery_codes_remaining"`
}

type adminMFASetupResponse struct {
	SetupID    string `json:"setup_id"`
	Secret     string `json:"secret"`
	OtpauthURI string `json:"otpauth_uri"`
	ExpiresAt  string `json:"expires_at"`
}

type adminMFAEnableResponse struct {
	adminMFAStatusResponse
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

func PostAdminMFAVerifyHandler(c *gin.Context) {
	postAdminMFAVerify(c, adminauth.DefaultCookieNames())
}

func postAdminMFAVerify(c *gin.Context, cookieNames adminauth.CookieNames) {
	cookieNames = cookieNames.Normalized()
	var req adminMFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		clearAdminAuthCookiesWithNames(c, cookieNames)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mfa payload"})
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		clearAdminAuthCookiesWithNames(c, cookieNames)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	now := time.Now().UTC()
	principal, proofKind, ok, err := store.verifyAdminMFAChallenge(req.ChallengeToken, req.Code, now)
	if err != nil {
		clearAdminAuthCookiesWithNames(c, cookieNames)
		c.JSON(http.StatusForbidden, gin.H{"error": adminMFAErrorMessage(err)})
		return
	}
	if !ok {
		clearAdminAuthCookiesWithNames(c, cookieNames)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid mfa code"})
		return
	}
	sessionToken, csrfToken, expiresAt, sessionID, err := store.createAdminSession(principal, config.AdminSessionTTL, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue admin session"})
		return
	}
	principal.CredentialID = formatAdminCredentialID(sessionID)
	adminauth.SetCookiesWithNames(c.Writer, cookieNames, sessionToken, csrfToken, expiresAt, requestIsHTTPS(c))
	c.JSON(http.StatusOK, adminLoginSessionResponse(principal, expiresAt, cookieNames, c, gin.H{
		"mfa_verified": true,
		"mfa_method":   proofKind,
	}))
}

func GetAdminMFA(c *gin.Context) {
	principal, ok := currentAdminSessionPrincipal(c)
	if !ok {
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	status, err := store.loadAdminMFAStatus(principal.UserID, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load admin mfa status"})
		return
	}
	c.JSON(http.StatusOK, adminMFAStatusResponseForRecord(status))
}

func PostAdminMFASetup(c *gin.Context) {
	principal, ok := currentAdminSessionPrincipal(c)
	if !ok {
		return
	}
	var req adminMFASetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mfa setup payload"})
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	enabled, err := store.adminMFAEnabled(principal.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load admin mfa status"})
		return
	}
	if enabled {
		c.JSON(http.StatusConflict, gin.H{"error": "admin mfa is already enabled"})
		return
	}
	user, ok, err := store.verifyAdminCurrentPassword(principal.UserID, req.CurrentPassword)
	if err != nil {
		writeAdminCurrentPasswordCheckError(c, err)
		return
	}
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": errAdminAuthCurrentPassword.Error()})
		return
	}
	setup, err := store.createAdminMFASetup(user, time.Now().UTC())
	if err != nil {
		if errors.Is(err, errAdminMFAAlreadyEnabled) {
			c.JSON(http.StatusConflict, gin.H{"error": adminMFAErrorMessage(err)})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create mfa setup"})
		return
	}
	c.JSON(http.StatusCreated, adminMFASetupResponse{
		SetupID:    setup.SetupID,
		Secret:     setup.Secret,
		OtpauthURI: setup.OtpauthURI,
		ExpiresAt:  setup.ExpiresAt.Format(time.RFC3339),
	})
}

func PostAdminMFAEnable(c *gin.Context) {
	principal, ok := currentAdminSessionPrincipal(c)
	if !ok {
		return
	}
	var req adminMFAEnableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mfa enable payload"})
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	recoveryCodes, err := store.enableAdminMFAFromSetup(principal.UserID, req.SetupID, req.Code, time.Now().UTC())
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errAdminMFACodeInvalid) || errors.Is(err, adminauth.ErrInvalidTOTPCode) {
			status = http.StatusForbidden
		} else if errors.Is(err, errAdminMFAAlreadyEnabled) {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": adminMFAErrorMessage(err)})
		return
	}
	status, err := store.loadAdminMFAStatus(principal.UserID, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load admin mfa status"})
		return
	}
	resp := adminMFAEnableResponse{
		adminMFAStatusResponse: adminMFAStatusResponseForRecord(status),
		RecoveryCodes:          recoveryCodes,
	}
	c.JSON(http.StatusOK, resp)
}

func PostAdminMFARecoveryCodesRegenerate(c *gin.Context) {
	principal, ok := currentAdminSessionPrincipal(c)
	if !ok {
		return
	}
	var req adminMFAProtectedMutationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mfa recovery code payload"})
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	if !verifyAdminMFASensitiveMutation(c, store, principal.UserID, req.CurrentPassword, req.Code) {
		return
	}
	codes, err := store.regenerateAdminMFARecoveryCodes(principal.UserID, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to regenerate recovery codes"})
		return
	}
	status, err := store.loadAdminMFAStatus(principal.UserID, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load admin mfa status"})
		return
	}
	c.JSON(http.StatusOK, adminMFAEnableResponse{
		adminMFAStatusResponse: adminMFAStatusResponseForRecord(status),
		RecoveryCodes:          codes,
	})
}

func PostAdminMFADisable(c *gin.Context) {
	principal, ok := currentAdminSessionPrincipal(c)
	if !ok {
		return
	}
	var req adminMFAProtectedMutationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mfa disable payload"})
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "admin auth store is unavailable"})
		return
	}
	if !verifyAdminMFASensitiveMutation(c, store, principal.UserID, req.CurrentPassword, req.Code) {
		return
	}
	if err := store.disableAdminMFA(principal.UserID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable mfa"})
		return
	}
	c.JSON(http.StatusOK, adminMFAStatusResponse{Enabled: false})
}

func verifyAdminMFASensitiveMutation(c *gin.Context, store *wafEventStore, userID int64, currentPassword string, code string) bool {
	if _, ok, err := store.verifyAdminCurrentPassword(userID, currentPassword); err != nil {
		writeAdminCurrentPasswordCheckError(c, err)
		return false
	} else if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": errAdminAuthCurrentPassword.Error()})
		return false
	}
	if proofKind, ok, err := store.verifyAdminMFACode(userID, code, time.Now().UTC()); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": adminMFAErrorMessage(err)})
		return false
	} else if !ok || strings.TrimSpace(proofKind) == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "mfa code is invalid"})
		return false
	}
	return true
}

func adminMFAStatusResponseForRecord(status adminMFAStatusRecord) adminMFAStatusResponse {
	return adminMFAStatusResponse{
		Enabled:                status.Enabled,
		EnabledAt:              status.EnabledAt,
		RecoveryCodesRemaining: status.RecoveryCodesRemaining,
	}
}

const (
	adminMFAIssuer            = "Tukuyomi"
	adminMFASetupTTL          = 10 * time.Minute
	adminMFAChallengeTTL      = 5 * time.Minute
	adminMFARecoveryCodeCount = 10
)

var (
	errAdminMFAUnavailable      = errors.New("admin mfa is not configured")
	errAdminMFAAlreadyEnabled   = errors.New("admin mfa is already enabled")
	errAdminMFAChallengeInvalid = errors.New("invalid mfa challenge")
	errAdminMFASetupInvalid     = errors.New("invalid mfa setup")
	errAdminMFACodeInvalid      = errors.New("invalid mfa code")
)

type adminMFAStatusRecord struct {
	Enabled                bool
	EnabledAt              string
	RecoveryCodesRemaining int
}

type adminMFASetupRecord struct {
	SetupID    string
	Secret     string
	Issuer     string
	Account    string
	OtpauthURI string
	ExpiresAt  time.Time
}

type adminMFAChallengeRecord struct {
	ChallengeID int64
	User        adminUserRecord
	ExpiresAt   time.Time
}

func (s *wafEventStore) loadAdminMFAStatus(userID int64, now time.Time) (adminMFAStatusRecord, error) {
	if s == nil || s.db == nil {
		return adminMFAStatusRecord{}, errAdminAuthStoreUnavailable
	}
	var status adminMFAStatusRecord
	var enabledAt string
	row := s.queryRow(`SELECT enabled_at FROM admin_mfa_totp WHERE user_id = ?`, userID)
	if err := row.Scan(&enabledAt); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return adminMFAStatusRecord{}, err
		}
	} else {
		status.Enabled = true
		status.EnabledAt = enabledAt
	}
	var remaining int
	if err := s.queryRow(`SELECT COUNT(*) FROM admin_mfa_recovery_codes WHERE user_id = ? AND used_at_unix IS NULL`, userID).Scan(&remaining); err != nil {
		return adminMFAStatusRecord{}, err
	}
	status.RecoveryCodesRemaining = remaining
	_ = now
	return status, nil
}

func (s *wafEventStore) adminMFAEnabled(userID int64) (bool, error) {
	if s == nil || s.db == nil {
		return false, errAdminAuthStoreUnavailable
	}
	var exists int
	if err := s.queryRow(`SELECT 1 FROM admin_mfa_totp WHERE user_id = ?`, userID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return exists == 1, nil
}

func (s *wafEventStore) createAdminMFASetup(user adminUserRecord, now time.Time) (adminMFASetupRecord, error) {
	if s == nil || s.db == nil {
		return adminMFASetupRecord{}, errAdminAuthStoreUnavailable
	}
	if user.UserID <= 0 || user.Username == "" {
		return adminMFASetupRecord{}, errAdminAuthInvalidCredential
	}
	enabled, err := s.adminMFAEnabled(user.UserID)
	if err != nil {
		return adminMFASetupRecord{}, err
	}
	if enabled {
		return adminMFASetupRecord{}, errAdminMFAAlreadyEnabled
	}
	now = normalizedAdminMFATime(now)
	_, _ = s.exec(`DELETE FROM admin_mfa_setups WHERE user_id = ? OR expires_at_unix <= ?`, user.UserID, now.Unix())

	setupID, err := randomAdminOpaqueToken(32)
	if err != nil {
		return adminMFASetupRecord{}, err
	}
	secret, err := adminauth.GenerateTOTPSecret()
	if err != nil {
		return adminMFASetupRecord{}, err
	}
	account := user.Username
	if user.Email != "" {
		account = user.Email
	}
	uri, err := adminauth.TOTPAuthURI(adminMFAIssuer, account, secret)
	if err != nil {
		return adminMFASetupRecord{}, err
	}
	expiresAt := now.Add(adminMFASetupTTL).UTC()
	if _, err := s.exec(
		`INSERT INTO admin_mfa_setups (
			setup_id, user_id, secret_base32, issuer, account_name,
			expires_at_unix, expires_at, created_at_unix, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		setupID,
		user.UserID,
		secret,
		adminMFAIssuer,
		account,
		expiresAt.Unix(),
		expiresAt.Format(time.RFC3339Nano),
		now.Unix(),
		now.Format(time.RFC3339Nano),
	); err != nil {
		return adminMFASetupRecord{}, err
	}
	return adminMFASetupRecord{
		SetupID:    setupID,
		Secret:     secret,
		Issuer:     adminMFAIssuer,
		Account:    account,
		OtpauthURI: uri,
		ExpiresAt:  expiresAt,
	}, nil
}

func (s *wafEventStore) enableAdminMFAFromSetup(userID int64, setupID string, code string, now time.Time) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, errAdminAuthStoreUnavailable
	}
	setupID = strings.TrimSpace(setupID)
	if setupID == "" {
		return nil, errAdminMFASetupInvalid
	}
	enabled, err := s.adminMFAEnabled(userID)
	if err != nil {
		return nil, err
	}
	if enabled {
		return nil, errAdminMFAAlreadyEnabled
	}
	now = normalizedAdminMFATime(now)
	setup, err := s.loadAdminMFASetup(userID, setupID, now)
	if err != nil {
		return nil, err
	}
	if _, ok, err := adminauth.VerifyTOTP(setup.Secret, code, now, nil); err != nil {
		return nil, err
	} else if !ok {
		return nil, errAdminMFACodeInvalid
	}
	recoveryCodes, err := adminauth.GenerateRecoveryCodes(adminMFARecoveryCodeCount)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := s.txExec(tx, s.upsertAdminMFATOTPStatement(), userID, setup.Secret, setup.Issuer, setup.Account, now.Unix(), now.Format(time.RFC3339Nano), now.Unix(), now.Format(time.RFC3339Nano), now.Unix(), now.Format(time.RFC3339Nano)); err != nil {
		return nil, err
	}
	if _, err := s.txExec(tx, `DELETE FROM admin_mfa_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	for _, recoveryCode := range recoveryCodes {
		hash, err := adminauth.HashRecoveryCode(recoveryCode, config.AdminSessionSecret)
		if err != nil {
			return nil, err
		}
		if _, err := s.txExec(tx,
			`INSERT INTO admin_mfa_recovery_codes (
				user_id, code_hash, created_at_unix, created_at
			) VALUES (?, ?, ?, ?)`,
			userID,
			hash,
			now.Unix(),
			now.Format(time.RFC3339Nano),
		); err != nil {
			return nil, err
		}
	}
	if _, err := s.txExec(tx, `DELETE FROM admin_mfa_setups WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return recoveryCodes, nil
}

func (s *wafEventStore) createAdminMFAChallenge(userID int64, ip string, userAgent string, now time.Time) (string, time.Time, error) {
	if s == nil || s.db == nil {
		return "", time.Time{}, errAdminAuthStoreUnavailable
	}
	now = normalizedAdminMFATime(now)
	_, _ = s.exec(`DELETE FROM admin_mfa_challenges WHERE expires_at_unix <= ? OR (user_id = ? AND consumed_at_unix IS NOT NULL)`, now.Unix(), userID)
	token, err := randomAdminOpaqueToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := now.Add(adminMFAChallengeTTL).UTC()
	if _, err := s.exec(
		`INSERT INTO admin_mfa_challenges (
			user_id, challenge_token_hash, expires_at_unix, expires_at,
			created_at_unix, created_at, ip, user_agent
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID,
		adminAuthSecretHash(token, config.AdminSessionSecret),
		expiresAt.Unix(),
		expiresAt.Format(time.RFC3339Nano),
		now.Unix(),
		now.Format(time.RFC3339Nano),
		strings.TrimSpace(ip),
		strings.TrimSpace(userAgent),
	); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (s *wafEventStore) verifyAdminMFAChallenge(token string, code string, now time.Time) (adminauth.Principal, string, bool, error) {
	if s == nil || s.db == nil {
		return adminauth.Principal{}, "", false, errAdminAuthStoreUnavailable
	}
	now = normalizedAdminMFATime(now)
	challenge, ok, err := s.loadAdminMFAChallenge(token, now)
	if err != nil || !ok {
		return adminauth.Principal{}, "", ok, err
	}
	proofKind, ok, err := s.verifyAdminMFACode(challenge.User.UserID, code, now)
	if err != nil || !ok {
		return adminauth.Principal{}, "", ok, err
	}
	if err := s.consumeAdminMFAChallenge(challenge.ChallengeID, now); err != nil {
		return adminauth.Principal{}, "", false, err
	}
	return adminPrincipalForUser(challenge.User, adminauth.AuthKindSession, ""), proofKind, true, nil
}

func (s *wafEventStore) regenerateAdminMFARecoveryCodes(userID int64, now time.Time) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, errAdminAuthStoreUnavailable
	}
	enabled, err := s.adminMFAEnabled(userID)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, errAdminMFAUnavailable
	}
	now = normalizedAdminMFATime(now)
	recoveryCodes, err := adminauth.GenerateRecoveryCodes(adminMFARecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := s.txExec(tx, `DELETE FROM admin_mfa_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	for _, recoveryCode := range recoveryCodes {
		hash, err := adminauth.HashRecoveryCode(recoveryCode, config.AdminSessionSecret)
		if err != nil {
			return nil, err
		}
		if _, err := s.txExec(tx, `INSERT INTO admin_mfa_recovery_codes (user_id, code_hash, created_at_unix, created_at) VALUES (?, ?, ?, ?)`, userID, hash, now.Unix(), now.Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return recoveryCodes, nil
}

func (s *wafEventStore) disableAdminMFA(userID int64) error {
	if s == nil || s.db == nil {
		return errAdminAuthStoreUnavailable
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	for _, stmt := range []string{
		`DELETE FROM admin_mfa_recovery_codes WHERE user_id = ?`,
		`DELETE FROM admin_mfa_setups WHERE user_id = ?`,
		`DELETE FROM admin_mfa_challenges WHERE user_id = ?`,
		`DELETE FROM admin_mfa_totp WHERE user_id = ?`,
	} {
		if _, err := s.txExec(tx, stmt, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *wafEventStore) loadAdminMFASetup(userID int64, setupID string, now time.Time) (adminMFASetupRecord, error) {
	row := s.queryRow(
		`SELECT setup_id, secret_base32, issuer, account_name, expires_at_unix
		   FROM admin_mfa_setups
		  WHERE user_id = ? AND setup_id = ?`,
		userID,
		setupID,
	)
	var rec adminMFASetupRecord
	var expiresAtUnix int64
	if err := row.Scan(&rec.SetupID, &rec.Secret, &rec.Issuer, &rec.Account, &expiresAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminMFASetupRecord{}, errAdminMFASetupInvalid
		}
		return adminMFASetupRecord{}, err
	}
	rec.ExpiresAt = time.Unix(expiresAtUnix, 0).UTC()
	if !now.Before(rec.ExpiresAt) {
		return adminMFASetupRecord{}, errAdminMFASetupInvalid
	}
	uri, err := adminauth.TOTPAuthURI(rec.Issuer, rec.Account, rec.Secret)
	if err != nil {
		return adminMFASetupRecord{}, err
	}
	rec.OtpauthURI = uri
	return rec, nil
}

func (s *wafEventStore) loadAdminMFAChallenge(token string, now time.Time) (adminMFAChallengeRecord, bool, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > maxAdminSessionTokenBytes {
		return adminMFAChallengeRecord{}, false, nil
	}
	row := s.queryRow(
		`SELECT c.challenge_id, c.expires_at_unix,
		        u.user_id, u.username, COALESCE(u.email, ''), u.role,
		        u.must_change_password, u.session_version, COALESCE(u.disabled_at_unix, 0)
		   FROM admin_mfa_challenges c
		   JOIN admin_users u ON u.user_id = c.user_id
		  WHERE c.challenge_token_hash = ? AND c.consumed_at_unix IS NULL`,
		adminAuthSecretHash(token, config.AdminSessionSecret),
	)
	var (
		rec            adminMFAChallengeRecord
		expiresAtUnix  int64
		mustChange     any
		disabledAtUnix int64
	)
	if err := row.Scan(&rec.ChallengeID, &expiresAtUnix, &rec.User.UserID, &rec.User.Username, &rec.User.Email, &rec.User.Role, &mustChange, &rec.User.SessionVersion, &disabledAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminMFAChallengeRecord{}, false, nil
		}
		return adminMFAChallengeRecord{}, false, err
	}
	rec.User.MustChangePassword = dbBoolValue(mustChange)
	rec.ExpiresAt = time.Unix(expiresAtUnix, 0).UTC()
	if disabledAtUnix > 0 || !now.Before(rec.ExpiresAt) {
		return adminMFAChallengeRecord{}, false, nil
	}
	return rec, true, nil
}

func (s *wafEventStore) verifyAdminMFACode(userID int64, code string, now time.Time) (string, bool, error) {
	if proofKind, ok, err := s.verifyAdminMFATOTP(userID, code, now); err != nil || ok {
		return proofKind, ok, err
	}
	if ok, err := s.consumeAdminMFARecoveryCode(userID, code, now); err != nil || ok {
		return "recovery_code", ok, err
	}
	return "", false, nil
}

func (s *wafEventStore) verifyAdminMFATOTP(userID int64, code string, now time.Time) (string, bool, error) {
	row := s.queryRow(`SELECT secret_base32, COALESCE(last_used_counter, -1) FROM admin_mfa_totp WHERE user_id = ?`, userID)
	var secret string
	var lastUsed int64
	if err := row.Scan(&secret, &lastUsed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	var lastUsedPtr *int64
	if lastUsed >= 0 {
		lastUsedPtr = &lastUsed
	}
	counter, ok, err := adminauth.VerifyTOTP(secret, code, now, lastUsedPtr)
	if errors.Is(err, adminauth.ErrInvalidTOTPCode) {
		return "", false, nil
	}
	if err != nil || !ok {
		return "", ok, err
	}
	res, err := s.exec(
		`UPDATE admin_mfa_totp
		    SET last_used_counter = ?, updated_at_unix = ?, updated_at = ?
		  WHERE user_id = ? AND (last_used_counter IS NULL OR last_used_counter < ?)`,
		counter,
		now.Unix(),
		now.Format(time.RFC3339Nano),
		userID,
		counter,
	)
	if err != nil {
		return "", false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return "", false, err
	}
	return "totp", affected == 1, nil
}

func (s *wafEventStore) consumeAdminMFARecoveryCode(userID int64, code string, now time.Time) (bool, error) {
	hash, err := adminauth.HashRecoveryCode(code, config.AdminSessionSecret)
	if err != nil {
		if errors.Is(err, adminauth.ErrInvalidRecoveryCode) {
			return false, nil
		}
		return false, err
	}
	res, err := s.exec(
		`UPDATE admin_mfa_recovery_codes
		    SET used_at_unix = ?, used_at = ?
		  WHERE user_id = ? AND code_hash = ? AND used_at_unix IS NULL`,
		now.Unix(),
		now.Format(time.RFC3339Nano),
		userID,
		hash,
	)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (s *wafEventStore) consumeAdminMFAChallenge(challengeID int64, now time.Time) error {
	res, err := s.exec(
		`UPDATE admin_mfa_challenges
		    SET consumed_at_unix = ?, consumed_at = ?
		  WHERE challenge_id = ? AND consumed_at_unix IS NULL`,
		now.Unix(),
		now.Format(time.RFC3339Nano),
		challengeID,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return errAdminMFAChallengeInvalid
	}
	return nil
}

func (s *wafEventStore) upsertAdminMFATOTPStatement() string {
	switch s.dbDriver {
	case logStatsDBDriverMySQL:
		return `INSERT INTO admin_mfa_totp (
			user_id, secret_base32, issuer, account_name,
			enabled_at_unix, enabled_at, created_at_unix, created_at, updated_at_unix, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			secret_base32 = VALUES(secret_base32),
			issuer = VALUES(issuer),
			account_name = VALUES(account_name),
			last_used_counter = NULL,
			enabled_at_unix = VALUES(enabled_at_unix),
			enabled_at = VALUES(enabled_at),
			updated_at_unix = VALUES(updated_at_unix),
			updated_at = VALUES(updated_at)`
	case logStatsDBDriverPostgres:
		return `INSERT INTO admin_mfa_totp (
			user_id, secret_base32, issuer, account_name,
			enabled_at_unix, enabled_at, created_at_unix, created_at, updated_at_unix, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET
			secret_base32 = EXCLUDED.secret_base32,
			issuer = EXCLUDED.issuer,
			account_name = EXCLUDED.account_name,
			last_used_counter = NULL,
			enabled_at_unix = EXCLUDED.enabled_at_unix,
			enabled_at = EXCLUDED.enabled_at,
			updated_at_unix = EXCLUDED.updated_at_unix,
			updated_at = EXCLUDED.updated_at`
	default:
		return `INSERT INTO admin_mfa_totp (
			user_id, secret_base32, issuer, account_name,
			enabled_at_unix, enabled_at, created_at_unix, created_at, updated_at_unix, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			secret_base32 = excluded.secret_base32,
			issuer = excluded.issuer,
			account_name = excluded.account_name,
			last_used_counter = NULL,
			enabled_at_unix = excluded.enabled_at_unix,
			enabled_at = excluded.enabled_at,
			updated_at_unix = excluded.updated_at_unix,
			updated_at = excluded.updated_at`
	}
}

func normalizedAdminMFATime(now time.Time) time.Time {
	now = now.UTC()
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now
}

func adminMFAErrorMessage(err error) string {
	switch {
	case errors.Is(err, errAdminMFAUnavailable):
		return "admin mfa is not enabled"
	case errors.Is(err, errAdminMFAAlreadyEnabled):
		return "admin mfa is already enabled"
	case errors.Is(err, errAdminMFAChallengeInvalid):
		return "mfa challenge is invalid or expired"
	case errors.Is(err, errAdminMFASetupInvalid):
		return "mfa setup is invalid or expired"
	case errors.Is(err, errAdminMFACodeInvalid), errors.Is(err, adminauth.ErrInvalidTOTPCode), errors.Is(err, adminauth.ErrInvalidRecoveryCode):
		return "mfa code is invalid"
	default:
		return fmt.Sprintf("%v", err)
	}
}
