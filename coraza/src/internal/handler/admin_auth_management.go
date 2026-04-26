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
