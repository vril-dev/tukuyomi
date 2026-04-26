package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/adminguard"
	"tukuyomi/internal/config"
)

type adminLoginRequest struct {
	Username   string `json:"username"`
	Email      string `json:"email"`
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

func RegisterAdminAuthRoutes(r *gin.Engine) {
	if r == nil {
		return
	}

	api := r.Group(
		config.APIBasePath,
		AdminAccessMiddleware("api"),
		AdminRateLimitMiddleware(),
	)
	api.GET("/auth/session", GetAdminSessionHandler)
	api.POST("/auth/login", PostAdminLoginHandler)
	api.POST("/auth/logout", PostAdminLogoutHandler)
}

func GetAdminSessionHandler(c *gin.Context) {
	if config.APIAuthDisable {
		c.JSON(http.StatusOK, gin.H{
			"authenticated":    true,
			"mode":             "disabled",
			"csrf_header_name": adminauth.CSRFHeaderName,
		})
		return
	}

	if store := getLogsStatsStore(); store != nil {
		if token, presented := adminSessionTokenFromRequest(c.Request); presented {
			dbSession, dbOK, dbErr := store.loadAdminSession(token, time.Now().UTC())
			if dbErr != nil {
				clearAdminAuthCookies(c)
				c.JSON(http.StatusOK, gin.H{
					"authenticated":    false,
					"mode":             "none",
					"csrf_header_name": adminauth.CSRFHeaderName,
				})
				return
			}
			if dbOK {
				csrfToken, err := store.ensureAdminSessionCSRFCookie(c, dbSession, time.Now().UTC())
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh admin session"})
					return
				}
				c.JSON(http.StatusOK, adminSessionResponse(dbSession, csrfToken, c))
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated":    false,
		"mode":             "none",
		"csrf_header_name": adminauth.CSRFHeaderName,
	})
}

func PostAdminLoginHandler(c *gin.Context) {
	if config.APIAuthDisable {
		c.JSON(http.StatusOK, gin.H{
			"ok":               true,
			"authenticated":    true,
			"mode":             "disabled",
			"csrf_header_name": adminauth.CSRFHeaderName,
		})
		return
	}

	var req adminLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid login payload"})
		return
	}

	if strings.TrimSpace(req.Password) == "" || adminLoginIdentifier(req) == "" {
		clearAdminAuthCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	postAdminPasswordLogin(c, req)
}

func PostAdminLogoutHandler(c *gin.Context) {
	if !config.APIAuthDisable {
		if store := getLogsStatsStore(); store != nil {
			if token, presented := adminSessionTokenFromRequest(c.Request); presented {
				session, ok, err := store.authenticateAdminSessionRequest(c.Request, token, time.Now().UTC())
				if err != nil {
					c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
					return
				}
				if ok {
					if err := store.revokeAdminSession(token, time.Now().UTC()); err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke admin session"})
						return
					}
					_ = session
					clearAdminAuthCookies(c)
					c.JSON(http.StatusOK, gin.H{"ok": true})
					return
				}
			}
		}
	}
	clearAdminAuthCookies(c)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func postAdminPasswordLogin(c *gin.Context, req adminLoginRequest) {
	identifier := adminLoginIdentifier(req)
	if identifier == "" || strings.TrimSpace(req.Password) == "" {
		clearAdminAuthCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		clearAdminAuthCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	now := time.Now().UTC()
	principal, ok, err := store.authenticateAdminPassword(identifier, req.Password, now)
	if err != nil {
		clearAdminAuthCookies(c)
		if errors.Is(err, errAdminAuthDisabledUser) || errors.Is(err, adminauth.ErrInvalidPasswordHash) || errors.Is(err, adminauth.ErrUnsupportedPasswordHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to authenticate admin user"})
		return
	}
	if !ok {
		clearAdminAuthCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	sessionToken, csrfToken, expiresAt, sessionID, err := store.createAdminSession(principal, config.AdminSessionTTL, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue admin session"})
		return
	}
	principal.CredentialID = strconv.FormatInt(sessionID, 10)
	adminauth.SetCookies(c.Writer, sessionToken, csrfToken, expiresAt, requestIsHTTPS(c))
	c.JSON(http.StatusOK, gin.H{
		"ok":                   true,
		"authenticated":        true,
		"mode":                 "session",
		"expires_at":           expiresAt.Format(time.RFC3339),
		"csrf_cookie_name":     adminauth.CSRFCookieName,
		"csrf_header_name":     adminauth.CSRFHeaderName,
		"must_change_password": principal.MustChangePassword,
		"user": gin.H{
			"user_id":              principal.UserID,
			"username":             principal.Username,
			"role":                 principal.Role,
			"must_change_password": principal.MustChangePassword,
		},
	})
}

func adminLoginIdentifier(req adminLoginRequest) string {
	for _, value := range []string{req.Identifier, req.Username, req.Email} {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func adminSessionResponse(session adminSessionRecord, csrfToken string, c *gin.Context) gin.H {
	resp := gin.H{
		"authenticated":        true,
		"mode":                 "session",
		"expires_at":           session.ExpiresAt.Format(time.RFC3339),
		"csrf_cookie_name":     adminauth.CSRFCookieName,
		"csrf_header_name":     adminauth.CSRFHeaderName,
		"session_cookie":       adminauth.SessionCookieName,
		"session_ttl_secs":     int(time.Until(session.ExpiresAt).Seconds()),
		"same_origin_only":     true,
		"cookie_secure_now":    requestIsHTTPS(c),
		"must_change_password": session.Principal.MustChangePassword,
		"user": gin.H{
			"user_id":              session.Principal.UserID,
			"username":             session.Principal.Username,
			"role":                 session.Principal.Role,
			"must_change_password": session.Principal.MustChangePassword,
		},
	}
	if csrfToken != "" {
		resp["csrf_token_present"] = true
	}
	return resp
}

func clearAdminAuthCookies(c *gin.Context) {
	if c == nil {
		return
	}
	adminauth.ClearCookies(c.Writer, requestIsHTTPS(c))
}

func requestIsHTTPS(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	if c.Request.TLS != nil {
		return true
	}
	if !trustedAdminForwardedHeaders(c.Request) {
		return false
	}

	if proto := normalizeForwardedProto(c.GetHeader("X-Forwarded-Proto")); proto == "https" {
		return true
	}
	if proto := normalizeForwardedProto(c.GetHeader("Forwarded")); proto == "https" {
		return true
	}
	return false
}

func trustedAdminForwardedHeaders(r *http.Request) bool {
	return adminguard.TrustedForwardedHeaders(r)
}

func normalizeForwardedProto(raw string) string {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "=") {
			for _, token := range strings.Split(part, ";") {
				key, value, ok := strings.Cut(strings.TrimSpace(token), "=")
				if !ok {
					continue
				}
				if strings.EqualFold(strings.TrimSpace(key), "proto") {
					return strings.ToLower(strings.Trim(strings.TrimSpace(value), `"`))
				}
			}
			continue
		}
		return strings.ToLower(part)
	}
	return ""
}
