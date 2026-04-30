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

const adminAuthCookieNamesContextKey = "tukuyomi.admin_auth_cookie_names"

func RegisterAdminAuthRoutes(r *gin.Engine) {
	RegisterAdminAuthRoutesAt(r, config.APIBasePath)
}

func RegisterAdminAuthRoutesAt(r *gin.Engine, apiBasePath string) {
	RegisterAdminAuthRoutesAtWithCookieNames(r, apiBasePath, adminauth.DefaultCookieNames())
}

func RegisterAdminAuthRoutesAtWithCookieNames(r *gin.Engine, apiBasePath string, cookieNames adminauth.CookieNames) {
	if r == nil {
		return
	}
	cookieNames = cookieNames.Normalized()

	api := r.Group(
		normalizeAdminAuthAPIBasePath(apiBasePath),
		AdminAccessMiddleware("api"),
		AdminRateLimitMiddleware(),
		AdminAuthCookieNamesMiddleware(cookieNames),
	)
	api.GET("/auth/session", func(c *gin.Context) {
		getAdminSession(c, cookieNames)
	})
	api.POST("/auth/login", func(c *gin.Context) {
		postAdminLogin(c, cookieNames)
	})
	api.POST("/auth/logout", func(c *gin.Context) {
		postAdminLogout(c, cookieNames)
	})
}

func AdminAuthCookieNamesMiddleware(cookieNames adminauth.CookieNames) gin.HandlerFunc {
	cookieNames = cookieNames.Normalized()
	return func(c *gin.Context) {
		c.Set(adminAuthCookieNamesContextKey, cookieNames)
		c.Next()
	}
}

func normalizeAdminAuthAPIBasePath(apiBasePath string) string {
	apiBasePath = strings.TrimSpace(apiBasePath)
	if apiBasePath == "" {
		apiBasePath = config.APIBasePath
	}
	if apiBasePath == "" {
		return "/tukuyomi-api"
	}
	if !strings.HasPrefix(apiBasePath, "/") {
		apiBasePath = "/" + apiBasePath
	}
	apiBasePath = strings.TrimRight(apiBasePath, "/")
	if apiBasePath == "" {
		return "/tukuyomi-api"
	}
	return apiBasePath
}

func GetAdminSessionHandler(c *gin.Context) {
	getAdminSession(c, adminauth.DefaultCookieNames())
}

func getAdminSession(c *gin.Context, cookieNames adminauth.CookieNames) {
	cookieNames = cookieNames.Normalized()
	if config.APIAuthDisable {
		c.JSON(http.StatusOK, gin.H{
			"authenticated":    true,
			"mode":             "disabled",
			"csrf_cookie_name": cookieNames.CSRF,
			"csrf_header_name": adminauth.CSRFHeaderName,
		})
		return
	}

	if store := getLogsStatsStore(); store != nil {
		if token, presented := adminSessionTokenFromRequestWithCookieNames(c.Request, cookieNames); presented {
			dbSession, dbOK, dbErr := store.loadAdminSession(token, time.Now().UTC())
			if dbErr != nil {
				clearAdminAuthCookiesWithNames(c, cookieNames)
				c.JSON(http.StatusOK, gin.H{
					"authenticated":    false,
					"mode":             "none",
					"csrf_cookie_name": cookieNames.CSRF,
					"csrf_header_name": adminauth.CSRFHeaderName,
				})
				return
			}
			if dbOK {
				csrfToken, err := store.ensureAdminSessionCSRFCookieWithNames(c, dbSession, time.Now().UTC(), cookieNames)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh admin session"})
					return
				}
				c.JSON(http.StatusOK, adminSessionResponseWithCookieNames(dbSession, csrfToken, c, cookieNames))
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated":    false,
		"mode":             "none",
		"csrf_cookie_name": cookieNames.CSRF,
		"csrf_header_name": adminauth.CSRFHeaderName,
	})
}

func PostAdminLoginHandler(c *gin.Context) {
	postAdminLogin(c, adminauth.DefaultCookieNames())
}

func postAdminLogin(c *gin.Context, cookieNames adminauth.CookieNames) {
	cookieNames = cookieNames.Normalized()
	if config.APIAuthDisable {
		c.JSON(http.StatusOK, gin.H{
			"ok":               true,
			"authenticated":    true,
			"mode":             "disabled",
			"csrf_cookie_name": cookieNames.CSRF,
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
		clearAdminAuthCookiesWithNames(c, cookieNames)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	postAdminPasswordLoginWithCookieNames(c, req, cookieNames)
}

func PostAdminLogoutHandler(c *gin.Context) {
	postAdminLogout(c, adminauth.DefaultCookieNames())
}

func postAdminLogout(c *gin.Context, cookieNames adminauth.CookieNames) {
	cookieNames = cookieNames.Normalized()
	if !config.APIAuthDisable {
		if store := getLogsStatsStore(); store != nil {
			if token, presented := adminSessionTokenFromRequestWithCookieNames(c.Request, cookieNames); presented {
				session, ok, err := store.authenticateAdminSessionRequestWithCookieNames(c.Request, token, time.Now().UTC(), cookieNames)
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
					clearAdminAuthCookiesWithNames(c, cookieNames)
					c.JSON(http.StatusOK, gin.H{"ok": true})
					return
				}
			}
		}
	}
	clearAdminAuthCookiesWithNames(c, cookieNames)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func postAdminPasswordLogin(c *gin.Context, req adminLoginRequest) {
	postAdminPasswordLoginWithCookieNames(c, req, adminauth.DefaultCookieNames())
}

func postAdminPasswordLoginWithCookieNames(c *gin.Context, req adminLoginRequest, cookieNames adminauth.CookieNames) {
	cookieNames = cookieNames.Normalized()
	identifier := adminLoginIdentifier(req)
	if identifier == "" || strings.TrimSpace(req.Password) == "" {
		clearAdminAuthCookiesWithNames(c, cookieNames)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		clearAdminAuthCookiesWithNames(c, cookieNames)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	now := time.Now().UTC()
	principal, ok, err := store.authenticateAdminPassword(identifier, req.Password, now)
	if err != nil {
		clearAdminAuthCookiesWithNames(c, cookieNames)
		if errors.Is(err, errAdminAuthDisabledUser) || errors.Is(err, adminauth.ErrInvalidPasswordHash) || errors.Is(err, adminauth.ErrUnsupportedPasswordHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to authenticate admin user"})
		return
	}
	if !ok {
		clearAdminAuthCookiesWithNames(c, cookieNames)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	sessionToken, csrfToken, expiresAt, sessionID, err := store.createAdminSession(principal, config.AdminSessionTTL, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue admin session"})
		return
	}
	principal.CredentialID = strconv.FormatInt(sessionID, 10)
	adminauth.SetCookiesWithNames(c.Writer, cookieNames, sessionToken, csrfToken, expiresAt, requestIsHTTPS(c))
	c.JSON(http.StatusOK, gin.H{
		"ok":                   true,
		"authenticated":        true,
		"mode":                 "session",
		"expires_at":           expiresAt.Format(time.RFC3339),
		"csrf_cookie_name":     cookieNames.CSRF,
		"csrf_header_name":     adminauth.CSRFHeaderName,
		"session_cookie":       cookieNames.Session,
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
	return adminSessionResponseWithCookieNames(session, csrfToken, c, adminauth.DefaultCookieNames())
}

func adminSessionResponseWithCookieNames(session adminSessionRecord, csrfToken string, c *gin.Context, cookieNames adminauth.CookieNames) gin.H {
	cookieNames = cookieNames.Normalized()
	resp := gin.H{
		"authenticated":        true,
		"mode":                 "session",
		"expires_at":           session.ExpiresAt.Format(time.RFC3339),
		"csrf_cookie_name":     cookieNames.CSRF,
		"csrf_header_name":     adminauth.CSRFHeaderName,
		"session_cookie":       cookieNames.Session,
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
	clearAdminAuthCookiesWithNames(c, currentAdminAuthCookieNames(c))
}

func clearAdminAuthCookiesWithNames(c *gin.Context, cookieNames adminauth.CookieNames) {
	if c == nil {
		return
	}
	adminauth.ClearCookiesWithNames(c.Writer, cookieNames, requestIsHTTPS(c))
}

func currentAdminAuthCookieNames(c *gin.Context) adminauth.CookieNames {
	if c == nil {
		return adminauth.DefaultCookieNames()
	}
	value, ok := c.Get(adminAuthCookieNamesContextKey)
	if !ok {
		return adminauth.DefaultCookieNames()
	}
	cookieNames, ok := value.(adminauth.CookieNames)
	if !ok {
		return adminauth.DefaultCookieNames()
	}
	return cookieNames.Normalized()
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
