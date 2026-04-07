package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
	"tukuyomi/internal/middleware"
)

type adminLoginRequest struct {
	APIKey string `json:"api_key"`
}

func RegisterAdminAuthRoutes(r *gin.Engine) {
	if r == nil {
		return
	}

	api := r.Group(config.APIBasePath, middleware.AdminAccess(middleware.AdminEndpointAPI))
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

	session, ok, err := readAdminSession(c)
	if err != nil {
		clearAdminAuthCookies(c)
		c.JSON(http.StatusOK, gin.H{
			"authenticated":    false,
			"mode":             "none",
			"csrf_header_name": adminauth.CSRFHeaderName,
		})
		return
	}
	if !ok {
		c.JSON(http.StatusOK, gin.H{
			"authenticated":    false,
			"mode":             "none",
			"csrf_header_name": adminauth.CSRFHeaderName,
		})
		return
	}

	ensureCSRFCookie(c, session)
	c.JSON(http.StatusOK, gin.H{
		"authenticated":     true,
		"mode":              "session",
		"expires_at":        session.ExpiresAt.Format(time.RFC3339),
		"csrf_cookie_name":  adminauth.CSRFCookieName,
		"csrf_header_name":  adminauth.CSRFHeaderName,
		"session_cookie":    adminauth.SessionCookieName,
		"session_ttl_secs":  int(time.Until(session.ExpiresAt).Seconds()),
		"same_origin_only":  true,
		"cookie_secure_now": requestIsHTTPS(c),
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

	if !middleware.HasValidAPIKey(req.APIKey) {
		clearAdminAuthCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
		return
	}

	now := time.Now().UTC()
	sessionToken, csrfToken, expiresAt, err := adminauth.Issue(config.AdminSessionSecret, config.AdminSessionTTL, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue admin session"})
		return
	}

	adminauth.SetCookies(c.Writer, sessionToken, csrfToken, expiresAt, requestIsHTTPS(c))
	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"authenticated":    true,
		"mode":             "session",
		"expires_at":       expiresAt.Format(time.RFC3339),
		"csrf_cookie_name": adminauth.CSRFCookieName,
		"csrf_header_name": adminauth.CSRFHeaderName,
	})
}

func PostAdminLogoutHandler(c *gin.Context) {
	if !config.APIAuthDisable {
		if session, ok, err := readAdminSession(c); err == nil && ok {
			if err := adminauth.ValidateCSRF(c.Request, session); err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
		}
	}
	clearAdminAuthCookies(c)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func readAdminSession(c *gin.Context) (adminauth.Session, bool, error) {
	if c == nil || c.Request == nil {
		return adminauth.Session{}, false, nil
	}

	cookie, err := c.Request.Cookie(adminauth.SessionCookieName)
	if err != nil || cookie == nil || strings.TrimSpace(cookie.Value) == "" {
		return adminauth.Session{}, false, nil
	}

	session, err := adminauth.Validate(config.AdminSessionSecret, cookie.Value, time.Now().UTC())
	if err != nil {
		return adminauth.Session{}, false, err
	}
	return session, true, nil
}

func ensureCSRFCookie(c *gin.Context, session adminauth.Session) {
	if c == nil || c.Request == nil {
		return
	}

	current, err := c.Request.Cookie(adminauth.CSRFCookieName)
	if err == nil && current != nil && strings.TrimSpace(current.Value) == session.CSRFToken {
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     adminauth.CSRFCookieName,
		Value:    session.CSRFToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   requestIsHTTPS(c),
		SameSite: http.SameSiteLaxMode,
		Expires:  session.ExpiresAt.UTC(),
		MaxAge:   int(time.Until(session.ExpiresAt.UTC()).Seconds()),
	})
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
	if !trustedForwardedHeaders(c) {
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
