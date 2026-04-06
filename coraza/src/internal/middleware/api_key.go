package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
)

func APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.APIAuthDisable {
			c.Next()
			return
		}
		if config.APIKeyPrimary == "" && config.APIKeySecondary == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		key := strings.TrimSpace(c.GetHeader("X-API-Key"))
		if HasValidAPIKey(key) {
			c.Next()
			return
		}

		session, ok, err := sessionFromRequest(c)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if ok {
			if err := adminauth.ValidateCSRF(c.Request, session); err != nil {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			c.Next()
			return
		}

		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

func HasValidAPIKey(key string) bool {
	return secureKeyMatch(strings.TrimSpace(key), config.APIKeyPrimary) || secureKeyMatch(strings.TrimSpace(key), config.APIKeySecondary)
}

func sessionFromRequest(c *gin.Context) (adminauth.Session, bool, error) {
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

func secureKeyMatch(got, expected string) bool {
	if got == "" || expected == "" {
		return false
	}
	if len(got) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}
