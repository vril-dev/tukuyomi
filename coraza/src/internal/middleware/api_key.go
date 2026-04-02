package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/config"
)

func APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.APIAuthDisable {
			c.Next()
			return
		}
		key := strings.TrimSpace(c.GetHeader("X-API-Key"))

		if config.APIKeyPrimary == "" && config.APIKeySecondary == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if secureKeyMatch(key, config.APIKeyPrimary) || secureKeyMatch(key, config.APIKeySecondary) {
			c.Next()
			return
		}
		c.AbortWithStatus(http.StatusUnauthorized)
	}
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
