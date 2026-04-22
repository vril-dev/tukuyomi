package handler

import (
	"strings"

	"github.com/gin-gonic/gin"
)

func requestClientIP(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}

	if v := strings.TrimSpace(c.GetHeader("X-Real-IP")); v != "" {
		return v
	}
	if v := strings.TrimSpace(c.GetHeader("X-Forwarded-For")); v != "" {
		if i := strings.Index(v, ","); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return v
	}

	return strings.TrimSpace(c.ClientIP())
}
