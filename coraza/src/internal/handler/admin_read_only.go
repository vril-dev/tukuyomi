package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

const adminReadOnlyMessage = "admin is read-only in this deployment; apply changes via rollout"

func AdminReadOnlyMutationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.AdminReadOnly {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":     adminReadOnlyMessage,
			"read_only": true,
		})
	}
}
