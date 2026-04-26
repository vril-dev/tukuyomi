package adminhttp

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

const ReadOnlyMessage = "admin is read-only in this deployment; apply changes via rollout"

func ReadOnlyMutationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.AdminReadOnly {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":     ReadOnlyMessage,
			"read_only": true,
		})
	}
}
