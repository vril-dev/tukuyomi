package handler

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func fileSavedAt(path string) string {
	info, err := os.Stat(strings.TrimSpace(path))
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format(time.RFC3339Nano)
}

func configBlobSavedAt(store *wafEventStore, configKey string) string {
	if store == nil {
		return ""
	}
	savedAt, found, err := store.GetConfigBlobUpdatedAt(configKey)
	if err != nil || !found {
		return ""
	}
	return savedAt
}

func respondConfigBlobDBError(c *gin.Context, message string, err error) {
	c.JSON(http.StatusInternalServerError, gin.H{
		"error":    message,
		"db_error": err.Error(),
	})
}
