package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

var errConfigDBStoreRequired = errors.New("configuration db store is not initialized")

func requireConfigDBStore() (*wafEventStore, error) {
	store := getLogsStatsStore()
	if store == nil {
		return nil, errConfigDBStoreRequired
	}
	return store, nil
}

func respondConfigDBStoreRequired(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": errConfigDBStoreRequired.Error()})
}

func respondIfConfigDBStoreRequired(c *gin.Context, err error) bool {
	if !errors.Is(err, errConfigDBStoreRequired) {
		return false
	}
	respondConfigDBStoreRequired(c)
	return true
}
