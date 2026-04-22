package handler

import (
	"os"
	"strings"
	"time"
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
