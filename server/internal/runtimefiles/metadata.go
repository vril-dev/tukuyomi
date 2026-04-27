package runtimefiles

import (
	"os"
	"strings"
	"time"
)

func FileSavedAt(path string) string {
	info, err := os.Stat(strings.TrimSpace(path))
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format(time.RFC3339Nano)
}
