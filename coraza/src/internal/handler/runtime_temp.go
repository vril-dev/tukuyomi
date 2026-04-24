package handler

import (
	"os"
	"path/filepath"
)

const runtimeTempDir = "data/tmp"

func makeRuntimeTempDir(pattern string) (string, error) {
	root := filepath.Clean(runtimeTempDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(root, pattern)
}
