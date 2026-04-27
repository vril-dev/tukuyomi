package runtimefiles

import (
	"os"
	"path/filepath"
)

const TempDir = "data/tmp"

func MakeTempDir(pattern string) (string, error) {
	root := filepath.Clean(TempDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(root, pattern)
}
