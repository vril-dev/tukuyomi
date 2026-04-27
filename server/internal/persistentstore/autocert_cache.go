package persistentstore

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

const (
	BackendLocal = "local"
	BackendS3    = "s3"
)

type AutocertCacheConfig struct {
	Backend      string
	LocalBaseDir string
	S3           S3CacheConfig
}

func NewAutocertCacheFromConfig(cfg AutocertCacheConfig, namespace string) (autocert.Cache, error) {
	namespace = cleanNamespace(namespace)
	if namespace == "" {
		return nil, fmt.Errorf("persistent cache namespace is required")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", BackendLocal:
		baseDir := strings.TrimSpace(cfg.LocalBaseDir)
		if baseDir == "" {
			return nil, fmt.Errorf("persistent_storage.local.base_dir is required")
		}
		return autocert.DirCache(filepath.Join(baseDir, filepath.FromSlash(namespace))), nil
	case BackendS3:
		return NewS3AutocertCacheFromEnv(cfg.S3, namespace)
	default:
		return nil, fmt.Errorf("persistent storage backend %q is not available for ACME cache", cfg.Backend)
	}
}

func cleanNamespace(namespace string) string {
	return strings.Trim(strings.TrimSpace(strings.ReplaceAll(namespace, "\\", "/")), "/")
}
