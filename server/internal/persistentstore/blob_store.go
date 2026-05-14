package persistentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type BlobStoreConfig struct {
	Backend      string
	LocalBaseDir string
	S3           S3CacheConfig
}

type BlobInfo struct {
	Size   int64
	SHA256 string
}

type BlobStore interface {
	PutBytes(ctx context.Context, key string, data []byte, sha256Hex string) error
	PutFile(ctx context.Context, key string, path string, sha256Hex string) error
	Stat(ctx context.Context, key string) (BlobInfo, bool, error)
	Get(ctx context.Context, key string) (io.ReadCloser, BlobInfo, error)
}

func NewBlobStoreFromConfig(cfg BlobStoreConfig) (BlobStore, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", BackendLocal:
		baseDir := strings.TrimSpace(cfg.LocalBaseDir)
		if baseDir == "" {
			return nil, fmt.Errorf("persistent_storage.local.base_dir is required")
		}
		return NewLocalBlobStore(baseDir)
	case BackendS3:
		return NewS3BlobStoreFromEnv(cfg.S3)
	default:
		return nil, fmt.Errorf("persistent storage backend %q is not available for blob storage", cfg.Backend)
	}
}

type LocalBlobStore struct {
	baseDir string
}

func NewLocalBlobStore(baseDir string) (*LocalBlobStore, error) {
	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "" {
		return nil, fmt.Errorf("local blob base dir is required")
	}
	return &LocalBlobStore{baseDir: baseDir}, nil
}

func (s *LocalBlobStore) PutBytes(ctx context.Context, key string, data []byte, wantSHA256 string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := cleanBlobKey(key)
	if err != nil {
		return err
	}
	if wantSHA256 != "" && sha256Hex(data) != wantSHA256 {
		return fmt.Errorf("blob %q sha256 mismatch before local write", key)
	}
	target := s.localPath(key)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, target)
}

func (s *LocalBlobStore) PutFile(ctx context.Context, key string, path string, wantSHA256 string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := cleanBlobKey(key)
	if err != nil {
		return err
	}
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	target := s.localPath(key)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	hasher := sha256.New()
	if _, err := io.Copy(tmp, io.TeeReader(src, hasher)); err != nil {
		_ = tmp.Close()
		return err
	}
	gotSHA256 := hex.EncodeToString(hasher.Sum(nil))
	if wantSHA256 != "" && gotSHA256 != wantSHA256 {
		_ = tmp.Close()
		return fmt.Errorf("blob %q sha256 mismatch before local write", key)
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, target)
}

func (s *LocalBlobStore) Stat(ctx context.Context, key string) (BlobInfo, bool, error) {
	if err := ctx.Err(); err != nil {
		return BlobInfo{}, false, err
	}
	key, err := cleanBlobKey(key)
	if err != nil {
		return BlobInfo{}, false, err
	}
	path := s.localPath(key)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return BlobInfo{}, false, nil
		}
		return BlobInfo{}, false, err
	}
	f, err := os.Open(path)
	if err != nil {
		return BlobInfo{}, false, err
	}
	defer f.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return BlobInfo{}, false, err
	}
	return BlobInfo{Size: info.Size(), SHA256: hex.EncodeToString(hasher.Sum(nil))}, true, nil
}

func (s *LocalBlobStore) Get(ctx context.Context, key string) (io.ReadCloser, BlobInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, BlobInfo{}, err
	}
	key, err := cleanBlobKey(key)
	if err != nil {
		return nil, BlobInfo{}, err
	}
	info, ok, err := s.Stat(ctx, key)
	if err != nil || !ok {
		if err == nil {
			err = os.ErrNotExist
		}
		return nil, BlobInfo{}, err
	}
	f, err := os.Open(s.localPath(key))
	if err != nil {
		return nil, BlobInfo{}, err
	}
	return f, info, nil
}

func (s *LocalBlobStore) localPath(key string) string {
	return filepath.Join(s.baseDir, filepath.FromSlash(key))
}

type S3BlobStore struct {
	bucket         string
	region         string
	endpoint       string
	prefix         string
	forcePathStyle bool
	credentials    S3Credentials
	client         *http.Client
	now            func() time.Time
}

func NewS3BlobStoreFromEnv(cfg S3CacheConfig) (*S3BlobStore, error) {
	credentials := S3Credentials{
		AccessKeyID:     strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID")),
		SecretAccessKey: strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY")),
		SessionToken:    strings.TrimSpace(os.Getenv("AWS_SESSION_TOKEN")),
	}
	if credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" {
		return nil, fmt.Errorf("persistent_storage.s3 requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = strings.TrimSpace(os.Getenv("AWS_REGION"))
	}
	if region == "" {
		region = strings.TrimSpace(os.Getenv("AWS_DEFAULT_REGION"))
	}
	if region == "" {
		region = s3DefaultRegion
	}
	return NewS3BlobStore(cfg, credentials, region)
}

func NewS3BlobStore(cfg S3CacheConfig, credentials S3Credentials, regionOverride string) (*S3BlobStore, error) {
	cache, err := NewS3AutocertCache(cfg, "blob-store-probe", credentials, regionOverride)
	if err != nil {
		return nil, err
	}
	return &S3BlobStore{
		bucket:         cache.bucket,
		region:         cache.region,
		endpoint:       cache.endpoint,
		prefix:         strings.Trim(strings.TrimSpace(cfg.Prefix), "/"),
		forcePathStyle: cache.forcePathStyle,
		credentials:    cache.credentials,
		client:         &http.Client{Timeout: 60 * time.Second},
		now:            time.Now,
	}, nil
}

func (s *S3BlobStore) PutBytes(ctx context.Context, key string, data []byte, wantSHA256 string) error {
	if wantSHA256 != "" && sha256Hex(data) != wantSHA256 {
		return fmt.Errorf("blob %q sha256 mismatch before s3 write", key)
	}
	return s.put(ctx, key, bytes.NewReader(data), int64(len(data)), sha256Hex(data))
}

func (s *S3BlobStore) PutFile(ctx context.Context, key string, path string, wantSHA256 string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if wantSHA256 == "" {
		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			return err
		}
		wantSHA256 = hex.EncodeToString(hasher.Sum(nil))
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	return s.put(ctx, key, f, info.Size(), wantSHA256)
}

func (s *S3BlobStore) put(ctx context.Context, key string, body io.Reader, size int64, payloadSHA256 string) error {
	objectKey, err := s.objectKey(key)
	if err != nil {
		return err
	}
	resp, err := s.do(ctx, http.MethodPut, objectKey, body, size, payloadSHA256)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return s3HTTPError("put blob", resp)
	}
	return nil
}

func (s *S3BlobStore) Stat(ctx context.Context, key string) (BlobInfo, bool, error) {
	objectKey, err := s.objectKey(key)
	if err != nil {
		return BlobInfo{}, false, err
	}
	resp, err := s.do(ctx, http.MethodHead, objectKey, nil, 0, sha256Hex(nil))
	if err != nil {
		return BlobInfo{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return BlobInfo{}, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return BlobInfo{}, false, s3HTTPError("stat blob", resp)
	}
	return BlobInfo{Size: resp.ContentLength}, true, nil
}

func (s *S3BlobStore) Get(ctx context.Context, key string) (io.ReadCloser, BlobInfo, error) {
	objectKey, err := s.objectKey(key)
	if err != nil {
		return nil, BlobInfo{}, err
	}
	resp, err := s.do(ctx, http.MethodGet, objectKey, nil, 0, sha256Hex(nil))
	if err != nil {
		return nil, BlobInfo{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return nil, BlobInfo{}, os.ErrNotExist
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err := s3HTTPError("get blob", resp)
		_ = resp.Body.Close()
		return nil, BlobInfo{}, err
	}
	return resp.Body, BlobInfo{Size: resp.ContentLength}, nil
}

func (s *S3BlobStore) objectKey(key string) (string, error) {
	key, err := cleanBlobKey(key)
	if err != nil {
		return "", err
	}
	objectKey := joinS3KeyParts(s.prefix, key)
	if err := validateS3ObjectKeyPrefix(objectKey); err != nil {
		return "", err
	}
	return objectKey, nil
}

func (s *S3BlobStore) do(ctx context.Context, method string, objectKey string, body io.Reader, size int64, payloadSHA256 string) (*http.Response, error) {
	if s == nil {
		return nil, errors.New("nil s3 blob store")
	}
	u, err := (&S3AutocertCache{
		bucket:         s.bucket,
		region:         s.region,
		endpoint:       s.endpoint,
		forcePathStyle: s.forcePathStyle,
	}).objectURL(objectKey)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	if err := s.sign(req, payloadSHA256); err != nil {
		return nil, err
	}
	return s.client.Do(req)
}

func (s *S3BlobStore) sign(req *http.Request, payloadSHA256 string) error {
	cache := &S3AutocertCache{
		region:      s.region,
		credentials: s.credentials,
		now:         s.now,
	}
	if cache.now == nil {
		cache.now = time.Now
	}
	t := cache.now().UTC()
	amzDate := t.Format("20060102T150405Z")
	shortDate := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadSHA256)
	if s.credentials.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.credentials.SessionToken)
	}
	canonicalHeaders, signedHeaders := canonicalS3Headers(req)
	credentialScope := strings.Join([]string{shortDate, s.region, s3Service, s3Request}, "/")
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		payloadSHA256,
	}, "\n")
	stringToSign := strings.Join([]string{
		s3Algorithm,
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	signature := hex.EncodeToString(newS3SigningKey(s.credentials.SecretAccessKey, shortDate, s.region).Sign([]byte(stringToSign)))
	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s3Algorithm,
		s.credentials.AccessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	))
	return nil
}

func cleanBlobKey(key string) (string, error) {
	key = strings.Trim(strings.TrimSpace(strings.ReplaceAll(key, "\\", "/")), "/")
	if key == "" {
		return "", fmt.Errorf("blob key is required")
	}
	if strings.Contains(key, "\x00") {
		return "", fmt.Errorf("blob key contains invalid NUL byte")
	}
	for _, part := range strings.Split(key, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("blob key must not contain empty or relative path segments")
		}
	}
	return key, nil
}
