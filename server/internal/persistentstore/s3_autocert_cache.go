package persistentstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const (
	s3Service        = "s3"
	s3Request        = "aws4_request"
	s3Algorithm      = "AWS4-HMAC-SHA256"
	s3DefaultRegion  = "us-east-1"
	s3MaxObjectBytes = 16 << 20
)

type S3CacheConfig struct {
	Bucket         string
	Region         string
	Endpoint       string
	Prefix         string
	ForcePathStyle bool
}

type S3Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

type S3AutocertCache struct {
	bucket         string
	region         string
	endpoint       string
	prefix         string
	forcePathStyle bool
	credentials    S3Credentials
	client         *http.Client
	now            func() time.Time
}

func NewS3AutocertCacheFromEnv(cfg S3CacheConfig, namespace string) (*S3AutocertCache, error) {
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
	return NewS3AutocertCache(cfg, namespace, credentials, region)
}

func NewS3AutocertCache(cfg S3CacheConfig, namespace string, credentials S3Credentials, regionOverride string) (*S3AutocertCache, error) {
	bucket := strings.TrimSpace(cfg.Bucket)
	if bucket == "" {
		return nil, fmt.Errorf("persistent_storage.s3.bucket is required")
	}
	if strings.ContainsAny(bucket, "/\x00") {
		return nil, fmt.Errorf("persistent_storage.s3.bucket contains invalid characters")
	}
	if strings.TrimSpace(credentials.AccessKeyID) == "" || strings.TrimSpace(credentials.SecretAccessKey) == "" {
		return nil, fmt.Errorf("persistent_storage.s3 credentials are required")
	}
	region := strings.TrimSpace(regionOverride)
	if region == "" {
		region = strings.TrimSpace(cfg.Region)
	}
	if region == "" {
		region = s3DefaultRegion
	}
	prefix := joinS3KeyParts(cfg.Prefix, namespace)
	if err := validateS3ObjectKeyPrefix(prefix); err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint != "" {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("persistent_storage.s3.endpoint invalid: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("persistent_storage.s3.endpoint must start with http:// or https://")
		}
		if parsed.Host == "" {
			return nil, fmt.Errorf("persistent_storage.s3.endpoint host is required")
		}
	}
	return &S3AutocertCache{
		bucket:         bucket,
		region:         region,
		endpoint:       endpoint,
		prefix:         prefix,
		forcePathStyle: cfg.ForcePathStyle || endpoint != "",
		credentials: S3Credentials{
			AccessKeyID:     strings.TrimSpace(credentials.AccessKeyID),
			SecretAccessKey: strings.TrimSpace(credentials.SecretAccessKey),
			SessionToken:    strings.TrimSpace(credentials.SessionToken),
		},
		client: &http.Client{Timeout: 30 * time.Second},
		now:    time.Now,
	}, nil
}

func (c *S3AutocertCache) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, c.objectKey(key), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, autocert.ErrCacheMiss
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, s3HTTPError("get", resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, s3MaxObjectBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > s3MaxObjectBytes {
		return nil, fmt.Errorf("s3 cache object %q exceeds %d bytes", key, s3MaxObjectBytes)
	}
	return data, nil
}

func (c *S3AutocertCache) Put(ctx context.Context, key string, data []byte) error {
	if len(data) > s3MaxObjectBytes {
		return fmt.Errorf("s3 cache object %q exceeds %d bytes", key, s3MaxObjectBytes)
	}
	resp, err := c.do(ctx, http.MethodPut, c.objectKey(key), data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return s3HTTPError("put", resp)
	}
	return nil
}

func (c *S3AutocertCache) Delete(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, c.objectKey(key), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return s3HTTPError("delete", resp)
	}
	return nil
}

func (c *S3AutocertCache) objectKey(key string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(key))
	return joinS3KeyParts(c.prefix, encoded)
}

func (c *S3AutocertCache) do(ctx context.Context, method string, objectKey string, data []byte) (*http.Response, error) {
	if c == nil {
		return nil, errors.New("nil s3 autocert cache")
	}
	if err := validateS3ObjectKeyPrefix(objectKey); err != nil {
		return nil, err
	}
	u, err := c.objectURL(objectKey)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if data != nil {
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if data != nil {
		req.ContentLength = int64(len(data))
	}
	if err := c.sign(req, data); err != nil {
		return nil, err
	}
	return c.client.Do(req)
}

func (c *S3AutocertCache) objectURL(objectKey string) (*url.URL, error) {
	base := c.endpoint
	if base == "" {
		base = "https://s3." + c.region + ".amazonaws.com"
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if c.forcePathStyle {
		u.Path = "/" + c.bucket + "/" + objectKey
		u.RawPath = "/" + escapeS3Key(c.bucket) + "/" + escapeS3Key(objectKey)
		return u, nil
	}
	u.Host = c.bucket + "." + u.Host
	u.Path = "/" + objectKey
	u.RawPath = "/" + escapeS3Key(objectKey)
	return u, nil
}

func (c *S3AutocertCache) sign(req *http.Request, payload []byte) error {
	t := c.now().UTC()
	amzDate := t.Format("20060102T150405Z")
	shortDate := t.Format("20060102")
	payloadHash := sha256Hex(payload)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if c.credentials.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.credentials.SessionToken)
	}

	canonicalHeaders, signedHeaders := canonicalS3Headers(req)
	credentialScope := strings.Join([]string{shortDate, c.region, s3Service, s3Request}, "/")
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	stringToSign := strings.Join([]string{
		s3Algorithm,
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	signature := hex.EncodeToString(newS3SigningKey(c.credentials.SecretAccessKey, shortDate, c.region).Sign([]byte(stringToSign)))
	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s3Algorithm,
		c.credentials.AccessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	))
	return nil
}

func canonicalS3Headers(req *http.Request) (string, string) {
	headers := map[string]string{
		"host":                 req.URL.Host,
		"x-amz-content-sha256": req.Header.Get("X-Amz-Content-Sha256"),
		"x-amz-date":           req.Header.Get("X-Amz-Date"),
	}
	if token := req.Header.Get("X-Amz-Security-Token"); token != "" {
		headers["x-amz-security-token"] = token
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.TrimSpace(headers[name]))
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(names, ";")
}

type signingKey []byte

func (k signingKey) Sign(data []byte) []byte {
	mac := hmac.New(sha256.New, k)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func newS3SigningKey(secret string, date string, region string) signingKey {
	kDate := signingKey([]byte("AWS4" + secret)).Sign([]byte(date))
	kRegion := signingKey(kDate).Sign([]byte(region))
	kService := signingKey(kRegion).Sign([]byte(s3Service))
	return signingKey(signingKey(kService).Sign([]byte(s3Request)))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func escapeS3Key(key string) string {
	if key == "" {
		return ""
	}
	parts := strings.Split(key, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func joinS3KeyParts(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(strings.TrimSpace(strings.ReplaceAll(part, "\\", "/")), "/")
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return strings.Join(out, "/")
}

func validateS3ObjectKeyPrefix(key string) error {
	if strings.Contains(key, "\x00") {
		return fmt.Errorf("s3 object key contains invalid NUL byte")
	}
	for _, part := range strings.Split(key, "/") {
		if part == "." || part == ".." {
			return fmt.Errorf("s3 object key must not contain relative path segments")
		}
	}
	return nil
}

func s3HTTPError(op string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	detail := strings.TrimSpace(string(body))
	if detail == "" {
		return fmt.Errorf("s3 cache %s failed: HTTP %d", op, resp.StatusCode)
	}
	return fmt.Errorf("s3 cache %s failed: HTTP %d: %s", op, resp.StatusCode, detail)
}
