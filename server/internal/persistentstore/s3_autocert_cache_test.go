package persistentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func TestS3AutocertCacheRoundTrip(t *testing.T) {
	store := map[string][]byte{}
	var sawAuthorization bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=minio/20260424/us-east-1/s3/aws4_request") {
			t.Fatalf("unexpected authorization header: %q", auth)
		}
		if r.Header.Get("X-Amz-Date") != "20260424T010203Z" {
			t.Fatalf("unexpected x-amz-date: %q", r.Header.Get("X-Amz-Date"))
		}
		sawAuthorization = true
		path := strings.TrimPrefix(r.URL.EscapedPath(), "/")
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read put body: %v", err)
			}
			if got, want := r.Header.Get("X-Amz-Content-Sha256"), sha256HexForTest(body); got != want {
				t.Fatalf("payload hash=%q want=%q", got, want)
			}
			store[path] = append([]byte(nil), body...)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body, ok := store[path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(body)
		case http.MethodDelete:
			delete(store, path)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	}))
	defer server.Close()

	cache, err := NewS3AutocertCache(S3CacheConfig{
		Bucket:         "runtime",
		Endpoint:       server.URL,
		Prefix:         "prod/",
		ForcePathStyle: true,
	}, "acme/production/default", S3Credentials{
		AccessKeyID:     "minio",
		SecretAccessKey: "minio-secret",
	}, "us-east-1")
	if err != nil {
		t.Fatalf("NewS3AutocertCache: %v", err)
	}
	cache.client = server.Client()
	cache.now = func() time.Time {
		return time.Date(2026, 4, 24, 1, 2, 3, 0, time.UTC)
	}

	ctx := context.Background()
	if err := cache.Put(ctx, "cert-cache-key", []byte("certificate-data")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := cache.Get(ctx, "cert-cache-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte("certificate-data")) {
		t.Fatalf("Get=%q want certificate-data", got)
	}
	if err := cache.Delete(ctx, "cert-cache-key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := cache.Get(ctx, "cert-cache-key"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get after delete err=%v want ErrCacheMiss", err)
	}
	if !sawAuthorization {
		t.Fatal("expected signed S3 requests")
	}
}

func TestS3AutocertCacheFromEnvRequiresCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	_, err := NewS3AutocertCacheFromEnv(S3CacheConfig{Bucket: "runtime"}, "acme/test/default")
	if err == nil {
		t.Fatal("expected missing credentials error")
	}
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestS3AutocertCacheMinIOIntegration(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv("TUKUYOMI_MINIO_S3_ENDPOINT"))
	bucket := strings.TrimSpace(os.Getenv("TUKUYOMI_MINIO_S3_BUCKET"))
	if endpoint == "" || bucket == "" {
		t.Skip("set TUKUYOMI_MINIO_S3_ENDPOINT and TUKUYOMI_MINIO_S3_BUCKET for MinIO integration")
	}
	cache, err := NewS3AutocertCacheFromEnv(S3CacheConfig{
		Bucket:         bucket,
		Endpoint:       endpoint,
		Prefix:         "tukuyomi-test/" + time.Now().UTC().Format("20060102T150405Z"),
		ForcePathStyle: true,
	}, "acme/minio/default")
	if err != nil {
		t.Fatalf("NewS3AutocertCacheFromEnv: %v", err)
	}
	ctx := context.Background()
	if err := cache.Put(ctx, "minio-key", []byte("minio-data")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := cache.Get(ctx, "minio-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte("minio-data")) {
		t.Fatalf("Get=%q want minio-data", got)
	}
	if err := cache.Delete(ctx, "minio-key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func sha256HexForTest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
