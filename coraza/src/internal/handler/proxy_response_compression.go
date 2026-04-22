package handler

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const (
	defaultProxyResponseCompressionMinBytes = 256
	proxyResponseCompressionAlgorithmGzip   = "gzip"
	proxyResponseCompressionAlgorithmBrotli = "br"
	proxyResponseCompressionAlgorithmZstd   = "zstd"
)

var supportedProxyResponseCompressionAlgorithms = []string{
	proxyResponseCompressionAlgorithmGzip,
	proxyResponseCompressionAlgorithmBrotli,
	proxyResponseCompressionAlgorithmZstd,
}

var defaultProxyResponseCompressionMIMETypes = []string{
	"application/javascript",
	"application/json",
	"application/ld+json",
	"application/wasm",
	"application/xml",
	"image/svg+xml",
	"text/*",
}

type ProxyResponseCompressionConfig struct {
	Enabled    bool     `json:"enabled"`
	Algorithms []string `json:"algorithms,omitempty"`
	MinBytes   int64    `json:"min_bytes,omitempty"`
	MIMETypes  []string `json:"mime_types,omitempty"`
}

type proxyResponseCompressionStatus struct {
	CompressedTotal       int64
	CompressedBytesIn     int64
	CompressedBytesOut    int64
	CompressedByAlgorithm map[string]int64
	SkippedClientTotal    int64
	SkippedEncodedTotal   int64
	SkippedBodylessTotal  int64
	SkippedSmallTotal     int64
	SkippedMimeTotal      int64
	SkippedTransformTotal int64
	SkippedUpgradeTotal   int64
}

type proxyResponseCompressionMetrics struct {
	compressedTotal       atomic.Int64
	compressedBytesIn     atomic.Int64
	compressedBytesOut    atomic.Int64
	compressedGzipTotal   atomic.Int64
	compressedBrotliTotal atomic.Int64
	compressedZstdTotal   atomic.Int64
	skippedClientTotal    atomic.Int64
	skippedEncodedTotal   atomic.Int64
	skippedBodylessTotal  atomic.Int64
	skippedSmallTotal     atomic.Int64
	skippedMimeTotal      atomic.Int64
	skippedTransformTotal atomic.Int64
	skippedUpgradeTotal   atomic.Int64
}

var proxyResponseCompressionRuntimeMetrics proxyResponseCompressionMetrics

func normalizeProxyResponseCompressionConfig(in ProxyResponseCompressionConfig) ProxyResponseCompressionConfig {
	out := in
	out.Algorithms = normalizeProxyResponseCompressionAlgorithms(out.Algorithms)
	if len(out.Algorithms) == 0 {
		out.Algorithms = []string{proxyResponseCompressionAlgorithmGzip}
	}
	out.MIMETypes = normalizeProxyResponseCompressionMIMETypes(out.MIMETypes)
	if len(out.MIMETypes) == 0 {
		out.MIMETypes = append([]string(nil), defaultProxyResponseCompressionMIMETypes...)
	}
	if out.MinBytes == 0 {
		out.MinBytes = defaultProxyResponseCompressionMinBytes
	}
	return out
}

func normalizeProxyResponseCompressionAlgorithms(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		next := strings.ToLower(strings.TrimSpace(raw))
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	return out
}

func normalizeProxyResponseCompressionMIMETypes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		next := strings.ToLower(strings.TrimSpace(raw))
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	return out
}

func validateProxyResponseCompressionConfig(cfg ProxyResponseCompressionConfig, maxResponseBufferBytes int64) error {
	if cfg.MinBytes < 0 {
		return fmt.Errorf("response_compression.min_bytes must be >= 0")
	}
	for _, algorithm := range cfg.Algorithms {
		if !proxyResponseCompressionAlgorithmSupported(algorithm) {
			return fmt.Errorf("response_compression.algorithms contains unsupported value %q", algorithm)
		}
	}
	for _, mimeType := range cfg.MIMETypes {
		if !proxyResponseCompressionValidMIMETypePattern(mimeType) {
			return fmt.Errorf("response_compression.mime_types contains invalid value %q", mimeType)
		}
	}
	if cfg.Enabled && maxResponseBufferBytes <= 0 {
		return fmt.Errorf("response_compression.enabled requires max_response_buffer_bytes > 0")
	}
	return nil
}

func proxyResponseCompressionValidMIMETypePattern(value string) bool {
	if value == "" {
		return false
	}
	if value == "*/*" {
		return true
	}
	if strings.HasSuffix(value, "/*") {
		major := strings.TrimSuffix(value, "/*")
		return major != "" && !strings.Contains(major, "/")
	}
	parsed, _, err := mime.ParseMediaType(value)
	return err == nil && parsed == value
}

func proxyResponseCompressionEnabled(cfg ProxyResponseCompressionConfig) bool {
	return cfg.Enabled && len(cfg.Algorithms) > 0
}

func proxyResponseCompressionAllowsAlgorithm(cfg ProxyResponseCompressionConfig, algorithm string) bool {
	if !proxyResponseCompressionEnabled(cfg) {
		return false
	}
	needle := strings.ToLower(strings.TrimSpace(algorithm))
	for _, configured := range cfg.Algorithms {
		if configured == needle {
			return true
		}
	}
	return false
}

func proxyResponseCompressionAlgorithmSupported(algorithm string) bool {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case proxyResponseCompressionAlgorithmGzip, proxyResponseCompressionAlgorithmBrotli, proxyResponseCompressionAlgorithmZstd:
		return true
	default:
		return false
	}
}

func proxyEffectiveResponseCacheVary(vary []string) []string {
	out := append([]string(nil), vary...)
	cfg := currentProxyConfig()
	if proxyResponseCompressionEnabled(cfg.ResponseCompression) {
		out = appendProxyVaryValue(out, "Accept-Encoding")
	}
	return out
}

func appendProxyVaryHeader(header http.Header, value string) {
	if header == nil {
		return
	}
	header["Vary"] = []string{strings.Join(appendProxyVaryValue(parseProxyVaryHeader(header.Values("Vary")), value), ", ")}
}

func appendProxyVaryValue(values []string, value string) []string {
	name := http.CanonicalHeaderKey(strings.TrimSpace(value))
	if name == "" {
		return values
	}
	for _, existing := range values {
		if http.CanonicalHeaderKey(existing) == name {
			return values
		}
	}
	return append(values, name)
}

func parseProxyVaryHeader(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, rawList := range values {
		for _, raw := range strings.Split(rawList, ",") {
			next := http.CanonicalHeaderKey(strings.TrimSpace(raw))
			if next == "" {
				continue
			}
			if _, ok := seen[next]; ok {
				continue
			}
			seen[next] = struct{}{}
			out = append(out, next)
		}
	}
	return out
}

func maybeCompressProxyResponse(res *http.Response) error {
	cfg := currentProxyConfig()
	compressionCfg := cfg.ResponseCompression
	if !proxyResponseCompressionEnabled(compressionCfg) || res == nil || res.Header == nil || res.Request == nil {
		return nil
	}
	if isDirectStaticResponse(res) {
		return nil
	}
	appendProxyVaryHeader(res.Header, "Accept-Encoding")
	if !proxyResponseHasEntityBody(res.Request.Method, res.StatusCode) {
		proxyResponseCompressionRuntimeMetrics.skippedBodylessTotal.Add(1)
		return nil
	}
	if proxyResponseIsUpgrade(res) {
		proxyResponseCompressionRuntimeMetrics.skippedUpgradeTotal.Add(1)
		return nil
	}
	if proxyResponseHasNoTransform(res.Header) {
		proxyResponseCompressionRuntimeMetrics.skippedTransformTotal.Add(1)
		return nil
	}
	algorithm, ok := proxySelectResponseCompressionAlgorithm(res.Request, compressionCfg)
	if !ok {
		proxyResponseCompressionRuntimeMetrics.skippedClientTotal.Add(1)
		return nil
	}
	if proxyResponseAlreadyEncoded(res.Header) {
		proxyResponseCompressionRuntimeMetrics.skippedEncodedTotal.Add(1)
		return nil
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	_ = res.Body.Close()
	restoreProxyResponseBody(res, body)

	if int64(len(body)) < compressionCfg.MinBytes {
		proxyResponseCompressionRuntimeMetrics.skippedSmallTotal.Add(1)
		return nil
	}
	if !proxyResponseCompressionAllowsMIMEType(compressionCfg, res.Header.Get("Content-Type"), body) {
		proxyResponseCompressionRuntimeMetrics.skippedMimeTotal.Add(1)
		return nil
	}

	compressed, err := proxyCompressResponseBody(algorithm, body)
	if err != nil {
		return err
	}
	if len(compressed) >= len(body) {
		proxyResponseCompressionRuntimeMetrics.skippedSmallTotal.Add(1)
		return nil
	}

	restoreProxyResponseBody(res, compressed)
	res.Header.Set("Content-Encoding", algorithm)
	res.Header.Del("Content-MD5")
	res.Header.Del("Accept-Ranges")
	weakenProxyResponseETag(res.Header)

	proxyResponseCompressionRuntimeMetrics.compressedTotal.Add(1)
	proxyResponseCompressionRuntimeMetrics.compressedBytesIn.Add(int64(len(body)))
	proxyResponseCompressionRuntimeMetrics.compressedBytesOut.Add(int64(len(compressed)))
	recordProxyResponseCompressionAlgorithm(algorithm)
	return nil
}

func proxyCompressResponseBody(algorithm string, body []byte) ([]byte, error) {
	var buf bytes.Buffer
	switch algorithm {
	case proxyResponseCompressionAlgorithmGzip:
		gz, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		if err != nil {
			return nil, err
		}
		if _, err := gz.Write(body); err != nil {
			_ = gz.Close()
			return nil, err
		}
		if err := gz.Close(); err != nil {
			return nil, err
		}
	case proxyResponseCompressionAlgorithmBrotli:
		bw := brotli.NewWriterLevel(&buf, brotli.BestSpeed)
		if _, err := bw.Write(body); err != nil {
			_ = bw.Close()
			return nil, err
		}
		if err := bw.Close(); err != nil {
			return nil, err
		}
	case proxyResponseCompressionAlgorithmZstd:
		zw, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			return nil, err
		}
		if _, err := zw.Write(body); err != nil {
			zw.Close()
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported response compression algorithm %q", algorithm)
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

func restoreProxyResponseBody(res *http.Response, body []byte) {
	if res == nil {
		return
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	res.ContentLength = int64(len(body))
	if res.Header != nil {
		res.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
}

func proxyResponseHasEntityBody(method string, status int) bool {
	if method == http.MethodHead {
		return false
	}
	if status >= 100 && status < 200 {
		return false
	}
	switch status {
	case http.StatusNoContent, http.StatusNotModified:
		return false
	default:
		return true
	}
}

func proxyResponseIsUpgrade(res *http.Response) bool {
	if res == nil {
		return false
	}
	connectionValues := strings.ToLower(strings.Join(res.Header.Values("Connection"), ","))
	if strings.Contains(connectionValues, "upgrade") {
		return true
	}
	if res.Request == nil {
		return false
	}
	upgrade := strings.TrimSpace(res.Request.Header.Get("Upgrade"))
	return upgrade != ""
}

func proxyResponseHasNoTransform(header http.Header) bool {
	cacheControl := strings.ToLower(strings.Join(header.Values("Cache-Control"), ","))
	return strings.Contains(cacheControl, "no-transform")
}

func proxySelectResponseCompressionAlgorithm(req *http.Request, cfg ProxyResponseCompressionConfig) (string, bool) {
	if req == nil {
		return "", false
	}
	accepted := parseProxyAcceptEncoding(req.Header.Get("Accept-Encoding"))
	if !accepted.present {
		return "", false
	}
	for _, algorithm := range cfg.Algorithms {
		if accepted.allows(algorithm) {
			return algorithm, true
		}
	}
	return "", false
}

type proxyAcceptEncodingPreferences struct {
	values      map[string]float64
	wildcardQ   float64
	hasWildcard bool
	present     bool
}

func parseProxyAcceptEncoding(raw string) proxyAcceptEncodingPreferences {
	out := proxyAcceptEncodingPreferences{
		values: make(map[string]float64),
	}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	out.present = true
	for _, part := range strings.Split(raw, ",") {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		q := 1.0
		if semi := strings.Index(token, ";"); semi >= 0 {
			params := strings.Split(token[semi+1:], ";")
			token = strings.TrimSpace(token[:semi])
			for _, param := range params {
				parts := strings.SplitN(strings.TrimSpace(param), "=", 2)
				if len(parts) != 2 || !strings.EqualFold(parts[0], "q") {
					continue
				}
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
					q = parsed
				}
			}
		}
		if q <= 0 {
			if strings.EqualFold(token, "*") {
				out.hasWildcard = true
				out.wildcardQ = q
			} else {
				out.values[strings.ToLower(token)] = q
			}
			continue
		}
		token = strings.ToLower(token)
		if token == "*" {
			out.hasWildcard = true
			out.wildcardQ = q
			continue
		}
		out.values[token] = q
	}
	return out
}

func (p proxyAcceptEncodingPreferences) allows(encoding string) bool {
	if !p.present {
		return false
	}
	needle := strings.ToLower(strings.TrimSpace(encoding))
	if q, ok := p.values[needle]; ok {
		return q > 0
	}
	if p.hasWildcard {
		return p.wildcardQ > 0
	}
	return false
}

func proxyResponseAlreadyEncoded(header http.Header) bool {
	encoding := strings.ToLower(strings.TrimSpace(header.Get("Content-Encoding")))
	return encoding != "" && encoding != "identity"
}

func proxyResponseCompressionAllowsMIMEType(cfg ProxyResponseCompressionConfig, contentType string, body []byte) bool {
	mediaType := proxyResponseCompressionMediaType(contentType, body)
	if mediaType == "" {
		return false
	}
	major, _, _ := strings.Cut(mediaType, "/")
	for _, pattern := range cfg.MIMETypes {
		switch {
		case pattern == "*/*":
			return true
		case strings.HasSuffix(pattern, "/*"):
			if strings.TrimSuffix(pattern, "/*") == major {
				return true
			}
		case pattern == mediaType:
			return true
		}
	}
	return false
}

func proxyResponseCompressionMediaType(contentType string, body []byte) string {
	value := strings.TrimSpace(contentType)
	if value == "" && len(body) > 0 {
		value = http.DetectContentType(body)
	}
	if value == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(value))
	}
	return strings.ToLower(strings.TrimSpace(mediaType))
}

func weakenProxyResponseETag(header http.Header) {
	if header == nil {
		return
	}
	etag := strings.TrimSpace(header.Get("ETag"))
	if etag == "" || strings.HasPrefix(etag, "W/") {
		return
	}
	header.Set("ETag", "W/"+etag)
}

func proxyResponseCompressionStatusSnapshot() proxyResponseCompressionStatus {
	return proxyResponseCompressionStatus{
		CompressedTotal:       proxyResponseCompressionRuntimeMetrics.compressedTotal.Load(),
		CompressedBytesIn:     proxyResponseCompressionRuntimeMetrics.compressedBytesIn.Load(),
		CompressedBytesOut:    proxyResponseCompressionRuntimeMetrics.compressedBytesOut.Load(),
		CompressedByAlgorithm: proxyResponseCompressionByAlgorithmSnapshot(),
		SkippedClientTotal:    proxyResponseCompressionRuntimeMetrics.skippedClientTotal.Load(),
		SkippedEncodedTotal:   proxyResponseCompressionRuntimeMetrics.skippedEncodedTotal.Load(),
		SkippedBodylessTotal:  proxyResponseCompressionRuntimeMetrics.skippedBodylessTotal.Load(),
		SkippedSmallTotal:     proxyResponseCompressionRuntimeMetrics.skippedSmallTotal.Load(),
		SkippedMimeTotal:      proxyResponseCompressionRuntimeMetrics.skippedMimeTotal.Load(),
		SkippedTransformTotal: proxyResponseCompressionRuntimeMetrics.skippedTransformTotal.Load(),
		SkippedUpgradeTotal:   proxyResponseCompressionRuntimeMetrics.skippedUpgradeTotal.Load(),
	}
}

func recordProxyResponseCompressionAlgorithm(algorithm string) {
	switch algorithm {
	case proxyResponseCompressionAlgorithmGzip:
		proxyResponseCompressionRuntimeMetrics.compressedGzipTotal.Add(1)
	case proxyResponseCompressionAlgorithmBrotli:
		proxyResponseCompressionRuntimeMetrics.compressedBrotliTotal.Add(1)
	case proxyResponseCompressionAlgorithmZstd:
		proxyResponseCompressionRuntimeMetrics.compressedZstdTotal.Add(1)
	}
}

func proxyResponseCompressionByAlgorithmSnapshot() map[string]int64 {
	out := make(map[string]int64, len(supportedProxyResponseCompressionAlgorithms))
	for _, algorithm := range supportedProxyResponseCompressionAlgorithms {
		switch algorithm {
		case proxyResponseCompressionAlgorithmGzip:
			out[algorithm] = proxyResponseCompressionRuntimeMetrics.compressedGzipTotal.Load()
		case proxyResponseCompressionAlgorithmBrotli:
			out[algorithm] = proxyResponseCompressionRuntimeMetrics.compressedBrotliTotal.Load()
		case proxyResponseCompressionAlgorithmZstd:
			out[algorithm] = proxyResponseCompressionRuntimeMetrics.compressedZstdTotal.Load()
		}
	}
	return out
}
