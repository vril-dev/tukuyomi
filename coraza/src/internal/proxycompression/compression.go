package proxycompression

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const (
	DefaultMinBytes = 256
	AlgorithmGzip   = "gzip"
	AlgorithmBrotli = "br"
	AlgorithmZstd   = "zstd"
)

var supportedAlgorithms = []string{
	AlgorithmGzip,
	AlgorithmBrotli,
	AlgorithmZstd,
}

var defaultMIMETypes = []string{
	"application/javascript",
	"application/json",
	"application/ld+json",
	"application/wasm",
	"application/xml",
	"image/svg+xml",
	"text/*",
}

type Config struct {
	Enabled    bool     `json:"enabled"`
	Algorithms []string `json:"algorithms,omitempty"`
	MinBytes   int64    `json:"min_bytes,omitempty"`
	MIMETypes  []string `json:"mime_types,omitempty"`
}

func SupportedAlgorithms() []string {
	return append([]string(nil), supportedAlgorithms...)
}

func DefaultMIMETypes() []string {
	return append([]string(nil), defaultMIMETypes...)
}

func NormalizeConfig(in Config) Config {
	out := in
	out.Algorithms = NormalizeAlgorithms(out.Algorithms)
	if len(out.Algorithms) == 0 {
		out.Algorithms = []string{AlgorithmGzip}
	}
	out.MIMETypes = NormalizeMIMETypes(out.MIMETypes)
	if len(out.MIMETypes) == 0 {
		out.MIMETypes = DefaultMIMETypes()
	}
	if out.MinBytes == 0 {
		out.MinBytes = DefaultMinBytes
	}
	return out
}

func NormalizeAlgorithms(in []string) []string {
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

func NormalizeMIMETypes(in []string) []string {
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

func ValidateConfig(cfg Config, maxResponseBufferBytes int64) error {
	if cfg.MinBytes < 0 {
		return fmt.Errorf("response_compression.min_bytes must be >= 0")
	}
	for _, algorithm := range cfg.Algorithms {
		if !AlgorithmSupported(algorithm) {
			return fmt.Errorf("response_compression.algorithms contains unsupported value %q", algorithm)
		}
	}
	for _, mimeType := range cfg.MIMETypes {
		if !validMIMETypePattern(mimeType) {
			return fmt.Errorf("response_compression.mime_types contains invalid value %q", mimeType)
		}
	}
	if cfg.Enabled && maxResponseBufferBytes <= 0 {
		return fmt.Errorf("response_compression.enabled requires max_response_buffer_bytes > 0")
	}
	return nil
}

func validMIMETypePattern(value string) bool {
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

func Enabled(cfg Config) bool {
	return cfg.Enabled && len(cfg.Algorithms) > 0
}

func AllowsAlgorithm(cfg Config, algorithm string) bool {
	if !Enabled(cfg) {
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

func AlgorithmSupported(algorithm string) bool {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case AlgorithmGzip, AlgorithmBrotli, AlgorithmZstd:
		return true
	default:
		return false
	}
}

func AppendVaryHeader(header http.Header, value string) {
	if header == nil {
		return
	}
	header["Vary"] = []string{strings.Join(AppendVaryValue(ParseVaryHeader(header.Values("Vary")), value), ", ")}
}

func AppendVaryValue(values []string, value string) []string {
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

func ParseVaryHeader(values []string) []string {
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

func CompressBody(algorithm string, body []byte) ([]byte, error) {
	var buf bytes.Buffer
	switch algorithm {
	case AlgorithmGzip:
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
	case AlgorithmBrotli:
		bw := brotli.NewWriterLevel(&buf, brotli.BestSpeed)
		if _, err := bw.Write(body); err != nil {
			_ = bw.Close()
			return nil, err
		}
		if err := bw.Close(); err != nil {
			return nil, err
		}
	case AlgorithmZstd:
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

func RestoreResponseBody(res *http.Response, body []byte) {
	if res == nil {
		return
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	res.ContentLength = int64(len(body))
	if res.Header != nil {
		res.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
}

func HasEntityBody(method string, status int) bool {
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

func IsUpgrade(res *http.Response) bool {
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

func HasNoTransform(header http.Header) bool {
	cacheControl := strings.ToLower(strings.Join(header.Values("Cache-Control"), ","))
	return strings.Contains(cacheControl, "no-transform")
}

func SelectAlgorithm(req *http.Request, cfg Config) (string, bool) {
	if req == nil {
		return "", false
	}
	accepted := parseAcceptEncoding(req.Header.Get("Accept-Encoding"))
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

type acceptEncodingPreferences struct {
	values      map[string]float64
	wildcardQ   float64
	hasWildcard bool
	present     bool
}

func parseAcceptEncoding(raw string) acceptEncodingPreferences {
	out := acceptEncodingPreferences{
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

func (p acceptEncodingPreferences) allows(encoding string) bool {
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

func AlreadyEncoded(header http.Header) bool {
	encoding := strings.ToLower(strings.TrimSpace(header.Get("Content-Encoding")))
	return encoding != "" && encoding != "identity"
}

func AllowsMIMEType(cfg Config, contentType string, body []byte) bool {
	mediaType := MediaType(contentType, body)
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

func MediaType(contentType string, body []byte) string {
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

func WeakenETag(header http.Header) {
	if header == nil {
		return
	}
	etag := strings.TrimSpace(header.Get("ETag"))
	if etag == "" || strings.HasPrefix(etag, "W/") {
		return
	}
	header.Set("ETag", "W/"+etag)
}
