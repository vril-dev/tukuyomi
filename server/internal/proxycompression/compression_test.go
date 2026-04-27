package proxycompression

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNormalizeConfigDefaultsAndDedupes(t *testing.T) {
	cfg := NormalizeConfig(Config{
		Enabled:    true,
		Algorithms: []string{" GZIP ", "gzip", "BR"},
		MIMETypes:  []string{" APPLICATION/JSON ", "application/json", "text/*"},
	})

	if strings.Join(cfg.Algorithms, ",") != "gzip,br" {
		t.Fatalf("algorithms=%v", cfg.Algorithms)
	}
	if strings.Join(cfg.MIMETypes, ",") != "application/json,text/*" {
		t.Fatalf("mime_types=%v", cfg.MIMETypes)
	}
	if cfg.MinBytes != DefaultMinBytes {
		t.Fatalf("min_bytes=%d want %d", cfg.MinBytes, DefaultMinBytes)
	}
}

func TestValidateConfigRejectsUnsafeConfiguration(t *testing.T) {
	if err := ValidateConfig(Config{MinBytes: -1}, 1024); err == nil {
		t.Fatal("expected negative min_bytes error")
	}
	if err := ValidateConfig(Config{Algorithms: []string{"brotli"}}, 1024); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
	if err := ValidateConfig(Config{MIMETypes: []string{"text/plain; charset=utf-8"}}, 1024); err == nil {
		t.Fatal("expected MIME pattern error")
	}
	if err := ValidateConfig(Config{Enabled: true, Algorithms: []string{AlgorithmGzip}}, 0); err == nil {
		t.Fatal("expected buffering requirement error")
	}
}

func TestSelectAlgorithmHonorsConfiguredOrderAndQZero(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept-Encoding", "gzip;q=0, br")

	got, ok := SelectAlgorithm(req, Config{
		Enabled:    true,
		Algorithms: []string{AlgorithmGzip, AlgorithmBrotli},
	})
	if !ok || got != AlgorithmBrotli {
		t.Fatalf("algorithm=(%q,%t) want br,true", got, ok)
	}
}

func TestAllowsMIMETypeMatchesExactWildcardAndDetectedTypes(t *testing.T) {
	cfg := Config{MIMETypes: []string{"application/json", "text/*"}}
	if !AllowsMIMEType(cfg, "application/json; charset=utf-8", nil) {
		t.Fatal("expected application/json to match")
	}
	if !AllowsMIMEType(cfg, "text/plain", nil) {
		t.Fatal("expected text wildcard to match")
	}
	if !AllowsMIMEType(cfg, "", []byte("plain text response")) {
		t.Fatal("expected detected text/plain to match")
	}
	if AllowsMIMEType(cfg, "image/png", nil) {
		t.Fatal("did not expect image/png to match")
	}
}

func TestCompressBodyGzipRoundTrip(t *testing.T) {
	payload := []byte(strings.Repeat("compressible payload ", 16))
	compressed, err := CompressBody(AlgorithmGzip, payload)
	if err != nil {
		t.Fatalf("compress gzip: %v", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("new gzip reader: %v", err)
	}
	got, err := io.ReadAll(gr)
	_ = gr.Close()
	if err != nil {
		t.Fatalf("read gzip body: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("gzip round trip changed payload")
	}
}

func TestMetricsSnapshotTracksAlgorithmsAndSkips(t *testing.T) {
	var metrics Metrics
	metrics.RecordCompressed(AlgorithmGzip, 100, 40)
	metrics.RecordSkipped(SkipClient)
	metrics.RecordSkipped(SkipMIME)

	status := metrics.Snapshot()
	if status.CompressedTotal != 1 || status.CompressedBytesIn != 100 || status.CompressedBytesOut != 40 {
		t.Fatalf("unexpected compression totals: %+v", status)
	}
	if status.CompressedByAlgorithm[AlgorithmGzip] != 1 {
		t.Fatalf("gzip total=%d want 1", status.CompressedByAlgorithm[AlgorithmGzip])
	}
	if status.SkippedClientTotal != 1 || status.SkippedMimeTotal != 1 {
		t.Fatalf("unexpected skipped totals: %+v", status)
	}
}
