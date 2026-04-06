package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(v string) error {
	*h = append(*h, v)
	return nil
}

type requestResult struct {
	Latency time.Duration
	Status  int
	Err     string
}

type latencySummary struct {
	Count  int     `json:"count"`
	MinMS  float64 `json:"min_ms"`
	MeanMS float64 `json:"mean_ms"`
	P50MS  float64 `json:"p50_ms"`
	P95MS  float64 `json:"p95_ms"`
	P99MS  float64 `json:"p99_ms"`
	MaxMS  float64 `json:"max_ms"`
}

type benchReport struct {
	URL                string         `json:"url"`
	Method             string         `json:"method"`
	Concurrency        int            `json:"concurrency"`
	DurationSec        float64        `json:"duration_sec"`
	TimeoutSec         float64        `json:"timeout_sec"`
	ExpectedStatus     int            `json:"expected_status,omitempty"`
	StartedAt          string         `json:"started_at"`
	FinishedAt         string         `json:"finished_at"`
	ElapsedSec         float64        `json:"elapsed_sec"`
	Attempts           int            `json:"attempts"`
	Responses          int            `json:"responses"`
	NetworkErrors      int            `json:"network_errors"`
	UnexpectedStatuses int            `json:"unexpected_statuses"`
	ErrorRate          float64        `json:"error_rate"`
	RequestsPerSec     float64        `json:"requests_per_sec"`
	StatusCodes        map[string]int `json:"status_codes"`
	Latencies          latencySummary `json:"latencies"`
}

func main() {
	var (
		rawURL       string
		method       string
		durationText string
		timeoutText  string
		body         string
		concurrency  int
		expected     int
		insecureTLS  bool
		headers      headerFlags
	)

	flag.StringVar(&rawURL, "url", "", "request URL")
	flag.StringVar(&method, "method", http.MethodGet, "HTTP method")
	flag.StringVar(&durationText, "duration", "10s", "benchmark duration")
	flag.StringVar(&timeoutText, "timeout", "5s", "per-request timeout")
	flag.StringVar(&body, "body", "", "request body")
	flag.IntVar(&concurrency, "concurrency", 10, "number of concurrent workers")
	flag.IntVar(&expected, "expect-status", 0, "expected HTTP status code (0 disables mismatch counting)")
	flag.BoolVar(&insecureTLS, "insecure-tls", false, "skip TLS certificate verification")
	flag.Var(&headers, "H", "header in 'Name: value' form; may be repeated")
	flag.Parse()

	if strings.TrimSpace(rawURL) == "" {
		fatalf("missing -url")
	}
	if concurrency < 1 {
		fatalf("concurrency must be >= 1")
	}

	duration, err := time.ParseDuration(durationText)
	if err != nil || duration <= 0 {
		fatalf("invalid -duration: %q", durationText)
	}
	timeout, err := time.ParseDuration(timeoutText)
	if err != nil || timeout <= 0 {
		fatalf("invalid -timeout: %q", timeoutText)
	}

	headerMap, hostHeader := parseHeaders(headers)
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConns:        concurrency * 4,
			MaxIdleConnsPerHost: concurrency * 4,
			IdleConnTimeout:     30 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecureTLS}, //nolint:gosec
		},
	}

	startedAt := time.Now().UTC()
	deadline := startedAt.Add(duration)
	results := make(chan requestResult, concurrency*8)
	var attempts int64
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				atomic.AddInt64(&attempts, 1)
				result := doRequest(client, rawURL, method, body, headerMap, hostHeader)
				results <- result
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	statusCodes := map[string]int{}
	latencies := make([]float64, 0, 1024)
	responses := 0
	networkErrors := 0
	unexpectedStatuses := 0

	for result := range results {
		if result.Err != "" {
			networkErrors++
			continue
		}
		responses++
		latencies = append(latencies, float64(result.Latency)/float64(time.Millisecond))
		statusCodes[fmt.Sprintf("%d", result.Status)]++
		if expected > 0 && result.Status != expected {
			unexpectedStatuses++
		}
	}

	finishedAt := time.Now().UTC()
	elapsed := finishedAt.Sub(startedAt)
	attemptCount := int(atomic.LoadInt64(&attempts))
	if elapsed <= 0 {
		elapsed = time.Millisecond
	}

	report := benchReport{
		URL:                rawURL,
		Method:             strings.ToUpper(method),
		Concurrency:        concurrency,
		DurationSec:        duration.Seconds(),
		TimeoutSec:         timeout.Seconds(),
		ExpectedStatus:     expected,
		StartedAt:          startedAt.Format(time.RFC3339Nano),
		FinishedAt:         finishedAt.Format(time.RFC3339Nano),
		ElapsedSec:         elapsed.Seconds(),
		Attempts:           attemptCount,
		Responses:          responses,
		NetworkErrors:      networkErrors,
		UnexpectedStatuses: unexpectedStatuses,
		ErrorRate:          ratio(networkErrors+unexpectedStatuses, attemptCount),
		RequestsPerSec:     float64(responses) / elapsed.Seconds(),
		StatusCodes:        statusCodes,
		Latencies:          summarizeLatencies(latencies),
	}

	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fatalf("encode report: %v", err)
	}
}

func doRequest(client *http.Client, rawURL, method, body string, headers http.Header, hostHeader string) requestResult {
	req, err := http.NewRequest(strings.ToUpper(method), rawURL, bytes.NewBufferString(body))
	if err != nil {
		return requestResult{Err: err.Error()}
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if hostHeader != "" {
		req.Host = hostHeader
	}

	started := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(started)
	if err != nil {
		return requestResult{Latency: latency, Err: err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	return requestResult{Latency: latency, Status: resp.StatusCode}
}

func parseHeaders(values []string) (http.Header, string) {
	out := http.Header{}
	hostHeader := ""
	for _, raw := range values {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			fatalf("invalid header %q: want 'Name: value'", raw)
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if name == "" {
			fatalf("invalid header %q: empty name", raw)
		}
		if strings.EqualFold(name, "Host") {
			hostHeader = value
			continue
		}
		out.Add(name, value)
	}
	return out, hostHeader
}

func summarizeLatencies(values []float64) latencySummary {
	if len(values) == 0 {
		return latencySummary{}
	}
	sort.Float64s(values)
	sum := 0.0
	for _, value := range values {
		sum += value
	}
	return latencySummary{
		Count:  len(values),
		MinMS:  roundMillis(values[0]),
		MeanMS: roundMillis(sum / float64(len(values))),
		P50MS:  roundMillis(percentile(values, 0.50)),
		P95MS:  roundMillis(percentile(values, 0.95)),
		P99MS:  roundMillis(percentile(values, 0.99)),
		MaxMS:  roundMillis(values[len(values)-1]),
	}
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	if p <= 0 {
		return values[0]
	}
	if p >= 1 {
		return values[len(values)-1]
	}
	idx := int(math.Ceil(float64(len(values))*p)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return values[idx]
}

func ratio(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func roundMillis(v float64) float64 {
	return math.Round(v*1000) / 1000
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
