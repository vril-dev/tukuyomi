package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"tukuyomi/internal/config"
)

func newRequestBodyTestEngine(t *testing.T) corazaEngine {
	t.Helper()
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "test.conf")
	mustWrite(t, rulePath, `
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS|ARGS_NAMES|FILES|FILES_NAMES "@rx (?i)<script>" "id:100001,phase:2,deny,status:403,log,msg:'block-xss'"
SecRule XML:/* "@rx evil-xml" "id:100002,phase:2,deny,status:403,log,msg:'block-xml'"
`)
	w, err := buildWAF([]string{rulePath})
	if err != nil {
		t.Fatalf("buildWAF() error = %v", err)
	}
	return corazaEngine{w: w}
}

func setRequestBodyPolicy(t *testing.T, mode string, limit int64, oversize string) {
	t.Helper()
	prevMode, prevLimit, prevOversize := config.WAFRequestBodyMode, config.WAFRequestBodyInspectLimitBytes, config.WAFRequestBodyOversizeAction
	t.Cleanup(func() {
		config.WAFRequestBodyMode = prevMode
		config.WAFRequestBodyInspectLimitBytes = prevLimit
		config.WAFRequestBodyOversizeAction = prevOversize
	})
	config.WAFRequestBodyMode = mode
	config.WAFRequestBodyInspectLimitBytes = limit
	config.WAFRequestBodyOversizeAction = oversize
}

func newBodyRequest(contentType, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/form", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	return req
}

func readForwardedBody(t *testing.T, req *http.Request) string {
	t.Helper()
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read forwarded body: %v", err)
	}
	return string(got)
}

const multipartScriptField = "--XX\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n<script>\r\n--XX--\r\n"

func TestRequestBodyEnforceBlocksSupportedContentTypes(t *testing.T) {
	setRequestBodyPolicy(t, config.WAFRequestBodyModeEnforce, config.DefaultWAFRequestBodyInspectLimit, config.WAFRequestBodyOversizeInspectPrefix)
	e := newRequestBodyTestEngine(t)
	cases := []struct {
		name, contentType, body string
		ruleID                  int
	}{
		{"urlencoded", "application/x-www-form-urlencoded", "q=%3Cscript%3E", 100001},
		{"multipart field", "multipart/form-data; boundary=XX", multipartScriptField, 100001},
		{"multipart filename", "multipart/form-data; boundary=XX", "--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"<script>.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--XX--\r\n", 100001},
		{"json", "application/json; charset=utf-8", `{"q":"<script>"}`, 100001},
		{"json suffix", "application/problem+json", `{"q":"<script>"}`, 100001},
		{"xml", "application/xml", `<r><a>evil-xml</a></r>`, 100002},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newBodyRequest(tc.contentType, tc.body)
			d, err := e.InspectRequest(req)
			if err != nil {
				t.Fatalf("InspectRequest() error = %v", err)
			}
			if d.Interruption == nil || d.Interruption.RuleID != tc.ruleID || d.Interruption.Status != http.StatusForbidden {
				t.Fatalf("interruption = %+v, want rule %d status 403", d.Interruption, tc.ruleID)
			}
			if !d.RequestBody.Inspected || d.RequestBody.Bytes != len(tc.body) {
				t.Fatalf("request body result = %+v", d.RequestBody)
			}
			if got := readForwardedBody(t, req); got != tc.body {
				t.Fatalf("forwarded body = %q, want %q", got, tc.body)
			}
		})
	}
}

func TestRequestBodyBenignBodiesPassAndAreForwardedIntact(t *testing.T) {
	setRequestBodyPolicy(t, config.WAFRequestBodyModeEnforce, config.DefaultWAFRequestBodyInspectLimit, config.WAFRequestBodyOversizeInspectPrefix)
	e := newRequestBodyTestEngine(t)
	cases := []struct{ contentType, body string }{
		{"application/x-www-form-urlencoded", "name=alice&comment=hello"},
		{"application/json", `{"name":"alice","tags":["a","b"]}`},
		{"multipart/form-data; boundary=XX", "--XX\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nalice\r\n--XX--\r\n"},
		{"text/plain", "<script> is not parsed for text/plain"},
		{"application/octet-stream", "<script>"},
	}
	for _, tc := range cases {
		req := newBodyRequest(tc.contentType, tc.body)
		d, err := e.InspectRequest(req)
		if err != nil {
			t.Fatalf("%s: InspectRequest() error = %v", tc.contentType, err)
		}
		if d.Interruption != nil || d.RequestBody.DryRun != nil {
			t.Fatalf("%s: unexpected block %+v / %+v", tc.contentType, d.Interruption, d.RequestBody.DryRun)
		}
		if got := readForwardedBody(t, req); got != tc.body {
			t.Fatalf("%s: forwarded body = %q", tc.contentType, got)
		}
	}
}

func TestRequestBodyOffModeKeepsBodyUninspected(t *testing.T) {
	setRequestBodyPolicy(t, config.WAFRequestBodyModeOff, config.DefaultWAFRequestBodyInspectLimit, config.WAFRequestBodyOversizeInspectPrefix)
	e := newRequestBodyTestEngine(t)
	req := newBodyRequest("application/x-www-form-urlencoded", "q=%3Cscript%3E")
	d, err := e.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if d.Interruption != nil || d.RequestBody.Inspected {
		t.Fatalf("off mode inspected the body: %+v %+v", d.Interruption, d.RequestBody)
	}
	if got := readForwardedBody(t, req); got != "q=%3Cscript%3E" {
		t.Fatalf("forwarded body = %q", got)
	}
}

func TestRequestBodyDetectModeRecordsBodyOnlyBlocks(t *testing.T) {
	setRequestBodyPolicy(t, config.WAFRequestBodyModeDetect, config.DefaultWAFRequestBodyInspectLimit, config.WAFRequestBodyOversizeInspectPrefix)
	e := newRequestBodyTestEngine(t)

	req := newBodyRequest("application/x-www-form-urlencoded", "q=%3Cscript%3E")
	d, err := e.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if d.Interruption != nil {
		t.Fatalf("detect mode blocked a body-only match: %+v", d.Interruption)
	}
	if d.RequestBody.DryRun == nil || d.RequestBody.DryRun.RuleID != 100001 || d.RequestBody.Reason != requestBodyReasonRule {
		t.Fatalf("dry run = %+v reason=%q", d.RequestBody.DryRun, d.RequestBody.Reason)
	}

	query := httptest.NewRequest(http.MethodPost, "http://example.test/form?x=%3Cscript%3E", strings.NewReader("q=%3Cscript%3E"))
	query.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	d, err = e.InspectRequest(query)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if d.Interruption == nil || d.RequestBody.DryRun != nil {
		t.Fatalf("detect mode must still enforce non-body matches: %+v %+v", d.Interruption, d.RequestBody.DryRun)
	}
}

func TestRequestBodyOversizeInspectsPrefixAndForwardsAll(t *testing.T) {
	setRequestBodyPolicy(t, config.WAFRequestBodyModeEnforce, 1024, config.WAFRequestBodyOversizeInspectPrefix)
	e := newRequestBodyTestEngine(t)

	tail := "q=%3Cscript%3E&pad=" + strings.Repeat("a", 2048)
	req := newBodyRequest("application/x-www-form-urlencoded", tail)
	d, err := e.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if d.Interruption == nil || d.Interruption.RuleID != 100001 || !d.RequestBody.Truncated {
		t.Fatalf("prefix attack: interruption=%+v body=%+v", d.Interruption, d.RequestBody)
	}

	late := "pad=" + strings.Repeat("a", 2048) + "&q=%3Cscript%3E"
	req = newBodyRequest("application/x-www-form-urlencoded", late)
	d, err = e.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if d.Interruption != nil || !d.RequestBody.Truncated || d.RequestBody.Bytes != 1024 {
		t.Fatalf("beyond-limit payload: interruption=%+v body=%+v", d.Interruption, d.RequestBody)
	}
	if got := readForwardedBody(t, req); got != late {
		t.Fatalf("forwarded %d bytes, want %d", len(got), len(late))
	}

	truncatedJSON := `{"pad":"` + strings.Repeat("a", 2048) + `"}`
	req = newBodyRequest("application/json", truncatedJSON)
	d, err = e.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if d.Interruption != nil || d.RequestBody.DryRun != nil {
		t.Fatalf("truncated JSON must not be treated as a parse error: %+v %+v", d.Interruption, d.RequestBody.DryRun)
	}

	truncatedMultipart := "--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n" + strings.Repeat("A", 4096) + "\r\n--XX--\r\n"
	req = newBodyRequest("multipart/form-data; boundary=XX", truncatedMultipart)
	d, err = e.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if d.Interruption != nil || !d.RequestBody.Truncated {
		t.Fatalf("truncated multipart must pass: %+v %+v", d.Interruption, d.RequestBody)
	}
	if got := readForwardedBody(t, req); got != truncatedMultipart {
		t.Fatalf("multipart forwarded %d bytes, want %d", len(got), len(truncatedMultipart))
	}
}

func TestRequestBodyOversizeReject(t *testing.T) {
	setRequestBodyPolicy(t, config.WAFRequestBodyModeEnforce, 1024, config.WAFRequestBodyOversizeReject)
	e := newRequestBodyTestEngine(t)
	body := "pad=" + strings.Repeat("a", 2048)

	req := newBodyRequest("application/x-www-form-urlencoded", body)
	d, err := e.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if d.Interruption == nil || d.Interruption.Status != http.StatusRequestEntityTooLarge || d.RequestBody.Reason != requestBodyReasonOversize {
		t.Fatalf("known length: interruption=%+v body=%+v", d.Interruption, d.RequestBody)
	}
	if got := readForwardedBody(t, req); got != body {
		t.Fatalf("known-length oversize body was consumed before rejecting")
	}

	chunked := newBodyRequest("application/x-www-form-urlencoded", body)
	chunked.ContentLength = -1
	d, err = e.InspectRequest(chunked)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if d.Interruption == nil || d.Interruption.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("unknown length: interruption=%+v body=%+v", d.Interruption, d.RequestBody)
	}

	setRequestBodyPolicy(t, config.WAFRequestBodyModeDetect, 1024, config.WAFRequestBodyOversizeReject)
	req = newBodyRequest("application/x-www-form-urlencoded", body)
	d, err = e.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if d.Interruption != nil || d.RequestBody.DryRun == nil || d.RequestBody.DryRun.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("detect oversize: interruption=%+v dry=%+v", d.Interruption, d.RequestBody.DryRun)
	}
}

func TestRequestBodyMalformedBodiesAreRejected(t *testing.T) {
	setRequestBodyPolicy(t, config.WAFRequestBodyModeEnforce, config.DefaultWAFRequestBodyInspectLimit, config.WAFRequestBodyOversizeInspectPrefix)
	e := newRequestBodyTestEngine(t)
	cases := []struct {
		name, contentType, body string
		ruleID                  int
	}{
		{"invalid json", "application/json", `{"q":`, requestBodyRuleBodyError},
		{"unterminated multipart", "multipart/form-data; boundary=XX", "--XX\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nvalue", requestBodyRuleMultipartStrict},
	}
	for _, tc := range cases {
		req := newBodyRequest(tc.contentType, tc.body)
		d, err := e.InspectRequest(req)
		if err != nil {
			t.Fatalf("%s: InspectRequest() error = %v", tc.name, err)
		}
		if d.Interruption == nil || d.Interruption.Status != http.StatusBadRequest || d.RequestBody.Reason != requestBodyReasonParseError {
			t.Fatalf("%s: interruption=%+v body=%+v", tc.name, d.Interruption, d.RequestBody)
		}
	}
}

func TestRequestBodyArgumentsLimit(t *testing.T) {
	setRequestBodyPolicy(t, config.WAFRequestBodyModeEnforce, config.DefaultWAFRequestBodyInspectLimit, config.WAFRequestBodyOversizeInspectPrefix)
	e := newRequestBodyTestEngine(t)
	query := func(n int) string {
		parts := make([]string, 0, n)
		for i := 0; i < n; i++ {
			parts = append(parts, "a"+strconv.Itoa(i)+"=1")
		}
		return strings.Join(parts, "&")
	}

	d, err := e.InspectRequest(httptest.NewRequest(http.MethodGet, "http://example.test/?"+query(1000), nil))
	if err != nil || d.Interruption != nil {
		t.Fatalf("1000 arguments: err=%v interruption=%+v", err, d.Interruption)
	}
	d, err = e.InspectRequest(httptest.NewRequest(http.MethodGet, "http://example.test/?"+query(1001), nil))
	if err != nil || d.Interruption == nil || d.Interruption.RuleID != requestBodyRuleArgumentsLimit || d.Interruption.Status != http.StatusBadRequest {
		t.Fatalf("1001 query arguments: err=%v interruption=%+v", err, d.Interruption)
	}
	req := newBodyRequest("application/x-www-form-urlencoded", query(1001))
	d, err = e.InspectRequest(req)
	if err != nil || d.Interruption == nil || d.RequestBody.Reason != requestBodyReasonArgumentsLimit {
		t.Fatalf("1001 body arguments: err=%v interruption=%+v body=%+v", err, d.Interruption, d.RequestBody)
	}

	setRequestBodyPolicy(t, config.WAFRequestBodyModeOff, config.DefaultWAFRequestBodyInspectLimit, config.WAFRequestBodyOversizeInspectPrefix)
	d, err = e.InspectRequest(httptest.NewRequest(http.MethodGet, "http://example.test/?"+query(1001), nil))
	if err != nil || d.Interruption != nil {
		t.Fatalf("off mode keeps the previous argument behavior: err=%v interruption=%+v", err, d.Interruption)
	}
}

func TestRequestBodyBuiltinRulesAreHiddenFromMatches(t *testing.T) {
	setRequestBodyPolicy(t, config.WAFRequestBodyModeEnforce, config.DefaultWAFRequestBodyInspectLimit, config.WAFRequestBodyOversizeInspectPrefix)
	e := newRequestBodyTestEngine(t)
	d, err := e.InspectRequest(newBodyRequest("application/json", `{"name":"alice"}`))
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	for _, m := range d.Matches {
		if m.RuleID >= requestBodyRuleIDMin && m.RuleID <= requestBodyRuleIDMax {
			t.Fatalf("built-in rule %d leaked into matches", m.RuleID)
		}
	}
}

type countingReplayBody struct {
	r      io.Reader
	read   int
	replay []byte
}

func (b *countingReplayBody) Read(p []byte) (int, error) {
	if len(b.replay) > 0 {
		n := copy(p, b.replay)
		b.replay = b.replay[n:]
		return n, nil
	}
	n, err := b.r.Read(p)
	b.read += n
	return n, err
}

func (b *countingReplayBody) Close() error { return nil }

func (b *countingReplayBody) ReplayRequestBodyPrefix(prefix []byte) {
	b.replay = append(append([]byte(nil), prefix...), b.replay...)
}

func TestRequestBodyReplayerKeepsBodyWrapper(t *testing.T) {
	setRequestBodyPolicy(t, config.WAFRequestBodyModeEnforce, config.DefaultWAFRequestBodyInspectLimit, config.WAFRequestBodyOversizeInspectPrefix)
	e := newRequestBodyTestEngine(t)
	body := "name=alice"
	wrapper := &countingReplayBody{r: strings.NewReader(body)}
	req := newBodyRequest("application/x-www-form-urlencoded", body)
	req.Body = wrapper
	if _, err := e.InspectRequest(req); err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if req.Body != wrapper {
		t.Fatalf("request body wrapper was replaced")
	}
	if got := readForwardedBody(t, req); got != body || wrapper.read != len(body) {
		t.Fatalf("forwarded=%q counted=%d, want %q counted %d", got, wrapper.read, body, len(body))
	}
}

func BenchmarkRequestBodyInspection128KiB(b *testing.B) {
	prevMode, prevLimit, prevOversize := config.WAFRequestBodyMode, config.WAFRequestBodyInspectLimitBytes, config.WAFRequestBodyOversizeAction
	b.Cleanup(func() {
		config.WAFRequestBodyMode = prevMode
		config.WAFRequestBodyInspectLimitBytes = prevLimit
		config.WAFRequestBodyOversizeAction = prevOversize
	})
	config.WAFRequestBodyMode = config.WAFRequestBodyModeEnforce
	config.WAFRequestBodyInspectLimitBytes = config.DefaultWAFRequestBodyInspectLimit
	config.WAFRequestBodyOversizeAction = config.WAFRequestBodyOversizeInspectPrefix

	dir := b.TempDir()
	rulePath := filepath.Join(dir, "bench.conf")
	if err := os.WriteFile(rulePath, []byte("SecRuleEngine On\nSecRule ARGS \"@rx (?i)<script>\" \"id:100001,phase:2,deny,status:403,log\"\n"), 0o600); err != nil {
		b.Fatal(err)
	}
	w, err := buildWAF([]string{rulePath})
	if err != nil {
		b.Fatal(err)
	}
	e := corazaEngine{w: w}
	body := "name=alice&pad=" + strings.Repeat("a", int(config.DefaultWAFRequestBodyInspectLimit)*2)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := newBodyRequest("application/x-www-form-urlencoded", body)
		if _, err := e.InspectRequest(req); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRequestBodyRouteOverride(t *testing.T) {
	setRequestBodyPolicy(t, config.WAFRequestBodyModeEnforce, 1024, config.WAFRequestBodyOversizeReject)
	base := newRequestBodyTestEngine(t)

	skip := WithRequestBodyOverride(base, RequestBodyOverride{Skip: true})
	body := "q=%3Cscript%3E&pad=" + strings.Repeat("a", 4096)
	req := newBodyRequest("application/x-www-form-urlencoded", body)
	d, err := skip.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if d.Interruption != nil || d.RequestBody.Inspected {
		t.Fatalf("skip override must neither inspect nor reject oversize: %+v %+v", d.Interruption, d.RequestBody)
	}
	if got := readForwardedBody(t, req); got != body {
		t.Fatalf("skip override changed the forwarded body")
	}
	query := httptest.NewRequest(http.MethodGet, "http://example.test/?q=%3Cscript%3E", nil)
	if d, err := skip.InspectRequest(query); err != nil || d.Interruption == nil {
		t.Fatalf("skip override must still inspect the query: err=%v interruption=%+v", err, d.Interruption)
	}

	late := "pad=" + strings.Repeat("a", 2048) + "&q=%3Cscript%3E"
	larger := WithRequestBodyOverride(base, RequestBodyOverride{InspectLimitBytes: 8192})
	d, err = larger.InspectRequest(newBodyRequest("application/x-www-form-urlencoded", late))
	if err != nil || d.Interruption == nil || d.Interruption.RuleID != 100001 {
		t.Fatalf("raised limit must inspect the late payload: err=%v interruption=%+v", err, d.Interruption)
	}
	d, err = base.InspectRequest(newBodyRequest("application/x-www-form-urlencoded", late))
	if err != nil || d.Interruption == nil || d.Interruption.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("global policy must still reject the oversize body: err=%v interruption=%+v", err, d.Interruption)
	}
}
