package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corazaTypes "github.com/corazawaf/coraza/v3/types"
	"github.com/gin-gonic/gin"
)

type testRuleMetadata struct {
	id       int
	file     string
	line     int
	revision string
	version  string
	severity corazaTypes.RuleSeverity
	tags     []string
	maturity int
	accuracy int
	operator string
	phase    corazaTypes.RulePhase
	raw      string
	secMark  string
}

func (r testRuleMetadata) ID() int                            { return r.id }
func (r testRuleMetadata) File() string                       { return r.file }
func (r testRuleMetadata) Line() int                          { return r.line }
func (r testRuleMetadata) Revision() string                   { return r.revision }
func (r testRuleMetadata) Severity() corazaTypes.RuleSeverity { return r.severity }
func (r testRuleMetadata) Version() string                    { return r.version }
func (r testRuleMetadata) Tags() []string                     { return append([]string(nil), r.tags...) }
func (r testRuleMetadata) Maturity() int                      { return r.maturity }
func (r testRuleMetadata) Accuracy() int                      { return r.accuracy }
func (r testRuleMetadata) Operator() string                   { return r.operator }
func (r testRuleMetadata) Phase() corazaTypes.RulePhase       { return r.phase }
func (r testRuleMetadata) Raw() string                        { return r.raw }
func (r testRuleMetadata) SecMark() string                    { return r.secMark }

type testMatchedRule struct {
	message       string
	data          string
	disruptive    bool
	matchedDatas  []corazaTypes.MatchData
	rule          corazaTypes.RuleMetadata
	transactionID string
}

func (m testMatchedRule) Message() string         { return m.message }
func (m testMatchedRule) Data() string            { return m.data }
func (m testMatchedRule) URI() string             { return "/login" }
func (m testMatchedRule) TransactionID() string   { return m.transactionID }
func (m testMatchedRule) Disruptive() bool        { return m.disruptive }
func (m testMatchedRule) ServerIPAddress() string { return "127.0.0.1" }
func (m testMatchedRule) ClientIPAddress() string { return "203.0.113.10" }
func (m testMatchedRule) MatchedDatas() []corazaTypes.MatchData {
	return append([]corazaTypes.MatchData(nil), m.matchedDatas...)
}
func (m testMatchedRule) Rule() corazaTypes.RuleMetadata { return m.rule }
func (m testMatchedRule) AuditLog() string               { return "" }
func (m testMatchedRule) ErrorLog() string               { return "" }

func setSecurityAuditRuntimeForTest(t *testing.T, rt *securityAuditRuntime) {
	t.Helper()
	securityAuditMu.Lock()
	prev := securityAuditConfig
	securityAuditConfig = rt
	securityAuditMu.Unlock()

	prevWriter := securityAuditWriterInstance
	securityAuditWriterInstance = &securityAuditWriter{
		state: make(map[string]securityAuditStreamState),
	}

	t.Cleanup(func() {
		securityAuditMu.Lock()
		securityAuditConfig = prev
		securityAuditMu.Unlock()
		securityAuditWriterInstance = prevWriter
	})
}

func testSecurityAuditRuntime(tmp string) *securityAuditRuntime {
	return &securityAuditRuntime{
		Enabled:         true,
		CaptureMode:     securityAuditCaptureModeAllSecurityFinding,
		CaptureHeaders:  true,
		CaptureBody:     true,
		MaxBodyBytes:    4,
		RedactHeaders:   map[string]struct{}{"authorization": {}, "cookie": {}},
		EncryptionKey:   []byte("0123456789abcdef0123456789abcdef"),
		EncryptionKeyID: "enc-test",
		HMACKey:         []byte("0123456789abcdef0123456789abcdef"),
		HMACKeyID:       "sig-test",
		File:            filepath.Join(tmp, "security-audit.ndjson"),
		BlobDir:         filepath.Join(tmp, "blobs"),
	}
}

func TestPrepareSecurityAuditEvidencePreservesRequestBody(t *testing.T) {
	rt := testSecurityAuditRuntime(t.TempDir())
	setSecurityAuditRuntimeForTest(t, rt)

	req := httptest.NewRequest(http.MethodPost, "https://proxy.example.com/login", strings.NewReader("abcdef"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer secret-token")

	capture, err := prepareSecurityAuditEvidence(req)
	if err != nil {
		t.Fatalf("prepareSecurityAuditEvidence: %v", err)
	}
	if capture == nil {
		t.Fatal("expected capture")
	}
	if !capture.BodyCaptured || !capture.BodyTruncated {
		t.Fatalf("capture body flags = %+v", capture)
	}
	if string(capture.Body) != "abcd" {
		t.Fatalf("capture body=%q want=%q", string(capture.Body), "abcd")
	}
	if got := capture.Headers["Authorization"]; len(got) != 1 || got[0] != "[REDACTED]" {
		t.Fatalf("authorization header not redacted: %#v", got)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(body) != "abcdef" {
		t.Fatalf("restored body=%q want=%q", string(body), "abcdef")
	}
}

func TestSecurityAuditTrailFinalizeWritesSignedRecordAndEncryptedEvidence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	rt := testSecurityAuditRuntime(tmp)
	rt.MaxBodyBytes = 128
	setSecurityAuditRuntimeForTest(t, rt)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example.com/login?from=ui", strings.NewReader(`{"password":"secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	c.Request = req

	trail := newSecurityAuditTrail(c.Request, "req-1", "203.0.113.7", "JP")
	if trail == nil {
		t.Fatal("expected audit trail")
	}
	trail.recordCountryBlock(http.StatusForbidden, "JP")
	trail.setTerminal("country_block", "country_block", "blocked", http.StatusForbidden)
	c.Writer.WriteHeader(http.StatusForbidden)
	trail.Finalize(c)

	items, err := readSecurityAuditByReqID("req-1")
	if err != nil {
		t.Fatalf("readSecurityAuditByReqID: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items=%d want=1", len(items))
	}
	item := items[0]
	if item.FinalAction != "blocked" {
		t.Fatalf("final action=%q", item.FinalAction)
	}
	if item.Evidence == nil {
		t.Fatal("expected evidence metadata")
	}
	if item.Evidence.Cipher != securityAuditCipherAES256GCM {
		t.Fatalf("cipher=%q", item.Evidence.Cipher)
	}
	if item.Integrity.Sequence != 1 {
		t.Fatalf("sequence=%d", item.Integrity.Sequence)
	}

	blobPath := filepath.Join(rt.BlobDir, item.Evidence.StorageRef)
	rawBlob, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if bytes.Contains(rawBlob, []byte("secret")) {
		t.Fatalf("encrypted blob leaked plaintext: %s", string(rawBlob))
	}

	verify := verifySecurityAuditFile(rt.File)
	if !verify.OK {
		t.Fatalf("verify result = %+v", verify)
	}
}

func TestVerifySecurityAuditDetectsTampering(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	rt := testSecurityAuditRuntime(tmp)
	rt.CaptureBody = false
	setSecurityAuditRuntimeForTest(t, rt)

	record := &securityAuditRecord{
		Version:        1,
		TS:             "2026-04-02T00:00:00Z",
		Service:        "coraza",
		Event:          securityAuditEventName,
		DecisionID:     "dec-1",
		ReqID:          "req-2",
		Method:         http.MethodGet,
		Host:           "proxy.example.com",
		Path:           "/admin",
		FinalAction:    "blocked",
		FinalStatus:    http.StatusForbidden,
		TerminalPolicy: "waf",
		TerminalEvent:  "waf_block",
	}
	if err := securityAuditWriterInstance.Append(rt, record); err != nil {
		t.Fatalf("append record: %v", err)
	}
	okResult := verifySecurityAuditFile(rt.File)
	if !okResult.OK {
		t.Fatalf("initial verify=%+v", okResult)
	}

	raw, err := os.ReadFile(rt.File)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	idx := bytes.Index(raw, []byte(`"signature":"`))
	if idx < 0 {
		t.Fatalf("signature field missing: %s", string(raw))
	}
	raw[idx+13] = '0'
	if err := os.WriteFile(rt.File, raw, 0o644); err != nil {
		t.Fatalf("rewrite tampered file: %v", err)
	}

	bad := verifySecurityAuditFile(rt.File)
	if bad.OK {
		t.Fatalf("expected verify failure, got %+v", bad)
	}
}

func TestVerifySecurityAuditDetectsTailTruncation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	rt := testSecurityAuditRuntime(tmp)
	rt.CaptureBody = false
	setSecurityAuditRuntimeForTest(t, rt)

	records := []*securityAuditRecord{
		{
			Version:        1,
			TS:             "2026-04-02T00:00:00Z",
			Service:        "coraza",
			Event:          securityAuditEventName,
			DecisionID:     "dec-tail-1",
			ReqID:          "req-tail-1",
			Method:         http.MethodGet,
			Host:           "proxy.example.com",
			Path:           "/one",
			FinalAction:    "blocked",
			FinalStatus:    http.StatusForbidden,
			TerminalPolicy: "waf",
			TerminalEvent:  "waf_block",
		},
		{
			Version:        1,
			TS:             "2026-04-02T00:00:01Z",
			Service:        "coraza",
			Event:          securityAuditEventName,
			DecisionID:     "dec-tail-2",
			ReqID:          "req-tail-2",
			Method:         http.MethodGet,
			Host:           "proxy.example.com",
			Path:           "/two",
			FinalAction:    "blocked",
			FinalStatus:    http.StatusForbidden,
			TerminalPolicy: "waf",
			TerminalEvent:  "waf_block",
		},
	}
	for _, record := range records {
		if err := securityAuditWriterInstance.Append(rt, record); err != nil {
			t.Fatalf("append record: %v", err)
		}
	}
	okResult := verifySecurityAuditFile(rt.File)
	if !okResult.OK || okResult.LastSeq != 2 {
		t.Fatalf("initial verify=%+v", okResult)
	}

	raw, err := os.ReadFile(rt.File)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	lines := bytesSplitKeep(raw, '\n')
	if len(lines) < 2 {
		t.Fatalf("expected >=2 lines, got %d", len(lines))
	}
	if err := os.WriteFile(rt.File, lines[0], 0o644); err != nil {
		t.Fatalf("truncate audit file: %v", err)
	}

	bad := verifySecurityAuditFile(rt.File)
	if bad.OK {
		t.Fatalf("expected tail anchor failure, got %+v", bad)
	}
	if !strings.Contains(bad.Error, "tail anchor") {
		t.Fatalf("unexpected tail truncation error: %+v", bad)
	}
}

func TestVerifySecurityAuditRejectsInvalidFinalLine(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	rt := testSecurityAuditRuntime(tmp)
	rt.CaptureBody = false
	setSecurityAuditRuntimeForTest(t, rt)

	record := &securityAuditRecord{
		Version:        1,
		TS:             "2026-04-02T00:00:00Z",
		Service:        "coraza",
		Event:          securityAuditEventName,
		DecisionID:     "dec-invalid-tail",
		ReqID:          "req-invalid-tail",
		Method:         http.MethodGet,
		Host:           "proxy.example.com",
		Path:           "/audit",
		FinalAction:    "blocked",
		FinalStatus:    http.StatusForbidden,
		TerminalPolicy: "waf",
		TerminalEvent:  "waf_block",
	}
	if err := securityAuditWriterInstance.Append(rt, record); err != nil {
		t.Fatalf("append record: %v", err)
	}
	if err := os.WriteFile(rt.File, []byte("{not-json}\n"), 0o644); err != nil {
		t.Fatalf("rewrite invalid audit file: %v", err)
	}

	bad := verifySecurityAuditFile(rt.File)
	if bad.OK {
		t.Fatalf("expected decode failure, got %+v", bad)
	}
	if !strings.Contains(bad.Error, "decode security audit entry") {
		t.Fatalf("unexpected invalid line error: %+v", bad)
	}
}

func TestRecordWAFBlockLinksMatchedRules(t *testing.T) {
	trail := &securityAuditTrail{}
	matches := []corazaTypes.MatchedRule{
		testMatchedRule{
			disruptive: false,
			rule: testRuleMetadata{
				id:       942100,
				file:     "rules/crs/request-942.conf",
				line:     88,
				severity: corazaTypes.RuleSeverityCritical,
				tags:     []string{"attack-sqli", "paranoia-level/1"},
				operator: "@rx",
				phase:    corazaTypes.PhaseRequestBody,
			},
		},
		testMatchedRule{
			disruptive: true,
			rule: testRuleMetadata{
				id:       949110,
				file:     "rules/crs/request-949.conf",
				line:     42,
				severity: corazaTypes.RuleSeverityCritical,
				tags:     []string{"anomaly-evaluation"},
				operator: "@gt",
				phase:    corazaTypes.PhaseRequestBody,
			},
		},
	}

	steps := trail.recordWAFMatches(matches)
	blockStep := trail.recordWAFBlock(949110, http.StatusForbidden, steps)
	if blockStep != 3 {
		t.Fatalf("block step=%d want=3", blockStep)
	}
	if len(trail.Nodes) != 3 {
		t.Fatalf("node count=%d want=3", len(trail.Nodes))
	}
	if trail.Nodes[0].RuleID != "942100" || trail.Nodes[0].ActionEffective != "observe" {
		t.Fatalf("first waf node=%+v", trail.Nodes[0])
	}
	if trail.Nodes[1].RuleID != "949110" || trail.Nodes[1].ActionEffective != "block" {
		t.Fatalf("second waf node=%+v", trail.Nodes[1])
	}
	if got := trail.Nodes[2].DependsOn; len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("terminal depends_on=%v want=[1 2]", got)
	}
}

func TestSecurityAuditHandlersExposeRecordAndEvidenceMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	rt := testSecurityAuditRuntime(tmp)
	setSecurityAuditRuntimeForTest(t, rt)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example.com/login", strings.NewReader("hello"))
	req.Header.Set("Content-Type", "text/plain")
	c.Request = req

	trail := newSecurityAuditTrail(c.Request, "req-3", "203.0.113.8", "US")
	trail.recordCountryBlock(http.StatusForbidden, "US")
	trail.setTerminal("country_block", "country_block", "blocked", http.StatusForbidden)
	c.Writer.WriteHeader(http.StatusForbidden)
	trail.Finalize(c)

	getRec := httptest.NewRecorder()
	getCtx, _ := gin.CreateTestContext(getRec)
	getCtx.Request = httptest.NewRequest(http.MethodGet, "/logs/security-audit?req_id=req-3", nil)
	q := getCtx.Request.URL.Query()
	q.Set("req_id", "req-3")
	getCtx.Request.URL.RawQuery = q.Encode()
	GetSecurityAudit(getCtx)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GetSecurityAudit code=%d body=%s", getRec.Code, getRec.Body.String())
	}
	var payload struct {
		Items []securityAuditRecord `json:"items"`
		Count int                   `json:"count"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode audit payload: %v", err)
	}
	if payload.Count != 1 || len(payload.Items) != 1 {
		t.Fatalf("payload=%+v", payload)
	}
	if payload.Items[0].Evidence == nil {
		t.Fatal("expected evidence in audit response")
	}

	metaRec := httptest.NewRecorder()
	metaCtx, _ := gin.CreateTestContext(metaRec)
	metaCtx.Params = gin.Params{{Key: "capture_id", Value: payload.Items[0].Evidence.CaptureID}}
	metaCtx.Request = httptest.NewRequest(http.MethodGet, "/logs/security-audit/evidence/id/metadata", nil)
	GetSecurityAuditEvidenceMetadata(metaCtx)
	if metaRec.Code != http.StatusOK {
		t.Fatalf("GetSecurityAuditEvidenceMetadata code=%d body=%s", metaRec.Code, metaRec.Body.String())
	}
}
