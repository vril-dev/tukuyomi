package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/config"
)

func containsExactString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func testScopedFPTunerRuleLine(host, scheme, path string, ruleID int, variable string) string {
	scope := buildFPTunerHostScope(host, scheme)
	return fmt.Sprintf(
		"SecRule REQUEST_HEADERS:Host \"@%s %s\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith %s\" \"ctl:ruleRemoveTargetById=%d;%s\"",
		scope.Operator, scope.Operand, path, ruleID, variable,
	)
}

func TestDecodeFPTunerProviderResponseWrapped(t *testing.T) {
	raw := []byte(`{"proposal":{"id":"fp-1","summary":"ok","rule_line":"SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""}}`)

	decision, err := decodeFPTunerProviderResponse(raw)
	if err != nil {
		t.Fatalf("decodeFPTunerProviderResponse wrapped error: %v", err)
	}
	if decision.Proposal == nil {
		t.Fatal("proposal is nil")
	}
	if decision.Proposal.ID != "fp-1" {
		t.Fatalf("proposal.ID=%q want=fp-1", decision.Proposal.ID)
	}
}

func TestDecodeFPTunerProviderResponseDirect(t *testing.T) {
	raw := []byte(`{"id":"fp-2","summary":"ok","rule_line":"SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""}`)

	decision, err := decodeFPTunerProviderResponse(raw)
	if err != nil {
		t.Fatalf("decodeFPTunerProviderResponse direct error: %v", err)
	}
	if decision.Proposal == nil {
		t.Fatal("proposal is nil")
	}
	if decision.Proposal.ID != "fp-2" {
		t.Fatalf("proposal.ID=%q want=fp-2", decision.Proposal.ID)
	}
}

func TestDecodeFPTunerProviderResponseNoProposal(t *testing.T) {
	raw := []byte(`{"decision":"no_proposal","reason":"Looks like a real attack payload, not a credible false positive.","confidence":0.1}`)

	decision, err := decodeFPTunerProviderResponse(raw)
	if err != nil {
		t.Fatalf("decodeFPTunerProviderResponse no_proposal error: %v", err)
	}
	if decision.NoProposal == nil {
		t.Fatal("no_proposal is nil")
	}
	if decision.NoProposal.Decision != "no_proposal" {
		t.Fatalf("decision=%q want=no_proposal", decision.NoProposal.Decision)
	}
	if !strings.Contains(decision.NoProposal.Reason, "real attack payload") {
		t.Fatalf("reason=%q", decision.NoProposal.Reason)
	}
}

func TestBuildFPTunerRuleLine(t *testing.T) {
	line := buildFPTunerRuleLine(fpTunerEventInput{
		Scheme:          "http",
		Host:            "search.example.com",
		Path:            "/search",
		RuleID:          100004,
		MatchedVariable: "ARGS:q",
	})

	if !strings.Contains(line, "ctl:ruleRemoveTargetById=100004;ARGS:q") {
		t.Fatalf("rule line missing ctl fragment: %s", line)
	}
	if !strings.Contains(line, `SecRule REQUEST_HEADERS:Host "@rx ^search\.example\.com(:80)?$"`) {
		t.Fatalf("unexpected rule line host scope: %s", line)
	}
	if !strings.Contains(line, `SecRule REQUEST_URI "@beginsWith /search"`) {
		t.Fatalf("unexpected rule line path scope: %s", line)
	}
}

func TestBuildFPTunerRuleLineKeepsExactHostForNonDefaultPort(t *testing.T) {
	line := buildFPTunerRuleLine(fpTunerEventInput{
		Scheme:          "https",
		Host:            "search.example.com:8443",
		Path:            "/search",
		RuleID:          100004,
		MatchedVariable: "ARGS:q",
	})

	if !strings.Contains(line, `SecRule REQUEST_HEADERS:Host "@streq search.example.com:8443"`) {
		t.Fatalf("unexpected non-default host scope: %s", line)
	}
}

func TestValidateFPTunerRuleLine(t *testing.T) {
	good := testScopedFPTunerRuleLine("search.example.com", "https", "/search", 100004, "ARGS:q")
	if err := validateFPTunerRuleLine(good); err != nil {
		t.Fatalf("validateFPTunerRuleLine good returned err: %v", err)
	}

	bad := `SecAction "id:1,phase:1,pass"`
	if err := validateFPTunerRuleLine(bad); err == nil {
		t.Fatal("validateFPTunerRuleLine should reject unsafe line")
	}
}

func TestValidateFPTunerRuleLineRejectsBroadHostRegex(t *testing.T) {
	bad := "SecRule REQUEST_HEADERS:Host \"@rx ^.*example\\.com.*$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\n" +
		"SecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""
	if err := validateFPTunerRuleLine(bad); err == nil {
		t.Fatal("validateFPTunerRuleLine should reject broad host regex")
	}
}

func TestMaskSensitiveText(t *testing.T) {
	in := "Authorization=Bearer abc.def.ghi token=supersecret1234567890123456 email=a@example.com ip=10.1.2.3"
	out := maskSensitiveText(in)
	if strings.Contains(out, "supersecret1234567890123456") {
		t.Fatalf("token should be masked: %s", out)
	}
	if strings.Contains(out, "a@example.com") {
		t.Fatalf("email should be masked: %s", out)
	}
	if strings.Contains(out, "10.1.2.3") {
		t.Fatalf("ip should be masked: %s", out)
	}
}

func TestLatestSecurityEventFallsBackToSemanticAnomaly(t *testing.T) {
	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":      now.Format(time.RFC3339Nano),
			"event":   "semantic_anomaly",
			"req_id":  "req-sem-1",
			"method":  "POST",
			"path":    "/login",
			"action":  "block",
			"score":   5,
			"status":  403,
			"reason":  "temporal:ip_burst",
			"reasons": "temporal:ip_burst",
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	event, source, err := latestSecurityEvent()
	if err != nil {
		t.Fatalf("latestSecurityEvent error: %v", err)
	}
	if source != "security_log" {
		t.Fatalf("source=%q want=security_log", source)
	}
	if event.EventType != "semantic_anomaly" {
		t.Fatalf("event_type=%q want=semantic_anomaly", event.EventType)
	}
	if event.Path != "/login" {
		t.Fatalf("path=%q want=/login", event.Path)
	}
	if event.Score != 5 {
		t.Fatalf("score=%d want=5", event.Score)
	}
}

func TestLatestSecurityEventUsesWAFBlockMatchedValue(t *testing.T) {
	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":               now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
			"event":            "semantic_anomaly",
			"req_id":           "req-sem-1",
			"method":           "POST",
			"path":             "/semantic",
			"status":           403,
			"reason":           "temporal:ip_burst",
			"reasons":          "temporal:ip_burst",
			"matched_value":    "should-not-win",
			"matched_variable": "ARGS:mode",
		},
		{
			"ts":               now.Format(time.RFC3339Nano),
			"event":            "waf_block",
			"req_id":           "req-waf-1",
			"method":           "GET",
			"original_scheme":  "https",
			"original_host":    "login.example.com:8443",
			"path":             "/login",
			"rule_id":          942100,
			"status":           403,
			"matched_variable": "ARGS:username",
			"matched_value":    "admin@example.com",
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	event, source, err := latestSecurityEvent()
	if err != nil {
		t.Fatalf("latestSecurityEvent error: %v", err)
	}
	if source != "waf_log" {
		t.Fatalf("source=%q want=waf_log", source)
	}
	if event.EventType != "" {
		t.Fatalf("event_type=%q want empty for latestWAFBlockEvent path", event.EventType)
	}
	if event.RuleID != 942100 {
		t.Fatalf("rule_id=%d want=942100", event.RuleID)
	}
	if event.Host != "login.example.com:8443" {
		t.Fatalf("host=%q want=login.example.com:8443", event.Host)
	}
	if event.Scheme != "https" {
		t.Fatalf("scheme=%q want=https", event.Scheme)
	}
	if event.MatchedVariable != "ARGS:username" {
		t.Fatalf("matched_variable=%q want=ARGS:username", event.MatchedVariable)
	}
	if event.MatchedValue != "admin@example.com" {
		t.Fatalf("matched_value=%q want=admin@example.com", event.MatchedValue)
	}
}

func TestLatestSecurityEventFallsBackToOriginalQueryForLowSignalWAFBlock(t *testing.T) {
	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":               now.Format(time.RFC3339Nano),
			"event":            "waf_block",
			"req_id":           "req-waf-low-signal",
			"method":           "GET",
			"original_scheme":  "http",
			"original_host":    "localhost:80",
			"path":             "/",
			"rule_id":          949110,
			"status":           403,
			"matched_variable": "TX:blocking_inbound_anomaly_score",
			"matched_value":    "25",
			"original_query":   "%3Cscript%3Ewindow.alert(document.cookie);%3C/script%3E",
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	event, source, err := latestSecurityEvent()
	if err != nil {
		t.Fatalf("latestSecurityEvent error: %v", err)
	}
	if source != "waf_log" {
		t.Fatalf("source=%q want=waf_log", source)
	}
	if event.RuleID != 949110 {
		t.Fatalf("rule_id=%d want=949110", event.RuleID)
	}
	if event.Host != "localhost:80" {
		t.Fatalf("host=%q want=localhost:80", event.Host)
	}
	if event.Scheme != "http" {
		t.Fatalf("scheme=%q want=http", event.Scheme)
	}
	if event.Query != "<script>window.alert(document.cookie);</script>" {
		t.Fatalf("query=%q want decoded query payload", event.Query)
	}
	if event.MatchedVariable != "QUERY_STRING" {
		t.Fatalf("matched_variable=%q want=QUERY_STRING", event.MatchedVariable)
	}
	if event.MatchedValue != "<script>window.alert(document.cookie);</script>" {
		t.Fatalf("matched_value=%q want decoded query payload", event.MatchedValue)
	}
}

func TestLatestSecurityEventFallsBackToOriginalQueryForUnsafeMatchedVariable(t *testing.T) {
	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":               now.Format(time.RFC3339Nano),
			"event":            "waf_block",
			"req_id":           "req-waf-unsafe-var",
			"method":           "GET",
			"original_scheme":  "http",
			"original_host":    "localhost:80",
			"path":             "/",
			"rule_id":          941100,
			"status":           403,
			"matched_variable": "ARGS_NAMES:<script>window.alert(document.cookie);</script>",
			"matched_value":    "<script>window.alert(document.cookie);</script>",
			"original_query":   "%3Cscript%3Ewindow.alert(document.cookie);%3C/script%3E",
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	event, source, err := latestSecurityEvent()
	if err != nil {
		t.Fatalf("latestSecurityEvent error: %v", err)
	}
	if source != "waf_log" {
		t.Fatalf("source=%q want=waf_log", source)
	}
	if event.MatchedVariable != "QUERY_STRING" {
		t.Fatalf("matched_variable=%q want=QUERY_STRING", event.MatchedVariable)
	}
	if event.Query != "<script>window.alert(document.cookie);</script>" {
		t.Fatalf("query=%q want decoded query payload", event.Query)
	}
}

func TestDecodeJSONBodyStrictRejectsUnknownFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	body := []byte(`{"event":{"path":"/search"},"unknown":"x"}`)
	req := httptest.NewRequest("POST", "/tukuyomi-api/fp-tuner/propose", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	var payload fpTunerProposeBody
	err := decodeJSONBodyStrict(c, &payload)
	if err == nil {
		t.Fatal("decodeJSONBodyStrict should reject unknown fields")
	}
}

func TestDecodeJSONBodyStrictSingleObject(t *testing.T) {
	gin.SetMode(gin.TestMode)
	obj := fpTunerApplyBody{
		Proposal: fpTunerProposal{
			ID:         "fp-1",
			RuleLine:   testScopedFPTunerRuleLine("search.example.com", "https", "/search", 100004, "ARGS:q"),
			TargetPath: "tukuyomi.conf",
		},
	}
	raw, _ := json.Marshal(obj)
	req := httptest.NewRequest("POST", "/tukuyomi-api/fp-tuner/apply", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	var payload fpTunerApplyBody
	if err := decodeJSONBodyStrict(c, &payload); err != nil {
		t.Fatalf("decodeJSONBodyStrict returned error: %v", err)
	}
	if payload.Proposal.ID != "fp-1" {
		t.Fatalf("proposal id mismatch: %q", payload.Proposal.ID)
	}
}

func TestProposalHashStable(t *testing.T) {
	p := fpTunerProposal{
		ID:         "fp-1",
		TargetPath: "tukuyomi.conf",
		RuleLine:   testScopedFPTunerRuleLine("search.example.com", "https", "/search", 100004, "ARGS:q"),
	}
	h1 := proposalHash(p)
	h2 := proposalHash(p)
	if h1 == "" || h1 != h2 {
		t.Fatalf("proposalHash should be stable and non-empty: %q %q", h1, h2)
	}
}

func TestApprovalTokenLifecycle(t *testing.T) {
	prevTTL := config.FPTunerApprovalTTL
	config.FPTunerApprovalTTL = 60 * time.Second
	defer func() { config.FPTunerApprovalTTL = prevTTL }()

	fpApprovalMu.Lock()
	fpApprovalStore = map[string]fpApprovalEntry{}
	fpApprovalMu.Unlock()

	proposal := fpTunerProposal{
		ID:         "fp-1",
		TargetPath: "tukuyomi.conf",
		RuleLine:   testScopedFPTunerRuleLine("search.example.com", "https", "/search", 100004, "ARGS:q"),
	}
	token, err := issueFPTunerApprovalToken(proposal)
	if err != nil {
		t.Fatalf("issueFPTunerApprovalToken error: %v", err)
	}
	if token == "" {
		t.Fatal("approval token should not be empty")
	}

	if err := consumeFPTunerApprovalToken(token, proposal); err != nil {
		t.Fatalf("consumeFPTunerApprovalToken first call error: %v", err)
	}
	if err := consumeFPTunerApprovalToken(token, proposal); err == nil {
		t.Fatal("consumeFPTunerApprovalToken should reject reused token")
	}
}

func TestApprovalTokenProposalMismatch(t *testing.T) {
	prevTTL := config.FPTunerApprovalTTL
	config.FPTunerApprovalTTL = 60 * time.Second
	defer func() { config.FPTunerApprovalTTL = prevTTL }()

	fpApprovalMu.Lock()
	fpApprovalStore = map[string]fpApprovalEntry{}
	fpApprovalMu.Unlock()

	p1 := fpTunerProposal{
		ID:         "fp-1",
		TargetPath: "tukuyomi.conf",
		RuleLine:   testScopedFPTunerRuleLine("search.example.com", "https", "/search", 100004, "ARGS:q"),
	}
	p2 := fpTunerProposal{
		ID:         "fp-2",
		TargetPath: "tukuyomi.conf",
		RuleLine:   testScopedFPTunerRuleLine("search.example.com", "https", "/users", 100004, "ARGS:q"),
	}

	token, err := issueFPTunerApprovalToken(p1)
	if err != nil {
		t.Fatalf("issueFPTunerApprovalToken error: %v", err)
	}
	if err := consumeFPTunerApprovalToken(token, p2); err == nil {
		t.Fatal("consumeFPTunerApprovalToken should reject proposal mismatch")
	}
}

func TestProposeFPTuningHTTPModeSanitizesProviderPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var captured fpTunerProviderRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("provider request method=%s want=POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-provider-key" {
			t.Errorf("provider auth header=%q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("provider decode error: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"proposal":{"id":"fp-http-001","summary":"ok","rule_line":"SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""}}`))
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerAPIKey = "test-provider-key"
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"tukuyomi.conf",
		"event":{
			"scheme":"https",
			"host":"search.example.com",
			"path":"/search",
			"query":"token=sensitive-value&email=a@example.com&ip=10.1.2.3",
			"rule_id":100004,
			"matched_variable":"ARGS:q",
			"matched_value":"token=sensitive-value&email=a@example.com&ip=10.1.2.3"
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/tukuyomi-api/fp-tuner/propose", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	ProposeFPTuning(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var out struct {
		OK       bool   `json:"ok"`
		Mode     string `json:"mode"`
		Proposal struct {
			ID string `json:"id"`
		} `json:"proposal"`
		Approval struct {
			Required bool `json:"required"`
		} `json:"approval"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response decode error: %v", err)
	}
	if !out.OK {
		t.Fatalf("response ok=false: %s", w.Body.String())
	}
	if out.Mode != "http" {
		t.Fatalf("mode=%q want=http", out.Mode)
	}
	if out.Proposal.ID != "fp-http-001" {
		t.Fatalf("proposal id=%q want=fp-http-001", out.Proposal.ID)
	}
	if out.Approval.Required {
		t.Fatal("approval.required should be false in this test")
	}

	if captured.TargetPath != "tukuyomi.conf" {
		t.Fatalf("provider target_path=%q want=tukuyomi.conf", captured.TargetPath)
	}
	if captured.Input.Host != "search.example.com" {
		t.Fatalf("provider input host=%q want=search.example.com", captured.Input.Host)
	}
	if captured.Input.Scheme != "https" {
		t.Fatalf("provider input scheme=%q want=https", captured.Input.Scheme)
	}
	if !containsExactString(captured.Constraints, "Target engine is Coraza with ModSecurity-compatible exclusion syntax") {
		t.Fatalf("constraints missing Coraza guidance: %#v", captured.Constraints)
	}
	if !containsExactString(captured.Constraints, "Rule must be a two-line chain: REQUEST_HEADERS:Host exact match, or a default-port-aware regex for http:80 / https:443 only, then REQUEST_URI @beginsWith with ctl:ruleRemoveTargetById") {
		t.Fatalf("constraints missing host-aware chain guidance: %#v", captured.Constraints)
	}
	if !containsExactString(captured.Constraints, "If this is not a credible false positive or evidence is insufficient, return no_proposal with reason") {
		t.Fatalf("constraints missing no_proposal guidance: %#v", captured.Constraints)
	}
	if strings.Contains(captured.Input.MatchedValue, "a@example.com") {
		t.Fatalf("provider input contains unmasked email: %q", captured.Input.MatchedValue)
	}
	if strings.Contains(captured.Input.MatchedValue, "sensitive-value") {
		t.Fatalf("provider input contains unmasked token: %q", captured.Input.MatchedValue)
	}
	if strings.Contains(captured.Input.MatchedValue, "10.1.2.3") {
		t.Fatalf("provider input contains unmasked ip: %q", captured.Input.MatchedValue)
	}
	if !strings.Contains(captured.Input.MatchedValue, "token=[redacted]") {
		t.Fatalf("provider input missing redacted token marker: %q", captured.Input.MatchedValue)
	}
	if !strings.Contains(captured.Input.MatchedValue, "[redacted-email]") {
		t.Fatalf("provider input missing redacted email marker: %q", captured.Input.MatchedValue)
	}
	if !strings.Contains(captured.Input.MatchedValue, "[redacted-ip]") {
		t.Fatalf("provider input missing redacted ip marker: %q", captured.Input.MatchedValue)
	}
	if !strings.Contains(captured.Input.Query, "token=[redacted]") || !strings.Contains(captured.Input.Query, "[redacted-email]") || !strings.Contains(captured.Input.Query, "[redacted-ip]") {
		t.Fatalf("provider input query was not masked: %q", captured.Input.Query)
	}
}

func TestProposeFPTuningRejectsMismatchedTargetRuleID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"proposal":{"id":"fp-http-unsafe-001","summary":"ok","rule_line":"SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=999999;ARGS:q\""}}`))
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"tukuyomi.conf",
		"event":{
			"scheme":"https",
			"host":"search.example.com",
			"path":"/search",
			"rule_id":100004,
			"matched_variable":"ARGS:q",
			"matched_value":"select * from users"
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/tukuyomi-api/fp-tuner/propose", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	ProposeFPTuning(c)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "observed rule_id 100004") {
		t.Fatalf("unexpected body=%s", w.Body.String())
	}
}

func TestProposeFPTuningRejectsMismatchedHost(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"proposal":{"id":"fp-http-unsafe-host","summary":"ok","rule_line":"SecRule REQUEST_HEADERS:Host \"@rx ^admin\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""}}`))
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"tukuyomi.conf",
		"event":{
			"scheme":"https",
			"host":"search.example.com",
			"path":"/search",
			"rule_id":100004,
			"matched_variable":"ARGS:q",
			"matched_value":"select * from users"
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/tukuyomi-api/fp-tuner/propose", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	ProposeFPTuning(c)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "observed host scope") || !strings.Contains(w.Body.String(), "search") {
		t.Fatalf("unexpected body=%s", w.Body.String())
	}
}

func TestProposeFPTuningRejectsMismatchedVariable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"proposal":{"id":"fp-http-unsafe-002","summary":"ok","rule_line":"SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:username\""}}`))
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"tukuyomi.conf",
		"event":{
			"scheme":"https",
			"host":"search.example.com",
			"path":"/search",
			"rule_id":100004,
			"matched_variable":"ARGS:q",
			"matched_value":"select * from users"
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/tukuyomi-api/fp-tuner/propose", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	ProposeFPTuning(c)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "observed matched_variable") || !strings.Contains(w.Body.String(), "ARGS:q") {
		t.Fatalf("unexpected body=%s", w.Body.String())
	}
}

func TestRequestFPTunerProposalHTTPStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "provider failed", http.StatusBadGateway)
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second

	_, err := requestFPTunerProposalHTTP(fpTunerProviderRequest{
		Version:    "v1",
		TargetPath: "tukuyomi.conf",
		Input: fpTunerEventInput{
			Host:            "search.example.com",
			Path:            "/search",
			RuleID:          100004,
			MatchedVariable: "ARGS:q",
		},
	})
	if err == nil {
		t.Fatal("requestFPTunerProposalHTTP should fail on provider non-2xx")
	}
	if !strings.Contains(err.Error(), "provider returned HTTP 502") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveFPTunerEventInputsRejectsMixedInput(t *testing.T) {
	_, _, err := resolveFPTunerEventInputs(fpTunerProposeBody{
		Event: &fpTunerEventInput{Path: "/search"},
		Events: []fpTunerEventInput{
			{Path: "/login"},
		},
	})
	if err == nil {
		t.Fatal("resolveFPTunerEventInputs should reject mixed event and events")
	}
}

func TestResolveFPTunerEventInputsRejectsMissingManualFields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    fpTunerProposeBody
		wantErr string
	}{
		{
			name: "missing host",
			body: fpTunerProposeBody{
				Event: &fpTunerEventInput{
					Path:            "/",
					RuleID:          941100,
					MatchedVariable: "QUERY_STRING",
				},
			},
			wantErr: "event.host is required",
		},
		{
			name: "missing path",
			body: fpTunerProposeBody{
				Event: &fpTunerEventInput{
					Host:            "search.example.com",
					RuleID:          941100,
					MatchedVariable: "QUERY_STRING",
				},
			},
			wantErr: "event.path is required",
		},
		{
			name: "missing rule_id",
			body: fpTunerProposeBody{
				Event: &fpTunerEventInput{
					Host:            "search.example.com",
					Path:            "/",
					MatchedVariable: "QUERY_STRING",
				},
			},
			wantErr: "event.rule_id is required",
		},
		{
			name: "missing matched_variable",
			body: fpTunerProposeBody{
				Event: &fpTunerEventInput{
					Host:   "search.example.com",
					Path:   "/",
					RuleID: 941100,
				},
			},
			wantErr: "event.matched_variable is required",
		},
		{
			name: "missing batch matched_variable",
			body: fpTunerProposeBody{
				Events: []fpTunerEventInput{
					{
						Host:   "search.example.com",
						Path:   "/",
						RuleID: 941100,
					},
				},
			},
			wantErr: "events[0].matched_variable is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := resolveFPTunerEventInputs(tc.body)
			if err == nil {
				t.Fatal("resolveFPTunerEventInputs should reject incomplete manual input")
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("err=%q want=%q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestResolveFPTunerEventInputsRejectsIncompleteLatestEvent(t *testing.T) {
	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":     now.Format(time.RFC3339Nano),
			"event":  "semantic_anomaly",
			"req_id": "req-sem-1",
			"method": "GET",
			"path":   "/login",
			"status": 403,
			"reason": "temporal:ip_burst",
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)
	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	_, _, err := resolveFPTunerEventInputs(fpTunerProposeBody{})
	if err == nil {
		t.Fatal("resolveFPTunerEventInputs should reject incomplete latest event")
	}
	if err.Error() != "latest_event.host is required" {
		t.Fatalf("err=%q want latest_event.host is required", err.Error())
	}
}

func TestProposeFPTuningBatchHTTPReturnsV2(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			_, _ = w.Write([]byte(`{"proposal":{"id":"fp-http-batch-001","summary":"ok","rule_line":"SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""}}`))
			return
		}
		_, _ = w.Write([]byte(`{"proposal":{"id":"fp-http-batch-002","summary":"ok","rule_line":"SecRule REQUEST_HEADERS:Host \"@rx ^login\\.example\\.com(:443)?$\" \"id:190124,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /login\" \"ctl:ruleRemoveTargetById=100005;ARGS:username\""}}`))
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"tukuyomi.conf",
		"events":[
			{"scheme":"https","host":"search.example.com","path":"/search","rule_id":100004,"matched_variable":"ARGS:q","matched_value":"q=test"},
			{"scheme":"https","host":"login.example.com","path":"/login","rule_id":100005,"matched_variable":"ARGS:username","matched_value":"admin"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/tukuyomi-api/fp-tuner/propose", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	ProposeFPTuning(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var out struct {
		OK              bool   `json:"ok"`
		Count           int    `json:"count"`
		ContractVersion string `json:"contract_version"`
		Proposals       []struct {
			Input struct {
				Host string `json:"host"`
				Path string `json:"path"`
			} `json:"input"`
			Proposal struct {
				ID string `json:"id"`
			} `json:"proposal"`
		} `json:"proposals"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response decode error: %v", err)
	}
	if !out.OK {
		t.Fatalf("response ok=false: %s", w.Body.String())
	}
	if out.ContractVersion != "fp_tuner.v2" {
		t.Fatalf("contract_version=%q want=fp_tuner.v2", out.ContractVersion)
	}
	if out.Count != 2 || len(out.Proposals) != 2 {
		t.Fatalf("count/proposals mismatch: count=%d proposals=%d body=%s", out.Count, len(out.Proposals), w.Body.String())
	}
	if callCount != 2 {
		t.Fatalf("provider call count=%d want=2", callCount)
	}
	if out.Proposals[0].Input.Host != "search.example.com" || out.Proposals[1].Input.Host != "login.example.com" {
		t.Fatalf("unexpected batch proposal hosts: %s", w.Body.String())
	}
	if out.Proposals[0].Input.Path != "/search" || out.Proposals[1].Input.Path != "/login" {
		t.Fatalf("unexpected batch proposal order: %s", w.Body.String())
	}
}

func TestProposeFPTuningUnsafeProposalReturns422(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"proposal":{"id":"fp-http-unsafe","summary":"bad","rule_line":"SecAction \"id:1,phase:1,pass\""}}`))
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"tukuyomi.conf",
		"event":{"host":"search.example.com","path":"/search","rule_id":100004,"matched_variable":"ARGS:q","matched_value":"q=test"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/tukuyomi-api/fp-tuner/propose", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	ProposeFPTuning(c)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "provider returned unsafe proposal") {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestProposeFPTuningNoProposalReturns200(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"no_proposal","reason":"Attack-like XSS payload in QUERY_STRING; do not exclude.","confidence":0.08}`))
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = true

	reqBody := `{
		"target_path":"tukuyomi.conf",
		"event":{"host":"localhost:80","path":"/","query":"<script>alert(1)</script>","rule_id":941100,"matched_variable":"QUERY_STRING","matched_value":"<script>alert(1)</script>"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/tukuyomi-api/fp-tuner/propose", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	ProposeFPTuning(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var out struct {
		OK         bool               `json:"ok"`
		Proposal   *fpTunerProposal   `json:"proposal"`
		NoProposal *fpTunerNoProposal `json:"no_proposal"`
		Approval   fpTunerApproval    `json:"approval"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !out.OK {
		t.Fatalf("response ok=false: %s", w.Body.String())
	}
	if out.Proposal != nil {
		t.Fatalf("proposal should be nil: %s", w.Body.String())
	}
	if out.NoProposal == nil {
		t.Fatalf("no_proposal should be present: %s", w.Body.String())
	}
	if out.Approval.Required {
		t.Fatalf("approval.required should be false on no_proposal: %s", w.Body.String())
	}
}

func TestGetFPTunerAuditReturnsNewestFirstAndClampsLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "fp-tuner-audit.ndjson")
	restore := setFPTunerAuditFileForTest(t, auditPath)
	defer restore()

	lines := make([][]byte, 0, 105)
	for i := 0; i < 105; i += 1 {
		entry, err := json.Marshal(fpTunerAuditEntry{
			TS:           "2026-04-01T00:00:00Z",
			Service:      "coraza",
			Event:        "fp_tuner_apply_success",
			Actor:        "alice@example.com",
			ProposalID:   "fp-1",
			ProposalHash: "hash-1",
			TargetPath:   "tukuyomi.conf",
			Count:        i,
		})
		if err != nil {
			t.Fatalf("marshal audit entry: %v", err)
		}
		lines = append(lines, append(entry, '\n'))
	}
	if err := os.WriteFile(auditPath, bytes.Join(lines, nil), 0o644); err != nil {
		t.Fatalf("write audit file: %v", err)
	}

	for _, tc := range []struct {
		name      string
		query     string
		wantCount int
		wantFirst int
		wantLast  int
	}{
		{
			name:      "default limit",
			query:     "/fp-tuner:audit",
			wantCount: 20,
			wantFirst: 104,
			wantLast:  85,
		},
		{
			name:      "limit zero clamps to one",
			query:     "/fp-tuner:audit?limit=0",
			wantCount: 1,
			wantFirst: 104,
			wantLast:  104,
		},
		{
			name:      "limit high clamps to hundred",
			query:     "/fp-tuner:audit?limit=200",
			wantCount: 100,
			wantFirst: 104,
			wantLast:  5,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodGet, tc.query, nil)

			GetFPTunerAudit(c)

			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var body struct {
				Entries []fpTunerAuditEntry `json:"entries"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if len(body.Entries) != tc.wantCount {
				t.Fatalf("entries=%d want=%d", len(body.Entries), tc.wantCount)
			}
			if body.Entries[0].Count != tc.wantFirst {
				t.Fatalf("first count=%d want=%d", body.Entries[0].Count, tc.wantFirst)
			}
			if body.Entries[len(body.Entries)-1].Count != tc.wantLast {
				t.Fatalf("last count=%d want=%d", body.Entries[len(body.Entries)-1].Count, tc.wantLast)
			}
		})
	}
}

func TestGetFPTunerRecentWAFBlocksReturnsRequestedWAFBlockRows(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":     now.Add(-3 * time.Minute).Format(time.RFC3339Nano),
			"event":  "proxy_route",
			"req_id": "req-route-1",
			"path":   "/",
		},
		{
			"ts":               now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
			"event":            "waf_block",
			"req_id":           "req-waf-1",
			"method":           "GET",
			"original_scheme":  "http",
			"original_host":    "localhost:80",
			"path":             "/",
			"rule_id":          949110,
			"status":           403,
			"matched_variable": "TX:blocking_inbound_anomaly_score",
			"matched_value":    "25",
			"original_query":   "%3Csvg%20onload%3Dalert(1)%3E",
		},
		{
			"ts":     now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
			"event":  "proxy_route",
			"req_id": "req-route-2",
			"path":   "/",
		},
		{
			"ts":               now.Format(time.RFC3339Nano),
			"event":            "waf_block",
			"req_id":           "req-waf-2",
			"method":           "GET",
			"original_scheme":  "https",
			"original_host":    "search.example.com:8443",
			"path":             "/",
			"rule_id":          941100,
			"status":           403,
			"matched_variable": "QUERY_STRING",
			"matched_value":    "<script>alert(1)</script>",
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)
	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStore(true, dbPath, 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/fp-tuner/recent-waf-blocks?limit=2", nil)

	GetFPTunerRecentWAFBlocks(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var out fpTunerRecentWAFBlocksResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out.Lines) != 2 {
		t.Fatalf("lines=%d want=2 body=%s", len(out.Lines), w.Body.String())
	}
	if got := anyToString(out.Lines[0]["req_id"]); got != "req-waf-2" {
		t.Fatalf("first req_id=%q want=req-waf-2", got)
	}
	if got := anyToString(out.Lines[0]["original_host"]); got != "search.example.com:8443" {
		t.Fatalf("first original_host=%q want=search.example.com:8443", got)
	}
	if got := anyToString(out.Lines[1]["req_id"]); got != "req-waf-1" {
		t.Fatalf("second req_id=%q want=req-waf-1", got)
	}
	if got := anyToString(out.Lines[1]["matched_variable"]); got != "QUERY_STRING" {
		t.Fatalf("fallback matched_variable=%q want=QUERY_STRING", got)
	}
	if got := anyToString(out.Lines[1]["matched_value"]); got != "<svg onload=alert(1)>" {
		t.Fatalf("fallback matched_value=%q want decoded query payload", got)
	}
}

func TestGetFPTunerAuditMissingFileReturnsEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "missing-fp-tuner-audit.ndjson")
	restore := setFPTunerAuditFileForTest(t, auditPath)
	defer restore()

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/fp-tuner:audit", nil)

	GetFPTunerAudit(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Entries []fpTunerAuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(body.Entries) != 0 {
		t.Fatalf("entries=%d want=0", len(body.Entries))
	}
}

func saveFPTunerConfigForTest() func() {
	oldRulesFile := config.RulesFile
	oldCRSEnable := config.CRSEnable
	oldEndpoint := config.FPTunerEndpoint
	oldAPIKey := config.FPTunerAPIKey
	oldTimeout := config.FPTunerTimeout
	oldRequireApproval := config.FPTunerRequireApproval
	oldAuditFile := config.FPTunerAuditFile
	return func() {
		config.RulesFile = oldRulesFile
		config.CRSEnable = oldCRSEnable
		config.FPTunerEndpoint = oldEndpoint
		config.FPTunerAPIKey = oldAPIKey
		config.FPTunerTimeout = oldTimeout
		config.FPTunerRequireApproval = oldRequireApproval
		config.FPTunerAuditFile = oldAuditFile
	}
}

func setFPTunerAuditFileForTest(t *testing.T, path string) func() {
	t.Helper()
	prev := config.FPTunerAuditFile
	config.FPTunerAuditFile = path
	return func() {
		config.FPTunerAuditFile = prev
	}
}
