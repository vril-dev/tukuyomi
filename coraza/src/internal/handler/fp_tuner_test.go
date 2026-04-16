package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/config"
)

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
	good := "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\n" +
		"SecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""
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
	if event.MatchedValue != "<script>window.alert(document.cookie);</script>" {
		t.Fatalf("matched_value=%q want decoded query payload", event.MatchedValue)
	}
}

func TestLatestSecurityEventFallsBackToOriginalQueryForRequestFilename(t *testing.T) {
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
			"req_id":           "req-waf-request-filename",
			"method":           "GET",
			"path":             "/",
			"rule_id":          949110,
			"status":           403,
			"matched_variable": "REQUEST_FILENAME",
			"matched_value":    "/",
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
	if event.MatchedValue != "<script>window.alert(document.cookie);</script>" {
		t.Fatalf("matched_value=%q want decoded query payload", event.MatchedValue)
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
			RuleLine:   "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\"",
			TargetPath: "rules/tukuyomi.conf",
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
		TargetPath: "rules/tukuyomi.conf",
		RuleLine:   "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\"",
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
		TargetPath: "rules/tukuyomi.conf",
		RuleLine:   "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\"",
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
		TargetPath: "rules/tukuyomi.conf",
		RuleLine:   "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\"",
	}
	p2 := fpTunerProposal{
		ID:         "fp-2",
		TargetPath: "rules/tukuyomi.conf",
		RuleLine:   "SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190124,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /users\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\"",
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
	config.RulesFile = "rules/tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerAPIKey = "test-provider-key"
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"rules/tukuyomi.conf",
		"event":{
			"scheme":"https",
			"host":"search.example.com",
			"path":"/search",
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

	if captured.TargetPath != "rules/tukuyomi.conf" {
		t.Fatalf("provider target_path=%q want=rules/tukuyomi.conf", captured.TargetPath)
	}
	if captured.Input.Host != "search.example.com" {
		t.Fatalf("provider input host=%q want=search.example.com", captured.Input.Host)
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
		TargetPath: "rules/tukuyomi.conf",
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
		Event: &fpTunerEventInput{Host: "search.example.com", Path: "/search", RuleID: 100004, MatchedVariable: "ARGS:q"},
		Events: []fpTunerEventInput{
			{Host: "login.example.com", Path: "/login", RuleID: 100005, MatchedVariable: "ARGS:username"},
		},
	})
	if err == nil {
		t.Fatal("resolveFPTunerEventInputs should reject mixed event and events")
	}
}

func TestProposeFPTuningBatchHTTPReturnsV2(t *testing.T) {
	gin.SetMode(gin.TestMode)

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch callCount {
		case 1:
			_, _ = w.Write([]byte(`{"proposal":{"id":"fp-http-batch-001","summary":"ok","rule_line":"SecRule REQUEST_HEADERS:Host \"@rx ^search\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""}}`))
		default:
			_, _ = w.Write([]byte(`{"proposal":{"id":"fp-http-batch-002","summary":"ok","rule_line":"SecRule REQUEST_HEADERS:Host \"@rx ^login\\.example\\.com(:443)?$\" \"id:190124,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /login\" \"ctl:ruleRemoveTargetById=100005;ARGS:username\""}}`))
		}
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "rules/tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"rules/tukuyomi.conf",
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
	if out.Proposals[0].Input.Path != "/search" || out.Proposals[1].Input.Path != "/login" {
		t.Fatalf("unexpected batch proposal order: %s", w.Body.String())
	}
	if callCount != 2 {
		t.Fatalf("provider callCount=%d want=2", callCount)
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
	config.RulesFile = "rules/tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"rules/tukuyomi.conf",
		"event":{"scheme":"https","host":"search.example.com","path":"/search","rule_id":100004,"matched_variable":"ARGS:q","matched_value":"q=test"}
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

func TestProposeFPTuningRejectsDriftedHostScope(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"proposal":{"id":"fp-http-unsafe-host","summary":"bad","rule_line":"SecRule REQUEST_HEADERS:Host \"@rx ^admin\\.example\\.com(:443)?$\" \"id:190123,phase:1,pass,nolog,chain,msg:'tukuyomi fp_tuner scoped exclusion'\"\nSecRule REQUEST_URI \"@beginsWith /search\" \"ctl:ruleRemoveTargetById=100004;ARGS:q\""}}`))
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "rules/tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"rules/tukuyomi.conf",
		"event":{"scheme":"https","host":"search.example.com","path":"/search","rule_id":100004,"matched_variable":"ARGS:q","matched_value":"q=test"}
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
	if !strings.Contains(w.Body.String(), "outside the observed Coraza event scope") {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestProposeFPTuningReturnsNoProposal(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"no_proposal","reason":"Attack-like XSS payload in QUERY_STRING; do not exclude.","confidence":0.08}`))
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "rules/tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"rules/tukuyomi.conf",
		"event":{"scheme":"http","host":"localhost","path":"/","query":"<script>alert(1)</script>","rule_id":941100,"matched_variable":"QUERY_STRING","matched_value":"<script>alert(1)</script>"}
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
		Proposal   *fpTunerProposal   `json:"proposal"`
		NoProposal *fpTunerNoProposal `json:"no_proposal"`
		Approval   struct {
			Required bool `json:"required"`
		} `json:"approval"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response decode error: %v", err)
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

func TestGetFPTunerRecentWAFBlocksReturnsRequestedWAFBlockRows(t *testing.T) {
	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":               now.Add(-3 * time.Minute).Format(time.RFC3339Nano),
			"event":            "waf_block",
			"req_id":           "req-older",
			"method":           "GET",
			"path":             "/login",
			"rule_id":          942100,
			"status":           403,
			"matched_variable": "ARGS:username",
			"matched_value":    "admin",
		},
		{
			"ts":               now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
			"event":            "waf_block",
			"req_id":           "req-middle",
			"method":           "GET",
			"path":             "/",
			"rule_id":          949110,
			"status":           403,
			"matched_variable": "TX:blocking_inbound_anomaly_score",
			"matched_value":    "25",
			"original_query":   "%3Cscript%3Ewindow.alert(document.cookie);%3C/script%3E",
		},
		{
			"ts":               now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
			"event":            "waf_block",
			"req_id":           "req-newest",
			"method":           "GET",
			"path":             "/search",
			"rule_id":          941100,
			"status":           403,
			"matched_variable": "ARGS:q",
			"matched_value":    "<script>alert(1)</script>",
		},
		{
			"ts":     now.Format(time.RFC3339Nano),
			"event":  "semantic_anomaly",
			"req_id": "req-semantic",
			"method": "POST",
			"path":   "/login",
			"status": 403,
			"score":  5,
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	gin.SetMode(gin.TestMode)
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/fp-tuner/recent-waf-blocks?limit=2", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	GetFPTunerRecentWAFBlocks(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var out fpTunerRecentWAFBlocksResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response decode error: %v", err)
	}
	if len(out.Lines) != 2 {
		t.Fatalf("len(lines)=%d want=2 body=%s", len(out.Lines), w.Body.String())
	}
	if got := anyToString(out.Lines[0]["req_id"]); got != "req-newest" {
		t.Fatalf("latest req_id=%q want=req-newest", got)
	}
	if got := anyToString(out.Lines[1]["req_id"]); got != "req-middle" {
		t.Fatalf("second req_id=%q want=req-middle", got)
	}
	if got := anyToString(out.Lines[1]["matched_variable"]); got != "QUERY_STRING" {
		t.Fatalf("fallback matched_variable=%q want=QUERY_STRING", got)
	}
	if got := anyToString(out.Lines[1]["matched_value"]); got != "<script>window.alert(document.cookie);</script>" {
		t.Fatalf("fallback matched_value=%q want decoded query payload", got)
	}
}

func saveFPTunerConfigForTest() func() {
	oldRulesFile := config.RulesFile
	oldCRSEnable := config.CRSEnable
	oldEndpoint := config.FPTunerEndpoint
	oldAPIKey := config.FPTunerAPIKey
	oldTimeout := config.FPTunerTimeout
	oldRequireApproval := config.FPTunerRequireApproval
	return func() {
		config.RulesFile = oldRulesFile
		config.CRSEnable = oldCRSEnable
		config.FPTunerEndpoint = oldEndpoint
		config.FPTunerAPIKey = oldAPIKey
		config.FPTunerTimeout = oldTimeout
		config.FPTunerRequireApproval = oldRequireApproval
	}
}
