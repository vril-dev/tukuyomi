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
	raw := []byte(`{"proposal":{"id":"fp-1","summary":"ok","rule_line":"SecRule REQUEST_URI \"@beginsWith /search\" \"id:190123,phase:1,pass,nolog,ctl:ruleRemoveTargetById=100004;ARGS:q,msg:'tukuyomi fp_tuner scoped exclusion'\""}}`)

	proposal, err := decodeFPTunerProviderResponse(raw)
	if err != nil {
		t.Fatalf("decodeFPTunerProviderResponse wrapped error: %v", err)
	}
	if proposal.ID != "fp-1" {
		t.Fatalf("proposal.ID=%q want=fp-1", proposal.ID)
	}
}

func TestDecodeFPTunerProviderResponseDirect(t *testing.T) {
	raw := []byte(`{"id":"fp-2","summary":"ok","rule_line":"SecRule REQUEST_URI \"@beginsWith /search\" \"id:190123,phase:1,pass,nolog,ctl:ruleRemoveTargetById=100004;ARGS:q,msg:'tukuyomi fp_tuner scoped exclusion'\""}`)

	proposal, err := decodeFPTunerProviderResponse(raw)
	if err != nil {
		t.Fatalf("decodeFPTunerProviderResponse direct error: %v", err)
	}
	if proposal.ID != "fp-2" {
		t.Fatalf("proposal.ID=%q want=fp-2", proposal.ID)
	}
}

func TestBuildFPTunerRuleLine(t *testing.T) {
	line := buildFPTunerRuleLine(fpTunerEventInput{
		Path:            "/search",
		RuleID:          100004,
		MatchedVariable: "ARGS:q",
	})

	if !strings.Contains(line, "ctl:ruleRemoveTargetById=100004;ARGS:q") {
		t.Fatalf("rule line missing ctl fragment: %s", line)
	}
	if !strings.HasPrefix(line, `SecRule REQUEST_URI "@beginsWith /search"`) {
		t.Fatalf("unexpected rule line prefix: %s", line)
	}
}

func TestValidateFPTunerRuleLine(t *testing.T) {
	good := `SecRule REQUEST_URI "@beginsWith /search" "id:190123,phase:1,pass,nolog,ctl:ruleRemoveTargetById=100004;ARGS:q,msg:'tukuyomi fp_tuner scoped exclusion'"`
	if err := validateFPTunerRuleLine(good); err != nil {
		t.Fatalf("validateFPTunerRuleLine good returned err: %v", err)
	}

	bad := `SecAction "id:1,phase:1,pass"`
	if err := validateFPTunerRuleLine(bad); err == nil {
		t.Fatal("validateFPTunerRuleLine should reject unsafe line")
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
			RuleLine:   `SecRule REQUEST_URI "@beginsWith /search" "id:190123,phase:1,pass,nolog,ctl:ruleRemoveTargetById=100004;ARGS:q,msg:'tukuyomi fp_tuner scoped exclusion'"`,
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
		RuleLine:   `SecRule REQUEST_URI "@beginsWith /search" "id:190123,phase:1,pass,nolog,ctl:ruleRemoveTargetById=100004;ARGS:q,msg:'tukuyomi fp_tuner scoped exclusion'"`,
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
		RuleLine:   `SecRule REQUEST_URI "@beginsWith /search" "id:190123,phase:1,pass,nolog,ctl:ruleRemoveTargetById=100004;ARGS:q,msg:'tukuyomi fp_tuner scoped exclusion'"`,
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
		RuleLine:   `SecRule REQUEST_URI "@beginsWith /search" "id:190123,phase:1,pass,nolog,ctl:ruleRemoveTargetById=100004;ARGS:q,msg:'tukuyomi fp_tuner scoped exclusion'"`,
	}
	p2 := fpTunerProposal{
		ID:         "fp-2",
		TargetPath: "rules/tukuyomi.conf",
		RuleLine:   `SecRule REQUEST_URI "@beginsWith /users" "id:190124,phase:1,pass,nolog,ctl:ruleRemoveTargetById=100004;ARGS:q,msg:'tukuyomi fp_tuner scoped exclusion'"`,
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
		_, _ = w.Write([]byte(`{"proposal":{"id":"fp-http-001","summary":"ok","rule_line":"SecRule REQUEST_URI \"@beginsWith /search\" \"id:190123,phase:1,pass,nolog,ctl:ruleRemoveTargetById=100004;ARGS:q,msg:'tukuyomi fp_tuner scoped exclusion'\""}}`))
	}))
	defer srv.Close()

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "rules/tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerMode = "http"
	config.FPTunerEndpoint = srv.URL
	config.FPTunerAPIKey = "test-provider-key"
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"rules/tukuyomi.conf",
		"event":{
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

func TestProposeFPTuningBatchMockReturnsV2(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveFPTunerConfigForTest()
	defer restore()
	config.RulesFile = "rules/tukuyomi.conf"
	config.CRSEnable = false
	config.FPTunerMode = "mock"
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"rules/tukuyomi.conf",
		"events":[
			{"path":"/search","rule_id":100004,"matched_variable":"ARGS:q","matched_value":"q=test"},
			{"path":"/login","rule_id":100005,"matched_variable":"ARGS:username","matched_value":"admin"}
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
	config.FPTunerMode = "http"
	config.FPTunerEndpoint = srv.URL
	config.FPTunerTimeout = 2 * time.Second
	config.FPTunerRequireApproval = false

	reqBody := `{
		"target_path":"rules/tukuyomi.conf",
		"event":{"path":"/search","rule_id":100004,"matched_variable":"ARGS:q","matched_value":"q=test"}
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

func saveFPTunerConfigForTest() func() {
	oldRulesFile := config.RulesFile
	oldCRSEnable := config.CRSEnable
	oldMode := config.FPTunerMode
	oldEndpoint := config.FPTunerEndpoint
	oldAPIKey := config.FPTunerAPIKey
	oldTimeout := config.FPTunerTimeout
	oldRequireApproval := config.FPTunerRequireApproval
	return func() {
		config.RulesFile = oldRulesFile
		config.CRSEnable = oldCRSEnable
		config.FPTunerMode = oldMode
		config.FPTunerEndpoint = oldEndpoint
		config.FPTunerAPIKey = oldAPIKey
		config.FPTunerTimeout = oldTimeout
		config.FPTunerRequireApproval = oldRequireApproval
	}
}
