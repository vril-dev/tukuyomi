package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/waf"
)

const (
	fpTunerDefaultRuleID        = 100004
	fpTunerDefaultVariable      = "ARGS:q"
	fpTunerDefaultConfidence    = 0.82
	fpTunerMaxMatchedValueBytes = 512
	fpTunerMaxBodyBytes         = int64(1 * 1024 * 1024)
	fpTunerApprovalTokenBytes   = 24
)

var (
	fpTunerVariableAllowed = regexp.MustCompile(`^[A-Za-z0-9_.:!]+$`)
	fpTunerRuleLinePattern = regexp.MustCompile(`^SecRule REQUEST_URI "@beginsWith [^"\r\n]+" "id:[0-9]{6,},phase:1,pass,nolog,ctl:ruleRemoveTargetById=[0-9]+;[A-Za-z0-9_.:!]+,msg:'[^'\r\n]*'"$`)
	fpTunerMaskBearerToken = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
	fpTunerMaskJWT         = regexp.MustCompile(`\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b`)
	fpTunerMaskEmail       = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	fpTunerMaskIPv4        = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	fpTunerMaskSecretKV    = regexp.MustCompile(`(?i)\b(token|access_token|refresh_token|api_key|apikey|password|passwd|secret)=([^&\s]+)`)
	fpTunerMaskLongToken   = regexp.MustCompile(`\b[A-Za-z0-9._~+/=-]{24,}\b`)
)

type fpApprovalEntry struct {
	ProposalHash string
	ExpiresAt    time.Time
}

var (
	fpApprovalMu    sync.Mutex
	fpApprovalStore = map[string]fpApprovalEntry{}
)

type fpTunerEventInput struct {
	EventID         string `json:"event_id,omitempty"`
	EventType       string `json:"event_type,omitempty"`
	ObservedAt      string `json:"observed_at,omitempty"`
	Method          string `json:"method,omitempty"`
	Path            string `json:"path,omitempty"`
	Policy          string `json:"policy,omitempty"`
	RuleID          int    `json:"rule_id,omitempty"`
	Status          int    `json:"status,omitempty"`
	Score           int    `json:"score,omitempty"`
	Reason          string `json:"reason,omitempty"`
	MatchedVariable string `json:"matched_variable,omitempty"`
	MatchedValue    string `json:"matched_value,omitempty"`
}

type fpTunerProposeBody struct {
	Event      *fpTunerEventInput  `json:"event,omitempty"`
	Events     []fpTunerEventInput `json:"events,omitempty"`
	TargetPath string              `json:"target_path,omitempty"`
}

type fpTunerApproval struct {
	Required bool   `json:"required"`
	Token    string `json:"token,omitempty"`
}

type fpTunerProposeResult struct {
	Input    fpTunerEventInput `json:"input"`
	Proposal fpTunerProposal   `json:"proposal"`
	Approval fpTunerApproval   `json:"approval"`
}

type fpTunerProposeError struct {
	Status  int
	Message string
	Details string
	Err     error
}

func (e *fpTunerProposeError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	if e.Details != "" {
		return e.Details
	}
	return e.Message
}

func (e *fpTunerProposeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type fpTunerProposal struct {
	ID         string  `json:"id"`
	Title      string  `json:"title"`
	Summary    string  `json:"summary"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
	TargetPath string  `json:"target_path"`
	RuleLine   string  `json:"rule_line"`
}

type fpTunerProviderRequest struct {
	Version     string            `json:"version"`
	Model       string            `json:"model,omitempty"`
	Input       fpTunerEventInput `json:"input"`
	TargetPath  string            `json:"target_path"`
	Constraints []string          `json:"constraints"`
}

type fpTunerProviderResponse struct {
	Proposal fpTunerProposal `json:"proposal"`
}

type fpTunerApplyBody struct {
	Proposal      fpTunerProposal `json:"proposal"`
	Simulate      *bool           `json:"simulate,omitempty"`
	ApprovalToken string          `json:"approval_token,omitempty"`
}

func ProposeFPTuning(c *gin.Context) {
	var in fpTunerProposeBody
	if err := decodeJSONBodyStrict(c, &in); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	events, source, err := resolveFPTunerEventInputs(in)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "error": err.Error()})
		return
	}

	targetPath, err := selectFPTunerTargetPath(in.TargetPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": err.Error()})
		return
	}

	results := make([]fpTunerProposeResult, 0, len(events))
	mode := ""
	for _, event := range events {
		result, proposalMode, proposalErr := buildFPTunerProposeResult(event, targetPath)
		if proposalErr != nil {
			writeFPTunerProposeError(c, proposalErr)
			return
		}
		if mode == "" {
			mode = proposalMode
		}
		results = append(results, result)
	}

	appendFPTunerAudit(c, "fp_tuner_propose", map[string]any{
		"mode":              mode,
		"source":            source,
		"count":             len(results),
		"approval_required": config.FPTunerRequireApproval,
		"target_path":       targetPath,
	})
	if len(results) == 1 {
		c.JSON(http.StatusOK, gin.H{
			"ok":               true,
			"contract_version": "fp_tuner.v1",
			"mode":             mode,
			"source":           source,
			"approval":         results[0].Approval,
			"input":            results[0].Input,
			"proposal":         results[0].Proposal,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"contract_version": "fp_tuner.v2",
		"mode":             mode,
		"source":           source,
		"count":            len(results),
		"proposals":        results,
	})
}

func ApplyFPTuning(c *gin.Context) {
	var in fpTunerApplyBody
	if err := decodeJSONBodyStrict(c, &in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	line := strings.TrimSpace(in.Proposal.RuleLine)
	if line == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "proposal.rule_line is required"})
		return
	}
	if err := validateFPTunerRuleLine(line); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "error": err.Error()})
		return
	}

	targetPath, err := selectFPTunerTargetPath(in.Proposal.TargetPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": err.Error()})
		return
	}

	simulate := true
	if in.Simulate != nil {
		simulate = *in.Simulate
	}

	curRaw, err := os.ReadFile(targetPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	curETag := bypassconf.ComputeETag(curRaw)
	if ifMatch := c.GetHeader("If-Match"); ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	if strings.Contains(string(curRaw), line) {
		appendFPTunerAudit(c, "fp_tuner_apply_duplicate", map[string]any{
			"proposal_id":    in.Proposal.ID,
			"proposal_hash":  proposalHash(in.Proposal),
			"target_path":    targetPath,
			"simulate":       simulate,
			"approval_token": in.ApprovalToken != "",
		})
		c.JSON(http.StatusOK, gin.H{
			"ok":               true,
			"contract_version": "fp_tuner.v1",
			"duplicate":        true,
			"etag":             curETag,
			"hot_reloaded":     false,
			"reloaded_file":    targetPath,
		})
		return
	}

	nextRaw := appendFPTunerRule(curRaw, in.Proposal.ID, line)
	if err := waf.ValidateWithRuleOverride(targetPath, nextRaw); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "error": err.Error()})
		return
	}

	if !simulate && config.FPTunerRequireApproval {
		if err := consumeFPTunerApprovalToken(in.ApprovalToken, in.Proposal); err != nil {
			appendFPTunerAudit(c, "fp_tuner_apply_denied", map[string]any{
				"proposal_id":    in.Proposal.ID,
				"proposal_hash":  proposalHash(in.Proposal),
				"target_path":    targetPath,
				"simulate":       false,
				"approval_error": err.Error(),
			})
			c.JSON(http.StatusForbidden, gin.H{
				"ok":               false,
				"contract_version": "fp_tuner.v1",
				"error":            fmt.Sprintf("approval required: %v", err),
			})
			return
		}
	}

	if simulate {
		appendFPTunerAudit(c, "fp_tuner_apply_simulate", map[string]any{
			"proposal_id":    in.Proposal.ID,
			"proposal_hash":  proposalHash(in.Proposal),
			"target_path":    targetPath,
			"simulate":       true,
			"approval_token": in.ApprovalToken != "",
		})
		c.JSON(http.StatusOK, gin.H{
			"ok":               true,
			"contract_version": "fp_tuner.v1",
			"simulated":        true,
			"hot_reloaded":     false,
			"reloaded_file":    targetPath,
			"preview_etag":     bypassconf.ComputeETag(nextRaw),
		})
		return
	}

	if err := bypassconf.AtomicWriteWithBackup(targetPath, nextRaw); err != nil {
		appendFPTunerAudit(c, "fp_tuner_apply_error", map[string]any{
			"proposal_id":   in.Proposal.ID,
			"proposal_hash": proposalHash(in.Proposal),
			"target_path":   targetPath,
			"simulate":      false,
			"error":         err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := waf.ReloadBaseWAF(); err != nil {
		_ = bypassconf.AtomicWriteWithBackup(targetPath, curRaw)
		_ = waf.ReloadBaseWAF()
		appendFPTunerAudit(c, "fp_tuner_apply_error", map[string]any{
			"proposal_id":   in.Proposal.ID,
			"proposal_hash": proposalHash(in.Proposal),
			"target_path":   targetPath,
			"simulate":      false,
			"error":         fmt.Sprintf("reload failed and rollback applied: %v", err),
		})
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("reload failed and rollback applied: %v", err),
		})
		return
	}

	appendFPTunerAudit(c, "fp_tuner_apply_success", map[string]any{
		"proposal_id":   in.Proposal.ID,
		"proposal_hash": proposalHash(in.Proposal),
		"target_path":   targetPath,
		"simulate":      false,
		"hot_reloaded":  true,
	})
	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"contract_version": "fp_tuner.v1",
		"etag":             bypassconf.ComputeETag(nextRaw),
		"hot_reloaded":     true,
		"reloaded_file":    targetPath,
	})
}

func resolveFPTunerEventInput(in *fpTunerEventInput) (fpTunerEventInput, string, error) {
	if in != nil {
		norm := normalizeFPTunerEventInput(*in)
		if norm.Path == "" {
			return fpTunerEventInput{}, "", fmt.Errorf("event.path is required")
		}
		return norm, "request", nil
	}

	event, source, err := latestSecurityEvent()
	if err != nil {
		return fpTunerEventInput{}, "", err
	}

	return normalizeFPTunerEventInput(event), source, nil
}

func resolveFPTunerEventInputs(in fpTunerProposeBody) ([]fpTunerEventInput, string, error) {
	if in.Event != nil && len(in.Events) > 0 {
		return nil, "", fmt.Errorf("event and events cannot be used together")
	}
	if len(in.Events) > 0 {
		out := make([]fpTunerEventInput, 0, len(in.Events))
		for i, raw := range in.Events {
			norm := normalizeFPTunerEventInput(raw)
			if norm.Path == "" {
				return nil, "", fmt.Errorf("events[%d].path is required", i)
			}
			out = append(out, norm)
		}
		return out, "request_batch", nil
	}
	event, source, err := resolveFPTunerEventInput(in.Event)
	if err != nil {
		return nil, "", err
	}
	return []fpTunerEventInput{event}, source, nil
}

func writeFPTunerProposeError(c *gin.Context, err error) {
	var proposeErr *fpTunerProposeError
	if errors.As(err, &proposeErr) {
		body := gin.H{"ok": false, "error": proposeErr.Message}
		if proposeErr.Details != "" {
			body["details"] = proposeErr.Details
		}
		c.JSON(proposeErr.Status, body)
		return
	}
	c.JSON(http.StatusBadGateway, gin.H{"ok": false, "error": err.Error()})
}

func buildFPTunerProposeResult(event fpTunerEventInput, targetPath string) (fpTunerProposeResult, string, error) {
	providerReq := fpTunerProviderRequest{
		Version:    "v1",
		Model:      strings.TrimSpace(config.FPTunerModel),
		Input:      maskFPTunerProviderInput(event),
		TargetPath: targetPath,
		Constraints: []string{
			"Only return one scoped exclusion rule",
			"Rule must be SecRule REQUEST_URI with ctl:ruleRemoveTargetById",
			"No global disable operations",
		},
	}
	proposal, mode, err := requestFPTunerProposal(providerReq)
	if err != nil {
		return fpTunerProposeResult{}, "", &fpTunerProposeError{
			Status:  http.StatusBadGateway,
			Message: err.Error(),
			Err:     err,
		}
	}
	proposal = fillFPTunerProposalDefaults(proposal, event, targetPath)
	if err := validateFPTunerRuleLine(proposal.RuleLine); err != nil {
		return fpTunerProposeResult{}, "", &fpTunerProposeError{
			Status:  http.StatusUnprocessableEntity,
			Message: "provider returned unsafe proposal",
			Details: err.Error(),
			Err:     err,
		}
	}
	result := fpTunerProposeResult{
		Input:    event,
		Proposal: proposal,
		Approval: fpTunerApproval{Required: config.FPTunerRequireApproval},
	}
	if config.FPTunerRequireApproval {
		token, err := issueFPTunerApprovalToken(proposal)
		if err != nil {
			return fpTunerProposeResult{}, "", &fpTunerProposeError{
				Status:  http.StatusInternalServerError,
				Message: "failed to issue approval token",
				Details: err.Error(),
				Err:     err,
			}
		}
		result.Approval.Token = token
	}
	return result, mode, nil
}

func latestWAFBlockEvent() (fpTunerEventInput, error) {
	path, ok := logFiles["waf"]
	if !ok {
		return fpTunerEventInput{}, fmt.Errorf("waf log source is not configured")
	}
	path = resolveLogPath("waf", path)

	if store := getLogsStatsStore(); store != nil {
		event, err := store.LatestWAFBlockEvent(path)
		if err == nil {
			return event, nil
		}
	}

	lines, _, _, _, err := readByLine(path, 120, nil, "")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fpTunerEventInput{}, fmt.Errorf("waf event log not found: %s", path)
		}
		return fpTunerEventInput{}, err
	}
	for i := len(lines) - 1; i >= 0; i-- {
		ln := lines[i]
		if strings.TrimSpace(anyToString(ln["event"])) != "waf_block" {
			continue
		}
		return fpTunerEventInput{
			EventID:         anyToString(ln["req_id"]),
			ObservedAt:      anyToString(ln["ts"]),
			Method:          anyToString(ln["method"]),
			Path:            anyToString(ln["path"]),
			RuleID:          anyToInt(ln["rule_id"]),
			Status:          anyToInt(ln["status"]),
			MatchedVariable: anyToString(ln["matched_variable"]),
			MatchedValue:    anyToString(ln["matched_value"]),
		}, nil
	}

	return fpTunerEventInput{}, fmt.Errorf("no waf_block event found in %s", path)
}

func latestSecurityEvent() (fpTunerEventInput, string, error) {
	if event, err := latestWAFBlockEvent(); err == nil {
		return event, "waf_log", nil
	}

	path, ok := logFiles["waf"]
	if !ok {
		return fpTunerEventInput{}, "", fmt.Errorf("waf log source is not configured")
	}
	path = resolveLogPath("waf", path)

	lines, _, _, _, err := readByLine(path, 120, nil, "")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fpTunerEventInput{}, "", fmt.Errorf("waf event log not found: %s", path)
		}
		return fpTunerEventInput{}, "", err
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if event, ok := fpTunerEventInputFromLogLine(lines[i]); ok {
			return event, "security_log", nil
		}
	}
	return fpTunerEventInput{}, "", fmt.Errorf("no waf_block or semantic_anomaly event found in %s", path)
}

func fpTunerEventInputFromLogLine(ln logLine) (fpTunerEventInput, bool) {
	eventType := strings.TrimSpace(anyToString(ln["event"]))
	switch eventType {
	case "waf_block":
		return fpTunerEventInput{
			EventID:         anyToString(ln["req_id"]),
			EventType:       eventType,
			ObservedAt:      anyToString(ln["ts"]),
			Method:          anyToString(ln["method"]),
			Path:            anyToString(ln["path"]),
			Policy:          "waf",
			RuleID:          anyToInt(ln["rule_id"]),
			Status:          anyToInt(ln["status"]),
			MatchedVariable: anyToString(ln["matched_variable"]),
			MatchedValue:    anyToString(ln["matched_value"]),
		}, true
	case "semantic_anomaly":
		return fpTunerEventInput{
			EventID:    anyToString(ln["req_id"]),
			EventType:  eventType,
			ObservedAt: anyToString(ln["ts"]),
			Method:     anyToString(ln["method"]),
			Path:       anyToString(ln["path"]),
			Policy:     "semantic",
			Status:     anyToInt(ln["status"]),
			Score:      anyToInt(ln["score"]),
			Reason:     firstNonEmptyString(anyToString(ln["reason"]), anyToString(ln["reasons"])),
		}, true
	default:
		return fpTunerEventInput{}, false
	}
}

func normalizeFPTunerEventInput(in fpTunerEventInput) fpTunerEventInput {
	in.EventID = strings.TrimSpace(in.EventID)
	in.EventType = strings.TrimSpace(in.EventType)
	in.ObservedAt = strings.TrimSpace(in.ObservedAt)
	in.Method = strings.ToUpper(strings.TrimSpace(in.Method))
	if in.Method == "" {
		in.Method = http.MethodGet
	}
	in.Path = normalizeFPTunerPath(in.Path)
	in.Policy = strings.TrimSpace(in.Policy)
	if in.RuleID <= 0 {
		in.RuleID = fpTunerDefaultRuleID
	}
	if in.Status <= 0 {
		in.Status = http.StatusForbidden
	}
	if in.Score < 0 {
		in.Score = 0
	}
	in.Reason = clampText(strings.TrimSpace(in.Reason), fpTunerMaxMatchedValueBytes)
	in.MatchedVariable = normalizeFPTunerVariable(in.MatchedVariable)
	in.MatchedValue = clampText(strings.TrimSpace(in.MatchedValue), fpTunerMaxMatchedValueBytes)
	return in
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func normalizeFPTunerPath(v string) string {
	p := strings.TrimSpace(v)
	if p == "" || !strings.HasPrefix(p, "/") {
		return "/"
	}
	if strings.ContainsAny(p, "\n\r\"") {
		return "/"
	}
	return p
}

func normalizeFPTunerVariable(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return fpTunerDefaultVariable
	}
	if !fpTunerVariableAllowed.MatchString(s) {
		return fpTunerDefaultVariable
	}
	return s
}

func clampText(v string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(v) <= max {
		return v
	}
	return v[:max]
}

func requestFPTunerProposal(req fpTunerProviderRequest) (fpTunerProposal, string, error) {
	mode := strings.ToLower(strings.TrimSpace(config.FPTunerMode))
	if mode == "" {
		mode = "mock"
	}

	switch mode {
	case "mock":
		p, err := requestFPTunerProposalMock(req)
		return p, mode, err
	case "http":
		p, err := requestFPTunerProposalHTTP(req)
		return p, mode, err
	default:
		return fpTunerProposal{}, "", fmt.Errorf("unsupported WAF_FP_TUNER_MODE: %s", mode)
	}
}

func requestFPTunerProposalMock(req fpTunerProviderRequest) (fpTunerProposal, error) {
	fixture := strings.TrimSpace(config.FPTunerMockResponseFile)
	if fixture != "" {
		proposal, err := readFPTunerMockProposal(fixture)
		if err == nil {
			return fillFPTunerProposalDefaults(proposal, req.Input, req.TargetPath), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fpTunerProposal{}, err
		}
	}

	proposal := buildMockFPTunerProposal(req.Input, req.TargetPath)
	return fillFPTunerProposalDefaults(proposal, req.Input, req.TargetPath), nil
}

func requestFPTunerProposalHTTP(req fpTunerProviderRequest) (fpTunerProposal, error) {
	endpoint := strings.TrimSpace(config.FPTunerEndpoint)
	if endpoint == "" {
		return fpTunerProposal{}, fmt.Errorf("WAF_FP_TUNER_ENDPOINT is empty")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fpTunerProposal{}, err
	}

	client := &http.Client{Timeout: config.FPTunerTimeout}
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fpTunerProposal{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(config.FPTunerAPIKey); key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+key)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return fpTunerProposal{}, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fpTunerProposal{}, fmt.Errorf("provider returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	proposal, err := decodeFPTunerProviderResponse(raw)
	if err != nil {
		return fpTunerProposal{}, err
	}
	return fillFPTunerProposalDefaults(proposal, req.Input, req.TargetPath), nil
}

func readFPTunerMockProposal(path string) (fpTunerProposal, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fpTunerProposal{}, err
	}
	return decodeFPTunerProviderResponse(raw)
}

func decodeFPTunerProviderResponse(raw []byte) (fpTunerProposal, error) {
	var wrapped fpTunerProviderResponse
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		if strings.TrimSpace(wrapped.Proposal.RuleLine) != "" || strings.TrimSpace(wrapped.Proposal.Summary) != "" {
			return wrapped.Proposal, nil
		}
	}

	var direct fpTunerProposal
	if err := json.Unmarshal(raw, &direct); err == nil {
		if strings.TrimSpace(direct.RuleLine) != "" || strings.TrimSpace(direct.Summary) != "" {
			return direct, nil
		}
	}

	return fpTunerProposal{}, fmt.Errorf("provider response must be fp_tuner proposal json")
}

func proposalHash(p fpTunerProposal) string {
	h := sha256.Sum256([]byte(
		strings.TrimSpace(p.ID) + "|" +
			strings.TrimSpace(p.TargetPath) + "|" +
			strings.TrimSpace(p.RuleLine),
	))
	return fmt.Sprintf("%x", h[:])
}

func issueFPTunerApprovalToken(proposal fpTunerProposal) (string, error) {
	ttl := config.FPTunerApprovalTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	buf := make([]byte, fpTunerApprovalTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := fmt.Sprintf("%x", buf)
	digest := proposalHash(proposal)
	expireAt := time.Now().UTC().Add(ttl)

	fpApprovalMu.Lock()
	defer fpApprovalMu.Unlock()
	pruneExpiredFPTunerApprovals(time.Now().UTC())
	fpApprovalStore[token] = fpApprovalEntry{
		ProposalHash: digest,
		ExpiresAt:    expireAt,
	}

	return token, nil
}

func consumeFPTunerApprovalToken(token string, proposal fpTunerProposal) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("missing approval_token")
	}

	now := time.Now().UTC()
	digest := proposalHash(proposal)

	fpApprovalMu.Lock()
	defer fpApprovalMu.Unlock()
	pruneExpiredFPTunerApprovals(now)

	entry, ok := fpApprovalStore[token]
	if !ok {
		return fmt.Errorf("approval token is invalid or expired")
	}
	delete(fpApprovalStore, token)

	if entry.ProposalHash != digest {
		return fmt.Errorf("approval token does not match proposal")
	}
	if now.After(entry.ExpiresAt) {
		return fmt.Errorf("approval token expired")
	}
	return nil
}

func pruneExpiredFPTunerApprovals(now time.Time) {
	for k, v := range fpApprovalStore {
		if now.After(v.ExpiresAt) {
			delete(fpApprovalStore, k)
		}
	}
}

func appendFPTunerAudit(c *gin.Context, event string, fields map[string]any) {
	path := strings.TrimSpace(config.FPTunerAuditFile)
	if path == "" {
		path = "/app/logs/coraza/fp-tuner-audit.ndjson"
	}

	entry := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"service": "coraza",
		"event":   event,
		"actor":   fpTunerActor(c),
	}
	if c != nil {
		entry["ip"] = requestClientIP(c)
	}
	for k, v := range fields {
		entry[k] = v
	}
	emitJSONLog(entry)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		emitJSONLog(map[string]any{
			"ts":      time.Now().UTC().Format(time.RFC3339Nano),
			"service": "coraza",
			"level":   "WARN",
			"event":   "fp_tuner_audit_write_error",
			"path":    path,
			"error":   err.Error(),
		})
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		emitJSONLog(map[string]any{
			"ts":      time.Now().UTC().Format(time.RFC3339Nano),
			"service": "coraza",
			"level":   "WARN",
			"event":   "fp_tuner_audit_write_error",
			"path":    path,
			"error":   err.Error(),
		})
		return
	}
	defer f.Close()

	b, err := json.Marshal(entry)
	if err != nil {
		emitJSONLog(map[string]any{
			"ts":      time.Now().UTC().Format(time.RFC3339Nano),
			"service": "coraza",
			"level":   "WARN",
			"event":   "fp_tuner_audit_write_error",
			"path":    path,
			"error":   err.Error(),
		})
		return
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		emitJSONLog(map[string]any{
			"ts":      time.Now().UTC().Format(time.RFC3339Nano),
			"service": "coraza",
			"level":   "WARN",
			"event":   "fp_tuner_audit_write_error",
			"path":    path,
			"error":   err.Error(),
		})
	}
}

func fpTunerActor(c *gin.Context) string {
	if c == nil {
		return "unknown"
	}
	if actor := strings.TrimSpace(c.GetHeader("X-Tukuyomi-Actor")); actor != "" {
		return actor
	}
	key := strings.TrimSpace(c.GetHeader("X-API-Key"))
	if key == "" {
		return "api-key:none"
	}
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("api-key:sha256:%x", sum[:6])
}

func decodeJSONBodyStrict(c *gin.Context, out any) error {
	if c == nil || c.Request == nil || c.Request.Body == nil {
		return io.EOF
	}

	dec := json.NewDecoder(io.LimitReader(c.Request.Body, fpTunerMaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}

	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request body must contain a single JSON object")
		}
		return err
	}

	return nil
}

func maskFPTunerProviderInput(in fpTunerEventInput) fpTunerEventInput {
	out := in
	out.MatchedValue = maskSensitiveText(out.MatchedValue)
	out.Path = maskSensitiveText(out.Path)
	return out
}

func maskSensitiveText(in string) string {
	out := strings.TrimSpace(in)
	if out == "" {
		return ""
	}
	out = fpTunerMaskBearerToken.ReplaceAllString(out, "Bearer [redacted-token]")
	out = fpTunerMaskJWT.ReplaceAllString(out, "[redacted-jwt]")
	out = fpTunerMaskEmail.ReplaceAllString(out, "[redacted-email]")
	out = fpTunerMaskIPv4.ReplaceAllString(out, "[redacted-ip]")
	out = fpTunerMaskSecretKV.ReplaceAllString(out, "$1=[redacted]")
	out = fpTunerMaskLongToken.ReplaceAllStringFunc(out, func(v string) string {
		if strings.Contains(v, "/") || strings.Contains(v, ".") {
			return "[redacted-token]"
		}
		hasUpper := strings.IndexFunc(v, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0
		hasLower := strings.IndexFunc(v, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0
		hasDigit := strings.IndexFunc(v, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0
		if hasDigit && (hasUpper || hasLower) {
			return "[redacted-token]"
		}
		return v
	})
	return out
}

func fillFPTunerProposalDefaults(proposal fpTunerProposal, in fpTunerEventInput, targetPath string) fpTunerProposal {
	if strings.TrimSpace(proposal.ID) == "" {
		proposal.ID = fmt.Sprintf("fp-%d", time.Now().UTC().Unix())
	}
	if strings.TrimSpace(proposal.Title) == "" {
		proposal.Title = "Scoped false-positive tuning suggestion"
	}
	if strings.TrimSpace(proposal.Summary) == "" {
		proposal.Summary = fmt.Sprintf("Exclude %s from rule %d only under path prefix %s.", in.MatchedVariable, in.RuleID, in.Path)
	}
	if strings.TrimSpace(proposal.Reason) == "" {
		proposal.Reason = "Generated by tukuyomi fp-tuner mock flow"
	}
	if proposal.Confidence <= 0 {
		proposal.Confidence = fpTunerDefaultConfidence
	}
	if proposal.Confidence > 1 && proposal.Confidence <= 100 {
		proposal.Confidence = proposal.Confidence / 100
	}
	if strings.TrimSpace(proposal.TargetPath) == "" {
		proposal.TargetPath = targetPath
	}
	if strings.TrimSpace(proposal.RuleLine) == "" {
		proposal.RuleLine = buildFPTunerRuleLine(in)
	}
	return proposal
}

func buildMockFPTunerProposal(in fpTunerEventInput, targetPath string) fpTunerProposal {
	return fpTunerProposal{
		ID:         fmt.Sprintf("fp-%d", time.Now().UTC().Unix()),
		Title:      "Scoped false-positive tuning suggestion",
		Summary:    fmt.Sprintf("Possible false positive on %s (%s).", in.Path, in.MatchedVariable),
		Reason:     "Mock provider response used for API contract testing",
		Confidence: fpTunerDefaultConfidence,
		TargetPath: targetPath,
		RuleLine:   buildFPTunerRuleLine(in),
	}
}

func buildFPTunerRuleLine(in fpTunerEventInput) string {
	ruleID := in.RuleID
	if ruleID <= 0 {
		ruleID = fpTunerDefaultRuleID
	}
	path := normalizeFPTunerPath(in.Path)
	variable := normalizeFPTunerVariable(in.MatchedVariable)
	generatedID := generateFPTunerRuleID(ruleID, path, variable)
	msg := "tukuyomi fp_tuner scoped exclusion"
	return fmt.Sprintf(`SecRule REQUEST_URI "@beginsWith %s" "id:%d,phase:1,pass,nolog,ctl:ruleRemoveTargetById=%d;%s,msg:'%s'"`, path, generatedID, ruleID, variable, msg)
}

func generateFPTunerRuleID(ruleID int, path, variable string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strconv.Itoa(ruleID)))
	_, _ = h.Write([]byte("|" + path + "|" + variable))
	return 190000 + int(h.Sum32()%9000)
}

func selectFPTunerTargetPath(requested string) (string, error) {
	if strings.TrimSpace(requested) != "" {
		return ensureEditableRulePath(requested)
	}
	for _, part := range strings.Split(config.RulesFile, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := ensureEditableRulePath(part); err == nil {
			return p, nil
		}
	}
	files := configuredRuleFiles()
	if len(files) == 0 {
		return "", fmt.Errorf("no editable rule files configured")
	}
	return ensureEditableRulePath(files[0])
}

func validateFPTunerRuleLine(line string) error {
	s := strings.TrimSpace(line)
	if !fpTunerRuleLinePattern.MatchString(s) {
		return fmt.Errorf("proposal.rule_line must be a scoped SecRule REQUEST_URI exclusion")
	}
	return nil
}

func appendFPTunerRule(cur []byte, proposalID, line string) []byte {
	trimmed := strings.TrimRight(string(cur), "\n")
	if proposalID == "" {
		proposalID = "manual"
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	comment := fmt.Sprintf("# fp-tuner proposal=%s applied_at=%s", proposalID, stamp)
	if trimmed == "" {
		return []byte(comment + "\n" + line + "\n")
	}
	return []byte(trimmed + "\n\n" + comment + "\n" + line + "\n")
}

func anyToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case fmt.Stringer:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return ""
	}
}

func anyToInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int8:
		return int(t)
	case int16:
		return int(t)
	case int32:
		return int(t)
	case int64:
		return int(t)
	case uint:
		return int(t)
	case uint32:
		return int(t)
	case uint64:
		return int(t)
	case float64:
		return int(t)
	case json.Number:
		n, err := t.Int64()
		if err == nil {
			return int(n)
		}
		f, err := t.Float64()
		if err == nil {
			return int(f)
		}
		return 0
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}
