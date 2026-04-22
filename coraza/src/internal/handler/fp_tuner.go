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
	"net/url"
	"os"
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
	fpTunerDefaultConfidence    = 0.82
	fpTunerMaxMatchedValueBytes = 512
	fpTunerMaxBodyBytes         = int64(1 * 1024 * 1024)
	fpTunerApprovalTokenBytes   = 24
)

var (
	fpTunerVariableAllowed     = regexp.MustCompile(`^[A-Za-z0-9_.:!]+$`)
	fpTunerHostRuleLinePattern = regexp.MustCompile(`^SecRule REQUEST_HEADERS:Host "@(streq|rx) [^"\r\n]+" "id:[0-9]{6,},phase:1,pass,nolog,chain,msg:'[^'\r\n]*'"$`)
	fpTunerHostRuleLineParts   = regexp.MustCompile(`^SecRule REQUEST_HEADERS:Host "@(streq|rx) ([^"\r\n]+)" "id:([0-9]{6,}),phase:1,pass,nolog,chain,msg:'([^'\r\n]*)'"$`)
	fpTunerPathRuleLinePattern = regexp.MustCompile(`^SecRule REQUEST_URI "@beginsWith [^"\r\n]+" "ctl:ruleRemoveTargetById=[0-9]+;[A-Za-z0-9_.:!]+"$`)
	fpTunerPathRuleLineParts   = regexp.MustCompile(`^SecRule REQUEST_URI "@beginsWith ([^"\r\n]+)" "ctl:ruleRemoveTargetById=([0-9]+);([A-Za-z0-9_.:!]+)"$`)
	fpTunerMaskBearerToken     = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
	fpTunerMaskJWT             = regexp.MustCompile(`\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b`)
	fpTunerMaskEmail           = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	fpTunerMaskIPv4            = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	fpTunerMaskSecretKV        = regexp.MustCompile(`(?i)\b(token|access_token|refresh_token|api_key|apikey|password|passwd|secret)=([^&\s]+)`)
	fpTunerMaskLongToken       = regexp.MustCompile(`\b[A-Za-z0-9._~+/=-]{24,}\b`)
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
	Scheme          string `json:"scheme,omitempty"`
	Host            string `json:"host,omitempty"`
	Path            string `json:"path,omitempty"`
	Query           string `json:"query,omitempty"`
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

type fpTunerNoProposal struct {
	Decision   string  `json:"decision"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence,omitempty"`
}

type fpTunerProposeResult struct {
	Input      fpTunerEventInput  `json:"input"`
	Proposal   *fpTunerProposal   `json:"proposal,omitempty"`
	NoProposal *fpTunerNoProposal `json:"no_proposal,omitempty"`
	Approval   fpTunerApproval    `json:"approval"`
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

type fpTunerProviderDecision struct {
	Proposal   *fpTunerProposal
	NoProposal *fpTunerNoProposal
}

type fpTunerParsedRuleLine struct {
	HostOperator string
	HostOperand  string
	Host         string
	Path         string
	GeneratedID  int
	TargetRuleID int
	Variable     string
	Message      string
}

type fpTunerRecentWAFBlocksResponse struct {
	Lines []logLine `json:"lines"`
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
			"no_proposal":      results[0].NoProposal,
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

func GetFPTunerRecentWAFBlocks(c *gin.Context) {
	path, ok := logFiles["waf"]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "waf log source is not configured"})
		return
	}
	path = resolveLogPath("waf", path)

	limit := clampInt(mustAtoiDefault(c.Query("limit"), 20), 1, 100)
	lines, err := readRecentFPTunerWAFBlockLines(path, limit)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusOK, fpTunerRecentWAFBlocksResponse{Lines: nil})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, fpTunerRecentWAFBlocksResponse{Lines: lines})
}

func resolveFPTunerEventInput(in *fpTunerEventInput) (fpTunerEventInput, string, error) {
	if in != nil {
		norm := normalizeFPTunerEventInput(*in)
		if err := validateFPTunerResolvedEventInput("event", norm); err != nil {
			return fpTunerEventInput{}, "", err
		}
		return norm, "request", nil
	}

	event, source, err := latestSecurityEvent()
	if err != nil {
		return fpTunerEventInput{}, "", err
	}

	norm := normalizeFPTunerEventInput(event)
	if err := validateFPTunerResolvedEventInput("latest_event", norm); err != nil {
		return fpTunerEventInput{}, "", err
	}
	return norm, source, nil
}

func resolveFPTunerEventInputs(in fpTunerProposeBody) ([]fpTunerEventInput, string, error) {
	if in.Event != nil && len(in.Events) > 0 {
		return nil, "", fmt.Errorf("event and events cannot be used together")
	}
	if len(in.Events) > 0 {
		out := make([]fpTunerEventInput, 0, len(in.Events))
		for i, raw := range in.Events {
			norm := normalizeFPTunerEventInput(raw)
			if err := validateFPTunerResolvedEventInput(fmt.Sprintf("events[%d]", i), norm); err != nil {
				return nil, "", err
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
			"Target engine is Coraza with ModSecurity-compatible exclusion syntax",
			"Only return one scoped exclusion for the observed existing detection rule_id on the observed host and path",
			"Rule must be a two-line chain: REQUEST_HEADERS:Host exact match, or a default-port-aware regex for http:80 / https:443 only, then REQUEST_URI @beginsWith with ctl:ruleRemoveTargetById",
			"Never generate deny/block rules, signatures, or global disable operations",
			"If this is not a credible false positive or evidence is insufficient, return no_proposal with reason",
		},
	}
	decision, mode, err := requestFPTunerProposal(providerReq)
	if err != nil {
		return fpTunerProposeResult{}, "", &fpTunerProposeError{
			Status:  http.StatusBadGateway,
			Message: err.Error(),
			Err:     err,
		}
	}
	if decision.NoProposal != nil {
		return fpTunerProposeResult{
			Input:      event,
			NoProposal: decision.NoProposal,
			Approval:   fpTunerApproval{Required: false},
		}, mode, nil
	}
	if decision.Proposal == nil {
		return fpTunerProposeResult{}, "", &fpTunerProposeError{
			Status:  http.StatusBadGateway,
			Message: "provider returned neither proposal nor no_proposal",
			Err:     fmt.Errorf("provider returned neither proposal nor no_proposal"),
		}
	}
	proposal := fillFPTunerProposalDefaults(*decision.Proposal, event, targetPath)
	parsed, err := parseFPTunerRuleLine(proposal.RuleLine)
	if err != nil {
		return fpTunerProposeResult{}, "", &fpTunerProposeError{
			Status:  http.StatusUnprocessableEntity,
			Message: "provider returned unsafe proposal",
			Details: err.Error(),
			Err:     err,
		}
	}
	if err := validateFPTunerProposalBinding(parsed, event); err != nil {
		return fpTunerProposeResult{}, "", &fpTunerProposeError{
			Status:  http.StatusUnprocessableEntity,
			Message: "provider returned proposal outside the observed Coraza event scope",
			Details: err.Error(),
			Err:     err,
		}
	}
	result := fpTunerProposeResult{
		Input:    event,
		Proposal: &proposal,
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
		if event, ok := fpTunerEventInputFromLogLine(lines[i]); ok && event.EventType == "waf_block" {
			event.EventType = ""
			return event, nil
		}
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
		event := fpTunerEventInput{
			EventID:         anyToString(ln["req_id"]),
			EventType:       eventType,
			ObservedAt:      anyToString(ln["ts"]),
			Method:          anyToString(ln["method"]),
			Scheme:          anyToString(ln["original_scheme"]),
			Host:            firstNonEmptyString(anyToString(ln["original_host"]), anyToString(ln["rewritten_host"])),
			Path:            anyToString(ln["path"]),
			Query:           firstNonEmptyString(anyToString(ln["original_query"]), anyToString(ln["rewritten_query"])),
			Policy:          "waf",
			RuleID:          anyToInt(ln["rule_id"]),
			Status:          anyToInt(ln["status"]),
			MatchedVariable: anyToString(ln["matched_variable"]),
			MatchedValue:    anyToString(ln["matched_value"]),
		}
		return normalizeFPTunerWAFEventInput(event, ln), true
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

func normalizeFPTunerWAFEventInput(in fpTunerEventInput, ln logLine) fpTunerEventInput {
	in.Scheme = normalizeFPTunerScheme(in.Scheme)
	in.Host = normalizeFPTunerHost(in.Host)
	in.Query = normalizeFPTunerQuery(in.Query)
	in.MatchedVariable = strings.TrimSpace(in.MatchedVariable)
	in.MatchedValue = strings.TrimSpace(in.MatchedValue)
	if !shouldFallbackToQueryScope(in.MatchedVariable, in.MatchedValue) {
		return in
	}

	query := firstNonEmptyString(anyToString(ln["original_query"]), anyToString(ln["rewritten_query"]))
	query = decodeFPTunerQueryPayload(query)
	if strings.TrimSpace(query) == "" {
		return in
	}

	in.MatchedVariable = "QUERY_STRING"
	in.MatchedValue = clampText(query, fpTunerMaxMatchedValueBytes)
	in.Query = query
	return in
}

func shouldFallbackToQueryScope(variable string, value string) bool {
	variable = strings.TrimSpace(variable)
	value = strings.TrimSpace(value)
	if variable == "" {
		return value == ""
	}
	return strings.HasPrefix(variable, "TX:") || normalizeFPTunerVariable(variable) == ""
}

func decodeFPTunerQueryPayload(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(trimmed)
	if err != nil {
		return trimmed
	}
	return decoded
}

func readRecentFPTunerWAFBlockLines(path string, limit int) ([]logLine, error) {
	if limit <= 0 {
		return nil, nil
	}

	if store := getLogsStatsStore(); store != nil {
		return store.RecentWAFBlockLogLines(path, limit)
	}

	tail := minInt(maxLinesPerRead, maxInt(limit*10, limit))
	lines, _, _, _, err := readByLine(path, tail, nil, "")
	if err != nil {
		return nil, err
	}

	out := make([]logLine, 0, limit)
	for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
		if strings.TrimSpace(anyToString(lines[i]["event"])) != "waf_block" {
			continue
		}
		out = append(out, normalizeFPTunerWAFLogLine(lines[i]))
	}
	return out, nil
}

func normalizeFPTunerWAFLogLine(ln logLine) logLine {
	out := logLine{}
	for k, v := range ln {
		out[k] = v
	}
	input, ok := fpTunerEventInputFromLogLine(out)
	if !ok || input.EventType != "waf_block" {
		return out
	}
	out["matched_variable"] = input.MatchedVariable
	out["matched_value"] = input.MatchedValue
	return out
}

func normalizeFPTunerEventInput(in fpTunerEventInput) fpTunerEventInput {
	in.EventID = strings.TrimSpace(in.EventID)
	in.EventType = strings.TrimSpace(in.EventType)
	in.ObservedAt = strings.TrimSpace(in.ObservedAt)
	in.Method = strings.ToUpper(strings.TrimSpace(in.Method))
	if in.Method == "" {
		in.Method = http.MethodGet
	}
	in.Scheme = normalizeFPTunerScheme(in.Scheme)
	in.Host = normalizeFPTunerHost(in.Host)
	if in.Scheme == "" {
		in.Scheme = inferFPTunerSchemeFromHost(in.Host)
	}
	in.Path = normalizeFPTunerPath(in.Path)
	in.Query = normalizeFPTunerQuery(in.Query)
	in.Policy = strings.TrimSpace(in.Policy)
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

func validateFPTunerResolvedEventInput(field string, in fpTunerEventInput) error {
	if strings.TrimSpace(in.Host) == "" {
		return fmt.Errorf("%s.host is required", field)
	}
	if strings.TrimSpace(in.Path) == "" {
		return fmt.Errorf("%s.path is required", field)
	}
	if in.RuleID <= 0 {
		return fmt.Errorf("%s.rule_id is required", field)
	}
	if strings.TrimSpace(in.MatchedVariable) == "" {
		return fmt.Errorf("%s.matched_variable is required", field)
	}
	return nil
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
		return ""
	}
	if strings.ContainsAny(p, "\n\r\"") {
		return ""
	}
	return p
}

func normalizeFPTunerHost(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") || strings.Contains(s, "/") || strings.ContainsAny(s, " \t\r\n") {
		return ""
	}
	parsed, err := url.Parse("http://" + s)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Host)
}

func normalizeFPTunerScheme(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "http":
		return "http"
	case "https":
		return "https"
	default:
		return ""
	}
}

func inferFPTunerSchemeFromHost(host string) string {
	_, port := splitFPTunerHostPort(host)
	switch port {
	case "80":
		return "http"
	case "443":
		return "https"
	default:
		return ""
	}
}

func splitFPTunerHostPort(host string) (string, string) {
	normalized := normalizeFPTunerHost(host)
	if normalized == "" {
		return "", ""
	}
	parsed, err := url.Parse("http://" + normalized)
	if err != nil || parsed.Host == "" {
		return normalized, ""
	}
	port := parsed.Port()
	if port == "" {
		return strings.ToLower(parsed.Host), ""
	}
	return strings.ToLower(strings.TrimSuffix(parsed.Host, ":"+port)), port
}

func normalizeFPTunerQuery(v string) string {
	return clampText(strings.TrimSpace(strings.TrimPrefix(v, "?")), fpTunerMaxMatchedValueBytes)
}

func normalizeFPTunerVariable(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return ""
	}
	if !fpTunerVariableAllowed.MatchString(s) {
		return ""
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

func requestFPTunerProposal(req fpTunerProviderRequest) (fpTunerProviderDecision, string, error) {
	p, err := requestFPTunerProposalHTTP(req)
	return p, "http", err
}

func requestFPTunerProposalHTTP(req fpTunerProviderRequest) (fpTunerProviderDecision, error) {
	endpoint := strings.TrimSpace(config.FPTunerEndpoint)
	if endpoint == "" {
		return fpTunerProviderDecision{}, fmt.Errorf("fp_tuner.endpoint is empty")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fpTunerProviderDecision{}, err
	}

	client := &http.Client{Timeout: config.FPTunerTimeout}
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fpTunerProviderDecision{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(config.FPTunerAPIKey); key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+key)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return fpTunerProviderDecision{}, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fpTunerProviderDecision{}, fmt.Errorf("provider returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	decision, err := decodeFPTunerProviderResponse(raw)
	if err != nil {
		return fpTunerProviderDecision{}, err
	}
	if decision.Proposal != nil {
		proposal := fillFPTunerProposalDefaults(*decision.Proposal, req.Input, req.TargetPath)
		decision.Proposal = &proposal
	}
	if decision.NoProposal != nil {
		noProposal := normalizeFPTunerNoProposal(*decision.NoProposal)
		decision.NoProposal = &noProposal
	}
	return decision, nil
}

func decodeFPTunerProviderResponse(raw []byte) (fpTunerProviderDecision, error) {
	type wrapped struct {
		Decision   string             `json:"decision,omitempty"`
		Proposal   *fpTunerProposal   `json:"proposal,omitempty"`
		NoProposal *fpTunerNoProposal `json:"no_proposal,omitempty"`
		Reason     string             `json:"reason,omitempty"`
		Confidence float64            `json:"confidence,omitempty"`
	}

	var env wrapped
	if err := json.Unmarshal(raw, &env); err == nil {
		if env.Proposal != nil && (strings.TrimSpace(env.Proposal.RuleLine) != "" || strings.TrimSpace(env.Proposal.Summary) != "") {
			return fpTunerProviderDecision{Proposal: env.Proposal}, nil
		}
		if env.NoProposal != nil {
			return fpTunerProviderDecision{NoProposal: env.NoProposal}, nil
		}
		if strings.EqualFold(strings.TrimSpace(env.Decision), "no_proposal") {
			return fpTunerProviderDecision{NoProposal: &fpTunerNoProposal{
				Decision:   "no_proposal",
				Reason:     strings.TrimSpace(env.Reason),
				Confidence: env.Confidence,
			}}, nil
		}
	}

	var directNoProposal fpTunerNoProposal
	if err := json.Unmarshal(raw, &directNoProposal); err == nil {
		if strings.EqualFold(strings.TrimSpace(directNoProposal.Decision), "no_proposal") {
			return fpTunerProviderDecision{NoProposal: &directNoProposal}, nil
		}
	}

	var direct fpTunerProposal
	if err := json.Unmarshal(raw, &direct); err == nil {
		if strings.TrimSpace(direct.RuleLine) != "" || strings.TrimSpace(direct.Summary) != "" {
			return fpTunerProviderDecision{Proposal: &direct}, nil
		}
	}

	return fpTunerProviderDecision{}, fmt.Errorf("provider response must be fp_tuner proposal json or no_proposal json")
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
		path = defaultFPTunerAuditFile
	}

	info := newAdminAuditInfo(c, event)
	entry := map[string]any{
		"ts":      info.TS,
		"service": info.Service,
		"event":   info.Event,
		"actor":   info.Actor,
	}
	if info.IP != "" {
		entry["ip"] = info.IP
	}
	for k, v := range fields {
		entry[k] = v
	}
	emitJSONLog(entry)
	appendAdminAudit(path, "fp_tuner_audit_write_error", entry)
}

func fpTunerActor(c *gin.Context) string {
	return adminAuditActor(c)
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
	out.Query = maskSensitiveText(out.Query)
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
		proposal.Summary = fmt.Sprintf("Exclude %s from rule %d only under host %s and path prefix %s.", in.MatchedVariable, in.RuleID, in.Host, in.Path)
	}
	if strings.TrimSpace(proposal.Reason) == "" {
		proposal.Reason = "Generated by tukuyomi fp-tuner provider flow"
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

func normalizeFPTunerNoProposal(in fpTunerNoProposal) fpTunerNoProposal {
	in.Decision = "no_proposal"
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" {
		in.Reason = "Provider could not justify a safe Coraza scoped exclusion for this event."
	}
	if in.Confidence > 1 && in.Confidence <= 100 {
		in.Confidence = in.Confidence / 100
	}
	if in.Confidence < 0 {
		in.Confidence = 0
	}
	return in
}

func buildFPTunerRuleLine(in fpTunerEventInput) string {
	ruleID := in.RuleID
	if ruleID <= 0 {
		ruleID = fpTunerDefaultRuleID
	}
	scope := buildFPTunerHostScope(in.Host, in.Scheme)
	path := normalizeFPTunerPath(in.Path)
	variable := normalizeFPTunerVariable(in.MatchedVariable)
	generatedID := generateFPTunerRuleID(ruleID, scope.Operator, scope.Operand, path, variable)
	msg := "tukuyomi fp_tuner scoped exclusion"
	return fmt.Sprintf(
		"SecRule REQUEST_HEADERS:Host \"@%s %s\" \"id:%d,phase:1,pass,nolog,chain,msg:'%s'\"\nSecRule REQUEST_URI \"@beginsWith %s\" \"ctl:ruleRemoveTargetById=%d;%s\"",
		scope.Operator, scope.Operand, generatedID, msg, path, ruleID, variable,
	)
}

type fpTunerHostScope struct {
	Operator string
	Operand  string
	Host     string
}

func buildFPTunerHostScope(host string, scheme string) fpTunerHostScope {
	normalizedHost := normalizeFPTunerHost(host)
	normalizedScheme := normalizeFPTunerScheme(scheme)
	if normalizedScheme == "" {
		normalizedScheme = inferFPTunerSchemeFromHost(normalizedHost)
	}
	hostOnly, port := splitFPTunerHostPort(normalizedHost)
	switch {
	case normalizedScheme == "http" && (port == "" || port == "80") && hostOnly != "":
		return fpTunerHostScope{
			Operator: "rx",
			Operand:  "^" + regexp.QuoteMeta(hostOnly) + "(:80)?$",
			Host:     hostOnly,
		}
	case normalizedScheme == "https" && (port == "" || port == "443") && hostOnly != "":
		return fpTunerHostScope{
			Operator: "rx",
			Operand:  "^" + regexp.QuoteMeta(hostOnly) + "(:443)?$",
			Host:     hostOnly,
		}
	default:
		return fpTunerHostScope{
			Operator: "streq",
			Operand:  normalizedHost,
			Host:     normalizedHost,
		}
	}
}

func generateFPTunerRuleID(ruleID int, hostOperator string, hostOperand string, path, variable string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strconv.Itoa(ruleID)))
	_, _ = h.Write([]byte("|" + hostOperator + "|" + hostOperand + "|" + path + "|" + variable))
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
	_, err := parseFPTunerRuleLine(line)
	return err
}

func parseFPTunerRuleLine(line string) (fpTunerParsedRuleLine, error) {
	s := strings.TrimSpace(line)
	parts := strings.Split(s, "\n")
	if len(parts) != 2 {
		return fpTunerParsedRuleLine{}, fmt.Errorf("proposal.rule_line must be a scoped Host + REQUEST_URI chain exclusion")
	}
	hostLine := strings.TrimSpace(parts[0])
	pathLine := strings.TrimSpace(parts[1])
	if !fpTunerHostRuleLinePattern.MatchString(hostLine) || !fpTunerPathRuleLinePattern.MatchString(pathLine) {
		return fpTunerParsedRuleLine{}, fmt.Errorf("proposal.rule_line must be a scoped Host + REQUEST_URI chain exclusion")
	}
	hostParts := fpTunerHostRuleLineParts.FindStringSubmatch(hostLine)
	pathParts := fpTunerPathRuleLineParts.FindStringSubmatch(pathLine)
	if len(hostParts) != 5 || len(pathParts) != 4 {
		return fpTunerParsedRuleLine{}, fmt.Errorf("proposal.rule_line must be a scoped Host + REQUEST_URI chain exclusion")
	}
	hostScope, err := parseFPTunerHostScope(hostParts[1], hostParts[2])
	if err != nil {
		return fpTunerParsedRuleLine{}, fmt.Errorf("proposal.rule_line must be a scoped Host + REQUEST_URI chain exclusion")
	}
	generatedID, err := strconv.Atoi(hostParts[3])
	if err != nil {
		return fpTunerParsedRuleLine{}, fmt.Errorf("proposal.rule_line has invalid generated rule id")
	}
	targetRuleID, err := strconv.Atoi(pathParts[2])
	if err != nil {
		return fpTunerParsedRuleLine{}, fmt.Errorf("proposal.rule_line has invalid target rule id")
	}
	return fpTunerParsedRuleLine{
		HostOperator: hostScope.Operator,
		HostOperand:  hostScope.Operand,
		Host:         hostScope.Host,
		Path:         normalizeFPTunerPath(pathParts[1]),
		GeneratedID:  generatedID,
		TargetRuleID: targetRuleID,
		Variable:     pathParts[3],
		Message:      hostParts[4],
	}, nil
}

func parseFPTunerHostScope(operator string, operand string) (fpTunerHostScope, error) {
	switch strings.TrimSpace(operator) {
	case "streq":
		host := normalizeFPTunerHost(operand)
		if host == "" {
			return fpTunerHostScope{}, fmt.Errorf("invalid host exact match")
		}
		return fpTunerHostScope{Operator: "streq", Operand: host, Host: host}, nil
	case "rx":
		host, defaultPort, err := parseFPTunerDefaultPortRegexOperand(operand)
		if err != nil {
			return fpTunerHostScope{}, err
		}
		return fpTunerHostScope{
			Operator: "rx",
			Operand:  "^" + regexp.QuoteMeta(host) + "(:%s)?$",
			Host:     host,
		}.withDefaultPort(defaultPort), nil
	default:
		return fpTunerHostScope{}, fmt.Errorf("unsupported host operator")
	}
}

func (s fpTunerHostScope) withDefaultPort(defaultPort string) fpTunerHostScope {
	if s.Operator == "rx" {
		s.Operand = fmt.Sprintf(s.Operand, defaultPort)
	}
	return s
}

func parseFPTunerDefaultPortRegexOperand(operand string) (string, string, error) {
	switch {
	case strings.HasPrefix(operand, "^") && strings.HasSuffix(operand, "(:80)?$"):
		host, err := unescapeFPTunerQuotedRegexLiteral(strings.TrimSuffix(strings.TrimPrefix(operand, "^"), "(:80)?$"))
		return host, "80", err
	case strings.HasPrefix(operand, "^") && strings.HasSuffix(operand, "(:443)?$"):
		host, err := unescapeFPTunerQuotedRegexLiteral(strings.TrimSuffix(strings.TrimPrefix(operand, "^"), "(:443)?$"))
		return host, "443", err
	default:
		return "", "", fmt.Errorf("unsupported host regex")
	}
}

func unescapeFPTunerQuotedRegexLiteral(escaped string) (string, error) {
	if strings.TrimSpace(escaped) == "" {
		return "", fmt.Errorf("empty host literal")
	}
	var out strings.Builder
	escapeNext := false
	for _, r := range escaped {
		if escapeNext {
			out.WriteRune(r)
			escapeNext = false
			continue
		}
		if r == '\\' {
			escapeNext = true
			continue
		}
		if strings.ContainsRune(`.^$|?*+()[]{}\`, r) {
			return "", fmt.Errorf("regex metacharacters must be escaped")
		}
		out.WriteRune(r)
	}
	if escapeNext {
		return "", fmt.Errorf("trailing escape")
	}
	literal := out.String()
	host := normalizeFPTunerHost(literal)
	hostOnly, port := splitFPTunerHostPort(host)
	if host == "" || hostOnly == "" || port != "" {
		return "", fmt.Errorf("invalid host literal")
	}
	if regexp.QuoteMeta(hostOnly) != escaped {
		return "", fmt.Errorf("host regex must be a quoted literal")
	}
	return hostOnly, nil
}

func validateFPTunerProposalBinding(parsed fpTunerParsedRuleLine, event fpTunerEventInput) error {
	expectedHostScope := buildFPTunerHostScope(event.Host, event.Scheme)
	expectedPath := normalizeFPTunerPath(event.Path)
	expectedVariable := normalizeFPTunerVariable(event.MatchedVariable)
	if expectedHostScope.Operand == "" || expectedPath == "" || expectedVariable == "" || event.RuleID <= 0 {
		return fmt.Errorf("observed fp tuner event is incomplete")
	}
	if parsed.HostOperator != expectedHostScope.Operator || parsed.HostOperand != expectedHostScope.Operand {
		return fmt.Errorf("proposal.rule_line must stay on observed host scope %q", expectedHostScope.Operand)
	}
	if parsed.Path != expectedPath {
		return fmt.Errorf("proposal.rule_line must stay on observed path %q", expectedPath)
	}
	if parsed.TargetRuleID != event.RuleID {
		return fmt.Errorf("proposal.rule_line must target observed rule_id %d", event.RuleID)
	}
	if parsed.Variable != expectedVariable {
		return fmt.Errorf("proposal.rule_line must target observed matched_variable %q", expectedVariable)
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
