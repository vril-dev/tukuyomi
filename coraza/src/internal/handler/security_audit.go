package handler

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
	"tukuyomi/internal/logfilearchive"
	"tukuyomi/internal/observability"
	"tukuyomi/internal/waf"
)

const (
	securityAuditCaptureModeOff                = "off"
	securityAuditCaptureModeEnforcedOnly       = "enforced_only"
	securityAuditCaptureModeSecurityEvents     = "security_events"
	securityAuditCaptureModeAllSecurityFinding = "all_security_findings"

	securityAuditCipherAES256GCM = "AES-256-GCM"
	securityAuditEventName       = "security_audit"
)

type securityAuditRuntime struct {
	Enabled                bool
	CaptureMode            string
	CaptureHeaders         bool
	CaptureBody            bool
	MaxBodyBytes           int64
	RedactHeaders          map[string]struct{}
	RedactBodyContentTypes []string
	EncryptionKey          []byte
	EncryptionKeyID        string
	HMACKey                []byte
	HMACKeyID              string
	File                   string
	BlobDir                string

	RecordsTotal             atomic.Uint64
	CapturesTotal            atomic.Uint64
	VerifyFailuresTotal      atomic.Uint64
	LastVerifyAtUnix         atomic.Int64
	LastVerifyOK             atomic.Bool
	LastVerifyError          atomic.Value
	LastIntegritySequence    atomic.Int64
	LastIntegrityHash        atomic.Value
	LastCaptureError         atomic.Value
	LastWriteError           atomic.Value
	LastVerificationAnchored atomic.Bool
}

type securityAuditStatus struct {
	Enabled                bool   `json:"enabled"`
	CaptureMode            string `json:"capture_mode"`
	CaptureHeaders         bool   `json:"capture_headers"`
	CaptureBody            bool   `json:"capture_body"`
	MaxBodyBytes           int64  `json:"max_body_bytes"`
	File                   string `json:"file"`
	BlobDir                string `json:"blob_dir"`
	EncryptionKeyID        string `json:"encryption_key_id,omitempty"`
	HMACKeyID              string `json:"hmac_key_id,omitempty"`
	RecordsTotal           uint64 `json:"records_total"`
	CapturesTotal          uint64 `json:"captures_total"`
	VerifyFailuresTotal    uint64 `json:"verify_failures_total"`
	LastVerifyAt           string `json:"last_verify_at,omitempty"`
	LastVerifyOK           bool   `json:"last_verify_ok"`
	LastVerifyError        string `json:"last_verify_error,omitempty"`
	LastIntegritySequence  int64  `json:"last_integrity_sequence"`
	LastIntegrityHash      string `json:"last_integrity_hash,omitempty"`
	LastCaptureError       string `json:"last_capture_error,omitempty"`
	LastWriteError         string `json:"last_write_error,omitempty"`
	LastVerificationAnchor bool   `json:"last_verification_anchored"`
}

type securityAuditEvidenceCapture struct {
	Headers         map[string][]string
	Body            []byte
	BodyCaptured    bool
	BodyTruncated   bool
	BodyRedacted    bool
	BodyContentType string
}

type securityAuditEvidenceBlob struct {
	Version         int    `json:"version"`
	Cipher          string `json:"cipher"`
	KeyID           string `json:"key_id"`
	CreatedAt       string `json:"created_at"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
	PlaintextSize   int    `json:"plaintext_size"`
}

type securityAuditBlobIn struct {
	Method          string              `json:"method"`
	Host            string              `json:"host"`
	Path            string              `json:"path"`
	Query           string              `json:"query,omitempty"`
	Headers         map[string][]string `json:"headers,omitempty"`
	BodyBase64      string              `json:"body_base64,omitempty"`
	BodyContentType string              `json:"body_content_type,omitempty"`
	BodyCaptured    bool                `json:"body_captured"`
	BodyTruncated   bool                `json:"body_truncated,omitempty"`
	BodyRedacted    bool                `json:"body_redacted,omitempty"`
}

type securityAuditEvidenceMetadata struct {
	CaptureID       string `json:"capture_id"`
	StorageRef      string `json:"storage_ref,omitempty"`
	Cipher          string `json:"cipher"`
	KeyID           string `json:"key_id"`
	SHA256          string `json:"sha256"`
	Size            int    `json:"size"`
	HeadersCaptured bool   `json:"headers_captured"`
	BodyCaptured    bool   `json:"body_captured"`
	BodyTruncated   bool   `json:"body_truncated,omitempty"`
	BodyRedacted    bool   `json:"body_redacted,omitempty"`
	BodyContentType string `json:"body_content_type,omitempty"`
}

type securityAuditDecisionNode struct {
	Step            int            `json:"step"`
	Phase           string         `json:"phase"`
	PolicyFamily    string         `json:"policy_family"`
	Matched         bool           `json:"matched"`
	SourceEvent     string         `json:"source_event,omitempty"`
	RuleID          string         `json:"rule_id,omitempty"`
	SignalID        string         `json:"signal_id,omitempty"`
	ScoreBefore     *int           `json:"score_before,omitempty"`
	ScoreDelta      *int           `json:"score_delta,omitempty"`
	ScoreAfter      *int           `json:"score_after,omitempty"`
	Threshold       *int           `json:"threshold,omitempty"`
	ActionCandidate string         `json:"action_candidate,omitempty"`
	ActionEffective string         `json:"action_effective,omitempty"`
	Status          *int           `json:"status,omitempty"`
	DryRun          bool           `json:"dry_run,omitempty"`
	DependsOn       []int          `json:"depends_on,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

type securityAuditIntegrity struct {
	Version   int    `json:"version"`
	KeyID     string `json:"key_id"`
	PrevHash  string `json:"prev_hash,omitempty"`
	EntryHash string `json:"entry_hash"`
	Signature string `json:"signature"`
	Sequence  int64  `json:"sequence"`
}

type securityAuditRecord struct {
	Version        int                            `json:"version"`
	TS             string                         `json:"ts"`
	Service        string                         `json:"service"`
	Event          string                         `json:"event"`
	DecisionID     string                         `json:"decision_id"`
	ReqID          string                         `json:"req_id"`
	TraceID        string                         `json:"trace_id,omitempty"`
	IP             string                         `json:"ip,omitempty"`
	Country        string                         `json:"country,omitempty"`
	CountrySource  string                         `json:"country_source,omitempty"`
	Method         string                         `json:"method,omitempty"`
	Host           string                         `json:"host,omitempty"`
	Path           string                         `json:"path,omitempty"`
	Query          string                         `json:"query,omitempty"`
	FinalAction    string                         `json:"final_action"`
	FinalStatus    int                            `json:"final_status,omitempty"`
	TerminalPolicy string                         `json:"terminal_policy,omitempty"`
	TerminalEvent  string                         `json:"terminal_event,omitempty"`
	DecisionChain  []securityAuditDecisionNode    `json:"decision_chain,omitempty"`
	Evidence       *securityAuditEvidenceMetadata `json:"evidence,omitempty"`
	Warnings       []string                       `json:"warnings,omitempty"`
	Integrity      securityAuditIntegrity         `json:"integrity"`
}

type signableSecurityAuditRecord struct {
	Version        int                            `json:"version"`
	TS             string                         `json:"ts"`
	Service        string                         `json:"service"`
	Event          string                         `json:"event"`
	DecisionID     string                         `json:"decision_id"`
	ReqID          string                         `json:"req_id"`
	TraceID        string                         `json:"trace_id,omitempty"`
	IP             string                         `json:"ip,omitempty"`
	Country        string                         `json:"country,omitempty"`
	CountrySource  string                         `json:"country_source,omitempty"`
	Method         string                         `json:"method,omitempty"`
	Host           string                         `json:"host,omitempty"`
	Path           string                         `json:"path,omitempty"`
	Query          string                         `json:"query,omitempty"`
	FinalAction    string                         `json:"final_action"`
	FinalStatus    int                            `json:"final_status,omitempty"`
	TerminalPolicy string                         `json:"terminal_policy,omitempty"`
	TerminalEvent  string                         `json:"terminal_event,omitempty"`
	DecisionChain  []securityAuditDecisionNode    `json:"decision_chain,omitempty"`
	Evidence       *securityAuditEvidenceMetadata `json:"evidence,omitempty"`
	Warnings       []string                       `json:"warnings,omitempty"`
}

type securityAuditStreamState struct {
	LastHash     string `json:"last_hash,omitempty"`
	LastSequence int64  `json:"last_sequence"`
}

type securityAuditStateEnvelope struct {
	Version   int                      `json:"version"`
	KeyID     string                   `json:"key_id"`
	State     securityAuditStreamState `json:"state"`
	Signature string                   `json:"signature"`
}

type securityAuditVerifyResult struct {
	OK        bool   `json:"ok"`
	Anchored  bool   `json:"anchored"`
	Entries   int    `json:"entries"`
	Files     int    `json:"files"`
	LastHash  string `json:"last_hash,omitempty"`
	LastSeq   int64  `json:"last_sequence"`
	CheckedAt string `json:"checked_at"`
	Error     string `json:"error,omitempty"`
}

type securityAuditTrail struct {
	DecisionID    string
	RequestID     string
	TraceID       string
	ClientIP      string
	Country       string
	CountrySource string
	Method        string
	Host          string
	Path          string
	Query         string
	Evidence      *securityAuditEvidenceCapture

	Nodes          []securityAuditDecisionNode
	Findings       bool
	Terminal       bool
	TerminalPolicy string
	TerminalEvent  string
	FinalAction    string
	FinalStatus    int
	Warnings       []string
	Emitted        bool

	BotNodeID       int
	SemanticNodeIDs []int
	SemanticNodeID  int
}

type securityAuditWriter struct {
	mu    sync.Mutex
	state map[string]securityAuditStreamState
}

var (
	securityAuditMu             sync.RWMutex
	securityAuditConfig         *securityAuditRuntime
	securityAuditWriterInstance = &securityAuditWriter{
		state: make(map[string]securityAuditStreamState),
	}
)

func InitSecurityAuditRuntime() error {
	rt := &securityAuditRuntime{
		Enabled:                config.SecurityAuditEnabled,
		CaptureMode:            strings.TrimSpace(config.SecurityAuditCaptureMode),
		CaptureHeaders:         config.SecurityAuditCaptureHeaders,
		CaptureBody:            config.SecurityAuditCaptureBody,
		MaxBodyBytes:           config.SecurityAuditMaxBodyBytes,
		RedactHeaders:          make(map[string]struct{}, len(config.SecurityAuditRedactHeaders)),
		RedactBodyContentTypes: append([]string(nil), config.SecurityAuditRedactBodyContentTypes...),
		EncryptionKeyID:        strings.TrimSpace(config.SecurityAuditEncryptionKeyID),
		HMACKeyID:              strings.TrimSpace(config.SecurityAuditHMACKeyID),
		File:                   strings.TrimSpace(config.SecurityAuditFile),
		BlobDir:                strings.TrimSpace(config.SecurityAuditBlobDir),
	}
	for _, header := range config.SecurityAuditRedactHeaders {
		header = strings.ToLower(strings.TrimSpace(header))
		if header != "" {
			rt.RedactHeaders[header] = struct{}{}
		}
	}
	if !rt.Enabled {
		securityAuditMu.Lock()
		securityAuditConfig = rt
		securityAuditMu.Unlock()
		return nil
	}
	if rt.CaptureMode == "" {
		rt.CaptureMode = securityAuditCaptureModeOff
	}
	if rt.File == "" {
		return fmt.Errorf("security audit file path is empty")
	}
	if rt.CaptureMode != securityAuditCaptureModeOff && (rt.CaptureHeaders || rt.CaptureBody) {
		if rt.BlobDir == "" {
			return fmt.Errorf("security audit blob dir is empty")
		}
		key, err := decodeSecurityAuditKey(config.SecurityAuditEncryptionKey, 32)
		if err != nil {
			return fmt.Errorf("security audit encryption key: %w", err)
		}
		rt.EncryptionKey = key
	}
	hmacKey, err := decodeSecurityAuditHMACKey(config.SecurityAuditHMACKey)
	if err != nil {
		return fmt.Errorf("security audit hmac key: %w", err)
	}
	rt.HMACKey = hmacKey
	if rt.CaptureMode != securityAuditCaptureModeOff && rt.MaxBodyBytes <= 0 {
		rt.MaxBodyBytes = 32 * 1024
	}
	securityAuditMu.Lock()
	securityAuditConfig = rt
	securityAuditMu.Unlock()
	return nil
}

func currentSecurityAuditRuntime() *securityAuditRuntime {
	securityAuditMu.RLock()
	defer securityAuditMu.RUnlock()
	return securityAuditConfig
}

func SecurityAuditStatusSnapshot() securityAuditStatus {
	rt := currentSecurityAuditRuntime()
	if rt == nil {
		return securityAuditStatus{}
	}
	status := securityAuditStatus{
		Enabled:                rt.Enabled,
		CaptureMode:            rt.CaptureMode,
		CaptureHeaders:         rt.CaptureHeaders,
		CaptureBody:            rt.CaptureBody,
		MaxBodyBytes:           rt.MaxBodyBytes,
		File:                   rt.File,
		BlobDir:                rt.BlobDir,
		EncryptionKeyID:        rt.EncryptionKeyID,
		HMACKeyID:              rt.HMACKeyID,
		RecordsTotal:           rt.RecordsTotal.Load(),
		CapturesTotal:          rt.CapturesTotal.Load(),
		VerifyFailuresTotal:    rt.VerifyFailuresTotal.Load(),
		LastVerifyOK:           rt.LastVerifyOK.Load(),
		LastIntegritySequence:  rt.LastIntegritySequence.Load(),
		LastVerificationAnchor: rt.LastVerificationAnchored.Load(),
	}
	if lastVerifyAt := rt.LastVerifyAtUnix.Load(); lastVerifyAt > 0 {
		status.LastVerifyAt = time.Unix(lastVerifyAt, 0).UTC().Format(time.RFC3339Nano)
	}
	if raw, ok := rt.LastVerifyError.Load().(string); ok {
		status.LastVerifyError = strings.TrimSpace(raw)
	}
	if raw, ok := rt.LastIntegrityHash.Load().(string); ok {
		status.LastIntegrityHash = strings.TrimSpace(raw)
	}
	if raw, ok := rt.LastCaptureError.Load().(string); ok {
		status.LastCaptureError = strings.TrimSpace(raw)
	}
	if raw, ok := rt.LastWriteError.Load().(string); ok {
		status.LastWriteError = strings.TrimSpace(raw)
	}
	return status
}

func decodeSecurityAuditKey(raw string, wantLen int) ([]byte, error) {
	key, err := decodeSecurityAuditKeyMaterial(raw)
	if err != nil {
		return nil, err
	}
	if len(key) != wantLen {
		return nil, fmt.Errorf("must be %d bytes after decoding", wantLen)
	}
	return key, nil
}

func decodeSecurityAuditHMACKey(raw string) ([]byte, error) {
	key, err := decodeSecurityAuditKeyMaterial(raw)
	if err != nil {
		return nil, err
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("must be at least 32 bytes after decoding")
	}
	return key, nil
}

func decodeSecurityAuditKeyMaterial(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("is empty")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if out, err := enc.DecodeString(raw); err == nil && len(out) > 0 {
			return out, nil
		}
	}
	return []byte(raw), nil
}

func newSecurityAuditTrail(req *http.Request, reqID, clientIP, country string) *securityAuditTrail {
	rt := currentSecurityAuditRuntime()
	if rt == nil || !rt.Enabled || req == nil {
		return nil
	}
	trail := &securityAuditTrail{
		DecisionID: fmt.Sprintf("%s-%x", strings.TrimSpace(reqID), time.Now().UTC().UnixNano()),
		RequestID:  strings.TrimSpace(reqID),
		TraceID:    observability.TraceIDFromContext(req.Context()),
		ClientIP:   strings.TrimSpace(clientIP),
		Country:    strings.TrimSpace(country),
		Method:     strings.ToUpper(strings.TrimSpace(req.Method)),
		Host:       strings.TrimSpace(req.Host),
	}
	if req.URL != nil {
		trail.Path = req.URL.Path
		trail.Query = req.URL.RawQuery
	}
	capture, err := prepareSecurityAuditEvidence(req)
	if err != nil {
		trail.Warnings = append(trail.Warnings, "capture_prepare_error:"+err.Error())
		rt.LastCaptureError.Store(err.Error())
	} else {
		trail.Evidence = capture
	}
	return trail
}

func prepareSecurityAuditEvidence(req *http.Request) (*securityAuditEvidenceCapture, error) {
	rt := currentSecurityAuditRuntime()
	if rt == nil || !rt.Enabled || req == nil {
		return nil, nil
	}
	if !rt.CaptureHeaders && !rt.CaptureBody {
		return nil, nil
	}
	capture := &securityAuditEvidenceCapture{}
	if rt.CaptureHeaders {
		capture.Headers = cloneAndRedactHeaders(req.Header, rt.RedactHeaders)
	}
	if rt.CaptureBody && req.Body != nil && rt.CaptureMode != securityAuditCaptureModeOff {
		contentType := normalizeSecurityAuditContentType(req.Header.Get("Content-Type"))
		capture.BodyContentType = contentType
		if matchesSecurityAuditContentType(rt.RedactBodyContentTypes, contentType) {
			capture.BodyCaptured = false
			capture.BodyRedacted = true
			return capture, nil
		}
		limit := rt.MaxBodyBytes
		if limit <= 0 {
			limit = 32 * 1024
		}
		buf, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), req.Body))
		capture.BodyCaptured = len(buf) > 0
		if int64(len(buf)) > limit {
			capture.Body = append([]byte(nil), buf[:limit]...)
			capture.BodyTruncated = true
		} else {
			capture.Body = append([]byte(nil), buf...)
		}
	}
	return capture, nil
}

func cloneAndRedactHeaders(in http.Header, redactions map[string]struct{}) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for key, values := range in {
		if _, ok := redactions[strings.ToLower(strings.TrimSpace(key))]; ok {
			out[key] = []string{"[REDACTED]"}
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	return out
}

func normalizeSecurityAuditContentType(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if idx := strings.Index(v, ";"); idx >= 0 {
		v = v[:idx]
	}
	return strings.TrimSpace(v)
}

func matchesSecurityAuditContentType(patterns []string, contentType string) bool {
	contentType = normalizeSecurityAuditContentType(contentType)
	if contentType == "" {
		return false
	}
	for _, pattern := range patterns {
		pattern = normalizeSecurityAuditContentType(pattern)
		if pattern == "" {
			continue
		}
		if contentType == pattern || strings.HasPrefix(contentType, pattern) {
			return true
		}
	}
	return false
}

func (t *securityAuditTrail) addNode(node securityAuditDecisionNode) int {
	if t == nil {
		return 0
	}
	node.Step = len(t.Nodes) + 1
	if len(node.DependsOn) > 0 {
		node.DependsOn = append([]int(nil), node.DependsOn...)
	}
	t.Nodes = append(t.Nodes, node)
	if node.Matched {
		t.Findings = true
	}
	return node.Step
}

func ptrInt(v int) *int {
	out := v
	return &out
}

func (t *securityAuditTrail) recordCountryBlock(status int, country string) int {
	metadata := map[string]any{
		"country": strings.TrimSpace(country),
	}
	if strings.TrimSpace(t.CountrySource) != "" {
		metadata["country_source"] = strings.TrimSpace(t.CountrySource)
	}
	return t.addNode(securityAuditDecisionNode{
		Phase:           "pre_waf",
		PolicyFamily:    "country_block",
		Matched:         true,
		SourceEvent:     "country_block",
		ActionCandidate: "block",
		ActionEffective: "block",
		Status:          ptrInt(status),
		Metadata:        metadata,
	})
}

func (t *securityAuditTrail) recordIPReputation(status int) int {
	return t.addNode(securityAuditDecisionNode{
		Phase:           "pre_waf",
		PolicyFamily:    "ip_reputation",
		Matched:         true,
		SourceEvent:     "ip_reputation",
		ActionCandidate: "block",
		ActionEffective: "block",
		Status:          ptrInt(status),
	})
}

func (t *securityAuditTrail) recordBotDefense(decision botDefenseDecision, sourceEvent string, challengePenaltyApplied bool, challengePenaltyTTL time.Duration) int {
	metadata := map[string]any{
		"mode":       decision.Mode,
		"risk_score": decision.RiskScore,
	}
	if decision.FlowPolicy != "" {
		metadata["flow_policy"] = decision.FlowPolicy
	}
	if len(decision.Signals) > 0 {
		metadata["signals"] = append([]string(nil), decision.Signals...)
	}
	if decision.ChallengeOutcome != "" {
		metadata["challenge_outcome"] = decision.ChallengeOutcome
	}
	if decision.ChallengeFailureReason != "" {
		metadata["challenge_failure_reason"] = decision.ChallengeFailureReason
	}
	if decision.TelemetryCookieRequired {
		metadata["telemetry_cookie_required"] = true
	}
	if challengePenaltyApplied {
		metadata["ip_reputation_feedback_applied"] = true
		metadata["ip_reputation_feedback_ttl_seconds"] = int(challengePenaltyTTL.Seconds())
	}
	step := t.addNode(securityAuditDecisionNode{
		Phase:           "pre_waf",
		PolicyFamily:    "bot_defense",
		Matched:         decision.Action != "" || decision.RiskScore > 0,
		SourceEvent:     sourceEvent,
		ActionCandidate: decision.Action,
		ActionEffective: botDefenseEffectiveAction(decision),
		Status:          optionalStatusPtr(decision.Status),
		DryRun:          decision.DryRun,
		Metadata:        metadata,
	})
	t.BotNodeID = step
	return step
}

func botDefenseEffectiveAction(decision botDefenseDecision) string {
	if decision.Action == "" {
		return "allow"
	}
	if decision.DryRun {
		return "dry_run"
	}
	return decision.Action
}

func optionalStatusPtr(v int) *int {
	if v <= 0 {
		return nil
	}
	return ptrInt(v)
}

func (t *securityAuditTrail) recordSemantic(eval semanticEvaluation) int {
	if t == nil {
		return 0
	}
	score := 0
	t.SemanticNodeIDs = t.SemanticNodeIDs[:0]
	appendSignalNodes := func(phase string, signals []semanticSignal) {
		for _, signal := range signals {
			before := score
			score += signal.Score
			step := t.addNode(securityAuditDecisionNode{
				Phase:        phase,
				PolicyFamily: "semantic",
				Matched:      signal.Score > 0,
				SourceEvent:  "semantic_anomaly",
				SignalID:     signal.Reason,
				ScoreBefore:  ptrInt(before),
				ScoreDelta:   ptrInt(signal.Score),
				ScoreAfter:   ptrInt(score),
			})
			if step > 0 {
				t.SemanticNodeIDs = append(t.SemanticNodeIDs, step)
			}
		}
	}
	appendSignalNodes("semantic_base", eval.BaseSignals)
	appendSignalNodes("semantic_stateful", eval.StatefulSignals)
	appendSignalNodes("semantic_provider", eval.ProviderSignals)

	threshold := semanticThresholdForAction(eval.Action)
	metadata := map[string]any{
		"reasons":                  append([]string(nil), eval.Reasons...),
		"base_reasons":             append([]string(nil), eval.BaseReasons...),
		"stateful_reasons":         append([]string(nil), eval.StatefulReasons...),
		"provider_reasons":         append([]string(nil), eval.ProviderReasons...),
		"base_score":               eval.BaseScore,
		"stateful_score":           eval.StatefulScore,
		"provider_score":           eval.ProviderScore,
		"score_breakdown":          semanticSignalLogObjects(eval.Signals),
		"base_score_breakdown":     semanticSignalLogObjects(eval.BaseSignals),
		"stateful_score_breakdown": semanticSignalLogObjects(eval.StatefulSignals),
		"provider_score_breakdown": semanticSignalLogObjects(eval.ProviderSignals),
	}
	step := t.addNode(securityAuditDecisionNode{
		Phase:           "semantic_decision",
		PolicyFamily:    "semantic",
		Matched:         eval.Score > 0 || eval.Action != semanticActionNone,
		SourceEvent:     "semantic_anomaly",
		ScoreBefore:     ptrInt(0),
		ScoreDelta:      ptrInt(eval.Score),
		ScoreAfter:      ptrInt(eval.Score),
		Threshold:       threshold,
		ActionCandidate: eval.Action,
		ActionEffective: semanticEffectiveAction(eval.Action),
		DependsOn:       append([]int(nil), t.SemanticNodeIDs...),
		Metadata:        metadata,
	})
	t.SemanticNodeID = step
	return step
}

func semanticThresholdForAction(action string) *int {
	cfg := GetSemanticConfig()
	switch action {
	case semanticActionLogOnly:
		return ptrInt(cfg.LogThreshold)
	case semanticActionChallenge:
		return ptrInt(cfg.ChallengeThreshold)
	case semanticActionBlock:
		return ptrInt(cfg.BlockThreshold)
	default:
		return nil
	}
}

func semanticEffectiveAction(action string) string {
	switch action {
	case semanticActionLogOnly:
		return "observe"
	case semanticActionChallenge:
		return "challenge"
	case semanticActionBlock:
		return "block"
	default:
		return "allow"
	}
}

func (t *securityAuditTrail) recordRateLimit(decision rateLimitDecision, semanticScore, botRisk int, feedback requestSecurityRateLimitFeedbackResult) int {
	depends := make([]int, 0, 2)
	if t.SemanticNodeID > 0 && semanticScore > 0 {
		depends = append(depends, t.SemanticNodeID)
	}
	if t.BotNodeID > 0 && botRisk > 0 {
		depends = append(depends, t.BotNodeID)
	}
	actionEffective := "block"
	if feedback.Promoted {
		if feedback.DryRun {
			actionEffective = "dry_run"
		} else {
			actionEffective = "quarantine"
		}
	}
	metadata := map[string]any{
		"policy_id":   decision.PolicyID,
		"limit":       decision.Limit,
		"base_limit":  decision.BaseLimit,
		"window_sec":  decision.WindowSeconds,
		"key_by":      decision.KeyBy,
		"key_hash":    decision.Key,
		"adaptive":    decision.Adaptive,
		"risk_score":  decision.RiskScore,
		"retry_after": decision.RetryAfterSeconds,
	}
	if feedback.Promoted {
		metadata["quarantine_promoted"] = true
		metadata["quarantine_promotion_dry_run"] = feedback.DryRun
		metadata["quarantine_promotion_strikes"] = feedback.Strikes
	}
	return t.addNode(securityAuditDecisionNode{
		Phase:           "pre_waf",
		PolicyFamily:    "rate_limit",
		Matched:         !decision.Allowed,
		SourceEvent:     "rate_limited",
		ActionCandidate: "block",
		ActionEffective: actionEffective,
		Status:          optionalStatusPtr(decision.Status),
		DependsOn:       depends,
		Metadata:        metadata,
	})
}

func copyStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return append([]string(nil), in...)
}

func (t *securityAuditTrail) recordWAFMatches(matches []waf.Match) []int {
	if t == nil || len(matches) == 0 {
		return nil
	}
	steps := make([]int, 0, len(matches))
	for _, matched := range matches {
		if matched.RuleID <= 0 {
			continue
		}
		metadata := map[string]any{
			"phase":              matched.Phase,
			"disruptive":         matched.Disruptive,
			"matched_data_count": len(matched.MatchedData),
		}
		if file := strings.TrimSpace(matched.File); file != "" {
			metadata["rule_file"] = file
		}
		if line := matched.Line; line > 0 {
			metadata["rule_line"] = line
		}
		if revision := strings.TrimSpace(matched.Revision); revision != "" {
			metadata["revision"] = revision
		}
		if version := strings.TrimSpace(matched.Version); version != "" {
			metadata["version"] = version
		}
		if severity := strings.TrimSpace(matched.Severity); severity != "" {
			metadata["severity"] = severity
		}
		if maturity := matched.Maturity; maturity > 0 {
			metadata["maturity"] = maturity
		}
		if accuracy := matched.Accuracy; accuracy > 0 {
			metadata["accuracy"] = accuracy
		}
		if operator := strings.TrimSpace(matched.Operator); operator != "" {
			metadata["operator"] = operator
		}
		if tags := copyStringSlice(matched.Tags); len(tags) > 0 {
			metadata["tags"] = tags
		}
		action := "observe"
		if matched.Disruptive {
			action = "block"
		}
		step := t.addNode(securityAuditDecisionNode{
			Phase:           "waf_rule_match",
			PolicyFamily:    "waf",
			Matched:         true,
			SourceEvent:     "waf_rule_match",
			RuleID:          strconv.Itoa(matched.RuleID),
			ActionCandidate: action,
			ActionEffective: action,
			Metadata:        metadata,
		})
		if step > 0 {
			steps = append(steps, step)
		}
	}
	return steps
}

func (t *securityAuditTrail) recordWAFBlock(ruleID int, status int, dependsOn []int) int {
	return t.addNode(securityAuditDecisionNode{
		Phase:           "waf",
		PolicyFamily:    "waf",
		Matched:         true,
		SourceEvent:     "waf_block",
		RuleID:          strconv.Itoa(ruleID),
		ActionCandidate: "block",
		ActionEffective: "block",
		Status:          optionalStatusPtr(status),
		DependsOn:       append([]int(nil), dependsOn...),
	})
}

func (t *securityAuditTrail) setTerminal(policy, event, action string, status int) {
	if t == nil {
		return
	}
	t.Terminal = true
	t.TerminalPolicy = strings.TrimSpace(policy)
	t.TerminalEvent = strings.TrimSpace(event)
	t.FinalAction = strings.TrimSpace(action)
	t.FinalStatus = status
	t.Findings = true
}

func (t *securityAuditTrail) Finalize(c *gin.Context) {
	var w http.ResponseWriter
	if c != nil {
		w = c.Writer
	}
	t.FinalizeHTTP(w)
}

func (t *securityAuditTrail) FinalizeHTTP(w http.ResponseWriter) {
	if t == nil || t.Emitted {
		return
	}
	rt := currentSecurityAuditRuntime()
	if rt == nil || !rt.Enabled {
		return
	}

	finalStatus := t.FinalStatus
	if finalStatus == 0 && w != nil {
		finalStatus = proxyResponseStatus(w, 0)
	}
	finalAction := strings.TrimSpace(t.FinalAction)
	if finalAction == "" {
		switch {
		case t.Terminal:
			finalAction = "blocked"
		case t.Findings:
			finalAction = "allow_with_findings"
		default:
			finalAction = "allow"
		}
	}
	if !shouldEmitSecurityAudit(rt.CaptureMode, finalAction, t.Findings, t.Terminal) {
		return
	}
	record := securityAuditRecord{
		Version:        1,
		TS:             time.Now().UTC().Format(time.RFC3339Nano),
		Service:        "coraza",
		Event:          securityAuditEventName,
		DecisionID:     t.DecisionID,
		ReqID:          t.RequestID,
		TraceID:        t.TraceID,
		IP:             t.ClientIP,
		Country:        t.Country,
		CountrySource:  t.CountrySource,
		Method:         t.Method,
		Host:           t.Host,
		Path:           t.Path,
		Query:          t.Query,
		FinalAction:    finalAction,
		FinalStatus:    finalStatus,
		TerminalPolicy: t.TerminalPolicy,
		TerminalEvent:  t.TerminalEvent,
		DecisionChain:  append([]securityAuditDecisionNode(nil), t.Nodes...),
		Warnings:       append([]string(nil), t.Warnings...),
	}
	if evidence, err := persistSecurityAuditEvidence(rt, t); err != nil {
		record.Warnings = append(record.Warnings, "evidence_write_error:"+err.Error())
		rt.LastCaptureError.Store(err.Error())
	} else if evidence != nil {
		record.Evidence = evidence
		rt.CapturesTotal.Add(1)
	}
	if err := securityAuditWriterInstance.Append(rt, &record); err != nil {
		rt.LastWriteError.Store(err.Error())
		emitJSONLog(map[string]any{
			"ts":      record.TS,
			"service": "coraza",
			"level":   "WARN",
			"event":   "security_audit_write_error",
			"req_id":  record.ReqID,
			"error":   err.Error(),
		})
		return
	}
	rt.RecordsTotal.Add(1)
	t.Emitted = true
}

func shouldEmitSecurityAudit(mode string, finalAction string, findings bool, terminal bool) bool {
	switch strings.TrimSpace(mode) {
	case securityAuditCaptureModeOff:
		return terminal || findings
	case securityAuditCaptureModeEnforcedOnly:
		return terminal
	case securityAuditCaptureModeSecurityEvents:
		return terminal || finalAction == "allow_with_findings"
	case securityAuditCaptureModeAllSecurityFinding:
		return findings || terminal
	default:
		return terminal || findings
	}
}

func persistSecurityAuditEvidence(rt *securityAuditRuntime, trail *securityAuditTrail) (*securityAuditEvidenceMetadata, error) {
	if rt == nil || trail == nil || trail.Evidence == nil {
		return nil, nil
	}
	if !rt.CaptureHeaders && !rt.CaptureBody {
		return nil, nil
	}
	if rt.CaptureMode == securityAuditCaptureModeOff {
		return nil, nil
	}
	if len(rt.EncryptionKey) == 0 {
		return nil, nil
	}
	payload := securityAuditBlobIn{
		Method:          trail.Method,
		Host:            trail.Host,
		Path:            trail.Path,
		Query:           trail.Query,
		Headers:         trail.Evidence.Headers,
		BodyContentType: trail.Evidence.BodyContentType,
		BodyCaptured:    trail.Evidence.BodyCaptured,
		BodyTruncated:   trail.Evidence.BodyTruncated,
		BodyRedacted:    trail.Evidence.BodyRedacted,
	}
	if trail.Evidence.BodyCaptured && len(trail.Evidence.Body) > 0 {
		payload.BodyBase64 = base64.StdEncoding.EncodeToString(trail.Evidence.Body)
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	captureID := fmt.Sprintf("%s-%x", strings.TrimSpace(trail.RequestID), time.Now().UTC().UnixNano())
	block, err := aes.NewCipher(rt.EncryptionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(captureID))
	sum := sha256.Sum256(plaintext)
	envelope := securityAuditEvidenceBlob{
		Version:         1,
		Cipher:          securityAuditCipherAES256GCM,
		KeyID:           rt.EncryptionKeyID,
		CreatedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
		PlaintextSHA256: hex.EncodeToString(sum[:]),
		PlaintextSize:   len(plaintext),
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(rt.BlobDir, 0o700); err != nil {
		return nil, err
	}
	storageRef := captureID + ".json.enc"
	target := filepath.Join(rt.BlobDir, storageRef)
	if err := os.WriteFile(target, raw, 0o600); err != nil {
		return nil, err
	}
	return &securityAuditEvidenceMetadata{
		CaptureID:       captureID,
		StorageRef:      storageRef,
		Cipher:          securityAuditCipherAES256GCM,
		KeyID:           rt.EncryptionKeyID,
		SHA256:          envelope.PlaintextSHA256,
		Size:            envelope.PlaintextSize,
		HeadersCaptured: len(payload.Headers) > 0,
		BodyCaptured:    payload.BodyCaptured,
		BodyTruncated:   payload.BodyTruncated,
		BodyRedacted:    payload.BodyRedacted,
		BodyContentType: payload.BodyContentType,
	}, nil
}

func (w *securityAuditWriter) Append(rt *securityAuditRuntime, record *securityAuditRecord) error {
	if w == nil || rt == nil || record == nil {
		return fmt.Errorf("security audit writer is not initialized")
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	state, err := w.loadStateLocked(rt, rt.File)
	if err != nil {
		return err
	}
	signable := signableSecurityAuditRecord{
		Version:        record.Version,
		TS:             record.TS,
		Service:        record.Service,
		Event:          record.Event,
		DecisionID:     record.DecisionID,
		ReqID:          record.ReqID,
		TraceID:        record.TraceID,
		IP:             record.IP,
		Country:        record.Country,
		CountrySource:  record.CountrySource,
		Method:         record.Method,
		Host:           record.Host,
		Path:           record.Path,
		Query:          record.Query,
		FinalAction:    record.FinalAction,
		FinalStatus:    record.FinalStatus,
		TerminalPolicy: record.TerminalPolicy,
		TerminalEvent:  record.TerminalEvent,
		DecisionChain:  record.DecisionChain,
		Evidence:       record.Evidence,
		Warnings:       record.Warnings,
	}
	payload, err := json.Marshal(struct {
		PrevHash string                      `json:"prev_hash,omitempty"`
		Sequence int64                       `json:"sequence"`
		KeyID    string                      `json:"key_id"`
		Record   signableSecurityAuditRecord `json:"record"`
	}{
		PrevHash: state.LastHash,
		Sequence: state.LastSequence + 1,
		KeyID:    rt.HMACKeyID,
		Record:   signable,
	})
	if err != nil {
		return err
	}
	hash := sha256.Sum256(payload)
	mac := hmac.New(sha256.New, rt.HMACKey)
	_, _ = mac.Write(payload)
	record.Integrity = securityAuditIntegrity{
		Version:   1,
		KeyID:     rt.HMACKeyID,
		PrevHash:  state.LastHash,
		EntryHash: hex.EncodeToString(hash[:]),
		Signature: hex.EncodeToString(mac.Sum(nil)),
		Sequence:  state.LastSequence + 1,
	}
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	if err := os.MkdirAll(filepath.Dir(rt.File), 0o755); err != nil {
		return err
	}
	if config.FileRotateBytes > 0 {
		if info, err := os.Stat(rt.File); err == nil && info.Size() > 0 && info.Size()+int64(len(line)) > config.FileRotateBytes {
			if err := logfilearchive.RotateGzip(rt.File); err != nil {
				return err
			}
		}
	}
	f, err := os.OpenFile(rt.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := logfilearchive.PruneManaged(rt.File, time.Now().UTC()); err != nil {
		return err
	}
	state.LastHash = record.Integrity.EntryHash
	state.LastSequence = record.Integrity.Sequence
	w.state[rt.File] = state
	if err := writeSecurityAuditState(rt.File, state, rt); err != nil {
		return err
	}
	rt.LastIntegritySequence.Store(state.LastSequence)
	rt.LastIntegrityHash.Store(state.LastHash)
	return nil
}

func (w *securityAuditWriter) loadStateLocked(rt *securityAuditRuntime, path string) (securityAuditStreamState, error) {
	if state, ok := w.state[path]; ok {
		return state, nil
	}
	state, err := readSecurityAuditState(path, rt)
	if err == nil {
		w.state[path] = state
		return state, nil
	}
	if !os.IsNotExist(err) {
		return securityAuditStreamState{}, err
	}
	repaired, verifyErr := computeSecurityAuditState(path)
	if verifyErr != nil {
		return securityAuditStreamState{}, verifyErr
	}
	w.state[path] = repaired
	return repaired, nil
}

func signSecurityAuditState(rt *securityAuditRuntime, state securityAuditStreamState) (string, error) {
	if rt == nil || len(rt.HMACKey) == 0 {
		return "", fmt.Errorf("security audit hmac key is not initialized")
	}
	payload, err := json.Marshal(struct {
		Version int                      `json:"version"`
		KeyID   string                   `json:"key_id"`
		State   securityAuditStreamState `json:"state"`
	}{
		Version: 1,
		KeyID:   rt.HMACKeyID,
		State:   state,
	})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, rt.HMACKey)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func readSecurityAuditState(path string, rt *securityAuditRuntime) (securityAuditStreamState, error) {
	raw, err := os.ReadFile(securityAuditStatePath(path))
	if err != nil {
		return securityAuditStreamState{}, err
	}
	var envelope securityAuditStateEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return securityAuditStreamState{}, err
	}
	if envelope.Version != 1 {
		return securityAuditStreamState{}, fmt.Errorf("unsupported security audit state version: %d", envelope.Version)
	}
	if rt == nil {
		return securityAuditStreamState{}, fmt.Errorf("security audit runtime is not initialized")
	}
	if keyID := strings.TrimSpace(envelope.KeyID); keyID != strings.TrimSpace(rt.HMACKeyID) {
		return securityAuditStreamState{}, fmt.Errorf("unknown security audit state key id: %s", keyID)
	}
	wantSignature, err := signSecurityAuditState(rt, envelope.State)
	if err != nil {
		return securityAuditStreamState{}, err
	}
	if !hmac.Equal([]byte(strings.TrimSpace(envelope.Signature)), []byte(wantSignature)) {
		return securityAuditStreamState{}, fmt.Errorf("security audit state signature mismatch")
	}
	return envelope.State, nil
}

func writeSecurityAuditState(path string, state securityAuditStreamState, rt *securityAuditRuntime) error {
	signature, err := signSecurityAuditState(rt, state)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(securityAuditStateEnvelope{
		Version:   1,
		KeyID:     rt.HMACKeyID,
		State:     state,
		Signature: signature,
	})
	if err != nil {
		return err
	}
	tmp := securityAuditStatePath(path) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, securityAuditStatePath(path))
}

func securityAuditStatePath(path string) string {
	return path + ".state.json"
}

func computeSecurityAuditState(path string) (securityAuditStreamState, error) {
	files, err := listSecurityAuditFilesChronological(path)
	if err != nil {
		return securityAuditStreamState{}, err
	}
	var state securityAuditStreamState
	for _, file := range files {
		if err := walkSecurityAuditFile(file.Path, false, func(record securityAuditRecord) error {
			state.LastHash = record.Integrity.EntryHash
			state.LastSequence = record.Integrity.Sequence
			return nil
		}); err != nil {
			return securityAuditStreamState{}, err
		}
	}
	return state, nil
}

type securityAuditFileInfo struct {
	Path    string
	Active  bool
	Seq     int64
	ModTime time.Time
}

func listSecurityAuditFilesChronological(path string) ([]securityAuditFileInfo, error) {
	baseFiles, err := logfilearchive.ListManaged(path)
	if err != nil {
		return nil, err
	}
	out := make([]securityAuditFileInfo, 0, len(baseFiles))
	base := filepath.Base(path)
	for _, file := range baseFiles {
		info := securityAuditFileInfo{
			Path:    file.Path,
			Active:  file.Active,
			ModTime: file.ModTime,
		}
		name := filepath.Base(file.Path)
		if file.Active {
			info.Seq = 1<<62 - 1
		} else if strings.HasPrefix(name, base+".") {
			suffix := strings.TrimPrefix(name, base+".")
			suffix = strings.TrimSuffix(suffix, ".gz")
			if v, err := strconv.ParseInt(suffix, 10, 64); err == nil {
				info.Seq = v
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		if out[i].ModTime.Equal(out[j].ModTime) {
			return out[i].Path < out[j].Path
		}
		return out[i].ModTime.Before(out[j].ModTime)
	})
	return out, nil
}

func walkSecurityAuditFile(path string, newestFirst bool, fn func(record securityAuditRecord) error) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	var reader io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader = gz
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	chunks := bytesSplitKeep(raw, '\n')
	isPartialChunk := func(chunk []byte, idx int) bool {
		return idx == len(chunks)-1 && len(chunk) > 0 && chunk[len(chunk)-1] != '\n'
	}
	if newestFirst {
		for i := len(chunks) - 1; i >= 0; i-- {
			if err := decodeSecurityAuditChunk(chunks[i], isPartialChunk(chunks[i], i), fn); err != nil {
				return err
			}
		}
		return nil
	}
	for i, chunk := range chunks {
		if err := decodeSecurityAuditChunk(chunk, isPartialChunk(chunk, i), fn); err != nil {
			return err
		}
	}
	return nil
}

func decodeSecurityAuditChunk(chunk []byte, allowPartial bool, fn func(record securityAuditRecord) error) error {
	line := bytes.TrimSpace(trimLastNewline(chunk))
	if len(line) == 0 {
		return nil
	}
	var record securityAuditRecord
	if err := json.Unmarshal(line, &record); err != nil {
		if allowPartial {
			return nil
		}
		return fmt.Errorf("decode security audit entry: %w", err)
	}
	if strings.TrimSpace(record.Event) != securityAuditEventName {
		return nil
	}
	return fn(record)
}

func verifySecurityAuditFile(path string) securityAuditVerifyResult {
	result := securityAuditVerifyResult{
		OK:        true,
		Anchored:  true,
		CheckedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	rt := currentSecurityAuditRuntime()
	if rt == nil || !rt.Enabled {
		result.OK = false
		result.Error = "security audit disabled"
		return result
	}
	files, err := listSecurityAuditFilesChronological(path)
	if err != nil {
		result.OK = false
		result.Error = err.Error()
		return result
	}
	result.Files = len(files)
	prevHash := ""
	prevSeq := int64(0)
	firstRecord := true
	for _, file := range files {
		err := walkSecurityAuditFile(file.Path, false, func(record securityAuditRecord) error {
			result.Entries++
			if keyID := strings.TrimSpace(record.Integrity.KeyID); keyID != strings.TrimSpace(rt.HMACKeyID) {
				return fmt.Errorf("unknown security audit hmac key id sequence=%d key_id=%s", record.Integrity.Sequence, keyID)
			}
			signable := signableSecurityAuditRecord{
				Version:        record.Version,
				TS:             record.TS,
				Service:        record.Service,
				Event:          record.Event,
				DecisionID:     record.DecisionID,
				ReqID:          record.ReqID,
				TraceID:        record.TraceID,
				IP:             record.IP,
				Country:        record.Country,
				Method:         record.Method,
				Host:           record.Host,
				Path:           record.Path,
				Query:          record.Query,
				FinalAction:    record.FinalAction,
				FinalStatus:    record.FinalStatus,
				TerminalPolicy: record.TerminalPolicy,
				TerminalEvent:  record.TerminalEvent,
				DecisionChain:  record.DecisionChain,
				Evidence:       record.Evidence,
				Warnings:       record.Warnings,
			}
			payload, err := json.Marshal(struct {
				PrevHash string                      `json:"prev_hash,omitempty"`
				Sequence int64                       `json:"sequence"`
				KeyID    string                      `json:"key_id"`
				Record   signableSecurityAuditRecord `json:"record"`
			}{
				PrevHash: record.Integrity.PrevHash,
				Sequence: record.Integrity.Sequence,
				KeyID:    record.Integrity.KeyID,
				Record:   signable,
			})
			if err != nil {
				return err
			}
			hash := sha256.Sum256(payload)
			if got := hex.EncodeToString(hash[:]); got != strings.TrimSpace(record.Integrity.EntryHash) {
				return fmt.Errorf("entry hash mismatch sequence=%d", record.Integrity.Sequence)
			}
			mac := hmac.New(sha256.New, rt.HMACKey)
			_, _ = mac.Write(payload)
			if got := hex.EncodeToString(mac.Sum(nil)); got != strings.TrimSpace(record.Integrity.Signature) {
				return fmt.Errorf("signature mismatch sequence=%d", record.Integrity.Sequence)
			}
			if firstRecord {
				firstRecord = false
				if strings.TrimSpace(record.Integrity.PrevHash) != "" {
					result.Anchored = false
				}
			} else {
				if strings.TrimSpace(record.Integrity.PrevHash) != prevHash {
					return fmt.Errorf("prev hash mismatch sequence=%d", record.Integrity.Sequence)
				}
				if record.Integrity.Sequence != prevSeq+1 {
					return fmt.Errorf("sequence gap at %d", record.Integrity.Sequence)
				}
			}
			prevHash = strings.TrimSpace(record.Integrity.EntryHash)
			prevSeq = record.Integrity.Sequence
			result.LastHash = prevHash
			result.LastSeq = prevSeq
			return nil
		})
		if err != nil {
			result.OK = false
			result.Error = err.Error()
			if rt != nil {
				rt.VerifyFailuresTotal.Add(1)
				rt.LastVerifyAtUnix.Store(time.Now().UTC().Unix())
				rt.LastVerifyOK.Store(false)
				rt.LastVerifyError.Store(err.Error())
				rt.LastVerificationAnchored.Store(result.Anchored)
			}
			return result
		}
	}
	anchorState, err := readSecurityAuditState(path, rt)
	if err != nil {
		if os.IsNotExist(err) {
			if result.Entries > 0 {
				result.OK = false
				result.Error = "security audit tail anchor missing"
			}
		} else {
			result.OK = false
			result.Error = err.Error()
		}
		if !result.OK && rt != nil {
			rt.VerifyFailuresTotal.Add(1)
			rt.LastVerifyAtUnix.Store(time.Now().UTC().Unix())
			rt.LastVerifyOK.Store(false)
			rt.LastVerifyError.Store(result.Error)
			rt.LastVerificationAnchored.Store(result.Anchored)
		}
		return result
	}
	if anchorState.LastSequence != result.LastSeq || strings.TrimSpace(anchorState.LastHash) != strings.TrimSpace(result.LastHash) {
		result.OK = false
		result.Error = fmt.Sprintf("security audit tail anchor mismatch sequence=%d/%d", result.LastSeq, anchorState.LastSequence)
		if rt != nil {
			rt.VerifyFailuresTotal.Add(1)
			rt.LastVerifyAtUnix.Store(time.Now().UTC().Unix())
			rt.LastVerifyOK.Store(false)
			rt.LastVerifyError.Store(result.Error)
			rt.LastVerificationAnchored.Store(result.Anchored)
		}
		return result
	}
	if rt != nil {
		rt.LastVerifyAtUnix.Store(time.Now().UTC().Unix())
		rt.LastVerifyOK.Store(result.OK)
		rt.LastVerifyError.Store("")
		rt.LastVerificationAnchored.Store(result.Anchored)
	}
	return result
}

func readSecurityAuditByReqID(reqID string) ([]securityAuditRecord, error) {
	rt := currentSecurityAuditRuntime()
	if rt == nil || !rt.Enabled {
		return nil, nil
	}
	reqID = strings.TrimSpace(reqID)
	if reqID == "" {
		return nil, nil
	}
	files, err := listSecurityAuditFilesChronological(rt.File)
	if err != nil {
		return nil, err
	}
	out := make([]securityAuditRecord, 0, 1)
	for i := len(files) - 1; i >= 0; i-- {
		err := walkSecurityAuditFile(files[i].Path, true, func(record securityAuditRecord) error {
			if strings.TrimSpace(record.ReqID) == reqID {
				out = append(out, record)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if len(out) > 0 {
			break
		}
	}
	return out, nil
}

func readSecurityAuditEvidenceMetadata(captureID string) (*securityAuditEvidenceMetadata, error) {
	rt := currentSecurityAuditRuntime()
	if rt == nil || !rt.Enabled {
		return nil, nil
	}
	captureID = strings.TrimSpace(captureID)
	if captureID == "" {
		return nil, nil
	}
	files, err := listSecurityAuditFilesChronological(rt.File)
	if err != nil {
		return nil, err
	}
	for i := len(files) - 1; i >= 0; i-- {
		var found *securityAuditEvidenceMetadata
		err := walkSecurityAuditFile(files[i].Path, true, func(record securityAuditRecord) error {
			if record.Evidence != nil && strings.TrimSpace(record.Evidence.CaptureID) == captureID {
				copy := *record.Evidence
				found = &copy
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if found != nil {
			return found, nil
		}
	}
	return nil, nil
}

func GetSecurityAudit(c *gin.Context) {
	reqID := strings.TrimSpace(c.Query("req_id"))
	if reqID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "req_id is required"})
		return
	}
	items, err := readSecurityAuditByReqID(reqID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"items": items,
		"count": len(items),
	})
}

func VerifySecurityAudit(c *gin.Context) {
	rt := currentSecurityAuditRuntime()
	if rt == nil || !rt.Enabled {
		c.JSON(http.StatusOK, securityAuditVerifyResult{
			OK:        false,
			Anchored:  false,
			CheckedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Error:     "security audit disabled",
		})
		return
	}
	c.JSON(http.StatusOK, verifySecurityAuditFile(rt.File))
}

func GetSecurityAuditEvidenceMetadata(c *gin.Context) {
	captureID := strings.TrimSpace(c.Param("capture_id"))
	if captureID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "capture_id is required"})
		return
	}
	meta, err := readSecurityAuditEvidenceMetadata(captureID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if meta == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "capture metadata not found"})
		return
	}
	c.JSON(http.StatusOK, meta)
}
