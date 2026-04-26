package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/challengecookie"
	"tukuyomi/internal/policyhost"
	"tukuyomi/internal/runtimefiles"
	"tukuyomi/internal/semanticprovider"
	"tukuyomi/internal/semanticrisk"
)

const (
	semanticModeOff       = "off"
	semanticModeLogOnly   = "log_only"
	semanticModeChallenge = "challenge"
	semanticModeBlock     = "block"
)

const (
	semanticActionNone      = "none"
	semanticActionLogOnly   = "log_only"
	semanticActionChallenge = "challenge"
	semanticActionBlock     = "block"
)

const semanticDefaultScope = "default"

const semanticConfigBlobKey = "semantic_rules"

const (
	semanticProviderNameBuiltinAttackFamily = semanticprovider.NameBuiltinAttackFamily
	defaultSemanticProviderTimeoutMS        = semanticprovider.DefaultTimeoutMS
	maxSemanticProviderExcerptBytes         = semanticprovider.MaxExcerptBytes
)

type semanticProviderConfig = semanticprovider.Config
type semanticProviderInput = semanticprovider.Input
type semanticProviderOutput = semanticprovider.Output
type semanticProviderRuntime = semanticprovider.Runtime

func normalizeSemanticProviderConfig(cfg semanticProviderConfig) (semanticProviderConfig, error) {
	return semanticprovider.NormalizeConfig(cfg)
}

func buildSemanticProviderRuntime(cfg semanticProviderConfig) *semanticProviderRuntime {
	return semanticprovider.BuildRuntime(cfg)
}

func evaluateSemanticProvider(rt *semanticProviderRuntime, in semanticProviderInput) *semanticProviderOutput {
	return semanticprovider.Evaluate(rt, in)
}

func newSemanticProviderInput(
	r *http.Request,
	requestID string,
	telemetry *semanticTelemetry,
	bodyChunk []byte,
	baseScore, statefulScore int,
	baseSignals, statefulSignals []semanticSignal,
) semanticProviderInput {
	in := semanticProviderInput{
		RequestID:       strings.TrimSpace(requestID),
		BaseScore:       baseScore,
		StatefulScore:   statefulScore,
		BaseReasons:     semanticReasons(baseSignals),
		StatefulReasons: semanticReasons(statefulSignals),
	}
	if telemetry != nil {
		in.ActorKey = telemetry.Context.ActorKey
		in.PathClass = telemetry.Context.PathClass
		in.TargetClass = telemetry.Context.TargetClass
		in.SurfaceClass = telemetry.Context.SurfaceClass
		in.QueryHash = telemetry.Fingerprints.QueryHash
		in.FormHash = telemetry.Fingerprints.FormHash
		in.JSONHash = telemetry.Fingerprints.JSONHash
		in.BodyHash = telemetry.Fingerprints.BodyHash
		in.HeaderHash = telemetry.Fingerprints.HeaderHash
	}
	if r != nil && r.URL != nil {
		in.QueryExcerpt = boundedSemanticProviderExcerpt(normalizeSemanticFingerprintText(r.URL.RawQuery))
	}
	contentType := ""
	if r != nil {
		contentType = semanticNormalizedContentType(r.Header.Get("Content-Type"))
		in.HeaderExcerpt = boundedSemanticProviderExcerpt(semanticHeaderExcerpt(r.Header))
	}
	if len(bodyChunk) > 0 {
		switch {
		case contentType == "application/x-www-form-urlencoded":
			in.FormExcerpt = boundedSemanticProviderExcerpt(normalizeSemanticFingerprintText(string(bodyChunk)))
		case contentType == "application/json", strings.HasSuffix(contentType, "+json"), semanticLooksLikeJSON(bodyChunk):
			in.JSONExcerpt = boundedSemanticProviderExcerpt(semanticJSONExcerpt(bodyChunk))
		default:
			in.BodyExcerpt = boundedSemanticProviderExcerpt(normalizeSemanticFingerprintText(string(bodyChunk)))
		}
	}
	return in
}

func boundedSemanticProviderExcerpt(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) <= maxSemanticProviderExcerptBytes {
		return raw
	}
	return raw[:maxSemanticProviderExcerptBytes]
}

func semanticHeaderExcerpt(header http.Header) string {
	if header == nil {
		return ""
	}
	parts := make([]string, 0, 3)
	for _, name := range []string{"User-Agent", "Referer", "Content-Type"} {
		value := strings.TrimSpace(header.Get(name))
		if value == "" {
			continue
		}
		parts = append(parts, strings.ToLower(name)+"="+normalizeSemanticFingerprintText(value))
	}
	return strings.Join(parts, "\n")
}

func semanticJSONExcerpt(body []byte) string {
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return normalizeSemanticFingerprintText(string(body))
	}
	return semanticCanonicalJSONFingerprint(payload, 0)
}

func semanticProviderOutputSignals(out semanticProviderOutput) []semanticSignal {
	if out.ScoreDelta <= 0 {
		return nil
	}
	reason := "provider:" + strings.TrimSpace(out.AttackFamily)
	if reason == "provider:" {
		reason = "provider:" + strings.TrimSpace(out.Name)
	}
	return []semanticSignal{{
		Reason: reason,
		Score:  out.ScoreDelta,
	}}
}

var (
	semanticPatternUnionSelect = regexp.MustCompile(`\bunion\b[\s\W]{0,48}\bselect\b`)
	semanticPatternBooleanSQL  = regexp.MustCompile(`\b(or|and)\b[\s\W]{0,24}(1=1|true|false|[\w'"]+\s*=\s*[\w'"]+)`)
	semanticPatternSQLMeta     = regexp.MustCompile(`\binformation_schema\b|\bxp_cmdshell\b|\bload_file\s*\(`)
	semanticPatternPathTrav    = regexp.MustCompile(`\.\./|\.\.\\`)
	semanticPatternXSS         = regexp.MustCompile(`<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img[^>]+onerror`)
	semanticPatternCmd         = regexp.MustCompile(`(;|\|\||&&)\s*(/bin/sh|cmd\.exe|powershell|wget|curl|bash|sh)`)
	semanticPatternCommentObf  = regexp.MustCompile(`/\*.*?\*/`)
	semanticPatternWhitespace  = regexp.MustCompile(`\s+`)
)

type semanticConfig struct {
	Enabled                     bool                   `json:"enabled"`
	Mode                        string                 `json:"mode"`
	ExemptPathPrefixes          []string               `json:"exempt_path_prefixes,omitempty"`
	LogThreshold                int                    `json:"log_threshold"`
	ChallengeThreshold          int                    `json:"challenge_threshold"`
	BlockThreshold              int                    `json:"block_threshold"`
	MaxInspectBody              int64                  `json:"max_inspect_body"`
	Provider                    semanticProviderConfig `json:"provider,omitempty"`
	TemporalWindowSeconds       int                    `json:"temporal_window_seconds,omitempty"`
	TemporalMaxEntriesPerIP     int                    `json:"temporal_max_entries_per_ip,omitempty"`
	TemporalBurstThreshold      int                    `json:"temporal_burst_threshold,omitempty"`
	TemporalBurstScore          int                    `json:"temporal_burst_score,omitempty"`
	TemporalPathFanoutThreshold int                    `json:"temporal_path_fanout_threshold,omitempty"`
	TemporalPathFanoutScore     int                    `json:"temporal_path_fanout_score,omitempty"`
	TemporalUAChurnThreshold    int                    `json:"temporal_ua_churn_threshold,omitempty"`
	TemporalUAChurnScore        int                    `json:"temporal_ua_churn_score,omitempty"`
}

type semanticFile struct {
	Default semanticConfig            `json:"default"`
	Hosts   map[string]semanticConfig `json:"hosts,omitempty"`
}

type semanticStats struct {
	InspectedRequests uint64 `json:"inspected_requests"`
	ScoredRequests    uint64 `json:"scored_requests"`
	LogOnlyActions    uint64 `json:"log_only_actions"`
	ChallengeActions  uint64 `json:"challenge_actions"`
	BlockActions      uint64 `json:"block_actions"`
}

type semanticEvaluation struct {
	Score            int
	BaseScore        int
	StatefulScore    int
	ProviderScore    int
	HostScope        string
	Reasons          []string
	BaseReasons      []string
	StatefulReasons  []string
	ProviderReasons  []string
	Signals          []semanticSignal
	BaseSignals      []semanticSignal
	StatefulSignals  []semanticSignal
	ProviderSignals  []semanticSignal
	Action           string
	Telemetry        *semanticTelemetry
	StatefulSnapshot *semanticHistorySnapshot
	ProviderResult   *semanticProviderOutput
}

type semanticSignal = semanticrisk.Signal
type semanticHistorySnapshot = semanticrisk.HistorySnapshot

const statefulAdminAfterSuspiciousScore = semanticrisk.StatefulAdminAfterSuspiciousScore

type runtimeSemanticScope struct {
	Raw semanticConfig

	temporal *semanticrisk.TemporalStore
	history  *semanticrisk.HistoryStore
	provider *semanticProviderRuntime

	challengeCookieName string
	challengeSecret     []byte
	challengeTTL        time.Duration
	challengeStatusCode int

	inspectedRequests atomic.Uint64
	scoredRequests    atomic.Uint64
	logOnlyActions    atomic.Uint64
	challengeActions  atomic.Uint64
	blockActions      atomic.Uint64
}

type runtimeSemanticConfig struct {
	File    semanticFile
	Raw     semanticConfig
	Default *runtimeSemanticScope
	Hosts   map[string]*runtimeSemanticScope
}

type semanticScopeSelection struct {
	Raw      semanticConfig
	Runtime  *runtimeSemanticScope
	ScopeKey string
}

var (
	semanticMu      sync.RWMutex
	semanticPath    string
	semanticRuntime *runtimeSemanticConfig
)

func InitSemantic(path string) error {
	target := strings.TrimSpace(path)
	if target == "" {
		return fmt.Errorf("semantic path is empty")
	}
	semanticMu.Lock()
	semanticPath = target
	semanticMu.Unlock()

	if handled, err := initPolicyJSONConfigFromDB(semanticPolicyJSONDomain.dbInit(applySemanticPolicyRaw)); handled {
		return err
	}

	if err := ensureSemanticFile(target); err != nil {
		return err
	}

	return ReloadSemantic()
}

func GetSemanticPath() string {
	semanticMu.RLock()
	defer semanticMu.RUnlock()
	return semanticPath
}

func GetSemanticConfig() semanticConfig {
	semanticMu.RLock()
	defer semanticMu.RUnlock()
	if semanticRuntime == nil {
		return semanticConfig{}
	}
	return semanticRuntime.Raw
}

func GetSemanticFile() semanticFile {
	semanticMu.RLock()
	defer semanticMu.RUnlock()
	if semanticRuntime == nil {
		return semanticFile{}
	}
	return cloneSemanticFile(semanticRuntime.File)
}

func GetSemanticStats() semanticStats {
	rt := currentSemanticRuntime()
	if rt == nil {
		return semanticStats{}
	}
	stats := semanticScopeStats(rt.Default)
	for _, scope := range rt.Hosts {
		addSemanticStats(&stats, semanticScopeStats(scope))
	}
	return stats
}

func GetSemanticRules(c *gin.Context) {
	path := GetSemanticPath()
	raw, _ := os.ReadFile(path)
	savedAt := runtimefiles.FileSavedAt(path)
	dbRaw, rec, found, ok := loadPolicyJSONConfigForAdmin(c, semanticPolicyJSONDomain.adminRead())
	if !ok {
		return
	}
	if found {
		rt, parseErr := ValidateSemanticRaw(string(dbRaw))
		if parseErr != nil {
			respondConfigBlobDBError(c, "semantic db rows parse failed", parseErr)
			return
		}
		savedAt = configVersionSavedAt(rec)
		c.JSON(http.StatusOK, gin.H{
			"etag":                 rec.ETag,
			"raw":                  string(dbRaw),
			"enabled":              rt.Raw.Enabled,
			"mode":                 rt.Raw.Mode,
			"exempt_path_prefixes": rt.Raw.ExemptPathPrefixes,
			"log_threshold":        rt.Raw.LogThreshold,
			"challenge_threshold":  rt.Raw.ChallengeThreshold,
			"block_threshold":      rt.Raw.BlockThreshold,
			"max_inspect_body":     rt.Raw.MaxInspectBody,
			"provider_enabled":     rt.Raw.Provider.Enabled,
			"provider_name":        rt.Raw.Provider.Name,
			"provider_timeout_ms":  rt.Raw.Provider.TimeoutMS,
			"stats":                GetSemanticStats(),
			"saved_at":             savedAt,
		})
		return
	}
	cfg := GetSemanticConfig()
	stats := GetSemanticStats()

	c.JSON(http.StatusOK, gin.H{
		"etag":                 bypassconf.ComputeETag(raw),
		"raw":                  string(raw),
		"enabled":              cfg.Enabled,
		"mode":                 cfg.Mode,
		"exempt_path_prefixes": cfg.ExemptPathPrefixes,
		"log_threshold":        cfg.LogThreshold,
		"challenge_threshold":  cfg.ChallengeThreshold,
		"block_threshold":      cfg.BlockThreshold,
		"max_inspect_body":     cfg.MaxInspectBody,
		"provider_enabled":     cfg.Provider.Enabled,
		"provider_name":        cfg.Provider.Name,
		"provider_timeout_ms":  cfg.Provider.TimeoutMS,
		"stats":                stats,
		"saved_at":             savedAt,
	})
}

func ValidateSemanticRules(c *gin.Context) {
	in, ok := bindRawPolicyPutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateSemanticRaw(in.Raw)
	if err != nil {
		respondPolicyValidationError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":                   true,
		"messages":             []string{},
		"enabled":              rt.Raw.Enabled,
		"mode":                 rt.Raw.Mode,
		"exempt_path_prefixes": rt.Raw.ExemptPathPrefixes,
		"log_threshold":        rt.Raw.LogThreshold,
		"challenge_threshold":  rt.Raw.ChallengeThreshold,
		"block_threshold":      rt.Raw.BlockThreshold,
		"max_inspect_body":     rt.Raw.MaxInspectBody,
		"provider_enabled":     rt.Raw.Provider.Enabled,
		"provider_name":        rt.Raw.Provider.Name,
		"provider_timeout_ms":  rt.Raw.Provider.TimeoutMS,
	})
}

func PutSemanticRules(c *gin.Context) {
	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
		return
	}

	in, ok := bindRawPolicyPutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateSemanticRaw(in.Raw)
	if err != nil {
		respondPolicyValidationError(c, err)
		return
	}

	normalizedRaw, err := normalizeSemanticPolicyRaw(in.Raw)
	if err != nil {
		respondPolicyValidationError(c, err)
		return
	}
	rec, ok := writePolicyJSONConfigUpdate(c, store, semanticPolicyJSONDomain.update(normalizedRaw))
	if !ok {
		return
	}
	if err := applySemanticPolicyRaw(normalizedRaw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":                   true,
		"etag":                 rec.ETag,
		"enabled":              rt.Raw.Enabled,
		"mode":                 rt.Raw.Mode,
		"exempt_path_prefixes": rt.Raw.ExemptPathPrefixes,
		"log_threshold":        rt.Raw.LogThreshold,
		"challenge_threshold":  rt.Raw.ChallengeThreshold,
		"block_threshold":      rt.Raw.BlockThreshold,
		"max_inspect_body":     rt.Raw.MaxInspectBody,
		"provider_enabled":     rt.Raw.Provider.Enabled,
		"provider_name":        rt.Raw.Provider.Name,
		"provider_timeout_ms":  rt.Raw.Provider.TimeoutMS,
		"saved_at":             rec.ActivatedAt.Format(time.RFC3339Nano),
	})
}

func SyncSemanticStorage() error {
	return syncPolicyJSONConfigStorage(semanticPolicyJSONDomain.sync(applySemanticPolicyRaw))
}

func ReloadSemantic() error {
	path := GetSemanticPath()
	if path == "" {
		return fmt.Errorf("semantic path is empty")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rt, err := buildSemanticRuntimeFromRaw(raw)
	if err != nil {
		return err
	}

	semanticMu.Lock()
	semanticRuntime = rt
	semanticMu.Unlock()

	return nil
}

func ValidateSemanticRaw(raw string) (*runtimeSemanticConfig, error) {
	return buildSemanticRuntimeFromRaw([]byte(raw))
}

func EvaluateSemantic(r *http.Request) semanticEvaluation {
	return evaluateSemanticRequest(r, "", "", time.Now().UTC())
}

func EvaluateSemanticWithContext(r *http.Request, clientIP string, now time.Time) semanticEvaluation {
	return evaluateSemanticRequest(r, clientIP, "", now)
}

func EvaluateSemanticWithRequestID(r *http.Request, clientIP, requestID string, now time.Time) semanticEvaluation {
	return evaluateSemanticRequest(r, clientIP, requestID, now)
}

func evaluateSemanticRequest(r *http.Request, clientIP, requestID string, now time.Time) semanticEvaluation {
	rt := currentSemanticRuntime()
	if rt == nil || r == nil || r.URL == nil {
		return semanticEvaluation{Action: semanticActionNone}
	}

	scope := selectSemanticScope(rt, r)
	if scope.Runtime == nil {
		return semanticEvaluation{Action: semanticActionNone}
	}
	cfg := scope.Raw
	if !cfg.Enabled || cfg.Mode == semanticModeOff {
		return semanticEvaluation{Action: semanticActionNone}
	}

	path := sanitizeSemanticText(r.URL.Path)
	for _, pfx := range cfg.ExemptPathPrefixes {
		if pfx == "/" || strings.HasPrefix(path, pfx) {
			eval := semanticEvaluation{Action: semanticActionNone, HostScope: scope.ScopeKey}
			scope.Runtime.observe(eval)
			return eval
		}
	}

	baseScore := 0
	baseSignals := make([]semanticSignal, 0, 12)
	var bodyChunk []byte
	inspectSemanticText("path", r.URL.Path, &baseScore, &baseSignals)
	inspectSemanticText("query", r.URL.RawQuery, &baseScore, &baseSignals)
	inspectSemanticText("user_agent", r.UserAgent(), &baseScore, &baseSignals)
	inspectSemanticText("referer", r.Referer(), &baseScore, &baseSignals)

	if cfg.MaxInspectBody > 0 && r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		n := cfg.MaxInspectBody + 1
		chunk, _ := io.ReadAll(io.LimitReader(r.Body, n))
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(chunk), r.Body))
		if int64(len(chunk)) > cfg.MaxInspectBody {
			chunk = chunk[:cfg.MaxInspectBody]
		}
		bodyChunk = append(bodyChunk[:0], chunk...)
		if len(chunk) > 0 {
			inspectSemanticText("body", string(chunk), &baseScore, &baseSignals)
		}
	}
	telemetry := buildSemanticTelemetry(r, clientIP, requestID, bodyChunk)
	statefulScore := 0
	statefulSignals := make([]semanticSignal, 0, 8)
	inspectSemanticTemporalRisk(scope.Runtime, cfg, clientIP, r.URL.Path, r.UserAgent(), now, &statefulScore, &statefulSignals)
	statefulSnapshot := inspectSemanticStatefulRisk(scope.Runtime, telemetry, baseScore, now, &statefulScore, &statefulSignals)
	providerResult := evaluateSemanticProvider(
		scope.Runtime.provider,
		newSemanticProviderInput(r, requestID, telemetry, bodyChunk, baseScore, statefulScore, baseSignals, statefulSignals),
	)
	providerScore := 0
	providerSignals := make([]semanticSignal, 0, 4)
	providerReasons := make([]string, 0, 4)
	if providerResult != nil && providerResult.ScoreDelta > 0 {
		providerScore = providerResult.ScoreDelta
		providerSignals = semanticProviderOutputSignals(*providerResult)
		providerReasons = append(providerReasons, providerResult.ReasonCodes...)
	}
	if len(providerReasons) == 0 {
		providerReasons = semanticReasons(providerSignals)
	}
	score := baseScore + statefulScore + providerScore
	signals := append(append(append([]semanticSignal(nil), baseSignals...), statefulSignals...), providerSignals...)

	action := semanticActionNone
	if score >= cfg.LogThreshold {
		action = semanticActionLogOnly
		switch cfg.Mode {
		case semanticModeChallenge:
			if score >= cfg.ChallengeThreshold {
				action = semanticActionChallenge
			}
		case semanticModeBlock:
			if score >= cfg.BlockThreshold {
				action = semanticActionBlock
			}
		}
	}

	eval := semanticEvaluation{
		Score:            score,
		BaseScore:        baseScore,
		StatefulScore:    statefulScore,
		ProviderScore:    providerScore,
		HostScope:        scope.ScopeKey,
		Reasons:          semanticReasons(signals),
		BaseReasons:      semanticReasons(baseSignals),
		StatefulReasons:  semanticReasons(statefulSignals),
		ProviderReasons:  unique(providerReasons),
		Signals:          signals,
		BaseSignals:      baseSignals,
		StatefulSignals:  statefulSignals,
		ProviderSignals:  providerSignals,
		Action:           action,
		Telemetry:        telemetry,
		StatefulSnapshot: statefulSnapshot,
		ProviderResult:   providerResult,
	}
	scope.Runtime.observe(eval)
	return eval
}

func HasValidSemanticChallengeCookie(r *http.Request, clientIP string, now time.Time) bool {
	rt := currentSemanticRuntime()
	if rt == nil {
		return true
	}
	scope := selectSemanticScope(rt, r)
	if scope.Runtime == nil {
		return true
	}
	cfg := scope.Raw
	if !cfg.Enabled || cfg.Mode != semanticModeChallenge {
		return true
	}

	c, err := r.Cookie(scope.Runtime.challengeCookieName)
	if err != nil {
		return false
	}
	return verifySemanticChallengeToken(scope.Runtime, c.Value, clientIP, r.UserAgent(), now.UTC())
}

func WriteSemanticChallenge(w http.ResponseWriter, r *http.Request, clientIP string) {
	rt := currentSemanticRuntime()
	if rt == nil {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	scope := selectSemanticScope(rt, r)
	if scope.Runtime == nil {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	token := issueSemanticChallengeToken(scope.Runtime, clientIP, r.UserAgent(), time.Now().UTC())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Tukuyomi-Semantic-Challenge", "required")

	if !acceptsHTML(r.Header.Get("Accept")) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(scope.Runtime.challengeStatusCode)
		_, _ = w.Write([]byte(`{"error":"semantic challenge required"}`))
		return
	}

	maxAge := int(scope.Runtime.challengeTTL.Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	body := fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Semantic Challenge</title></head>
<body>
<p>Verifying request safety...</p>
<script>
(() => {
  const token = %q;
  const cookieName = %q;
  document.cookie = cookieName + "=" + token + "; Path=/; Max-Age=%d; SameSite=Lax";
  window.location.replace(window.location.href);
})();
</script>
<noscript>JavaScript is required to continue.</noscript>
</body></html>`, token, scope.Runtime.challengeCookieName, maxAge)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(scope.Runtime.challengeStatusCode)
	_, _ = w.Write([]byte(body))
}

func currentSemanticRuntime() *runtimeSemanticConfig {
	semanticMu.RLock()
	defer semanticMu.RUnlock()
	return semanticRuntime
}

func selectSemanticScope(rt *runtimeSemanticConfig, req *http.Request) semanticScopeSelection {
	if rt == nil {
		return semanticScopeSelection{ScopeKey: semanticDefaultScope}
	}
	if req != nil {
		for _, candidate := range policyhost.Candidates(req.Host, req.TLS != nil) {
			if scope, ok := rt.Hosts[candidate]; ok {
				return semanticScopeSelection{
					Raw:      scope.Raw,
					Runtime:  scope,
					ScopeKey: candidate,
				}
			}
		}
	}
	return semanticScopeSelection{
		Raw:      rt.Raw,
		Runtime:  rt.Default,
		ScopeKey: semanticDefaultScope,
	}
}

func (rt *runtimeSemanticScope) observe(eval semanticEvaluation) {
	if rt == nil {
		return
	}
	rt.inspectedRequests.Add(1)
	if eval.Score > 0 {
		rt.scoredRequests.Add(1)
	}
	switch eval.Action {
	case semanticActionLogOnly:
		rt.logOnlyActions.Add(1)
	case semanticActionChallenge:
		rt.challengeActions.Add(1)
	case semanticActionBlock:
		rt.blockActions.Add(1)
	}
}

func buildSemanticRuntimeFromRaw(raw []byte) (*runtimeSemanticConfig, error) {
	top, err := decodeSemanticJSONObject(raw)
	if err != nil {
		return nil, err
	}

	if _, hasDefault := top["default"]; !hasDefault {
		if _, hasHosts := top["hosts"]; !hasHosts {
			scope, err := buildRuntimeSemanticScopeFromRaw(raw)
			if err != nil {
				return nil, err
			}
			return &runtimeSemanticConfig{
				File: semanticFile{
					Default: cloneSemanticConfig(scope.Raw),
				},
				Raw:     cloneSemanticConfig(scope.Raw),
				Default: scope,
				Hosts:   map[string]*runtimeSemanticScope{},
			}, nil
		}
	}

	for key := range top {
		if key != "default" && key != "hosts" {
			return nil, fmt.Errorf("invalid json")
		}
	}

	defaultObject, err := decodeSemanticObjectValue(top["default"], "default")
	if err != nil {
		return nil, err
	}
	defaultScope, err := buildRuntimeSemanticScopeFromRaw(mustMarshalSemanticObject(defaultObject))
	if err != nil {
		return nil, err
	}

	runtime := &runtimeSemanticConfig{
		File: semanticFile{
			Default: cloneSemanticConfig(defaultScope.Raw),
		},
		Raw:     cloneSemanticConfig(defaultScope.Raw),
		Default: defaultScope,
		Hosts:   map[string]*runtimeSemanticScope{},
	}

	hosts, err := decodeSemanticHosts(top["hosts"])
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return runtime, nil
	}

	runtime.File.Hosts = make(map[string]semanticConfig, len(hosts))
	for rawHost, rawScope := range hosts {
		hostKey, err := policyhost.NormalizePattern(rawHost)
		if err != nil {
			return nil, fmt.Errorf("hosts[%q]: %w", rawHost, err)
		}
		hostObject, err := decodeSemanticObjectValue(rawScope, fmt.Sprintf("hosts[%q]", rawHost))
		if err != nil {
			return nil, err
		}
		mergedObject := mergeSemanticJSONObject(defaultObject, hostObject)
		scope, err := buildRuntimeSemanticScopeFromRaw(mustMarshalSemanticObject(mergedObject))
		if err != nil {
			return nil, err
		}
		runtime.File.Hosts[hostKey] = cloneSemanticConfig(scope.Raw)
		runtime.Hosts[hostKey] = scope
	}

	return runtime, nil
}

func buildRuntimeSemanticScopeFromRaw(raw []byte) (*runtimeSemanticScope, error) {
	cfg, err := decodeSemanticConfig(raw)
	if err != nil {
		return nil, err
	}
	return buildRuntimeSemanticScope(cfg)
}

func buildRuntimeSemanticScope(cfg semanticConfig) (*runtimeSemanticScope, error) {
	norm, err := normalizeSemanticConfig(cfg)
	if err != nil {
		return nil, err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		secret = []byte("tukuyomi-semantic-ephemeral")
	}

	return &runtimeSemanticScope{
		Raw:                 norm,
		temporal:            newTemporalRiskStore(norm),
		history:             newSemanticHistoryStore(norm),
		provider:            buildSemanticProviderRuntime(norm.Provider),
		challengeCookieName: "__tukuyomi_semantic_ok",
		challengeSecret:     secret,
		challengeTTL:        12 * time.Hour,
		challengeStatusCode: http.StatusTooManyRequests,
	}, nil
}

func decodeSemanticConfig(raw []byte) (semanticConfig, error) {
	var cfg semanticConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return semanticConfig{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return semanticConfig{}, fmt.Errorf("invalid json")
	}
	return cfg, nil
}

func decodeSemanticJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, fmt.Errorf("semantic config must be a JSON object")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid json")
	}
	return obj, nil
}

func decodeSemanticObjectValue(raw json.RawMessage, field string) (map[string]any, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("%s must be a JSON object", field)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid json")
	}
	return out, nil
}

func decodeSemanticHosts(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var out map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("hosts must be a JSON object")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid json")
	}
	return out, nil
}

func mergeSemanticJSONObject(base, override map[string]any) map[string]any {
	out := cloneSemanticJSONValue(base).(map[string]any)
	for key, value := range override {
		out[key] = mergeSemanticJSONValue(out[key], value)
	}
	return out
}

func mergeSemanticJSONValue(base, override any) any {
	baseObject, baseOK := base.(map[string]any)
	overrideObject, overrideOK := override.(map[string]any)
	if baseOK && overrideOK {
		return mergeSemanticJSONObject(baseObject, overrideObject)
	}
	return cloneSemanticJSONValue(override)
}

func cloneSemanticJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = cloneSemanticJSONValue(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = cloneSemanticJSONValue(item)
		}
		return out
	default:
		return typed
	}
}

func mustMarshalSemanticObject(value map[string]any) []byte {
	raw, _ := json.Marshal(value)
	return raw
}

func cloneSemanticFile(in semanticFile) semanticFile {
	out := semanticFile{
		Default: cloneSemanticConfig(in.Default),
	}
	if len(in.Hosts) > 0 {
		out.Hosts = make(map[string]semanticConfig, len(in.Hosts))
		for host, cfg := range in.Hosts {
			out.Hosts[host] = cloneSemanticConfig(cfg)
		}
	}
	return out
}

func cloneSemanticConfig(in semanticConfig) semanticConfig {
	out := in
	out.ExemptPathPrefixes = append([]string(nil), in.ExemptPathPrefixes...)
	return out
}

func semanticEnabled(file semanticFile) bool {
	if file.Default.Enabled && file.Default.Mode != semanticModeOff {
		return true
	}
	for _, scope := range file.Hosts {
		if scope.Enabled && scope.Mode != semanticModeOff {
			return true
		}
	}
	return false
}

func semanticScopeStats(scope *runtimeSemanticScope) semanticStats {
	if scope == nil {
		return semanticStats{}
	}
	return semanticStats{
		InspectedRequests: scope.inspectedRequests.Load(),
		ScoredRequests:    scope.scoredRequests.Load(),
		LogOnlyActions:    scope.logOnlyActions.Load(),
		ChallengeActions:  scope.challengeActions.Load(),
		BlockActions:      scope.blockActions.Load(),
	}
}

func addSemanticStats(dst *semanticStats, src semanticStats) {
	dst.InspectedRequests += src.InspectedRequests
	dst.ScoredRequests += src.ScoredRequests
	dst.LogOnlyActions += src.LogOnlyActions
	dst.ChallengeActions += src.ChallengeActions
	dst.BlockActions += src.BlockActions
}

func normalizeSemanticConfig(cfg semanticConfig) (semanticConfig, error) {
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Mode == "" {
		cfg.Mode = semanticModeOff
	}
	cfg.ExemptPathPrefixes = normalizeSemanticPathPrefixes(cfg.ExemptPathPrefixes)
	if cfg.LogThreshold <= 0 {
		cfg.LogThreshold = 4
	}
	if cfg.ChallengeThreshold <= 0 {
		cfg.ChallengeThreshold = 7
	}
	if cfg.BlockThreshold <= 0 {
		cfg.BlockThreshold = 9
	}
	if cfg.MaxInspectBody <= 0 {
		cfg.MaxInspectBody = 16 * 1024
	}
	normProvider, err := normalizeSemanticProviderConfig(cfg.Provider)
	if err != nil {
		return semanticConfig{}, err
	}
	cfg.Provider = normProvider
	if cfg.TemporalWindowSeconds <= 0 {
		cfg.TemporalWindowSeconds = semanticrisk.DefaultTemporalWindowSeconds
	}
	if cfg.TemporalMaxEntriesPerIP <= 0 {
		cfg.TemporalMaxEntriesPerIP = semanticrisk.DefaultTemporalMaxEntriesPerIP
	}
	if cfg.TemporalBurstThreshold <= 0 {
		cfg.TemporalBurstThreshold = semanticrisk.DefaultTemporalBurstThreshold
	}
	if cfg.TemporalBurstScore <= 0 {
		cfg.TemporalBurstScore = semanticrisk.DefaultTemporalBurstScore
	}
	if cfg.TemporalPathFanoutThreshold <= 0 {
		cfg.TemporalPathFanoutThreshold = semanticrisk.DefaultTemporalPathFanoutThreshold
	}
	if cfg.TemporalPathFanoutScore <= 0 {
		cfg.TemporalPathFanoutScore = semanticrisk.DefaultTemporalPathFanoutScore
	}
	if cfg.TemporalUAChurnThreshold <= 0 {
		cfg.TemporalUAChurnThreshold = semanticrisk.DefaultTemporalUAChurnThreshold
	}
	if cfg.TemporalUAChurnScore <= 0 {
		cfg.TemporalUAChurnScore = semanticrisk.DefaultTemporalUAChurnScore
	}
	if !cfg.Enabled {
		cfg.Mode = semanticModeOff
		return cfg, nil
	}

	switch cfg.Mode {
	case semanticModeOff, semanticModeLogOnly, semanticModeChallenge, semanticModeBlock:
	default:
		return semanticConfig{}, fmt.Errorf("mode must be off|log_only|challenge|block")
	}
	if cfg.LogThreshold <= 0 {
		return semanticConfig{}, fmt.Errorf("log_threshold must be > 0")
	}
	if cfg.ChallengeThreshold < cfg.LogThreshold {
		return semanticConfig{}, fmt.Errorf("challenge_threshold must be >= log_threshold")
	}
	if cfg.BlockThreshold < cfg.ChallengeThreshold {
		return semanticConfig{}, fmt.Errorf("block_threshold must be >= challenge_threshold")
	}
	if cfg.MaxInspectBody <= 0 || cfg.MaxInspectBody > 1024*1024 {
		return semanticConfig{}, fmt.Errorf("max_inspect_body must be between 1 and 1048576")
	}
	if cfg.TemporalWindowSeconds <= 0 || cfg.TemporalWindowSeconds > 600 {
		return semanticConfig{}, fmt.Errorf("temporal_window_seconds must be between 1 and 600")
	}
	if cfg.TemporalMaxEntriesPerIP <= 0 || cfg.TemporalMaxEntriesPerIP > 4096 {
		return semanticConfig{}, fmt.Errorf("temporal_max_entries_per_ip must be between 1 and 4096")
	}
	if cfg.TemporalBurstThreshold <= 0 {
		return semanticConfig{}, fmt.Errorf("temporal_burst_threshold must be > 0")
	}
	if cfg.TemporalBurstScore <= 0 {
		return semanticConfig{}, fmt.Errorf("temporal_burst_score must be > 0")
	}
	if cfg.TemporalPathFanoutThreshold <= 0 {
		return semanticConfig{}, fmt.Errorf("temporal_path_fanout_threshold must be > 0")
	}
	if cfg.TemporalPathFanoutScore <= 0 {
		return semanticConfig{}, fmt.Errorf("temporal_path_fanout_score must be > 0")
	}
	if cfg.TemporalUAChurnThreshold <= 0 {
		return semanticConfig{}, fmt.Errorf("temporal_ua_churn_threshold must be > 0")
	}
	if cfg.TemporalUAChurnScore <= 0 {
		return semanticConfig{}, fmt.Errorf("temporal_ua_churn_score must be > 0")
	}

	return cfg, nil
}

func normalizeSemanticPathPrefixes(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if !strings.HasPrefix(v, "/") {
			v = "/" + v
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func sanitizeSemanticText(v string) string {
	return strings.TrimSpace(v)
}

func inspectSemanticText(scope, raw string, score *int, signals *[]semanticSignal) {
	norm := normalizeSemanticInput(raw)
	if norm == "" {
		return
	}
	if len(norm) > 1024 {
		appendSemanticSignal(signals, score, scope+":long_payload", 1)
	}
	if strings.Count(norm, "%") >= 8 || strings.Count(norm, "\\x") >= 2 {
		appendSemanticSignal(signals, score, scope+":high_encoding_density", 1)
	}
	if semanticPatternCommentObf.MatchString(norm) {
		appendSemanticSignal(signals, score, scope+":comment_obfuscation", 2)
	}
	if semanticPatternUnionSelect.MatchString(norm) {
		appendSemanticSignal(signals, score, scope+":sql_union_select", 4)
	}
	if semanticPatternBooleanSQL.MatchString(norm) {
		appendSemanticSignal(signals, score, scope+":sql_boolean_chain", 2)
	}
	if semanticPatternSQLMeta.MatchString(norm) {
		appendSemanticSignal(signals, score, scope+":sql_meta_keyword", 3)
	}
	if semanticPatternPathTrav.MatchString(norm) {
		appendSemanticSignal(signals, score, scope+":path_traversal", 3)
	}
	if semanticPatternXSS.MatchString(norm) {
		appendSemanticSignal(signals, score, scope+":xss_pattern", 3)
	}
	if semanticPatternCmd.MatchString(norm) {
		appendSemanticSignal(signals, score, scope+":command_chain", 3)
	}
}

func normalizeSemanticInput(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	for i := 0; i < 2; i++ {
		decoded, err := url.QueryUnescape(v)
		if err != nil || decoded == v {
			break
		}
		v = decoded
	}
	v = strings.ToLower(v)
	v = strings.ReplaceAll(v, "\u0000", "")
	v = strings.ReplaceAll(v, "+", " ")
	v = semanticPatternWhitespace.ReplaceAllString(v, " ")
	return strings.TrimSpace(v)
}

func appendSemanticSignal(signals *[]semanticSignal, score *int, reason string, delta int) {
	for _, existing := range *signals {
		if existing.Reason == reason {
			return
		}
	}
	*signals = append(*signals, semanticSignal{Reason: reason, Score: delta})
	*score += delta
}

func newTemporalRiskStore(cfg semanticConfig) *semanticrisk.TemporalStore {
	return semanticrisk.NewTemporalStore(semanticrisk.TemporalConfig{
		WindowSeconds:   cfg.TemporalWindowSeconds,
		MaxEntriesPerIP: cfg.TemporalMaxEntriesPerIP,
	})
}

func newSemanticHistoryStore(cfg semanticConfig) *semanticrisk.HistoryStore {
	return semanticrisk.NewHistoryStore(semanticrisk.TemporalConfig{
		WindowSeconds:   cfg.TemporalWindowSeconds,
		MaxEntriesPerIP: cfg.TemporalMaxEntriesPerIP,
	})
}

func inspectSemanticTemporalRisk(rt *runtimeSemanticScope, cfg semanticConfig, clientIP, path, userAgent string, now time.Time, score *int, signals *[]semanticSignal) {
	if rt == nil || rt.temporal == nil {
		return
	}
	snap := rt.temporal.Observe(clientIP, path, userAgent, now)
	for _, signal := range semanticrisk.EvaluateTemporal(snap, semanticTemporalThresholds(cfg)) {
		appendSemanticSignal(signals, score, signal.Reason, signal.Score)
	}
}

func semanticTemporalThresholds(cfg semanticConfig) semanticrisk.TemporalThresholds {
	return semanticrisk.TemporalThresholds{
		BurstThreshold:      cfg.TemporalBurstThreshold,
		BurstScore:          cfg.TemporalBurstScore,
		PathFanoutThreshold: cfg.TemporalPathFanoutThreshold,
		PathFanoutScore:     cfg.TemporalPathFanoutScore,
		UAChurnThreshold:    cfg.TemporalUAChurnThreshold,
		UAChurnScore:        cfg.TemporalUAChurnScore,
	}
}

func inspectSemanticStatefulRisk(
	rt *runtimeSemanticScope,
	telemetry *semanticTelemetry,
	baseScore int,
	now time.Time,
	score *int,
	signals *[]semanticSignal,
) *semanticHistorySnapshot {
	if rt == nil || rt.history == nil || telemetry == nil {
		return nil
	}
	key := strings.TrimSpace(telemetry.Context.ActorKey)
	if key == "" {
		return nil
	}
	currentTargetClass := telemetry.Context.TargetClass
	currentSurfaceClass := telemetry.Context.SurfaceClass
	snapshot := rt.history.Observe(key, semanticrisk.HistoryObservation{
		At:           now.UTC(),
		PathClass:    telemetry.Context.PathClass,
		TargetClass:  currentTargetClass,
		SurfaceClass: currentSurfaceClass,
		BaseScore:    baseScore,
	}, now.UTC())

	for _, signal := range semanticrisk.EvaluateStateful(snapshot, currentTargetClass, currentSurfaceClass, baseScore) {
		appendSemanticSignal(signals, score, signal.Reason, signal.Score)
	}
	return &snapshot
}

func semanticReasons(signals []semanticSignal) []string {
	if len(signals) == 0 {
		return nil
	}
	out := make([]string, 0, len(signals))
	for _, signal := range signals {
		out = append(out, signal.Reason)
	}
	return out
}

func semanticSignalLogObjects(signals []semanticSignal) []map[string]any {
	if len(signals) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(signals))
	for _, signal := range signals {
		out = append(out, map[string]any{
			"reason": signal.Reason,
			"score":  signal.Score,
		})
	}
	return out
}

func issueSemanticChallengeToken(rt *runtimeSemanticScope, ipStr, userAgent string, now time.Time) string {
	exp := now.UTC().Add(rt.challengeTTL).Unix()
	payload := strconv.FormatInt(exp, 10)
	return payload + "." + signSemanticChallenge(rt, ipStr, userAgent, payload)
}

func verifySemanticChallengeToken(rt *runtimeSemanticScope, token, ipStr, userAgent string, now time.Time) bool {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 {
		return false
	}

	expUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expUnix <= 0 {
		return false
	}
	if now.UTC().Unix() > expUnix {
		return false
	}

	return challengecookie.ConstantTimeHexEqual(parts[1], signSemanticChallenge(rt, ipStr, userAgent, parts[0]))
}

func signSemanticChallenge(rt *runtimeSemanticScope, ipStr, userAgent, payload string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(ipStr) + "\n" + strings.ToLower(strings.TrimSpace(userAgent)) + "\n" + payload + "\n" + string(rt.challengeSecret)))
	return hex.EncodeToString(sum[:])
}

func ensureSemanticFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(defaultSemanticPolicyRaw()), 0o644)
}

func defaultSemanticPolicyRaw() string {
	return `{
  "enabled": true,
  "mode": "log_only",
  "provider": {
    "enabled": false,
    "name": "builtin_attack_family",
    "timeout_ms": 25
  },
  "exempt_path_prefixes": [
    "/tukuyomi-api",
    "/tukuyomi-ui",
    "/health",
    "/healthz",
    "/metrics",
    "/favicon.ico",
    "/_next/",
    "/assets/",
    "/static/"
  ],
  "log_threshold": 7,
  "challenge_threshold": 10,
  "block_threshold": 13,
  "max_inspect_body": 8192,
  "temporal_window_seconds": 10,
  "temporal_max_entries_per_ip": 128,
  "temporal_burst_threshold": 20,
  "temporal_burst_score": 2,
  "temporal_path_fanout_threshold": 8,
  "temporal_path_fanout_score": 2,
  "temporal_ua_churn_threshold": 4,
  "temporal_ua_churn_score": 1
}
`
}
