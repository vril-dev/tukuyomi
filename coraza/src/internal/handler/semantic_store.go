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
	Enabled                     bool     `json:"enabled"`
	Mode                        string   `json:"mode"`
	ExemptPathPrefixes          []string `json:"exempt_path_prefixes,omitempty"`
	LogThreshold                int      `json:"log_threshold"`
	ChallengeThreshold          int      `json:"challenge_threshold"`
	BlockThreshold              int      `json:"block_threshold"`
	MaxInspectBody              int64    `json:"max_inspect_body"`
	TemporalWindowSeconds       int      `json:"temporal_window_seconds,omitempty"`
	TemporalMaxEntriesPerIP     int      `json:"temporal_max_entries_per_ip,omitempty"`
	TemporalBurstThreshold      int      `json:"temporal_burst_threshold,omitempty"`
	TemporalBurstScore          int      `json:"temporal_burst_score,omitempty"`
	TemporalPathFanoutThreshold int      `json:"temporal_path_fanout_threshold,omitempty"`
	TemporalPathFanoutScore     int      `json:"temporal_path_fanout_score,omitempty"`
	TemporalUAChurnThreshold    int      `json:"temporal_ua_churn_threshold,omitempty"`
	TemporalUAChurnScore        int      `json:"temporal_ua_churn_score,omitempty"`
}

type semanticStats struct {
	InspectedRequests uint64 `json:"inspected_requests"`
	ScoredRequests    uint64 `json:"scored_requests"`
	LogOnlyActions    uint64 `json:"log_only_actions"`
	ChallengeActions  uint64 `json:"challenge_actions"`
	BlockActions      uint64 `json:"block_actions"`
}

type semanticEvaluation struct {
	Score   int
	Reasons []string
	Signals []semanticSignal
	Action  string
}

type runtimeSemanticConfig struct {
	Raw semanticConfig

	temporal *temporalRiskStore

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
	if err := ensureSemanticFile(target); err != nil {
		return err
	}

	semanticMu.Lock()
	semanticPath = target
	semanticMu.Unlock()

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

func GetSemanticStats() semanticStats {
	rt := currentSemanticRuntime()
	if rt == nil {
		return semanticStats{}
	}
	return semanticStats{
		InspectedRequests: rt.inspectedRequests.Load(),
		ScoredRequests:    rt.scoredRequests.Load(),
		LogOnlyActions:    rt.logOnlyActions.Load(),
		ChallengeActions:  rt.challengeActions.Load(),
		BlockActions:      rt.blockActions.Load(),
	}
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
	return EvaluateSemanticWithContext(r, "", time.Now().UTC())
}

func EvaluateSemanticWithContext(r *http.Request, clientIP string, now time.Time) semanticEvaluation {
	rt := currentSemanticRuntime()
	if rt == nil || r == nil || r.URL == nil {
		return semanticEvaluation{Action: semanticActionNone}
	}

	cfg := rt.Raw
	if !cfg.Enabled || cfg.Mode == semanticModeOff {
		return semanticEvaluation{Action: semanticActionNone}
	}

	path := sanitizeSemanticText(r.URL.Path)
	for _, pfx := range cfg.ExemptPathPrefixes {
		if pfx == "/" || strings.HasPrefix(path, pfx) {
			eval := semanticEvaluation{Action: semanticActionNone}
			rt.observe(eval)
			return eval
		}
	}

	score := 0
	signals := make([]semanticSignal, 0, 12)
	inspectSemanticText("path", r.URL.Path, &score, &signals)
	inspectSemanticText("query", r.URL.RawQuery, &score, &signals)
	inspectSemanticText("user_agent", r.UserAgent(), &score, &signals)
	inspectSemanticText("referer", r.Referer(), &score, &signals)

	if cfg.MaxInspectBody > 0 && r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		n := cfg.MaxInspectBody + 1
		chunk, _ := io.ReadAll(io.LimitReader(r.Body, n))
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(chunk), r.Body))
		if int64(len(chunk)) > cfg.MaxInspectBody {
			chunk = chunk[:cfg.MaxInspectBody]
		}
		if len(chunk) > 0 {
			inspectSemanticText("body", string(chunk), &score, &signals)
		}
	}
	inspectSemanticTemporalRisk(rt, cfg, clientIP, r.URL.Path, r.UserAgent(), now, &score, &signals)

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
		Score:   score,
		Reasons: semanticReasons(signals),
		Signals: signals,
		Action:  action,
	}
	rt.observe(eval)
	return eval
}

func HasValidSemanticChallengeCookie(r *http.Request, clientIP string, now time.Time) bool {
	rt := currentSemanticRuntime()
	if rt == nil {
		return true
	}
	cfg := rt.Raw
	if !cfg.Enabled || cfg.Mode != semanticModeChallenge {
		return true
	}

	c, err := r.Cookie(rt.challengeCookieName)
	if err != nil {
		return false
	}
	return verifySemanticChallengeToken(rt, c.Value, clientIP, r.UserAgent(), now.UTC())
}

func WriteSemanticChallenge(w http.ResponseWriter, r *http.Request, clientIP string) {
	rt := currentSemanticRuntime()
	if rt == nil {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	token := issueSemanticChallengeToken(rt, clientIP, r.UserAgent(), time.Now().UTC())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Tukuyomi-Semantic-Challenge", "required")

	if !acceptsHTML(r.Header.Get("Accept")) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(rt.challengeStatusCode)
		_, _ = w.Write([]byte(`{"error":"semantic challenge required"}`))
		return
	}

	maxAge := int(rt.challengeTTL.Seconds())
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
</body></html>`, token, rt.challengeCookieName, maxAge)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(rt.challengeStatusCode)
	_, _ = w.Write([]byte(body))
}

func currentSemanticRuntime() *runtimeSemanticConfig {
	semanticMu.RLock()
	defer semanticMu.RUnlock()
	return semanticRuntime
}

func (rt *runtimeSemanticConfig) observe(eval semanticEvaluation) {
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
	var cfg semanticConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}

	norm, err := normalizeSemanticConfig(cfg)
	if err != nil {
		return nil, err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		secret = []byte("tukuyomi-semantic-ephemeral")
	}

	return &runtimeSemanticConfig{
		Raw:                 norm,
		temporal:            newTemporalRiskStore(norm),
		challengeCookieName: "__tukuyomi_semantic_ok",
		challengeSecret:     secret,
		challengeTTL:        12 * time.Hour,
		challengeStatusCode: http.StatusTooManyRequests,
	}, nil
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
	if cfg.TemporalWindowSeconds <= 0 {
		cfg.TemporalWindowSeconds = defaultTemporalWindowSeconds
	}
	if cfg.TemporalMaxEntriesPerIP <= 0 {
		cfg.TemporalMaxEntriesPerIP = defaultTemporalMaxEntriesPerIP
	}
	if cfg.TemporalBurstThreshold <= 0 {
		cfg.TemporalBurstThreshold = defaultTemporalBurstThreshold
	}
	if cfg.TemporalBurstScore <= 0 {
		cfg.TemporalBurstScore = defaultTemporalBurstScore
	}
	if cfg.TemporalPathFanoutThreshold <= 0 {
		cfg.TemporalPathFanoutThreshold = defaultTemporalPathFanoutThreshold
	}
	if cfg.TemporalPathFanoutScore <= 0 {
		cfg.TemporalPathFanoutScore = defaultTemporalPathFanoutScore
	}
	if cfg.TemporalUAChurnThreshold <= 0 {
		cfg.TemporalUAChurnThreshold = defaultTemporalUAChurnThreshold
	}
	if cfg.TemporalUAChurnScore <= 0 {
		cfg.TemporalUAChurnScore = defaultTemporalUAChurnScore
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

func issueSemanticChallengeToken(rt *runtimeSemanticConfig, ipStr, userAgent string, now time.Time) string {
	exp := now.UTC().Add(rt.challengeTTL).Unix()
	payload := strconv.FormatInt(exp, 10)
	return payload + "." + signSemanticChallenge(rt, ipStr, userAgent, payload)
}

func verifySemanticChallengeToken(rt *runtimeSemanticConfig, token, ipStr, userAgent string, now time.Time) bool {
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

	return subtleConstantTimeHexEqual(parts[1], signSemanticChallenge(rt, ipStr, userAgent, parts[0]))
}

func signSemanticChallenge(rt *runtimeSemanticConfig, ipStr, userAgent, payload string) string {
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

	const defaultRaw = `{
  "enabled": true,
  "mode": "log_only",
  "exempt_path_prefixes": [
    "/tukuyomi-api",
    "/tukuyomi-admin",
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
	return os.WriteFile(path, []byte(defaultRaw), 0o644)
}
