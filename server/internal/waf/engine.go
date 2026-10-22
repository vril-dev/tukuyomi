package waf

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	corazaTypes "github.com/corazawaf/coraza/v3/types"
	corazaVariables "github.com/corazawaf/coraza/v3/types/variables"

	"tukuyomi/internal/config"
	"tukuyomi/internal/wafengine"
)

const EngineModeCoraza = wafengine.ModeCoraza

type Engine interface {
	Name() string
	InspectRequest(*http.Request) (Decision, error)
}

type Decision struct {
	Engine       string
	Hit          bool
	RuleIDs      []string
	Matches      []Match
	Interruption *Interruption
	RequestBody  RequestBodyResult
}

type Interruption struct {
	RuleID int
	Status int
}

type Match struct {
	RuleID      int
	Phase       string
	File        string
	Line        int
	Revision    string
	Version     string
	Severity    string
	Maturity    int
	Accuracy    int
	Operator    string
	Tags        []string
	Disruptive  bool
	MatchedData []MatchData
}

type MatchData struct {
	Variable string
	Key      string
	Value    string
}

type corazaEngine struct {
	w            coraza.WAF
	bodyOverride *RequestBodyOverride
}

func (e corazaEngine) Name() string {
	return EngineModeCoraza
}

func (e corazaEngine) InspectRequest(req *http.Request) (Decision, error) {
	decision := Decision{Engine: e.Name()}
	if e.w == nil {
		return decision, errors.New("coraza WAF is not initialized")
	}
	if req == nil || req.URL == nil {
		return decision, errors.New("request is nil")
	}

	policy := currentRequestBodyPolicy()
	if e.bodyOverride != nil {
		policy = policy.withOverride(*e.bodyOverride)
	}
	var errs []error
	sample, err := readInspectionBody(req, policy)
	if err != nil {
		errs = append(errs, fmt.Errorf("body read: %w", err))
	}
	if sample.Oversize && policy.OversizeAction == config.WAFRequestBodyOversizeReject && policy.Mode == config.WAFRequestBodyModeEnforce {
		decision.RequestBody = RequestBodyResult{Oversize: true, Truncated: sample.Truncated, Reason: requestBodyReasonOversize}
		decision.Interruption = &Interruption{RuleID: requestBodyRuleOversize, Status: http.StatusRequestEntityTooLarge}
		return decision, errors.Join(errs...)
	}

	decision, signals, err := e.inspect(req, sample.Data)
	if err != nil {
		errs = append(errs, err)
	}
	decision.RequestBody = RequestBodyResult{
		Inspected: len(sample.Data) > 0,
		Bytes:     len(sample.Data),
		Truncated: sample.Truncated,
		Oversize:  sample.Oversize,
	}
	if policy.Mode == config.WAFRequestBodyModeOff {
		return decision, errors.Join(errs...)
	}

	if decision.Interruption != nil {
		if policy.Mode == config.WAFRequestBodyModeDetect && decision.RequestBody.Inspected {
			withoutBody, _, err := e.inspect(req, nil)
			if err != nil {
				errs = append(errs, fmt.Errorf("detect re-run: %w", err))
			}
			if withoutBody.Interruption == nil {
				decision.RequestBody.Reason = requestBodyReasonRule
				decision.RequestBody.DryRun = decision.Interruption
				decision.Interruption = nil
			}
		}
		return decision, errors.Join(errs...)
	}

	var blocked *Interruption
	switch {
	case signals.ArgumentsLimit:
		decision.RequestBody.Reason = requestBodyReasonArgumentsLimit
		blocked = &Interruption{RuleID: requestBodyRuleArgumentsLimit, Status: http.StatusBadRequest}
	case signals.BodyError && decision.RequestBody.Inspected && !sample.Truncated:
		decision.RequestBody.Reason = requestBodyReasonParseError
		blocked = &Interruption{RuleID: requestBodyRuleBodyError, Status: http.StatusBadRequest}
	case signals.MultipartStrict && decision.RequestBody.Inspected && !sample.Truncated:
		decision.RequestBody.Reason = requestBodyReasonParseError
		blocked = &Interruption{RuleID: requestBodyRuleMultipartStrict, Status: http.StatusBadRequest}
	case sample.Oversize && policy.OversizeAction == config.WAFRequestBodyOversizeReject:
		decision.RequestBody.Reason = requestBodyReasonOversize
		blocked = &Interruption{RuleID: requestBodyRuleOversize, Status: http.StatusRequestEntityTooLarge}
	}
	if blocked != nil {
		if policy.Mode == config.WAFRequestBodyModeDetect {
			decision.RequestBody.DryRun = blocked
		} else {
			decision.Interruption = blocked
		}
	}
	return decision, errors.Join(errs...)
}

// inspect runs one Coraza transaction. body is written to the transaction only
// when it is non-empty.
func (e corazaEngine) inspect(req *http.Request, body []byte) (Decision, requestBodySignals, error) {
	decision := Decision{Engine: e.Name()}
	tx := e.w.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	// Unlike Coraza's http middleware, pass only the path and query: absolute-form
	// HTTP/1 targets and HTTP/3 request URLs carry a scheme and host, which would
	// keep REQUEST_URI rules anchored at "/" from matching.
	tx.ProcessURI(req.URL.RequestURI(), req.Method, req.Proto)
	addCorazaRequestHeaders(tx, req)

	var errs []error
	if it := tx.ProcessRequestHeaders(); it == nil && len(body) > 0 {
		if _, _, err := tx.WriteRequestBody(body); err != nil {
			errs = append(errs, fmt.Errorf("body write: %w", err))
		}
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		errs = append(errs, fmt.Errorf("body: %w", err))
	}

	matches, signals := splitRequestBodySignals(convertCorazaMatches(tx.MatchedRules()))
	decision.Matches = matches
	decision.Hit = len(matches) > 0
	decision.RuleIDs = uniqueRuleIDs(matches)
	if it := tx.Interruption(); it != nil {
		decision.Interruption = &Interruption{
			RuleID: it.RuleID,
			Status: it.Status,
		}
	}

	return decision, signals, errors.Join(errs...)
}

func addCorazaRequestHeaders(tx corazaTypes.Transaction, req *http.Request) {
	if tx == nil || req == nil {
		return
	}
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
	}
	for key, values := range req.Header {
		key = strings.TrimSpace(key)
		if key == "" || strings.EqualFold(key, "Host") {
			continue
		}
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
	if req.Header.Get("Content-Length") == "" && shouldAddSyntheticContentLength(req) {
		tx.AddRequestHeader("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}
	if req.Header.Get("Transfer-Encoding") == "" && len(req.TransferEncoding) > 0 {
		tx.AddRequestHeader("Transfer-Encoding", strings.Join(req.TransferEncoding, ", "))
	}
}

func shouldAddSyntheticContentLength(req *http.Request) bool {
	if req == nil || req.ContentLength < 0 {
		return false
	}
	if req.ContentLength > 0 {
		return true
	}
	switch req.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func GetBaseEngine() Engine {
	if mode := wafengine.Normalize(config.WAFEngineMode); mode != EngineModeCoraza {
		return nil
	}
	base := getBaseWAF()
	if base == nil {
		return nil
	}
	return corazaEngine{w: base}
}

func GetEngineForExtraRule(extraRule string) (Engine, error) {
	if mode := wafengine.Normalize(config.WAFEngineMode); mode != EngineModeCoraza {
		return nil, fmt.Errorf("extra-rule WAF engine is unavailable for mode %q", mode)
	}
	w, err := getWAFForExtraRule(extraRule)
	if err != nil || w == nil {
		return nil, err
	}
	return corazaEngine{w: w}, nil
}

func EngineCapabilities() []wafengine.Capability {
	return wafengine.Capabilities()
}

func convertCorazaMatches(matches []corazaTypes.MatchedRule) []Match {
	out := make([]Match, 0, len(matches))
	for _, matched := range matches {
		converted, ok := convertCorazaMatch(matched)
		if ok {
			out = append(out, converted)
		}
	}
	return out
}

func convertCorazaMatch(matched corazaTypes.MatchedRule) (Match, bool) {
	if matched == nil {
		return Match{}, false
	}
	rule := matched.Rule()
	if rule == nil {
		return Match{}, false
	}
	return Match{
		RuleID:      rule.ID(),
		Phase:       corazaRulePhaseLabel(rule.Phase()),
		File:        strings.TrimSpace(rule.File()),
		Line:        rule.Line(),
		Revision:    strings.TrimSpace(rule.Revision()),
		Version:     strings.TrimSpace(rule.Version()),
		Severity:    strings.TrimSpace(rule.Severity().String()),
		Maturity:    rule.Maturity(),
		Accuracy:    rule.Accuracy(),
		Operator:    strings.TrimSpace(rule.Operator()),
		Tags:        append([]string(nil), rule.Tags()...),
		Disruptive:  matched.Disruptive(),
		MatchedData: convertCorazaMatchData(matched.MatchedDatas()),
	}, true
}

func corazaRulePhaseLabel(phase corazaTypes.RulePhase) string {
	switch phase {
	case corazaTypes.PhaseRequestHeaders:
		return "request_headers"
	case corazaTypes.PhaseRequestBody:
		return "request_body"
	case corazaTypes.PhaseResponseHeaders:
		return "response_headers"
	case corazaTypes.PhaseResponseBody:
		return "response_body"
	case corazaTypes.PhaseLogging:
		return "logging"
	default:
		return "unknown"
	}
}

func convertCorazaMatchData(datas []corazaTypes.MatchData) []MatchData {
	if len(datas) == 0 {
		return nil
	}
	out := make([]MatchData, 0, len(datas))
	for _, data := range datas {
		if data == nil {
			continue
		}
		variable := ""
		if variableRef := data.Variable(); variableRef != corazaVariables.Unknown {
			variable = strings.TrimSpace(variableRef.Name())
		}
		out = append(out, MatchData{
			Variable: variable,
			Key:      strings.TrimSpace(data.Key()),
			Value:    strings.TrimSpace(data.Value()),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func uniqueRuleIDs(matches []Match) []string {
	seen := map[int]struct{}{}
	out := make([]string, 0, len(matches))
	for _, matched := range matches {
		if matched.RuleID <= 0 {
			continue
		}
		if _, ok := seen[matched.RuleID]; ok {
			continue
		}
		seen[matched.RuleID] = struct{}{}
		out = append(out, fmt.Sprintf("%d", matched.RuleID))
	}
	return out
}
