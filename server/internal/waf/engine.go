package waf

import (
	"errors"
	"fmt"
	"net/http"
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
	w coraza.WAF
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

	tx := e.w.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	tx.AddRequestHeader("Host", req.Host)

	var errs []error
	_ = tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		errs = append(errs, fmt.Errorf("body: %w", err))
	}

	decision.Matches = convertCorazaMatches(tx.MatchedRules())
	decision.Hit = len(decision.Matches) > 0
	decision.RuleIDs = uniqueRuleIDs(decision.Matches)
	if it := tx.Interruption(); it != nil {
		decision.Interruption = &Interruption{
			RuleID: it.RuleID,
			Status: it.Status,
		}
	}

	return decision, errors.Join(errs...)
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
