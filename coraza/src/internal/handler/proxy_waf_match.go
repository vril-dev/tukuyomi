package handler

import (
	"strings"

	corazaTypes "github.com/corazawaf/coraza/v3/types"
	corazaVariables "github.com/corazawaf/coraza/v3/types/variables"
)

type wafPrimaryMatch struct {
	Variable string
	Value    string
}

func selectPrimaryWAFMatch(matches []corazaTypes.MatchedRule, interruptionRuleID int) (wafPrimaryMatch, bool) {
	best := wafPrimaryMatch{}
	bestScore := -1
	found := false

	for _, matched := range matches {
		if matched == nil {
			continue
		}
		isInterruptionRule := interruptionRuleID > 0 && matchedRuleID(matched) == interruptionRuleID
		for _, md := range matched.MatchedDatas() {
			primary, ok := normalizePrimaryWAFMatch(md)
			if !ok {
				continue
			}
			score := scorePrimaryWAFMatch(primary, isInterruptionRule)
			if score > bestScore {
				best = primary
				bestScore = score
				found = true
			}
		}
	}

	if found {
		return best, true
	}
	return wafPrimaryMatch{}, false
}

func normalizePrimaryWAFMatch(md corazaTypes.MatchData) (wafPrimaryMatch, bool) {
	if md == nil {
		return wafPrimaryMatch{}, false
	}

	variable := ""
	if variableRef := md.Variable(); variableRef != corazaVariables.Unknown {
		variable = strings.TrimSpace(variableRef.Name())
	}
	key := strings.TrimSpace(md.Key())
	if variable != "" && key != "" {
		variable += ":" + key
	}

	value := clampText(strings.TrimSpace(md.Value()), fpTunerMaxMatchedValueBytes)
	if variable == "" && value == "" {
		return wafPrimaryMatch{}, false
	}
	return wafPrimaryMatch{
		Variable: variable,
		Value:    value,
	}, true
}

func matchedRuleID(matched corazaTypes.MatchedRule) int {
	if matched == nil {
		return 0
	}
	rule := matched.Rule()
	if rule == nil {
		return 0
	}
	return rule.ID()
}

func scorePrimaryWAFMatch(match wafPrimaryMatch, isInterruptionRule bool) int {
	score := matchVariableSignalScore(match.Variable)
	if match.Value != "" {
		score += 10
	}
	if isInterruptionRule {
		score += 1
	}
	return score
}

func isTXBookkeepingVariable(variable string) bool {
	trimmed := strings.TrimSpace(variable)
	return trimmed == "TX" || strings.HasPrefix(trimmed, "TX:")
}

func matchVariableSignalScore(variable string) int {
	trimmed := strings.TrimSpace(strings.ToUpper(variable))
	switch {
	case trimmed == "":
		return 0
	case isTXBookkeepingVariable(trimmed):
		return 1
	case strings.HasPrefix(trimmed, "ARGS"),
		strings.HasPrefix(trimmed, "QUERY_STRING"),
		strings.HasPrefix(trimmed, "REQUEST_BODY"),
		strings.HasPrefix(trimmed, "REQUEST_COOKIES"),
		strings.HasPrefix(trimmed, "XML"),
		strings.HasPrefix(trimmed, "JSON"),
		strings.HasPrefix(trimmed, "MULTIPART"),
		strings.HasPrefix(trimmed, "FILES"):
		return 400
	case strings.HasPrefix(trimmed, "REQUEST_HEADERS"):
		return 260
	case strings.HasPrefix(trimmed, "REQUEST_URI"),
		strings.HasPrefix(trimmed, "REQUEST_LINE"),
		strings.HasPrefix(trimmed, "REQUEST_BASENAME"):
		return 220
	case strings.HasPrefix(trimmed, "REQUEST_FILENAME"):
		return 120
	default:
		return 180
	}
}
