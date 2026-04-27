package wafmatch

import (
	"strings"

	"tukuyomi/internal/waf"
)

type Primary struct {
	Variable string
	Value    string
}

func SelectPrimary(matches []waf.Match, interruptionRuleID int, maxValueBytes int) (Primary, bool) {
	best := Primary{}
	bestScore := -1
	found := false

	for _, matched := range matches {
		isInterruptionRule := interruptionRuleID > 0 && matchedRuleID(matched) == interruptionRuleID
		for _, md := range matched.MatchedData {
			primary, ok := normalizePrimary(md, maxValueBytes)
			if !ok {
				continue
			}
			score := scorePrimary(primary, isInterruptionRule)
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
	return Primary{}, false
}

func normalizePrimary(md waf.MatchData, maxValueBytes int) (Primary, bool) {
	variable := strings.TrimSpace(md.Variable)
	key := strings.TrimSpace(md.Key)
	if variable != "" && key != "" {
		variable += ":" + key
	}

	value := clampText(strings.TrimSpace(md.Value), maxValueBytes)
	if variable == "" && value == "" {
		return Primary{}, false
	}
	return Primary{
		Variable: variable,
		Value:    value,
	}, true
}

func matchedRuleID(matched waf.Match) int {
	return matched.RuleID
}

func scorePrimary(match Primary, isInterruptionRule bool) int {
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

func clampText(v string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(v) <= max {
		return v
	}
	return v[:max]
}
