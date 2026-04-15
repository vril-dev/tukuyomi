package handler

import (
	"testing"

	corazaTypes "github.com/corazawaf/coraza/v3/types"
	corazaVariables "github.com/corazawaf/coraza/v3/types/variables"
)

type testMatchData struct {
	variable   corazaVariables.RuleVariable
	key        string
	value      string
	message    string
	data       string
	chainLevel int
}

func (m testMatchData) Variable() corazaVariables.RuleVariable { return m.variable }
func (m testMatchData) Key() string                            { return m.key }
func (m testMatchData) Value() string                          { return m.value }
func (m testMatchData) Message() string                        { return m.message }
func (m testMatchData) Data() string                           { return m.data }
func (m testMatchData) ChainLevel() int                        { return m.chainLevel }

type testRuleMetadata struct{ id int }

func (r testRuleMetadata) ID() int                            { return r.id }
func (r testRuleMetadata) File() string                       { return "" }
func (r testRuleMetadata) Line() int                          { return 0 }
func (r testRuleMetadata) Revision() string                   { return "" }
func (r testRuleMetadata) Severity() corazaTypes.RuleSeverity { return 0 }
func (r testRuleMetadata) Version() string                    { return "" }
func (r testRuleMetadata) Tags() []string                     { return nil }
func (r testRuleMetadata) Maturity() int                      { return 0 }
func (r testRuleMetadata) Accuracy() int                      { return 0 }
func (r testRuleMetadata) Operator() string                   { return "" }
func (r testRuleMetadata) Phase() corazaTypes.RulePhase       { return 0 }
func (r testRuleMetadata) Raw() string                        { return "" }
func (r testRuleMetadata) SecMark() string                    { return "" }

type testMatchedRule struct {
	rule         corazaTypes.RuleMetadata
	matchedDatas []corazaTypes.MatchData
}

func (m testMatchedRule) Message() string                       { return "" }
func (m testMatchedRule) Data() string                          { return "" }
func (m testMatchedRule) URI() string                           { return "" }
func (m testMatchedRule) TransactionID() string                 { return "" }
func (m testMatchedRule) Disruptive() bool                      { return false }
func (m testMatchedRule) ServerIPAddress() string               { return "" }
func (m testMatchedRule) ClientIPAddress() string               { return "" }
func (m testMatchedRule) Rule() corazaTypes.RuleMetadata        { return m.rule }
func (m testMatchedRule) MatchedDatas() []corazaTypes.MatchData { return m.matchedDatas }
func (m testMatchedRule) AuditLog() string                      { return "" }
func (m testMatchedRule) ErrorLog() string                      { return "" }

func TestSelectPrimaryWAFMatch(t *testing.T) {
	t.Run("prefers interruption rule with non-empty value", func(t *testing.T) {
		matches := []corazaTypes.MatchedRule{
			testMatchedRule{
				rule: testRuleMetadata{id: 942100},
				matchedDatas: []corazaTypes.MatchData{
					testMatchData{variable: corazaVariables.QueryString, key: "q", value: "fallback"},
				},
			},
			testMatchedRule{
				rule: testRuleMetadata{id: 920350},
				matchedDatas: []corazaTypes.MatchData{
					testMatchData{variable: corazaVariables.RequestBody, key: "id", value: "123"},
				},
			},
		}

		got, ok := selectPrimaryWAFMatch(matches, 920350)
		if !ok {
			t.Fatal("expected primary match")
		}
		if got.Variable != corazaVariables.RequestBody.Name()+":id" {
			t.Fatalf("variable=%q want=%q", got.Variable, corazaVariables.RequestBody.Name()+":id")
		}
		if got.Value != "123" {
			t.Fatalf("value=%q want=123", got.Value)
		}
	})

	t.Run("prefers request-derived value over interruption tx bookkeeping", func(t *testing.T) {
		txScore := wafPrimaryMatch{Variable: "TX:blocking_inbound_anomaly_score", Value: "25"}
		if scorePrimaryWAFMatch(txScore, true) >= scorePrimaryWAFMatch(wafPrimaryMatch{Variable: corazaVariables.QueryString.Name(), Value: "<script>window.alert(1)</script>"}, false) {
			t.Fatal("request-derived query string should outrank TX anomaly score")
		}

		got, ok := selectPrimaryWAFMatch([]corazaTypes.MatchedRule{
			testMatchedRule{
				rule: testRuleMetadata{id: 941100},
				matchedDatas: []corazaTypes.MatchData{
					testMatchData{variable: corazaVariables.QueryString, value: "<script>window.alert(1)</script>"},
				},
			},
			testMatchedRule{
				rule: testRuleMetadata{id: 949110},
				matchedDatas: []corazaTypes.MatchData{
					testMatchData{variable: corazaVariables.Unknown, value: "25"},
				},
			},
		}, 949110)
		if !ok {
			t.Fatal("expected primary match")
		}
		if got.Variable != corazaVariables.QueryString.Name() {
			t.Fatalf("variable=%q want=%q", got.Variable, corazaVariables.QueryString.Name())
		}
		if got.Value != "<script>window.alert(1)</script>" {
			t.Fatalf("value=%q want payload", got.Value)
		}
	})

	t.Run("query string outranks interruption request filename", func(t *testing.T) {
		got, ok := selectPrimaryWAFMatch([]corazaTypes.MatchedRule{
			testMatchedRule{
				rule: testRuleMetadata{id: 941100},
				matchedDatas: []corazaTypes.MatchData{
					testMatchData{variable: corazaVariables.QueryString, value: "<script>window.alert(document.cookie);</script>"},
				},
			},
			testMatchedRule{
				rule: testRuleMetadata{id: 949110},
				matchedDatas: []corazaTypes.MatchData{
					testMatchData{variable: corazaVariables.RequestFilename, value: "/"},
				},
			},
		}, 949110)
		if !ok {
			t.Fatal("expected primary match")
		}
		if got.Variable != corazaVariables.QueryString.Name() {
			t.Fatalf("variable=%q want=%q", got.Variable, corazaVariables.QueryString.Name())
		}
		if got.Value != "<script>window.alert(document.cookie);</script>" {
			t.Fatalf("value=%q want payload", got.Value)
		}
	})
}
