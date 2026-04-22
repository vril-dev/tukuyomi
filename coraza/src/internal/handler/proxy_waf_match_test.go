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

	t.Run("args outrank request headers host noise", func(t *testing.T) {
		got, ok := selectPrimaryWAFMatch([]corazaTypes.MatchedRule{
			testMatchedRule{
				rule: testRuleMetadata{id: 920350},
				matchedDatas: []corazaTypes.MatchData{
					testMatchData{variable: corazaVariables.RequestHeaders, key: "Host", value: "127.0.0.1"},
				},
			},
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

	t.Run("request filename still wins when it is the only useful signal", func(t *testing.T) {
		got, ok := selectPrimaryWAFMatch([]corazaTypes.MatchedRule{
			testMatchedRule{
				rule: testRuleMetadata{id: 930120},
				matchedDatas: []corazaTypes.MatchData{
					testMatchData{variable: corazaVariables.RequestFilename, value: "/etc/passwd"},
				},
			},
		}, 930120)
		if !ok {
			t.Fatal("expected primary match")
		}
		if got.Variable != corazaVariables.RequestFilename.Name() {
			t.Fatalf("variable=%q want=%q", got.Variable, corazaVariables.RequestFilename.Name())
		}
		if got.Value != "/etc/passwd" {
			t.Fatalf("value=%q want=/etc/passwd", got.Value)
		}
	})

	t.Run("falls back to first normalized match when values are empty", func(t *testing.T) {
		matches := []corazaTypes.MatchedRule{
			testMatchedRule{
				rule: testRuleMetadata{id: 942100},
				matchedDatas: []corazaTypes.MatchData{
					testMatchData{variable: corazaVariables.QueryString, key: "q", value: ""},
					testMatchData{variable: corazaVariables.RequestBody, key: "id", value: ""},
				},
			},
		}

		got, ok := selectPrimaryWAFMatch(matches, 942100)
		if !ok {
			t.Fatal("expected fallback primary match")
		}
		if got.Variable != corazaVariables.QueryString.Name()+":q" {
			t.Fatalf("variable=%q want=%q", got.Variable, corazaVariables.QueryString.Name()+":q")
		}
		if got.Value != "" {
			t.Fatalf("value=%q want empty", got.Value)
		}
	})
}
