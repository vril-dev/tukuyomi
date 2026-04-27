package wafmatch

import (
	"testing"

	"tukuyomi/internal/waf"
)

func TestSelectPrimary(t *testing.T) {
	t.Run("prefers interruption rule with non-empty value", func(t *testing.T) {
		matches := []waf.Match{
			{
				RuleID: 942100,
				MatchedData: []waf.MatchData{
					{Variable: "QUERY_STRING", Key: "q", Value: "fallback"},
				},
			},
			{
				RuleID: 920350,
				MatchedData: []waf.MatchData{
					{Variable: "REQUEST_BODY", Key: "id", Value: "123"},
				},
			},
		}

		got, ok := SelectPrimary(matches, 920350, 2048)
		if !ok {
			t.Fatal("expected primary match")
		}
		if got.Variable != "REQUEST_BODY:id" {
			t.Fatalf("variable=%q want=%q", got.Variable, "REQUEST_BODY:id")
		}
		if got.Value != "123" {
			t.Fatalf("value=%q want=123", got.Value)
		}
	})

	t.Run("prefers request-derived value over interruption tx bookkeeping", func(t *testing.T) {
		txScore := Primary{Variable: "TX:blocking_inbound_anomaly_score", Value: "25"}
		if scorePrimary(txScore, true) >= scorePrimary(Primary{Variable: "QUERY_STRING", Value: "<script>window.alert(1)</script>"}, false) {
			t.Fatal("request-derived query string should outrank TX anomaly score")
		}

		got, ok := SelectPrimary([]waf.Match{
			{
				RuleID: 941100,
				MatchedData: []waf.MatchData{
					{Variable: "QUERY_STRING", Value: "<script>window.alert(1)</script>"},
				},
			},
			{
				RuleID: 949110,
				MatchedData: []waf.MatchData{
					{Value: "25"},
				},
			},
		}, 949110, 2048)
		if !ok {
			t.Fatal("expected primary match")
		}
		if got.Variable != "QUERY_STRING" {
			t.Fatalf("variable=%q want=%q", got.Variable, "QUERY_STRING")
		}
		if got.Value != "<script>window.alert(1)</script>" {
			t.Fatalf("value=%q want payload", got.Value)
		}
	})

	t.Run("query string outranks interruption request filename", func(t *testing.T) {
		got, ok := SelectPrimary([]waf.Match{
			{
				RuleID: 941100,
				MatchedData: []waf.MatchData{
					{Variable: "QUERY_STRING", Value: "<script>window.alert(document.cookie);</script>"},
				},
			},
			{
				RuleID: 949110,
				MatchedData: []waf.MatchData{
					{Variable: "REQUEST_FILENAME", Value: "/"},
				},
			},
		}, 949110, 2048)
		if !ok {
			t.Fatal("expected primary match")
		}
		if got.Variable != "QUERY_STRING" {
			t.Fatalf("variable=%q want=%q", got.Variable, "QUERY_STRING")
		}
		if got.Value != "<script>window.alert(document.cookie);</script>" {
			t.Fatalf("value=%q want payload", got.Value)
		}
	})

	t.Run("args outrank request headers host noise", func(t *testing.T) {
		got, ok := SelectPrimary([]waf.Match{
			{
				RuleID: 920350,
				MatchedData: []waf.MatchData{
					{Variable: "REQUEST_HEADERS", Key: "Host", Value: "127.0.0.1"},
				},
			},
			{
				RuleID: 941100,
				MatchedData: []waf.MatchData{
					{Variable: "QUERY_STRING", Value: "<script>window.alert(document.cookie);</script>"},
				},
			},
			{
				RuleID: 949110,
				MatchedData: []waf.MatchData{
					{Variable: "REQUEST_FILENAME", Value: "/"},
				},
			},
		}, 949110, 2048)
		if !ok {
			t.Fatal("expected primary match")
		}
		if got.Variable != "QUERY_STRING" {
			t.Fatalf("variable=%q want=%q", got.Variable, "QUERY_STRING")
		}
		if got.Value != "<script>window.alert(document.cookie);</script>" {
			t.Fatalf("value=%q want payload", got.Value)
		}
	})

	t.Run("request filename still wins when it is the only useful signal", func(t *testing.T) {
		got, ok := SelectPrimary([]waf.Match{
			{
				RuleID: 930120,
				MatchedData: []waf.MatchData{
					{Variable: "REQUEST_FILENAME", Value: "/etc/passwd"},
				},
			},
		}, 930120, 2048)
		if !ok {
			t.Fatal("expected primary match")
		}
		if got.Variable != "REQUEST_FILENAME" {
			t.Fatalf("variable=%q want=%q", got.Variable, "REQUEST_FILENAME")
		}
		if got.Value != "/etc/passwd" {
			t.Fatalf("value=%q want=/etc/passwd", got.Value)
		}
	})

	t.Run("falls back to first normalized match when values are empty", func(t *testing.T) {
		matches := []waf.Match{
			{
				RuleID: 942100,
				MatchedData: []waf.MatchData{
					{Variable: "QUERY_STRING", Key: "q", Value: ""},
					{Variable: "REQUEST_BODY", Key: "id", Value: ""},
				},
			},
		}

		got, ok := SelectPrimary(matches, 942100, 2048)
		if !ok {
			t.Fatal("expected fallback primary match")
		}
		if got.Variable != "QUERY_STRING:q" {
			t.Fatalf("variable=%q want=%q", got.Variable, "QUERY_STRING:q")
		}
		if got.Value != "" {
			t.Fatalf("value=%q want empty", got.Value)
		}
	})
}

func TestSelectPrimaryClampsValue(t *testing.T) {
	got, ok := SelectPrimary([]waf.Match{
		{
			RuleID: 941100,
			MatchedData: []waf.MatchData{
				{Variable: "QUERY_STRING", Value: "abcdef"},
			},
		},
	}, 941100, 3)
	if !ok {
		t.Fatal("expected primary match")
	}
	if got.Value != "abc" {
		t.Fatalf("value=%q want abc", got.Value)
	}
}
