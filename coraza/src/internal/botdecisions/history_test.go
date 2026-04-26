package botdecisions

import "testing"

func TestHistoryKeepsMostRecentFirst(t *testing.T) {
	history := NewHistory(10)
	history.Add(Record{RequestID: "req-1"})
	history.Add(Record{RequestID: "req-2", Action: "challenge", Signals: []string{"risk"}})

	items := history.Recent(10)
	if len(items) != 2 {
		t.Fatalf("items=%d want 2", len(items))
	}
	if items[0].RequestID != "req-2" || items[0].Action != "challenge" {
		t.Fatalf("latest mismatch: %#v", items[0])
	}
	if items[1].Action != "allow" {
		t.Fatalf("empty action should normalize to allow: %#v", items[1])
	}
}

func TestHistoryCapsRecordsAndClones(t *testing.T) {
	history := NewHistory(2)
	signals := []string{"a"}
	history.Add(Record{RequestID: "req-1"})
	history.Add(Record{RequestID: "req-2", Signals: signals})
	signals[0] = "mutated"
	history.Add(Record{RequestID: "req-3"})

	items := history.Recent(10)
	if len(items) != 2 {
		t.Fatalf("items=%d want cap 2", len(items))
	}
	if items[1].RequestID != "req-2" {
		t.Fatalf("oldest retained=%q want req-2", items[1].RequestID)
	}
	if items[1].Signals[0] != "a" {
		t.Fatalf("signals were not cloned: %#v", items[1].Signals)
	}

	items[1].Signals[0] = "mutated-again"
	latest, ok := history.Latest()
	if !ok {
		t.Fatal("expected latest")
	}
	if latest.RequestID != "req-3" {
		t.Fatalf("latest=%q want req-3", latest.RequestID)
	}
	if got := history.Recent(10)[1].Signals[0]; got != "a" {
		t.Fatalf("stored signals mutated through Recent: %q", got)
	}
}
