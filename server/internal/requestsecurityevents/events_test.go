package requestsecurityevents

import "testing"

func TestBusPublishesInOrderAndClones(t *testing.T) {
	stats := NewStats()
	bus := NewBus(stats)

	attrs := map[string]any{"risk": 7}
	observed := 0
	bus.Subscribe(func(evt Event) {
		observed++
		if evt.Attributes != nil {
			evt.Attributes["risk"] = 99
		}
	})

	first := bus.Publish(Event{ReqID: "req-1", EventType: TypeSemanticAnomaly, Attributes: attrs})
	attrs["risk"] = 8
	second := bus.Publish(Event{ReqID: "req-1", EventType: TypeRateLimited})

	if first.Sequence != 1 || second.Sequence != 2 {
		t.Fatalf("sequences=%d/%d", first.Sequence, second.Sequence)
	}
	if first.EventID == "" || second.EventID == "" || first.EventID == second.EventID {
		t.Fatalf("event ids not generated distinctly: %q %q", first.EventID, second.EventID)
	}
	if observed != 2 {
		t.Fatalf("observed=%d want=2", observed)
	}
	events := bus.Events()
	if len(events) != 2 || events[0].Attributes["risk"] != 7 {
		t.Fatalf("stored events=%#v", events)
	}
	events[0].Attributes["risk"] = 42
	if got := bus.Events()[0].Attributes["risk"]; got != 7 {
		t.Fatalf("event clone leaked mutation: %v", got)
	}
	if snapshot := stats.Snapshot(); snapshot.PublishedTotal != 2 {
		t.Fatalf("published=%d want=2", snapshot.PublishedTotal)
	}
}

func TestStatsRestore(t *testing.T) {
	stats := NewStats()
	stats.AddBotChallengeFailure()
	stats.AddBotChallengePenalty()
	stats.AddRateLimitPromotion()
	stats.AddRateLimitPromotionDryRun()
	snapshot := stats.Snapshot()
	if snapshot.BotChallengeFailuresTotal != 1 || snapshot.RateLimitPromotionDryRunTotal != 1 {
		t.Fatalf("snapshot=%#v", snapshot)
	}
	stats.Restore(StatsSnapshot{PublishedTotal: 3})
	if got := stats.Snapshot(); got.PublishedTotal != 3 || got.BotChallengeFailuresTotal != 0 {
		t.Fatalf("restored=%#v", got)
	}
}
