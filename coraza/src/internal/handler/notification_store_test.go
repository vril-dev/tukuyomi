package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNotificationManagerTransitions(t *testing.T) {
	var (
		mu      sync.Mutex
		states  []string
		sources []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode webhook body: %v", err)
		}
		mu.Lock()
		states = append(states, stringValue(body["state"]))
		sources = append(sources, stringValue(body["source"]))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mgr := newNotificationManager("test")
	mgr.Update(notificationConfig{
		Enabled:         true,
		CooldownSeconds: 0,
		Sinks: []notificationSinkConfig{
			{
				Name:       "webhook",
				Type:       notificationSinkTypeWebhook,
				Enabled:    true,
				WebhookURL: srv.URL,
				TimeoutSec: 5,
			},
		},
		Upstream: notificationTriggerConfig{
			Enabled:            true,
			WindowSeconds:      1,
			ActiveThreshold:    1,
			EscalatedThreshold: 2,
		},
		Security: notificationSecurityTrigger{
			Enabled:            true,
			WindowSeconds:      1,
			ActiveThreshold:    1,
			EscalatedThreshold: 2,
			Sources:            []string{"rate_limited"},
		},
	})

	start := time.Unix(1700000000, 0).UTC()
	mgr.Observe(notificationObservation{
		Category:   notificationCategorySecurity,
		Source:     "rate_limited",
		Path:       "/login",
		RemoteIP:   "203.0.113.10",
		ObservedAt: start,
	})
	mgr.flushExpired(start.Add(1100 * time.Millisecond))

	mgr.Observe(notificationObservation{
		Category:   notificationCategorySecurity,
		Source:     "rate_limited",
		Path:       "/login",
		RemoteIP:   "203.0.113.10",
		ObservedAt: start.Add(1200 * time.Millisecond),
	})
	mgr.Observe(notificationObservation{
		Category:   notificationCategorySecurity,
		Source:     "rate_limited",
		Path:       "/login",
		RemoteIP:   "203.0.113.11",
		ObservedAt: start.Add(1400 * time.Millisecond),
	})
	mgr.flushExpired(start.Add(2200 * time.Millisecond))
	mgr.flushExpired(start.Add(3200 * time.Millisecond))

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		got := append([]string(nil), states...)
		src := append([]string(nil), sources...)
		mu.Unlock()
		if len(got) >= 3 {
			wantCounts := map[string]int{
				notificationStateActive:    1,
				notificationStateEscalated: 1,
				notificationStateQuiet:     1,
			}
			gotCounts := map[string]int{}
			for i := range got {
				gotCounts[got[i]]++
				if src[i] != "rate_limited" {
					t.Fatalf("sources[%d]=%q want=rate_limited all=%v", i, src[i], src)
				}
			}
			for state, want := range wantCounts {
				if gotCounts[state] < want {
					t.Fatalf("missing state %q counts=%v all=%v", state, gotCounts, got)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for webhook notifications, got=%v", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
