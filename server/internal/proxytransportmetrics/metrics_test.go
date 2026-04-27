package proxytransportmetrics

import (
	"net/url"
	"testing"
	"time"
)

func TestMetricsRecordsAndSnapshotsSorted(t *testing.T) {
	metrics := New()
	a := mustURL(t, "http://a.example")
	b := mustURL(t, "http://b.example")

	metrics.RecordAttempt("b", b, true, 25*time.Millisecond)
	metrics.RecordError("b", b, true, ErrorKindStatus)
	metrics.RecordRetry("b", b, true, RetryReasonStatus)
	metrics.RecordPassiveFailure("b", b, true, PassiveFailureReasonStatus)
	metrics.RecordCircuitTransition("b", b, true, CircuitStateOpen)
	metrics.RecordAttempt("a", a, true, -time.Millisecond)

	snapshot := metrics.Snapshot()
	if len(snapshot.Upstreams) != 2 {
		t.Fatalf("upstreams=%d want=2", len(snapshot.Upstreams))
	}
	if snapshot.Upstreams[0].Upstream >= snapshot.Upstreams[1].Upstream {
		t.Fatalf("upstreams not sorted: %#v", snapshot.Upstreams)
	}
	var bSnapshot UpstreamSnapshot
	for _, upstream := range snapshot.Upstreams {
		if upstream.Upstream == UpstreamLabel("b", b, true) {
			bSnapshot = upstream
		}
	}
	if bSnapshot.RequestsTotal != 1 || bSnapshot.ErrorsStatusTotal != 1 || bSnapshot.RetriesStatusTotal != 1 || bSnapshot.PassiveFailuresStatusTotal != 1 || bSnapshot.CircuitOpenTransitionsTotal != 1 {
		t.Fatalf("unexpected b snapshot: %#v", bSnapshot)
	}
}

func TestMetricsActiveSetBoundsEntries(t *testing.T) {
	metrics := New()
	activeURL := mustURL(t, "http://active.example")
	inactiveURL := mustURL(t, "http://inactive.example")
	active := UpstreamLabel("active", activeURL, true)

	metrics.SyncUpstreams([]string{active})
	metrics.RecordAttempt("inactive", inactiveURL, true, time.Millisecond)
	if got := len(metrics.Snapshot().Upstreams); got != 0 {
		t.Fatalf("inactive upstreams=%d want=0", got)
	}
	metrics.RecordAttempt("active", activeURL, true, time.Millisecond)
	if got := len(metrics.Snapshot().Upstreams); got != 1 {
		t.Fatalf("active upstreams=%d want=1", got)
	}
	metrics.ResetUpstreams(nil)
	if got := len(metrics.Snapshot().Upstreams); got != 0 {
		t.Fatalf("reset upstreams=%d want=0", got)
	}
}

func TestUpstreamLabel(t *testing.T) {
	target := mustURL(t, "http://backend.internal/v1")
	managed := UpstreamLabel("Primary Backend", target, true)
	if managed != "primary-backend--ae269abef70f1f63" {
		t.Fatalf("managed label=%q", managed)
	}
	if direct := UpstreamLabel("ignored", target, false); direct != "http://backend.internal/v1" {
		t.Fatalf("direct label=%q", direct)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	return u
}
