package handler

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestIPReputationStoreApplyPenaltyExpires(t *testing.T) {
	store, err := newIPReputationStore(ipReputationConfig{
		Enabled:            true,
		BlockStatusCode:    403,
		RefreshIntervalSec: 60,
		RequestTimeoutSec:  5,
	})
	if err != nil {
		t.Fatalf("newIPReputationStore() unexpected error: %v", err)
	}

	now := time.Unix(1_700_100_000, 0).UTC()
	if ok := store.ApplyPenalty("203.0.113.10", 2*time.Minute, now); !ok {
		t.Fatal("expected dynamic penalty to be applied")
	}
	if !store.isBlockedAt("203.0.113.10", now.Add(time.Minute)) {
		t.Fatal("penalized IP should be blocked before TTL expires")
	}
	if store.isBlockedAt("203.0.113.10", now.Add(3*time.Minute)) {
		t.Fatal("penalized IP should not remain blocked after TTL expires")
	}
}

func TestIPReputationStoreApplyPenaltyRespectsAllowlist(t *testing.T) {
	store, err := newIPReputationStore(ipReputationConfig{
		Enabled:            true,
		Allowlist:          []string{"203.0.113.11/32"},
		BlockStatusCode:    403,
		RefreshIntervalSec: 60,
		RequestTimeoutSec:  5,
	})
	if err != nil {
		t.Fatalf("newIPReputationStore() unexpected error: %v", err)
	}

	now := time.Unix(1_700_100_100, 0).UTC()
	if ok := store.ApplyPenalty("203.0.113.11", 5*time.Minute, now); ok {
		t.Fatal("allowlisted IP should not receive dynamic penalty")
	}
	if store.isBlockedAt("203.0.113.11", now.Add(time.Minute)) {
		t.Fatal("allowlisted IP should never be blocked by dynamic penalty")
	}
}

func TestEvaluateIPReputationForHost_UsesHostScopePrecedence(t *testing.T) {
	restore := saveIPReputationStateForTest()
	defer restore()

	rt, err := ValidateIPReputationRaw(`{
  "default": {
    "enabled": true,
    "blocklist": ["203.0.113.10"],
    "block_status_code": 451
  },
  "hosts": {
    "admin.example.com": {
      "blocklist": ["203.0.113.11"],
      "block_status_code": 452
    },
    "admin.example.com:8443": {
      "blocklist": ["203.0.113.12"],
      "block_status_code": 453
    }
  }
}`)
	if err != nil {
		t.Fatalf("ValidateIPReputationRaw() unexpected error: %v", err)
	}

	ipReputationMu.Lock()
	ipReputationRuntime = &rt
	ipReputationStoreRT = rt.Default.Store
	ipReputationMu.Unlock()

	blocked, status, scope := EvaluateIPReputationForHost("admin.example.com:8443", true, "203.0.113.12")
	if !blocked || status != 453 || scope != "admin.example.com:8443" {
		t.Fatalf("port-specific scope mismatch: blocked=%v status=%d scope=%q", blocked, status, scope)
	}

	blocked, status, scope = EvaluateIPReputationForHost("admin.example.com:443", true, "203.0.113.11")
	if !blocked || status != 452 || scope != "admin.example.com" {
		t.Fatalf("host scope mismatch: blocked=%v status=%d scope=%q", blocked, status, scope)
	}

	blocked, status, scope = EvaluateIPReputationForHost("www.example.com", true, "203.0.113.10")
	if !blocked || status != 451 || scope != ipReputationDefaultScope {
		t.Fatalf("default scope mismatch: blocked=%v status=%d scope=%q", blocked, status, scope)
	}
}

func TestApplyIPReputationPenaltyForScope_IsolatesDynamicPenalties(t *testing.T) {
	restore := saveIPReputationStateForTest()
	defer restore()

	rt, err := ValidateIPReputationRaw(`{
  "default": {
    "enabled": false
  },
  "hosts": {
    "one.example.com": {
      "enabled": true,
      "block_status_code": 451
    },
    "two.example.com": {
      "enabled": true,
      "block_status_code": 452
    }
  }
}`)
	if err != nil {
		t.Fatalf("ValidateIPReputationRaw() unexpected error: %v", err)
	}

	ipReputationMu.Lock()
	ipReputationRuntime = &rt
	ipReputationStoreRT = rt.Default.Store
	ipReputationMu.Unlock()

	now := time.Now().UTC()
	clientIP := "203.0.113.25"
	if ok := ApplyIPReputationPenaltyForScope("one.example.com", clientIP, 2*time.Minute, now); !ok {
		t.Fatal("expected host-scoped penalty to be applied")
	}

	blocked, status, scope := EvaluateIPReputationForHost("one.example.com", true, clientIP)
	if !blocked || status != http.StatusUnavailableForLegalReasons || scope != "one.example.com" {
		t.Fatalf("penalized host mismatch: blocked=%v status=%d scope=%q", blocked, status, scope)
	}

	if blocked, _, _ := EvaluateIPReputationForHost("two.example.com", true, clientIP); blocked {
		t.Fatal("penalty should not leak into another host scope")
	}
	if blocked, _, _ := EvaluateIPReputationForHost("www.example.com", true, clientIP); blocked {
		t.Fatal("penalty should not leak into default scope")
	}

	if snapshot := IPReputationStatusForHost("one.example.com", true); snapshot.DynamicPenaltyCount != 1 {
		t.Fatalf("host scope dynamic penalty count=%d want=1", snapshot.DynamicPenaltyCount)
	}
	if snapshot := IPReputationStatusForHost("two.example.com", true); snapshot.DynamicPenaltyCount != 0 {
		t.Fatalf("other host dynamic penalty count=%d want=0", snapshot.DynamicPenaltyCount)
	}
}

func TestEvaluateIPReputationForHost_FailClosedOnFeedErrorsBlocksByDefault(t *testing.T) {
	restore := saveIPReputationStateForTest()
	defer restore()

	missingFeed := filepath.Join(t.TempDir(), "missing-feed.txt")
	rt, err := ValidateIPReputationRaw(`{
  "default": {
    "enabled": true,
    "feed_urls": ["` + missingFeed + `"],
    "allowlist": ["203.0.113.11/32"],
    "block_status_code": 451,
    "fail_open": false
  }
}`)
	if err != nil {
		t.Fatalf("ValidateIPReputationRaw() unexpected error: %v", err)
	}

	ipReputationMu.Lock()
	ipReputationRuntime = &rt
	ipReputationStoreRT = rt.Default.Store
	ipReputationMu.Unlock()

	blocked, status, scope := EvaluateIPReputationForHost("www.example.com", true, "203.0.113.10")
	if !blocked || status != 451 || scope != ipReputationDefaultScope {
		t.Fatalf("fail-closed scope mismatch: blocked=%v status=%d scope=%q", blocked, status, scope)
	}

	if blocked, _, _ := EvaluateIPReputationForHost("www.example.com", true, "203.0.113.11"); blocked {
		t.Fatal("explicit allowlist should still pass during fail-closed feed outage")
	}

	if snapshot := IPReputationStatus(); snapshot.LastRefreshError == "" {
		t.Fatal("expected refresh error snapshot during fail-closed feed outage")
	}
}

func TestEvaluateIPReputationForHost_FailOpenOnFeedErrorsUsesLocalListsOnly(t *testing.T) {
	restore := saveIPReputationStateForTest()
	defer restore()

	missingFeed := filepath.Join(t.TempDir(), "missing-feed.txt")
	rt, err := ValidateIPReputationRaw(`{
  "default": {
    "enabled": true,
    "feed_urls": ["` + missingFeed + `"],
    "blocklist": ["203.0.113.12/32"],
    "block_status_code": 451,
    "fail_open": true
  }
}`)
	if err != nil {
		t.Fatalf("ValidateIPReputationRaw() unexpected error: %v", err)
	}

	ipReputationMu.Lock()
	ipReputationRuntime = &rt
	ipReputationStoreRT = rt.Default.Store
	ipReputationMu.Unlock()

	if blocked, _, _ := EvaluateIPReputationForHost("www.example.com", true, "203.0.113.10"); blocked {
		t.Fatal("feed outage with fail-open should not deny by default")
	}

	blocked, status, scope := EvaluateIPReputationForHost("www.example.com", true, "203.0.113.12")
	if !blocked || status != 451 || scope != ipReputationDefaultScope {
		t.Fatalf("local blocklist should still apply during fail-open outage: blocked=%v status=%d scope=%q", blocked, status, scope)
	}
}
