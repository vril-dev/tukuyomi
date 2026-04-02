package handler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateIPReputationRawRejectsInvalidCIDR(t *testing.T) {
	t.Parallel()

	_, err := ValidateIPReputationRaw(`{
  "enabled": true,
  "allowlist": ["not-a-cidr"]
}`)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestIPReputationAllowOverridesBlock(t *testing.T) {
	t.Parallel()

	store, err := newIPReputationStore(ipReputationConfig{
		Enabled:            true,
		Allowlist:          []string{"203.0.113.10/32"},
		Blocklist:          []string{"203.0.113.0/24"},
		RefreshIntervalSec: 900,
		RequestTimeoutSec:  5,
		BlockStatusCode:    403,
		FailOpen:           true,
	})
	if err != nil {
		t.Fatalf("newIPReputationStore: %v", err)
	}
	defer store.Close()

	if store.IsBlocked("203.0.113.10") {
		t.Fatal("allowlisted IP should not be blocked")
	}
	if !store.IsBlocked("203.0.113.11") {
		t.Fatal("blocklisted IP should be blocked")
	}
}

func TestIPReputationLoadFeedParsesAllowAndBlockLines(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	feedPath := filepath.Join(tmp, "feed.txt")
	raw := "" +
		"# comment\n" +
		"allow 198.51.100.1/32\n" +
		"deny 203.0.113.0/24\n" +
		"! 2001:db8::1\n"
	if err := os.WriteFile(feedPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write feed: %v", err)
	}

	store, err := newIPReputationStore(ipReputationConfig{
		Enabled:            true,
		FeedURLs:           []string{feedPath},
		RefreshIntervalSec: 900,
		RequestTimeoutSec:  5,
		BlockStatusCode:    403,
		FailOpen:           true,
	})
	if err != nil {
		t.Fatalf("newIPReputationStore: %v", err)
	}
	defer store.Close()

	if store.IsBlocked("198.51.100.1") {
		t.Fatal("feed allow entry should not be blocked")
	}
	if !store.IsBlocked("203.0.113.10") {
		t.Fatal("feed deny entry should be blocked")
	}
	if store.IsBlocked("2001:db8::1") {
		t.Fatal("feed allow entry with bang prefix should not be blocked")
	}
}
