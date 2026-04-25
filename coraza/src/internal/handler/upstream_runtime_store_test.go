package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"tukuyomi/internal/config"
)

func TestParseUpstreamRuntimeRawValidatesAdminStateAndWeight(t *testing.T) {
	primaryKey := proxyBackendLookupKey("primary", "http://127.0.0.1:8080")
	_, err := ParseUpstreamRuntimeRaw(fmt.Sprintf(`{
  "version": "v1",
  "backends": {
    %q: {
      "admin_state": "paused"
    }
  }
}`, primaryKey))
	if err == nil {
		t.Fatal("expected invalid admin_state error")
	}

	_, err = ParseUpstreamRuntimeRaw(fmt.Sprintf(`{
  "version": "v1",
  "backends": {
    %q: {
      "weight_override": 0
    }
  }
}`, primaryKey))
	if err == nil {
		t.Fatal("expected invalid weight_override error")
	}
}

func TestLoadUpstreamRuntimeFilePrunesUnknownBackends(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "conf", "upstream-runtime.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	primaryKey := proxyBackendLookupKey("primary", "http://127.0.0.1:8080")
	staleKey := proxyBackendLookupKey("stale", "http://127.0.0.1:9090")
	raw := fmt.Sprintf(`{
  "version": "v1",
  "backends": {
    %q: {
      "admin_state": "draining"
    },
    %q: {
      "admin_state": "disabled"
    }
  }
}
`, primaryKey, staleKey)
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	file, err := LoadUpstreamRuntimeFile(path, map[string]struct{}{
		primaryKey: {},
	})
	if err != nil {
		t.Fatalf("LoadUpstreamRuntimeFile: %v", err)
	}
	if got := len(file.Backends); got != 1 {
		t.Fatalf("backends=%d want=1", got)
	}
	if _, ok := file.Backends[staleKey]; ok {
		t.Fatal("stale backend override should be pruned")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(after) == raw {
		t.Fatal("expected pruned runtime file to be persisted")
	}
}

func TestBuildProxyBackendStatesAppliesRuntimeOverrides(t *testing.T) {
	tmp := t.TempDir()
	oldPath := config.UpstreamRuntimeFile
	config.UpstreamRuntimeFile = filepath.Join(tmp, "conf", "upstream-runtime.json")
	defer func() {
		config.UpstreamRuntimeFile = oldPath
	}()

	primaryKey := proxyBackendLookupKey("primary", "http://127.0.0.1:8080")
	overrideRaw := fmt.Sprintf(`{
  "version": "v1",
  "backends": {
    %q: {
      "admin_state": "draining",
      "weight_override": 7
    }
  }
}
`, primaryKey)
	if err := os.MkdirAll(filepath.Dir(config.UpstreamRuntimeFile), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(config.UpstreamRuntimeFile, []byte(overrideRaw), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 2, "enabled": true },
    { "name": "secondary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ]
}`)

	backends, err := buildProxyBackendStates(cfg, nil)
	if err != nil {
		t.Fatalf("buildProxyBackendStates: %v", err)
	}
	if len(backends) != 2 {
		t.Fatalf("len(backends)=%d want=2", len(backends))
	}
	if got := backends[0].AdminState; got != upstreamAdminStateDraining {
		t.Fatalf("primary admin_state=%q want=%q", got, upstreamAdminStateDraining)
	}
	if backends[0].WeightOverride == nil || *backends[0].WeightOverride != 7 {
		t.Fatalf("primary weight_override=%v want=7", backends[0].WeightOverride)
	}
	if got := backends[0].EffectiveWeight; got != 7 {
		t.Fatalf("primary effective_weight=%d want=7", got)
	}
	if got := backends[1].AdminState; got != upstreamAdminStateEnabled {
		t.Fatalf("secondary admin_state=%q want=%q", got, upstreamAdminStateEnabled)
	}
	if backends[1].WeightOverride != nil {
		t.Fatalf("secondary weight_override=%v want=nil", backends[1].WeightOverride)
	}
	if got := backends[1].EffectiveWeight; got != 1 {
		t.Fatalf("secondary effective_weight=%d want=1", got)
	}
}

func TestBuildProxyBackendStatesLoadsRuntimeOverridesFromDB(t *testing.T) {
	tmp := t.TempDir()
	store := initConfigDBStoreForTest(t)

	oldPath := config.UpstreamRuntimeFile
	config.UpstreamRuntimeFile = filepath.Join(tmp, "conf", "upstream-runtime.json")
	defer func() {
		config.UpstreamRuntimeFile = oldPath
	}()

	primaryKey := proxyBackendLookupKey("primary", "http://127.0.0.1:8080")
	overrideRaw := fmt.Sprintf(`{
  "version": "v1",
	"backends": {
    %q: {
      "admin_state": "disabled",
      "weight_override": 5
    }
  }
}
`, primaryKey)
	runtimeFile, err := ParseUpstreamRuntimeRaw(overrideRaw)
	if err != nil {
		t.Fatalf("ParseUpstreamRuntimeRaw: %v", err)
	}
	if _, _, err := store.writeUpstreamRuntimeConfigVersion("", runtimeFile, nil, configVersionSourceImport, "", "test upstream runtime import", 0); err != nil {
		t.Fatalf("writeUpstreamRuntimeConfigVersion: %v", err)
	}

	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 2, "enabled": true }
  ]
}`)

	backends, err := buildProxyBackendStates(cfg, nil)
	if err != nil {
		t.Fatalf("buildProxyBackendStates: %v", err)
	}
	if len(backends) != 1 {
		t.Fatalf("len(backends)=%d want=1", len(backends))
	}
	if got := backends[0].AdminState; got != upstreamAdminStateDisabled {
		t.Fatalf("admin_state=%q want=%q", got, upstreamAdminStateDisabled)
	}
	if backends[0].WeightOverride == nil || *backends[0].WeightOverride != 5 {
		t.Fatalf("weight_override=%v want=5", backends[0].WeightOverride)
	}
	if _, err := os.Stat(config.UpstreamRuntimeFile); !os.IsNotExist(err) {
		t.Fatalf("upstream runtime file should not be restored, stat err=%v", err)
	}
}

func TestOrderProxyRouteCandidatesSkipsDrainingManagedBackend(t *testing.T) {
	tmp := t.TempDir()
	oldPath := config.UpstreamRuntimeFile
	config.UpstreamRuntimeFile = filepath.Join(tmp, "conf", "upstream-runtime.json")
	defer func() {
		config.UpstreamRuntimeFile = oldPath
	}()

	overrideRaw := fmt.Sprintf(`{
  "version": "v1",
  "backends": {
    %q: {
      "admin_state": "draining"
    }
  }
}
`, proxyBackendLookupKey("primary", "http://127.0.0.1:8080"))
	if err := os.MkdirAll(filepath.Dir(config.UpstreamRuntimeFile), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(config.UpstreamRuntimeFile, []byte(overrideRaw), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true },
    { "name": "secondary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ]
}`)

	tracker := newUpstreamHealthMonitorForTest(t, cfg)
	candidates := []proxyRouteTargetCandidate{
		{
			Key:     proxyBackendLookupKey("primary", "http://127.0.0.1:8080"),
			Name:    "primary",
			Target:  mustURL("http://127.0.0.1:8080"),
			Weight:  1,
			Managed: true,
		},
		{
			Key:     proxyBackendLookupKey("secondary", "http://127.0.0.1:8081"),
			Name:    "secondary",
			Target:  mustURL("http://127.0.0.1:8081"),
			Weight:  1,
			Managed: true,
		},
	}
	ordered := orderProxyRouteCandidates(nil, candidates, proxyRouteTargetSelectionOptions{}, tracker)
	if len(ordered) != 1 {
		t.Fatalf("len(ordered)=%d want=1", len(ordered))
	}
	if ordered[0].Name != "secondary" {
		t.Fatalf("selected=%q want=secondary", ordered[0].Name)
	}
}

func TestOrderProxyRouteCandidatesFailsClosedWhenNoManagedBackendSelectable(t *testing.T) {
	tmp := t.TempDir()
	oldPath := config.UpstreamRuntimeFile
	config.UpstreamRuntimeFile = filepath.Join(tmp, "conf", "upstream-runtime.json")
	defer func() {
		config.UpstreamRuntimeFile = oldPath
	}()

	overrideRaw := fmt.Sprintf(`{
  "version": "v1",
  "backends": {
    %q: {
      "admin_state": "disabled"
    },
    %q: {
      "admin_state": "draining"
    }
  }
}
`, proxyBackendLookupKey("primary", "http://127.0.0.1:8080"), proxyBackendLookupKey("secondary", "http://127.0.0.1:8081"))
	if err := os.MkdirAll(filepath.Dir(config.UpstreamRuntimeFile), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(config.UpstreamRuntimeFile, []byte(overrideRaw), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true },
    { "name": "secondary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ]
}`)

	tracker := newUpstreamHealthMonitorForTest(t, cfg)
	candidates := []proxyRouteTargetCandidate{
		{
			Key:     proxyBackendLookupKey("primary", "http://127.0.0.1:8080"),
			Name:    "primary",
			Target:  mustURL("http://127.0.0.1:8080"),
			Weight:  1,
			Managed: true,
		},
		{
			Key:     proxyBackendLookupKey("secondary", "http://127.0.0.1:8081"),
			Name:    "secondary",
			Target:  mustURL("http://127.0.0.1:8081"),
			Weight:  1,
			Managed: true,
		},
	}
	ordered := orderProxyRouteCandidates(nil, candidates, proxyRouteTargetSelectionOptions{}, tracker)
	if len(ordered) != 0 {
		t.Fatalf("len(ordered)=%d want=0", len(ordered))
	}
}

func TestUpstreamHealthMonitorSelectTargetUsesWeightOverride(t *testing.T) {
	tmp := t.TempDir()
	oldPath := config.UpstreamRuntimeFile
	config.UpstreamRuntimeFile = filepath.Join(tmp, "conf", "upstream-runtime.json")
	defer func() {
		config.UpstreamRuntimeFile = oldPath
	}()

	overrideRaw := fmt.Sprintf(`{
  "version": "v1",
  "backends": {
    %q: {
      "weight_override": 3
    }
  }
}
`, proxyBackendLookupKey("primary", "http://127.0.0.1:8080"))
	if err := os.MkdirAll(filepath.Dir(config.UpstreamRuntimeFile), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(config.UpstreamRuntimeFile, []byte(overrideRaw), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true },
    { "name": "secondary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ]
}`)

	tracker := newUpstreamHealthMonitorForTest(t, cfg)
	var got []string
	for range 4 {
		selection, ok := tracker.SelectTarget()
		if !ok {
			t.Fatal("SelectTarget returned false")
		}
		got = append(got, selection.Name)
		tracker.ReleaseTarget(selection.Key)
	}
	want := []string{"primary", "primary", "primary", "secondary"}
	if !slices.Equal(got, want) {
		t.Fatalf("selections=%v want=%v", got, want)
	}
}
