package proxyheaders

import (
	"net/http"
	"strings"
	"testing"
)

func TestNormalizeConfigCanonicalizesAndDedupesNames(t *testing.T) {
	cfg := NormalizeConfig(Config{
		Mode:         " AUTO ",
		CustomRemove: []string{" x-powered-by ", "Server", " server "},
		CustomKeep:   []string{" x-envoy-internal ", "Server", "x-envoy-internal"},
		DebugLog:     true,
	})
	if cfg.Mode != ModeAuto {
		t.Fatalf("mode=%q", cfg.Mode)
	}
	if got := strings.Join(cfg.CustomRemove, ","); got != "Server,X-Powered-By" {
		t.Fatalf("custom_remove=%q", got)
	}
	if got := strings.Join(cfg.CustomKeep, ","); got != "Server,X-Envoy-Internal" {
		t.Fatalf("custom_keep=%q", got)
	}
}

func TestBuildPolicyModes(t *testing.T) {
	autoPolicy := BuildPolicy(NormalizeConfig(Config{
		Mode:         ModeAuto,
		CustomKeep:   []string{"Server"},
		CustomRemove: []string{"X-Test-Leak"},
	}))
	if _, ok := autoPolicy.RemoveSet["Server"]; ok {
		t.Fatal("custom_keep should remove Server from auto mode default set")
	}
	if _, ok := autoPolicy.RemoveSet["X-Test-Leak"]; !ok {
		t.Fatal("custom_remove should be added in auto mode")
	}
	if _, ok := autoPolicy.RemoveSet["X-Powered-By"]; !ok {
		t.Fatal("embedded default set should be active in auto mode")
	}

	manualPolicy := BuildPolicy(NormalizeConfig(Config{
		Mode:         ModeManual,
		CustomKeep:   []string{"Server"},
		CustomRemove: []string{"X-Test-Leak"},
	}))
	if len(manualPolicy.RemoveSet) != 1 {
		t.Fatalf("manual remove count=%d want=1", len(manualPolicy.RemoveSet))
	}
	if _, ok := manualPolicy.RemoveSet["X-Test-Leak"]; !ok {
		t.Fatal("manual mode should remove custom_remove only")
	}
	if _, ok := manualPolicy.RemoveSet["X-Powered-By"]; ok {
		t.Fatal("manual mode should ignore embedded default set")
	}
}

func TestPlanKeepsHardSafetyForCacheSurfaces(t *testing.T) {
	offPolicy := BuildPolicy(NormalizeConfig(Config{Mode: ModeOff}))
	if Plan(SurfaceLive, offPolicy).NeedsHeaderIteration() {
		t.Fatal("live off mode without custom_remove should skip header iteration")
	}
	cachePlan := Plan(SurfaceCacheReplay, offPolicy)
	if !cachePlan.NeedsHeaderIteration() || !cachePlan.HardSafety {
		t.Fatalf("cache replay should keep hard safety enabled: %#v", cachePlan)
	}
}

func TestFilterHeadersCanonicalizesAndRemovesPolicyHeaders(t *testing.T) {
	filtered := FilterHeaders(http.Header{
		"server":       {"origin"},
		"content-type": {"text/plain"},
	}, Policy{
		Mode:      ModeAuto,
		RemoveSet: NameSet("Server"),
	}, FilterOptions{Surface: string(SurfaceLive)})

	if !filtered.Changed {
		t.Fatal("lowercase header key should force canonicalization")
	}
	if got := filtered.Header.Get("Server"); got != "" {
		t.Fatalf("Server=%q", got)
	}
	if got := filtered.Header.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type=%q", got)
	}
	if got := strings.Join(filtered.PolicyRemoved, ","); got != "Server" {
		t.Fatalf("removed=%q", got)
	}
}

func TestFilterHeadersNoopReusesHeaderMap(t *testing.T) {
	in := http.Header{
		"Content-Type": {"text/plain"},
		"X-App":        {"ok"},
	}
	filtered := FilterHeaders(in, Policy{
		Mode:      ModeAuto,
		RemoveSet: NameSet("Server", "X-Powered-By"),
	}, FilterOptions{Surface: string(SurfaceLive)})

	if filtered.Changed {
		t.Fatal("canonical header map without removals should use no-op fast path")
	}
	filtered.Header.Set("X-Reuse-Probe", "same-map")
	if got := in.Get("X-Reuse-Probe"); got != "same-map" {
		t.Fatalf("header map was cloned on no-op path, probe=%q", got)
	}
}
