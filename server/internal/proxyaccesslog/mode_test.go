package proxyaccesslog

import "testing"

func TestNormalizeMode(t *testing.T) {
	cases := map[string]string{
		"":         ModeFull,
		" FULL ":   ModeFull,
		"minimal":  ModeMinimal,
		" OFF ":    ModeOff,
		"expanded": "expanded",
	}
	for raw, want := range cases {
		if got := NormalizeMode(raw); got != want {
			t.Fatalf("NormalizeMode(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestRuntimeMode(t *testing.T) {
	SetRuntimeMode(ModeMinimal)
	if got := CurrentRuntimeMode(); got != ModeMinimal {
		t.Fatalf("mode=%q want %q", got, ModeMinimal)
	}
	SetRuntimeMode(ModeOff)
	if got := CurrentRuntimeMode(); got != ModeOff {
		t.Fatalf("mode=%q want %q", got, ModeOff)
	}
	SetRuntimeMode("")
	if got := CurrentRuntimeMode(); got != ModeFull {
		t.Fatalf("mode=%q want %q", got, ModeFull)
	}
}
