package wafengine

import (
	"fmt"
	"strings"
)

const (
	ModeCoraza      = "coraza"
	ModeModSecurity = "mod_security"
	DefaultMode     = ModeCoraza
)

type Capability struct {
	Mode              string `json:"mode"`
	Label             string `json:"label"`
	Available         bool   `json:"available"`
	Default           bool   `json:"default"`
	RuntimeSwitchable bool   `json:"runtime_switchable"`
	Reason            string `json:"reason,omitempty"`
}

var catalog = []Capability{
	{
		Mode:              ModeCoraza,
		Label:             "Coraza",
		Available:         true,
		Default:           true,
		RuntimeSwitchable: false,
	},
	{
		Mode:              ModeModSecurity,
		Label:             "ModSecurity",
		Available:         false,
		Default:           false,
		RuntimeSwitchable: false,
		Reason:            "ModSecurity engine adapter is not compiled into this build.",
	},
}

func Normalize(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return DefaultMode
	}
	return mode
}

func Capabilities() []Capability {
	out := make([]Capability, len(catalog))
	copy(out, catalog)
	return out
}

func Lookup(mode string) (Capability, bool) {
	mode = Normalize(mode)
	for _, capability := range catalog {
		if capability.Mode == mode {
			return capability, true
		}
	}
	return Capability{}, false
}

func KnownModes() []string {
	out := make([]string, 0, len(catalog))
	for _, capability := range catalog {
		out = append(out, capability.Mode)
	}
	return out
}

func AvailableModes() []string {
	out := make([]string, 0, len(catalog))
	for _, capability := range catalog {
		if capability.Available {
			out = append(out, capability.Mode)
		}
	}
	return out
}

func ValidateConfiguredMode(mode string) error {
	capability, ok := Lookup(mode)
	if !ok {
		return fmt.Errorf("must be one of: %s", strings.Join(KnownModes(), ", "))
	}
	if !capability.Available {
		reason := strings.TrimSpace(capability.Reason)
		if reason == "" {
			reason = "engine is not available in this build"
		}
		return fmt.Errorf("%q is recognized but unavailable: %s", capability.Mode, reason)
	}
	return nil
}
