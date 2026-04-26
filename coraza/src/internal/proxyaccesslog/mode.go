package proxyaccesslog

import (
	"fmt"
	"strings"
	"sync/atomic"
)

const (
	ModeFull    = "full"
	ModeMinimal = "minimal"
	ModeOff     = "off"
)

const (
	modeCodeFull int32 = iota
	modeCodeMinimal
	modeCodeOff
)

var runtimeMode atomic.Int32

func NormalizeMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", ModeFull:
		return ModeFull
	case ModeMinimal:
		return ModeMinimal
	case ModeOff:
		return ModeOff
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func ValidateMode(mode string) error {
	switch NormalizeMode(mode) {
	case ModeFull, ModeMinimal, ModeOff:
		return nil
	default:
		return fmt.Errorf("access_log_mode must be one of full|minimal|off")
	}
}

func SetRuntimeMode(mode string) {
	switch NormalizeMode(mode) {
	case ModeMinimal:
		runtimeMode.Store(modeCodeMinimal)
	case ModeOff:
		runtimeMode.Store(modeCodeOff)
	default:
		runtimeMode.Store(modeCodeFull)
	}
}

func CurrentRuntimeMode() string {
	switch runtimeMode.Load() {
	case modeCodeMinimal:
		return ModeMinimal
	case modeCodeOff:
		return ModeOff
	default:
		return ModeFull
	}
}
