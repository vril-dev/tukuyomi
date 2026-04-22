package handler

import (
	"fmt"
	"strings"
	"sync/atomic"
)

const (
	proxyAccessLogModeFull    = "full"
	proxyAccessLogModeMinimal = "minimal"
	proxyAccessLogModeOff     = "off"
)

const (
	proxyAccessLogModeCodeFull int32 = iota
	proxyAccessLogModeCodeMinimal
	proxyAccessLogModeCodeOff
)

var runtimeProxyAccessLogMode atomic.Int32

func normalizeProxyAccessLogMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", proxyAccessLogModeFull:
		return proxyAccessLogModeFull
	case proxyAccessLogModeMinimal:
		return proxyAccessLogModeMinimal
	case proxyAccessLogModeOff:
		return proxyAccessLogModeOff
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func validateProxyAccessLogMode(mode string) error {
	switch normalizeProxyAccessLogMode(mode) {
	case proxyAccessLogModeFull, proxyAccessLogModeMinimal, proxyAccessLogModeOff:
		return nil
	default:
		return fmt.Errorf("access_log_mode must be one of full|minimal|off")
	}
}

func setRuntimeProxyAccessLogMode(mode string) {
	switch normalizeProxyAccessLogMode(mode) {
	case proxyAccessLogModeMinimal:
		runtimeProxyAccessLogMode.Store(proxyAccessLogModeCodeMinimal)
	case proxyAccessLogModeOff:
		runtimeProxyAccessLogMode.Store(proxyAccessLogModeCodeOff)
	default:
		runtimeProxyAccessLogMode.Store(proxyAccessLogModeCodeFull)
	}
}

func currentProxyAccessLogMode() string {
	switch runtimeProxyAccessLogMode.Load() {
	case proxyAccessLogModeCodeMinimal:
		return proxyAccessLogModeMinimal
	case proxyAccessLogModeCodeOff:
		return proxyAccessLogModeOff
	default:
		return proxyAccessLogModeFull
	}
}
