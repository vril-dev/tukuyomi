package handler

import (
	"strings"
	"sync"
	"time"

	"tukuyomi/internal/config"
)

type serverTLSRuntimeStatus struct {
	Enabled          bool   `json:"enabled"`
	Source           string `json:"source"`
	CertNotAfter     string `json:"cert_not_after,omitempty"`
	LastError        string `json:"last_error,omitempty"`
	ACMESuccessTotal uint64 `json:"acme_success_total"`
	ACMEFailureTotal uint64 `json:"acme_failure_total"`
}

var (
	serverTLSRuntimeMu sync.RWMutex
	serverTLSRuntime   serverTLSRuntimeStatus
	serverTLSReload    func(SiteConfigFile, []SiteRuntimeStatus) error
)

func SetServerTLSRuntimeStatus(status serverTLSRuntimeStatus) {
	serverTLSRuntimeMu.Lock()
	serverTLSRuntime = status
	serverTLSRuntimeMu.Unlock()
}

func ServerTLSRuntimeStatusSnapshot() serverTLSRuntimeStatus {
	serverTLSRuntimeMu.RLock()
	defer serverTLSRuntimeMu.RUnlock()
	return serverTLSRuntime
}

func ResetServerTLSRuntimeStatus() {
	SetServerTLSRuntimeStatus(serverTLSRuntimeStatus{})
}

func SetServerTLSReloadHook(fn func(SiteConfigFile, []SiteRuntimeStatus) error) {
	serverTLSRuntimeMu.Lock()
	serverTLSReload = fn
	serverTLSRuntimeMu.Unlock()
}

func ReloadServerTLSRuntimeForSites(sites SiteConfigFile, statuses []SiteRuntimeStatus) error {
	if !config.ServerTLSEnabled {
		return nil
	}
	serverTLSRuntimeMu.RLock()
	fn := serverTLSReload
	serverTLSRuntimeMu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(cloneSiteConfigFile(sites), cloneSiteRuntimeStatuses(statuses))
}

func RecordServerTLSConfigured(source string, certNotAfter time.Time) {
	serverTLSRuntimeMu.Lock()
	defer serverTLSRuntimeMu.Unlock()
	serverTLSRuntime.Enabled = true
	serverTLSRuntime.Source = strings.TrimSpace(source)
	if !certNotAfter.IsZero() {
		serverTLSRuntime.CertNotAfter = certNotAfter.UTC().Format(time.RFC3339Nano)
	}
	serverTLSRuntime.LastError = ""
}

func RecordServerTLSError(err error) {
	serverTLSRuntimeMu.Lock()
	defer serverTLSRuntimeMu.Unlock()
	if err == nil {
		serverTLSRuntime.LastError = ""
		return
	}
	serverTLSRuntime.LastError = strings.TrimSpace(err.Error())
}

func RecordServerTLSACMESuccess(certNotAfter time.Time) {
	serverTLSRuntimeMu.Lock()
	defer serverTLSRuntimeMu.Unlock()
	serverTLSRuntime.Enabled = true
	serverTLSRuntime.Source = "acme"
	serverTLSRuntime.ACMESuccessTotal++
	serverTLSRuntime.LastError = ""
	if !certNotAfter.IsZero() {
		serverTLSRuntime.CertNotAfter = certNotAfter.UTC().Format(time.RFC3339Nano)
	}
}

func RecordServerTLSACMEFailure(err error) {
	serverTLSRuntimeMu.Lock()
	defer serverTLSRuntimeMu.Unlock()
	serverTLSRuntime.Enabled = true
	serverTLSRuntime.Source = "acme"
	serverTLSRuntime.ACMEFailureTotal++
	if err != nil {
		serverTLSRuntime.LastError = strings.TrimSpace(err.Error())
	}
}
