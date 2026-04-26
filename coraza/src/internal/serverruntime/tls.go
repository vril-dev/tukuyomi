package serverruntime

import (
	"strings"
	"sync"
	"time"
)

type TLSStatus struct {
	Enabled          bool   `json:"enabled"`
	Source           string `json:"source"`
	CertNotAfter     string `json:"cert_not_after,omitempty"`
	LastError        string `json:"last_error,omitempty"`
	ACMESuccessTotal uint64 `json:"acme_success_total"`
	ACMEFailureTotal uint64 `json:"acme_failure_total"`
}

var (
	tlsMu     sync.RWMutex
	tlsStatus TLSStatus
)

func SetTLSStatus(status TLSStatus) {
	tlsMu.Lock()
	tlsStatus = status
	tlsMu.Unlock()
}

func TLSStatusSnapshot() TLSStatus {
	tlsMu.RLock()
	defer tlsMu.RUnlock()
	return tlsStatus
}

func ResetTLSStatus() {
	SetTLSStatus(TLSStatus{})
}

func RecordTLSConfigured(source string, certNotAfter time.Time) {
	tlsMu.Lock()
	defer tlsMu.Unlock()
	tlsStatus.Enabled = true
	tlsStatus.Source = strings.TrimSpace(source)
	if !certNotAfter.IsZero() {
		tlsStatus.CertNotAfter = certNotAfter.UTC().Format(time.RFC3339Nano)
	}
	tlsStatus.LastError = ""
}

func RecordTLSError(err error) {
	tlsMu.Lock()
	defer tlsMu.Unlock()
	if err == nil {
		tlsStatus.LastError = ""
		return
	}
	tlsStatus.LastError = strings.TrimSpace(err.Error())
}

func RecordTLSACMESuccess(certNotAfter time.Time) {
	tlsMu.Lock()
	defer tlsMu.Unlock()
	tlsStatus.Enabled = true
	tlsStatus.Source = "acme"
	tlsStatus.ACMESuccessTotal++
	tlsStatus.LastError = ""
	if !certNotAfter.IsZero() {
		tlsStatus.CertNotAfter = certNotAfter.UTC().Format(time.RFC3339Nano)
	}
}

func RecordTLSACMEFailure(err error) {
	tlsMu.Lock()
	defer tlsMu.Unlock()
	tlsStatus.Enabled = true
	tlsStatus.Source = "acme"
	tlsStatus.ACMEFailureTotal++
	if err != nil {
		tlsStatus.LastError = strings.TrimSpace(err.Error())
	}
}
