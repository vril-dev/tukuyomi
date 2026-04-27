package serverruntime

import (
	"strings"
	"sync"
)

type HTTP3Status struct {
	Enabled    bool   `json:"enabled"`
	Advertised bool   `json:"advertised"`
	AltSvc     string `json:"alt_svc,omitempty"`
	LastError  string `json:"last_error,omitempty"`
}

var (
	http3Mu     sync.RWMutex
	http3Status HTTP3Status
)

func SetHTTP3Status(status HTTP3Status) {
	http3Mu.Lock()
	http3Status = status
	http3Mu.Unlock()
}

func HTTP3StatusSnapshot() HTTP3Status {
	http3Mu.RLock()
	defer http3Mu.RUnlock()
	return http3Status
}

func ResetHTTP3Status() {
	SetHTTP3Status(HTTP3Status{})
}

func RecordHTTP3Configured(altSvc string) {
	http3Mu.Lock()
	defer http3Mu.Unlock()
	http3Status.Enabled = true
	http3Status.Advertised = strings.TrimSpace(altSvc) != ""
	http3Status.AltSvc = strings.TrimSpace(altSvc)
	http3Status.LastError = ""
}

func RecordHTTP3Error(err error) {
	http3Mu.Lock()
	defer http3Mu.Unlock()
	http3Status.Enabled = true
	if err == nil {
		http3Status.LastError = ""
		return
	}
	http3Status.LastError = strings.TrimSpace(err.Error())
}
