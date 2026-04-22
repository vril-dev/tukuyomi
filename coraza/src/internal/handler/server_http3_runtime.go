package handler

import (
	"strings"
	"sync"
)

type serverHTTP3RuntimeStatus struct {
	Enabled    bool   `json:"enabled"`
	Advertised bool   `json:"advertised"`
	AltSvc     string `json:"alt_svc,omitempty"`
	LastError  string `json:"last_error,omitempty"`
}

var (
	serverHTTP3RuntimeMu sync.RWMutex
	serverHTTP3Runtime   serverHTTP3RuntimeStatus
)

func SetServerHTTP3RuntimeStatus(status serverHTTP3RuntimeStatus) {
	serverHTTP3RuntimeMu.Lock()
	serverHTTP3Runtime = status
	serverHTTP3RuntimeMu.Unlock()
}

func ServerHTTP3RuntimeStatusSnapshot() serverHTTP3RuntimeStatus {
	serverHTTP3RuntimeMu.RLock()
	defer serverHTTP3RuntimeMu.RUnlock()
	return serverHTTP3Runtime
}

func ResetServerHTTP3RuntimeStatus() {
	SetServerHTTP3RuntimeStatus(serverHTTP3RuntimeStatus{})
}

func RecordServerHTTP3Configured(altSvc string) {
	serverHTTP3RuntimeMu.Lock()
	defer serverHTTP3RuntimeMu.Unlock()
	serverHTTP3Runtime.Enabled = true
	serverHTTP3Runtime.Advertised = strings.TrimSpace(altSvc) != ""
	serverHTTP3Runtime.AltSvc = strings.TrimSpace(altSvc)
	serverHTTP3Runtime.LastError = ""
}

func RecordServerHTTP3Error(err error) {
	serverHTTP3RuntimeMu.Lock()
	defer serverHTTP3RuntimeMu.Unlock()
	serverHTTP3Runtime.Enabled = true
	if err == nil {
		serverHTTP3Runtime.LastError = ""
		return
	}
	serverHTTP3Runtime.LastError = strings.TrimSpace(err.Error())
}
