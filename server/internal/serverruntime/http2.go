package serverruntime

import "sync"

type HTTP2Status struct {
	Enabled    bool `json:"enabled"`
	Advertised bool `json:"advertised"`
}

var (
	http2Mu     sync.RWMutex
	http2Status HTTP2Status
)

func SetHTTP2Status(status HTTP2Status) {
	http2Mu.Lock()
	http2Status = status
	http2Mu.Unlock()
}

func HTTP2StatusSnapshot() HTTP2Status {
	http2Mu.RLock()
	defer http2Mu.RUnlock()
	return http2Status
}

func ResetHTTP2Status() {
	SetHTTP2Status(HTTP2Status{})
}

func RecordHTTP2Configured(advertised bool) {
	http2Mu.Lock()
	http2Status = HTTP2Status{Enabled: true, Advertised: advertised}
	http2Mu.Unlock()
}
