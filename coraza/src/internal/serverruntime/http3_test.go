package serverruntime

import (
	"errors"
	"testing"
)

func TestHTTP3StatusLifecycle(t *testing.T) {
	ResetHTTP3Status()
	RecordHTTP3Configured(`h3=":443"; ma=60`)
	status := HTTP3StatusSnapshot()
	if !status.Enabled || !status.Advertised || status.AltSvc == "" {
		t.Fatalf("configured status=%+v", status)
	}

	RecordHTTP3Error(errors.New("listen failed"))
	status = HTTP3StatusSnapshot()
	if status.LastError != "listen failed" {
		t.Fatalf("last_error=%q", status.LastError)
	}

	RecordHTTP3Error(nil)
	status = HTTP3StatusSnapshot()
	if status.LastError != "" {
		t.Fatalf("last_error=%q want empty", status.LastError)
	}
}
