package serverruntime

import (
	"errors"
	"testing"
	"time"
)

func TestTLSStatusRecordsConfiguredAndError(t *testing.T) {
	ResetTLSStatus()
	expires := time.Unix(2000, 0).UTC()

	RecordTLSConfigured(" file ", expires)
	status := TLSStatusSnapshot()
	if !status.Enabled || status.Source != "file" {
		t.Fatalf("unexpected configured status: %#v", status)
	}
	if status.CertNotAfter != expires.Format(time.RFC3339Nano) {
		t.Fatalf("cert_not_after=%q", status.CertNotAfter)
	}

	RecordTLSError(errors.New("boom"))
	if got := TLSStatusSnapshot().LastError; got != "boom" {
		t.Fatalf("last_error=%q want boom", got)
	}
	RecordTLSError(nil)
	if got := TLSStatusSnapshot().LastError; got != "" {
		t.Fatalf("last_error=%q want empty", got)
	}
}

func TestTLSStatusRecordsACMECounters(t *testing.T) {
	ResetTLSStatus()
	RecordTLSACMESuccess(time.Time{})
	RecordTLSACMEFailure(errors.New("fail"))

	status := TLSStatusSnapshot()
	if status.Source != "acme" || !status.Enabled {
		t.Fatalf("unexpected acme status: %#v", status)
	}
	if status.ACMESuccessTotal != 1 || status.ACMEFailureTotal != 1 {
		t.Fatalf("unexpected acme counters: %#v", status)
	}
	if status.LastError != "fail" {
		t.Fatalf("last_error=%q want fail", status.LastError)
	}
}
