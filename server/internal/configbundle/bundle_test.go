package configbundle

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDecodeRejectsUnknownDomain(t *testing.T) {
	raw := []byte(`{"schema_version":1,"domains":{"unknown":{}}}`)
	if _, err := Decode(raw); err == nil || !strings.Contains(err.Error(), `unknown config bundle domain "unknown"`) {
		t.Fatalf("Decode unknown domain err=%v", err)
	}
}

func TestDecodeRejectsMultipleJSONValues(t *testing.T) {
	raw := []byte(`{"schema_version":1,"domains":{}}{}`)
	if _, err := Decode(raw); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("Decode multiple values err=%v", err)
	}
}

func TestLegacySeedRawMapsJSONDomain(t *testing.T) {
	b := New("test", time.Time{})
	if err := SetDomainRaw(&b, DomainProxy, []byte(`{"upstreams":[]}`)); err != nil {
		t.Fatalf("SetDomainRaw: %v", err)
	}
	raw, found, err := b.LegacySeedRaw("proxy.json")
	if err != nil || !found {
		t.Fatalf("LegacySeedRaw found=%v err=%v", found, err)
	}
	if !json.Valid(raw) || !bytes.Contains(raw, []byte(`"upstreams"`)) {
		t.Fatalf("unexpected proxy raw: %s", raw)
	}
}

func TestLegacySeedRawConvertsCRSDisabledArray(t *testing.T) {
	b := New("test", time.Time{})
	if err := SetDomainRaw(&b, DomainCRSDisabled, []byte(`["REQUEST-913-SCANNER-DETECTION.conf"]`)); err != nil {
		t.Fatalf("SetDomainRaw: %v", err)
	}
	raw, found, err := b.LegacySeedRaw("crs-disabled.conf")
	if err != nil || !found {
		t.Fatalf("LegacySeedRaw found=%v err=%v", found, err)
	}
	if !bytes.Contains(raw, []byte("REQUEST-913-SCANNER-DETECTION.conf")) {
		t.Fatalf("unexpected crs raw: %s", raw)
	}
}
