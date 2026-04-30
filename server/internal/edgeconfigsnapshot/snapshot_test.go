package edgeconfigsnapshot

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestRevisionIgnoresGeneratedFields(t *testing.T) {
	base := Payload{
		SchemaVersion:  SchemaVersion,
		ConfigRevision: "old",
		GeneratedAt:    "2026-04-30T00:00:00Z",
		DeviceID:       "edge-1",
		KeyID:          "default",
		Domains: map[string]Domain{
			"proxy": {ETag: "etag-a", Raw: json.RawMessage(`{"routes":[]}`)},
		},
	}
	rev1, err := Revision(base)
	if err != nil {
		t.Fatalf("revision 1: %v", err)
	}
	base.ConfigRevision = "new"
	base.GeneratedAt = "2026-04-30T00:01:00Z"
	rev2, err := Revision(base)
	if err != nil {
		t.Fatalf("revision 2: %v", err)
	}
	if rev1 != rev2 {
		t.Fatalf("revision changed for generated fields: %q != %q", rev1, rev2)
	}
	base.Domains["proxy"] = Domain{ETag: "etag-b", Raw: json.RawMessage(`{"routes":[{"id":"changed"}]}`)}
	rev3, err := Revision(base)
	if err != nil {
		t.Fatalf("revision 3: %v", err)
	}
	if rev3 == rev1 {
		t.Fatalf("revision did not change after config domain changed")
	}
}

func TestRedactAppConfigRaw(t *testing.T) {
	raw := `{
		"admin":{"session_secret":"secret"},
		"security_audit":{"encryption_key":"enc","hmac_key":"hmac"},
		"fp_tuner":{"api_key":"api"},
		"storage":{"db_dsn":"db"},
		"keep":"value"
	}`
	redacted, paths, err := RedactAppConfigRaw(raw)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	for _, path := range []string{
		"app_config.admin.session_secret",
		"app_config.security_audit.encryption_key",
		"app_config.security_audit.hmac_key",
		"app_config.fp_tuner.api_key",
		"app_config.storage.db_dsn",
	} {
		if !slices.Contains(paths, path) {
			t.Fatalf("missing redacted path %q in %v", path, paths)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(redacted, &decoded); err != nil {
		t.Fatalf("redacted JSON: %v", err)
	}
	admin := decoded["admin"].(map[string]any)
	if admin["session_secret"] != "[redacted]" {
		t.Fatalf("session_secret was not redacted: %#v", admin["session_secret"])
	}
	if decoded["keep"] != "value" {
		t.Fatalf("non-secret field changed: %#v", decoded["keep"])
	}
}
