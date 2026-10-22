package bypassconf

import (
	"strings"
	"testing"
)

func TestParseRequestBodyOptions(t *testing.T) {
	file, err := Parse(`{
  "default": {"entries": [
    {"path": "/upload/", "request_body": "SKIP"},
    {"path": "/api/", "request_body": "inherit", "request_body_inspect_limit_bytes": 65536},
    {"path": "/admin/", "extra_rule": "admin.conf", "request_body": "skip"}
  ]}
}`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	got := file.Default.Entries
	if got[0].RequestBody != RequestBodySkip || got[1].RequestBody != "" || got[1].RequestBodyInspectLimitBytes != 65536 || got[2].RequestBody != RequestBodySkip {
		t.Fatalf("normalized entries = %+v", got)
	}

	raw, err := MarshalJSON(file)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	again, err := Parse(string(raw))
	if err != nil {
		t.Fatalf("Parse(marshaled) error = %v", err)
	}
	if again.Default.Entries[1].RequestBodyInspectLimitBytes != 65536 || again.Default.Entries[0].RequestBody != RequestBodySkip {
		t.Fatalf("round trip lost request body options: %+v", again.Default.Entries)
	}
	if strings.Contains(string(raw), `"request_body": ""`) {
		t.Fatalf("inherit must be omitted from JSON: %s", raw)
	}
}

func TestParseRejectsInvalidRequestBodyOptions(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"unknown mode", `{"default":{"entries":[{"path":"/a","request_body":"off"}]}}`, "request_body must be inherit or skip"},
		{"limit with skip", `{"default":{"entries":[{"path":"/a","request_body":"skip","request_body_inspect_limit_bytes":2048}]}}`, "cannot be set with request_body=skip"},
		{"limit too small", `{"default":{"entries":[{"path":"/a","request_body_inspect_limit_bytes":512}]}}`, "must be between 1024 and 1048576"},
		{"limit too large", `{"default":{"entries":[{"path":"/a","request_body_inspect_limit_bytes":2097152}]}}`, "must be between 1024 and 1048576"},
		{"negative limit", `{"hosts":{"example.com":{"entries":[{"path":"/a","request_body_inspect_limit_bytes":-1}]}}}`, "must be between 1024 and 1048576"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestMatchRequestBodyOptions(t *testing.T) {
	prev := GetFile()
	t.Cleanup(func() { SetFile(prev) })
	SetFile(File{
		Default: Scope{Entries: []Entry{
			{Path: "/upload/", RequestBody: RequestBodySkip},
			{Path: "/api/", RequestBodyInspectLimitBytes: 65536},
			{Path: "/api/", RequestBody: RequestBodySkip},
			{Path: "/rule/", ExtraRule: "rule.conf", RequestBodyInspectLimitBytes: 4096},
			{Path: "/health"},
			{Path: "/health", RequestBody: RequestBodySkip},
		}},
		Hosts: map[string]Scope{
			"example.com": {Entries: []Entry{{Path: "/upload/"}}},
		},
	})

	if got := Match("app.test", "/upload/file", false); got.Action != ACTION_NONE || got.RequestBody == nil || !got.RequestBody.Skip {
		t.Fatalf("body-only entry must keep the WAF on and skip the body: %+v", got)
	}
	if got := Match("app.test", "/api/users", false); got.Action != ACTION_NONE || got.RequestBody == nil || got.RequestBody.Skip || got.RequestBody.InspectLimitBytes != 65536 {
		t.Fatalf("first matching entry with body options must win: %+v", got)
	}
	if got := Match("app.test", "/rule/x", false); got.Action != ACTION_RULE || got.ExtraRule != "rule.conf" || got.RequestBody == nil || got.RequestBody.InspectLimitBytes != 4096 {
		t.Fatalf("extra rule entry must carry body options: %+v", got)
	}
	if got := Match("app.test", "/health", false); got.Action != ACTION_BYPASS {
		t.Fatalf("plain entry must still bypass the WAF: %+v", got)
	}
	if got := Match("app.test", "/other", false); got.Action != ACTION_NONE || got.RequestBody != nil {
		t.Fatalf("unmatched path must inherit: %+v", got)
	}
	if got := Match("example.com", "/upload/file", false); got.Action != ACTION_BYPASS || got.RequestBody != nil {
		t.Fatalf("host scope must replace the default scope: %+v", got)
	}
}
