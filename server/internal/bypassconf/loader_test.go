package bypassconf

import "testing"

func TestParseValid(t *testing.T) {
raw := `
# comment
/about/
/about/admin.php conf/rules/admin.conf
`

	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	entries := GetEntries(got)
	if len(entries) != 2 {
		t.Fatalf("len(Parse()) = %d, want 2", len(entries))
	}
	if entries[0].Path != "/about/" || entries[0].ExtraRule != "" {
		t.Fatalf("entry[0] = %+v", entries[0])
	}
	if entries[1].Path != "/about/admin.php" || entries[1].ExtraRule != "conf/rules/admin.conf" {
		t.Fatalf("entry[1] = %+v", entries[1])
	}
}

func TestParseInvalid(t *testing.T) {
	cases := []string{
		"about/",
		"/admin rules/admin",
		"/admin conf/rules/admin.conf extra",
	}

	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, err := Parse(tc); err == nil {
				t.Fatalf("Parse(%q) expected error, got nil", tc)
			}
		})
	}
}

func TestParseJSON(t *testing.T) {
raw := `{
  "default": {
    "entries": [
      { "path": "/about/" }
    ]
  },
  "hosts": {
    "example.com": {
      "entries": [
        { "path": "/admin", "extra_rule": "conf/rules/admin.conf" }
      ]
    }
  }
}`
	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(JSON) error = %v", err)
	}
	if len(got.Default.Entries) != 1 {
		t.Fatalf("len(default.entries) = %d, want 1", len(got.Default.Entries))
	}
	if got.Default.Entries[0].Path != "/about/" || got.Default.Entries[0].ExtraRule != "" {
		t.Fatalf("default.entry[0] = %+v", got.Default.Entries[0])
	}
	scope, ok := got.Hosts["example.com"]
	if !ok {
		t.Fatalf("expected example.com host scope, got %v", got.Hosts)
	}
	if len(scope.Entries) != 1 || scope.Entries[0].Path != "/admin" || scope.Entries[0].ExtraRule != "conf/rules/admin.conf" {
		t.Fatalf("host entries = %+v", scope.Entries)
	}
}

func TestMatchPrefersRuleOverBypass(t *testing.T) {
	mu.Lock()
	fileState = File{
		Default: Scope{
			Entries: []Entry{
				{Path: "/admin"},
				{Path: "/admin", ExtraRule: "conf/rules/admin.conf"},
			},
		},
	}
	mu.Unlock()

	got := Match("example.com", "/admin", false)
	if got.Action != ACTION_RULE || got.ExtraRule != "conf/rules/admin.conf" {
		t.Fatalf("Match() = %+v, want ACTION_RULE with extra rule", got)
	}
}

func TestMatchPrefersHostPortOverHostAndDefault(t *testing.T) {
	mu.Lock()
	fileState = File{
		Default: Scope{
			Entries: []Entry{{Path: "/shared/"}},
		},
		Hosts: map[string]Scope{
			"example.com": {
				Entries: []Entry{{Path: "/host/"}},
			},
			"example.com:8080": {
				Entries: []Entry{{Path: "/port/"}},
			},
		},
	}
	mu.Unlock()

	if got := Match("example.com:8080", "/port/test", false); got.Action != ACTION_BYPASS {
		t.Fatalf("port host match = %+v want bypass", got)
	}
	if got := Match("example.com", "/host/test", false); got.Action != ACTION_BYPASS {
		t.Fatalf("host match = %+v want bypass", got)
	}
	if got := Match("other.example.com", "/shared/test", false); got.Action != ACTION_BYPASS {
		t.Fatalf("default match = %+v want bypass", got)
	}
}

func TestMatchTreatsHTTPDefaultPortAsEquivalent(t *testing.T) {
	mu.Lock()
	fileState = File{
		Hosts: map[string]Scope{
			"example.com:80": {
				Entries: []Entry{{Path: "/http-only/"}},
			},
		},
	}
	mu.Unlock()

	if got := Match("example.com", "/http-only/index.html", false); got.Action != ACTION_BYPASS {
		t.Fatalf("default port match = %+v want bypass", got)
	}
}
