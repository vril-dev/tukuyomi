package bypassconf

import "testing"

func TestParseValid(t *testing.T) {
	raw := `
# comment
/about/
/about/admin.php rules/admin.conf
`

	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(Parse()) = %d, want 2", len(got))
	}
	if got[0].Path != "/about/" || got[0].ExtraRule != "" {
		t.Fatalf("entry[0] = %+v", got[0])
	}
	if got[1].Path != "/about/admin.php" || got[1].ExtraRule != "rules/admin.conf" {
		t.Fatalf("entry[1] = %+v", got[1])
	}
}

func TestParseInvalid(t *testing.T) {
	cases := []string{
		"about/",
		"/admin rules/admin",
		"/admin rules/admin.conf extra",
	}

	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, err := Parse(tc); err == nil {
				t.Fatalf("Parse(%q) expected error, got nil", tc)
			}
		})
	}
}

func TestMatchPrefersRuleOverBypass(t *testing.T) {
	mu.Lock()
	entries = []Entry{
		{Path: "/admin"},
		{Path: "/admin", ExtraRule: "rules/admin.conf"},
	}
	mu.Unlock()

	got := Match("/admin")
	if got.Action != ACTION_RULE || got.ExtraRule != "rules/admin.conf" {
		t.Fatalf("Match() = %+v, want ACTION_RULE with extra rule", got)
	}
}
