package semanticprovider

import "testing"

func TestNormalizeConfigDefaultsBuiltinProvider(t *testing.T) {
	cfg, err := NormalizeConfig(Config{Enabled: true})
	if err != nil {
		t.Fatalf("NormalizeConfig: %v", err)
	}
	if cfg.Name != NameBuiltinAttackFamily || cfg.TimeoutMS != DefaultTimeoutMS {
		t.Fatalf("cfg=%#v", cfg)
	}
}

func TestBuiltinProviderDetectsSQLFamily(t *testing.T) {
	rt := BuildRuntime(Config{Enabled: true, Name: NameBuiltinAttackFamily, TimeoutMS: 25})
	out := Evaluate(rt, Input{
		TargetClass:  "admin_management",
		BaseReasons:  []string{"sql_union_select"},
		QueryExcerpt: "UNION SELECT password FROM users",
	})
	if out == nil {
		t.Fatal("expected provider output")
	}
	if out.AttackFamily != "sql_injection" || out.ScoreDelta <= 0 {
		t.Fatalf("out=%#v", out)
	}
}
