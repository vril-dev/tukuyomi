package config

import "testing"

func TestLegacyCompatPath_DefaultOnly(t *testing.T) {
	if got := LegacyCompatPath(DefaultBypassFilePath, DefaultBypassFilePath, LegacyDefaultBypassFilePath); got != LegacyDefaultBypassFilePath {
		t.Fatalf("LegacyCompatPath(default)=%q want=%q", got, LegacyDefaultBypassFilePath)
	}
	if got := LegacyCompatPath("custom/bypass.conf", DefaultBypassFilePath, LegacyDefaultBypassFilePath); got != "" {
		t.Fatalf("LegacyCompatPath(custom)=%q want empty", got)
	}
}

func TestNormalizeBaseRuleAssetSpec(t *testing.T) {
	got := NormalizeBaseRuleAssetSpec(" ./tukuyomi.conf , rules/custom.conf ,, ")
	want := "tukuyomi.conf,rules/custom.conf"
	if got != want {
		t.Fatalf("NormalizeBaseRuleAssetSpec()=%q want=%q", got, want)
	}
}

func TestNormalizeBaseRuleAssetPathDoesNotRewriteDirectory(t *testing.T) {
	got := NormalizeBaseRuleAssetPath("rules/tukuyomi.conf")
	want := "rules/tukuyomi.conf"
	if got != want {
		t.Fatalf("NormalizeBaseRuleAssetPath()=%q want=%q", got, want)
	}
}
