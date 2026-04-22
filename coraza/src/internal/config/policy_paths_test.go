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
