package center

import "testing"

func TestNormalizeCenterSettingsMigratesLegacySharedAPIPath(t *testing.T) {
	cfg, err := decodeCenterSettings([]byte(`{"api_base_path":"/center-api","gateway_api_base_path":"/center-api"}`))
	if err != nil {
		t.Fatalf("decodeCenterSettings: %v", err)
	}
	if cfg.APIBasePath != "/center-manage-api" || cfg.GatewayAPIBasePath != "/center-api" {
		t.Fatalf("unexpected migrated API paths: %+v", cfg)
	}
}

func TestNormalizeCenterSettingsRejectsSharedCustomAPIPath(t *testing.T) {
	if _, err := normalizeCenterSettingsConfig(CenterSettingsConfig{
		APIBasePath:        "/shared-api",
		GatewayAPIBasePath: "/shared-api",
	}); err == nil {
		t.Fatal("expected shared custom API paths to be rejected")
	}
}
