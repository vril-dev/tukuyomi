package requestmeta

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestReadGeoIPConfigUploadRejectsOversizedInput(t *testing.T) {
	raw := strings.Repeat("A", MaxGeoIPConfigBytes+1)
	if _, _, err := ReadGeoIPConfigUpload(strings.NewReader(raw)); err == nil {
		t.Fatal("expected oversized GeoIP.conf error")
	}
}

func TestReadMMDBUploadValidatesMMDBPayload(t *testing.T) {
	if _, err := ReadMMDBUpload(bytes.NewReader([]byte("not-mmdb"))); err == nil {
		t.Fatal("expected invalid mmdb error")
	}
}

func TestBuildUpdateStatusPrefersPersistedStateError(t *testing.T) {
	status := BuildUpdateStatus(
		"db:geoip",
		"/bin/geoipupdate",
		nil,
		UpdateState{LastResult: "error", LastError: "stored failure"},
		true,
		nil,
		UpdateConfigStatus{},
		nil,
		"",
	)
	if got, want := status.LastError, "stored failure"; got != want {
		t.Fatalf("LastError=%q want=%q", got, want)
	}
	if !status.UpdaterAvailable {
		t.Fatal("expected updater to be available")
	}
}

func TestBuildCountryDBStatusCopiesInstalledAsset(t *testing.T) {
	ts := time.Unix(1_700_000_000, 0).UTC()
	status := BuildCountryDBStatus(
		CountryRuntimeStatus{ManagedPath: "db:mmdb", EffectiveMode: "mmdb", Loaded: true},
		"",
		"etag",
		"",
		CountryDBAssetStatus{Installed: true, SizeBytes: 100, ModTime: ts},
	)
	if got, want := status.ConfiguredMode, "header"; got != want {
		t.Fatalf("ConfiguredMode=%q want=%q", got, want)
	}
	if !status.Installed || status.SizeBytes != 100 || status.ModTime == "" {
		t.Fatalf("unexpected asset status: %#v", status)
	}
}
