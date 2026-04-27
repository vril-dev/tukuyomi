package handler

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestResolvePHPRuntimeIdentityUsesConfiguredCurrentUserAndGroup(t *testing.T) {
	mat := PHPRuntimeMaterializedStatus{
		RuntimeID: "php82",
		RunUser:   strconv.Itoa(os.Geteuid()),
		RunGroup:  strconv.Itoa(os.Getegid()),
	}
	identity, err := resolvePHPRuntimeIdentity(mat)
	if err != nil {
		t.Fatalf("resolvePHPRuntimeIdentity: %v", err)
	}
	if identity.UID != uint32(os.Geteuid()) || identity.GID != uint32(os.Getegid()) {
		t.Fatalf("identity mismatch: %+v current uid=%d gid=%d", identity, os.Geteuid(), os.Getegid())
	}
	if identity.EffectiveUser == "" || identity.EffectiveGroup == "" {
		t.Fatalf("effective labels should not be empty: %+v", identity)
	}
}

func TestValidatePHPRuntimeLaunchRejectsPrivilegeTransitionWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root current user")
	}
	mat := PHPRuntimeMaterializedStatus{
		RuntimeID: "php82",
		RunUser:   strconv.Itoa(os.Geteuid() + 1),
		RunGroup:  strconv.Itoa(os.Getegid() + 1),
	}
	identity, err := resolvePHPRuntimeIdentity(mat)
	if err != nil {
		t.Fatalf("resolvePHPRuntimeIdentity: %v", err)
	}
	if err := validatePHPRuntimePrivilegeTransition(identity); err == nil {
		t.Fatal("expected privilege transition error")
	} else if !strings.Contains(err.Error(), "cannot switch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePHPRuntimeLaunchRejectsUnreadableDocumentRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root current user")
	}
	tmp := t.TempDir()
	runtimeDir := filepath.Join(tmp, "runtime")
	if err := os.MkdirAll(filepath.Join(runtimeDir, "pools"), 0o755); err != nil {
		t.Fatalf("MkdirAll(runtime): %v", err)
	}
	configFile := filepath.Join(runtimeDir, "php-fpm.conf")
	poolFile := filepath.Join(runtimeDir, "pools", "app.conf")
	if err := os.WriteFile(configFile, []byte("[global]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	if err := os.WriteFile(poolFile, []byte("[app]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(pool): %v", err)
	}
	docroot := filepath.Join(tmp, "docroot")
	if err := os.MkdirAll(docroot, 0o700); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.Chmod(docroot, 0o600); err != nil {
		t.Fatalf("Chmod(docroot): %v", err)
	}

	mat := PHPRuntimeMaterializedStatus{
		RuntimeID:     "php82",
		RunUser:       strconv.Itoa(os.Geteuid()),
		RunGroup:      strconv.Itoa(os.Getegid()),
		RuntimeDir:    runtimeDir,
		ConfigFile:    configFile,
		PoolFiles:     []string{poolFile},
		DocumentRoots: []string{docroot},
	}
	identity, err := resolvePHPRuntimeIdentity(mat)
	if err != nil {
		t.Fatalf("resolvePHPRuntimeIdentity: %v", err)
	}
	if err := validatePHPRuntimeLaunch(mat, identity); err == nil {
		t.Fatal("expected document_root access error")
	} else if !strings.Contains(err.Error(), "document_root") {
		t.Fatalf("unexpected error: %v", err)
	}
}
