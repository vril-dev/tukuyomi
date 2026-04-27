package handler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type testPHPRuntimeArtifactOptions struct {
	DisplayName   string
	Version       string
	Modules       []string
	RunUser       string
	RunGroup      string
	BinaryBody    string
	CLIBinaryBody string
}

func writeTestPHPRuntimeArtifact(t *testing.T, inventoryPath string, runtimeID string, opts testPHPRuntimeArtifactOptions) string {
	t.Helper()

	runtimeDir := filepath.Join(phpRuntimeRootDirFromInventoryPath(inventoryPath), "binaries", runtimeID)
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(runtimeDir): %v", err)
	}

	if opts.DisplayName == "" {
		if display := defaultDisplayNameForRuntimeID(runtimeID); display != "" {
			opts.DisplayName = display
		} else {
			opts.DisplayName = runtimeID
		}
	}
	if opts.Version == "" {
		opts.Version = "PHP 8.2.99 (fpm-fcgi)"
	}
	if len(opts.Modules) == 0 {
		opts.Modules = []string{"mbstring", "redis"}
	}
	if opts.BinaryBody == "" {
		opts.BinaryBody = "#!/bin/sh\n" +
			"echo '" + opts.Version + "'\n"
	}

	binaryPath := filepath.Join(runtimeDir, "php-fpm")
	if err := os.WriteFile(binaryPath, []byte(opts.BinaryBody), 0o755); err != nil {
		t.Fatalf("write php-fpm binary: %v", err)
	}
	if opts.CLIBinaryBody == "" {
		opts.CLIBinaryBody = "#!/bin/sh\n" +
			"echo '" + opts.Version + "'\n"
	}
	cliBinaryPath := filepath.Join(runtimeDir, "php")
	if err := os.WriteFile(cliBinaryPath, []byte(opts.CLIBinaryBody), 0o755); err != nil {
		t.Fatalf("write php binary: %v", err)
	}

	modulesPath := filepath.Join(runtimeDir, "modules.json")
	modulesRaw, err := json.MarshalIndent(opts.Modules, "", "  ")
	if err != nil {
		t.Fatalf("marshal modules.json: %v", err)
	}
	if err := os.WriteFile(modulesPath, append(modulesRaw, '\n'), 0o600); err != nil {
		t.Fatalf("write modules.json: %v", err)
	}

	manifest := phpRuntimeArtifactManifest{
		RuntimeID:              runtimeID,
		DisplayName:            opts.DisplayName,
		DetectedVersion:        opts.Version,
		BinaryPath:             filepath.ToSlash(binaryPath),
		CLIBinaryPath:          filepath.ToSlash(cliBinaryPath),
		DefaultDisabledModules: append([]string(nil), defaultDisabledPHPRuntimeModules...),
		RunUser:                opts.RunUser,
		RunGroup:               opts.RunGroup,
		Source:                 "bundled",
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal runtime.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "runtime.json"), append(manifestRaw, '\n'), 0o600); err != nil {
		t.Fatalf("write runtime.json: %v", err)
	}

	return binaryPath
}
