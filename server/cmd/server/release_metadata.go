package main

import (
	"encoding/json"
	"log"
	"os"
	"runtime"
	"strings"

	"tukuyomi/internal/buildinfo"
	"tukuyomi/internal/config"
)

const releaseMetadataSchemaVersion = 1

type releaseBinaryMetadata struct {
	SchemaVersion  int    `json:"schema_version"`
	App            string `json:"app"`
	Version        string `json:"version,omitempty"`
	GOOS           string `json:"goos"`
	GOARCH         string `json:"goarch"`
	GoVersion      string `json:"go_version"`
	WorkerProtocol string `json:"worker_protocol"`
}

func currentReleaseBinaryMetadata() releaseBinaryMetadata {
	return releaseBinaryMetadata{
		SchemaVersion:  releaseMetadataSchemaVersion,
		App:            "tukuyomi",
		Version:        strings.TrimSpace(buildinfo.Version),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		GoVersion:      runtime.Version(),
		WorkerProtocol: workerReadinessProtocol,
	}
}

func runReleaseMetadataCommand() {
	if err := json.NewEncoder(os.Stdout).Encode(currentReleaseBinaryMetadata()); err != nil {
		log.Fatalf("[RELEASE][METADATA][FATAL] %v", err)
	}
}

func runValidateConfigCommand() {
	path := strings.TrimSpace(os.Getenv("WAF_CONFIG_FILE"))
	if err := config.ReloadFromConfigFile(path); err != nil {
		log.Fatalf("[CONFIG][VALIDATE][FATAL] load %s: %v", config.ConfigFile, err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true}); err != nil {
		log.Fatalf("[CONFIG][VALIDATE][FATAL] %v", err)
	}
}
