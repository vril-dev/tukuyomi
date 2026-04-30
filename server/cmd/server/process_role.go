package main

import (
	"fmt"
	"os"
	"strings"
)

type serverCommandKind string

const (
	serverCommandServe                 serverCommandKind = "serve"
	serverCommandCenter                serverCommandKind = "center"
	serverCommandSupervisor            serverCommandKind = "supervisor"
	serverCommandWorker                serverCommandKind = "worker"
	serverCommandReleaseMetadata       serverCommandKind = "release-metadata"
	serverCommandValidateConfig        serverCommandKind = "validate-config"
	serverCommandReleaseStatus         serverCommandKind = "release-status"
	serverCommandReleaseStage          serverCommandKind = "release-stage"
	serverCommandReleaseActivate       serverCommandKind = "release-activate"
	serverCommandReleaseRollback       serverCommandKind = "release-rollback"
	serverCommandDBMigrate             serverCommandKind = "db-migrate"
	serverCommandDBImport              serverCommandKind = "db-import"
	serverCommandDBImportPreview       serverCommandKind = "db-import-preview"
	serverCommandDBImportWAFRuleAssets serverCommandKind = "db-import-waf-rule-assets"
	serverCommandPreviewPrintTopology  serverCommandKind = "preview-print-topology"
	serverCommandRunScheduledTasks     serverCommandKind = "run-scheduled-tasks"
	serverCommandUpdateCountryDB       serverCommandKind = "update-country-db"
)

const (
	serverInternalProcessRoleEnv  = "TUKUYOMI_INTERNAL_PROCESS_ROLE"
	internalProcessRoleSupervisor = "supervisor"
	internalProcessRoleWorker     = "worker"
)

type serverCommand struct {
	kind serverCommandKind
	args []string
}

func parseServerCommand(args []string) (serverCommand, error) {
	return parseServerCommandWithEnv(args, os.Environ())
}

func parseServerCommandWithEnv(args []string, env []string) (serverCommand, error) {
	if role := internalProcessRoleFromEnv(env); role != "" {
		if len(args) >= 2 && strings.TrimSpace(args[1]) != "" {
			return serverCommand{}, fmt.Errorf("%s cannot be combined with a command", serverInternalProcessRoleEnv)
		}
		switch role {
		case internalProcessRoleSupervisor:
			return serverCommand{kind: serverCommandSupervisor}, nil
		case internalProcessRoleWorker:
			return serverCommand{kind: serverCommandWorker}, nil
		default:
			return serverCommand{}, fmt.Errorf("unknown internal process role %q", role)
		}
	}

	if len(args) < 2 {
		return serverCommand{kind: serverCommandServe}, nil
	}
	arg := strings.TrimSpace(args[1])
	switch arg {
	case "":
		return serverCommand{kind: serverCommandServe}, nil
	case "center":
		return serverCommand{kind: serverCommandCenter}, nil
	case "release-metadata":
		return serverCommand{kind: serverCommandReleaseMetadata, args: args[2:]}, nil
	case "validate-config":
		return serverCommand{kind: serverCommandValidateConfig, args: args[2:]}, nil
	case "release-status":
		return serverCommand{kind: serverCommandReleaseStatus, args: args[2:]}, nil
	case "release-stage":
		return serverCommand{kind: serverCommandReleaseStage, args: args[2:]}, nil
	case "release-activate":
		return serverCommand{kind: serverCommandReleaseActivate, args: args[2:]}, nil
	case "release-rollback":
		return serverCommand{kind: serverCommandReleaseRollback, args: args[2:]}, nil
	case "db-migrate":
		return serverCommand{kind: serverCommandDBMigrate}, nil
	case "db-import":
		return serverCommand{kind: serverCommandDBImport}, nil
	case "db-import-preview":
		return serverCommand{kind: serverCommandDBImportPreview}, nil
	case "db-import-waf-rule-assets":
		return serverCommand{kind: serverCommandDBImportWAFRuleAssets}, nil
	case "preview-print-topology":
		return serverCommand{kind: serverCommandPreviewPrintTopology}, nil
	case "run-scheduled-tasks":
		return serverCommand{kind: serverCommandRunScheduledTasks}, nil
	case "update-country-db":
		return serverCommand{kind: serverCommandUpdateCountryDB}, nil
	default:
		return serverCommand{}, fmt.Errorf("unknown command %q", arg)
	}
}

func internalProcessRoleFromEnv(env []string) string {
	for _, item := range env {
		name, value, found := strings.Cut(item, "=")
		if !found || name != serverInternalProcessRoleEnv {
			continue
		}
		return strings.TrimSpace(value)
	}
	return ""
}
