package main

import (
	"strings"
	"testing"
)

func TestParseServerCommandRoles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want serverCommandKind
	}{
		{name: "default serve", args: []string{"tukuyomi"}, want: serverCommandServe},
		{name: "center", args: []string{"tukuyomi", "center"}, want: serverCommandCenter},
		{name: "release metadata", args: []string{"tukuyomi", "release-metadata"}, want: serverCommandReleaseMetadata},
		{name: "validate config", args: []string{"tukuyomi", "validate-config"}, want: serverCommandValidateConfig},
		{name: "release status", args: []string{"tukuyomi", "release-status"}, want: serverCommandReleaseStatus},
		{name: "release stage", args: []string{"tukuyomi", "release-stage", "artifact.tar.gz", "abc"}, want: serverCommandReleaseStage},
		{name: "release activate", args: []string{"tukuyomi", "release-activate", "v1.2.3"}, want: serverCommandReleaseActivate},
		{name: "release rollback", args: []string{"tukuyomi", "release-rollback"}, want: serverCommandReleaseRollback},
		{
			name: "internal supervisor",
			args: []string{"tukuyomi"},
			want: serverCommandSupervisor,
		},
		{
			name: "internal worker",
			args: []string{"tukuyomi"},
			want: serverCommandWorker,
		},
		{name: "db migrate", args: []string{"tukuyomi", "db-migrate"}, want: serverCommandDBMigrate},
		{name: "admin bootstrap", args: []string{"tukuyomi", "admin-bootstrap"}, want: serverCommandAdminBootstrap},
		{name: "admin mfa", args: []string{"tukuyomi", "admin-mfa", "disable", "--username", "admin", "--reason", "lost authenticator"}, want: serverCommandAdminMFA},
		{name: "scheduled task defaults", args: []string{"tukuyomi", "bootstrap-scheduled-task-defaults"}, want: serverCommandBootstrapScheduledTasks},
		{name: "scheduled tasks", args: []string{"tukuyomi", "run-scheduled-tasks"}, want: serverCommandRunScheduledTasks},
		{name: "archive waf logs", args: []string{"tukuyomi", "archive-waf-logs"}, want: serverCommandArchiveWAFLogs},
		{name: "protected gateway bootstrap", args: []string{"tukuyomi", "bootstrap-center-protected-gateway", "--center-url", "http://127.0.0.1:9092"}, want: serverCommandBootstrapProtectedGateway},
		{name: "protected center bootstrap", args: []string{"tukuyomi", "bootstrap-center-protected-center", "--in", "identity.json"}, want: serverCommandBootstrapProtectedCenter},
		{name: "remote ssh", args: []string{"tukuyomi", "remote-ssh", "--center", "http://127.0.0.1:9092", "--device", "edge-1"}, want: serverCommandRemoteSSH},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := []string(nil)
			switch tt.name {
			case "internal supervisor":
				env = []string{serverInternalProcessRoleEnv + "=" + internalProcessRoleSupervisor}
			case "internal worker":
				env = []string{serverInternalProcessRoleEnv + "=" + internalProcessRoleWorker}
			}
			cmd, err := parseServerCommandWithEnv(tt.args, env)
			if err != nil {
				t.Fatalf("parseServerCommand: %v", err)
			}
			if got := cmd.kind; got != tt.want {
				t.Fatalf("kind=%s want=%s", got, tt.want)
			}
		})
	}
}

func TestParseServerCommandRejectsUnknown(t *testing.T) {
	t.Parallel()

	if _, err := parseServerCommandWithEnv([]string{"tukuyomi", "single"}, nil); err == nil {
		t.Fatal("expected explicit single command to be rejected")
	}
	if _, err := parseServerCommandWithEnv([]string{"tukuyomi", "supervisor"}, nil); err == nil {
		t.Fatal("expected public supervisor command to be rejected")
	}
	if _, err := parseServerCommandWithEnv([]string{"tukuyomi", "worker"}, nil); err == nil {
		t.Fatal("expected public worker command to be rejected")
	}
	if _, err := parseServerCommandWithEnv([]string{"tukuyomi", "-unknown"}, nil); err == nil {
		t.Fatal("expected unknown command to be rejected")
	}
	if _, err := parseServerCommandWithEnv([]string{"tukuyomi"}, []string{serverInternalProcessRoleEnv + "=manager"}); err == nil {
		t.Fatal("expected unknown internal role to be rejected")
	}
	if _, err := parseServerCommandWithEnv([]string{"tukuyomi", "db-migrate"}, []string{serverInternalProcessRoleEnv + "=" + internalProcessRoleWorker}); err == nil {
		t.Fatal("expected internal role plus command to be rejected")
	}
}

func TestParseAdminMFACommandConfig(t *testing.T) {
	t.Parallel()

	cfg, err := parseAdminMFACommandConfig([]string{"disable", "--username", "admin", "--reason", "lost authenticator"})
	if err != nil {
		t.Fatalf("parseAdminMFACommandConfig: %v", err)
	}
	if cfg.Action != "disable" || cfg.Username != "admin" || cfg.Email != "" || cfg.Reason != "lost authenticator" {
		t.Fatalf("unexpected config: %+v", cfg)
	}

	rejects := [][]string{
		{},
		{"rotate", "--username", "admin", "--reason", "x"},
		{"disable", "--username", "admin"},
		{"disable", "--username", "admin", "--email", "admin@example.test", "--reason", "x"},
		{"disable", "--reason", "x"},
		{"disable", "--email", "admin@example.test", "--reason", "x", "extra"},
	}
	for _, args := range rejects {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			if _, err := parseAdminMFACommandConfig(args); err == nil {
				t.Fatalf("expected args %v to be rejected", args)
			}
		})
	}
}
