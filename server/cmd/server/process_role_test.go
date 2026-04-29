package main

import "testing"

func TestParseServerCommandRoles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want serverCommandKind
	}{
		{name: "default serve", args: []string{"tukuyomi"}, want: serverCommandServe},
		{name: "center", args: []string{"tukuyomi", "center"}, want: serverCommandCenter},
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
		{name: "scheduled tasks", args: []string{"tukuyomi", "run-scheduled-tasks"}, want: serverCommandRunScheduledTasks},
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
