package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateScheduledTaskConfigFileRequiresCommand(t *testing.T) {
	_, err := prepareScheduledTaskConfigRaw(`{
  "tasks": [
    {
      "name": "app-cron",
      "enabled": true,
      "schedule": "* * * * *"
    }
  ]
}`, PHPRuntimeInventoryFile{})
	if err == nil {
		t.Fatal("expected command validation error")
	}
	if !strings.Contains(err.Error(), "tasks[0].command is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateScheduledTaskConfigFileAllowsIanaTimezone(t *testing.T) {
	_, err := prepareScheduledTaskConfigRaw(`{
  "tasks": [
    {
      "name": "app-cron",
      "enabled": true,
      "schedule": "*/5 * * * *",
      "timezone": "Asia/Tokyo",
      "command": "/usr/bin/env true"
    }
  ]
}`, PHPRuntimeInventoryFile{})
	if err != nil {
		t.Fatalf("prepareScheduledTaskConfigRaw: %v", err)
	}
}

func TestScheduledTaskRuntimeDirUsesDataSiblingForConfPath(t *testing.T) {
	testCases := []struct {
		name     string
		config   string
		wantPath string
	}{
		{name: "default relative", config: "conf/scheduled-tasks.json", wantPath: filepath.Join("data", "scheduled-tasks")},
		{name: "repo relative", config: filepath.Join("data", "conf", "scheduled-tasks.json"), wantPath: filepath.Join("data", "scheduled-tasks")},
		{name: "absolute deploy", config: "/opt/tukuyomi/conf/scheduled-tasks.json", wantPath: "/opt/tukuyomi/data/scheduled-tasks"},
		{name: "custom path keeps sibling runtime", config: "/tmp/custom/tasks.json", wantPath: "/tmp/custom/scheduled-task-runtime"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scheduledTaskRuntimeDir(tc.config); got != tc.wantPath {
				t.Fatalf("scheduledTaskRuntimeDir(%q)=%q want=%q", tc.config, got, tc.wantPath)
			}
		})
	}
}

func TestPrepareScheduledTaskConfigRawMigratesLegacyExecutorFields(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php85", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.5",
		Version:     "PHP 8.5.0 (fpm-fcgi)",
	})
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}

	raw := `{
  "tasks": [
    {
      "name": "legacy-cron",
      "enabled": true,
      "schedule": "* * * * *",
      "runtime_id": "php85",
      "working_dir": "apps/app",
      "command": "artisan",
      "args": ["schedule:run"]
    }
  ]
}`
	prepared, err := prepareScheduledTaskConfigRaw(raw, currentPHPRuntimeInventoryConfig())
	if err != nil {
		t.Fatalf("prepareScheduledTaskConfigRaw: %v", err)
	}
	if len(prepared.cfg.Tasks) != 1 {
		t.Fatalf("task count=%d want=1", len(prepared.cfg.Tasks))
	}
	task := prepared.cfg.Tasks[0]
	if task.RuntimeID != "" || task.PHPBinaryPath != "" || task.WorkingDir != "" || len(task.Args) != 0 {
		t.Fatalf("legacy fields should be cleared after normalization: %+v", task)
	}
	if !strings.Contains(task.Command, "apps/app/artisan") {
		t.Fatalf("normalized command missing script path: %q", task.Command)
	}
	if !strings.Contains(task.Command, "schedule:run") {
		t.Fatalf("normalized command missing args: %q", task.Command)
	}
}

func TestInitScheduledTaskRuntimeLoadsDBBlobWithoutRestoringFile(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer func() {
		_ = InitLogsStatsStore(false, "", 0)
	}()

	raw := `{
  "tasks": [
    {
      "name": "db-task",
      "enabled": true,
      "schedule": "*/5 * * * *",
      "timezone": "UTC",
      "command": "/usr/bin/env true"
    }
  ]
}`
	store := getLogsStatsStore()
	if err := store.UpsertConfigBlob(scheduledTaskConfigBlobKey, []byte(raw), "", time.Now().UTC()); err != nil {
		t.Fatalf("UpsertConfigBlob: %v", err)
	}

	configPath := filepath.Join(tmp, "conf", "scheduled-tasks.json")
	if err := InitScheduledTaskRuntime(configPath, 2); err != nil {
		t.Fatalf("InitScheduledTaskRuntime: %v", err)
	}
	_, _, cfg, _, _ := ScheduledTaskConfigSnapshot()
	if len(cfg.Tasks) != 1 || cfg.Tasks[0].Name != "db-task" {
		t.Fatalf("tasks=%+v", cfg.Tasks)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("scheduled task file should not be restored, stat err=%v", err)
	}
	paths := CurrentScheduledTaskRuntimePaths()
	if got, want := paths.ConfigStorage, "db:scheduled_tasks"; got != want {
		t.Fatalf("config_storage=%q want=%q", got, want)
	}
}

func TestRunDueScheduledTasksExecutesCommandOncePerMinute(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "data", "php", "scheduled-tasks.json")
	outputPath := filepath.Join(tmp, "scheduled-task-output.log")
	phpBinaryPath := filepath.Join(tmp, "bin", "php")
	artisanPath := filepath.Join(tmp, "app", "artisan")

	if err := os.MkdirAll(filepath.Dir(phpBinaryPath), 0o755); err != nil {
		t.Fatalf("mkdir php dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(artisanPath), 0o755); err != nil {
		t.Fatalf("mkdir app dir: %v", err)
	}
	if err := os.WriteFile(artisanPath, []byte("<?php echo \"ok\";\n"), 0o644); err != nil {
		t.Fatalf("write artisan stub: %v", err)
	}
	if err := os.WriteFile(phpBinaryPath, []byte("#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"$TASK_OUTPUT\"\n"), 0o755); err != nil {
		t.Fatalf("write php stub: %v", err)
	}

	command := strings.Join([]string{
		shellQuoteCommandPart(phpBinaryPath),
		shellQuoteCommandPart(artisanPath),
		shellQuoteCommandPart("schedule:run"),
	}, " ")
	raw := mustJSON(ScheduledTaskConfigFile{
		Tasks: []ScheduledTaskRecord{
			{
				Name:       "app-cron",
				Enabled:    true,
				Schedule:   "* * * * *",
				Command:    command,
				Env:        map[string]string{"TASK_OUTPUT": outputPath},
				TimeoutSec: 30,
			},
		},
	})
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write scheduled task config: %v", err)
	}
	if err := InitScheduledTaskRuntime(configPath, 2); err != nil {
		t.Fatalf("InitScheduledTaskRuntime: %v", err)
	}

	now := time.Date(2026, 4, 15, 9, 30, 0, 0, time.UTC)
	if err := RunDueScheduledTasks(now); err != nil {
		t.Fatalf("RunDueScheduledTasks(first): %v", err)
	}
	if err := RunDueScheduledTasks(now.Add(30 * time.Second)); err != nil {
		t.Fatalf("RunDueScheduledTasks(same minute): %v", err)
	}
	if err := RunDueScheduledTasks(now.Add(1 * time.Minute)); err != nil {
		t.Fatalf("RunDueScheduledTasks(next minute): %v", err)
	}

	outputRaw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(outputRaw)), "\n")
	if got, want := len(lines), 2; got != want {
		t.Fatalf("output line count=%d want=%d raw=%q", got, want, string(outputRaw))
	}
	if !strings.Contains(string(outputRaw), artisanPath+" schedule:run") {
		t.Fatalf("unexpected task output: %q", string(outputRaw))
	}

	statuses, err := ScheduledTaskStatusSnapshot(configPath, currentScheduledTaskConfig())
	if err != nil {
		t.Fatalf("ScheduledTaskStatusSnapshot: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("status count=%d want=1", len(statuses))
	}
	if statuses[0].LastResult != "success" {
		t.Fatalf("last_result=%q want=success", statuses[0].LastResult)
	}
	if statuses[0].ResolvedCommand != command {
		t.Fatalf("resolved_command=%q want=%q", statuses[0].ResolvedCommand, command)
	}
}
