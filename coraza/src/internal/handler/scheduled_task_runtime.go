package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"tukuyomi/internal/bypassconf"
)

const (
	defaultScheduledTaskConfigRaw  = "{\n  \"tasks\": []\n}\n"
	defaultScheduledTaskTimeout    = 300
	maxScheduledTaskTimeout        = 86400
	defaultScheduledTaskConfigPath = "conf/scheduled-tasks.json"
	defaultScheduledTaskRuntimeDir = "data/scheduled-tasks"
	scheduledTaskConfigBlobKey     = "scheduled_tasks"
)

type ScheduledTaskConfigFile struct {
	Tasks []ScheduledTaskRecord `json:"tasks,omitempty"`
}

type ScheduledTaskRecord struct {
	Name       string            `json:"name,omitempty"`
	Enabled    bool              `json:"enabled"`
	Schedule   string            `json:"schedule,omitempty"`
	Timezone   string            `json:"timezone,omitempty"`
	Command    string            `json:"command,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	TimeoutSec int               `json:"timeout_sec,omitempty"`

	// Legacy compatibility for the initial scheduled task draft format.
	DisplayName   string   `json:"display_name,omitempty"`
	RuntimeID     string   `json:"runtime_id,omitempty"`
	PHPBinaryPath string   `json:"php_binary_path,omitempty"`
	WorkingDir    string   `json:"working_dir,omitempty"`
	Args          []string `json:"args,omitempty"`
}

type ScheduledTaskStatus struct {
	Name               string `json:"name"`
	Running            bool   `json:"running"`
	PID                int    `json:"pid,omitempty"`
	LastScheduleMinute string `json:"last_schedule_minute,omitempty"`
	LastStartedAt      string `json:"last_started_at,omitempty"`
	LastFinishedAt     string `json:"last_finished_at,omitempty"`
	LastResult         string `json:"last_result,omitempty"`
	LastError          string `json:"last_error,omitempty"`
	LastExitCode       int    `json:"last_exit_code,omitempty"`
	LastDurationMS     int64  `json:"last_duration_ms,omitempty"`
	LogFile            string `json:"log_file,omitempty"`
	ResolvedCommand    string `json:"resolved_command,omitempty"`
}

type ScheduledTaskRuntimePaths struct {
	ConfigFile    string `json:"config_file"`
	ConfigStorage string `json:"config_storage,omitempty"`
	RuntimeDir    string `json:"runtime_dir"`
	StateFile     string `json:"state_file"`
	LogDir        string `json:"log_dir"`
}

type scheduledTaskStateFile struct {
	Tasks map[string]ScheduledTaskStatus `json:"tasks,omitempty"`
}

type scheduledTaskPreparedConfig struct {
	cfg       ScheduledTaskConfigFile
	raw       string
	etag      string
	versionID int64
}

type scheduledTaskRuntime struct {
	mu            sync.RWMutex
	configPath    string
	raw           string
	etag          string
	versionID     int64
	cfg           ScheduledTaskConfigFile
	rollbackMax   int
	rollbackStack []proxyRollbackEntry
}

var (
	scheduledTaskRuntimeMu sync.RWMutex
	scheduledTaskRt        *scheduledTaskRuntime
)

func InitScheduledTaskRuntime(path string, rollbackMax int) error {
	configPath := strings.TrimSpace(path)
	if configPath == "" {
		configPath = defaultScheduledTaskConfigPath
	}
	prepared, err := loadScheduledTaskPreparedConfig(configPath)
	if err != nil {
		return fmt.Errorf("initialize scheduled task config (%s): %w", configPath, err)
	}
	rt := &scheduledTaskRuntime{
		configPath:    configPath,
		raw:           prepared.raw,
		etag:          prepared.etag,
		versionID:     prepared.versionID,
		cfg:           prepared.cfg,
		rollbackMax:   clampProxyRollbackMax(rollbackMax),
		rollbackStack: make([]proxyRollbackEntry, 0, clampProxyRollbackMax(rollbackMax)),
	}
	scheduledTaskRuntimeMu.Lock()
	scheduledTaskRt = rt
	scheduledTaskRuntimeMu.Unlock()
	return nil
}

func loadScheduledTaskPreparedConfig(configPath string) (scheduledTaskPreparedConfig, error) {
	store := getLogsStatsStore()
	if store != nil {
		cfg, rec, found, err := store.loadActiveScheduledTaskConfig()
		if err != nil {
			return scheduledTaskPreparedConfig{}, err
		}
		if found {
			prepared, err := prepareScheduledTaskConfigRaw(mustJSON(cfg), currentPHPRuntimeInventoryConfig())
			if err != nil {
				return scheduledTaskPreparedConfig{}, err
			}
			prepared.etag = rec.ETag
			prepared.versionID = rec.VersionID
			return prepared, nil
		}
		if dbRaw, _, legacyFound, err := store.GetConfigBlob(scheduledTaskConfigBlobKey); err != nil {
			return scheduledTaskPreparedConfig{}, err
		} else if legacyFound {
			prepared, err := prepareScheduledTaskConfigRaw(string(dbRaw), currentPHPRuntimeInventoryConfig())
			if err != nil {
				return scheduledTaskPreparedConfig{}, err
			}
			rec, err := store.writeScheduledTaskConfigVersion("", prepared.cfg, configVersionSourceImport, "", "legacy scheduled tasks import", 0)
			if err != nil {
				return scheduledTaskPreparedConfig{}, err
			}
			_ = store.DeleteConfigBlob(scheduledTaskConfigBlobKey)
			prepared.etag = rec.ETag
			prepared.versionID = rec.VersionID
			return prepared, nil
		}
		return scheduledTaskPreparedConfig{}, fmt.Errorf("normalized scheduled task config missing in db; run make db-import before removing seed files")
	}

	raw, err := loadScheduledTaskConfigRaw(configPath)
	if err != nil {
		return scheduledTaskPreparedConfig{}, err
	}
	if strings.TrimSpace(raw) == "" {
		raw = defaultScheduledTaskConfigRaw
	}
	prepared, err := prepareScheduledTaskConfigRaw(raw, currentPHPRuntimeInventoryConfig())
	if err != nil {
		return scheduledTaskPreparedConfig{}, err
	}
	if store != nil {
		rec, err := store.writeScheduledTaskConfigVersion("", prepared.cfg, configVersionSourceImport, "", "scheduled tasks file import", 0)
		if err != nil {
			return scheduledTaskPreparedConfig{}, err
		}
		prepared.etag = rec.ETag
		prepared.versionID = rec.VersionID
	}
	return prepared, nil
}

func scheduledTaskRuntimeInstance() *scheduledTaskRuntime {
	scheduledTaskRuntimeMu.RLock()
	defer scheduledTaskRuntimeMu.RUnlock()
	return scheduledTaskRt
}

func currentScheduledTaskConfigPath() string {
	rt := scheduledTaskRuntimeInstance()
	if rt != nil {
		rt.mu.RLock()
		defer rt.mu.RUnlock()
		return rt.configPath
	}
	return defaultScheduledTaskConfigPath
}

func currentScheduledTaskConfig() ScheduledTaskConfigFile {
	rt := scheduledTaskRuntimeInstance()
	if rt == nil {
		return ScheduledTaskConfigFile{}
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return cloneScheduledTaskConfigFile(rt.cfg)
}

func ScheduledTaskConfigSnapshot() (raw string, etag string, cfg ScheduledTaskConfigFile, statuses []ScheduledTaskStatus, rollbackDepth int) {
	rt := scheduledTaskRuntimeInstance()
	if rt == nil {
		cfg = ScheduledTaskConfigFile{}
		return defaultScheduledTaskConfigRaw, bypassconf.ComputeETag([]byte(defaultScheduledTaskConfigRaw)), cfg, nil, 0
	}
	rt.mu.RLock()
	raw = rt.raw
	etag = rt.etag
	cfg = cloneScheduledTaskConfigFile(rt.cfg)
	configPath := rt.configPath
	rollbackDepth = len(rt.rollbackStack)
	rt.mu.RUnlock()
	statuses, _ = ScheduledTaskStatusSnapshot(configPath, cfg)
	return raw, etag, cfg, statuses, rollbackDepth
}

func ValidateScheduledTaskConfigRaw(raw string) (ScheduledTaskConfigFile, error) {
	prepared, err := prepareScheduledTaskConfigRaw(raw, currentPHPRuntimeInventoryConfig())
	if err != nil {
		return ScheduledTaskConfigFile{}, err
	}
	return cloneScheduledTaskConfigFile(prepared.cfg), nil
}

func ApplyScheduledTaskConfigRaw(ifMatch string, raw string) (string, ScheduledTaskConfigFile, error) {
	rt := scheduledTaskRuntimeInstance()
	if rt == nil {
		return "", ScheduledTaskConfigFile{}, fmt.Errorf("scheduled task runtime is not initialized")
	}
	prepared, err := prepareScheduledTaskConfigRaw(raw, currentPHPRuntimeInventoryConfig())
	if err != nil {
		return "", ScheduledTaskConfigFile{}, err
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if ifMatch = strings.TrimSpace(ifMatch); ifMatch != "" && ifMatch != rt.etag {
		return "", ScheduledTaskConfigFile{}, proxyRulesConflictError{CurrentETag: rt.etag}
	}

	prevRaw := rt.raw
	prevETag := rt.etag
	prevVersionID := rt.versionID
	prevCfg := cloneScheduledTaskConfigFile(rt.cfg)
	nextETag, nextVersionID, err := persistScheduledTaskConfigAuthoritative(rt.configPath, rt.etag, prepared, configVersionSourceApply, 0)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			return "", ScheduledTaskConfigFile{}, proxyRulesConflictError{CurrentETag: rt.etag}
		}
		return "", ScheduledTaskConfigFile{}, err
	}
	prepared.etag = nextETag
	prepared.versionID = nextVersionID
	rt.raw = prepared.raw
	rt.etag = prepared.etag
	rt.versionID = prepared.versionID
	rt.cfg = cloneScheduledTaskConfigFile(prepared.cfg)
	rt.pushRollbackLocked(proxyRollbackEntry{
		Raw:       prevRaw,
		ETag:      prevETag,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err := pruneScheduledTaskState(rt.configPath, prepared.cfg); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		if restoredETag, restoredVersionID, restoreErr := persistScheduledTaskConfigAuthoritative(rt.configPath, prepared.etag, scheduledTaskPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceRollback, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		return "", ScheduledTaskConfigFile{}, err
	}
	return rt.etag, cloneScheduledTaskConfigFile(rt.cfg), nil
}

func RollbackScheduledTaskConfig() (string, ScheduledTaskConfigFile, proxyRollbackEntry, error) {
	rt := scheduledTaskRuntimeInstance()
	if rt == nil {
		return "", ScheduledTaskConfigFile{}, proxyRollbackEntry{}, fmt.Errorf("scheduled task runtime is not initialized")
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if len(rt.rollbackStack) == 0 {
		return "", ScheduledTaskConfigFile{}, proxyRollbackEntry{}, fmt.Errorf("no rollback snapshot")
	}
	entry := rt.rollbackStack[len(rt.rollbackStack)-1]
	rt.rollbackStack = rt.rollbackStack[:len(rt.rollbackStack)-1]

	prepared, err := prepareScheduledTaskConfigRaw(entry.Raw, currentPHPRuntimeInventoryConfig())
	if err != nil {
		rt.pushRollbackLocked(entry)
		return "", ScheduledTaskConfigFile{}, proxyRollbackEntry{}, err
	}

	prevRaw := rt.raw
	prevETag := rt.etag
	prevVersionID := rt.versionID
	prevCfg := cloneScheduledTaskConfigFile(rt.cfg)
	restoredVersionID := int64(0)
	if store := getLogsStatsStore(); store != nil {
		if foundID, found, err := store.findConfigVersionIDByETag(scheduledTaskConfigDomain, entry.ETag); err == nil && found {
			restoredVersionID = foundID
		}
	}
	nextETag, nextVersionID, err := persistScheduledTaskConfigAuthoritative(rt.configPath, rt.etag, prepared, configVersionSourceRollback, restoredVersionID)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			return "", ScheduledTaskConfigFile{}, proxyRollbackEntry{}, proxyRulesConflictError{CurrentETag: rt.etag}
		}
		rt.pushRollbackLocked(entry)
		return "", ScheduledTaskConfigFile{}, proxyRollbackEntry{}, err
	}
	prepared.etag = nextETag
	prepared.versionID = nextVersionID
	rt.raw = prepared.raw
	rt.etag = prepared.etag
	rt.versionID = prepared.versionID
	rt.cfg = cloneScheduledTaskConfigFile(prepared.cfg)
	if err := pruneScheduledTaskState(rt.configPath, prepared.cfg); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		if restoredETag, restoredVersionID, restoreErr := persistScheduledTaskConfigAuthoritative(rt.configPath, prepared.etag, scheduledTaskPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceApply, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		rt.pushRollbackLocked(entry)
		return "", ScheduledTaskConfigFile{}, proxyRollbackEntry{}, err
	}
	return rt.etag, cloneScheduledTaskConfigFile(rt.cfg), entry, nil
}

func SyncScheduledTaskStorage() error {
	store := getLogsStatsStore()
	rt := scheduledTaskRuntimeInstance()
	if store == nil || rt == nil {
		return nil
	}
	cfg, rec, found, err := store.loadActiveScheduledTaskConfig()
	if err != nil {
		return err
	}
	if !found {
		rt.mu.RLock()
		cfg := cloneScheduledTaskConfigFile(rt.cfg)
		rt.mu.RUnlock()
		_, err := store.writeScheduledTaskConfigVersion("", cfg, configVersionSourceImport, "", "scheduled tasks runtime import", 0)
		return err
	}
	prepared, err := prepareScheduledTaskConfigRaw(mustJSON(cfg), currentPHPRuntimeInventoryConfig())
	if err != nil {
		return err
	}
	prepared.etag = rec.ETag
	prepared.versionID = rec.VersionID

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if prepared.etag == rt.etag {
		return nil
	}
	prevRaw := rt.raw
	prevETag := rt.etag
	prevVersionID := rt.versionID
	prevCfg := cloneScheduledTaskConfigFile(rt.cfg)
	rt.raw = prepared.raw
	rt.etag = prepared.etag
	rt.versionID = prepared.versionID
	rt.cfg = cloneScheduledTaskConfigFile(prepared.cfg)
	if err := pruneScheduledTaskState(rt.configPath, prepared.cfg); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		return err
	}
	return nil
}

func ScheduledTaskStatusSnapshot(configPath string, cfg ScheduledTaskConfigFile) ([]ScheduledTaskStatus, error) {
	var out []ScheduledTaskStatus
	err := withScheduledTaskStateLocked(configPath, func(state *scheduledTaskStateFile) error {
		if state.Tasks == nil {
			state.Tasks = map[string]ScheduledTaskStatus{}
		}
		changed := false
		out = make([]ScheduledTaskStatus, 0, len(cfg.Tasks))
		for _, task := range cfg.Tasks {
			status := state.Tasks[task.Name]
			if status.Name == "" {
				status.Name = task.Name
			}
			if status.Running && status.PID > 0 && !scheduledTaskPIDAlive(status.PID) {
				status.Running = false
				status.PID = 0
				if status.LastResult == "" {
					status.LastResult = "abandoned"
				}
				state.Tasks[task.Name] = status
				changed = true
			}
			out = append(out, status)
		}
		if changed {
			return persistScheduledTaskStateUnlocked(scheduledTaskStatePath(configPath), *state)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func RunDueScheduledTasks(now time.Time) error {
	cfg := currentScheduledTaskConfig()
	var failures []string
	for _, task := range cfg.Tasks {
		if !task.Enabled {
			continue
		}
		due, scheduleMinute, err := scheduledTaskMatchesNow(task, now)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", task.Name, err))
			continue
		}
		if !due {
			continue
		}
		if executed, err := runScheduledTaskIfDue(task, currentScheduledTaskConfigPath(), now, scheduleMinute); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", task.Name, err))
		} else if executed {
			// no-op; status already persisted
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func runScheduledTaskIfDue(task ScheduledTaskRecord, configPath string, now time.Time, scheduleMinute string) (bool, error) {
	lock, acquired, err := acquireScheduledTaskExecutionLock(configPath, task.Name)
	if err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}
	defer lock.release()

	statuses, err := ScheduledTaskStatusSnapshot(configPath, ScheduledTaskConfigFile{Tasks: []ScheduledTaskRecord{task}})
	if err != nil {
		return false, err
	}
	if len(statuses) > 0 && statuses[0].LastScheduleMinute == scheduleMinute {
		return false, nil
	}
	return true, executeScheduledTask(task, configPath, now, scheduleMinute)
}

func executeScheduledTask(task ScheduledTaskRecord, configPath string, now time.Time, scheduleMinute string) error {
	logPath := scheduledTaskLogPath(configPath, task.Name)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close()

	timeout := time.Duration(task.TimeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-lc", task.Command)
	cmd.Env = append(os.Environ(), scheduledTaskEnvList(task.Env)...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	startedAt := time.Now().UTC()
	_ = updateScheduledTaskStatus(configPath, task.Name, func(status *ScheduledTaskStatus) {
		status.Name = task.Name
		status.Running = true
		status.PID = 0
		status.LastScheduleMinute = scheduleMinute
		status.LastStartedAt = startedAt.Format(time.RFC3339Nano)
		status.LastFinishedAt = ""
		status.LastResult = "running"
		status.LastError = ""
		status.LastExitCode = 0
		status.LastDurationMS = 0
		status.LogFile = logPath
		status.ResolvedCommand = task.Command
	})

	if err := cmd.Start(); err != nil {
		_ = updateScheduledTaskStatus(configPath, task.Name, func(status *ScheduledTaskStatus) {
			status.Name = task.Name
			status.Running = false
			status.PID = 0
			status.LastFinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
			status.LastResult = "failed"
			status.LastError = err.Error()
			status.LogFile = logPath
			status.ResolvedCommand = task.Command
		})
		return err
	}

	_ = updateScheduledTaskStatus(configPath, task.Name, func(status *ScheduledTaskStatus) {
		status.Name = task.Name
		status.Running = true
		status.PID = cmd.Process.Pid
		status.LogFile = logPath
		status.ResolvedCommand = task.Command
	})

	waitErr := cmd.Wait()
	finishedAt := time.Now().UTC()
	durationMS := finishedAt.Sub(startedAt).Milliseconds()
	exitCode := 0
	lastResult := "success"
	lastErr := ""
	if waitErr != nil {
		lastResult = "failed"
		lastErr = waitErr.Error()
		var exitErr *exec.ExitError
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			lastResult = "timeout"
			lastErr = "execution timed out"
			exitCode = -1
		case errors.As(waitErr, &exitErr):
			exitCode = exitErr.ExitCode()
		default:
			exitCode = -1
		}
	}

	_ = updateScheduledTaskStatus(configPath, task.Name, func(status *ScheduledTaskStatus) {
		status.Name = task.Name
		status.Running = false
		status.PID = 0
		status.LastFinishedAt = finishedAt.Format(time.RFC3339Nano)
		status.LastResult = lastResult
		status.LastError = lastErr
		status.LastExitCode = exitCode
		status.LastDurationMS = durationMS
		status.LogFile = logPath
		status.ResolvedCommand = task.Command
	})

	return waitErr
}

func prepareScheduledTaskConfigRaw(raw string, inventory PHPRuntimeInventoryFile) (scheduledTaskPreparedConfig, error) {
	cfg, err := parseScheduledTaskConfigRaw(raw)
	if err != nil {
		return scheduledTaskPreparedConfig{}, err
	}
	cfg = normalizeScheduledTaskConfigFile(cfg, inventory)
	if err := validateScheduledTaskConfigFile(cfg, inventory); err != nil {
		return scheduledTaskPreparedConfig{}, err
	}
	normalizedRaw := mustJSON(cfg)
	return scheduledTaskPreparedConfig{
		cfg:  cfg,
		raw:  normalizedRaw,
		etag: bypassconf.ComputeETag([]byte(normalizedRaw)),
	}, nil
}

func parseScheduledTaskConfigRaw(raw string) (ScheduledTaskConfigFile, error) {
	var cfg ScheduledTaskConfigFile
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return ScheduledTaskConfigFile{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return ScheduledTaskConfigFile{}, fmt.Errorf("invalid json")
	}
	return cfg, nil
}

func normalizeScheduledTaskConfigFile(in ScheduledTaskConfigFile, inventory PHPRuntimeInventoryFile) ScheduledTaskConfigFile {
	out := ScheduledTaskConfigFile{
		Tasks: make([]ScheduledTaskRecord, 0, len(in.Tasks)),
	}
	for _, task := range in.Tasks {
		task.Name = normalizeConfigToken(task.Name)
		task.Schedule = strings.TrimSpace(task.Schedule)
		task.Timezone = strings.TrimSpace(task.Timezone)
		task.Command = strings.TrimSpace(task.Command)
		task.Env = normalizeScheduledTaskEnv(task.Env)
		task.TimeoutSec = normalizeScheduledTaskTimeout(task.TimeoutSec)
		task.RuntimeID = normalizeConfigToken(task.RuntimeID)
		task.PHPBinaryPath = strings.TrimSpace(task.PHPBinaryPath)
		task.WorkingDir = strings.TrimSpace(task.WorkingDir)
		task.Args = normalizeScheduledTaskArgs(task.Args)
		task.Command = normalizeScheduledTaskCommand(task, inventory)
		task.DisplayName = ""
		task.RuntimeID = ""
		task.PHPBinaryPath = ""
		task.WorkingDir = ""
		task.Args = nil
		out.Tasks = append(out.Tasks, task)
	}
	return out
}

func normalizeScheduledTaskArgs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, arg := range in {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		out = append(out, arg)
	}
	return out
}

func normalizeScheduledTaskEnv(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeScheduledTaskTimeout(v int) int {
	switch {
	case v <= 0:
		return defaultScheduledTaskTimeout
	case v > maxScheduledTaskTimeout:
		return maxScheduledTaskTimeout
	default:
		return v
	}
}

func validateScheduledTaskConfigFile(cfg ScheduledTaskConfigFile, inventory PHPRuntimeInventoryFile) error {
	seen := make(map[string]struct{}, len(cfg.Tasks))
	for i, task := range cfg.Tasks {
		field := fmt.Sprintf("tasks[%d]", i)
		if task.Name == "" {
			return fmt.Errorf("%s.name is required", field)
		}
		if !isValidConfigToken(task.Name) {
			return fmt.Errorf("%s.name must contain only [a-z0-9._-]", field)
		}
		if _, exists := seen[task.Name]; exists {
			return fmt.Errorf("%s.name duplicates %q", field, task.Name)
		}
		seen[task.Name] = struct{}{}
		if task.Schedule == "" {
			return fmt.Errorf("%s.schedule is required", field)
		}
		if _, err := parseScheduledTaskSchedule(task.Schedule); err != nil {
			return fmt.Errorf("%s.schedule: %w", field, err)
		}
		if task.Timezone != "" {
			if _, err := time.LoadLocation(task.Timezone); err != nil {
				return fmt.Errorf("%s.timezone: %w", field, err)
			}
		}
		if task.Command == "" {
			return fmt.Errorf("%s.command is required", field)
		}
		if strings.ContainsRune(task.Command, '\x00') {
			return fmt.Errorf("%s.command contains NUL", field)
		}
		if task.TimeoutSec < 1 || task.TimeoutSec > maxScheduledTaskTimeout {
			return fmt.Errorf("%s.timeout_sec must be between 1 and %d", field, maxScheduledTaskTimeout)
		}
		for key := range task.Env {
			if !isValidScheduledTaskEnvKey(key) {
				return fmt.Errorf("%s.env key %q is invalid", field, key)
			}
		}
	}
	return nil
}

func cloneScheduledTaskConfigFile(in ScheduledTaskConfigFile) ScheduledTaskConfigFile {
	out := ScheduledTaskConfigFile{
		Tasks: make([]ScheduledTaskRecord, 0, len(in.Tasks)),
	}
	for _, task := range in.Tasks {
		cloned := task
		if len(task.Args) > 0 {
			cloned.Args = append([]string(nil), task.Args...)
		}
		if len(task.Env) > 0 {
			cloned.Env = make(map[string]string, len(task.Env))
			for key, value := range task.Env {
				cloned.Env[key] = value
			}
		}
		out.Tasks = append(out.Tasks, cloned)
	}
	return out
}

func persistScheduledTaskConfigRaw(path string, raw string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("scheduled task config path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return bypassconf.AtomicWriteWithBackup(path, []byte(raw))
}

func persistScheduledTaskConfigAuthoritative(path string, expectedETag string, prepared scheduledTaskPreparedConfig, source string, restoredFromVersionID int64) (string, int64, error) {
	if store := getLogsStatsStore(); store != nil {
		rec, err := store.writeScheduledTaskConfigVersion(expectedETag, prepared.cfg, source, "", "scheduled tasks config update", restoredFromVersionID)
		if err != nil {
			return "", 0, err
		}
		return rec.ETag, rec.VersionID, nil
	}
	if err := persistScheduledTaskConfigRaw(path, prepared.raw); err != nil {
		return "", 0, err
	}
	return prepared.etag, 0, nil
}

func loadScheduledTaskConfigRaw(configPath string) (string, error) {
	rawBytes, _, err := readFileMaybe(configPath)
	if err != nil {
		return "", err
	}
	return string(rawBytes), nil
}

func scheduledTaskRuntimeDir(configPath string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return defaultScheduledTaskRuntimeDir
	}
	dir := filepath.Clean(filepath.Dir(configPath))
	if filepath.Base(dir) == "conf" {
		parent := filepath.Dir(dir)
		if filepath.Base(parent) == "data" {
			return filepath.Join(parent, "scheduled-tasks")
		}
		return filepath.Join(parent, "data", "scheduled-tasks")
	}
	return filepath.Join(dir, "scheduled-task-runtime")
}

func scheduledTaskStatePath(configPath string) string {
	return filepath.Join(scheduledTaskRuntimeDir(configPath), "state.json")
}

func scheduledTaskLockDir(configPath string) string {
	return filepath.Join(scheduledTaskRuntimeDir(configPath), "locks")
}

func scheduledTaskLogPath(configPath string, taskName string) string {
	return filepath.Join(scheduledTaskRuntimeDir(configPath), "logs", taskName+".log")
}

func CurrentScheduledTaskRuntimePaths() ScheduledTaskRuntimePaths {
	configPath := currentScheduledTaskConfigPath()
	runtimeDir := scheduledTaskRuntimeDir(configPath)
	return ScheduledTaskRuntimePaths{
		ConfigFile:    configPath,
		ConfigStorage: scheduledTaskConfigStorageLabel(configPath),
		RuntimeDir:    runtimeDir,
		StateFile:     scheduledTaskStatePath(configPath),
		LogDir:        filepath.Join(runtimeDir, "logs"),
	}
}

func scheduledTaskConfigStorageLabel(configPath string) string {
	if getLogsStatsStore() != nil {
		return "db:" + scheduledTaskConfigBlobKey
	}
	if strings.TrimSpace(configPath) == "" {
		return "memory"
	}
	return configPath
}

func loadScheduledTaskStateUnlocked(statePath string) (scheduledTaskStateFile, error) {
	raw, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return scheduledTaskStateFile{Tasks: map[string]ScheduledTaskStatus{}}, nil
		}
		return scheduledTaskStateFile{}, err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return scheduledTaskStateFile{Tasks: map[string]ScheduledTaskStatus{}}, nil
	}
	var state scheduledTaskStateFile
	if err := json.Unmarshal(raw, &state); err != nil {
		return scheduledTaskStateFile{}, fmt.Errorf("parse scheduled task state: %w", err)
	}
	if state.Tasks == nil {
		state.Tasks = map[string]ScheduledTaskStatus{}
	}
	return state, nil
}

func persistScheduledTaskStateUnlocked(statePath string, state scheduledTaskStateFile) error {
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return bypassconf.AtomicWriteWithBackup(statePath, append(raw, '\n'))
}

func withScheduledTaskStateLocked(configPath string, fn func(*scheduledTaskStateFile) error) error {
	runtimeDir := scheduledTaskRuntimeDir(configPath)
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return err
	}
	lockPath := filepath.Join(runtimeDir, "state.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	statePath := scheduledTaskStatePath(configPath)
	state, err := loadScheduledTaskStateUnlocked(statePath)
	if err != nil {
		return err
	}
	return fn(&state)
}

func updateScheduledTaskStatus(configPath string, taskName string, fn func(*ScheduledTaskStatus)) error {
	return withScheduledTaskStateLocked(configPath, func(state *scheduledTaskStateFile) error {
		status := state.Tasks[taskName]
		status.Name = taskName
		fn(&status)
		state.Tasks[taskName] = status
		return persistScheduledTaskStateUnlocked(scheduledTaskStatePath(configPath), *state)
	})
}

func pruneScheduledTaskState(configPath string, cfg ScheduledTaskConfigFile) error {
	allowed := make(map[string]struct{}, len(cfg.Tasks))
	for _, task := range cfg.Tasks {
		allowed[task.Name] = struct{}{}
	}
	return withScheduledTaskStateLocked(configPath, func(state *scheduledTaskStateFile) error {
		changed := false
		for name := range state.Tasks {
			if _, ok := allowed[name]; ok {
				continue
			}
			delete(state.Tasks, name)
			changed = true
		}
		if !changed {
			return nil
		}
		return persistScheduledTaskStateUnlocked(scheduledTaskStatePath(configPath), *state)
	})
}

type scheduledTaskExecutionLock struct {
	file *os.File
}

func acquireScheduledTaskExecutionLock(configPath string, taskName string) (*scheduledTaskExecutionLock, bool, error) {
	lockDir := scheduledTaskLockDir(configPath)
	if err := os.MkdirAll(lockDir, 0o755); err != nil {
		return nil, false, err
	}
	lockPath := filepath.Join(lockDir, taskName+".lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockFile.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, false, nil
		}
		return nil, false, err
	}
	_ = lockFile.Truncate(0)
	_, _ = lockFile.WriteString(strconv.Itoa(os.Getpid()))
	return &scheduledTaskExecutionLock{file: lockFile}, true, nil
}

func (l *scheduledTaskExecutionLock) release() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
}

func scheduledTaskPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func normalizeScheduledTaskCommand(task ScheduledTaskRecord, inventory PHPRuntimeInventoryFile) string {
	command := strings.TrimSpace(task.Command)
	if task.RuntimeID == "" && task.PHPBinaryPath == "" && task.WorkingDir == "" && len(task.Args) == 0 {
		return command
	}

	phpBinaryPath := strings.TrimSpace(task.PHPBinaryPath)
	if phpBinaryPath == "" && strings.TrimSpace(task.RuntimeID) != "" {
		idx := findPHPRuntimeRecordIndex(inventory, task.RuntimeID)
		if idx >= 0 {
			phpBinaryPath = strings.TrimSpace(inventory.Runtimes[idx].CLIBinaryPath)
		}
	}
	commandPath := command
	if commandPath != "" && task.WorkingDir != "" && !filepath.IsAbs(commandPath) {
		commandPath = filepath.Join(task.WorkingDir, commandPath)
	}
	parts := make([]string, 0, len(task.Args)+2)
	if phpBinaryPath != "" {
		parts = append(parts, shellQuoteCommandPart(phpBinaryPath))
	}
	if commandPath != "" {
		parts = append(parts, shellQuoteCommandPart(commandPath))
	}
	for _, arg := range task.Args {
		parts = append(parts, shellQuoteCommandPart(arg))
	}
	if len(parts) == 0 {
		return command
	}
	return strings.Join(parts, " ")
}

func shellQuoteCommandPart(part string) string {
	part = strings.TrimSpace(part)
	if part == "" {
		return "''"
	}
	if !strings.ContainsAny(part, " \t\n'\"\\$&|;<>*?()[]{}!") {
		return part
	}
	return "'" + strings.ReplaceAll(part, "'", `'"'"'`) + "'"
}

func scheduledTaskEnvList(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+env[key])
	}
	return out
}

func isValidScheduledTaskEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '_' && i >= 0:
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func scheduledTaskMatchesNow(task ScheduledTaskRecord, now time.Time) (bool, string, error) {
	location := time.Local
	if strings.TrimSpace(task.Timezone) != "" {
		loc, err := time.LoadLocation(task.Timezone)
		if err != nil {
			return false, "", err
		}
		location = loc
	}
	matched, minute, err := scheduledTaskScheduleMatches(task.Schedule, location, now)
	if err != nil {
		return false, "", err
	}
	return matched, minute, nil
}

type scheduledTaskCronField struct {
	Any    bool
	Values map[int]struct{}
}

func (f scheduledTaskCronField) matches(value int) bool {
	if f.Any {
		return true
	}
	_, ok := f.Values[value]
	return ok
}

func parseScheduledTaskSchedule(spec string) ([5]scheduledTaskCronField, error) {
	spec = strings.TrimSpace(spec)
	switch spec {
	case "@hourly":
		spec = "0 * * * *"
	case "@daily", "@midnight":
		spec = "0 0 * * *"
	case "@weekly":
		spec = "0 0 * * 0"
	case "@monthly":
		spec = "0 0 1 * *"
	default:
	}
	parts := strings.Fields(spec)
	if len(parts) != 5 {
		return [5]scheduledTaskCronField{}, fmt.Errorf("expected 5 cron fields")
	}
	fields := [5]scheduledTaskCronField{}
	var err error
	if fields[0], err = parseScheduledTaskCronField(parts[0], 0, 59, false); err != nil {
		return [5]scheduledTaskCronField{}, fmt.Errorf("minute: %w", err)
	}
	if fields[1], err = parseScheduledTaskCronField(parts[1], 0, 23, false); err != nil {
		return [5]scheduledTaskCronField{}, fmt.Errorf("hour: %w", err)
	}
	if fields[2], err = parseScheduledTaskCronField(parts[2], 1, 31, false); err != nil {
		return [5]scheduledTaskCronField{}, fmt.Errorf("day_of_month: %w", err)
	}
	if fields[3], err = parseScheduledTaskCronField(parts[3], 1, 12, false); err != nil {
		return [5]scheduledTaskCronField{}, fmt.Errorf("month: %w", err)
	}
	if fields[4], err = parseScheduledTaskCronField(parts[4], 0, 7, true); err != nil {
		return [5]scheduledTaskCronField{}, fmt.Errorf("day_of_week: %w", err)
	}
	return fields, nil
}

func parseScheduledTaskCronField(spec string, min int, max int, normalizeSunday bool) (scheduledTaskCronField, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return scheduledTaskCronField{}, fmt.Errorf("empty field")
	}
	if spec == "*" {
		return scheduledTaskCronField{Any: true}, nil
	}
	values := make(map[int]struct{})
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return scheduledTaskCronField{}, fmt.Errorf("empty list item")
		}
		step := 1
		base := part
		if slash := strings.Index(base, "/"); slash >= 0 {
			stepValue, err := strconv.Atoi(base[slash+1:])
			if err != nil || stepValue <= 0 {
				return scheduledTaskCronField{}, fmt.Errorf("invalid step %q", base[slash+1:])
			}
			step = stepValue
			base = base[:slash]
		}
		rangeStart := min
		rangeEnd := max
		switch {
		case base == "*":
		case strings.Contains(base, "-"):
			parts := strings.SplitN(base, "-", 2)
			if len(parts) != 2 {
				return scheduledTaskCronField{}, fmt.Errorf("invalid range %q", base)
			}
			start, err := strconv.Atoi(parts[0])
			if err != nil {
				return scheduledTaskCronField{}, fmt.Errorf("invalid value %q", parts[0])
			}
			end, err := strconv.Atoi(parts[1])
			if err != nil {
				return scheduledTaskCronField{}, fmt.Errorf("invalid value %q", parts[1])
			}
			rangeStart = start
			rangeEnd = end
		default:
			value, err := strconv.Atoi(base)
			if err != nil {
				return scheduledTaskCronField{}, fmt.Errorf("invalid value %q", base)
			}
			rangeStart = value
			rangeEnd = value
		}
		if normalizeSunday {
			if rangeStart == 7 {
				rangeStart = 0
			}
			if rangeEnd == 7 {
				rangeEnd = 0
			}
		}
		if rangeStart < min || rangeStart > max || rangeEnd < min || rangeEnd > max {
			return scheduledTaskCronField{}, fmt.Errorf("value out of range")
		}
		if !normalizeSunday && rangeEnd < rangeStart {
			return scheduledTaskCronField{}, fmt.Errorf("range end before start")
		}
		if normalizeSunday && rangeStart == 0 && rangeEnd != 0 && strings.Contains(base, "-") {
			return scheduledTaskCronField{}, fmt.Errorf("range end before start")
		}
		for value := rangeStart; value <= rangeEnd; value += step {
			normalized := value
			if normalizeSunday && normalized == 7 {
				normalized = 0
			}
			values[normalized] = struct{}{}
		}
	}
	return scheduledTaskCronField{Values: values}, nil
}

func scheduledTaskScheduleMatches(spec string, location *time.Location, now time.Time) (bool, string, error) {
	fields, err := parseScheduledTaskSchedule(spec)
	if err != nil {
		return false, "", err
	}
	if location == nil {
		location = time.Local
	}
	current := now.In(location).Truncate(time.Minute)
	minuteMatch := fields[0].matches(current.Minute())
	hourMatch := fields[1].matches(current.Hour())
	monthMatch := fields[3].matches(int(current.Month()))
	domMatch := fields[2].matches(current.Day())
	dowMatch := fields[4].matches(int(current.Weekday()))
	dayMatch := false
	switch {
	case fields[2].Any && fields[4].Any:
		dayMatch = true
	case fields[2].Any:
		dayMatch = dowMatch
	case fields[4].Any:
		dayMatch = domMatch
	default:
		dayMatch = domMatch || dowMatch
	}
	return minuteMatch && hourMatch && monthMatch && dayMatch, current.Format("2006-01-02T15:04Z07:00"), nil
}

func (rt *scheduledTaskRuntime) pushRollbackLocked(entry proxyRollbackEntry) {
	if rt.rollbackMax <= 0 {
		rt.rollbackMax = clampProxyRollbackMax(rt.rollbackMax)
	}
	rt.rollbackStack = append(rt.rollbackStack, entry)
	if len(rt.rollbackStack) > rt.rollbackMax {
		rt.rollbackStack = append([]proxyRollbackEntry(nil), rt.rollbackStack[len(rt.rollbackStack)-rt.rollbackMax:]...)
	}
}
