package daemonruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	daemonRuntimeDefaultStopSec = 5
	daemonRuntimeMaxRestart     = 5
	daemonRuntimeRestartWindow  = time.Minute
	daemonRuntimeRestartDelay   = 2 * time.Second
	daemonRuntimeDefaultLogTail = 16 * 1024
	daemonRuntimeMaxLogTail     = 64 * 1024
)

type ProcessStatus struct {
	AppID           string   `json:"app_id"`
	ProcessID       string   `json:"process_id"`
	Enabled         bool     `json:"enabled"`
	Running         bool     `json:"running"`
	PID             int      `json:"pid,omitempty"`
	Command         string   `json:"command,omitempty"`
	Args            []string `json:"args,omitempty"`
	AppRoot         string   `json:"app_root,omitempty"`
	WorkingDir      string   `json:"working_dir,omitempty"`
	ConfiguredUser  string   `json:"configured_user,omitempty"`
	ConfiguredGroup string   `json:"configured_group,omitempty"`
	EffectiveUser   string   `json:"effective_user,omitempty"`
	EffectiveGroup  string   `json:"effective_group,omitempty"`
	EffectiveUID    int      `json:"effective_uid,omitempty"`
	EffectiveGID    int      `json:"effective_gid,omitempty"`
	RestartPolicy   string   `json:"restart_policy,omitempty"`
	StartedAt       string   `json:"started_at,omitempty"`
	StoppedAt       string   `json:"stopped_at,omitempty"`
	LastAction      string   `json:"last_action,omitempty"`
	LastError       string   `json:"last_error,omitempty"`
	LogFile         string   `json:"log_file,omitempty"`
}

type ProcessLog struct {
	AppID     string `json:"app_id"`
	ProcessID string `json:"process_id"`
	LogFile   string `json:"log_file"`
	Tail      string `json:"tail"`
	Truncated bool   `json:"truncated"`
	MaxBytes  int64  `json:"max_bytes"`
}

type Spec struct {
	AppID           string
	ProcessID       string
	Enabled         bool
	Command         string
	Args            []string
	AppRoot         string
	WorkingDir      string
	Env             map[string]string
	RunUser         string
	RunGroup        string
	RestartPolicy   string
	GracefulStopSec int
}

type managedProcess struct {
	spec      Spec
	signature string
	cmd       *exec.Cmd
	logFile   *os.File
	done      chan error
	desired   bool
	stopping  bool
	startedAt time.Time
}

type restartState struct {
	windowStart time.Time
	count       int
}

type Identity struct {
	ConfiguredUser  string
	ConfiguredGroup string
	EffectiveUser   string
	EffectiveGroup  string
	UID             uint32
	GID             uint32
}

type Options struct {
	ResolvePath      func(string) string
	ResolveIdentity  func(Spec) (Identity, error)
	ValidateIdentity func(Identity) error
	TrimError        func(string) string
	OnRestart        func()
}

type Supervisor struct {
	mu        sync.Mutex
	options   Options
	processes map[string]*managedProcess
	statuses  map[string]ProcessStatus
	restarts  map[string]restartState
	manual    map[string]bool
}

func New(options Options) *Supervisor {
	return &Supervisor{
		options:   options,
		processes: map[string]*managedProcess{},
		statuses:  map[string]ProcessStatus{},
		restarts:  map[string]restartState{},
		manual:    map[string]bool{},
	}
}

func ValidateLaunch(spec Spec, identity Identity, options Options) error {
	return New(options).validateLaunch(spec, identity)
}

func (s *Supervisor) Snapshot() []ProcessStatus {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ProcessStatus, 0, len(s.statuses))
	for _, status := range s.statuses {
		out = append(out, status)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].AppID < out[j].AppID
	})
	return out
}

func (s *Supervisor) Reconcile(desired []Spec) error {
	if s == nil {
		return nil
	}
	desiredMap := make(map[string]Spec, len(desired))
	for _, spec := range desired {
		desiredMap[spec.AppID] = spec
	}

	s.mu.Lock()
	existingIDs := make([]string, 0, len(s.processes))
	for appID := range s.processes {
		existingIDs = append(existingIDs, appID)
	}
	s.mu.Unlock()
	sort.Strings(existingIDs)
	for _, appID := range existingIDs {
		if _, ok := desiredMap[appID]; ok {
			continue
		}
		if err := s.stop(appID, true); err != nil {
			return err
		}
	}

	for _, spec := range desired {
		if err := s.ensureProcess(spec, false); err != nil {
			return err
		}
	}
	return nil
}

func (s *Supervisor) Shutdown() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	appIDs := make([]string, 0, len(s.processes))
	for appID := range s.processes {
		appIDs = append(appIDs, appID)
	}
	s.mu.Unlock()
	sort.Strings(appIDs)
	for _, appID := range appIDs {
		if err := s.stop(appID, true); err != nil {
			return err
		}
	}
	return nil
}

func (s *Supervisor) ensureProcess(spec Spec, explicit bool) error {
	signature := daemonRuntimeSpecSignature(spec)
	identity, err := s.resolveIdentity(spec)
	if err != nil {
		s.updateStatus(spec, nil, false, 0, "identity_error", err.Error())
		return err
	}
	if !spec.Enabled && !explicit {
		if err := s.stop(spec.AppID, false); err != nil {
			return err
		}
		s.clearManualStop(spec.AppID)
		s.updateStatus(spec, &identity, false, 0, "disabled", "")
		return nil
	}
	if err := s.validateLaunch(spec, identity); err != nil {
		s.updateStatus(spec, &identity, false, 0, "preflight_failed", err.Error())
		return err
	}

	s.mu.Lock()
	if explicit {
		delete(s.manual, spec.AppID)
	} else if spec.Enabled && s.manual[spec.AppID] {
		s.mu.Unlock()
		s.updateStatus(spec, &identity, false, 0, "manual_stopped", "")
		return nil
	}
	current := s.processes[spec.AppID]
	if current != nil {
		current.desired = true
	}
	s.mu.Unlock()

	if current != nil && current.signature == signature {
		s.updateStatus(spec, &identity, true, current.cmd.Process.Pid, "running", "")
		return nil
	}
	if current != nil {
		if err := s.stop(spec.AppID, false); err != nil {
			s.updateStatus(spec, &identity, false, 0, "restart_failed", err.Error())
			return err
		}
	}
	if err := s.start(spec, signature, identity); err != nil {
		s.updateStatus(spec, &identity, false, 0, "start_failed", err.Error())
		return err
	}
	return nil
}

func (s *Supervisor) StartProcess(appID string, desired []Spec) error {
	spec, ok := daemonRuntimeSpecByAppID(appID, desired)
	if !ok {
		return fmt.Errorf("daemon app %q is not configured", appID)
	}
	spec.Enabled = true
	s.clearManualStop(spec.AppID)
	return s.ensureProcess(spec, true)
}

func (s *Supervisor) StopProcess(appID string, desired []Spec) error {
	spec, ok := daemonRuntimeSpecByAppID(appID, desired)
	if !ok {
		return fmt.Errorf("daemon app %q is not configured", appID)
	}
	if err := s.stop(spec.AppID, false); err != nil {
		return err
	}
	s.setManualStop(spec.AppID)
	identity, _ := s.resolveIdentity(spec)
	s.updateStatus(spec, &identity, false, 0, "manual_stopped", "")
	return nil
}

func (s *Supervisor) ReloadProcess(appID string, desired []Spec) error {
	spec, ok := daemonRuntimeSpecByAppID(appID, desired)
	if !ok {
		return fmt.Errorf("daemon app %q is not configured", appID)
	}
	s.clearManualStop(spec.AppID)
	if err := s.stop(spec.AppID, false); err != nil {
		return err
	}
	spec.Enabled = true
	return s.ensureProcess(spec, true)
}

func daemonRuntimeSpecByAppID(appID string, desired []Spec) (Spec, bool) {
	for _, spec := range desired {
		if spec.AppID == appID || spec.ProcessID == appID {
			return spec, true
		}
	}
	return Spec{}, false
}

func (s *Supervisor) start(spec Spec, signature string, identity Identity) error {
	cmdPath, workingDir, err := s.launchPaths(spec)
	if err != nil {
		return err
	}
	logPath := s.logPath(spec.AppID)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(cmdPath, spec.Args...)
	cmd.Dir = workingDir
	cmd.Env = s.launchEnv(spec)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if uint32(os.Geteuid()) != identity.UID || uint32(os.Getegid()) != identity.GID {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid:         identity.UID,
				Gid:         identity.GID,
				NoSetGroups: true,
			},
		}
	}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	proc := &managedProcess{
		spec:      spec,
		signature: signature,
		cmd:       cmd,
		logFile:   logFile,
		done:      make(chan error, 1),
		desired:   true,
		startedAt: time.Now(),
	}
	s.mu.Lock()
	s.processes[spec.AppID] = proc
	s.updateStatusLocked(spec, &identity, true, cmd.Process.Pid, "running", "")
	s.mu.Unlock()

	go func() {
		err := cmd.Wait()
		proc.done <- err
		close(proc.done)
		s.handleExit(proc, err)
	}()
	return nil
}

func (s *Supervisor) stop(appID string, deleteStatus bool) error {
	s.mu.Lock()
	proc := s.processes[appID]
	if proc == nil {
		if deleteStatus {
			delete(s.statuses, appID)
			delete(s.restarts, appID)
			delete(s.manual, appID)
		}
		s.mu.Unlock()
		return nil
	}
	proc.desired = false
	proc.stopping = true
	delete(s.processes, appID)
	status := s.statuses[appID]
	status.LastAction = "stopping"
	s.statuses[appID] = status
	cmd := proc.cmd
	done := proc.done
	timeout := time.Duration(proc.spec.GracefulStopSec) * time.Second
	if timeout <= 0 {
		timeout = daemonRuntimeDefaultStopSec * time.Second
	}
	s.mu.Unlock()

	if cmd.Process != nil {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !strings.Contains(strings.ToLower(err.Error()), "finished") {
			return err
		}
	}
	select {
	case err, ok := <-done:
		if ok && err != nil && !strings.Contains(strings.ToLower(err.Error()), "signal: terminated") {
			return err
		}
	case <-time.After(timeout):
		if cmd.Process != nil {
			if err := cmd.Process.Kill(); err != nil && !strings.Contains(strings.ToLower(err.Error()), "finished") {
				return err
			}
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("timeout waiting for daemon app %q to stop", appID)
		}
	}

	if deleteStatus {
		s.mu.Lock()
		delete(s.statuses, appID)
		delete(s.restarts, appID)
		delete(s.manual, appID)
		s.mu.Unlock()
		return nil
	}
	s.mu.Lock()
	status = s.statuses[appID]
	status.Running = false
	status.PID = 0
	status.StoppedAt = time.Now().UTC().Format(time.RFC3339Nano)
	status.LastAction = "stopped"
	s.statuses[appID] = status
	s.mu.Unlock()
	return nil
}

func (s *Supervisor) handleExit(proc *managedProcess, err error) {
	if proc.logFile != nil {
		_ = proc.logFile.Close()
	}
	spec := proc.spec
	restart := false
	s.mu.Lock()
	current := s.processes[spec.AppID]
	if current != proc {
		s.mu.Unlock()
		return
	}
	delete(s.processes, spec.AppID)
	s.updateStatusLocked(spec, nil, false, 0, "stopped", "")
	status := s.statuses[spec.AppID]
	if err != nil && !proc.stopping {
		status.LastAction = "exited"
		status.LastError = s.trimError(err.Error())
		s.statuses[spec.AppID] = status
	}
	if proc.desired && !proc.stopping {
		switch strings.TrimSpace(spec.RestartPolicy) {
		case "always":
			restart = true
		case "", "on-failure":
			restart = err != nil
		}
	}
	if restart && !s.allowRestartLocked(spec.AppID) {
		status = s.statuses[spec.AppID]
		status.LastAction = "restart_limited"
		status.LastError = "daemon app restart limit reached"
		s.statuses[spec.AppID] = status
		restart = false
	}
	s.mu.Unlock()

	if restart {
		go func() {
			time.Sleep(daemonRuntimeRestartDelay)
			if s.options.OnRestart != nil {
				s.options.OnRestart()
			}
		}()
	}
}

func (s *Supervisor) allowRestartLocked(appID string) bool {
	now := time.Now()
	state := s.restarts[appID]
	if state.windowStart.IsZero() || now.Sub(state.windowStart) > daemonRuntimeRestartWindow {
		state.windowStart = now
		state.count = 0
	}
	state.count++
	s.restarts[appID] = state
	return state.count <= daemonRuntimeMaxRestart
}

func (s *Supervisor) updateStatus(spec Spec, identity *Identity, running bool, pid int, action string, lastError string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateStatusLocked(spec, identity, running, pid, action, lastError)
}

func (s *Supervisor) updateStatusLocked(spec Spec, identity *Identity, running bool, pid int, action string, lastError string) {
	status := ProcessStatus{
		AppID:         spec.AppID,
		ProcessID:     spec.ProcessID,
		Enabled:       spec.Enabled,
		Running:       running,
		PID:           pid,
		Command:       spec.Command,
		Args:          append([]string(nil), spec.Args...),
		AppRoot:       spec.AppRoot,
		WorkingDir:    spec.WorkingDir,
		RestartPolicy: spec.RestartPolicy,
		LastAction:    action,
		LastError:     s.trimError(lastError),
		LogFile:       s.logPath(spec.AppID),
	}
	if running {
		if current := s.processes[spec.AppID]; current != nil && !current.startedAt.IsZero() {
			status.StartedAt = current.startedAt.UTC().Format(time.RFC3339Nano)
		}
	} else if prev := s.statuses[spec.AppID]; prev.StoppedAt != "" {
		status.StoppedAt = prev.StoppedAt
	}
	if identity != nil {
		status.ConfiguredUser = identity.ConfiguredUser
		status.ConfiguredGroup = identity.ConfiguredGroup
		status.EffectiveUser = identity.EffectiveUser
		status.EffectiveGroup = identity.EffectiveGroup
		status.EffectiveUID = int(identity.UID)
		status.EffectiveGID = int(identity.GID)
	}
	s.statuses[spec.AppID] = status
}

func (s *Supervisor) setManualStop(appID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manual[appID] = true
}

func (s *Supervisor) clearManualStop(appID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.manual, appID)
}

func (s *Supervisor) LogTail(appID string, maxBytes int64) (ProcessLog, error) {
	if s == nil {
		return ProcessLog{}, fmt.Errorf("daemon runtime supervisor is not initialized")
	}
	maxBytes = normalizeDaemonRuntimeLogTailBytes(maxBytes)
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return ProcessLog{}, fmt.Errorf("daemon app id is required")
	}

	s.mu.Lock()
	status, ok := s.statuses[appID]
	if !ok {
		for _, candidate := range s.statuses {
			if candidate.ProcessID == appID {
				status = candidate
				ok = true
				break
			}
		}
	}
	if !ok {
		s.mu.Unlock()
		return ProcessLog{}, fmt.Errorf("daemon app %q is not configured", appID)
	}
	logPath := s.logPath(status.AppID)
	out := ProcessLog{
		AppID:     status.AppID,
		ProcessID: status.ProcessID,
		LogFile:   logPath,
		MaxBytes:  maxBytes,
	}
	s.mu.Unlock()

	tail, truncated, err := daemonRuntimeReadFileTail(logPath, maxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return ProcessLog{}, err
	}
	out.Tail = tail
	out.Truncated = truncated
	return out, nil
}

func daemonRuntimeSpecSignature(spec Spec) string {
	raw, _ := json.Marshal(struct {
		Command         string            `json:"command"`
		Args            []string          `json:"args"`
		AppRoot         string            `json:"app_root"`
		WorkingDir      string            `json:"working_dir"`
		Env             map[string]string `json:"env"`
		RunUser         string            `json:"run_user"`
		RunGroup        string            `json:"run_group"`
		RestartPolicy   string            `json:"restart_policy"`
		GracefulStopSec int               `json:"graceful_stop_sec"`
	}{
		Command:         spec.Command,
		Args:            spec.Args,
		AppRoot:         spec.AppRoot,
		WorkingDir:      spec.WorkingDir,
		Env:             spec.Env,
		RunUser:         spec.RunUser,
		RunGroup:        spec.RunGroup,
		RestartPolicy:   spec.RestartPolicy,
		GracefulStopSec: spec.GracefulStopSec,
	})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *Supervisor) resolveIdentity(spec Spec) (Identity, error) {
	if s.options.ResolveIdentity != nil {
		return s.options.ResolveIdentity(spec)
	}
	currentUID := uint32(os.Geteuid())
	currentGID := uint32(os.Getegid())
	return Identity{
		ConfiguredUser:  strings.TrimSpace(spec.RunUser),
		ConfiguredGroup: strings.TrimSpace(spec.RunGroup),
		EffectiveUser:   fmt.Sprintf("%d", currentUID),
		EffectiveGroup:  fmt.Sprintf("%d", currentGID),
		UID:             currentUID,
		GID:             currentGID,
	}, nil
}

func (s *Supervisor) validateLaunch(spec Spec, identity Identity) error {
	if s.options.ValidateIdentity != nil {
		if err := s.options.ValidateIdentity(identity); err != nil {
			return err
		}
	}
	_, _, err := s.launchPaths(spec)
	return err
}

func (s *Supervisor) launchPaths(spec Spec) (string, string, error) {
	root := s.resolvePath(spec.AppRoot)
	if info, err := os.Stat(root); err != nil {
		return "", "", fmt.Errorf("app_root %q: %w", spec.AppRoot, err)
	} else if !info.IsDir() {
		return "", "", fmt.Errorf("app_root %q is not a directory", spec.AppRoot)
	}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", fmt.Errorf("app_root %q: %w", spec.AppRoot, err)
	}
	cmdPath := s.commandPath(spec)
	cmdReal, err := filepath.EvalSymlinks(cmdPath)
	if err != nil {
		return "", "", fmt.Errorf("command %q: %w", spec.Command, err)
	}
	if !daemonRuntimePathUnder(rootReal, cmdReal) {
		return "", "", fmt.Errorf("command escapes app_root")
	}
	info, err := os.Stat(cmdPath)
	if err != nil {
		return "", "", fmt.Errorf("command %q: %w", spec.Command, err)
	}
	if info.IsDir() {
		return "", "", fmt.Errorf("command %q points to a directory", spec.Command)
	}
	if info.Mode()&0o111 == 0 {
		return "", "", fmt.Errorf("command %q is not executable", spec.Command)
	}
	workingDir := s.workingDir(spec)
	workingDirReal, err := filepath.EvalSymlinks(workingDir)
	if err != nil {
		return "", "", fmt.Errorf("working_dir %q: %w", spec.WorkingDir, err)
	}
	if !daemonRuntimePathUnder(rootReal, workingDirReal) {
		return "", "", fmt.Errorf("working_dir escapes app_root")
	}
	if info, err := os.Stat(workingDir); err != nil {
		return "", "", fmt.Errorf("working_dir %q: %w", spec.WorkingDir, err)
	} else if !info.IsDir() {
		return "", "", fmt.Errorf("working_dir %q is not a directory", spec.WorkingDir)
	}
	return cmdReal, workingDirReal, nil
}

func (s *Supervisor) resolvePath(value string) string {
	if s.options.ResolvePath != nil {
		return s.options.ResolvePath(value)
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(value)
}

func (s *Supervisor) commandPath(spec Spec) string {
	return filepath.Join(s.resolvePath(spec.AppRoot), filepath.FromSlash(spec.Command))
}

func (s *Supervisor) workingDir(spec Spec) string {
	root := s.resolvePath(spec.AppRoot)
	if strings.TrimSpace(spec.WorkingDir) == "" {
		return root
	}
	return filepath.Join(root, filepath.FromSlash(spec.WorkingDir))
}

func (s *Supervisor) launchEnv(spec Spec) []string {
	env := os.Environ()
	keys := make([]string, 0, len(spec.Env))
	for key := range spec.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+spec.Env[key])
	}
	env = append(env,
		"TUKUYOMI_RUNTIME_APP_ID="+spec.AppID,
		"TUKUYOMI_RUNTIME_APP_MODE=daemon",
		"TUKUYOMI_RUNTIME_APP_ROOT="+s.resolvePath(spec.AppRoot),
	)
	return env
}

func (s *Supervisor) logPath(appID string) string {
	appID = daemonRuntimeSafePathToken(appID)
	if appID == "" {
		appID = "unknown"
	}
	return filepath.ToSlash(filepath.Join("data", "daemon-apps", appID, "daemon-supervisor.log"))
}

func (s *Supervisor) trimError(value string) string {
	if s.options.TrimError != nil {
		return s.options.TrimError(value)
	}
	value = strings.TrimSpace(value)
	if len(value) > 512 {
		return value[:512]
	}
	return value
}

func daemonRuntimePathUnder(root string, target string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func daemonRuntimeSafePathToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func normalizeDaemonRuntimeLogTailBytes(value int64) int64 {
	if value <= 0 {
		return daemonRuntimeDefaultLogTail
	}
	if value > daemonRuntimeMaxLogTail {
		return daemonRuntimeMaxLogTail
	}
	return value
}

func daemonRuntimeReadFileTail(path string, maxBytes int64) (string, bool, error) {
	maxBytes = normalizeDaemonRuntimeLogTailBytes(maxBytes)
	info, err := os.Stat(path)
	if err != nil {
		return "", false, err
	}
	if info.IsDir() {
		return "", false, fmt.Errorf("daemon log path is a directory")
	}
	size := info.Size()
	offset := int64(0)
	truncated := false
	if size > maxBytes {
		offset = size - maxBytes
		truncated = true
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return "", false, err
		}
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return "", false, err
	}
	return string(raw), truncated, nil
}
