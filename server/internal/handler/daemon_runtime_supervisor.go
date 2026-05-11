package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
)

type DaemonRuntimeProcessStatus struct {
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

type daemonRuntimeAppSpec struct {
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

type daemonRuntimeManagedProcess struct {
	spec      daemonRuntimeAppSpec
	signature string
	cmd       *exec.Cmd
	logFile   *os.File
	done      chan error
	desired   bool
	stopping  bool
	startedAt time.Time
}

type daemonRuntimeRestartState struct {
	windowStart time.Time
	count       int
}

type daemonRuntimeSupervisor struct {
	mu        sync.Mutex
	processes map[string]*daemonRuntimeManagedProcess
	statuses  map[string]DaemonRuntimeProcessStatus
	restarts  map[string]daemonRuntimeRestartState
}

var (
	daemonRuntimeSupervisorMu sync.RWMutex
	daemonRuntimeSupervisorRt *daemonRuntimeSupervisor
)

func InitDaemonRuntimeSupervisor() error {
	sup := &daemonRuntimeSupervisor{
		processes: map[string]*daemonRuntimeManagedProcess{},
		statuses:  map[string]DaemonRuntimeProcessStatus{},
		restarts:  map[string]daemonRuntimeRestartState{},
	}
	daemonRuntimeSupervisorMu.Lock()
	daemonRuntimeSupervisorRt = sup
	daemonRuntimeSupervisorMu.Unlock()
	return ReconcileDaemonRuntimeSupervisor()
}

func ShutdownDaemonRuntimeSupervisor() error {
	daemonRuntimeSupervisorMu.Lock()
	sup := daemonRuntimeSupervisorRt
	daemonRuntimeSupervisorRt = nil
	daemonRuntimeSupervisorMu.Unlock()
	if sup == nil {
		return nil
	}
	return sup.shutdown()
}

func daemonRuntimeSupervisorInstance() *daemonRuntimeSupervisor {
	daemonRuntimeSupervisorMu.RLock()
	defer daemonRuntimeSupervisorMu.RUnlock()
	return daemonRuntimeSupervisorRt
}

func DaemonRuntimeProcessSnapshot() []DaemonRuntimeProcessStatus {
	return runtimeAppProcessController().DaemonRuntimeProcessSnapshot()
}

func ReconcileDaemonRuntimeSupervisor() error {
	return runtimeAppProcessController().ReconcileDaemonRuntimeSupervisor()
}

func StartDaemonProcess(appID string) error {
	return runtimeAppProcessController().StartDaemonProcess(appID)
}

func StopDaemonProcess(appID string) error {
	return runtimeAppProcessController().StopDaemonProcess(appID)
}

func ReloadDaemonProcess(appID string) error {
	return runtimeAppProcessController().ReloadDaemonProcess(appID)
}

func localDaemonRuntimeProcessSnapshot() []DaemonRuntimeProcessStatus {
	sup := daemonRuntimeSupervisorInstance()
	if sup == nil {
		return nil
	}
	sup.mu.Lock()
	defer sup.mu.Unlock()
	out := make([]DaemonRuntimeProcessStatus, 0, len(sup.statuses))
	for _, status := range sup.statuses {
		out = append(out, status)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].AppID < out[j].AppID
	})
	return out
}

func localReconcileDaemonRuntimeSupervisor() error {
	sup := daemonRuntimeSupervisorInstance()
	if sup == nil {
		return nil
	}
	return sup.reconcile(currentDaemonRuntimeAppSpecs())
}

func localStartDaemonProcess(appID string) error {
	sup := daemonRuntimeSupervisorInstance()
	if sup == nil {
		return fmt.Errorf("daemon runtime supervisor is not initialized")
	}
	return sup.startProcess(normalizeConfigToken(appID))
}

func localStopDaemonProcess(appID string) error {
	sup := daemonRuntimeSupervisorInstance()
	if sup == nil {
		return fmt.Errorf("daemon runtime supervisor is not initialized")
	}
	return sup.stopProcess(normalizeConfigToken(appID))
}

func localReloadDaemonProcess(appID string) error {
	sup := daemonRuntimeSupervisorInstance()
	if sup == nil {
		return fmt.Errorf("daemon runtime supervisor is not initialized")
	}
	return sup.reloadProcess(normalizeConfigToken(appID))
}

func currentDaemonRuntimeAppSpecs() []daemonRuntimeAppSpec {
	cfg := currentVhostConfig()
	out := make([]daemonRuntimeAppSpec, 0, len(cfg.Vhosts))
	for _, vhost := range cfg.Vhosts {
		if normalizeVhostMode(vhost.Mode) != "daemon" {
			continue
		}
		appID := normalizeConfigToken(vhost.Name)
		if appID == "" {
			continue
		}
		processID := normalizeConfigToken(vhost.GeneratedTarget)
		if processID == "" {
			processID = appID
		}
		out = append(out, daemonRuntimeAppSpec{
			AppID:           appID,
			ProcessID:       processID,
			Enabled:         vhost.Enabled,
			Command:         vhost.Command,
			Args:            append([]string(nil), vhost.Args...),
			AppRoot:         vhost.AppRoot,
			WorkingDir:      vhost.WorkingDir,
			Env:             cloneStringMap(vhost.Env),
			RunUser:         vhost.RunUser,
			RunGroup:        vhost.RunGroup,
			RestartPolicy:   vhost.RestartPolicy,
			GracefulStopSec: vhost.GracefulStopSec,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].AppID < out[j].AppID
	})
	return out
}

func (s *daemonRuntimeSupervisor) reconcile(desired []daemonRuntimeAppSpec) error {
	desiredMap := make(map[string]daemonRuntimeAppSpec, len(desired))
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

func (s *daemonRuntimeSupervisor) shutdown() error {
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

func (s *daemonRuntimeSupervisor) ensureProcess(spec daemonRuntimeAppSpec, explicit bool) error {
	signature := daemonRuntimeSpecSignature(spec)
	identity, err := resolveDaemonRuntimeIdentity(spec)
	if err != nil {
		s.updateStatus(spec, nil, false, 0, "identity_error", err.Error())
		return err
	}
	if !spec.Enabled && !explicit {
		if err := s.stop(spec.AppID, false); err != nil {
			return err
		}
		s.updateStatus(spec, &identity, false, 0, "disabled", "")
		return nil
	}
	if err := validateDaemonRuntimeLaunch(spec, identity); err != nil {
		s.updateStatus(spec, &identity, false, 0, "preflight_failed", err.Error())
		return err
	}

	s.mu.Lock()
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

func (s *daemonRuntimeSupervisor) startProcess(appID string) error {
	spec, ok := daemonRuntimeSpecByAppID(appID)
	if !ok {
		return fmt.Errorf("daemon app %q is not configured", appID)
	}
	spec.Enabled = true
	return s.ensureProcess(spec, true)
}

func (s *daemonRuntimeSupervisor) stopProcess(appID string) error {
	spec, ok := daemonRuntimeSpecByAppID(appID)
	if !ok {
		return fmt.Errorf("daemon app %q is not configured", appID)
	}
	if err := s.stop(spec.AppID, false); err != nil {
		return err
	}
	identity, _ := resolveDaemonRuntimeIdentity(spec)
	s.updateStatus(spec, &identity, false, 0, "manual_stopped", "")
	return nil
}

func (s *daemonRuntimeSupervisor) reloadProcess(appID string) error {
	spec, ok := daemonRuntimeSpecByAppID(appID)
	if !ok {
		return fmt.Errorf("daemon app %q is not configured", appID)
	}
	if err := s.stop(spec.AppID, false); err != nil {
		return err
	}
	spec.Enabled = true
	return s.ensureProcess(spec, true)
}

func daemonRuntimeSpecByAppID(appID string) (daemonRuntimeAppSpec, bool) {
	appID = normalizeConfigToken(appID)
	for _, spec := range currentDaemonRuntimeAppSpecs() {
		if spec.AppID == appID || spec.ProcessID == appID {
			return spec, true
		}
	}
	return daemonRuntimeAppSpec{}, false
}

func (s *daemonRuntimeSupervisor) start(spec daemonRuntimeAppSpec, signature string, identity phpRuntimeResolvedIdentity) error {
	cmdPath, workingDir, err := daemonRuntimeLaunchPaths(spec)
	if err != nil {
		return err
	}
	logPath := daemonRuntimeLogPath(spec.AppID)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(cmdPath, spec.Args...)
	cmd.Dir = workingDir
	cmd.Env = daemonRuntimeLaunchEnv(spec)
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
	proc := &daemonRuntimeManagedProcess{
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

func (s *daemonRuntimeSupervisor) stop(appID string, deleteStatus bool) error {
	s.mu.Lock()
	proc := s.processes[appID]
	if proc == nil {
		if deleteStatus {
			delete(s.statuses, appID)
			delete(s.restarts, appID)
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

func (s *daemonRuntimeSupervisor) handleExit(proc *daemonRuntimeManagedProcess, err error) {
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
		status.LastError = trimStatusError(err.Error())
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
			_ = ReconcileDaemonRuntimeSupervisor()
		}()
	}
}

func (s *daemonRuntimeSupervisor) allowRestartLocked(appID string) bool {
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

func (s *daemonRuntimeSupervisor) updateStatus(spec daemonRuntimeAppSpec, identity *phpRuntimeResolvedIdentity, running bool, pid int, action string, lastError string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateStatusLocked(spec, identity, running, pid, action, lastError)
}

func (s *daemonRuntimeSupervisor) updateStatusLocked(spec daemonRuntimeAppSpec, identity *phpRuntimeResolvedIdentity, running bool, pid int, action string, lastError string) {
	status := DaemonRuntimeProcessStatus{
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
		LastError:     trimStatusError(lastError),
		LogFile:       daemonRuntimeLogPath(spec.AppID),
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

func daemonRuntimeSpecSignature(spec daemonRuntimeAppSpec) string {
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

func resolveDaemonRuntimeIdentity(spec daemonRuntimeAppSpec) (phpRuntimeResolvedIdentity, error) {
	currentUID := uint32(os.Geteuid())
	currentGID := uint32(os.Getegid())
	out := phpRuntimeResolvedIdentity{
		ConfiguredUser:  strings.TrimSpace(spec.RunUser),
		ConfiguredGroup: strings.TrimSpace(spec.RunGroup),
		EffectiveUser:   lookupUserLabel(currentUID),
		EffectiveGroup:  lookupGroupLabel(currentGID),
		UID:             currentUID,
		GID:             currentGID,
	}
	if out.ConfiguredUser != "" {
		uid, label, primaryGID, err := resolvePHPRuntimeUserSpec(out.ConfiguredUser)
		if err != nil {
			return phpRuntimeResolvedIdentity{}, fmt.Errorf("daemon app %q run_user: %w", spec.AppID, err)
		}
		out.UID = uid
		out.EffectiveUser = label
		if out.ConfiguredGroup == "" {
			if primaryGID == nil {
				return phpRuntimeResolvedIdentity{}, fmt.Errorf("daemon app %q run_group is required when run_user %q has no passwd entry", spec.AppID, out.ConfiguredUser)
			}
			out.GID = *primaryGID
			out.EffectiveGroup = lookupGroupLabel(*primaryGID)
		}
	}
	if out.ConfiguredGroup != "" {
		gid, label, err := resolvePHPRuntimeGroupSpec(out.ConfiguredGroup)
		if err != nil {
			return phpRuntimeResolvedIdentity{}, fmt.Errorf("daemon app %q run_group: %w", spec.AppID, err)
		}
		out.GID = gid
		out.EffectiveGroup = label
	}
	return out, nil
}

func validateDaemonRuntimeLaunch(spec daemonRuntimeAppSpec, identity phpRuntimeResolvedIdentity) error {
	if err := validatePHPRuntimePrivilegeTransition(identity); err != nil {
		return err
	}
	_, _, err := daemonRuntimeLaunchPaths(spec)
	return err
}

func daemonRuntimeLaunchPaths(spec daemonRuntimeAppSpec) (string, string, error) {
	root := absoluteRuntimePath(spec.AppRoot)
	if info, err := os.Stat(root); err != nil {
		return "", "", fmt.Errorf("app_root %q: %w", spec.AppRoot, err)
	} else if !info.IsDir() {
		return "", "", fmt.Errorf("app_root %q is not a directory", spec.AppRoot)
	}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", fmt.Errorf("app_root %q: %w", spec.AppRoot, err)
	}
	cmdPath := daemonRuntimeCommandPath(spec)
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
	workingDir := daemonRuntimeWorkingDir(spec)
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

func daemonRuntimeCommandPath(spec daemonRuntimeAppSpec) string {
	return filepath.Join(absoluteRuntimePath(spec.AppRoot), filepath.FromSlash(spec.Command))
}

func daemonRuntimeWorkingDir(spec daemonRuntimeAppSpec) string {
	root := absoluteRuntimePath(spec.AppRoot)
	if strings.TrimSpace(spec.WorkingDir) == "" {
		return root
	}
	return filepath.Join(root, filepath.FromSlash(spec.WorkingDir))
}

func daemonRuntimePathUnder(root string, target string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func daemonRuntimeLaunchEnv(spec daemonRuntimeAppSpec) []string {
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
		"TUKUYOMI_RUNTIME_APP_ROOT="+absoluteRuntimePath(spec.AppRoot),
	)
	return env
}

func daemonRuntimeLogPath(appID string) string {
	appID = normalizeConfigToken(appID)
	if appID == "" {
		appID = "unknown"
	}
	return filepath.ToSlash(filepath.Join("data", "daemon-apps", appID, "daemon-supervisor.log"))
}
