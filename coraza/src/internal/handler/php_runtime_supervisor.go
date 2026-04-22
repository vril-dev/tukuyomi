package handler

import (
	"crypto/sha256"
	"encoding/hex"
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

type PHPRuntimeProcessStatus struct {
	RuntimeID        string   `json:"runtime_id"`
	Running          bool     `json:"running"`
	PID              int      `json:"pid,omitempty"`
	BinaryPath       string   `json:"binary_path,omitempty"`
	ConfiguredUser   string   `json:"configured_user,omitempty"`
	ConfiguredGroup  string   `json:"configured_group,omitempty"`
	EffectiveUser    string   `json:"effective_user,omitempty"`
	EffectiveGroup   string   `json:"effective_group,omitempty"`
	EffectiveUID     int      `json:"effective_uid,omitempty"`
	EffectiveGID     int      `json:"effective_gid,omitempty"`
	ConfigFile       string   `json:"config_file,omitempty"`
	PoolFiles        []string `json:"pool_files,omitempty"`
	GeneratedTargets []string `json:"generated_targets,omitempty"`
	StartedAt        string   `json:"started_at,omitempty"`
	StoppedAt        string   `json:"stopped_at,omitempty"`
	LastAction       string   `json:"last_action,omitempty"`
	LastError        string   `json:"last_error,omitempty"`
}

type phpRuntimeManagedProcess struct {
	runtimeID string
	signature string
	cmd       *exec.Cmd
	logFile   *os.File
	done      chan error
	desired   bool
	stopping  bool
}

type phpRuntimeSupervisor struct {
	mu              sync.Mutex
	processes       map[string]*phpRuntimeManagedProcess
	statuses        map[string]PHPRuntimeProcessStatus
	manuallyStopped map[string]bool
}

var (
	phpRuntimeSupervisorMu sync.RWMutex
	phpRuntimeSupervisorRt *phpRuntimeSupervisor
)

func InitPHPRuntimeSupervisor() error {
	sup := &phpRuntimeSupervisor{
		processes:       map[string]*phpRuntimeManagedProcess{},
		statuses:        map[string]PHPRuntimeProcessStatus{},
		manuallyStopped: map[string]bool{},
	}
	phpRuntimeSupervisorMu.Lock()
	phpRuntimeSupervisorRt = sup
	phpRuntimeSupervisorMu.Unlock()
	return ReconcilePHPRuntimeSupervisor()
}

func ShutdownPHPRuntimeSupervisor() error {
	phpRuntimeSupervisorMu.Lock()
	sup := phpRuntimeSupervisorRt
	phpRuntimeSupervisorRt = nil
	phpRuntimeSupervisorMu.Unlock()
	if sup == nil {
		return nil
	}
	return sup.shutdown()
}

func phpRuntimeSupervisorInstance() *phpRuntimeSupervisor {
	phpRuntimeSupervisorMu.RLock()
	defer phpRuntimeSupervisorMu.RUnlock()
	return phpRuntimeSupervisorRt
}

func PHPRuntimeProcessSnapshot() []PHPRuntimeProcessStatus {
	sup := phpRuntimeSupervisorInstance()
	if sup == nil {
		return nil
	}
	sup.mu.Lock()
	defer sup.mu.Unlock()
	out := make([]PHPRuntimeProcessStatus, 0, len(sup.statuses))
	for _, status := range sup.statuses {
		cp := status
		cp.PoolFiles = append([]string(nil), status.PoolFiles...)
		cp.GeneratedTargets = append([]string(nil), status.GeneratedTargets...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RuntimeID < out[j].RuntimeID
	})
	return out
}

func ReconcilePHPRuntimeSupervisor() error {
	sup := phpRuntimeSupervisorInstance()
	if sup == nil {
		return nil
	}
	return sup.reconcile(PHPRuntimeMaterializationSnapshot())
}

func StartPHPRuntimeProcess(runtimeID string) error {
	sup := phpRuntimeSupervisorInstance()
	if sup == nil {
		return fmt.Errorf("php runtime supervisor is not initialized")
	}
	return sup.startRuntime(normalizeConfigToken(runtimeID))
}

func StopPHPRuntimeProcess(runtimeID string) error {
	sup := phpRuntimeSupervisorInstance()
	if sup == nil {
		return fmt.Errorf("php runtime supervisor is not initialized")
	}
	return sup.stopRuntime(normalizeConfigToken(runtimeID))
}

func ReloadPHPRuntimeProcess(runtimeID string) error {
	sup := phpRuntimeSupervisorInstance()
	if sup == nil {
		return fmt.Errorf("php runtime supervisor is not initialized")
	}
	return sup.reloadRuntime(normalizeConfigToken(runtimeID))
}

func (s *phpRuntimeSupervisor) reconcile(desired []PHPRuntimeMaterializedStatus) error {
	desiredMap := make(map[string]PHPRuntimeMaterializedStatus, len(desired))
	runtimeIDs := make([]string, 0, len(desired))
	for _, mat := range desired {
		desiredMap[mat.RuntimeID] = mat
		runtimeIDs = append(runtimeIDs, mat.RuntimeID)
	}
	sort.Strings(runtimeIDs)

	s.mu.Lock()
	existingIDs := make([]string, 0, len(s.processes))
	for runtimeID := range s.processes {
		existingIDs = append(existingIDs, runtimeID)
	}
	s.mu.Unlock()
	sort.Strings(existingIDs)
	for _, runtimeID := range existingIDs {
		if _, ok := desiredMap[runtimeID]; ok {
			continue
		}
		s.mu.Lock()
		delete(s.manuallyStopped, runtimeID)
		s.mu.Unlock()
		if err := s.stop(runtimeID, true); err != nil {
			return err
		}
	}

	for _, runtimeID := range runtimeIDs {
		mat := desiredMap[runtimeID]
		if err := s.ensureRuntime(mat); err != nil {
			return err
		}
	}
	return nil
}

func (s *phpRuntimeSupervisor) shutdown() error {
	s.mu.Lock()
	runtimeIDs := make([]string, 0, len(s.processes))
	for runtimeID := range s.processes {
		runtimeIDs = append(runtimeIDs, runtimeID)
	}
	s.mu.Unlock()
	sort.Strings(runtimeIDs)
	for _, runtimeID := range runtimeIDs {
		if err := s.stop(runtimeID, true); err != nil {
			return err
		}
	}
	return nil
}

func (s *phpRuntimeSupervisor) ensureRuntime(mat PHPRuntimeMaterializedStatus) error {
	signature, err := phpRuntimeMaterializationSignature(mat)
	if err != nil {
		s.updateStatus(mat, nil, false, 0, "reconcile_error", err.Error())
		return err
	}
	identity, err := resolvePHPRuntimeIdentity(mat)
	if err != nil {
		s.updateStatus(mat, nil, false, 0, "identity_error", err.Error())
		return err
	}
	if err := validatePHPRuntimeLaunch(mat, identity); err != nil {
		s.updateStatus(mat, &identity, false, 0, "preflight_failed", err.Error())
		return err
	}

	s.mu.Lock()
	current := s.processes[mat.RuntimeID]
	manualStop := s.manuallyStopped[mat.RuntimeID]
	if current != nil {
		current.desired = true
	}
	s.mu.Unlock()

	if manualStop && current == nil {
		s.updateStatus(mat, &identity, false, 0, "manual_stopped", "")
		return nil
	}
	if current != nil && current.signature == signature {
		s.updateStatus(mat, &identity, true, current.cmd.Process.Pid, "running", "")
		return nil
	}
	if current != nil {
		if err := s.stop(mat.RuntimeID, false); err != nil {
			s.updateStatus(mat, &identity, false, 0, "restart_failed", err.Error())
			return err
		}
	}
	if err := s.start(mat, signature, identity); err != nil {
		s.updateStatus(mat, &identity, false, 0, "start_failed", err.Error())
		return err
	}
	return nil
}

func (s *phpRuntimeSupervisor) startRuntime(runtimeID string) error {
	mat, ok := currentMaterializedRuntime(runtimeID)
	if !ok {
		return fmt.Errorf("runtime %q is not materialized; bind it from Vhosts first", runtimeID)
	}
	s.mu.Lock()
	delete(s.manuallyStopped, runtimeID)
	s.mu.Unlock()
	return s.ensureRuntime(mat)
}

func (s *phpRuntimeSupervisor) stopRuntime(runtimeID string) error {
	mat, ok := currentMaterializedRuntime(runtimeID)
	if !ok {
		return fmt.Errorf("runtime %q is not materialized", runtimeID)
	}
	s.mu.Lock()
	s.manuallyStopped[runtimeID] = true
	s.mu.Unlock()
	if err := s.stop(runtimeID, false); err != nil {
		return err
	}
	identity, err := resolvePHPRuntimeIdentity(mat)
	if err == nil {
		s.updateStatus(mat, &identity, false, 0, "manual_stopped", "")
	} else {
		s.updateStatus(mat, nil, false, 0, "manual_stopped", "")
	}
	return nil
}

func (s *phpRuntimeSupervisor) reloadRuntime(runtimeID string) error {
	mat, ok := currentMaterializedRuntime(runtimeID)
	if !ok {
		return fmt.Errorf("runtime %q is not materialized", runtimeID)
	}
	s.mu.Lock()
	proc := s.processes[runtimeID]
	delete(s.manuallyStopped, runtimeID)
	s.mu.Unlock()
	if proc == nil {
		return fmt.Errorf("runtime %q is not running", runtimeID)
	}
	if err := s.stop(runtimeID, false); err != nil {
		return err
	}
	return s.ensureRuntime(mat)
}

func (s *phpRuntimeSupervisor) start(mat PHPRuntimeMaterializedStatus, signature string, identity phpRuntimeResolvedIdentity) error {
	if strings.TrimSpace(mat.BinaryPath) == "" {
		return fmt.Errorf("runtime %q binary_path is empty", mat.RuntimeID)
	}
	if strings.TrimSpace(mat.ConfigFile) == "" {
		return fmt.Errorf("runtime %q config_file is empty", mat.RuntimeID)
	}
	binaryPath := absoluteRuntimePath(mat.BinaryPath)
	configPath := absoluteRuntimePath(mat.ConfigFile)
	logPath := filepath.Join(filepath.Dir(mat.ConfigFile), "php-fpm-supervisor.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(binaryPath, "-F", "-y", configPath)
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

	proc := &phpRuntimeManagedProcess{
		runtimeID: mat.RuntimeID,
		signature: signature,
		cmd:       cmd,
		logFile:   logFile,
		done:      make(chan error, 1),
		desired:   true,
	}

	s.mu.Lock()
	s.processes[mat.RuntimeID] = proc
	s.updateStatusLocked(mat, &identity, true, cmd.Process.Pid, "started", "")
	s.mu.Unlock()

	go func() {
		err := cmd.Wait()
		proc.done <- err
		close(proc.done)
		s.handleExit(mat, proc, err)
	}()

	return nil
}

func (s *phpRuntimeSupervisor) stop(runtimeID string, deleteStatus bool) error {
	s.mu.Lock()
	proc := s.processes[runtimeID]
	if proc == nil {
		if deleteStatus {
			delete(s.statuses, runtimeID)
			delete(s.manuallyStopped, runtimeID)
		}
		s.mu.Unlock()
		return nil
	}
	proc.desired = false
	proc.stopping = true
	delete(s.processes, runtimeID)
	status := s.statuses[runtimeID]
	status.LastAction = "stopping"
	s.statuses[runtimeID] = status
	cmd := proc.cmd
	done := proc.done
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
	case <-time.After(5 * time.Second):
		if cmd.Process != nil {
			if err := cmd.Process.Kill(); err != nil && !strings.Contains(strings.ToLower(err.Error()), "finished") {
				return err
			}
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("timeout waiting for php-fpm runtime %q to stop", runtimeID)
		}
	}

	if deleteStatus {
		s.mu.Lock()
		delete(s.statuses, runtimeID)
		delete(s.manuallyStopped, runtimeID)
		s.mu.Unlock()
	} else {
		s.mu.Lock()
		status := s.statuses[runtimeID]
		status.Running = false
		status.PID = 0
		status.StoppedAt = time.Now().UTC().Format(time.RFC3339Nano)
		status.LastAction = "stopped"
		s.statuses[runtimeID] = status
		s.mu.Unlock()
	}
	return nil
}

func (s *phpRuntimeSupervisor) handleExit(mat PHPRuntimeMaterializedStatus, proc *phpRuntimeManagedProcess, err error) {
	if proc.logFile != nil {
		_ = proc.logFile.Close()
	}

	s.mu.Lock()
	current := s.processes[mat.RuntimeID]
	if current != proc {
		s.mu.Unlock()
		return
	}
	restart := proc.desired && !proc.stopping
	s.updateStatusLocked(mat, nil, false, 0, "stopped", "")
	if err != nil && !proc.stopping {
		status := s.statuses[mat.RuntimeID]
		status.LastAction = "exited"
		status.LastError = err.Error()
		s.statuses[mat.RuntimeID] = status
	}
	delete(s.processes, mat.RuntimeID)
	s.mu.Unlock()

	if restart {
		_ = ReconcilePHPRuntimeSupervisor()
	}
}

func (s *phpRuntimeSupervisor) updateStatus(mat PHPRuntimeMaterializedStatus, identity *phpRuntimeResolvedIdentity, running bool, pid int, action string, lastErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateStatusLocked(mat, identity, running, pid, action, lastErr)
}

func (s *phpRuntimeSupervisor) updateStatusLocked(mat PHPRuntimeMaterializedStatus, identity *phpRuntimeResolvedIdentity, running bool, pid int, action string, lastErr string) {
	status := s.statuses[mat.RuntimeID]
	status.RuntimeID = mat.RuntimeID
	status.Running = running
	status.PID = pid
	status.BinaryPath = mat.BinaryPath
	status.ConfiguredUser = mat.RunUser
	status.ConfiguredGroup = mat.RunGroup
	status.ConfigFile = mat.ConfigFile
	status.PoolFiles = append([]string(nil), mat.PoolFiles...)
	status.GeneratedTargets = append([]string(nil), mat.GeneratedTarget...)
	status.LastAction = action
	status.LastError = strings.TrimSpace(lastErr)
	if identity != nil {
		status.EffectiveUser = identity.EffectiveUser
		status.EffectiveGroup = identity.EffectiveGroup
		status.EffectiveUID = int(identity.UID)
		status.EffectiveGID = int(identity.GID)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if running {
		if strings.TrimSpace(status.StartedAt) == "" {
			status.StartedAt = now
		}
		status.StoppedAt = ""
	} else {
		status.PID = 0
		status.StoppedAt = now
	}
	s.statuses[mat.RuntimeID] = status
}

func phpRuntimeMaterializationSignature(mat PHPRuntimeMaterializedStatus) (string, error) {
	sum := sha256.New()
	sum.Write([]byte(mat.RuntimeID))
	sum.Write([]byte{0})
	sum.Write([]byte(mat.BinaryPath))
	sum.Write([]byte{0})
	sum.Write([]byte(mat.RunUser))
	sum.Write([]byte{0})
	sum.Write([]byte(mat.RunGroup))
	sum.Write([]byte{0})
	configBody, err := os.ReadFile(mat.ConfigFile)
	if err != nil {
		return "", err
	}
	sum.Write(configBody)
	sum.Write([]byte{0})
	for _, poolFile := range mat.PoolFiles {
		sum.Write([]byte(poolFile))
		sum.Write([]byte{0})
		body, err := os.ReadFile(poolFile)
		if err != nil {
			return "", err
		}
		sum.Write(body)
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func currentMaterializedRuntime(runtimeID string) (PHPRuntimeMaterializedStatus, bool) {
	for _, mat := range PHPRuntimeMaterializationSnapshot() {
		if normalizeConfigToken(mat.RuntimeID) == normalizeConfigToken(runtimeID) {
			return mat, true
		}
	}
	return PHPRuntimeMaterializedStatus{}, false
}
