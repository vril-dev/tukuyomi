package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
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
		return fmt.Errorf("runtime %q is not materialized; bind it from Runtime Apps first", runtimeID)
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
	if action == "starting" {
		if strings.TrimSpace(status.StartedAt) == "" {
			status.StartedAt = now
		}
		status.StoppedAt = ""
	} else if running {
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

type PSGIRuntimeProcessStatus struct {
	ProcessID       string `json:"process_id"`
	VhostName       string `json:"vhost_name"`
	RuntimeID       string `json:"runtime_id"`
	Running         bool   `json:"running"`
	PID             int    `json:"pid,omitempty"`
	PerlPath        string `json:"perl_path,omitempty"`
	StarmanPath     string `json:"starman_path,omitempty"`
	ConfiguredUser  string `json:"configured_user,omitempty"`
	ConfiguredGroup string `json:"configured_group,omitempty"`
	EffectiveUser   string `json:"effective_user,omitempty"`
	EffectiveGroup  string `json:"effective_group,omitempty"`
	EffectiveUID    int    `json:"effective_uid,omitempty"`
	EffectiveGID    int    `json:"effective_gid,omitempty"`
	AppRoot         string `json:"app_root,omitempty"`
	PSGIFile        string `json:"psgi_file,omitempty"`
	PSGIPath        string `json:"psgi_path,omitempty"`
	ListenHost      string `json:"listen_host,omitempty"`
	ListenPort      int    `json:"listen_port,omitempty"`
	Workers         int    `json:"workers,omitempty"`
	MaxRequests     int    `json:"max_requests,omitempty"`
	IncludeExtlib   bool   `json:"include_extlib"`
	GeneratedTarget string `json:"generated_target,omitempty"`
	StartedAt       string `json:"started_at,omitempty"`
	StoppedAt       string `json:"stopped_at,omitempty"`
	LastAction      string `json:"last_action,omitempty"`
	LastError       string `json:"last_error,omitempty"`
}

type psgiRuntimeManagedProcess struct {
	processID string
	signature string
	cmd       *exec.Cmd
	logFile   *os.File
	done      chan error
	desired   bool
	stopping  bool
	ready     bool
	startedAt time.Time
}

type psgiRuntimeSupervisor struct {
	mu              sync.Mutex
	processes       map[string]*psgiRuntimeManagedProcess
	statuses        map[string]PSGIRuntimeProcessStatus
	manuallyStopped map[string]bool
}

var (
	psgiRuntimeSupervisorMu sync.RWMutex
	psgiRuntimeSupervisorRt *psgiRuntimeSupervisor
)

func InitPSGIRuntimeSupervisor() error {
	sup := &psgiRuntimeSupervisor{
		processes:       map[string]*psgiRuntimeManagedProcess{},
		statuses:        map[string]PSGIRuntimeProcessStatus{},
		manuallyStopped: map[string]bool{},
	}
	psgiRuntimeSupervisorMu.Lock()
	psgiRuntimeSupervisorRt = sup
	psgiRuntimeSupervisorMu.Unlock()
	return ReconcilePSGIRuntimeSupervisor()
}

func ShutdownPSGIRuntimeSupervisor() error {
	psgiRuntimeSupervisorMu.Lock()
	sup := psgiRuntimeSupervisorRt
	psgiRuntimeSupervisorRt = nil
	psgiRuntimeSupervisorMu.Unlock()
	if sup == nil {
		return nil
	}
	return sup.shutdown()
}

func psgiRuntimeSupervisorInstance() *psgiRuntimeSupervisor {
	psgiRuntimeSupervisorMu.RLock()
	defer psgiRuntimeSupervisorMu.RUnlock()
	return psgiRuntimeSupervisorRt
}

func PSGIRuntimeProcessSnapshot() []PSGIRuntimeProcessStatus {
	sup := psgiRuntimeSupervisorInstance()
	if sup == nil {
		return nil
	}
	sup.mu.Lock()
	defer sup.mu.Unlock()
	out := make([]PSGIRuntimeProcessStatus, 0, len(sup.statuses))
	for _, status := range sup.statuses {
		out = append(out, status)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ProcessID < out[j].ProcessID
	})
	return out
}

func ReconcilePSGIRuntimeSupervisor() error {
	sup := psgiRuntimeSupervisorInstance()
	if sup == nil {
		return nil
	}
	return sup.reconcile(PSGIRuntimeMaterializationSnapshot())
}

func StartPSGIProcess(vhostName string) error {
	sup := psgiRuntimeSupervisorInstance()
	if sup == nil {
		return fmt.Errorf("psgi runtime supervisor is not initialized")
	}
	return sup.startProcess(normalizeConfigToken(vhostName))
}

func StopPSGIProcess(vhostName string) error {
	sup := psgiRuntimeSupervisorInstance()
	if sup == nil {
		return fmt.Errorf("psgi runtime supervisor is not initialized")
	}
	return sup.stopProcess(normalizeConfigToken(vhostName))
}

func ReloadPSGIProcess(vhostName string) error {
	sup := psgiRuntimeSupervisorInstance()
	if sup == nil {
		return fmt.Errorf("psgi runtime supervisor is not initialized")
	}
	return sup.reloadProcess(normalizeConfigToken(vhostName))
}

func (s *psgiRuntimeSupervisor) reconcile(desired []PSGIRuntimeMaterializedStatus) error {
	desiredMap := make(map[string]PSGIRuntimeMaterializedStatus, len(desired))
	processIDs := make([]string, 0, len(desired))
	for _, mat := range desired {
		desiredMap[mat.ProcessID] = mat
		processIDs = append(processIDs, mat.ProcessID)
	}
	sort.Strings(processIDs)

	s.mu.Lock()
	existingIDs := make([]string, 0, len(s.processes))
	for processID := range s.processes {
		existingIDs = append(existingIDs, processID)
	}
	s.mu.Unlock()
	sort.Strings(existingIDs)
	for _, processID := range existingIDs {
		if _, ok := desiredMap[processID]; ok {
			continue
		}
		s.mu.Lock()
		delete(s.manuallyStopped, processID)
		s.mu.Unlock()
		if err := s.stop(processID, true); err != nil {
			return err
		}
	}

	for _, processID := range processIDs {
		mat := desiredMap[processID]
		if err := s.ensureProcess(mat); err != nil {
			return err
		}
	}
	return nil
}

func (s *psgiRuntimeSupervisor) shutdown() error {
	s.mu.Lock()
	processIDs := make([]string, 0, len(s.processes))
	for processID := range s.processes {
		processIDs = append(processIDs, processID)
	}
	s.mu.Unlock()
	sort.Strings(processIDs)
	for _, processID := range processIDs {
		if err := s.stop(processID, true); err != nil {
			return err
		}
	}
	return nil
}

func (s *psgiRuntimeSupervisor) ensureProcess(mat PSGIRuntimeMaterializedStatus) error {
	signature, err := psgiRuntimeMaterializationSignature(mat)
	if err != nil {
		s.updateStatus(mat, nil, false, 0, "reconcile_error", err.Error())
		return err
	}
	identity, err := resolvePSGIRuntimeIdentity(mat)
	if err != nil {
		s.updateStatus(mat, nil, false, 0, "identity_error", err.Error())
		return err
	}
	if err := validatePSGIRuntimeLaunch(mat, identity); err != nil {
		s.updateStatus(mat, &identity, false, 0, "preflight_failed", err.Error())
		return err
	}

	s.mu.Lock()
	current := s.processes[mat.ProcessID]
	manualStop := s.manuallyStopped[mat.ProcessID]
	if current != nil {
		current.desired = true
	}
	s.mu.Unlock()

	if manualStop && current == nil {
		s.updateStatus(mat, &identity, false, 0, "manual_stopped", "")
		return nil
	}
	if current != nil && current.signature == signature {
		action := "starting"
		if current.ready {
			action = "running"
		}
		s.updateStatus(mat, &identity, current.ready, current.cmd.Process.Pid, action, "")
		return nil
	}
	if current != nil {
		if err := s.stop(mat.ProcessID, false); err != nil {
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

func (s *psgiRuntimeSupervisor) startProcess(vhostName string) error {
	mat, ok := currentMaterializedPSGIProcess(vhostName)
	if !ok {
		return fmt.Errorf("psgi process %q is not materialized; bind it from Runtime Apps first", vhostName)
	}
	s.mu.Lock()
	delete(s.manuallyStopped, mat.ProcessID)
	s.mu.Unlock()
	if err := s.ensureProcess(mat); err != nil {
		return err
	}
	return s.waitForExplicitStartup(mat)
}

func (s *psgiRuntimeSupervisor) stopProcess(vhostName string) error {
	mat, ok := currentMaterializedPSGIProcess(vhostName)
	if !ok {
		return fmt.Errorf("psgi process %q is not materialized", vhostName)
	}
	s.mu.Lock()
	s.manuallyStopped[mat.ProcessID] = true
	s.mu.Unlock()
	if err := s.stop(mat.ProcessID, false); err != nil {
		return err
	}
	identity, err := resolvePSGIRuntimeIdentity(mat)
	if err == nil {
		s.updateStatus(mat, &identity, false, 0, "manual_stopped", "")
	} else {
		s.updateStatus(mat, nil, false, 0, "manual_stopped", "")
	}
	return nil
}

func (s *psgiRuntimeSupervisor) reloadProcess(vhostName string) error {
	mat, ok := currentMaterializedPSGIProcess(vhostName)
	if !ok {
		return fmt.Errorf("psgi process %q is not materialized", vhostName)
	}
	s.mu.Lock()
	proc := s.processes[mat.ProcessID]
	delete(s.manuallyStopped, mat.ProcessID)
	s.mu.Unlock()
	if proc == nil {
		return fmt.Errorf("psgi process %q is not running", mat.ProcessID)
	}
	if err := s.stop(mat.ProcessID, false); err != nil {
		return err
	}
	if err := s.ensureProcess(mat); err != nil {
		return err
	}
	return s.waitForExplicitStartup(mat)
}

func (s *psgiRuntimeSupervisor) waitForExplicitStartup(mat PSGIRuntimeMaterializedStatus) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		s.mu.Lock()
		_, alive := s.processes[mat.ProcessID]
		status := s.statuses[mat.ProcessID]
		s.mu.Unlock()
		if status.Running {
			return nil
		}
		if !alive {
			switch status.LastAction {
			case "start_failed", "preflight_failed", "identity_error", "reconcile_error", "restart_failed", "exited":
				if strings.TrimSpace(status.LastError) != "" {
					return fmt.Errorf("%s", status.LastError)
				}
				return fmt.Errorf("psgi process %q failed to start", mat.ProcessID)
			}
			return fmt.Errorf("psgi process %q stopped before accepting connections", mat.ProcessID)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("psgi process %q did not accept connections on %s within 15s", mat.ProcessID, runtimeListenEndpoint(psgiRuntimeListenHost(mat), mat.ListenPort))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *psgiRuntimeSupervisor) start(mat PSGIRuntimeMaterializedStatus, signature string, identity phpRuntimeResolvedIdentity) error {
	if strings.TrimSpace(mat.StarmanPath) == "" {
		return fmt.Errorf("psgi process %q starman_path is empty", mat.ProcessID)
	}
	starmanPath := absoluteRuntimePath(mat.StarmanPath)
	if err := preparePSGIRuntimeStarmanPIDFile(mat); err != nil {
		return err
	}
	logPath := filepath.Join(mat.RuntimeDir, "starman-supervisor.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(starmanPath, psgiRuntimeStarmanArgs(mat)...)
	cmd.Dir = absoluteRuntimePath(mat.AppRoot)
	cmd.Env = psgiRuntimeLaunchEnv(mat)
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

	proc := &psgiRuntimeManagedProcess{
		processID: mat.ProcessID,
		signature: signature,
		cmd:       cmd,
		logFile:   logFile,
		done:      make(chan error, 1),
		desired:   true,
		startedAt: time.Now(),
	}

	s.mu.Lock()
	s.processes[mat.ProcessID] = proc
	s.updateStatusLocked(mat, &identity, false, cmd.Process.Pid, "starting", "")
	s.mu.Unlock()

	go s.monitorStartupReadiness(mat, identity, proc)

	go func() {
		err := cmd.Wait()
		proc.done <- err
		close(proc.done)
		s.handleExit(mat, proc, err)
	}()

	return nil
}

func preparePSGIRuntimeStarmanPIDFile(mat PSGIRuntimeMaterializedStatus) error {
	pidPath := psgiRuntimePidPath(mat)
	if strings.TrimSpace(pidPath) == "" {
		return fmt.Errorf("psgi process %q pid file path is empty", mat.ProcessID)
	}
	info, err := os.Lstat(pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("psgi process %q pid file %q: %w", mat.ProcessID, pidPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("psgi process %q pid file %q is a directory", mat.ProcessID, pidPath)
	}
	if psgiRuntimePortAccepts(psgiRuntimeListenHost(mat), mat.ListenPort) {
		return fmt.Errorf("psgi process %q already has an unmanaged listener on %s", mat.ProcessID, runtimeListenEndpoint(psgiRuntimeListenHost(mat), mat.ListenPort))
	}
	if err := os.Remove(pidPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("psgi process %q remove stale pid file %q: %w", mat.ProcessID, pidPath, err)
	}
	return nil
}

func (s *psgiRuntimeSupervisor) monitorStartupReadiness(mat PSGIRuntimeMaterializedStatus, identity phpRuntimeResolvedIdentity, proc *psgiRuntimeManagedProcess) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if psgiRuntimePortAccepts(psgiRuntimeListenHost(mat), mat.ListenPort) {
			s.mu.Lock()
			if s.processes[mat.ProcessID] == proc && !proc.stopping {
				proc.ready = true
				s.updateStatusLocked(mat, &identity, true, proc.cmd.Process.Pid, "running", "")
			}
			s.mu.Unlock()
			return
		}
		s.mu.Lock()
		current := s.processes[mat.ProcessID]
		s.mu.Unlock()
		if current != proc {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func psgiRuntimePortAccepts(host string, port int) bool {
	if port <= 0 {
		return false
	}
	conn, err := net.DialTimeout("tcp", runtimeListenEndpoint(host, port), 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (s *psgiRuntimeSupervisor) stop(processID string, deleteStatus bool) error {
	s.mu.Lock()
	proc := s.processes[processID]
	if proc == nil {
		if deleteStatus {
			delete(s.statuses, processID)
			delete(s.manuallyStopped, processID)
		}
		s.mu.Unlock()
		return nil
	}
	proc.desired = false
	proc.stopping = true
	delete(s.processes, processID)
	status := s.statuses[processID]
	status.LastAction = "stopping"
	s.statuses[processID] = status
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
			return fmt.Errorf("timeout waiting for psgi process %q to stop", processID)
		}
	}

	if deleteStatus {
		s.mu.Lock()
		delete(s.statuses, processID)
		delete(s.manuallyStopped, processID)
		s.mu.Unlock()
	} else {
		s.mu.Lock()
		status := s.statuses[processID]
		status.Running = false
		status.PID = 0
		status.StoppedAt = time.Now().UTC().Format(time.RFC3339Nano)
		status.LastAction = "stopped"
		s.statuses[processID] = status
		s.mu.Unlock()
	}
	return nil
}

func (s *psgiRuntimeSupervisor) handleExit(mat PSGIRuntimeMaterializedStatus, proc *psgiRuntimeManagedProcess, err error) {
	if proc.logFile != nil {
		_ = proc.logFile.Close()
	}

	s.mu.Lock()
	current := s.processes[mat.ProcessID]
	if current != proc {
		s.mu.Unlock()
		return
	}
	startupFailure := !proc.stopping && !proc.ready
	restart := proc.desired && !proc.stopping && !startupFailure
	s.updateStatusLocked(mat, nil, false, 0, "stopped", "")
	if startupFailure {
		status := s.statuses[mat.ProcessID]
		status.LastAction = "start_failed"
		if err != nil {
			status.LastError = psgiRuntimeLogErrorSummary(mat.RuntimeDir, err.Error())
		} else {
			status.LastError = "psgi process exited before accepting connections"
		}
		s.statuses[mat.ProcessID] = status
	} else if err != nil && !proc.stopping {
		status := s.statuses[mat.ProcessID]
		status.LastAction = "exited"
		status.LastError = err.Error()
		s.statuses[mat.ProcessID] = status
	}
	delete(s.processes, mat.ProcessID)
	s.mu.Unlock()

	if restart {
		_ = ReconcilePSGIRuntimeSupervisor()
	}
}

func psgiRuntimeLogErrorSummary(runtimeDir string, fallback string) string {
	logPath := filepath.Join(runtimeDir, "starman-supervisor.log")
	body, err := os.ReadFile(logPath)
	if err != nil || len(body) == 0 {
		return trimStatusError(fallback)
	}
	if len(body) > 64*1024 {
		body = body[len(body)-64*1024:]
	}
	lines := strings.Split(string(body), "\n")
	patterns := []string{"error while loading", "can't locate", "compilation failed"}
	for _, pattern := range patterns {
		for i := len(lines) - 1; i >= 0; i-- {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			if strings.Contains(strings.ToLower(line), pattern) {
				return trimStatusError(line)
			}
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return trimStatusError(line)
		}
	}
	return trimStatusError(fallback)
}

func trimStatusError(value string) string {
	value = sanitizeRuntimeStatusError(strings.TrimSpace(value))
	const maxStatusErrorBytes = 600
	if len(value) <= maxStatusErrorBytes {
		return value
	}
	return strings.TrimSpace(value[:maxStatusErrorBytes]) + "..."
}

func sanitizeRuntimeStatusError(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	replacements := map[string]string{}
	addRuntimeStatusPathReplacement(replacements, absoluteRuntimePath("data"), "data")
	addRuntimeStatusPathReplacement(replacements, absoluteRuntimePath("conf"), "conf")
	addRuntimeStatusPathReplacement(replacements, absoluteRuntimePath("cache"), "cache")
	addRuntimeStatusPathReplacement(replacements, "/app/data", "data")
	addRuntimeStatusPathReplacement(replacements, "/app/conf", "conf")
	addRuntimeStatusPathReplacement(replacements, "/app/cache", "cache")
	addRuntimeStatusPathReplacement(replacements, "/app", "")
	if cwd, err := os.Getwd(); err == nil {
		addRuntimeStatusPathReplacement(replacements, cwd, "")
	}
	prefixes := make([]string, 0, len(replacements))
	for prefix := range replacements {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i]) > len(prefixes[j])
	})
	for _, prefix := range prefixes {
		replacement := replacements[prefix]
		value = strings.ReplaceAll(value, prefix+"/", replacement)
	}
	return value
}

func addRuntimeStatusPathReplacement(replacements map[string]string, prefix string, replacement string) {
	prefix = strings.TrimRight(filepath.ToSlash(filepath.Clean(strings.TrimSpace(prefix))), "/")
	if prefix == "" || prefix == "." || prefix == "/" {
		return
	}
	replacement = strings.TrimLeft(filepath.ToSlash(filepath.Clean(strings.TrimSpace(replacement))), "/")
	if replacement == "." {
		replacement = ""
	}
	if replacement != "" {
		replacement += "/"
	}
	replacements[prefix] = replacement
}

func (s *psgiRuntimeSupervisor) updateStatus(mat PSGIRuntimeMaterializedStatus, identity *phpRuntimeResolvedIdentity, running bool, pid int, action string, lastErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateStatusLocked(mat, identity, running, pid, action, lastErr)
}

func (s *psgiRuntimeSupervisor) updateStatusLocked(mat PSGIRuntimeMaterializedStatus, identity *phpRuntimeResolvedIdentity, running bool, pid int, action string, lastErr string) {
	status := s.statuses[mat.ProcessID]
	status.ProcessID = mat.ProcessID
	status.VhostName = mat.VhostName
	status.RuntimeID = mat.RuntimeID
	status.Running = running
	status.PID = pid
	status.PerlPath = mat.PerlPath
	status.StarmanPath = mat.StarmanPath
	status.ConfiguredUser = mat.RunUser
	status.ConfiguredGroup = mat.RunGroup
	status.AppRoot = mat.AppRoot
	status.PSGIFile = mat.PSGIFile
	status.PSGIPath = mat.PSGIPath
	status.ListenHost = psgiRuntimeListenHost(mat)
	status.ListenPort = mat.ListenPort
	status.Workers = mat.Workers
	status.MaxRequests = mat.MaxRequests
	status.IncludeExtlib = mat.IncludeExtlib
	status.GeneratedTarget = mat.GeneratedTarget
	status.LastAction = action
	status.LastError = trimStatusError(lastErr)
	if identity != nil {
		status.EffectiveUser = identity.EffectiveUser
		status.EffectiveGroup = identity.EffectiveGroup
		status.EffectiveUID = int(identity.UID)
		status.EffectiveGID = int(identity.GID)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if action == "starting" {
		if strings.TrimSpace(status.StartedAt) == "" {
			status.StartedAt = now
		}
		status.StoppedAt = ""
	} else if running {
		if strings.TrimSpace(status.StartedAt) == "" {
			status.StartedAt = now
		}
		status.StoppedAt = ""
	} else {
		status.PID = 0
		status.StoppedAt = now
	}
	s.statuses[mat.ProcessID] = status
}

func resolvePSGIRuntimeIdentity(mat PSGIRuntimeMaterializedStatus) (phpRuntimeResolvedIdentity, error) {
	currentUID := uint32(os.Geteuid())
	currentGID := uint32(os.Getegid())
	currentUser := lookupUserLabel(currentUID)
	currentGroup := lookupGroupLabel(currentGID)
	out := phpRuntimeResolvedIdentity{
		ConfiguredUser:  strings.TrimSpace(mat.RunUser),
		ConfiguredGroup: strings.TrimSpace(mat.RunGroup),
		EffectiveUser:   currentUser,
		EffectiveGroup:  currentGroup,
		UID:             currentUID,
		GID:             currentGID,
	}

	if out.ConfiguredUser != "" {
		uid, label, primaryGID, err := resolvePHPRuntimeUserSpec(out.ConfiguredUser)
		if err != nil {
			return phpRuntimeResolvedIdentity{}, fmt.Errorf("psgi process %q run_user: %w", mat.ProcessID, err)
		}
		out.UID = uid
		out.EffectiveUser = label
		if out.ConfiguredGroup == "" {
			if primaryGID == nil {
				return phpRuntimeResolvedIdentity{}, fmt.Errorf("psgi process %q run_group is required when run_user %q has no passwd entry", mat.ProcessID, out.ConfiguredUser)
			}
			out.GID = *primaryGID
			out.EffectiveGroup = lookupGroupLabel(*primaryGID)
		}
	}

	if out.ConfiguredGroup != "" {
		gid, label, err := resolvePHPRuntimeGroupSpec(out.ConfiguredGroup)
		if err != nil {
			return phpRuntimeResolvedIdentity{}, fmt.Errorf("psgi process %q run_group: %w", mat.ProcessID, err)
		}
		out.GID = gid
		out.EffectiveGroup = label
	}
	return out, nil
}

func validatePSGIRuntimeLaunch(mat PSGIRuntimeMaterializedStatus, identity phpRuntimeResolvedIdentity) error {
	if err := validatePHPRuntimePrivilegeTransition(identity); err != nil {
		return err
	}
	if err := ensurePSGIRuntimeDirAccess(mat, identity); err != nil {
		return err
	}
	if err := validatePSGIApplicationPaths(mat, identity); err != nil {
		return err
	}
	return nil
}

func ensurePSGIRuntimeDirAccess(mat PSGIRuntimeMaterializedStatus, identity phpRuntimeResolvedIdentity) error {
	runtimeDir := strings.TrimSpace(mat.RuntimeDir)
	if runtimeDir == "" {
		return fmt.Errorf("psgi process %q runtime_dir is empty", mat.ProcessID)
	}
	if os.Geteuid() == 0 && (identity.UID != 0 || identity.GID != 0) {
		if err := filepath.Walk(runtimeDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Chown(path, int(identity.UID), int(identity.GID))
		}); err != nil {
			return fmt.Errorf("psgi process %q runtime_dir ownership update failed: %w", mat.ProcessID, err)
		}
	}
	if err := validateRuntimePathAccess(runtimeDir, identity.UID, identity.GID, 0o7); err != nil {
		return fmt.Errorf("psgi process %q runtime_dir %q: %w", mat.ProcessID, runtimeDir, err)
	}
	if err := validateRuntimePathAccess(mat.ManifestFile, identity.UID, identity.GID, 0o4); err != nil {
		return fmt.Errorf("psgi process %q manifest_file %q: %w", mat.ProcessID, mat.ManifestFile, err)
	}
	return nil
}

func validatePSGIApplicationPaths(mat PSGIRuntimeMaterializedStatus, identity phpRuntimeResolvedIdentity) error {
	for label, path := range map[string]string{
		"perl_path":     mat.PerlPath,
		"starman_path":  mat.StarmanPath,
		"app_root":      mat.AppRoot,
		"document_root": mat.DocumentRoot,
		"psgi_path":     mat.PSGIPath,
	} {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("psgi process %q %s is empty", mat.ProcessID, label)
		}
	}
	if err := validateRuntimePathAccess(mat.PerlPath, identity.UID, identity.GID, 0o5); err != nil {
		return fmt.Errorf("psgi process %q perl_path %q: %w", mat.ProcessID, mat.PerlPath, err)
	}
	if err := validateRuntimePathAccess(mat.StarmanPath, identity.UID, identity.GID, 0o5); err != nil {
		return fmt.Errorf("psgi process %q starman_path %q: %w", mat.ProcessID, mat.StarmanPath, err)
	}
	if err := validateRuntimeDirPath(mat.ProcessID, "app_root", mat.AppRoot, identity); err != nil {
		return err
	}
	if err := validateRuntimeDirPath(mat.ProcessID, "document_root", mat.DocumentRoot, identity); err != nil {
		return err
	}
	if err := validateRuntimePathAccess(mat.PSGIPath, identity.UID, identity.GID, 0o4); err != nil {
		return fmt.Errorf("psgi process %q psgi_path %q: %w", mat.ProcessID, mat.PSGIPath, err)
	}
	return nil
}

func validateRuntimeDirPath(processID string, label string, path string, identity phpRuntimeResolvedIdentity) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("psgi process %q %s %q: %w", processID, label, path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("psgi process %q %s %q must be a directory", processID, label, path)
	}
	if err := validateRuntimePathAccess(path, identity.UID, identity.GID, 0o5); err != nil {
		return fmt.Errorf("psgi process %q %s %q: %w", processID, label, path, err)
	}
	return nil
}

func psgiRuntimeMaterializationSignature(mat PSGIRuntimeMaterializedStatus) (string, error) {
	sum := sha256.New()
	writeHashPart := func(value string) {
		sum.Write([]byte(value))
		sum.Write([]byte{0})
	}
	writeHashPart(mat.ProcessID)
	writeHashPart(mat.VhostName)
	writeHashPart(mat.RuntimeID)
	writeHashPart(mat.PerlPath)
	writeHashPart(mat.StarmanPath)
	writeHashPart(mat.RunUser)
	writeHashPart(mat.RunGroup)
	writeHashPart(mat.AppRoot)
	writeHashPart(mat.DocumentRoot)
	writeHashPart(mat.PSGIFile)
	writeHashPart(mat.PSGIPath)
	writeHashPart(psgiRuntimeListenHost(mat))
	writeHashPart(fmt.Sprintf("%d", mat.ListenPort))
	writeHashPart(fmt.Sprintf("%d", mat.Workers))
	writeHashPart(fmt.Sprintf("%d", mat.MaxRequests))
	writeHashPart(fmt.Sprintf("%t", mat.IncludeExtlib))
	writeHashPart(mat.GeneratedTarget)
	writeHashPart(psgiRuntimeArgsSignature(mat))
	keys := make([]string, 0, len(mat.Env))
	for key := range mat.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writeHashPart(key)
		writeHashPart(mat.Env[key])
	}
	manifest, err := os.ReadFile(mat.ManifestFile)
	if err != nil {
		return "", err
	}
	sum.Write(manifest)
	return hex.EncodeToString(sum.Sum(nil)), nil
}
