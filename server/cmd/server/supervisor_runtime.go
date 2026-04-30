package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

const (
	defaultSupervisorReadyTimeout = 30 * time.Second
	defaultSupervisorStopTimeout  = 10 * time.Second
	workerActivateFD              = 4
	workerDrainFD                 = 5
	workerListenFDStart           = 6
	workerActivateFDEnv           = "TUKUYOMI_WORKER_ACTIVATE_FD"
	workerDrainFDEnv              = "TUKUYOMI_WORKER_DRAIN_FD"
	workerListenFDsEnv            = "TUKUYOMI_WORKER_LISTEN_FDS"
	workerListenFDNamesEnv        = "TUKUYOMI_WORKER_LISTEN_FDNAMES"
)

type managedWorkerProcess struct {
	cmd              *exec.Cmd
	waitCh           chan error
	activationWriter *os.File
	drainWriter      *os.File
}

type supervisorWorker interface {
	Activate() error
	Drain(time.Duration) error
	Stop(time.Duration) error
	Wait() <-chan error
	ProcessID() int
}

type supervisorWorkerGeneration struct {
	id         int
	executable string
	worker     supervisorWorker
	ready      workerReadyMessage
	activated  time.Time
}

type supervisorRuntime struct {
	mu             sync.Mutex
	replaceMu      sync.Mutex
	executable     string
	listeners      *supervisorListenerSet
	readyTimeout   time.Duration
	stopTimeout    time.Duration
	rollbackWindow time.Duration
	nextGeneration int
	enableReplace  bool
	stateStore     *supervisorWorkerStateStore
	timeNow        func() time.Time
	active         *supervisorWorkerGeneration
	activeChange   chan struct{}
	startWorker    func(context.Context, string, *supervisorListenerSet, time.Duration) (supervisorWorker, workerReadyMessage, error)
}

type supervisorListenerSpec struct {
	role string
	addr string
}

type supervisorListenerEntry struct {
	role      string
	listener  net.Listener
	inherited bool
}

type supervisorListenerFile struct {
	role string
	file *os.File
}

type supervisorListenerSet struct {
	entries []supervisorListenerEntry
}

func runSupervisorServer() error {
	if strings.TrimSpace(config.ConfigFile) == "" {
		config.LoadEnv()
	}
	initRuntimeDBStoreOrFatal("[SUPERVISOR][DB][BOOTSTRAP]")
	if err := handler.SyncAppConfigStorage(); err != nil {
		return fmt.Errorf("sync supervisor app config: %w", err)
	}
	if err := initRuntimeAppsProcessOwner(); err != nil {
		return fmt.Errorf("initialize supervisor runtime apps owner: %w", err)
	}
	defer shutdownRuntimeAppSupervisors()
	controlServer, err := startRuntimeAppsControlServer()
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := controlServer.Close(ctx); err != nil {
			log.Printf("[RUNTIME_APPS][CONTROL][WARN] close: %v", err)
		}
	}()
	prevControlSocket, hadControlSocket := os.LookupEnv(runtimeAppsControlSocketEnv)
	if err := os.Setenv(runtimeAppsControlSocketEnv, controlServer.SocketPath()); err != nil {
		return fmt.Errorf("export runtime apps control socket: %w", err)
	}
	defer func() {
		if hadControlSocket {
			_ = os.Setenv(runtimeAppsControlSocketEnv, prevControlSocket)
		} else {
			_ = os.Unsetenv(runtimeAppsControlSocketEnv)
		}
	}()
	activation, err := loadSystemdActivationFromEnv()
	if err != nil {
		return fmt.Errorf("load supervisor listener activation: %w", err)
	}
	if activation.Active() {
		log.Printf("[SUPERVISOR] systemd socket activation enabled fds=%d", len(activation.fds))
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}

	listeners, err := prepareSupervisorListenerSet(activation)
	if err != nil {
		return err
	}
	defer listeners.Close()
	for _, entry := range listeners.entries {
		log.Printf("[SUPERVISOR] listener ready role=%s addr=%s inherited=%t", entry.role, entry.listener.Addr(), entry.inherited)
	}

	releasesDir := supervisorReleasesDirFromEnv()
	runtime := newSupervisorRuntime(executable, listeners)
	runtime.enableReplace = true
	active, err := runtime.StartInitial(context.Background())
	if err != nil {
		return err
	}
	releaseManager := newSupervisorReleaseManager(releasesDir)
	releaseControlServer, err := startSupervisorControlServer(runtime, releaseManager)
	if err != nil {
		if stopErr := active.worker.Stop(runtime.stopTimeout); stopErr != nil {
			log.Printf("[SUPERVISOR][WARN] stop active worker after control startup failure: %v", stopErr)
		}
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := releaseControlServer.Close(ctx); err != nil {
			log.Printf("[SUPERVISOR][CONTROL][WARN] close: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	return runtime.Run(active, sigCh)
}

func newSupervisorRuntime(executable string, listeners *supervisorListenerSet) *supervisorRuntime {
	releasesDir := supervisorReleasesDirFromEnv()
	return &supervisorRuntime{
		executable:     executable,
		listeners:      listeners,
		readyTimeout:   defaultSupervisorReadyTimeout,
		stopTimeout:    defaultSupervisorStopTimeout,
		stateStore:     newSupervisorWorkerStateStore(supervisorWorkerStatePathFromEnv(releasesDir)),
		rollbackWindow: defaultSupervisorRollbackWindow,
		activeChange:   make(chan struct{}),
		startWorker: func(ctx context.Context, executable string, listeners *supervisorListenerSet, timeout time.Duration) (supervisorWorker, workerReadyMessage, error) {
			return startWorkerCandidate(ctx, executable, listeners, timeout)
		},
	}
}

func (r *supervisorRuntime) Run(active *supervisorWorkerGeneration, sigCh <-chan os.Signal) error {
	if r == nil || active == nil || active.worker == nil {
		return fmt.Errorf("active worker is required")
	}
	r.setActive(active)
	for {
		active = r.activeGeneration()
		if active == nil || active.worker == nil {
			return fmt.Errorf("active worker is required")
		}
		waitCh := active.worker.Wait()
		activeChange := r.activeChangeChannel()
		select {
		case sig := <-sigCh:
			active = r.activeGeneration()
			if active == nil || active.worker == nil {
				return fmt.Errorf("active worker is required")
			}
			log.Printf("[SUPERVISOR] received %s; draining active worker", sig)
			return active.worker.Drain(r.stopTimeout)
		case err := <-waitCh:
			if r.activeGeneration() != active {
				continue
			}
			next, rollbackErr := r.rollbackAfterActiveExit(context.Background(), active, err)
			if rollbackErr == nil && next != nil {
				r.setActive(next)
				continue
			}
			if err == nil {
				return fmt.Errorf("worker exited unexpectedly")
			}
			return fmt.Errorf("worker stopped unexpectedly: %w", err)
		case <-activeChange:
			continue
		}
	}
}

func (r *supervisorRuntime) StartInitial(ctx context.Context) (*supervisorWorkerGeneration, error) {
	started := r.now()
	priorState, priorFound, err := r.loadWorkerState()
	if err != nil {
		return nil, err
	}
	if priorFound {
		r.seedNextGenerationFromState(priorState)
	}
	gen, err := r.startCandidate(ctx)
	if err != nil {
		return nil, err
	}
	if err := gen.worker.Activate(); err != nil {
		_ = gen.worker.Stop(r.stopTimeout)
		return nil, fmt.Errorf("activate initial worker: %w", err)
	}
	gen.activated = r.now()
	var previous *supervisorWorkerGenerationState
	if priorFound && priorState.Previous != nil {
		prev := *priorState.Previous
		previous = &prev
	}
	if err := r.recordWorkerActivationSuccess("initial", gen, previous, started); err != nil {
		_ = gen.worker.Stop(r.stopTimeout)
		return nil, fmt.Errorf("persist initial worker state: %w", err)
	}
	r.setActive(gen)
	log.Printf("[SUPERVISOR] worker activated generation=%d pid=%d", gen.id, gen.worker.ProcessID())
	return gen, nil
}

func (r *supervisorRuntime) Replace(ctx context.Context, active *supervisorWorkerGeneration) (*supervisorWorkerGeneration, error) {
	return r.ReplaceWithExecutable(ctx, active, r.executable)
}

func (r *supervisorRuntime) ReplaceWithExecutable(ctx context.Context, active *supervisorWorkerGeneration, executable string) (*supervisorWorkerGeneration, error) {
	if active == nil || active.worker == nil {
		return nil, fmt.Errorf("active worker is required")
	}
	if !r.enableReplace {
		return nil, fmt.Errorf("worker replacement is disabled")
	}
	if active.id > r.nextGeneration {
		r.nextGeneration = active.id
	}
	started := r.now()
	candidate, err := r.startCandidateWithExecutable(ctx, executable)
	if err != nil {
		if stateErr := r.recordWorkerActivationFailure("replace", active, nil, err, started); stateErr != nil {
			return nil, fmt.Errorf("%w; record activation failure: %v", err, stateErr)
		}
		return nil, err
	}
	if err := candidate.worker.Activate(); err != nil {
		_ = candidate.worker.Stop(r.stopTimeout)
		if stateErr := r.recordWorkerActivationFailure("replace", active, candidate, err, started); stateErr != nil {
			return nil, fmt.Errorf("activate candidate worker: %w; record activation failure: %v", err, stateErr)
		}
		return nil, fmt.Errorf("activate candidate worker: %w", err)
	}
	candidate.activated = r.now()
	previous := supervisorGenerationStateFromGeneration(active, "previous")
	if err := r.recordWorkerActivationSuccess("replace", candidate, &previous, started); err != nil {
		_ = candidate.worker.Stop(r.stopTimeout)
		return nil, fmt.Errorf("persist candidate worker state: %w", err)
	}
	log.Printf(
		"[SUPERVISOR] worker activated generation=%d pid=%d previous_generation=%d previous_pid=%d",
		candidate.id,
		candidate.worker.ProcessID(),
		active.id,
		active.worker.ProcessID(),
	)
	if err := active.worker.Drain(r.stopTimeout); err != nil {
		if stateErr := r.recordWorkerActivationFailure("replace_drain_previous", candidate, active, err, started); stateErr != nil {
			return candidate, fmt.Errorf("drain previous worker: %w; record activation failure: %v", err, stateErr)
		}
		return candidate, fmt.Errorf("drain previous worker: %w", err)
	}
	log.Printf("[SUPERVISOR] previous worker drained generation=%d pid=%d", active.id, active.worker.ProcessID())
	return candidate, nil
}

func (r *supervisorRuntime) ReplaceActive(ctx context.Context, executable string) (*supervisorWorkerGeneration, error) {
	if r == nil {
		return nil, fmt.Errorf("supervisor runtime is nil")
	}
	r.replaceMu.Lock()
	defer r.replaceMu.Unlock()
	active := r.activeGeneration()
	if active == nil || active.worker == nil {
		return nil, fmt.Errorf("active worker is required")
	}
	next, err := r.ReplaceWithExecutable(ctx, active, executable)
	if err != nil {
		return nil, err
	}
	r.setActive(next)
	return next, nil
}

func (r *supervisorRuntime) RollbackActive(ctx context.Context) (*supervisorWorkerGeneration, error) {
	if r == nil {
		return nil, fmt.Errorf("supervisor runtime is nil")
	}
	r.replaceMu.Lock()
	defer r.replaceMu.Unlock()
	if r.stateStore == nil {
		return nil, fmt.Errorf("worker state store is not configured")
	}
	state, found, err := r.stateStore.Load()
	if err != nil {
		return nil, err
	}
	if !found || state.Previous == nil || strings.TrimSpace(state.Previous.Executable) == "" {
		return nil, fmt.Errorf("no previous worker generation is available for rollback")
	}
	active := r.activeGeneration()
	if active == nil || active.worker == nil {
		return nil, fmt.Errorf("active worker is required")
	}
	next, err := r.ReplaceWithExecutable(ctx, active, state.Previous.Executable)
	if err != nil {
		return nil, err
	}
	r.setActive(next)
	return next, nil
}

func (r *supervisorRuntime) startCandidate(ctx context.Context) (*supervisorWorkerGeneration, error) {
	return r.startCandidateWithExecutable(ctx, r.executable)
}

func (r *supervisorRuntime) startCandidateWithExecutable(ctx context.Context, executable string) (*supervisorWorkerGeneration, error) {
	if r == nil {
		return nil, fmt.Errorf("supervisor runtime is nil")
	}
	if r.startWorker == nil {
		return nil, fmt.Errorf("worker starter is nil")
	}
	executable = strings.TrimSpace(executable)
	if executable == "" {
		return nil, fmt.Errorf("worker executable path is empty")
	}
	worker, ready, err := r.startWorker(ctx, executable, r.listeners, r.readyTimeout)
	if err != nil {
		return nil, err
	}
	r.nextGeneration++
	gen := &supervisorWorkerGeneration{
		id:         r.nextGeneration,
		executable: executable,
		worker:     worker,
		ready:      ready,
	}
	log.Printf(
		"[SUPERVISOR] worker ready generation=%d pid=%d listen=%s admin=%s tls=%t http3=%t version=%s go=%s",
		gen.id,
		ready.PID,
		ready.ListenAddr,
		ready.AdminListenAddr,
		ready.TLSEnabled,
		ready.HTTP3Enabled,
		ready.Version,
		ready.GoVersion,
	)
	return gen, nil
}

func (r *supervisorRuntime) rollbackAfterActiveExit(ctx context.Context, active *supervisorWorkerGeneration, waitErr error) (*supervisorWorkerGeneration, error) {
	if r == nil || active == nil {
		return nil, fmt.Errorf("active worker is required")
	}
	if r.stateStore == nil {
		return nil, fmt.Errorf("worker state store is not configured")
	}
	if r.rollbackWindow <= 0 {
		return nil, fmt.Errorf("worker rollback window is disabled")
	}
	state, found, err := r.stateStore.Load()
	if err != nil {
		return nil, err
	}
	if !found || state.Previous == nil {
		return nil, fmt.Errorf("no previous worker generation is available for rollback")
	}
	activeActivatedAt := active.activated
	if activeActivatedAt.IsZero() && strings.TrimSpace(state.Active.ActivatedAt) != "" {
		if parsed, parseErr := time.Parse(time.RFC3339Nano, state.Active.ActivatedAt); parseErr == nil {
			activeActivatedAt = parsed
		}
	}
	if activeActivatedAt.IsZero() {
		return nil, fmt.Errorf("active worker activation time is unknown")
	}
	now := r.now()
	if now.Sub(activeActivatedAt) > r.rollbackWindow {
		return nil, fmt.Errorf("active worker failed outside rollback window")
	}
	previous := *state.Previous
	r.seedNextGenerationFromState(state)
	started := now
	rollback, err := r.startCandidateWithExecutable(ctx, previous.Executable)
	if err != nil {
		if stateErr := r.recordWorkerActivationFailure("rollback", active, nil, err, started); stateErr != nil {
			return nil, fmt.Errorf("%w; record rollback failure: %v", err, stateErr)
		}
		return nil, err
	}
	if err := rollback.worker.Activate(); err != nil {
		_ = rollback.worker.Stop(r.stopTimeout)
		if stateErr := r.recordWorkerActivationFailure("rollback", active, rollback, err, started); stateErr != nil {
			return nil, fmt.Errorf("activate rollback worker: %w; record rollback failure: %v", err, stateErr)
		}
		return nil, fmt.Errorf("activate rollback worker: %w", err)
	}
	rollback.activated = r.now()
	crashed := supervisorGenerationStateFromGeneration(active, "crashed")
	if strings.TrimSpace(crashed.Executable) == "" {
		crashed = state.Active
		crashed.Status = "crashed"
	}
	if err := r.recordWorkerActivationSuccess("rollback", rollback, &crashed, started); err != nil {
		_ = rollback.worker.Stop(r.stopTimeout)
		return nil, fmt.Errorf("persist rollback worker state: %w", err)
	}
	log.Printf(
		"[SUPERVISOR] rolled back worker after active exit generation=%d pid=%d previous_generation=%d previous_pid=%d exit=%v",
		rollback.id,
		rollback.worker.ProcessID(),
		active.id,
		active.worker.ProcessID(),
		waitErr,
	)
	return rollback, nil
}

func (r *supervisorRuntime) now() time.Time {
	if r != nil && r.timeNow != nil {
		return r.timeNow().UTC()
	}
	return time.Now().UTC()
}

func (r *supervisorRuntime) loadWorkerState() (supervisorWorkerRuntimeState, bool, error) {
	if r == nil || r.stateStore == nil {
		return supervisorWorkerRuntimeState{}, false, nil
	}
	return r.stateStore.Load()
}

func (r *supervisorRuntime) seedNextGenerationFromState(state supervisorWorkerRuntimeState) {
	if r == nil {
		return
	}
	if maxID := maxSupervisorWorkerGenerationID(state); maxID > r.nextGeneration {
		r.nextGeneration = maxID
	}
}

func (r *supervisorRuntime) activeGeneration() *supervisorWorkerGeneration {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

func (r *supervisorRuntime) setActive(active *supervisorWorkerGeneration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active = active
	if r.activeChange == nil {
		r.activeChange = make(chan struct{})
		return
	}
	close(r.activeChange)
	r.activeChange = make(chan struct{})
}

func (r *supervisorRuntime) activeChangeChannel() <-chan struct{} {
	if r == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.activeChange == nil {
		r.activeChange = make(chan struct{})
	}
	return r.activeChange
}

func (r *supervisorRuntime) recordWorkerActivationSuccess(action string, active *supervisorWorkerGeneration, previous *supervisorWorkerGenerationState, started time.Time) error {
	if r == nil || r.stateStore == nil {
		return nil
	}
	activeState := supervisorGenerationStateFromGeneration(active, "active")
	completed := r.now()
	result := supervisorWorkerActivationResult{
		Action:                strings.TrimSpace(action),
		Success:               true,
		CandidateGenerationID: activeState.GenerationID,
		ActiveGenerationID:    activeState.GenerationID,
		StartedAt:             started.UTC().Format(time.RFC3339Nano),
		CompletedAt:           completed.Format(time.RFC3339Nano),
	}
	if previous != nil {
		result.PreviousGenerationID = previous.GenerationID
	}
	return r.stateStore.Save(supervisorWorkerRuntimeState{
		Active:         activeState,
		Previous:       previous,
		LastActivation: &result,
		UpdatedAt:      completed.Format(time.RFC3339Nano),
	})
}

func (r *supervisorRuntime) recordWorkerActivationFailure(action string, active *supervisorWorkerGeneration, candidate *supervisorWorkerGeneration, failure error, started time.Time) error {
	if r == nil || r.stateStore == nil {
		return nil
	}
	prior, found, err := r.stateStore.Load()
	if err != nil {
		return err
	}
	activeState := supervisorGenerationStateFromGeneration(active, "active")
	if strings.TrimSpace(activeState.Executable) == "" && found {
		activeState = prior.Active
	}
	previous := prior.Previous
	candidateID := 0
	if candidate != nil {
		candidateID = candidate.id
	}
	completed := r.now()
	result := supervisorWorkerActivationResult{
		Action:                strings.TrimSpace(action),
		Success:               false,
		Error:                 failureMessage(failure),
		CandidateGenerationID: candidateID,
		ActiveGenerationID:    activeState.GenerationID,
		StartedAt:             started.UTC().Format(time.RFC3339Nano),
		CompletedAt:           completed.Format(time.RFC3339Nano),
	}
	if previous != nil {
		result.PreviousGenerationID = previous.GenerationID
	}
	return r.stateStore.Save(supervisorWorkerRuntimeState{
		Active:         activeState,
		Previous:       previous,
		LastActivation: &result,
		UpdatedAt:      completed.Format(time.RFC3339Nano),
	})
}

func failureMessage(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}

func supervisorListenerSpecs() ([]supervisorListenerSpec, error) {
	if config.ServerHTTP3Enabled {
		return nil, fmt.Errorf("supervisor mode does not support HTTP/3 until UDP listener handoff is implemented")
	}
	specs := []supervisorListenerSpec{{role: "public", addr: config.ListenAddr}}
	if strings.TrimSpace(config.AdminListenAddr) != "" {
		specs = append(specs, supervisorListenerSpec{role: "admin", addr: config.AdminListenAddr})
	}
	if config.ServerTLSEnabled && config.ServerTLSRedirectHTTP {
		specs = append(specs, supervisorListenerSpec{role: "redirect", addr: config.ServerTLSHTTPRedirectAddr})
	}
	return specs, nil
}

func prepareSupervisorListenerSet(activation *systemdActivation) (*supervisorListenerSet, error) {
	specs, err := supervisorListenerSpecs()
	if err != nil {
		return nil, err
	}
	set := &supervisorListenerSet{entries: make([]supervisorListenerEntry, 0, len(specs))}
	for _, spec := range specs {
		ln, inherited, err := buildSupervisorTCPListenerForRole(spec.role, spec.addr, activation)
		if err != nil {
			set.Close()
			return nil, fmt.Errorf("create supervisor listener %s: %w", spec.role, err)
		}
		set.entries = append(set.entries, supervisorListenerEntry{
			role:      spec.role,
			listener:  ln,
			inherited: inherited,
		})
	}
	if activation != nil {
		activation.CloseUnused()
	}
	return set, nil
}

func buildSupervisorTCPListenerForRole(role string, addr string, activation *systemdActivation) (net.Listener, bool, error) {
	if activation != nil && activation.Active() {
		ln, ok, err := activation.TakeTCP(role, addr)
		if err != nil || ok {
			return ln, ok, err
		}
		return nil, false, fmt.Errorf("systemd activation is enabled but no fd exists for role %q", role)
	}
	ln, err := net.Listen("tcp", addr)
	return ln, false, err
}

func (s *supervisorListenerSet) Files() ([]supervisorListenerFile, error) {
	if s == nil || len(s.entries) == 0 {
		return nil, fmt.Errorf("supervisor listeners are required")
	}
	files := make([]supervisorListenerFile, 0, len(s.entries))
	for _, entry := range s.entries {
		fileProvider, ok := entry.listener.(interface {
			File() (*os.File, error)
		})
		if !ok {
			closeSupervisorListenerFiles(files)
			return nil, fmt.Errorf("listener %s does not expose a file descriptor", entry.role)
		}
		file, err := fileProvider.File()
		if err != nil {
			closeSupervisorListenerFiles(files)
			return nil, fmt.Errorf("duplicate listener %s fd: %w", entry.role, err)
		}
		files = append(files, supervisorListenerFile{role: entry.role, file: file})
	}
	return files, nil
}

func (s *supervisorListenerSet) Close() error {
	if s == nil {
		return nil
	}
	var out error
	for _, entry := range s.entries {
		if entry.listener == nil {
			continue
		}
		if err := entry.listener.Close(); err != nil && out == nil {
			out = err
		}
	}
	return out
}

func closeSupervisorListenerFiles(files []supervisorListenerFile) {
	for _, item := range files {
		if item.file != nil {
			_ = item.file.Close()
		}
	}
}

func startWorkerCandidate(ctx context.Context, executable string, listeners *supervisorListenerSet, readyTimeout time.Duration) (*managedWorkerProcess, workerReadyMessage, error) {
	if readyTimeout <= 0 {
		readyTimeout = defaultSupervisorReadyTimeout
	}
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		return nil, workerReadyMessage{}, fmt.Errorf("create readiness pipe: %w", err)
	}
	defer readyReader.Close()
	activationReader, activationWriter, err := os.Pipe()
	if err != nil {
		_ = readyWriter.Close()
		return nil, workerReadyMessage{}, fmt.Errorf("create activation pipe: %w", err)
	}
	drainReader, drainWriter, err := os.Pipe()
	if err != nil {
		_ = readyWriter.Close()
		_ = activationReader.Close()
		_ = activationWriter.Close()
		return nil, workerReadyMessage{}, fmt.Errorf("create drain pipe: %w", err)
	}

	listenerFiles, err := listeners.Files()
	if err != nil {
		_ = readyWriter.Close()
		_ = activationReader.Close()
		_ = activationWriter.Close()
		_ = drainReader.Close()
		_ = drainWriter.Close()
		return nil, workerReadyMessage{}, err
	}
	defer closeSupervisorListenerFiles(listenerFiles)

	cmd, err := buildWorkerCommand(executable, readyWriter, activationReader, drainReader, listenerFiles)
	if err != nil {
		_ = readyWriter.Close()
		_ = activationReader.Close()
		_ = activationWriter.Close()
		_ = drainReader.Close()
		_ = drainWriter.Close()
		return nil, workerReadyMessage{}, err
	}
	if err := cmd.Start(); err != nil {
		_ = readyWriter.Close()
		_ = activationReader.Close()
		_ = activationWriter.Close()
		_ = drainReader.Close()
		_ = drainWriter.Close()
		return nil, workerReadyMessage{}, fmt.Errorf("start worker: %w", err)
	}
	_ = readyWriter.Close()
	_ = activationReader.Close()
	_ = drainReader.Close()

	worker := &managedWorkerProcess{
		cmd:              cmd,
		waitCh:           make(chan error, 1),
		activationWriter: activationWriter,
		drainWriter:      drainWriter,
	}
	go func() {
		worker.waitCh <- cmd.Wait()
	}()

	readyCtx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	ready, err := waitForWorkerReady(readyCtx, readyReader, worker.waitCh)
	if err != nil {
		_ = worker.Stop(defaultSupervisorStopTimeout)
		return nil, workerReadyMessage{}, err
	}
	return worker, ready, nil
}

func buildWorkerCommand(executable string, readyWriter *os.File, activationReader *os.File, drainReader *os.File, listenerFiles []supervisorListenerFile) (*exec.Cmd, error) {
	executable = strings.TrimSpace(executable)
	if executable == "" {
		return nil, fmt.Errorf("worker executable path is empty")
	}
	if readyWriter == nil {
		return nil, fmt.Errorf("worker readiness writer is nil")
	}
	if activationReader == nil {
		return nil, fmt.Errorf("worker activation reader is nil")
	}
	if drainReader == nil {
		return nil, fmt.Errorf("worker drain reader is nil")
	}
	if len(listenerFiles) == 0 {
		return nil, fmt.Errorf("worker listener files are required")
	}
	names := make([]string, 0, len(listenerFiles))
	extraFiles := make([]*os.File, 0, len(listenerFiles)+3)
	extraFiles = append(extraFiles, readyWriter)
	extraFiles = append(extraFiles, activationReader)
	extraFiles = append(extraFiles, drainReader)
	for _, item := range listenerFiles {
		role := strings.TrimSpace(item.role)
		if role == "" || strings.Contains(role, ":") {
			return nil, fmt.Errorf("worker listener role %q is invalid", item.role)
		}
		if item.file == nil {
			return nil, fmt.Errorf("worker listener %s file is nil", role)
		}
		names = append(names, role)
		extraFiles = append(extraFiles, item.file)
	}
	cmd := exec.Command(executable)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(
		workerProcessEnv(os.Environ()),
		serverInternalProcessRoleEnv+"="+internalProcessRoleWorker,
		workerReadyFDEnv+"=3",
		workerActivateFDEnv+"="+fmt.Sprintf("%d", workerActivateFD),
		workerDrainFDEnv+"="+fmt.Sprintf("%d", workerDrainFD),
		workerListenFDsEnv+"="+fmt.Sprintf("%d", len(listenerFiles)),
		workerListenFDNamesEnv+"="+strings.Join(names, ":"),
	)
	cmd.ExtraFiles = extraFiles
	return cmd, nil
}

func workerProcessEnv(env []string) []string {
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		name, _, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		switch name {
		case "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PID", serverInternalProcessRoleEnv, workerReadyFDEnv, workerActivateFDEnv, workerDrainFDEnv, workerListenFDsEnv, workerListenFDNamesEnv:
			continue
		default:
			out = append(out, item)
		}
	}
	return out
}

func systemdActivationEnvPresent(env []string) bool {
	for _, item := range env {
		name, value, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		if name == "LISTEN_FDS" && strings.TrimSpace(value) != "" && strings.TrimSpace(value) != "0" {
			return true
		}
	}
	return false
}

func waitForWorkerReady(ctx context.Context, readyReader io.Reader, waitCh <-chan error) (workerReadyMessage, error) {
	if readyReader == nil {
		return workerReadyMessage{}, fmt.Errorf("worker readiness reader is nil")
	}
	readyCh := make(chan workerReadyResult, 1)
	go func() {
		var msg workerReadyMessage
		err := json.NewDecoder(readyReader).Decode(&msg)
		if err == nil {
			err = validateWorkerReadyMessage(msg)
		}
		readyCh <- workerReadyResult{msg: msg, err: err}
	}()

	select {
	case result := <-readyCh:
		if result.err != nil {
			return workerReadyMessage{}, fmt.Errorf("worker readiness failed: %w", result.err)
		}
		return result.msg, nil
	case err := <-waitCh:
		if err == nil {
			return workerReadyMessage{}, fmt.Errorf("worker exited before readiness")
		}
		return workerReadyMessage{}, fmt.Errorf("worker exited before readiness: %w", err)
	case <-ctx.Done():
		return workerReadyMessage{}, fmt.Errorf("worker readiness timeout: %w", ctx.Err())
	}
}

type workerReadyResult struct {
	msg workerReadyMessage
	err error
}

func (w *managedWorkerProcess) Wait() <-chan error {
	if w == nil {
		ch := make(chan error)
		close(ch)
		return ch
	}
	return w.waitCh
}

func (w *managedWorkerProcess) ProcessID() int {
	if w == nil || w.cmd == nil || w.cmd.Process == nil {
		return 0
	}
	return w.cmd.Process.Pid
}

func (w *managedWorkerProcess) Activate() error {
	if w == nil || w.activationWriter == nil {
		return nil
	}
	_, err := w.activationWriter.Write([]byte("1"))
	closeErr := w.activationWriter.Close()
	w.activationWriter = nil
	if err != nil {
		return err
	}
	return closeErr
}

func (w *managedWorkerProcess) Drain(grace time.Duration) error {
	if w == nil || w.cmd == nil || w.cmd.Process == nil {
		return nil
	}
	if grace <= 0 {
		grace = defaultSupervisorStopTimeout
	}
	select {
	case err := <-w.waitCh:
		return normalizeWorkerStopError(err)
	default:
	}
	if w.activationWriter != nil {
		_ = w.activationWriter.Close()
		w.activationWriter = nil
	}
	if w.drainWriter != nil {
		_, err := w.drainWriter.Write([]byte("1"))
		closeErr := w.drainWriter.Close()
		w.drainWriter = nil
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	} else if err := w.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		select {
		case waitErr := <-w.waitCh:
			return normalizeWorkerStopError(waitErr)
		default:
		}
		return err
	}
	select {
	case err := <-w.waitCh:
		return normalizeWorkerStopError(err)
	case <-time.After(grace):
		if err := w.cmd.Process.Kill(); err != nil {
			return err
		}
		return normalizeWorkerStopError(<-w.waitCh)
	}
}

func (w *managedWorkerProcess) Stop(grace time.Duration) error {
	if w == nil || w.cmd == nil || w.cmd.Process == nil {
		return nil
	}
	if w.activationWriter != nil {
		_ = w.activationWriter.Close()
		w.activationWriter = nil
	}
	if w.drainWriter != nil {
		_ = w.drainWriter.Close()
		w.drainWriter = nil
	}
	if grace <= 0 {
		grace = defaultSupervisorStopTimeout
	}
	select {
	case err := <-w.waitCh:
		return normalizeWorkerStopError(err)
	default:
	}
	if err := w.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		select {
		case waitErr := <-w.waitCh:
			return normalizeWorkerStopError(waitErr)
		default:
		}
		return err
	}
	select {
	case err := <-w.waitCh:
		return normalizeWorkerStopError(err)
	case <-time.After(grace):
		if err := w.cmd.Process.Kill(); err != nil {
			return err
		}
		return normalizeWorkerStopError(<-w.waitCh)
	}
}

func normalizeWorkerStopError(err error) error {
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() < 0 {
		return nil
	}
	return err
}
