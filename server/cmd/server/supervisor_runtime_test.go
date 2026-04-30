package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

func TestBuildWorkerCommand(t *testing.T) {
	t.Parallel()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer reader.Close()
	defer writer.Close()
	activationReader, activationWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("activation pipe: %v", err)
	}
	defer activationReader.Close()
	defer activationWriter.Close()
	drainReader, drainWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("drain pipe: %v", err)
	}
	defer drainReader.Close()
	defer drainWriter.Close()

	listeners := testSupervisorListenerFiles(t, "public")
	cmd, err := buildWorkerCommand("/tmp/tukuyomi-test", writer, activationReader, drainReader, listeners)
	if err != nil {
		t.Fatalf("buildWorkerCommand: %v", err)
	}
	if got, want := cmd.Path, "/tmp/tukuyomi-test"; got != want {
		t.Fatalf("path=%q want=%q", got, want)
	}
	if len(cmd.Args) != 1 {
		t.Fatalf("args=%#v want no public worker command", cmd.Args)
	}
	if len(cmd.ExtraFiles) != 4 || cmd.ExtraFiles[0] != writer || cmd.ExtraFiles[1] != activationReader || cmd.ExtraFiles[2] != drainReader || cmd.ExtraFiles[3] != listeners[0].file {
		t.Fatalf("extra files=%#v want readiness writer, activation reader, drain reader, public listener", cmd.ExtraFiles)
	}
	if !envContains(cmd.Env, serverInternalProcessRoleEnv+"="+internalProcessRoleWorker) {
		t.Fatalf("env missing %s=%s", serverInternalProcessRoleEnv, internalProcessRoleWorker)
	}
	if !envContains(cmd.Env, workerReadyFDEnv+"=3") {
		t.Fatalf("env missing %s=3", workerReadyFDEnv)
	}
	if !envContains(cmd.Env, workerActivateFDEnv+"=4") {
		t.Fatalf("env missing %s=4", workerActivateFDEnv)
	}
	if !envContains(cmd.Env, workerDrainFDEnv+"=5") {
		t.Fatalf("env missing %s=5", workerDrainFDEnv)
	}
	if !envContains(cmd.Env, workerListenFDsEnv+"=1") {
		t.Fatalf("env missing %s=1", workerListenFDsEnv)
	}
	if !envContains(cmd.Env, workerListenFDNamesEnv+"=public") {
		t.Fatalf("env missing %s=public", workerListenFDNamesEnv)
	}
	if envContainsPrefix(cmd.Env, "LISTEN_FDS=") || envContainsPrefix(cmd.Env, "LISTEN_PID=") {
		t.Fatalf("env must not expose systemd activation vars: %#v", cmd.Env)
	}
}

func TestWorkerProcessEnvDropsInheritedActivation(t *testing.T) {
	t.Parallel()

	got := workerProcessEnv([]string{
		"LISTEN_FDS=4",
		"LISTEN_FDNAMES=public:admin",
		"LISTEN_PID=123",
		serverInternalProcessRoleEnv + "=" + internalProcessRoleSupervisor,
		workerReadyFDEnv + "=8",
		workerActivateFDEnv + "=9",
		workerDrainFDEnv + "=10",
		workerListenFDsEnv + "=2",
		workerListenFDNamesEnv + "=public:admin",
		"KEEP=value",
	})
	if len(got) != 1 || got[0] != "KEEP=value" {
		t.Fatalf("env=%#v want only KEEP", got)
	}
}

func TestWorkerProcessEnvPreservesRuntimeAppsControlSocket(t *testing.T) {
	t.Parallel()

	got := workerProcessEnv([]string{
		runtimeAppsControlSocketEnv + "=/tmp/tukuyomi-runtime-apps.sock",
		"KEEP=value",
	})
	if !envContains(got, runtimeAppsControlSocketEnv+"=/tmp/tukuyomi-runtime-apps.sock") {
		t.Fatalf("env=%#v missing runtime apps control socket", got)
	}
	if !envContains(got, "KEEP=value") {
		t.Fatalf("env=%#v missing KEEP", got)
	}
}

func TestConfigureRuntimeAppProcessControllerForWorkerRequiresSocket(t *testing.T) {
	t.Setenv(serverInternalProcessRoleEnv, internalProcessRoleWorker)
	t.Setenv(runtimeAppsControlSocketEnv, "")
	t.Cleanup(handler.ResetRuntimeAppProcessController)

	err := configureRuntimeAppProcessControllerForWorker()
	if err == nil || !strings.Contains(err.Error(), runtimeAppsControlSocketEnv+" is required") {
		t.Fatalf("error=%v want missing runtime apps control socket", err)
	}
}

func TestValidateRuntimeAppsControlToken(t *testing.T) {
	t.Parallel()

	got, err := validateRuntimeAppsControlToken("runtime_id", " PHP85_1 ")
	if err != nil {
		t.Fatalf("validateRuntimeAppsControlToken: %v", err)
	}
	if got != "php85_1" {
		t.Fatalf("token=%q want php85_1", got)
	}
	for _, value := range []string{"", "bad/name", strings.Repeat("a", 129)} {
		if _, err := validateRuntimeAppsControlToken("runtime_id", value); err == nil {
			t.Fatalf("value %q accepted, want error", value)
		}
	}
}

func TestRuntimeAppsLocalProcessOwnerFromEnv(t *testing.T) {
	t.Parallel()

	if !runtimeAppsLocalProcessOwnerFromEnv(nil) {
		t.Fatal("default server process should own local Runtime Apps processes")
	}
	if runtimeAppsLocalProcessOwnerFromEnv([]string{serverInternalProcessRoleEnv + "=" + internalProcessRoleWorker}) {
		t.Fatal("worker process must not own local Runtime Apps processes")
	}
	if !runtimeAppsLocalProcessOwnerFromEnv([]string{serverInternalProcessRoleEnv + "=" + internalProcessRoleSupervisor}) {
		t.Fatal("supervisor process should own local Runtime Apps processes")
	}
}

func TestLoadWorkerListenerActivation(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		workerListenFDsEnv:     "2",
		workerListenFDNamesEnv: "public:admin",
	}
	activation, err := loadWorkerListenerActivation(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("loadWorkerListenerActivation: %v", err)
	}
	if !activation.Active() {
		t.Fatal("activation should be active")
	}
	if len(activation.fds) != 2 {
		t.Fatalf("fds=%#v", activation.fds)
	}
	if activation.fds[0].fd != workerListenFDStart || activation.fds[0].name != "public" {
		t.Fatalf("first fd=%#v", activation.fds[0])
	}
	if activation.fds[1].fd != workerListenFDStart+1 || activation.fds[1].name != "admin" {
		t.Fatalf("second fd=%#v", activation.fds[1])
	}
}

func TestActivationGateListenerBlocksUntilActivated(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	gate := newWorkerActivationGate()
	gated := &activationGateListener{Listener: ln, gate: gate}

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := gated.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer client.Close()

	select {
	case conn := <-accepted:
		_ = conn.Close()
		t.Fatal("accept completed before activation")
	case err := <-acceptErr:
		t.Fatalf("accept failed before activation: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	gate.activate()
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case err := <-acceptErr:
		t.Fatalf("accept failed after activation: %v", err)
	case <-time.After(time.Second):
		t.Fatal("accept did not complete after activation")
	}
}

func TestSupervisorListenerSpecsRejectHTTP3(t *testing.T) {
	old := config.ServerHTTP3Enabled
	config.ServerHTTP3Enabled = true
	t.Cleanup(func() { config.ServerHTTP3Enabled = old })

	_, err := supervisorListenerSpecs()
	if err == nil || !strings.Contains(err.Error(), "HTTP/3") {
		t.Fatalf("error=%v want HTTP/3 unsupported error", err)
	}
}

func TestPrepareSupervisorListenerSetCreatesPublicListener(t *testing.T) {
	restore := saveSupervisorListenerConfig()
	defer restore()
	config.ListenAddr = "127.0.0.1:0"
	config.AdminListenAddr = ""
	config.ServerTLSEnabled = false
	config.ServerTLSRedirectHTTP = false
	config.ServerHTTP3Enabled = false

	set, err := prepareSupervisorListenerSet(nil)
	if err != nil {
		t.Fatalf("prepareSupervisorListenerSet: %v", err)
	}
	defer set.Close()
	if len(set.entries) != 1 {
		t.Fatalf("entries=%#v want one public listener", set.entries)
	}
	if set.entries[0].role != "public" || set.entries[0].listener == nil || set.entries[0].inherited {
		t.Fatalf("entry=%#v", set.entries[0])
	}
}

func TestSupervisorRuntimeReplaceActivatesCandidateThenDrainsPrevious(t *testing.T) {
	activeWorker := newFakeSupervisorWorker(101)
	candidateWorker := newFakeSupervisorWorker(202)
	runtime := &supervisorRuntime{
		executable:    "/tmp/tukuyomi-test",
		readyTimeout:  time.Second,
		stopTimeout:   time.Second,
		enableReplace: true,
		startWorker: func(context.Context, string, *supervisorListenerSet, time.Duration) (supervisorWorker, workerReadyMessage, error) {
			return candidateWorker, workerReadyMessage{
				Protocol:   workerReadinessProtocol,
				PID:        candidateWorker.ProcessID(),
				ListenAddr: "127.0.0.1:9090",
			}, nil
		},
	}
	active := &supervisorWorkerGeneration{
		id:         1,
		executable: "/tmp/tukuyomi-test",
		worker:     activeWorker,
		ready: workerReadyMessage{
			Protocol:   workerReadinessProtocol,
			PID:        activeWorker.ProcessID(),
			ListenAddr: "127.0.0.1:9090",
		},
	}

	next, err := runtime.Replace(context.Background(), active)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if next.worker != candidateWorker {
		t.Fatalf("next worker=%#v want candidate", next.worker)
	}
	if !candidateWorker.activated {
		t.Fatal("candidate was not activated")
	}
	if !activeWorker.drained {
		t.Fatal("previous worker was not drained")
	}
	if candidateWorker.stopped {
		t.Fatal("candidate should remain active")
	}
}

func TestSupervisorRuntimeReplaceKeepsActiveWhenCandidateFails(t *testing.T) {
	activeWorker := newFakeSupervisorWorker(101)
	runtime := &supervisorRuntime{
		executable:    "/tmp/tukuyomi-test",
		readyTimeout:  time.Second,
		stopTimeout:   time.Second,
		enableReplace: true,
		startWorker: func(context.Context, string, *supervisorListenerSet, time.Duration) (supervisorWorker, workerReadyMessage, error) {
			return nil, workerReadyMessage{}, errors.New("candidate failed")
		},
	}
	active := &supervisorWorkerGeneration{id: 1, executable: "/tmp/tukuyomi-test", worker: activeWorker}

	next, err := runtime.Replace(context.Background(), active)
	if err == nil {
		t.Fatal("expected Replace error")
	}
	if next != nil {
		t.Fatalf("next=%#v want nil", next)
	}
	if activeWorker.drained || activeWorker.stopped {
		t.Fatal("active worker must keep running when candidate fails")
	}
}

func TestSupervisorRuntimeReplaceStopsCandidateWhenActivationFails(t *testing.T) {
	activeWorker := newFakeSupervisorWorker(101)
	candidateWorker := newFakeSupervisorWorker(202)
	candidateWorker.activateErr = errors.New("bad activation")
	runtime := &supervisorRuntime{
		executable:    "/tmp/tukuyomi-test",
		readyTimeout:  time.Second,
		stopTimeout:   time.Second,
		enableReplace: true,
		startWorker: func(context.Context, string, *supervisorListenerSet, time.Duration) (supervisorWorker, workerReadyMessage, error) {
			return candidateWorker, workerReadyMessage{
				Protocol:   workerReadinessProtocol,
				PID:        candidateWorker.ProcessID(),
				ListenAddr: "127.0.0.1:9090",
			}, nil
		},
	}
	active := &supervisorWorkerGeneration{id: 1, executable: "/tmp/tukuyomi-test", worker: activeWorker}

	next, err := runtime.Replace(context.Background(), active)
	if err == nil {
		t.Fatal("expected Replace activation error")
	}
	if next != nil {
		t.Fatalf("next=%#v want nil", next)
	}
	if !candidateWorker.stopped {
		t.Fatal("failed candidate was not stopped")
	}
	if activeWorker.drained || activeWorker.stopped {
		t.Fatal("active worker must keep running when candidate activation fails")
	}
}

func TestSupervisorWorkerStateStoreRoundTrip(t *testing.T) {
	store := newSupervisorWorkerStateStore(filepath.Join(t.TempDir(), "releases", "worker_runtime_state.json"))
	state := supervisorWorkerRuntimeState{
		Active: supervisorWorkerGenerationState{
			GenerationID: 7,
			Executable:   "/opt/tukuyomi/releases/current/tukuyomi",
			PID:          700,
			Status:       "active",
			ActivatedAt:  "2026-04-30T00:00:00Z",
		},
		Previous: &supervisorWorkerGenerationState{
			GenerationID: 6,
			Executable:   "/opt/tukuyomi/releases/previous/tukuyomi",
			Status:       "previous",
		},
		LastActivation: &supervisorWorkerActivationResult{
			Action:               "replace",
			Success:              true,
			ActiveGenerationID:   7,
			PreviousGenerationID: 6,
			StartedAt:            "2026-04-30T00:00:00Z",
			CompletedAt:          "2026-04-30T00:00:01Z",
		},
		UpdatedAt: "2026-04-30T00:00:01Z",
	}
	if err := store.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode=%#o want 0600", mode)
	}
	got, found, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !found {
		t.Fatal("state not found")
	}
	if got.SchemaVersion != supervisorWorkerStateSchemaVersion || got.Active.GenerationID != 7 || got.Previous == nil || got.Previous.GenerationID != 6 {
		t.Fatalf("state=%+v", got)
	}
}

func TestSupervisorRuntimeStartInitialPersistsStateAndSeedsGeneration(t *testing.T) {
	now := time.Date(2026, 4, 30, 1, 2, 3, 0, time.UTC)
	store := newSupervisorWorkerStateStore(filepath.Join(t.TempDir(), "worker_runtime_state.json"))
	if err := store.Save(supervisorWorkerRuntimeState{
		Active: supervisorWorkerGenerationState{
			GenerationID: 7,
			Executable:   "/opt/tukuyomi/releases/current/tukuyomi",
			Status:       "active",
			ActivatedAt:  now.Add(-time.Minute).Format(time.RFC3339Nano),
		},
		Previous: &supervisorWorkerGenerationState{
			GenerationID: 6,
			Executable:   "/opt/tukuyomi/releases/previous/tukuyomi",
			Status:       "previous",
		},
		UpdatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	worker := newFakeSupervisorWorker(808)
	runtime := &supervisorRuntime{
		executable:   "/opt/tukuyomi/releases/current/tukuyomi",
		readyTimeout: time.Second,
		stopTimeout:  time.Second,
		stateStore:   store,
		timeNow:      func() time.Time { return now },
		startWorker: func(context.Context, string, *supervisorListenerSet, time.Duration) (supervisorWorker, workerReadyMessage, error) {
			return worker, workerReadyMessage{Protocol: workerReadinessProtocol, PID: worker.ProcessID(), GoVersion: "go-test", ListenAddr: "127.0.0.1:9090"}, nil
		},
	}
	active, err := runtime.StartInitial(context.Background())
	if err != nil {
		t.Fatalf("StartInitial: %v", err)
	}
	if active.id != 8 {
		t.Fatalf("generation=%d want 8", active.id)
	}
	got, found, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !found || got.Active.GenerationID != 8 || got.Active.PID != 808 || got.Previous == nil || got.Previous.GenerationID != 6 {
		t.Fatalf("state=%+v found=%t", got, found)
	}
}

func TestSupervisorRuntimeReplacePersistsPreviousGeneration(t *testing.T) {
	now := time.Date(2026, 4, 30, 1, 2, 3, 0, time.UTC)
	store := newSupervisorWorkerStateStore(filepath.Join(t.TempDir(), "worker_runtime_state.json"))
	activeWorker := newFakeSupervisorWorker(101)
	candidateWorker := newFakeSupervisorWorker(202)
	runtime := &supervisorRuntime{
		executable:     "/opt/tukuyomi/releases/current/tukuyomi",
		readyTimeout:   time.Second,
		stopTimeout:    time.Second,
		enableReplace:  true,
		stateStore:     store,
		rollbackWindow: time.Minute,
		timeNow:        func() time.Time { return now },
		startWorker: func(context.Context, string, *supervisorListenerSet, time.Duration) (supervisorWorker, workerReadyMessage, error) {
			return candidateWorker, workerReadyMessage{Protocol: workerReadinessProtocol, PID: candidateWorker.ProcessID(), GoVersion: "go-test", ListenAddr: "127.0.0.1:9090"}, nil
		},
	}
	active := &supervisorWorkerGeneration{
		id:         1,
		executable: "/opt/tukuyomi/releases/previous/tukuyomi",
		worker:     activeWorker,
		activated:  now.Add(-time.Second),
		ready:      workerReadyMessage{Protocol: workerReadinessProtocol, PID: activeWorker.ProcessID(), GoVersion: "go-test", ListenAddr: "127.0.0.1:9090"},
	}
	next, err := runtime.Replace(context.Background(), active)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if next.id != 2 {
		t.Fatalf("candidate generation=%d want 2", next.id)
	}
	got, found, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !found || got.Active.GenerationID != 2 || got.Previous == nil || got.Previous.GenerationID != 1 || got.LastActivation == nil || !got.LastActivation.Success {
		t.Fatalf("state=%+v found=%t", got, found)
	}
}

func TestSupervisorRuntimeReplaceRecordsCandidateFailure(t *testing.T) {
	now := time.Date(2026, 4, 30, 1, 2, 3, 0, time.UTC)
	store := newSupervisorWorkerStateStore(filepath.Join(t.TempDir(), "worker_runtime_state.json"))
	activeWorker := newFakeSupervisorWorker(101)
	runtime := &supervisorRuntime{
		executable:    "/opt/tukuyomi/releases/current/tukuyomi",
		readyTimeout:  time.Second,
		stopTimeout:   time.Second,
		enableReplace: true,
		stateStore:    store,
		timeNow:       func() time.Time { return now },
		startWorker: func(context.Context, string, *supervisorListenerSet, time.Duration) (supervisorWorker, workerReadyMessage, error) {
			return nil, workerReadyMessage{}, errors.New("candidate failed")
		},
	}
	active := &supervisorWorkerGeneration{
		id:         3,
		executable: "/opt/tukuyomi/releases/current/tukuyomi",
		worker:     activeWorker,
		activated:  now.Add(-time.Second),
	}
	if _, err := runtime.Replace(context.Background(), active); err == nil {
		t.Fatal("expected Replace error")
	}
	got, found, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !found || got.Active.GenerationID != 3 || got.LastActivation == nil || got.LastActivation.Success || !strings.Contains(got.LastActivation.Error, "candidate failed") {
		t.Fatalf("state=%+v found=%t", got, found)
	}
}

func TestSupervisorRuntimeReplaceDisabledByDefault(t *testing.T) {
	activeWorker := newFakeSupervisorWorker(101)
	startedCandidate := false
	runtime := &supervisorRuntime{
		executable:   "/tmp/tukuyomi-test",
		readyTimeout: time.Second,
		stopTimeout:  time.Second,
		startWorker: func(context.Context, string, *supervisorListenerSet, time.Duration) (supervisorWorker, workerReadyMessage, error) {
			startedCandidate = true
			return newFakeSupervisorWorker(202), workerReadyMessage{}, nil
		},
	}
	active := &supervisorWorkerGeneration{id: 1, executable: "/tmp/tukuyomi-test", worker: activeWorker}

	next, err := runtime.Replace(context.Background(), active)
	if err == nil {
		t.Fatal("expected disabled replacement error")
	}
	if !strings.Contains(err.Error(), "worker replacement is disabled") {
		t.Fatalf("err=%v want disabled replacement error", err)
	}
	if next != nil {
		t.Fatalf("next=%#v want nil", next)
	}
	if startedCandidate {
		t.Fatal("disabled replacement must not start a candidate")
	}
	if activeWorker.drained || activeWorker.stopped {
		t.Fatal("active worker must keep running when replacement is disabled")
	}
}

func TestSupervisorRuntimeRunSIGHUPDrainsActiveWorker(t *testing.T) {
	activeWorker := newFakeSupervisorWorker(101)
	startedCandidate := false
	runtime := &supervisorRuntime{
		executable:   "/tmp/tukuyomi-test",
		readyTimeout: time.Second,
		stopTimeout:  time.Second,
		startWorker: func(context.Context, string, *supervisorListenerSet, time.Duration) (supervisorWorker, workerReadyMessage, error) {
			startedCandidate = true
			return newFakeSupervisorWorker(202), workerReadyMessage{}, nil
		},
	}
	active := &supervisorWorkerGeneration{id: 1, executable: "/tmp/tukuyomi-test", worker: activeWorker}
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGHUP

	if err := runtime.Run(active, sigCh); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !activeWorker.drained {
		t.Fatal("SIGHUP must drain the active worker")
	}
	if startedCandidate {
		t.Fatal("SIGHUP must not launch an unstaged candidate worker")
	}
}

func TestSupervisorRuntimeRunRollsBackRecentActiveCrash(t *testing.T) {
	now := time.Date(2026, 4, 30, 1, 2, 3, 0, time.UTC)
	store := newSupervisorWorkerStateStore(filepath.Join(t.TempDir(), "worker_runtime_state.json"))
	if err := store.Save(supervisorWorkerRuntimeState{
		Active: supervisorWorkerGenerationState{
			GenerationID: 2,
			Executable:   "/opt/tukuyomi/releases/current/tukuyomi",
			Status:       "active",
			ActivatedAt:  now.Add(-time.Second).Format(time.RFC3339Nano),
		},
		Previous: &supervisorWorkerGenerationState{
			GenerationID: 1,
			Executable:   "/opt/tukuyomi/releases/previous/tukuyomi",
			Status:       "previous",
		},
		UpdatedAt: now.Add(-time.Second).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	activeWorker := newFakeSupervisorWorker(202)
	rollbackWorker := newFakeSupervisorWorker(101)
	rollbackActivated := make(chan struct{})
	rollbackWorker.activateCh = rollbackActivated
	startedExecutable := make(chan string, 1)
	runtime := &supervisorRuntime{
		executable:     "/opt/tukuyomi/releases/current/tukuyomi",
		readyTimeout:   time.Second,
		stopTimeout:    time.Second,
		rollbackWindow: time.Minute,
		stateStore:     store,
		timeNow:        func() time.Time { return now },
		startWorker: func(_ context.Context, executable string, _ *supervisorListenerSet, _ time.Duration) (supervisorWorker, workerReadyMessage, error) {
			startedExecutable <- executable
			return rollbackWorker, workerReadyMessage{Protocol: workerReadinessProtocol, PID: rollbackWorker.ProcessID(), GoVersion: "go-test", ListenAddr: "127.0.0.1:9090"}, nil
		},
	}
	active := &supervisorWorkerGeneration{
		id:         2,
		executable: "/opt/tukuyomi/releases/current/tukuyomi",
		worker:     activeWorker,
		activated:  now.Add(-time.Second),
	}
	sigCh := make(chan os.Signal, 1)
	runErr := make(chan error, 1)
	go func() {
		runErr <- runtime.Run(active, sigCh)
	}()
	activeWorker.waitCh <- errors.New("active crashed")

	select {
	case executable := <-startedExecutable:
		if executable != "/opt/tukuyomi/releases/previous/tukuyomi" {
			t.Fatalf("rollback executable=%q", executable)
		}
	case <-time.After(time.Second):
		t.Fatal("rollback worker was not started")
	}
	select {
	case <-rollbackActivated:
	case <-time.After(time.Second):
		t.Fatal("rollback worker was not activated")
	}
	got := waitForSupervisorWorkerState(t, store, func(state supervisorWorkerRuntimeState, found bool) bool {
		return found &&
			state.Active.GenerationID == 3 &&
			state.Active.Executable == "/opt/tukuyomi/releases/previous/tukuyomi" &&
			state.Previous != nil &&
			state.Previous.Status == "crashed"
	})
	if got.Active.GenerationID != 3 {
		t.Fatalf("state=%+v", got)
	}
	sigCh <- syscall.SIGTERM
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after signal")
	}
	if !rollbackWorker.drained {
		t.Fatal("rollback worker was not drained on shutdown signal")
	}
}

func TestSupervisorRuntimeRunDoesNotRollbackOutsideWindow(t *testing.T) {
	now := time.Date(2026, 4, 30, 1, 2, 3, 0, time.UTC)
	store := newSupervisorWorkerStateStore(filepath.Join(t.TempDir(), "worker_runtime_state.json"))
	if err := store.Save(supervisorWorkerRuntimeState{
		Active: supervisorWorkerGenerationState{
			GenerationID: 2,
			Executable:   "/opt/tukuyomi/releases/current/tukuyomi",
			Status:       "active",
			ActivatedAt:  now.Add(-10 * time.Minute).Format(time.RFC3339Nano),
		},
		Previous: &supervisorWorkerGenerationState{
			GenerationID: 1,
			Executable:   "/opt/tukuyomi/releases/previous/tukuyomi",
			Status:       "previous",
		},
		UpdatedAt: now.Add(-10 * time.Minute).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	activeWorker := newFakeSupervisorWorker(202)
	startedCandidate := false
	runtime := &supervisorRuntime{
		executable:     "/opt/tukuyomi/releases/current/tukuyomi",
		readyTimeout:   time.Second,
		stopTimeout:    time.Second,
		rollbackWindow: time.Minute,
		stateStore:     store,
		timeNow:        func() time.Time { return now },
		startWorker: func(context.Context, string, *supervisorListenerSet, time.Duration) (supervisorWorker, workerReadyMessage, error) {
			startedCandidate = true
			return newFakeSupervisorWorker(101), workerReadyMessage{}, nil
		},
	}
	active := &supervisorWorkerGeneration{
		id:         2,
		executable: "/opt/tukuyomi/releases/current/tukuyomi",
		worker:     activeWorker,
		activated:  now.Add(-10 * time.Minute),
	}
	activeWorker.waitCh <- errors.New("active crashed")
	err := runtime.Run(active, make(chan os.Signal))
	if err == nil || !strings.Contains(err.Error(), "worker stopped unexpectedly") {
		t.Fatalf("Run error=%v", err)
	}
	if startedCandidate {
		t.Fatal("rollback candidate should not start outside rollback window")
	}
}

func TestSystemdActivationEnvPresent(t *testing.T) {
	t.Parallel()

	if !systemdActivationEnvPresent([]string{"LISTEN_FDS=2"}) {
		t.Fatal("expected activation env")
	}
	if systemdActivationEnvPresent([]string{"LISTEN_FDS=0", "OTHER=1"}) {
		t.Fatal("did not expect inactive activation env")
	}
	if systemdActivationEnvPresent([]string{"LISTEN_FDNAMES=public"}) {
		t.Fatal("did not expect activation without LISTEN_FDS")
	}
}

func TestWaitForWorkerReady(t *testing.T) {
	t.Parallel()

	msg := workerReadyMessage{
		Protocol:   workerReadinessProtocol,
		PID:        99,
		GoVersion:  "go-test",
		ListenAddr: ":9090",
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(msg); err != nil {
		t.Fatalf("encode: %v", err)
	}
	waitCh := make(chan error)
	got, err := waitForWorkerReady(context.Background(), &buf, waitCh)
	if err != nil {
		t.Fatalf("waitForWorkerReady: %v", err)
	}
	if got.PID != msg.PID || got.ListenAddr != msg.ListenAddr {
		t.Fatalf("ready=%#v want %#v", got, msg)
	}
}

func TestWaitForWorkerReadyReportsEarlyExit(t *testing.T) {
	t.Parallel()

	waitCh := make(chan error, 1)
	waitCh <- errors.New("boom")
	_, err := waitForWorkerReady(context.Background(), blockingReader{}, waitCh)
	if err == nil {
		t.Fatal("expected early exit error")
	}
}

func TestWaitForWorkerReadyTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	waitCh := make(chan error)
	_, err := waitForWorkerReady(ctx, blockingReader{}, waitCh)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

type blockingReader struct{}

func (blockingReader) Read([]byte) (int, error) {
	select {}
}

func envContains(env []string, want string) bool {
	for _, item := range env {
		if item == want {
			return true
		}
	}
	return false
}

func envContainsPrefix(env []string, prefix string) bool {
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}

func testSupervisorListenerFiles(t *testing.T, roles ...string) []supervisorListenerFile {
	t.Helper()
	out := make([]supervisorListenerFile, 0, len(roles))
	for _, role := range roles {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		fileProvider, ok := ln.(interface {
			File() (*os.File, error)
		})
		if !ok {
			t.Fatalf("listener does not expose File: %T", ln)
		}
		file, err := fileProvider.File()
		if err != nil {
			t.Fatalf("listener File: %v", err)
		}
		t.Cleanup(func() { _ = file.Close() })
		out = append(out, supervisorListenerFile{role: role, file: file})
	}
	return out
}

func saveSupervisorListenerConfig() func() {
	listenAddr := config.ListenAddr
	adminListenAddr := config.AdminListenAddr
	serverTLSEnabled := config.ServerTLSEnabled
	serverTLSRedirectHTTP := config.ServerTLSRedirectHTTP
	serverTLSHTTPRedirectAddr := config.ServerTLSHTTPRedirectAddr
	serverHTTP3Enabled := config.ServerHTTP3Enabled
	return func() {
		config.ListenAddr = listenAddr
		config.AdminListenAddr = adminListenAddr
		config.ServerTLSEnabled = serverTLSEnabled
		config.ServerTLSRedirectHTTP = serverTLSRedirectHTTP
		config.ServerTLSHTTPRedirectAddr = serverTLSHTTPRedirectAddr
		config.ServerHTTP3Enabled = serverHTTP3Enabled
	}
}

func waitForSupervisorWorkerState(t *testing.T, store *supervisorWorkerStateStore, accept func(supervisorWorkerRuntimeState, bool) bool) supervisorWorkerRuntimeState {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var last supervisorWorkerRuntimeState
	var found bool
	for time.Now().Before(deadline) {
		state, stateFound, err := store.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		last = state
		found = stateFound
		if accept(state, stateFound) {
			return state
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state did not reach expected condition; last=%+v found=%t", last, found)
	return supervisorWorkerRuntimeState{}
}

type fakeSupervisorWorker struct {
	pid         int
	waitCh      chan error
	activateCh  chan struct{}
	activated   bool
	drained     bool
	stopped     bool
	activateErr error
	drainErr    error
	stopErr     error
}

func newFakeSupervisorWorker(pid int) *fakeSupervisorWorker {
	return &fakeSupervisorWorker{pid: pid, waitCh: make(chan error, 1)}
}

func (w *fakeSupervisorWorker) Activate() error {
	w.activated = true
	if w.activateCh != nil {
		close(w.activateCh)
		w.activateCh = nil
	}
	return w.activateErr
}

func (w *fakeSupervisorWorker) Drain(time.Duration) error {
	w.drained = true
	if w.drainErr != nil {
		return w.drainErr
	}
	select {
	case w.waitCh <- nil:
	default:
	}
	return nil
}

func (w *fakeSupervisorWorker) Stop(time.Duration) error {
	w.stopped = true
	if w.stopErr != nil {
		return w.stopErr
	}
	select {
	case w.waitCh <- nil:
	default:
	}
	return nil
}

func (w *fakeSupervisorWorker) Wait() <-chan error {
	return w.waitCh
}

func (w *fakeSupervisorWorker) ProcessID() int {
	return w.pid
}
