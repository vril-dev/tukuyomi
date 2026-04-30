package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSupervisorReleaseManagerStagesRawExecutable(t *testing.T) {
	root := t.TempDir()
	manager := newSupervisorReleaseManager(filepath.Join(root, "releases"))
	artifact := writeFakeReleaseBinary(t, root, "v9.9.9")
	artifactSHA := testFileSHA256(t, artifact)

	result, err := manager.StageArtifact(context.Background(), supervisorReleaseStageRequest{
		ArtifactPath: artifact,
		SHA256:       artifactSHA,
	})
	if err != nil {
		t.Fatalf("StageArtifact: %v", err)
	}
	if result.Generation != "v9.9.9" || result.Metadata.WorkerProtocol != workerReadinessProtocol {
		t.Fatalf("stage result=%+v", result)
	}
	info, err := os.Stat(result.Executable)
	if err != nil {
		t.Fatalf("stat staged executable: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o755 {
		t.Fatalf("mode=%#o want 0755", mode)
	}
	staged, err := manager.ResolveGeneration(result.Generation)
	if err != nil {
		t.Fatalf("ResolveGeneration: %v", err)
	}
	if staged.Executable != result.Executable || staged.BinarySHA256 != result.BinarySHA256 {
		t.Fatalf("staged=%+v result=%+v", staged, result)
	}

	again, err := manager.StageArtifact(context.Background(), supervisorReleaseStageRequest{
		ArtifactPath: artifact,
		SHA256:       artifactSHA,
	})
	if err != nil {
		t.Fatalf("StageArtifact again: %v", err)
	}
	if !again.AlreadyStaged {
		t.Fatalf("again=%+v want already staged", again)
	}
}

func TestSupervisorDefaultRuntimePathsUseDataTree(t *testing.T) {
	t.Setenv(supervisorReleasesDirEnv, "")
	t.Setenv(supervisorWorkerStatePathEnv, "")
	t.Setenv(supervisorControlSocketEnv, "")

	if got := supervisorReleasesDirFromEnv(); got != filepath.Join("data", "releases") {
		t.Fatalf("releases dir=%q", got)
	}
	stateStore := newSupervisorWorkerStateStore("")
	if got := stateStore.path; got != filepath.Join("data", "releases", "worker_runtime_state.json") {
		t.Fatalf("state path=%q", got)
	}
	if got := supervisorControlSocketPathFromEnv(); got != filepath.Join("data", "run", "supervisor-control", "control.sock") {
		t.Fatalf("control socket=%q", got)
	}
}

func TestSupervisorReleaseManagerRejectsArtifactSHA(t *testing.T) {
	root := t.TempDir()
	manager := newSupervisorReleaseManager(filepath.Join(root, "releases"))
	artifact := writeFakeReleaseBinary(t, root, "v9.9.10")

	_, err := manager.StageArtifact(context.Background(), supervisorReleaseStageRequest{
		ArtifactPath: artifact,
		SHA256:       strings.Repeat("0", sha256.Size*2),
	})
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("err=%v want sha mismatch", err)
	}
}

func TestSupervisorReleaseControlStageActivateRollback(t *testing.T) {
	root := t.TempDir()
	socketPath := filepath.Join(root, "control", "control.sock")
	t.Setenv(supervisorControlSocketEnv, socketPath)

	manager := newSupervisorReleaseManager(filepath.Join(root, "releases"))
	v1 := writeFakeReleaseBinary(t, root, "v1.2.0")
	v2 := writeFakeReleaseBinary(t, root, "v1.2.1")
	v2SHA := testFileSHA256(t, v2)

	now := time.Date(2026, 4, 30, 1, 2, 3, 0, time.UTC)
	store := newSupervisorWorkerStateStore(filepath.Join(root, "releases", "worker_runtime_state.json"))
	activeWorker := newFakeSupervisorWorker(101)
	candidateWorker := newFakeSupervisorWorker(202)
	rollbackWorker := newFakeSupervisorWorker(303)
	runtime := &supervisorRuntime{
		executable:     v1,
		readyTimeout:   time.Second,
		stopTimeout:    time.Second,
		enableReplace:  true,
		stateStore:     store,
		rollbackWindow: time.Minute,
		timeNow:        func() time.Time { return now },
		activeChange:   make(chan struct{}),
		startWorker: func(_ context.Context, executable string, _ *supervisorListenerSet, _ time.Duration) (supervisorWorker, workerReadyMessage, error) {
			switch executable {
			case v1:
				return rollbackWorker, workerReadyMessage{Protocol: workerReadinessProtocol, PID: rollbackWorker.ProcessID(), GoVersion: "go-test", ListenAddr: "127.0.0.1:9090"}, nil
			case filepath.Join(root, "releases", supervisorWorkerGenerationsDirName, "v1.2.1", "tukuyomi"):
				return candidateWorker, workerReadyMessage{Protocol: workerReadinessProtocol, PID: candidateWorker.ProcessID(), GoVersion: "go-test", ListenAddr: "127.0.0.1:9090"}, nil
			default:
				return nil, workerReadyMessage{}, errors.New("unexpected executable")
			}
		},
	}
	active := &supervisorWorkerGeneration{
		id:         1,
		executable: v1,
		worker:     activeWorker,
		activated:  now.Add(-time.Minute),
		ready:      workerReadyMessage{Protocol: workerReadinessProtocol, PID: activeWorker.ProcessID(), GoVersion: "go-test", ListenAddr: "127.0.0.1:9090"},
	}
	runtime.setActive(active)
	if err := runtime.recordWorkerActivationSuccess("initial", active, nil, now.Add(-time.Minute)); err != nil {
		t.Fatalf("seed active state: %v", err)
	}
	server, err := startSupervisorControlServer(runtime, manager)
	if err != nil {
		t.Fatalf("startSupervisorControlServer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Close(ctx)
	})

	stagePayload, err := callSupervisorControl(context.Background(), http.MethodPost, "/v1/stage", supervisorReleaseStageRequest{
		ArtifactPath: v2,
		SHA256:       v2SHA,
	})
	if err != nil {
		t.Fatalf("stage API: %v", err)
	}
	var staged supervisorReleaseStageResult
	if err := json.Unmarshal(stagePayload, &staged); err != nil {
		t.Fatalf("decode stage response: %v", err)
	}
	if staged.Generation != "v1.2.1" {
		t.Fatalf("staged generation=%q", staged.Generation)
	}

	if _, err := callSupervisorControl(context.Background(), http.MethodPost, "/v1/activate", supervisorReleaseActivateRequest{Generation: staged.Generation}); err != nil {
		t.Fatalf("activate API: %v", err)
	}
	if !candidateWorker.activated || !activeWorker.drained {
		t.Fatalf("activate state candidate=%t active_drained=%t", candidateWorker.activated, activeWorker.drained)
	}
	if got := runtime.activeGeneration(); got == nil || got.executable != staged.Executable {
		t.Fatalf("active=%+v want staged executable", got)
	}

	if _, err := callSupervisorControl(context.Background(), http.MethodPost, "/v1/rollback", nil); err != nil {
		t.Fatalf("rollback API: %v", err)
	}
	if !rollbackWorker.activated || !candidateWorker.drained {
		t.Fatalf("rollback state rollback=%t candidate_drained=%t", rollbackWorker.activated, candidateWorker.drained)
	}
	state, found, err := store.Load()
	if err != nil {
		t.Fatalf("Load state: %v", err)
	}
	if !found || state.Active.Executable != v1 || state.Previous == nil || state.Previous.Executable != staged.Executable {
		t.Fatalf("state=%+v found=%t", state, found)
	}
}

func TestSupervisorReleaseManagerPrunesInactiveGenerations(t *testing.T) {
	root := t.TempDir()
	manager := newSupervisorReleaseManager(filepath.Join(root, "releases"))
	generationsDir := filepath.Join(root, "releases", supervisorWorkerGenerationsDirName)
	names := []string{"g1", "g2", "g3", "g4", "g5"}
	for i, name := range names {
		dir := filepath.Join(generationsDir, name)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "tukuyomi"), []byte(name), 0o755); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		ts := time.Unix(int64(100+i), 0)
		if err := os.Chtimes(dir, ts, ts); err != nil {
			t.Fatalf("chtimes %s: %v", name, err)
		}
	}
	state := supervisorWorkerRuntimeState{
		Active: supervisorWorkerGenerationState{
			GenerationID: 5,
			Executable:   filepath.Join(generationsDir, "g5", "tukuyomi"),
			Status:       "active",
		},
		Previous: &supervisorWorkerGenerationState{
			GenerationID: 4,
			Executable:   filepath.Join(generationsDir, "g4", "tukuyomi"),
			Status:       "previous",
		},
	}
	removed, err := manager.PruneInactive(state, 1)
	if err != nil {
		t.Fatalf("PruneInactive: %v", err)
	}
	if strings.Join(removed, ",") != "g2,g1" {
		t.Fatalf("removed=%v want g2,g1", removed)
	}
	for _, name := range []string{"g3", "g4", "g5"} {
		if _, err := os.Stat(filepath.Join(generationsDir, name)); err != nil {
			t.Fatalf("generation %s should remain: %v", name, err)
		}
	}
}

func writeFakeReleaseBinary(t *testing.T, dir string, version string) string {
	t.Helper()
	metadata, err := json.Marshal(releaseBinaryMetadata{
		SchemaVersion:  releaseMetadataSchemaVersion,
		App:            "tukuyomi",
		Version:        version,
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		GoVersion:      "go-test",
		WorkerProtocol: workerReadinessProtocol,
	})
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	path := filepath.Join(dir, "tukuyomi-"+sanitizeReleaseGenerationToken(version))
	script := "#!/bin/sh\ncase \"$1\" in\n  release-metadata)\n    cat <<'JSON'\n" + string(metadata) + "\nJSON\n    ;;\n  validate-config)\n    printf '{\"ok\":true}\\n'\n    ;;\n  *)\n    exit 64\n    ;;\nesac\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	return path
}

func testFileSHA256(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file for sha: %v", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
