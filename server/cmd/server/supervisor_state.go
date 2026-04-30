package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	supervisorWorkerStateSchemaVersion = 1
	supervisorWorkerStatePathEnv       = "TUKUYOMI_SUPERVISOR_WORKER_STATE_FILE"
	defaultSupervisorWorkerStateFile   = "worker_runtime_state.json"
	defaultSupervisorRollbackWindow    = 2 * time.Minute
)

type supervisorWorkerStateStore struct {
	path string
}

type supervisorWorkerRuntimeState struct {
	SchemaVersion  int                               `json:"schema_version"`
	Active         supervisorWorkerGenerationState   `json:"active"`
	Previous       *supervisorWorkerGenerationState  `json:"previous,omitempty"`
	LastActivation *supervisorWorkerActivationResult `json:"last_activation,omitempty"`
	UpdatedAt      string                            `json:"updated_at"`
}

type supervisorWorkerGenerationState struct {
	GenerationID    int    `json:"generation_id"`
	Executable      string `json:"executable"`
	PID             int    `json:"pid,omitempty"`
	Version         string `json:"version,omitempty"`
	GoVersion       string `json:"go_version,omitempty"`
	ListenAddr      string `json:"listen_addr,omitempty"`
	AdminListenAddr string `json:"admin_listen_addr,omitempty"`
	ActivatedAt     string `json:"activated_at,omitempty"`
	Status          string `json:"status"`
}

type supervisorWorkerActivationResult struct {
	Action                string `json:"action"`
	Success               bool   `json:"success"`
	Error                 string `json:"error,omitempty"`
	CandidateGenerationID int    `json:"candidate_generation_id,omitempty"`
	ActiveGenerationID    int    `json:"active_generation_id,omitempty"`
	PreviousGenerationID  int    `json:"previous_generation_id,omitempty"`
	StartedAt             string `json:"started_at"`
	CompletedAt           string `json:"completed_at"`
}

func newSupervisorWorkerStateStore(path string) *supervisorWorkerStateStore {
	path = strings.TrimSpace(path)
	if path == "" {
		path = supervisorWorkerStatePathFromEnv(supervisorReleasesDirFromEnv())
	}
	return &supervisorWorkerStateStore{path: path}
}

func supervisorWorkerStatePathFromEnv(releasesDir string) string {
	if value := strings.TrimSpace(os.Getenv(supervisorWorkerStatePathEnv)); value != "" {
		return value
	}
	releasesDir = strings.TrimSpace(releasesDir)
	if releasesDir == "" {
		releasesDir = supervisorReleasesDirFromEnv()
	}
	return filepath.Join(releasesDir, defaultSupervisorWorkerStateFile)
}

func (s *supervisorWorkerStateStore) Load() (supervisorWorkerRuntimeState, bool, error) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return supervisorWorkerRuntimeState{}, false, nil
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return supervisorWorkerRuntimeState{}, false, nil
		}
		return supervisorWorkerRuntimeState{}, false, fmt.Errorf("read supervisor worker state: %w", err)
	}
	var state supervisorWorkerRuntimeState
	if err := json.Unmarshal(raw, &state); err != nil {
		return supervisorWorkerRuntimeState{}, false, fmt.Errorf("decode supervisor worker state: %w", err)
	}
	if state.SchemaVersion != supervisorWorkerStateSchemaVersion {
		return supervisorWorkerRuntimeState{}, false, fmt.Errorf("unsupported supervisor worker state schema %d", state.SchemaVersion)
	}
	if err := validateSupervisorWorkerGenerationState(state.Active, false); err != nil {
		return supervisorWorkerRuntimeState{}, false, fmt.Errorf("invalid active worker state: %w", err)
	}
	if state.Previous != nil {
		if err := validateSupervisorWorkerGenerationState(*state.Previous, true); err != nil {
			return supervisorWorkerRuntimeState{}, false, fmt.Errorf("invalid previous worker state: %w", err)
		}
	}
	return state, true, nil
}

func (s *supervisorWorkerStateStore) Save(state supervisorWorkerRuntimeState) error {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil
	}
	state.SchemaVersion = supervisorWorkerStateSchemaVersion
	if strings.TrimSpace(state.UpdatedAt) == "" {
		state.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := validateSupervisorWorkerGenerationState(state.Active, false); err != nil {
		return fmt.Errorf("invalid active worker state: %w", err)
	}
	if state.Previous != nil {
		if err := validateSupervisorWorkerGenerationState(*state.Previous, true); err != nil {
			return fmt.Errorf("invalid previous worker state: %w", err)
		}
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create supervisor worker state dir: %w", err)
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal supervisor worker state: %w", err)
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp(dir, ".worker-runtime-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create supervisor worker state temp file: %w", err)
	}
	tmpPath := tmp.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure supervisor worker state temp file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write supervisor worker state temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync supervisor worker state temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close supervisor worker state temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace supervisor worker state file: %w", err)
	}
	removeTmp = false
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync supervisor worker state dir: %w", err)
	}
	return nil
}

func validateSupervisorWorkerGenerationState(state supervisorWorkerGenerationState, allowEmpty bool) error {
	if state.GenerationID == 0 && strings.TrimSpace(state.Executable) == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("generation is empty")
	}
	if state.GenerationID <= 0 {
		return fmt.Errorf("generation_id must be positive")
	}
	if strings.TrimSpace(state.Executable) == "" {
		return fmt.Errorf("executable is required")
	}
	if len(state.Executable) > 4096 {
		return fmt.Errorf("executable is too long")
	}
	if strings.ContainsRune(state.Executable, 0) {
		return fmt.Errorf("executable contains NUL")
	}
	if strings.TrimSpace(state.Status) == "" {
		return fmt.Errorf("status is required")
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func supervisorGenerationStateFromGeneration(gen *supervisorWorkerGeneration, status string) supervisorWorkerGenerationState {
	if gen == nil {
		return supervisorWorkerGenerationState{}
	}
	pid := 0
	if gen.worker != nil {
		pid = gen.worker.ProcessID()
	}
	activatedAt := ""
	if !gen.activated.IsZero() {
		activatedAt = gen.activated.UTC().Format(time.RFC3339Nano)
	}
	return supervisorWorkerGenerationState{
		GenerationID:    gen.id,
		Executable:      strings.TrimSpace(gen.executable),
		PID:             pid,
		Version:         strings.TrimSpace(gen.ready.Version),
		GoVersion:       strings.TrimSpace(gen.ready.GoVersion),
		ListenAddr:      strings.TrimSpace(gen.ready.ListenAddr),
		AdminListenAddr: strings.TrimSpace(gen.ready.AdminListenAddr),
		ActivatedAt:     activatedAt,
		Status:          status,
	}
}

func maxSupervisorWorkerGenerationID(state supervisorWorkerRuntimeState) int {
	maxID := state.Active.GenerationID
	if state.Previous != nil && state.Previous.GenerationID > maxID {
		maxID = state.Previous.GenerationID
	}
	if state.LastActivation != nil {
		if state.LastActivation.CandidateGenerationID > maxID {
			maxID = state.LastActivation.CandidateGenerationID
		}
		if state.LastActivation.ActiveGenerationID > maxID {
			maxID = state.LastActivation.ActiveGenerationID
		}
		if state.LastActivation.PreviousGenerationID > maxID {
			maxID = state.LastActivation.PreviousGenerationID
		}
	}
	return maxID
}
