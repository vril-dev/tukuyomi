package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	supervisorControlSocketEnv          = "TUKUYOMI_SUPERVISOR_CONTROL_SOCKET"
	defaultSupervisorControlSocketPath  = "data/run/supervisor-control/control.sock"
	supervisorControlReadHeaderTimeout  = 5 * time.Second
	supervisorControlOperationTimeout   = 90 * time.Second
	supervisorControlMaxRequestBodySize = 1 << 20
)

type supervisorControlServer struct {
	socketPath string
	listener   net.Listener
	server     *http.Server
	runtime    *supervisorRuntime
	releases   *supervisorReleaseManager
}

type supervisorReleaseActivateRequest struct {
	Generation string `json:"generation"`
}

func startSupervisorControlServer(runtime *supervisorRuntime, releases *supervisorReleaseManager) (*supervisorControlServer, error) {
	if runtime == nil {
		return nil, fmt.Errorf("supervisor runtime is required")
	}
	if releases == nil {
		return nil, fmt.Errorf("release manager is required")
	}
	socketPath := supervisorControlSocketPathFromEnv()
	listener, err := listenSupervisorControlSocket(socketPath)
	if err != nil {
		return nil, err
	}
	s := &supervisorControlServer{
		socketPath: socketPath,
		listener:   listener,
		runtime:    runtime,
		releases:   releases,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/stage", s.handleStage)
	mux.HandleFunc("/v1/activate", s.handleActivate)
	mux.HandleFunc("/v1/rollback", s.handleRollback)
	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: supervisorControlReadHeaderTimeout,
	}
	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[SUPERVISOR][CONTROL][ERR] %v", err)
		}
	}()
	log.Printf("[SUPERVISOR][CONTROL] socket ready path=%s", socketPath)
	return s, nil
}

func (s *supervisorControlServer) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var out error
	if s.server != nil {
		if err := s.server.Shutdown(ctx); err != nil && out == nil {
			out = err
		}
	}
	if s.listener != nil {
		if err := s.listener.Close(); err != nil && out == nil && !strings.Contains(err.Error(), "use of closed network connection") {
			out = err
		}
	}
	if s.socketPath != "" {
		if err := os.Remove(s.socketPath); err != nil && out == nil && !os.IsNotExist(err) {
			out = err
		}
	}
	return out
}

func (s *supervisorControlServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondSupervisorControlError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	state, found, err := s.runtime.loadWorkerState()
	if err != nil {
		respondSupervisorControlError(w, http.StatusInternalServerError, err.Error())
		return
	}
	staged, err := s.releases.StagedGenerations()
	if err != nil {
		respondSupervisorControlError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondSupervisorControlJSON(w, http.StatusOK, map[string]any{
		"state_found": found,
		"state":       state,
		"staged":      staged,
	})
}

func (s *supervisorControlServer) handleStage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondSupervisorControlError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var in supervisorReleaseStageRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, supervisorControlMaxRequestBodySize)).Decode(&in); err != nil {
		respondSupervisorControlError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), supervisorControlOperationTimeout)
	defer cancel()
	result, err := s.releases.StageArtifact(ctx, in)
	if err != nil {
		respondSupervisorControlError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if state, found, err := s.runtime.loadWorkerState(); err == nil && found {
		if _, pruneErr := s.releases.PruneInactive(state, defaultSupervisorReleasePruneKeep); pruneErr != nil {
			respondSupervisorControlError(w, http.StatusInternalServerError, pruneErr.Error())
			return
		}
	}
	respondSupervisorControlJSON(w, http.StatusOK, result)
}

func (s *supervisorControlServer) handleActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondSupervisorControlError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var in supervisorReleaseActivateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, supervisorControlMaxRequestBodySize)).Decode(&in); err != nil {
		respondSupervisorControlError(w, http.StatusBadRequest, err.Error())
		return
	}
	staged, err := s.releases.ResolveGeneration(in.Generation)
	if err != nil {
		respondSupervisorControlError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), supervisorControlOperationTimeout)
	defer cancel()
	next, err := s.runtime.ReplaceActive(ctx, staged.Executable)
	if err != nil {
		respondSupervisorControlError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if state, found, err := s.runtime.loadWorkerState(); err == nil && found {
		if _, pruneErr := s.releases.PruneInactive(state, defaultSupervisorReleasePruneKeep); pruneErr != nil {
			respondSupervisorControlError(w, http.StatusInternalServerError, pruneErr.Error())
			return
		}
	}
	respondSupervisorControlJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"generation": next.id,
		"executable": next.executable,
	})
}

func (s *supervisorControlServer) handleRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondSupervisorControlError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), supervisorControlOperationTimeout)
	defer cancel()
	next, err := s.runtime.RollbackActive(ctx)
	if err != nil {
		respondSupervisorControlError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if state, found, err := s.runtime.loadWorkerState(); err == nil && found {
		if _, pruneErr := s.releases.PruneInactive(state, defaultSupervisorReleasePruneKeep); pruneErr != nil {
			respondSupervisorControlError(w, http.StatusInternalServerError, pruneErr.Error())
			return
		}
	}
	respondSupervisorControlJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"generation": next.id,
		"executable": next.executable,
	})
}

func supervisorControlSocketPathFromEnv() string {
	if value := strings.TrimSpace(os.Getenv(supervisorControlSocketEnv)); value != "" {
		return value
	}
	return defaultSupervisorControlSocketPath
}

func listenSupervisorControlSocket(socketPath string) (net.Listener, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		return nil, fmt.Errorf("supervisor control socket path is required")
	}
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create supervisor control socket dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure supervisor control socket dir: %w", err)
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("supervisor control socket path exists and is not a socket")
		}
		if conn, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond); dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("supervisor control socket is already active")
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("remove stale supervisor control socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat supervisor control socket: %w", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen supervisor control socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("secure supervisor control socket: %w", err)
	}
	return listener, nil
}

func supervisorControlHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: supervisorControlOperationTimeout,
	}
}

func callSupervisorControl(ctx context.Context, method string, path string, body any) (json.RawMessage, error) {
	socketPath := supervisorControlSocketPathFromEnv()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://supervisor"+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := supervisorControlHTTPClient(socketPath).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	limited := &io.LimitedReader{R: res.Body, N: supervisorControlMaxRequestBodySize + 1}
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > supervisorControlMaxRequestBodySize {
		return nil, fmt.Errorf("supervisor control response is too large")
	}
	payload := json.RawMessage(bytes.TrimSpace(raw))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("supervisor control %s %s failed: %s", method, path, strings.TrimSpace(string(payload)))
	}
	return payload, nil
}

func respondSupervisorControlJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func respondSupervisorControlError(w http.ResponseWriter, status int, message string) {
	respondSupervisorControlJSON(w, status, map[string]any{"error": strings.TrimSpace(message)})
}
