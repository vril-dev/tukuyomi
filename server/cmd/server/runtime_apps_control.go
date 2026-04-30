package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

const runtimeAppsControlSocketEnv = "TUKUYOMI_RUNTIME_APPS_CONTROL_SOCKET"

type runtimeAppsControlServer struct {
	dir        string
	socketPath string
	listener   net.Listener
	server     *http.Server
}

func startRuntimeAppsControlServer() (*runtimeAppsControlServer, error) {
	dir, err := os.MkdirTemp("", "tukuyomi-runtime-apps-control-*")
	if err != nil {
		return nil, fmt.Errorf("create runtime apps control dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("secure runtime apps control dir: %w", err)
	}
	socketPath := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("listen runtime apps control socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("secure runtime apps control socket: %w", err)
	}
	s := &runtimeAppsControlServer{
		dir:        dir,
		socketPath: socketPath,
		listener:   listener,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/php/processes", s.handlePHPProcesses)
	mux.HandleFunc("/v1/php/reconcile", s.handlePHPReconcile)
	mux.HandleFunc("/v1/php/action", s.handlePHPAction)
	mux.HandleFunc("/v1/psgi/processes", s.handlePSGIProcesses)
	mux.HandleFunc("/v1/psgi/reconcile", s.handlePSGIReconcile)
	mux.HandleFunc("/v1/psgi/action", s.handlePSGIAction)
	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[RUNTIME_APPS][CONTROL][ERR] %v", err)
		}
	}()
	return s, nil
}

func (s *runtimeAppsControlServer) Close(ctx context.Context) error {
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
	if s.dir != "" {
		if err := os.RemoveAll(s.dir); err != nil && out == nil {
			out = err
		}
	}
	return out
}

func (s *runtimeAppsControlServer) SocketPath() string {
	if s == nil {
		return ""
	}
	return s.socketPath
}

func initRuntimeAppsProcessOwner() error {
	if err := handler.InitPHPRuntimeInventoryRuntime(config.PHPRuntimeInventoryFile, config.ProxyRollbackMax); err != nil {
		return fmt.Errorf("initialize php runtime inventory: %w", err)
	}
	if err := handler.InitPSGIRuntimeInventoryRuntime(config.PSGIRuntimeInventoryFile, config.ProxyRollbackMax); err != nil {
		return fmt.Errorf("initialize psgi runtime inventory: %w", err)
	}
	if err := handler.InitVhostRuntime(config.VhostConfigFile, config.ProxyRollbackMax); err != nil {
		if handler.IsVhostStartupConfigError(err) {
			log.Printf("[RUNTIME_APPS][WARN] process owner degraded at startup: %v", err)
		} else {
			return fmt.Errorf("initialize runtime apps: %w", err)
		}
	}
	if err := handler.InitPHPRuntimeSupervisor(); err != nil {
		if shutdownErr := handler.ShutdownPHPRuntimeSupervisor(); shutdownErr != nil {
			log.Printf("[RUNTIME_APPS][WARN] shutdown php runtime supervisor after owner init failure: %v", shutdownErr)
		}
		return fmt.Errorf("initialize php runtime supervisor: %w", err)
	}
	if err := handler.InitPSGIRuntimeSupervisor(); err != nil {
		if shutdownErr := handler.ShutdownPSGIRuntimeSupervisor(); shutdownErr != nil {
			log.Printf("[RUNTIME_APPS][WARN] shutdown psgi runtime supervisor after owner init failure: %v", shutdownErr)
		}
		if shutdownErr := handler.ShutdownPHPRuntimeSupervisor(); shutdownErr != nil {
			log.Printf("[RUNTIME_APPS][WARN] shutdown php runtime supervisor after psgi owner init failure: %v", shutdownErr)
		}
		return fmt.Errorf("initialize psgi runtime supervisor: %w", err)
	}
	return nil
}

func refreshRuntimeAppsProcessOwnerState() error {
	if err := handler.InitPHPRuntimeInventoryRuntime(config.PHPRuntimeInventoryFile, config.ProxyRollbackMax); err != nil {
		return fmt.Errorf("reload php runtime inventory: %w", err)
	}
	if err := handler.InitPSGIRuntimeInventoryRuntime(config.PSGIRuntimeInventoryFile, config.ProxyRollbackMax); err != nil {
		return fmt.Errorf("reload psgi runtime inventory: %w", err)
	}
	if err := handler.InitVhostRuntime(config.VhostConfigFile, config.ProxyRollbackMax); err != nil {
		return fmt.Errorf("reload runtime apps: %w", err)
	}
	return nil
}

func configureRuntimeAppProcessControllerForWorker() error {
	if runtimeAppsLocalProcessOwnerFromEnv(os.Environ()) {
		handler.ResetRuntimeAppProcessController()
		return nil
	}
	socketPath := strings.TrimSpace(os.Getenv(runtimeAppsControlSocketEnv))
	if socketPath == "" {
		return fmt.Errorf("%s is required for supervised workers", runtimeAppsControlSocketEnv)
	}
	controller, err := handler.NewRuntimeAppProcessHTTPController(socketPath)
	if err != nil {
		return err
	}
	handler.SetRuntimeAppProcessController(controller)
	return nil
}

func runtimeAppsLocalProcessOwnerFromEnv(env []string) bool {
	return internalProcessRoleFromEnv(env) != internalProcessRoleWorker
}

func (s *runtimeAppsControlServer) handlePHPProcesses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondRuntimeAppsControlError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	respondRuntimeAppsControlJSON(w, http.StatusOK, map[string]any{"processes": handler.PHPRuntimeProcessSnapshot()})
}

func (s *runtimeAppsControlServer) handlePHPReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondRuntimeAppsControlError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := refreshRuntimeAppsProcessOwnerState(); err != nil {
		respondRuntimeAppsControlError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	respondRuntimeAppsControlJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *runtimeAppsControlServer) handlePHPAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondRuntimeAppsControlError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var in runtimeAppProcessControlActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		respondRuntimeAppsControlError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := refreshRuntimeAppsProcessOwnerState(); err != nil {
		respondRuntimeAppsControlError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	runtimeID, err := validateRuntimeAppsControlToken("runtime_id", in.RuntimeID)
	if err != nil {
		respondRuntimeAppsControlError(w, http.StatusBadRequest, err.Error())
		return
	}
	var actionErr error
	switch strings.TrimSpace(in.Action) {
	case "start":
		actionErr = handler.StartPHPRuntimeProcess(runtimeID)
	case "stop":
		actionErr = handler.StopPHPRuntimeProcess(runtimeID)
	case "reload":
		actionErr = handler.ReloadPHPRuntimeProcess(runtimeID)
	default:
		actionErr = fmt.Errorf("unknown php runtime action %q", in.Action)
	}
	if actionErr != nil {
		respondRuntimeAppsControlError(w, http.StatusUnprocessableEntity, actionErr.Error())
		return
	}
	respondRuntimeAppsControlJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *runtimeAppsControlServer) handlePSGIProcesses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondRuntimeAppsControlError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	respondRuntimeAppsControlJSON(w, http.StatusOK, map[string]any{"processes": handler.PSGIRuntimeProcessSnapshot()})
}

func (s *runtimeAppsControlServer) handlePSGIReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondRuntimeAppsControlError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := refreshRuntimeAppsProcessOwnerState(); err != nil {
		respondRuntimeAppsControlError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	respondRuntimeAppsControlJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *runtimeAppsControlServer) handlePSGIAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondRuntimeAppsControlError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var in runtimeAppProcessControlActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		respondRuntimeAppsControlError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := refreshRuntimeAppsProcessOwnerState(); err != nil {
		respondRuntimeAppsControlError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	processID, err := validateRuntimeAppsControlToken("process_id", in.ProcessID)
	if err != nil {
		respondRuntimeAppsControlError(w, http.StatusBadRequest, err.Error())
		return
	}
	var actionErr error
	switch strings.TrimSpace(in.Action) {
	case "start":
		actionErr = handler.StartPSGIProcess(processID)
	case "stop":
		actionErr = handler.StopPSGIProcess(processID)
	case "reload":
		actionErr = handler.ReloadPSGIProcess(processID)
	default:
		actionErr = fmt.Errorf("unknown psgi runtime action %q", in.Action)
	}
	if actionErr != nil {
		respondRuntimeAppsControlError(w, http.StatusUnprocessableEntity, actionErr.Error())
		return
	}
	respondRuntimeAppsControlJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type runtimeAppProcessControlActionRequest struct {
	Action    string `json:"action"`
	RuntimeID string `json:"runtime_id,omitempty"`
	ProcessID string `json:"process_id,omitempty"`
}

func validateRuntimeAppsControlToken(field string, value string) (string, error) {
	token := strings.ToLower(strings.TrimSpace(value))
	if token == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	if len(token) > 128 {
		return "", fmt.Errorf("%s is too long", field)
	}
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return "", fmt.Errorf("%s contains an invalid character", field)
		}
	}
	return token, nil
}

func respondRuntimeAppsControlJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func respondRuntimeAppsControlError(w http.ResponseWriter, status int, message string) {
	respondRuntimeAppsControlJSON(w, status, map[string]any{"error": strings.TrimSpace(message)})
}
