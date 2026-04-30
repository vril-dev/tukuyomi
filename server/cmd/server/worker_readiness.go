package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"tukuyomi/internal/buildinfo"
	"tukuyomi/internal/config"
)

const (
	workerReadinessProtocol = "tukuyomi.worker.ready.v1"
	workerReadyFDEnv        = "TUKUYOMI_WORKER_READY_FD"
)

type workerReadyMessage struct {
	Protocol        string `json:"protocol"`
	PID             int    `json:"pid"`
	Version         string `json:"version,omitempty"`
	GoVersion       string `json:"go_version"`
	ReadyAt         string `json:"ready_at"`
	ListenAddr      string `json:"listen_addr"`
	AdminListenAddr string `json:"admin_listen_addr,omitempty"`
	TLSEnabled      bool   `json:"tls_enabled"`
	HTTP3Enabled    bool   `json:"http3_enabled"`
}

type workerReadyNotifier struct {
	file *os.File
	once sync.Once
	err  error
}

func newWorkerReadinessFromEnv() (*workerReadyNotifier, error) {
	raw := strings.TrimSpace(os.Getenv(workerReadyFDEnv))
	if raw == "" {
		return nil, nil
	}
	fd, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", workerReadyFDEnv, err)
	}
	if fd < 3 {
		return nil, fmt.Errorf("%s must be >= 3", workerReadyFDEnv)
	}
	file := os.NewFile(uintptr(fd), "tukuyomi-worker-ready")
	if file == nil {
		return nil, fmt.Errorf("open readiness fd %d", fd)
	}
	return &workerReadyNotifier{file: file}, nil
}

func notifyWorkerReady(notifier *workerReadyNotifier) error {
	if notifier == nil {
		return nil
	}
	msg := currentWorkerReadyMessage()
	notifier.once.Do(func() {
		if err := json.NewEncoder(notifier.file).Encode(msg); err != nil {
			notifier.err = err
		}
		if err := notifier.file.Close(); err != nil && notifier.err == nil {
			notifier.err = err
		}
	})
	return notifier.err
}

func currentWorkerReadyMessage() workerReadyMessage {
	return workerReadyMessage{
		Protocol:        workerReadinessProtocol,
		PID:             os.Getpid(),
		Version:         strings.TrimSpace(buildinfo.Version),
		GoVersion:       runtime.Version(),
		ReadyAt:         time.Now().UTC().Format(time.RFC3339Nano),
		ListenAddr:      strings.TrimSpace(config.ListenAddr),
		AdminListenAddr: strings.TrimSpace(config.AdminListenAddr),
		TLSEnabled:      config.ServerTLSEnabled,
		HTTP3Enabled:    config.ServerHTTP3Enabled,
	}
}

func validateWorkerReadyMessage(msg workerReadyMessage) error {
	if msg.Protocol != workerReadinessProtocol {
		return fmt.Errorf("unexpected worker readiness protocol %q", msg.Protocol)
	}
	if msg.PID <= 0 {
		return fmt.Errorf("worker readiness pid must be positive")
	}
	if strings.TrimSpace(msg.ListenAddr) == "" {
		return fmt.Errorf("worker readiness listen_addr is empty")
	}
	if strings.TrimSpace(msg.GoVersion) == "" {
		return fmt.Errorf("worker readiness go_version is empty")
	}
	return nil
}
