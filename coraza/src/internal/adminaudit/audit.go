package adminaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultLimit       = 20
	MaxLimit           = 100
	DefaultFPTunerFile = "audit/fp-tuner-audit.ndjson"
)

type Info struct {
	TS      string `json:"ts"`
	Service string `json:"service"`
	Event   string `json:"event"`
	Actor   string `json:"actor"`
	IP      string `json:"ip,omitempty"`
}

type FPTunerEntry struct {
	TS               string `json:"ts"`
	Service          string `json:"service,omitempty"`
	Event            string `json:"event,omitempty"`
	Actor            string `json:"actor,omitempty"`
	IP               string `json:"ip,omitempty"`
	ProposalID       string `json:"proposal_id,omitempty"`
	ProposalHash     string `json:"proposal_hash,omitempty"`
	TargetPath       string `json:"target_path,omitempty"`
	Mode             string `json:"mode,omitempty"`
	Source           string `json:"source,omitempty"`
	Count            int    `json:"count,omitempty"`
	Simulate         *bool  `json:"simulate,omitempty"`
	ApprovalRequired *bool  `json:"approval_required,omitempty"`
	ApprovalToken    any    `json:"approval_token,omitempty"`
	ApprovalError    string `json:"approval_error,omitempty"`
	HotReloaded      *bool  `json:"hot_reloaded,omitempty"`
	Error            string `json:"error,omitempty"`
}

func NewInfo(event string, actor string, ip string) Info {
	return Info{
		TS:      time.Now().UTC().Format(time.RFC3339Nano),
		Service: "coraza",
		Event:   strings.TrimSpace(event),
		Actor:   strings.TrimSpace(actor),
		IP:      strings.TrimSpace(ip),
	}
}

func Append(path string, entry any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

func Latest[T any](path string, limit int, decodeLabel string) ([]T, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []T{}, nil
		}
		return nil, err
	}

	entries := make([]T, 0)
	for _, chunk := range bytes.Split(raw, []byte{'\n'}) {
		line := bytes.TrimSpace(chunk)
		if len(line) == 0 {
			continue
		}
		var entry T
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("decode %s audit entry: %w", decodeLabel, err)
		}
		entries = append(entries, entry)
	}

	limit = ClampLimit(limit)
	if len(entries) == 0 {
		return []T{}, nil
	}

	start := 0
	if len(entries) > limit {
		start = len(entries) - limit
	}
	out := make([]T, 0, len(entries)-start)
	for i := len(entries) - 1; i >= start; i -= 1 {
		out = append(out, entries[i])
	}
	return out, nil
}

func ParseLimit(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultLimit
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return DefaultLimit
	}
	return ClampLimit(limit)
}

func ClampLimit(limit int) int {
	if limit < 1 {
		return 1
	}
	if limit > MaxLimit {
		return MaxLimit
	}
	return limit
}
