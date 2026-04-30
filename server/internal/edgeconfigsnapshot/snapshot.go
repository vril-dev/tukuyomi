package edgeconfigsnapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion = 1
	MaxBytes      = 2 * 1024 * 1024
)

type Build struct {
	Revision    string
	PayloadHash string
	PayloadRaw  []byte
}

type Payload struct {
	SchemaVersion  int               `json:"schema_version"`
	ConfigRevision string            `json:"config_revision"`
	GeneratedAt    string            `json:"generated_at"`
	DeviceID       string            `json:"device_id"`
	KeyID          string            `json:"key_id"`
	GatewayVersion string            `json:"gateway_version,omitempty"`
	GoVersion      string            `json:"go_version,omitempty"`
	Domains        map[string]Domain `json:"domains"`
	RedactedPaths  []string          `json:"redacted_paths,omitempty"`
	Warnings       []string          `json:"warnings,omitempty"`
}

type Domain struct {
	ETag  string          `json:"etag,omitempty"`
	Raw   json.RawMessage `json:"raw,omitempty"`
	Error string          `json:"error,omitempty"`
}

type Builder struct {
	payload Payload
}

func New(deviceID, keyID, gatewayVersion, goVersion string) *Builder {
	return &Builder{payload: Payload{
		SchemaVersion:  SchemaVersion,
		DeviceID:       deviceID,
		KeyID:          keyID,
		GatewayVersion: clampText(gatewayVersion, 128),
		GoVersion:      clampText(goVersion, 64),
		Domains:        map[string]Domain{},
	}}
}

func (b *Builder) AddRawDomain(name, etag string, raw []byte) {
	if b == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	compacted, err := compactJSONRaw(raw)
	if err != nil {
		b.AddDomainError(name, err)
		return
	}
	b.payload.Domains[name] = Domain{
		ETag: strings.TrimSpace(etag),
		Raw:  compacted,
	}
}

func (b *Builder) AddValueDomain(name, etag string, value any) {
	if b == nil {
		return
	}
	raw, err := json.Marshal(value)
	if err != nil {
		b.AddDomainError(name, err)
		return
	}
	b.AddRawDomain(name, etag, raw)
}

func (b *Builder) AddDomainError(name string, err error) {
	if b == nil || err == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	b.payload.Domains[name] = Domain{Error: clampText(err.Error(), 512)}
}

func (b *Builder) AddRedactedPaths(paths ...string) {
	if b == nil {
		return
	}
	b.payload.RedactedPaths = append(b.payload.RedactedPaths, paths...)
}

func (b *Builder) AddWarning(warning string) {
	if b == nil {
		return
	}
	warning = strings.TrimSpace(warning)
	if warning != "" {
		b.payload.Warnings = append(b.payload.Warnings, warning)
	}
}

func (b *Builder) Build() (Build, error) {
	if b == nil {
		return Build{}, fmt.Errorf("config snapshot builder is nil")
	}
	payload := b.payload
	if payload.Domains == nil {
		payload.Domains = map[string]Domain{}
	}
	payload.RedactedPaths = sortedUniqueStrings(payload.RedactedPaths)
	payload.Warnings = sortedUniqueStrings(payload.Warnings)
	revision, err := Revision(payload)
	if err != nil {
		return Build{}, err
	}
	payload.ConfigRevision = revision
	payload.GeneratedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(payload)
	if err != nil {
		return Build{}, fmt.Errorf("marshal config snapshot: %w", err)
	}
	if len(raw) > MaxBytes {
		return Build{}, fmt.Errorf("config snapshot exceeds %d bytes", MaxBytes)
	}
	sum := sha256.Sum256(raw)
	return Build{
		Revision:    revision,
		PayloadHash: hex.EncodeToString(sum[:]),
		PayloadRaw:  raw,
	}, nil
}

func Revision(payload Payload) (string, error) {
	payload.ConfigRevision = ""
	payload.GeneratedAt = ""
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal config snapshot revision: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func RedactAppConfigRaw(raw string) ([]byte, []string, error) {
	var obj any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return nil, nil, err
	}
	paths := []string{}
	for _, path := range []string{
		"admin.session_secret",
		"security_audit.encryption_key",
		"security_audit.hmac_key",
		"fp_tuner.api_key",
		"storage.db_dsn",
	} {
		if redactJSONPath(obj, path) {
			paths = append(paths, "app_config."+path)
		}
	}
	compacted, err := compactJSONRaw(mustMarshalJSON(obj))
	if err != nil {
		return nil, nil, err
	}
	return compacted, paths, nil
}

func compactJSONRaw(raw []byte) (json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), buf.Bytes()...), nil
}

func redactJSONPath(root any, dotted string) bool {
	parts := strings.Split(strings.TrimSpace(dotted), ".")
	if len(parts) == 0 {
		return false
	}
	current := root
	for i, part := range parts {
		obj, ok := current.(map[string]any)
		if !ok {
			return false
		}
		if i == len(parts)-1 {
			value, found := obj[part]
			if !found {
				return false
			}
			if s, ok := value.(string); ok && s == "" {
				return false
			}
			obj[part] = "[redacted]"
			return true
		}
		next, found := obj[part]
		if !found {
			return false
		}
		current = next
	}
	return false
}

func mustMarshalJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return raw
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func clampText(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}
