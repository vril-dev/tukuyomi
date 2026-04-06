package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

const (
	logOutputConfigBlobKey = "log_output_profile"

	logOutputModeStdout  = "stdout-ndjson"
	logOutputModeFile    = "file-ndjson"
	logOutputModeDual    = "dual"
	logOutputModeDisable = "disabled"

	defaultLogOutputFilePath = "conf/log-output.json"
	defaultLogOutputProvider = "custom"
)

type logOutputTarget struct {
	Mode     string `json:"mode"`
	FilePath string `json:"file_path,omitempty"`
}

type logOutputConfig struct {
	Provider    string          `json:"provider,omitempty"`
	WAF         logOutputTarget `json:"waf,omitempty"`
	Interesting logOutputTarget `json:"interesting,omitempty"`
	AccessError logOutputTarget `json:"access_error,omitempty"`
}

type logOutputStatus struct {
	Path                string          `json:"path"`
	Provider            string          `json:"provider"`
	WAF                 logOutputTarget `json:"waf"`
	Interesting         logOutputTarget `json:"interesting"`
	AccessError         logOutputTarget `json:"access_error"`
	StdoutStreams       int             `json:"stdout_streams"`
	FileStreams         int             `json:"file_streams"`
	LocalReadCompatible bool            `json:"local_read_compatible"`
}

var (
	logOutputMu      sync.RWMutex
	logOutputPath    string
	logOutputRuntime *logOutputStatus
)

func InitLogOutput(path string) error {
	target := strings.TrimSpace(path)
	if target == "" {
		target = defaultLogOutputFilePath
	}
	if err := ensureLogOutputFile(target); err != nil {
		return err
	}

	logOutputMu.Lock()
	logOutputPath = target
	logOutputMu.Unlock()

	return ReloadLogOutput()
}

func GetLogOutputPath() string {
	logOutputMu.RLock()
	target := strings.TrimSpace(logOutputPath)
	logOutputMu.RUnlock()
	if target != "" {
		return target
	}
	if strings.TrimSpace(config.LogOutputFile) != "" {
		return strings.TrimSpace(config.LogOutputFile)
	}
	return defaultLogOutputFilePath
}

func GetLogOutputStatus() logOutputStatus {
	logOutputMu.RLock()
	rt := logOutputRuntime
	logOutputMu.RUnlock()
	if rt != nil {
		return *rt
	}
	defaults := defaultLogOutputStatus()
	defaults.Path = GetLogOutputPath()
	return defaults
}

func ReloadLogOutput() error {
	path := GetLogOutputPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rt, err := parseLogOutputRaw(string(raw), true)
	if err != nil {
		return err
	}
	rt.Path = path
	applyLogOutputPaths(*rt)

	logOutputMu.Lock()
	logOutputRuntime = rt
	logOutputMu.Unlock()
	return nil
}

func ValidateLogOutputRaw(raw string) (*logOutputStatus, error) {
	return parseLogOutputRaw(raw, true)
}

func ParseLogOutputRaw(raw string) (*logOutputStatus, error) {
	return parseLogOutputRaw(raw, false)
}

func SyncLogOutputStorage() error {
	return syncConfigBlobFilePath(configBlobSyncOptions{
		ConfigKey: logOutputConfigBlobKey,
		Path:      GetLogOutputPath(),
		ValidateRaw: func(raw string) error {
			_, err := ValidateLogOutputRaw(raw)
			return err
		},
		Reload:           ReloadLogOutput,
		SkipWriteIfEqual: true,
	})
}

func emitJSONLog(obj map[string]any) {
	if shouldEmitLogOutputStdout("waf") {
		if b, err := json.Marshal(obj); err == nil {
			log.Println(string(b))
		}
	}
	ObserveNotificationLogEvent(obj)
}

func appendEventToFile(obj map[string]any) error {
	target := currentLogOutputTarget("waf")
	if !logOutputWritesFile(target.Mode) {
		return nil
	}
	return appendJSONLineToPath(target.FilePath, obj)
}

func parseLogOutputRaw(raw string, validateTargets bool) (*logOutputStatus, error) {
	cfg := defaultLogOutputConfig()
	raw = strings.TrimSpace(raw)
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return nil, err
		}
	}

	provider, err := normalizeLogOutputProvider(cfg.Provider)
	if err != nil {
		return nil, err
	}
	wafTarget, err := normalizeLogOutputTarget("waf", cfg.WAF, logOutputModeDual, defaultLogPathForStream("waf"), validateTargets)
	if err != nil {
		return nil, err
	}
	intrTarget, err := normalizeLogOutputTarget("interesting", cfg.Interesting, logOutputModeFile, defaultLogPathForStream("intr"), validateTargets)
	if err != nil {
		return nil, err
	}
	accerrTarget, err := normalizeLogOutputTarget("access_error", cfg.AccessError, logOutputModeFile, defaultLogPathForStream("accerr"), validateTargets)
	if err != nil {
		return nil, err
	}

	rt := &logOutputStatus{
		Path:        GetLogOutputPath(),
		Provider:    provider,
		WAF:         wafTarget,
		Interesting: intrTarget,
		AccessError: accerrTarget,
	}
	for _, target := range []logOutputTarget{rt.WAF, rt.Interesting, rt.AccessError} {
		if logOutputWritesStdout(target.Mode) {
			rt.StdoutStreams++
		}
		if logOutputWritesFile(target.Mode) {
			rt.FileStreams++
		}
	}
	rt.LocalReadCompatible = logOutputWritesFile(rt.WAF.Mode) && logOutputWritesFile(rt.Interesting.Mode) && logOutputWritesFile(rt.AccessError.Mode)
	return rt, nil
}

func defaultLogOutputStatus() logOutputStatus {
	return logOutputStatus{
		Path:     GetLogOutputPath(),
		Provider: defaultLogOutputProvider,
		WAF: logOutputTarget{
			Mode:     logOutputModeDual,
			FilePath: defaultLogPathForStream("waf"),
		},
		Interesting: logOutputTarget{
			Mode:     logOutputModeFile,
			FilePath: defaultLogPathForStream("intr"),
		},
		AccessError: logOutputTarget{
			Mode:     logOutputModeFile,
			FilePath: defaultLogPathForStream("accerr"),
		},
		StdoutStreams:       1,
		FileStreams:         3,
		LocalReadCompatible: true,
	}
}

func defaultLogOutputConfig() logOutputConfig {
	status := defaultLogOutputStatus()
	return logOutputConfig{
		Provider:    status.Provider,
		WAF:         status.WAF,
		Interesting: status.Interesting,
		AccessError: status.AccessError,
	}
}

func ensureLogOutputFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	cfg := defaultLogOutputConfig()
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

func normalizeLogOutputProvider(v string) (string, error) {
	provider := strings.ToLower(strings.TrimSpace(v))
	if provider == "" {
		return defaultLogOutputProvider, nil
	}
	for _, r := range provider {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return "", fmt.Errorf("provider must be lowercase alnum/dash/underscore")
	}
	return provider, nil
}

func normalizeLogOutputTarget(name string, target logOutputTarget, defaultMode, defaultPath string, validateTargets bool) (logOutputTarget, error) {
	mode := strings.ToLower(strings.TrimSpace(target.Mode))
	if mode == "" {
		mode = defaultMode
	}
	if !isAllowedLogOutputMode(mode) {
		return logOutputTarget{}, fmt.Errorf("%s.mode must be one of %q, %q, %q, %q", name, logOutputModeStdout, logOutputModeFile, logOutputModeDual, logOutputModeDisable)
	}
	path := strings.TrimSpace(target.FilePath)
	if path == "" {
		path = defaultPath
	}
	if logOutputWritesFile(mode) {
		if strings.TrimSpace(path) == "" {
			return logOutputTarget{}, fmt.Errorf("%s.file_path is required for %s mode", name, mode)
		}
		if validateTargets {
			if err := validateWritableLogTarget(path); err != nil {
				return logOutputTarget{}, fmt.Errorf("%s.file_path: %w", name, err)
			}
		}
	}
	return logOutputTarget{
		Mode:     mode,
		FilePath: path,
	}, nil
}

func validateWritableLogTarget(path string) error {
	dir := filepath.Dir(strings.TrimSpace(path))
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tukuyomi-log-output-check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Remove(name)
}

func defaultLogPathForStream(stream string) string {
	switch stream {
	case "waf":
		if v := strings.TrimSpace(os.Getenv("WAF_EVENTS_FILE")); v != "" {
			return v
		}
		if v := strings.TrimSpace(config.LogFile); v != "" {
			return v
		}
	case "intr", "accerr":
	}
	if path := strings.TrimSpace(logFiles[stream]); path != "" {
		return path
	}
	switch stream {
	case "intr":
		return filepath.Join(logDirNginx, "interesting.ndjson")
	case "accerr":
		return filepath.Join(logDirNginx, "access-error.ndjson")
	default:
		return filepath.Join(logDirCoraza, "waf-events.ndjson")
	}
}

func currentLogOutputTarget(stream string) logOutputTarget {
	rt := GetLogOutputStatus()
	switch stream {
	case "intr":
		return rt.Interesting
	case "accerr":
		return rt.AccessError
	default:
		return rt.WAF
	}
}

func shouldEmitLogOutputStdout(stream string) bool {
	return logOutputWritesStdout(currentLogOutputTarget(stream).Mode)
}

func emitLogOutputStream(stream string, obj map[string]any) error {
	target := currentLogOutputTarget(stream)
	if logOutputWritesStdout(target.Mode) {
		if b, err := json.Marshal(obj); err == nil {
			log.Println(string(b))
		}
	}
	if !logOutputWritesFile(target.Mode) {
		return nil
	}
	return appendJSONLineToPath(target.FilePath, obj)
}

func logOutputWritesStdout(mode string) bool {
	return mode == logOutputModeStdout || mode == logOutputModeDual
}

func logOutputWritesFile(mode string) bool {
	return mode == logOutputModeFile || mode == logOutputModeDual
}

func isAllowedLogOutputMode(mode string) bool {
	switch mode {
	case logOutputModeStdout, logOutputModeFile, logOutputModeDual, logOutputModeDisable:
		return true
	default:
		return false
	}
}

func applyLogOutputPaths(rt logOutputStatus) {
	logFiles["waf"] = rt.WAF.FilePath
	logFiles["intr"] = rt.Interesting.FilePath
	logFiles["accerr"] = rt.AccessError.FilePath
}

func renderLogOutputResponse(raw string, etag string, rt *logOutputStatus) map[string]any {
	status := defaultLogOutputStatus()
	if rt != nil {
		status = *rt
	}
	return map[string]any{
		"etag":                   etag,
		"raw":                    raw,
		"path":                   status.Path,
		"provider":               status.Provider,
		"waf_mode":               status.WAF.Mode,
		"waf_file_path":          status.WAF.FilePath,
		"interesting_mode":       status.Interesting.Mode,
		"interesting_file_path":  status.Interesting.FilePath,
		"access_error_mode":      status.AccessError.Mode,
		"access_error_file_path": status.AccessError.FilePath,
		"stdout_streams":         status.StdoutStreams,
		"file_streams":           status.FileStreams,
		"local_read_compatible":  status.LocalReadCompatible,
	}
}

func currentLogOutputETag(raw []byte) string {
	return bypassconf.ComputeETag(raw)
}

func logOutputUpdatedAt() time.Time {
	return time.Now().UTC()
}
