package requestmeta

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

const MaxGeoIPUpdateOutputBytes = 16 << 10

type UpdateState struct {
	LastAttempt string `json:"last_attempt,omitempty"`
	LastSuccess string `json:"last_success,omitempty"`
	LastResult  string `json:"last_result,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

type UpdateService struct {
	ResolveUpdater func() (string, error)
	RunUpdater     func(context.Context, string, string, string) error
	ReadConfig     func() ([]byte, GeoIPConfigSummary, error)
	MakeTempDir    func(string) (string, error)
	ReplaceMMDB    func([]byte) error
	PersistState   func(UpdateState) error
	Now            func() time.Time
}

func (s UpdateService) RunNow(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	state := UpdateState{
		LastAttempt: now.Format(time.RFC3339Nano),
		LastResult:  "error",
	}
	defer func() {
		if s.PersistState != nil {
			_ = s.PersistState(state)
		}
	}()

	updaterPath, err := s.resolveUpdater()
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	rawConfig, summary, err := s.readConfig()
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	edition := summary.SupportedCountryEdition
	if edition == "" {
		state.LastError = "GeoIP.conf does not include a supported country edition"
		return errors.New(state.LastError)
	}
	updateConfig, err := RenderGeoIPConfigForCountryEdition(rawConfig, edition)
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	tmpDir, err := s.makeTempDir("country-db-update-*")
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "GeoIP.conf")
	if err := os.WriteFile(configPath, updateConfig, 0o600); err != nil {
		state.LastError = err.Error()
		return err
	}
	if err := s.runUpdater(ctx, updaterPath, configPath, tmpDir); err != nil {
		state.LastError = err.Error()
		return err
	}

	sourcePath := filepath.Join(tmpDir, edition+".mmdb")
	info, err := os.Stat(sourcePath)
	if err != nil || info.IsDir() {
		state.LastError = fmt.Sprintf("geoipupdate did not produce %s.mmdb", edition)
		return errors.New(state.LastError)
	}
	payload, err := os.ReadFile(sourcePath)
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	if _, err := maxminddb.FromBytes(payload); err != nil {
		state.LastError = fmt.Sprintf("invalid updated country mmdb: %v", err)
		return errors.New(state.LastError)
	}
	if err := s.replaceMMDB(payload); err != nil {
		state.LastError = err.Error()
		return err
	}
	state.LastResult = "success"
	state.LastSuccess = now.Format(time.RFC3339Nano)
	state.LastError = ""
	return nil
}

func (s UpdateService) resolveUpdater() (string, error) {
	if s.ResolveUpdater == nil {
		return "", errors.New("GeoIP updater resolver is required")
	}
	return s.ResolveUpdater()
}

func (s UpdateService) readConfig() ([]byte, GeoIPConfigSummary, error) {
	if s.ReadConfig == nil {
		return nil, GeoIPConfigSummary{}, errors.New("GeoIP config reader is required")
	}
	return s.ReadConfig()
}

func (s UpdateService) makeTempDir(pattern string) (string, error) {
	if s.MakeTempDir == nil {
		return "", errors.New("GeoIP update temp directory provider is required")
	}
	return s.MakeTempDir(pattern)
}

func (s UpdateService) runUpdater(ctx context.Context, binaryPath, configPath, databaseDir string) error {
	if s.RunUpdater == nil {
		return errors.New("GeoIP updater runner is required")
	}
	return s.RunUpdater(ctx, binaryPath, configPath, databaseDir)
}

func (s UpdateService) replaceMMDB(payload []byte) error {
	if s.ReplaceMMDB == nil {
		return errors.New("country MMDB replacement callback is required")
	}
	return s.ReplaceMMDB(payload)
}

func ResolveGeoIPUpdateBinary() (string, error) {
	candidates := make([]string, 0, 5)
	if path := strings.TrimSpace(os.Getenv("GEOIPUPDATE_BIN")); path != "" {
		candidates = append(candidates, path)
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "geoipupdate"),
			filepath.Join(exeDir, "bin", "geoipupdate"),
		)
	}
	candidates = append(candidates,
		filepath.Join(".", "bin", "geoipupdate"),
	)
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return filepath.Clean(candidate), nil
		}
	}
	if path, err := exec.LookPath("geoipupdate"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("geoipupdate binary not found; install MaxMind geoipupdate or set GEOIPUPDATE_BIN")
}

func RunGeoIPUpdate(ctx context.Context, binaryPath, configPath, databaseDir string) error {
	cmd := exec.CommandContext(ctx, binaryPath, "-f", configPath, "-d", databaseDir, "-v")
	output, err := cmd.CombinedOutput()
	if len(output) > MaxGeoIPUpdateOutputBytes {
		output = output[:MaxGeoIPUpdateOutputBytes]
	}
	if err != nil {
		if len(output) > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
		}
		return err
	}
	return nil
}
