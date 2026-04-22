package handler

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

const (
	managedCountryGeoIPConfigPath      = "data/geoip/GeoIP.conf"
	managedCountryUpdateStatusPath     = "data/geoip/update-status.json"
	maxRequestCountryConfigUploadBytes = 512 << 10
	maxRequestCountryUpdateOutputBytes = 16 << 10
)

var (
	requestCountryUpdateNowFunc = defaultRunRequestCountryDBUpdateNow
	requestCountryUpdateRun     = defaultRunGeoIPUpdate
	requestCountryMMDBLoader    = loadManagedRequestCountryMMDB
)

func RunManagedRequestCountryUpdateNow(ctx context.Context) error {
	return requestCountryUpdateNowFunc(ctx)
}

type requestCountryGeoIPConfigSummary struct {
	EditionIDs              []string
	SupportedCountryEdition string
	HasAccountID            bool
	HasLicenseKey           bool
}

type requestCountryUpdateState struct {
	LastAttempt string `json:"last_attempt,omitempty"`
	LastSuccess string `json:"last_success,omitempty"`
	LastResult  string `json:"last_result,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

type requestCountryUpdateStatusResponse struct {
	ManagedConfigPath       string   `json:"managed_config_path"`
	ConfigInstalled         bool     `json:"config_installed"`
	ConfigSizeBytes         int64    `json:"config_size_bytes"`
	ConfigModTime           string   `json:"config_mod_time,omitempty"`
	EditionIDs              []string `json:"edition_ids,omitempty"`
	SupportedCountryEdition string   `json:"supported_country_edition,omitempty"`
	UpdaterAvailable        bool     `json:"updater_available"`
	UpdaterPath             string   `json:"updater_path,omitempty"`
	LastAttempt             string   `json:"last_attempt,omitempty"`
	LastSuccess             string   `json:"last_success,omitempty"`
	LastResult              string   `json:"last_result,omitempty"`
	LastError               string   `json:"last_error,omitempty"`
}

func managedRequestCountryGeoIPConfigPath() string {
	return managedCountryGeoIPConfigPath
}

func managedRequestCountryUpdateStatusPath() string {
	return managedCountryUpdateStatusPath
}

func parseRequestCountryGeoIPConfig(raw []byte) (requestCountryGeoIPConfigSummary, error) {
	var (
		out            requestCountryGeoIPConfigSummary
		accountIDSeen  bool
		licenseKeySeen bool
		editions       []string
	)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 4096), maxRequestCountryConfigUploadBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(strings.Join(parts[1:], " "))
		switch key {
		case "accountid", "userid":
			accountIDSeen = value != ""
		case "licensekey":
			licenseKeySeen = value != ""
		case "editionids", "productids":
			for _, token := range strings.FieldsFunc(value, func(r rune) bool {
				return r == ' ' || r == ',' || r == '\t'
			}) {
				token = strings.TrimSpace(token)
				if token == "" {
					continue
				}
				editions = append(editions, token)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("read GeoIP.conf: %w", err)
	}
	out.EditionIDs = uniqueSortedStrings(editions)
	out.HasAccountID = accountIDSeen
	out.HasLicenseKey = licenseKeySeen
	out.SupportedCountryEdition = selectSupportedCountryEdition(out.EditionIDs)
	if !out.HasAccountID {
		return out, fmt.Errorf("GeoIP.conf must include AccountID")
	}
	if !out.HasLicenseKey {
		return out, fmt.Errorf("GeoIP.conf must include LicenseKey")
	}
	if len(out.EditionIDs) == 0 {
		return out, fmt.Errorf("GeoIP.conf must include EditionIDs")
	}
	if out.SupportedCountryEdition == "" {
		return out, fmt.Errorf("GeoIP.conf EditionIDs must include GeoLite2-Country or GeoIP2-Country")
	}
	return out, nil
}

func selectSupportedCountryEdition(editionIDs []string) string {
	for _, id := range editionIDs {
		switch strings.TrimSpace(id) {
		case "GeoIP2-Country", "GeoLite2-Country":
			return strings.TrimSpace(id)
		}
	}
	return ""
}

func uniqueSortedStrings(values []string) []string {
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
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func buildRequestCountryUpdateStatus() requestCountryUpdateStatusResponse {
	out := requestCountryUpdateStatusResponse{
		ManagedConfigPath: managedRequestCountryGeoIPConfigPath(),
	}
	if updaterPath, err := resolveGeoIPUpdateBinary(); err == nil {
		out.UpdaterAvailable = true
		out.UpdaterPath = updaterPath
	} else {
		out.LastError = err.Error()
	}
	if state, err := readRequestCountryUpdateState(); err == nil {
		out.LastAttempt = state.LastAttempt
		out.LastSuccess = state.LastSuccess
		out.LastResult = state.LastResult
		if state.LastError != "" {
			out.LastError = state.LastError
		}
	}
	info, err := os.Stat(managedRequestCountryGeoIPConfigPath())
	if err == nil && !info.IsDir() {
		out.ConfigInstalled = true
		out.ConfigSizeBytes = info.Size()
		out.ConfigModTime = info.ModTime().UTC().Format(time.RFC3339Nano)
		raw, readErr := os.ReadFile(managedRequestCountryGeoIPConfigPath())
		if readErr != nil {
			if out.LastError == "" {
				out.LastError = readErr.Error()
			}
			return out
		}
		summary, parseErr := parseRequestCountryGeoIPConfig(raw)
		if parseErr != nil {
			if out.LastError == "" {
				out.LastError = parseErr.Error()
			}
			return out
		}
		out.EditionIDs = summary.EditionIDs
		out.SupportedCountryEdition = summary.SupportedCountryEdition
		return out
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) && out.LastError == "" {
		out.LastError = err.Error()
	}
	return out
}

func readManagedRequestCountryGeoIPConfig() ([]byte, requestCountryGeoIPConfigSummary, error) {
	raw, err := os.ReadFile(managedRequestCountryGeoIPConfigPath())
	if err != nil {
		return nil, requestCountryGeoIPConfigSummary{}, fmt.Errorf("read managed GeoIP.conf: %w", err)
	}
	summary, err := parseRequestCountryGeoIPConfig(raw)
	if err != nil {
		return nil, summary, err
	}
	return raw, summary, nil
}

func writeManagedRequestCountryGeoIPConfig(src io.Reader) error {
	if src == nil {
		return fmt.Errorf("GeoIP.conf upload source is required")
	}
	tmp, err := os.CreateTemp("", "tukuyomi-country-geoip-conf-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	written, err := io.Copy(tmp, io.LimitReader(src, maxRequestCountryConfigUploadBytes+1))
	if err != nil {
		return err
	}
	if written > maxRequestCountryConfigUploadBytes {
		return fmt.Errorf("GeoIP.conf upload exceeds %d bytes", maxRequestCountryConfigUploadBytes)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	raw, err := os.ReadFile(tmpPath)
	if err != nil {
		return err
	}
	if _, err := parseRequestCountryGeoIPConfig(raw); err != nil {
		return err
	}
	target := managedRequestCountryGeoIPConfigPath()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return bypassconf.AtomicWriteWithBackup(target, raw)
}

func removeManagedRequestCountryGeoIPConfig() error {
	if err := os.Remove(managedRequestCountryGeoIPConfigPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func readRequestCountryUpdateState() (requestCountryUpdateState, error) {
	raw, err := os.ReadFile(managedRequestCountryUpdateStatusPath())
	if err != nil {
		return requestCountryUpdateState{}, err
	}
	var state requestCountryUpdateState
	if err := json.Unmarshal(raw, &state); err != nil {
		return requestCountryUpdateState{}, err
	}
	return state, nil
}

func persistRequestCountryUpdateState(state requestCountryUpdateState) error {
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	path := managedRequestCountryUpdateStatusPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return bypassconf.AtomicWriteWithBackup(path, append(payload, '\n'))
}

func resolveGeoIPUpdateBinary() (string, error) {
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

func defaultRunGeoIPUpdate(ctx context.Context, binaryPath, configPath, databaseDir string) error {
	cmd := exec.CommandContext(ctx, binaryPath, "-f", configPath, "-d", databaseDir, "-v")
	output, err := cmd.CombinedOutput()
	if len(output) > maxRequestCountryUpdateOutputBytes {
		output = output[:maxRequestCountryUpdateOutputBytes]
	}
	if err != nil {
		if len(output) > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
		}
		return err
	}
	return nil
}

func defaultRunRequestCountryDBUpdateNow(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now().UTC()
	state := requestCountryUpdateState{
		LastAttempt: now.Format(time.RFC3339Nano),
		LastResult:  "error",
	}
	defer func() {
		_ = persistRequestCountryUpdateState(state)
	}()
	updaterPath, err := resolveGeoIPUpdateBinary()
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	_, summary, err := readManagedRequestCountryGeoIPConfig()
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	edition := summary.SupportedCountryEdition
	if edition == "" {
		state.LastError = "GeoIP.conf does not include a supported country edition"
		return errors.New(state.LastError)
	}
	tmpDir, err := os.MkdirTemp("", "tukuyomi-country-db-update-*")
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	defer os.RemoveAll(tmpDir)

	if err := requestCountryUpdateRun(ctx, updaterPath, managedRequestCountryGeoIPConfigPath(), tmpDir); err != nil {
		state.LastError = err.Error()
		return err
	}

	sourcePath := filepath.Join(tmpDir, edition+".mmdb")
	info, err := os.Stat(sourcePath)
	if err != nil || info.IsDir() {
		state.LastError = fmt.Sprintf("geoipupdate did not produce %s.mmdb", edition)
		return errors.New(state.LastError)
	}
	reader, err := maxminddb.Open(sourcePath)
	if err != nil {
		state.LastError = fmt.Sprintf("invalid updated country mmdb: %v", err)
		return errors.New(state.LastError)
	}
	_ = reader.Close()
	payload, err := os.ReadFile(sourcePath)
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	target := managedRequestCountryMMDBPath()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		state.LastError = err.Error()
		return err
	}
	if err := bypassconf.AtomicWriteWithBackup(target, payload); err != nil {
		state.LastError = err.Error()
		return err
	}
	if strings.EqualFold(config.RequestCountryMode, "mmdb") {
		if err := reloadRequestCountryRuntime(config.RequestCountryMode); err != nil {
			state.LastError = err.Error()
			return err
		}
	}
	state.LastResult = "success"
	state.LastSuccess = now.Format(time.RFC3339Nano)
	state.LastError = ""
	return nil
}
