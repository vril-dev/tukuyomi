package handler

import (
	"bufio"
	"context"
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
)

const (
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
	return requestCountryGeoIPConfigStorageLabel
}

func managedRequestCountryUpdateStatusPath() string {
	return requestCountryUpdateStateStorageLabel
}

func currentRequestCountryGeoIPConfigStorageLabel() string {
	return requestCountryGeoIPConfigStorageLabel
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
		ManagedConfigPath: currentRequestCountryGeoIPConfigStorageLabel(),
	}
	if updaterPath, err := resolveGeoIPUpdateBinary(); err == nil {
		out.UpdaterAvailable = true
		out.UpdaterPath = updaterPath
	} else {
		out.LastError = err.Error()
	}
	if state, found, err := readRequestCountryUpdateState(); err == nil && found {
		out.LastAttempt = state.LastAttempt
		out.LastSuccess = state.LastSuccess
		out.LastResult = state.LastResult
		if state.LastError != "" {
			out.LastError = state.LastError
		}
	} else if err != nil && out.LastError == "" {
		out.LastError = err.Error()
	}

	store := getLogsStatsStore()
	if store == nil {
		if out.LastError == "" {
			out.LastError = errConfigDBStoreRequired.Error()
		}
		return out
	}
	cfg, rec, found, err := store.loadActiveRequestCountryGeoIPConfig()
	if err != nil {
		if out.LastError == "" {
			out.LastError = err.Error()
		}
		return out
	}
	if !found || !cfg.Present {
		return out
	}
	out.ConfigInstalled = true
	out.ConfigSizeBytes = cfg.SizeBytes
	if !rec.ActivatedAt.IsZero() {
		out.ConfigModTime = rec.ActivatedAt.UTC().Format(time.RFC3339Nano)
	}
	out.EditionIDs = append([]string(nil), cfg.Summary.EditionIDs...)
	out.SupportedCountryEdition = cfg.Summary.SupportedCountryEdition
	return out
}

func readManagedRequestCountryGeoIPConfig() ([]byte, requestCountryGeoIPConfigSummary, error) {
	store, err := requireConfigDBStore()
	if err != nil {
		return nil, requestCountryGeoIPConfigSummary{}, err
	}
	cfg, _, found, err := store.loadActiveRequestCountryGeoIPConfig()
	if err != nil {
		return nil, requestCountryGeoIPConfigSummary{}, fmt.Errorf("read managed GeoIP.conf (%s): %w", requestCountryGeoIPConfigStorageLabel, err)
	}
	if !found || !cfg.Present {
		return nil, requestCountryGeoIPConfigSummary{}, fmt.Errorf("read managed GeoIP.conf (%s): not found", requestCountryGeoIPConfigStorageLabel)
	}
	return append([]byte(nil), cfg.Raw...), cfg.Summary, nil
}

func writeManagedRequestCountryGeoIPConfig(src io.Reader) error {
	if src == nil {
		return fmt.Errorf("GeoIP.conf upload source is required")
	}
	raw, err := io.ReadAll(io.LimitReader(src, maxRequestCountryConfigUploadBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxRequestCountryConfigUploadBytes {
		return fmt.Errorf("GeoIP.conf upload exceeds %d bytes", maxRequestCountryConfigUploadBytes)
	}
	return writeManagedRequestCountryGeoIPConfigRaw(raw, configVersionSourceApply, "request country GeoIP config upload")
}

func writeManagedRequestCountryGeoIPConfigRaw(raw []byte, source string, reason string) error {
	summary, err := parseRequestCountryGeoIPConfig(raw)
	if err != nil {
		return err
	}
	store, err := requireConfigDBStore()
	if err != nil {
		return err
	}
	_, _, err = store.writeRequestCountryGeoIPConfigVersion("", requestCountryGeoIPConfigVersion{
		Present: true,
		Raw:     raw,
		Summary: summary,
	}, source, "", reason, 0)
	return err
}

func removeManagedRequestCountryGeoIPConfig() error {
	store, err := requireConfigDBStore()
	if err != nil {
		return err
	}
	_, _, err = store.writeRequestCountryGeoIPConfigVersion("", requestCountryGeoIPConfigVersion{Present: false}, configVersionSourceApply, "", "request country GeoIP config removal", 0)
	return err
}

func readRequestCountryUpdateState() (requestCountryUpdateState, bool, error) {
	store, err := requireConfigDBStore()
	if err != nil {
		return requestCountryUpdateState{}, false, err
	}
	return store.loadRequestCountryUpdateState()
}

func persistRequestCountryUpdateState(state requestCountryUpdateState) error {
	store, err := requireConfigDBStore()
	if err != nil {
		return err
	}
	return store.upsertRequestCountryUpdateState(state, time.Now().UTC())
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
	rawConfig, summary, err := readManagedRequestCountryGeoIPConfig()
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	edition := summary.SupportedCountryEdition
	if edition == "" {
		state.LastError = "GeoIP.conf does not include a supported country edition"
		return errors.New(state.LastError)
	}
	tmpDir, err := makeRuntimeTempDir("country-db-update-*")
	if err != nil {
		state.LastError = err.Error()
		return err
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "GeoIP.conf")
	if err := os.WriteFile(configPath, rawConfig, 0o600); err != nil {
		state.LastError = err.Error()
		return err
	}
	if err := requestCountryUpdateRun(ctx, updaterPath, configPath, tmpDir); err != nil {
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
	if err := replaceManagedCountryMMDBRaw(payload, configVersionSourceApply, "request country mmdb update"); err != nil {
		state.LastError = err.Error()
		return err
	}
	state.LastResult = "success"
	state.LastSuccess = now.Format(time.RFC3339Nano)
	state.LastError = ""
	return nil
}
