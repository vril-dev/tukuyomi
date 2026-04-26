package requestmeta

import (
	"fmt"
	"io"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

const MaxMMDBUploadBytes = 128 << 20

type CountryDBAssetStatus struct {
	Installed bool
	SizeBytes int64
	ModTime   time.Time
}

type CountryDBStatus struct {
	ManagedPath    string `json:"managed_path"`
	ConfigETag     string `json:"config_etag,omitempty"`
	ConfiguredMode string `json:"configured_mode"`
	EffectiveMode  string `json:"effective_mode"`
	Installed      bool   `json:"installed"`
	Loaded         bool   `json:"loaded"`
	SizeBytes      int64  `json:"size_bytes"`
	ModTime        string `json:"mod_time,omitempty"`
	LastError      string `json:"last_error,omitempty"`
}

type UpdateConfigStatus struct {
	Installed bool
	SizeBytes int64
	ModTime   time.Time
	Summary   GeoIPConfigSummary
}

type UpdateStatus struct {
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

func BuildCountryDBStatus(runtime CountryRuntimeStatus, configuredMode, configETag, lastError string, asset CountryDBAssetStatus) CountryDBStatus {
	out := CountryDBStatus{
		ManagedPath:    runtime.ManagedPath,
		ConfigETag:     configETag,
		ConfiguredMode: normalizeCountryRuntimeMode(configuredMode),
		EffectiveMode:  runtime.EffectiveMode,
		Loaded:         runtime.Loaded,
		LastError:      runtime.LastError,
	}
	if out.LastError == "" {
		out.LastError = lastError
	}
	if asset.Installed {
		out.Installed = true
		out.SizeBytes = asset.SizeBytes
		if !asset.ModTime.IsZero() {
			out.ModTime = asset.ModTime.UTC().Format(time.RFC3339Nano)
		}
	}
	return out
}

func BuildUpdateStatus(managedConfigPath, updaterPath string, updaterErr error, state UpdateState, stateFound bool, stateErr error, config UpdateConfigStatus, configErr error, storeUnavailableError string) UpdateStatus {
	out := UpdateStatus{
		ManagedConfigPath: managedConfigPath,
	}
	if updaterErr == nil {
		out.UpdaterAvailable = true
		out.UpdaterPath = updaterPath
	} else {
		out.LastError = updaterErr.Error()
	}
	if stateErr == nil && stateFound {
		out.LastAttempt = state.LastAttempt
		out.LastSuccess = state.LastSuccess
		out.LastResult = state.LastResult
		if state.LastError != "" {
			out.LastError = state.LastError
		}
	} else if stateErr != nil && out.LastError == "" {
		out.LastError = stateErr.Error()
	}
	if storeUnavailableError != "" && out.LastError == "" {
		out.LastError = storeUnavailableError
		return out
	}
	if configErr != nil {
		if out.LastError == "" {
			out.LastError = configErr.Error()
		}
		return out
	}
	if !config.Installed {
		return out
	}
	out.ConfigInstalled = true
	out.ConfigSizeBytes = config.SizeBytes
	if !config.ModTime.IsZero() {
		out.ConfigModTime = config.ModTime.UTC().Format(time.RFC3339Nano)
	}
	out.EditionIDs = append([]string(nil), config.Summary.EditionIDs...)
	out.SupportedCountryEdition = config.Summary.SupportedCountryEdition
	return out
}

func ReadMMDBUpload(src io.Reader) ([]byte, error) {
	if src == nil {
		return nil, fmt.Errorf("country db upload source is required")
	}
	raw, err := readBounded(src, MaxMMDBUploadBytes, "country db upload")
	if err != nil {
		return nil, err
	}
	if err := ValidateMMDB(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func ValidateMMDB(raw []byte) error {
	reader, err := maxminddb.FromBytes(raw)
	if err != nil {
		return fmt.Errorf("invalid country mmdb: %w", err)
	}
	_ = reader.Close()
	return nil
}

func ReadGeoIPConfigUpload(src io.Reader) ([]byte, GeoIPConfigSummary, error) {
	if src == nil {
		return nil, GeoIPConfigSummary{}, fmt.Errorf("GeoIP.conf upload source is required")
	}
	raw, err := readBounded(src, MaxGeoIPConfigBytes, "GeoIP.conf upload")
	if err != nil {
		return nil, GeoIPConfigSummary{}, err
	}
	summary, err := ParseGeoIPConfig(raw)
	if err != nil {
		return nil, GeoIPConfigSummary{}, err
	}
	return raw, summary, nil
}

func readBounded(src io.Reader, limit int64, label string) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(src, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, limit)
	}
	return raw, nil
}
