package requestmeta

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

const defaultCountryRuntimeRefreshInterval = 15 * time.Second

type CountryMMDBRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

type MMDBState struct {
	Reader      *maxminddb.Reader
	ManagedPath string
	VersionID   int64
	VersionETag string
	SizeBytes   int64
	ModTime     time.Time
}

func (s MMDBState) Close() {
	if s.Reader != nil {
		_ = s.Reader.Close()
	}
}

type MMDBVersion struct {
	VersionID int64
	ETag      string
}

type MMDBLoader func() (MMDBState, error)

type MMDBVersionProbe func() (MMDBVersion, bool, error)

type CountryRuntimeOptions struct {
	Mode                  string
	ManagedPath           string
	Loader                MMDBLoader
	VersionProbe          MMDBVersionProbe
	StoreUnavailableError string
	RefreshInterval       time.Duration
}

type CountryRuntimeStatus struct {
	ConfiguredMode string `json:"configured_mode"`
	EffectiveMode  string `json:"effective_mode"`
	ManagedPath    string `json:"managed_path"`
	Loaded         bool   `json:"loaded"`
	DBSizeBytes    int64  `json:"db_size_bytes"`
	DBModTime      string `json:"db_mod_time,omitempty"`
	LastError      string `json:"last_error,omitempty"`
}

type countryRuntime struct {
	mu                    sync.RWMutex
	configuredMode        string
	effectiveMode         string
	managedPath           string
	reader                *maxminddb.Reader
	versionID             int64
	versionETag           string
	dbSizeBytes           int64
	dbModTime             time.Time
	lastError             string
	nextRefreshCheck      time.Time
	loader                MMDBLoader
	versionProbe          MMDBVersionProbe
	storeUnavailableError string
	refreshInterval       time.Duration
}

var (
	countryRuntimeMu sync.RWMutex
	countryRuntimeRt *countryRuntime
)

func InitCountryRuntime(opts CountryRuntimeOptions) error {
	mode := normalizeCountryRuntimeMode(opts.Mode)
	refreshInterval := opts.RefreshInterval
	if refreshInterval <= 0 {
		refreshInterval = defaultCountryRuntimeRefreshInterval
	}
	rt := &countryRuntime{
		configuredMode:        mode,
		effectiveMode:         mode,
		managedPath:           strings.TrimSpace(opts.ManagedPath),
		loader:                opts.Loader,
		versionProbe:          opts.VersionProbe,
		storeUnavailableError: strings.TrimSpace(opts.StoreUnavailableError),
		refreshInterval:       refreshInterval,
	}
	if mode == "mmdb" {
		state, err := rt.loadMMDBState()
		if err != nil {
			rt.lastError = err.Error()
			swapCountryRuntime(rt)
			return err
		}
		rt.applyState(state)
	}
	swapCountryRuntime(rt)
	return nil
}

func CloseCountryRuntime() {
	swapCountryRuntime(nil)
}

func CountryRuntimeStatusSnapshot(fallbackMode, managedPath string) CountryRuntimeStatus {
	countryRuntimeMu.RLock()
	rt := countryRuntimeRt
	countryRuntimeMu.RUnlock()
	if rt == nil {
		mode := normalizeCountryRuntimeMode(fallbackMode)
		return CountryRuntimeStatus{
			ConfiguredMode: mode,
			EffectiveMode:  mode,
			ManagedPath:    strings.TrimSpace(managedPath),
			Loaded:         false,
		}
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := CountryRuntimeStatus{
		ConfiguredMode: rt.configuredMode,
		EffectiveMode:  rt.effectiveMode,
		ManagedPath:    rt.managedPath,
		Loaded:         rt.reader != nil,
		DBSizeBytes:    rt.dbSizeBytes,
		LastError:      rt.lastError,
	}
	if !rt.dbModTime.IsZero() {
		out.DBModTime = rt.dbModTime.UTC().Format(time.RFC3339Nano)
	}
	return out
}

func LookupCountryMMDB(clientIP string) (string, bool, error) {
	countryRuntimeMu.RLock()
	rt := countryRuntimeRt
	countryRuntimeMu.RUnlock()
	if rt == nil {
		return "", false, fmt.Errorf("request country runtime is not initialized")
	}
	rt.maybeRefreshFromManagedSource()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if rt.effectiveMode != "mmdb" {
		return "", false, nil
	}
	if rt.reader == nil {
		return "", false, fmt.Errorf("country mmdb is not loaded")
	}
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		return "", false, nil
	}
	return DefaultLookupCountryMMDB(rt.reader, ip)
}

func DefaultLookupCountryMMDB(reader *maxminddb.Reader, ip net.IP) (string, bool, error) {
	if reader == nil {
		return "", false, fmt.Errorf("country mmdb reader is required")
	}
	var record CountryMMDBRecord
	if err := reader.Lookup(ip, &record); err != nil {
		return "", false, err
	}
	code := NormalizeCountryCode(record.Country.ISOCode)
	if code == "UNKNOWN" {
		code = NormalizeCountryCode(record.RegisteredCountry.ISOCode)
	}
	if code == "UNKNOWN" {
		return "", false, nil
	}
	return code, true, nil
}

func swapCountryRuntime(rt *countryRuntime) {
	countryRuntimeMu.Lock()
	prev := countryRuntimeRt
	countryRuntimeRt = rt
	countryRuntimeMu.Unlock()
	if prev != nil {
		prev.close()
	}
}

func normalizeCountryRuntimeMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "header"
	}
	return mode
}

func (rt *countryRuntime) maybeRefreshFromManagedSource() {
	if rt == nil {
		return
	}
	rt.mu.RLock()
	if rt.effectiveMode != "mmdb" {
		rt.mu.RUnlock()
		return
	}
	now := time.Now()
	if !rt.nextRefreshCheck.IsZero() && now.Before(rt.nextRefreshCheck) {
		rt.mu.RUnlock()
		return
	}
	currentVersionID := rt.versionID
	currentVersionETag := rt.versionETag
	rt.mu.RUnlock()

	version, found, err := rt.activeVersion()
	if err != nil {
		rt.recordRefreshError(now, err.Error())
		return
	}
	if !found {
		rt.recordRefreshError(now, "managed country mmdb is not installed")
		return
	}
	if version.VersionID == currentVersionID && version.ETag == currentVersionETag {
		rt.mu.Lock()
		rt.nextRefreshCheck = now.Add(rt.refreshInterval)
		rt.mu.Unlock()
		return
	}

	state, err := rt.loadMMDBState()
	if err != nil {
		rt.recordRefreshError(now, err.Error())
		return
	}
	rt.mu.Lock()
	oldReader := rt.reader
	rt.applyStateLocked(state)
	rt.lastError = ""
	rt.nextRefreshCheck = now.Add(rt.refreshInterval)
	rt.mu.Unlock()
	if oldReader != nil {
		_ = oldReader.Close()
	}
}

func (rt *countryRuntime) activeVersion() (MMDBVersion, bool, error) {
	if rt.versionProbe == nil {
		if rt.storeUnavailableError != "" {
			return MMDBVersion{}, false, errors.New(rt.storeUnavailableError)
		}
		return MMDBVersion{}, false, fmt.Errorf("country mmdb version probe is required")
	}
	return rt.versionProbe()
}

func (rt *countryRuntime) loadMMDBState() (MMDBState, error) {
	if rt.loader == nil {
		return MMDBState{}, fmt.Errorf("country mmdb loader is required")
	}
	return rt.loader()
}

func (rt *countryRuntime) recordRefreshError(now time.Time, message string) {
	rt.mu.Lock()
	rt.nextRefreshCheck = now.Add(rt.refreshInterval)
	rt.lastError = message
	rt.mu.Unlock()
}

func (rt *countryRuntime) applyState(state MMDBState) {
	rt.mu.Lock()
	rt.applyStateLocked(state)
	rt.mu.Unlock()
}

func (rt *countryRuntime) applyStateLocked(state MMDBState) {
	rt.reader = state.Reader
	rt.managedPath = state.ManagedPath
	rt.versionID = state.VersionID
	rt.versionETag = state.VersionETag
	rt.dbSizeBytes = state.SizeBytes
	rt.dbModTime = state.ModTime
}

func (rt *countryRuntime) close() {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	reader := rt.reader
	rt.reader = nil
	rt.mu.Unlock()
	if reader != nil {
		_ = reader.Close()
	}
}
