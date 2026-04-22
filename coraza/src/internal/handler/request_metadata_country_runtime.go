package handler

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"tukuyomi/internal/config"
)

const managedCountryMMDBPath = "data/geoip/country.mmdb"

type requestCountryMMDBRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

type requestCountryRuntimeStatus struct {
	ConfiguredMode string `json:"configured_mode"`
	EffectiveMode  string `json:"effective_mode"`
	ManagedPath    string `json:"managed_path"`
	Loaded         bool   `json:"loaded"`
	DBSizeBytes    int64  `json:"db_size_bytes"`
	DBModTime      string `json:"db_mod_time,omitempty"`
	LastError      string `json:"last_error,omitempty"`
}

type requestCountryRuntime struct {
	mu               sync.RWMutex
	configuredMode   string
	effectiveMode    string
	managedPath      string
	reader           *maxminddb.Reader
	dbSizeBytes      int64
	dbModTime        time.Time
	lastError        string
	nextRefreshCheck time.Time
}

var (
	requestCountryRuntimeMu       sync.RWMutex
	requestCountryRuntimeRt       *requestCountryRuntime
	requestCountryMMDBLookup      = defaultLookupRequestCountryMMDB
	requestCountryRefreshInterval = 15 * time.Second
)

func managedRequestCountryMMDBPath() string {
	return managedCountryMMDBPath
}

func InitRequestCountryRuntime() error {
	return reloadRequestCountryRuntime(config.RequestCountryMode)
}

func ValidateRequestCountryRuntimeConfig(cfg config.AppConfigFile) error {
	mode := strings.ToLower(strings.TrimSpace(cfg.RequestMeta.Country.Mode))
	if mode == "" || mode == "header" {
		return nil
	}
	if mode != "mmdb" {
		return fmt.Errorf("request_metadata.country.mode must be one of: header, mmdb")
	}
	state, err := loadManagedRequestCountryMMDB()
	if err != nil {
		return err
	}
	if state.reader != nil {
		_ = state.reader.Close()
	}
	return nil
}

func RequestCountryRuntimeStatusSnapshot() requestCountryRuntimeStatus {
	requestCountryRuntimeMu.RLock()
	rt := requestCountryRuntimeRt
	requestCountryRuntimeMu.RUnlock()
	if rt == nil {
		mode := strings.ToLower(strings.TrimSpace(config.RequestCountryMode))
		if mode == "" {
			mode = "header"
		}
		return requestCountryRuntimeStatus{
			ConfiguredMode: mode,
			EffectiveMode:  mode,
			ManagedPath:    managedRequestCountryMMDBPath(),
			Loaded:         false,
		}
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := requestCountryRuntimeStatus{
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

func lookupRequestCountryMMDB(clientIP string) (string, bool, error) {
	requestCountryRuntimeMu.RLock()
	rt := requestCountryRuntimeRt
	requestCountryRuntimeMu.RUnlock()
	if rt == nil {
		return "", false, fmt.Errorf("request country runtime is not initialized")
	}
	rt.maybeRefreshFromManagedFile()
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
	return requestCountryMMDBLookup(rt.reader, ip)
}

func defaultLookupRequestCountryMMDB(reader *maxminddb.Reader, ip net.IP) (string, bool, error) {
	var record requestCountryMMDBRecord
	if err := reader.Lookup(ip, &record); err != nil {
		return "", false, err
	}
	code := normalizeCountryCode(record.Country.ISOCode)
	if code == "UNKNOWN" {
		code = normalizeCountryCode(record.RegisteredCountry.ISOCode)
	}
	if code == "UNKNOWN" {
		return "", false, nil
	}
	return code, true, nil
}

type loadedRequestCountryMMDBState struct {
	reader      *maxminddb.Reader
	managedPath string
	sizeBytes   int64
	modTime     time.Time
}

func loadManagedRequestCountryMMDB() (loadedRequestCountryMMDBState, error) {
	path := managedRequestCountryMMDBPath()
	info, err := os.Stat(path)
	if err != nil {
		return loadedRequestCountryMMDBState{}, fmt.Errorf("open managed country mmdb (%s): %w", path, err)
	}
	if info.IsDir() {
		return loadedRequestCountryMMDBState{}, fmt.Errorf("managed country mmdb path is a directory: %s", path)
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return loadedRequestCountryMMDBState{}, fmt.Errorf("open managed country mmdb (%s): %w", path, err)
	}
	return loadedRequestCountryMMDBState{
		reader:      reader,
		managedPath: filepath.Clean(path),
		sizeBytes:   info.Size(),
		modTime:     info.ModTime().UTC(),
	}, nil
}

func (rt *requestCountryRuntime) maybeRefreshFromManagedFile() {
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
	currentPath := rt.managedPath
	currentSize := rt.dbSizeBytes
	currentModTime := rt.dbModTime
	rt.mu.RUnlock()

	info, err := os.Stat(currentPath)
	if err != nil {
		rt.mu.Lock()
		rt.nextRefreshCheck = now.Add(requestCountryRefreshInterval)
		rt.lastError = err.Error()
		rt.mu.Unlock()
		return
	}
	modTime := info.ModTime().UTC()
	size := info.Size()
	if size == currentSize && modTime.Equal(currentModTime) {
		rt.mu.Lock()
		rt.nextRefreshCheck = now.Add(requestCountryRefreshInterval)
		rt.mu.Unlock()
		return
	}

	state, err := requestCountryMMDBLoader()
	if err != nil {
		rt.mu.Lock()
		rt.nextRefreshCheck = now.Add(requestCountryRefreshInterval)
		rt.lastError = err.Error()
		rt.mu.Unlock()
		return
	}
	rt.mu.Lock()
	oldReader := rt.reader
	rt.reader = state.reader
	rt.managedPath = state.managedPath
	rt.dbSizeBytes = state.sizeBytes
	rt.dbModTime = state.modTime
	rt.lastError = ""
	rt.nextRefreshCheck = now.Add(requestCountryRefreshInterval)
	rt.mu.Unlock()
	if oldReader != nil {
		_ = oldReader.Close()
	}
}

func reloadRequestCountryRuntime(mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "header"
	}
	rt := &requestCountryRuntime{
		configuredMode: mode,
		effectiveMode:  mode,
		managedPath:    managedRequestCountryMMDBPath(),
	}
	if mode == "mmdb" {
		state, err := loadManagedRequestCountryMMDB()
		if err != nil {
			rt.lastError = err.Error()
			requestCountryRuntimeMu.Lock()
			prev := requestCountryRuntimeRt
			requestCountryRuntimeRt = rt
			requestCountryRuntimeMu.Unlock()
			if prev != nil {
				prev.close()
			}
			return err
		}
		rt.reader = state.reader
		rt.dbSizeBytes = state.sizeBytes
		rt.dbModTime = state.modTime
		rt.managedPath = state.managedPath
	}
	requestCountryRuntimeMu.Lock()
	prev := requestCountryRuntimeRt
	requestCountryRuntimeRt = rt
	requestCountryRuntimeMu.Unlock()
	if prev != nil {
		prev.close()
	}
	return nil
}

func (rt *requestCountryRuntime) close() {
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
