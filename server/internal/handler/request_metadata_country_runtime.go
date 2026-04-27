package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oschwald/maxminddb-golang"

	"tukuyomi/internal/config"
	"tukuyomi/internal/requestmeta"
	"tukuyomi/internal/runtimefiles"
)

var requestCountryRefreshInterval = 15 * time.Second

var (
	requestCountryUpdateNowFunc = defaultRunRequestCountryDBUpdateNow
	requestCountryUpdateRun     = requestmeta.RunGeoIPUpdate
	requestCountryMMDBLoader    = loadManagedRequestCountryMMDB
)

type requestCountryRuntimeStatus = requestmeta.CountryRuntimeStatus

type loadedRequestCountryMMDBState = requestmeta.MMDBState

type requestCountryDBStatusResponse = requestmeta.CountryDBStatus

type requestCountryGeoIPConfigSummary = requestmeta.GeoIPConfigSummary

type requestCountryUpdateState = requestmeta.UpdateState

type requestCountryUpdateStatusResponse = requestmeta.UpdateStatus

type putRequestCountryModeBody struct {
	Mode string `json:"mode"`
}

const (
	requestCountryMMDBConfigDomain           = requestmeta.MMDBConfigDomain
	requestCountryMMDBConfigSchemaVersion    = requestmeta.MMDBConfigSchemaVersion
	requestCountryMMDBStorageLabel           = requestmeta.MMDBStorageLabel
	requestCountryGeoIPConfigDomain          = requestmeta.GeoIPConfigDomain
	requestCountryGeoIPConfigSchemaVersion   = requestmeta.GeoIPConfigSchemaVersion
	requestCountryGeoIPConfigStorageLabel    = requestmeta.GeoIPConfigStorageLabel
	requestCountryUpdateStateTable           = requestmeta.UpdateStateTable
	requestCountryUpdateStateStorageLabel    = requestmeta.UpdateStateStorageLabel
	requestCountryUpdateStateDefaultStateKey = requestmeta.UpdateStateDefaultStateKey
)

type requestCountryMMDBAssetVersion = requestmeta.MMDBAssetVersion

type requestCountryGeoIPConfigVersion = requestmeta.GeoIPConfigVersion

func (s *wafEventStore) loadActiveRequestCountryMMDBAsset() (requestCountryMMDBAssetVersion, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(requestCountryMMDBConfigDomain)
	if err != nil || !found {
		return requestCountryMMDBAssetVersion{}, configVersionRecord{}, false, err
	}
	asset, err := s.loadRequestCountryMMDBAssetVersion(rec.VersionID)
	if err != nil {
		return requestCountryMMDBAssetVersion{}, configVersionRecord{}, false, err
	}
	asset.ETag = rec.ETag
	return asset, rec, true, nil
}

func (s *wafEventStore) loadRequestCountryMMDBAssetVersion(versionID int64) (requestCountryMMDBAssetVersion, error) {
	var (
		asset   requestCountryMMDBAssetVersion
		present int
		raw     []byte
	)
	if err := s.queryRow(`SELECT present, size_bytes, content_hash, raw_bytes FROM request_country_mmdb_assets WHERE version_id = ?`, versionID).
		Scan(&present, &asset.SizeBytes, &asset.ContentHash, &raw); err != nil {
		return requestCountryMMDBAssetVersion{}, err
	}
	asset.Present = boolFromDB(present)
	if asset.Present {
		asset.Raw = append([]byte(nil), raw...)
	}
	return requestmeta.NormalizeMMDBAssetVersion(asset), nil
}

func (s *wafEventStore) writeRequestCountryMMDBAssetVersion(expectedETag string, asset requestCountryMMDBAssetVersion, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, requestCountryMMDBAssetVersion, error) {
	asset = requestmeta.NormalizeMMDBAssetVersion(asset)
	rec, err := s.writeConfigVersion(
		requestCountryMMDBConfigDomain,
		requestCountryMMDBConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		requestmeta.MMDBAssetHash(asset),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			var raw any
			if asset.Present {
				raw = asset.Raw
			}
			_, err := s.txExec(tx, `INSERT INTO request_country_mmdb_assets (version_id, present, size_bytes, content_hash, raw_bytes) VALUES (?, ?, ?, ?, ?)`,
				versionID, boolToDB(asset.Present), asset.SizeBytes, asset.ContentHash, raw)
			return err
		},
	)
	if err != nil {
		return configVersionRecord{}, requestCountryMMDBAssetVersion{}, err
	}
	asset.ETag = rec.ETag
	return rec, asset, nil
}

func (s *wafEventStore) loadActiveRequestCountryGeoIPConfig() (requestCountryGeoIPConfigVersion, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(requestCountryGeoIPConfigDomain)
	if err != nil || !found {
		return requestCountryGeoIPConfigVersion{}, configVersionRecord{}, false, err
	}
	cfg, err := s.loadRequestCountryGeoIPConfigVersion(rec.VersionID)
	if err != nil {
		return requestCountryGeoIPConfigVersion{}, configVersionRecord{}, false, err
	}
	cfg.ETag = rec.ETag
	return cfg, rec, true, nil
}

func (s *wafEventStore) loadRequestCountryGeoIPConfigVersion(versionID int64) (requestCountryGeoIPConfigVersion, error) {
	var (
		cfg        requestCountryGeoIPConfigVersion
		present    int
		accountID  int
		licenseKey int
		rawText    string
	)
	if err := s.queryRow(`SELECT present, raw_text, size_bytes, has_account_id, has_license_key, supported_country_edition FROM request_country_geoip_configs WHERE version_id = ?`, versionID).
		Scan(&present, &rawText, &cfg.SizeBytes, &accountID, &licenseKey, &cfg.Summary.SupportedCountryEdition); err != nil {
		return requestCountryGeoIPConfigVersion{}, err
	}
	cfg.Present = boolFromDB(present)
	cfg.Summary.HasAccountID = boolFromDB(accountID)
	cfg.Summary.HasLicenseKey = boolFromDB(licenseKey)
	if cfg.Present {
		cfg.Raw = []byte(rawText)
		rows, err := s.query(`SELECT edition_id FROM request_country_geoip_config_editions WHERE version_id = ? ORDER BY position`, versionID)
		if err != nil {
			return requestCountryGeoIPConfigVersion{}, err
		}
		defer rows.Close()
		for rows.Next() {
			var edition string
			if err := rows.Scan(&edition); err != nil {
				return requestCountryGeoIPConfigVersion{}, err
			}
			cfg.Summary.EditionIDs = append(cfg.Summary.EditionIDs, edition)
		}
		if err := rows.Err(); err != nil {
			return requestCountryGeoIPConfigVersion{}, err
		}
	}
	return requestmeta.NormalizeGeoIPConfigVersion(cfg), nil
}

func (s *wafEventStore) writeRequestCountryGeoIPConfigVersion(expectedETag string, cfg requestCountryGeoIPConfigVersion, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, requestCountryGeoIPConfigVersion, error) {
	cfg = requestmeta.NormalizeGeoIPConfigVersion(cfg)
	rec, err := s.writeConfigVersion(
		requestCountryGeoIPConfigDomain,
		requestCountryGeoIPConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		requestmeta.GeoIPConfigHash(cfg),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			_, err := s.txExec(tx, `INSERT INTO request_country_geoip_configs (
				version_id, present, raw_text, size_bytes, has_account_id, has_license_key, supported_country_edition
			) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				versionID,
				boolToDB(cfg.Present),
				string(cfg.Raw),
				cfg.SizeBytes,
				boolToDB(cfg.Summary.HasAccountID),
				boolToDB(cfg.Summary.HasLicenseKey),
				cfg.Summary.SupportedCountryEdition,
			)
			if err != nil {
				return err
			}
			for idx, edition := range cfg.Summary.EditionIDs {
				if _, err := s.txExec(tx, `INSERT INTO request_country_geoip_config_editions (version_id, position, edition_id) VALUES (?, ?, ?)`, versionID, idx, edition); err != nil {
					return err
				}
			}
			return nil
		},
	)
	if err != nil {
		return configVersionRecord{}, requestCountryGeoIPConfigVersion{}, err
	}
	cfg.ETag = rec.ETag
	return rec, cfg, nil
}

func (s *wafEventStore) loadRequestCountryUpdateState() (requestCountryUpdateState, bool, error) {
	if s == nil || s.db == nil {
		return requestCountryUpdateState{}, false, nil
	}
	row := s.queryRow(`SELECT last_attempt, last_success, last_result, last_error FROM request_country_update_state WHERE state_key = ?`, requestCountryUpdateStateDefaultStateKey)
	var state requestCountryUpdateState
	if err := row.Scan(&state.LastAttempt, &state.LastSuccess, &state.LastResult, &state.LastError); err != nil {
		if err == sql.ErrNoRows {
			return requestCountryUpdateState{}, false, nil
		}
		return requestCountryUpdateState{}, false, err
	}
	return requestmeta.NormalizeUpdateState(state), true, nil
}

func (s *wafEventStore) upsertRequestCountryUpdateStateStmt() string {
	if s != nil && s.dbDriver == logStatsDBDriverMySQL {
		return `INSERT INTO request_country_update_state (
			state_key, last_attempt, last_success, last_result, last_error, updated_at_unix, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			last_attempt = VALUES(last_attempt),
			last_success = VALUES(last_success),
			last_result = VALUES(last_result),
			last_error = VALUES(last_error),
			updated_at_unix = VALUES(updated_at_unix),
			updated_at = VALUES(updated_at)`
	}
	return `INSERT INTO request_country_update_state (
		state_key, last_attempt, last_success, last_result, last_error, updated_at_unix, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(state_key) DO UPDATE SET
		last_attempt = excluded.last_attempt,
		last_success = excluded.last_success,
		last_result = excluded.last_result,
		last_error = excluded.last_error,
		updated_at_unix = excluded.updated_at_unix,
		updated_at = excluded.updated_at`
}

func (s *wafEventStore) upsertRequestCountryUpdateState(state requestCountryUpdateState, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	state = requestmeta.NormalizeUpdateState(state)
	ts := now.UTC()
	_, err := s.exec(
		s.upsertRequestCountryUpdateStateStmt(),
		requestCountryUpdateStateDefaultStateKey,
		state.LastAttempt,
		state.LastSuccess,
		state.LastResult,
		state.LastError,
		ts.Unix(),
		ts.Format(time.RFC3339Nano),
	)
	return err
}

func managedRequestCountryMMDBPath() string {
	return requestCountryMMDBStorageLabel
}

func InitRequestCountryRuntime() error {
	return reloadRequestCountryRuntime(config.RequestCountryMode)
}

func currentRequestCountryMMDBStorageLabel() string {
	return requestCountryMMDBStorageLabel
}

func newRequestMetadataResolvers() []requestmeta.Resolver {
	return requestmeta.NewDefaultResolvers(func() string {
		return config.RequestCountryMode
	}, lookupRequestCountryMMDB)
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
	state.Close()
	return nil
}

func RequestCountryRuntimeStatusSnapshot() requestCountryRuntimeStatus {
	return requestmeta.CountryRuntimeStatusSnapshot(config.RequestCountryMode, currentRequestCountryMMDBStorageLabel())
}

func GetRequestCountryDBStatus(c *gin.Context) {
	c.JSON(http.StatusOK, buildRequestCountryDBStatus())
}

func PutRequestCountryMode(c *gin.Context) {
	var in putRequestCountryModeBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}

	raw, etag, current, err := loadSettingsAppConfig()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	if ifMatch != etag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": etag})
		return
	}

	current.RequestMeta.Country.Mode = strings.ToLower(strings.TrimSpace(in.Mode))
	normalized, err := config.NormalizeAndValidateAppConfigFile(current)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	if err := ValidateRequestCountryRuntimeConfig(normalized); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	nextRaw, err := marshalAppConfigBlob(normalized)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	nextETag := etag
	if nextRaw != raw {
		persistedETag, err := persistSettingsAppConfig(normalized, etag)
		if err != nil {
			if errors.Is(err, errConfigVersionConflict) {
				c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": etag})
				return
			}
			if respondIfConfigDBStoreRequired(c, err) {
				return
			}
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
			return
		}
		nextETag = persistedETag
	}
	c.JSON(http.StatusOK, buildRequestCountryDBStatusWithETag(nextETag))
}

func UploadRequestCountryDB(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart form field 'file' is required"})
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	defer src.Close()

	if err := replaceManagedCountryMMDB(src); err != nil {
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, buildRequestCountryDBStatus())
}

func DeleteRequestCountryDB(c *gin.Context) {
	if strings.EqualFold(currentConfiguredRequestCountryMode(), "mmdb") {
		c.JSON(http.StatusConflict, gin.H{
			"error": "country db removal requires request_metadata.country.mode=header",
		})
		return
	}
	if err := removeManagedCountryMMDB(); err != nil {
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, buildRequestCountryDBStatus())
}

func RunManagedRequestCountryUpdateNow(ctx context.Context) error {
	return requestCountryUpdateNowFunc(ctx)
}

func GetRequestCountryUpdateStatus(c *gin.Context) {
	c.JSON(http.StatusOK, buildRequestCountryUpdateStatus())
}

func UploadRequestCountryUpdateConfig(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart form field 'file' is required"})
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	defer src.Close()
	if err := writeManagedRequestCountryGeoIPConfig(src); err != nil {
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, buildRequestCountryUpdateStatus())
}

func DeleteRequestCountryUpdateConfig(c *gin.Context) {
	if err := removeManagedRequestCountryGeoIPConfig(); err != nil {
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, buildRequestCountryUpdateStatus())
}

func RunRequestCountryUpdateNow(c *gin.Context) {
	if err := requestCountryUpdateNowFunc(context.Background()); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error":  err.Error(),
			"status": buildRequestCountryUpdateStatus(),
		})
		return
	}
	c.JSON(http.StatusOK, buildRequestCountryUpdateStatus())
}

func buildRequestCountryDBStatus() requestCountryDBStatusResponse {
	return buildRequestCountryDBStatusWithETag("")
}

func buildRequestCountryDBStatusWithETag(etag string) requestCountryDBStatusResponse {
	runtime := RequestCountryRuntimeStatusSnapshot()
	configETag := etag
	if configETag == "" {
		if _, currentETag, _, err := loadSettingsAppConfig(); err == nil {
			configETag = currentETag
		}
	}
	configuredMode := currentConfiguredRequestCountryMode()
	store := getLogsStatsStore()
	if store == nil {
		return requestmeta.BuildCountryDBStatus(runtime, configuredMode, configETag, errConfigDBStoreRequired.Error(), requestmeta.CountryDBAssetStatus{})
	}
	asset, rec, found, err := store.loadActiveRequestCountryMMDBAsset()
	if err != nil {
		return requestmeta.BuildCountryDBStatus(runtime, configuredMode, configETag, err.Error(), requestmeta.CountryDBAssetStatus{})
	}
	assetStatus := requestmeta.CountryDBAssetStatus{}
	if found && asset.Present {
		assetStatus.Installed = true
		assetStatus.SizeBytes = asset.SizeBytes
		assetStatus.ModTime = rec.ActivatedAt
	}
	return requestmeta.BuildCountryDBStatus(runtime, configuredMode, configETag, "", assetStatus)
}

func currentConfiguredRequestCountryMode() string {
	cfg, err := loadSettingsAppConfigOnly()
	if err == nil {
		mode := strings.ToLower(strings.TrimSpace(cfg.RequestMeta.Country.Mode))
		if mode == "" {
			return "header"
		}
		return mode
	}
	mode := strings.ToLower(strings.TrimSpace(config.RequestCountryMode))
	if mode == "" {
		return "header"
	}
	return mode
}

func replaceManagedCountryMMDB(src io.Reader) error {
	raw, err := requestmeta.ReadMMDBUpload(src)
	if err != nil {
		return err
	}
	return replaceManagedCountryMMDBRaw(raw, configVersionSourceApply, "request country mmdb upload")
}

func replaceManagedCountryMMDBRaw(raw []byte, source string, reason string) error {
	if err := requestmeta.ValidateMMDB(raw); err != nil {
		return err
	}
	store, err := requireConfigDBStore()
	if err != nil {
		return err
	}
	if _, _, err := store.writeRequestCountryMMDBAssetVersion("", requestCountryMMDBAssetVersion{
		Present: true,
		Raw:     raw,
	}, source, "", reason, 0); err != nil {
		return err
	}
	if strings.EqualFold(RequestCountryRuntimeStatusSnapshot().EffectiveMode, "mmdb") {
		if err := reloadRequestCountryRuntime("mmdb"); err != nil {
			return err
		}
	}
	return nil
}

func removeManagedCountryMMDB() error {
	store, err := requireConfigDBStore()
	if err != nil {
		return err
	}
	_, _, err = store.writeRequestCountryMMDBAssetVersion("", requestCountryMMDBAssetVersion{Present: false}, configVersionSourceApply, "", "request country mmdb removal", 0)
	return err
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

func buildRequestCountryUpdateStatus() requestCountryUpdateStatusResponse {
	updaterPath, updaterErr := requestmeta.ResolveGeoIPUpdateBinary()
	state, stateFound, stateErr := readRequestCountryUpdateState()
	store := getLogsStatsStore()
	if store == nil {
		return requestmeta.BuildUpdateStatus(currentRequestCountryGeoIPConfigStorageLabel(), updaterPath, updaterErr, state, stateFound, stateErr, requestmeta.UpdateConfigStatus{}, nil, errConfigDBStoreRequired.Error())
	}
	cfg, rec, found, err := store.loadActiveRequestCountryGeoIPConfig()
	if err != nil {
		return requestmeta.BuildUpdateStatus(currentRequestCountryGeoIPConfigStorageLabel(), updaterPath, updaterErr, state, stateFound, stateErr, requestmeta.UpdateConfigStatus{}, err, "")
	}
	if !found || !cfg.Present {
		return requestmeta.BuildUpdateStatus(currentRequestCountryGeoIPConfigStorageLabel(), updaterPath, updaterErr, state, stateFound, stateErr, requestmeta.UpdateConfigStatus{}, nil, "")
	}
	return requestmeta.BuildUpdateStatus(currentRequestCountryGeoIPConfigStorageLabel(), updaterPath, updaterErr, state, stateFound, stateErr, requestmeta.UpdateConfigStatus{
		Installed: true,
		SizeBytes: cfg.SizeBytes,
		ModTime:   rec.ActivatedAt,
		Summary:   cfg.Summary,
	}, nil, "")
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
	raw, summary, err := requestmeta.ReadGeoIPConfigUpload(src)
	if err != nil {
		return err
	}
	return writeManagedRequestCountryGeoIPConfigRaw(raw, summary, configVersionSourceApply, "request country GeoIP config upload")
}

func writeManagedRequestCountryGeoIPConfigRaw(raw []byte, summary requestCountryGeoIPConfigSummary, source string, reason string) error {
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

func defaultRunRequestCountryDBUpdateNow(ctx context.Context) error {
	service := requestmeta.UpdateService{
		ResolveUpdater: requestmeta.ResolveGeoIPUpdateBinary,
		RunUpdater:     requestCountryUpdateRun,
		ReadConfig:     readManagedRequestCountryGeoIPConfig,
		MakeTempDir:    runtimefiles.MakeTempDir,
		ReplaceMMDB: func(payload []byte) error {
			return replaceManagedCountryMMDBRaw(payload, configVersionSourceApply, "request country mmdb update")
		},
		PersistState: persistRequestCountryUpdateState,
	}
	return service.RunNow(ctx)
}

func lookupRequestCountryMMDB(clientIP string) (string, bool, error) {
	return requestmeta.LookupCountryMMDB(clientIP)
}

func loadManagedRequestCountryMMDB() (loadedRequestCountryMMDBState, error) {
	store, err := requireConfigDBStore()
	if err != nil {
		return loadedRequestCountryMMDBState{}, err
	}
	return loadManagedRequestCountryMMDBFromDB(store)
}

func loadManagedRequestCountryMMDBFromDB(store *wafEventStore) (loadedRequestCountryMMDBState, error) {
	asset, rec, found, err := store.loadActiveRequestCountryMMDBAsset()
	if err != nil {
		return loadedRequestCountryMMDBState{}, fmt.Errorf("open managed country mmdb (%s): %w", requestCountryMMDBStorageLabel, err)
	}
	if !found || !asset.Present {
		return loadedRequestCountryMMDBState{}, fmt.Errorf("open managed country mmdb (%s): not found", requestCountryMMDBStorageLabel)
	}
	reader, err := maxminddb.FromBytes(asset.Raw)
	if err != nil {
		return loadedRequestCountryMMDBState{}, fmt.Errorf("open managed country mmdb (%s): %w", requestCountryMMDBStorageLabel, err)
	}
	return loadedRequestCountryMMDBState{
		Reader:      reader,
		ManagedPath: requestCountryMMDBStorageLabel,
		VersionID:   rec.VersionID,
		VersionETag: rec.ETag,
		SizeBytes:   asset.SizeBytes,
		ModTime:     rec.ActivatedAt.UTC(),
	}, nil
}

func activeRequestCountryMMDBVersion() (requestmeta.MMDBVersion, bool, error) {
	store := getLogsStatsStore()
	if store == nil {
		return requestmeta.MMDBVersion{}, false, errConfigDBStoreRequired
	}
	_, rec, found, err := store.loadActiveRequestCountryMMDBAsset()
	if err != nil || !found {
		return requestmeta.MMDBVersion{}, found, err
	}
	return requestmeta.MMDBVersion{
		VersionID: rec.VersionID,
		ETag:      rec.ETag,
	}, true, nil
}

func reloadRequestCountryRuntime(mode string) error {
	return requestmeta.InitCountryRuntime(requestmeta.CountryRuntimeOptions{
		Mode:                  mode,
		ManagedPath:           currentRequestCountryMMDBStorageLabel(),
		Loader:                requestCountryMMDBLoader,
		VersionProbe:          activeRequestCountryMMDBVersion,
		StoreUnavailableError: errConfigDBStoreRequired.Error(),
		RefreshInterval:       requestCountryRefreshInterval,
	})
}
