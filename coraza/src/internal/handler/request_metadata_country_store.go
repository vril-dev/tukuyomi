package handler

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"
)

const (
	requestCountryMMDBConfigDomain           = "request_country_mmdb_asset"
	requestCountryMMDBConfigSchemaVersion    = 1
	requestCountryMMDBStorageLabel           = "db:" + requestCountryMMDBConfigDomain
	requestCountryGeoIPConfigDomain          = "request_country_geoip_config"
	requestCountryGeoIPConfigSchemaVersion   = 1
	requestCountryGeoIPConfigStorageLabel    = "db:" + requestCountryGeoIPConfigDomain
	requestCountryUpdateStateTable           = "request_country_update_state"
	requestCountryUpdateStateStorageLabel    = "db:" + requestCountryUpdateStateTable
	requestCountryUpdateStateDefaultStateKey = "default"
)

type requestCountryMMDBAssetVersion struct {
	Present     bool
	Raw         []byte
	SizeBytes   int64
	ContentHash string
	ETag        string
}

type requestCountryGeoIPConfigVersion struct {
	Present   bool
	Raw       []byte
	Summary   requestCountryGeoIPConfigSummary
	SizeBytes int64
	ETag      string
}

func normalizeRequestCountryMMDBAssetVersion(asset requestCountryMMDBAssetVersion) requestCountryMMDBAssetVersion {
	asset.Raw = append([]byte(nil), asset.Raw...)
	if !asset.Present {
		asset.Raw = nil
		asset.SizeBytes = 0
		asset.ContentHash = ""
		return asset
	}
	asset.SizeBytes = int64(len(asset.Raw))
	asset.ContentHash = sha256HexBytes(asset.Raw)
	return asset
}

func normalizeRequestCountryGeoIPConfigVersion(cfg requestCountryGeoIPConfigVersion) requestCountryGeoIPConfigVersion {
	cfg.Raw = append([]byte(nil), cfg.Raw...)
	if !cfg.Present {
		cfg.Raw = nil
		cfg.SizeBytes = 0
		cfg.Summary = requestCountryGeoIPConfigSummary{}
		return cfg
	}
	cfg.SizeBytes = int64(len(cfg.Raw))
	cfg.Summary.EditionIDs = append([]string(nil), cfg.Summary.EditionIDs...)
	return cfg
}

func requestCountryMMDBAssetHash(asset requestCountryMMDBAssetVersion) string {
	asset = normalizeRequestCountryMMDBAssetVersion(asset)
	sum := sha256.New()
	if asset.Present {
		_, _ = sum.Write([]byte("present:1\n"))
		_, _ = sum.Write(asset.Raw)
	} else {
		_, _ = sum.Write([]byte("present:0\n"))
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func requestCountryGeoIPConfigHash(cfg requestCountryGeoIPConfigVersion) string {
	cfg = normalizeRequestCountryGeoIPConfigVersion(cfg)
	sum := sha256.New()
	if cfg.Present {
		_, _ = sum.Write([]byte("present:1\n"))
		_, _ = sum.Write(cfg.Raw)
	} else {
		_, _ = sum.Write([]byte("present:0\n"))
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func sha256HexBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

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
	return normalizeRequestCountryMMDBAssetVersion(asset), nil
}

func (s *wafEventStore) writeRequestCountryMMDBAssetVersion(expectedETag string, asset requestCountryMMDBAssetVersion, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, requestCountryMMDBAssetVersion, error) {
	asset = normalizeRequestCountryMMDBAssetVersion(asset)
	rec, err := s.writeConfigVersion(
		requestCountryMMDBConfigDomain,
		requestCountryMMDBConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		requestCountryMMDBAssetHash(asset),
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
	return normalizeRequestCountryGeoIPConfigVersion(cfg), nil
}

func (s *wafEventStore) writeRequestCountryGeoIPConfigVersion(expectedETag string, cfg requestCountryGeoIPConfigVersion, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, requestCountryGeoIPConfigVersion, error) {
	cfg = normalizeRequestCountryGeoIPConfigVersion(cfg)
	rec, err := s.writeConfigVersion(
		requestCountryGeoIPConfigDomain,
		requestCountryGeoIPConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		requestCountryGeoIPConfigHash(cfg),
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

func normalizeRequestCountryUpdateState(state requestCountryUpdateState) requestCountryUpdateState {
	state.LastAttempt = strings.TrimSpace(state.LastAttempt)
	state.LastSuccess = strings.TrimSpace(state.LastSuccess)
	state.LastResult = strings.TrimSpace(state.LastResult)
	state.LastError = strings.TrimSpace(state.LastError)
	return state
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
	return normalizeRequestCountryUpdateState(state), true, nil
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
	state = normalizeRequestCountryUpdateState(state)
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
