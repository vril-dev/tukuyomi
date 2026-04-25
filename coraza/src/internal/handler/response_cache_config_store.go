package handler

import (
	"database/sql"
	"fmt"
	"strings"

	"tukuyomi/internal/bypassconf"
)

const responseCacheConfigSchemaVersion = 1

func (s *wafEventStore) loadActiveResponseCacheConfig() (responseCacheConfig, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(responseCacheConfigBlobKey)
	if err != nil || !found {
		return responseCacheConfig{}, configVersionRecord{}, false, err
	}
	cfg, err := s.loadResponseCacheConfigVersion(rec.VersionID)
	if err != nil {
		return responseCacheConfig{}, configVersionRecord{}, false, err
	}
	return cfg, rec, true, nil
}

func (s *wafEventStore) writeResponseCacheConfigVersion(expectedETag string, cfg responseCacheConfig, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, responseCacheConfig, error) {
	cfg = normalizeResponseCacheConfig(cfg)
	if err := validateResponseCacheConfig(cfg); err != nil {
		return configVersionRecord{}, responseCacheConfig{}, err
	}
	raw, err := marshalResponseCacheConfig(cfg)
	if err != nil {
		return configVersionRecord{}, responseCacheConfig{}, err
	}
	rec, err := s.writeConfigVersion(
		responseCacheConfigBlobKey,
		responseCacheConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		configContentHash(string(raw)),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			_, err := s.txExec(tx, `INSERT INTO response_cache_config (version_id, enabled, store_dir, max_bytes, memory_enabled, memory_max_bytes, memory_max_entries) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				versionID, boolToDB(cfg.Enabled), cfg.StoreDir, cfg.MaxBytes, boolToDB(cfg.MemoryEnabled), cfg.MemoryMaxBytes, cfg.MemoryMaxEntries)
			return err
		},
	)
	if err != nil {
		return configVersionRecord{}, responseCacheConfig{}, err
	}
	return rec, cfg, nil
}

func (s *wafEventStore) loadResponseCacheConfigVersion(versionID int64) (responseCacheConfig, error) {
	var cfg responseCacheConfig
	var enabled, memoryEnabled int
	if err := s.queryRow(`SELECT enabled, store_dir, max_bytes, memory_enabled, memory_max_bytes, memory_max_entries FROM response_cache_config WHERE version_id = ?`, versionID).
		Scan(&enabled, &cfg.StoreDir, &cfg.MaxBytes, &memoryEnabled, &cfg.MemoryMaxBytes, &cfg.MemoryMaxEntries); err != nil {
		return responseCacheConfig{}, err
	}
	cfg.Enabled = boolFromDB(enabled)
	cfg.MemoryEnabled = boolFromDB(memoryEnabled)
	return normalizeResponseCacheConfig(cfg), nil
}

func loadRuntimeResponseCacheConfig(store *wafEventStore) ([]byte, configVersionRecord, bool, error) {
	cfg, rec, found, err := store.loadActiveResponseCacheConfig()
	if err != nil || found {
		if err != nil {
			return nil, configVersionRecord{}, false, err
		}
		raw, marshalErr := marshalResponseCacheConfig(cfg)
		return raw, rec, true, marshalErr
	}
	if legacyRaw, _, legacyFound, legacyErr := store.GetConfigBlob(responseCacheConfigBlobKey); legacyErr != nil {
		return nil, configVersionRecord{}, false, legacyErr
	} else if legacyFound {
		prepared, prepareErr := prepareResponseCacheRaw(string(legacyRaw))
		if prepareErr != nil {
			return nil, configVersionRecord{}, false, prepareErr
		}
		rec, _, err := store.writeResponseCacheConfigVersion("", prepared.cfg, configVersionSourceImport, "", "legacy response cache config import", 0)
		if err != nil {
			return nil, configVersionRecord{}, false, err
		}
		_ = store.DeleteConfigBlob(responseCacheConfigBlobKey)
		return []byte(prepared.raw), rec, true, nil
	}
	return nil, configVersionRecord{}, false, nil
}

func loadOrSeedResponseCacheConfig(store *wafEventStore, path string) ([]byte, configVersionRecord, bool, error) {
	raw, rec, found, err := loadRuntimeResponseCacheConfig(store)
	if err != nil || found {
		return raw, rec, found, err
	}

	prepared, err := defaultPreparedResponseCacheConfig()
	if err != nil {
		return nil, configVersionRecord{}, false, fmt.Errorf("prepare response cache seed: %w", err)
	}
	rec, _, err = store.writeResponseCacheConfigVersion("", prepared.cfg, configVersionSourceImport, "", "response cache config seed import", 0)
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	return []byte(prepared.raw), rec, true, nil
}

func responseCacheExpectedETag(ifMatch string, currentRaw string, currentETag string) string {
	ifMatch = strings.TrimSpace(ifMatch)
	if ifMatch == "" || ifMatch == currentETag {
		return ifMatch
	}
	if currentRaw != "" && ifMatch == bypassconf.ComputeETag([]byte(currentRaw)) {
		return currentETag
	}
	return ifMatch
}

func defaultPreparedResponseCacheConfig() (preparedResponseCacheConfig, error) {
	raw, err := marshalResponseCacheConfig(normalizeResponseCacheConfig(responseCacheConfig{}))
	if err != nil {
		return preparedResponseCacheConfig{}, err
	}
	return prepareResponseCacheRaw(string(raw))
}
