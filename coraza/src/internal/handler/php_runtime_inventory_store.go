package handler

import (
	"database/sql"
	"errors"
	"strings"
)

const (
	phpRuntimeInventoryConfigDomain        = "php_runtime_inventory"
	phpRuntimeInventoryConfigSchemaVersion = 1
)

func phpRuntimeInventoryPreparedHash(prepared phpRuntimeInventoryPreparedConfig) string {
	return configContentHash(strings.TrimSpace(prepared.raw) + "\n" + mustJSON(normalizePHPRuntimeInventoryFile(prepared.cfg)))
}

func (s *wafEventStore) writePHPRuntimeInventoryConfigVersion(expectedETag string, cfg PHPRuntimeInventoryFile, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, error) {
	normalized := normalizePHPRuntimeInventoryFile(cfg)
	state := phpRuntimeInventoryStateFromConfig(normalized)
	prepared := phpRuntimeInventoryPreparedConfig{
		state: state,
		cfg:   normalized,
		raw:   marshalPHPRuntimeInventoryStateRaw(state),
	}
	return s.writePHPRuntimeInventoryPreparedConfigVersion(expectedETag, prepared, source, actor, reason, restoredFromVersionID)
}

func (s *wafEventStore) writePHPRuntimeInventoryPreparedConfigVersion(expectedETag string, prepared phpRuntimeInventoryPreparedConfig, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, error) {
	normalized := normalizePHPRuntimeInventoryFile(prepared.cfg)
	prepared.cfg = normalized
	if strings.TrimSpace(prepared.raw) == "" {
		prepared.raw = marshalPHPRuntimeInventoryStateRaw(prepared.state)
	}
	return s.writeConfigVersion(
		phpRuntimeInventoryConfigDomain,
		phpRuntimeInventoryConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		phpRuntimeInventoryPreparedHash(prepared),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			if err := s.insertPHPRuntimeInventoryStateTx(tx, versionID, prepared.state, prepared.raw); err != nil {
				return err
			}
			return s.insertPHPRuntimeInventoryRowsTx(tx, versionID, normalized)
		},
	)
}

func (s *wafEventStore) loadActivePHPRuntimeInventoryPreparedConfig(inventoryPath string) (phpRuntimeInventoryPreparedConfig, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(phpRuntimeInventoryConfigDomain)
	if err != nil || !found {
		return phpRuntimeInventoryPreparedConfig{}, configVersionRecord{}, false, err
	}
	cfg, err := s.loadPHPRuntimeInventoryConfigVersion(rec.VersionID)
	if err != nil {
		return phpRuntimeInventoryPreparedConfig{}, configVersionRecord{}, false, err
	}
	state, raw, err := s.loadPHPRuntimeInventoryStateVersion(rec.VersionID, normalizePHPRuntimeInventoryFile(cfg), rec)
	if err != nil {
		return phpRuntimeInventoryPreparedConfig{}, configVersionRecord{}, false, err
	}
	prepared, err := preparePHPRuntimeInventoryState(state, inventoryPath)
	if err != nil {
		return phpRuntimeInventoryPreparedConfig{}, configVersionRecord{}, false, err
	}
	if strings.TrimSpace(raw) != "" {
		prepared.raw = raw
	}
	return prepared, rec, true, nil
}

func (s *wafEventStore) insertPHPRuntimeInventoryStateTx(tx *sql.Tx, versionID int64, state phpRuntimeInventoryStateFile, raw string) error {
	autoDiscover := 0
	if !state.explicitRuntimes {
		autoDiscover = 1
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = marshalPHPRuntimeInventoryStateRaw(state)
	}
	_, err := s.txExec(tx, `INSERT INTO php_runtime_inventory_state (version_id, auto_discover, raw_text) VALUES (?, ?, ?)`, versionID, autoDiscover, raw)
	return err
}

func (s *wafEventStore) loadPHPRuntimeInventoryStateVersion(versionID int64, cfg PHPRuntimeInventoryFile, rec configVersionRecord) (phpRuntimeInventoryStateFile, string, error) {
	var autoDiscover int
	var raw string
	err := s.queryRow(`SELECT auto_discover, raw_text FROM php_runtime_inventory_state WHERE version_id = ?`, versionID).Scan(&autoDiscover, &raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			state := phpRuntimeInventoryStateFromConfig(cfg)
			if len(cfg.Runtimes) == 0 && rec.Source == configVersionSourceImport {
				state = phpRuntimeInventoryStateFile{}
			}
			return state, marshalPHPRuntimeInventoryStateRaw(state), nil
		}
		return phpRuntimeInventoryStateFile{}, "", err
	}
	if autoDiscover != 0 {
		state := phpRuntimeInventoryStateFile{}
		return state, marshalPHPRuntimeInventoryStateRaw(state), nil
	}
	state, err := parsePHPRuntimeInventoryRaw(raw)
	if err != nil || !state.explicitRuntimes {
		state = phpRuntimeInventoryStateFromConfig(cfg)
		raw = marshalPHPRuntimeInventoryStateRaw(state)
	}
	return state, raw, nil
}

func (s *wafEventStore) insertPHPRuntimeInventoryRowsTx(tx *sql.Tx, versionID int64, cfg PHPRuntimeInventoryFile) error {
	for i, runtime := range cfg.Runtimes {
		if _, err := s.txExec(
			tx,
			`INSERT INTO php_runtime_inventory (version_id, position, runtime_id, display_name, detected_version, binary_path, cli_binary_path, available, availability_message, run_user, run_group, source, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			versionID,
			i,
			runtime.RuntimeID,
			runtime.DisplayName,
			runtime.DetectedVersion,
			runtime.BinaryPath,
			runtime.CLIBinaryPath,
			boolToDB(runtime.Available),
			runtime.AvailabilityMessage,
			runtime.RunUser,
			runtime.RunGroup,
			runtime.Source,
			runtime.SHA256,
		); err != nil {
			return err
		}
		for j, module := range runtime.Modules {
			if _, err := s.txExec(tx, `INSERT INTO php_runtime_modules (version_id, runtime_position, position, module) VALUES (?, ?, ?, ?)`, versionID, i, j, module); err != nil {
				return err
			}
		}
		for j, module := range runtime.DefaultDisabledModules {
			if _, err := s.txExec(tx, `INSERT INTO php_runtime_default_disabled_modules (version_id, runtime_position, position, module) VALUES (?, ?, ?, ?)`, versionID, i, j, module); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *wafEventStore) loadPHPRuntimeInventoryConfigVersion(versionID int64) (PHPRuntimeInventoryFile, error) {
	rows, err := s.query(
		`SELECT position, runtime_id, display_name, detected_version, binary_path, cli_binary_path, available, availability_message, run_user, run_group, source, sha256
		   FROM php_runtime_inventory
		  WHERE version_id = ?
		  ORDER BY position`,
		versionID,
	)
	if err != nil {
		return PHPRuntimeInventoryFile{}, err
	}
	type runtimeRow struct {
		position int
		runtime  PHPRuntimeRecord
	}
	scanned := make([]runtimeRow, 0)
	for rows.Next() {
		var item runtimeRow
		var available int
		if err := rows.Scan(
			&item.position,
			&item.runtime.RuntimeID,
			&item.runtime.DisplayName,
			&item.runtime.DetectedVersion,
			&item.runtime.BinaryPath,
			&item.runtime.CLIBinaryPath,
			&available,
			&item.runtime.AvailabilityMessage,
			&item.runtime.RunUser,
			&item.runtime.RunGroup,
			&item.runtime.Source,
			&item.runtime.SHA256,
		); err != nil {
			_ = rows.Close()
			return PHPRuntimeInventoryFile{}, err
		}
		item.runtime.Available = available != 0
		scanned = append(scanned, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return PHPRuntimeInventoryFile{}, err
	}
	if err := rows.Close(); err != nil {
		return PHPRuntimeInventoryFile{}, err
	}

	out := PHPRuntimeInventoryFile{Runtimes: make([]PHPRuntimeRecord, 0, len(scanned))}
	for _, item := range scanned {
		modules, err := s.loadPHPRuntimeInventoryModules(versionID, item.position, `php_runtime_modules`)
		if err != nil {
			return PHPRuntimeInventoryFile{}, err
		}
		disabled, err := s.loadPHPRuntimeInventoryModules(versionID, item.position, `php_runtime_default_disabled_modules`)
		if err != nil {
			return PHPRuntimeInventoryFile{}, err
		}
		item.runtime.Modules = modules
		item.runtime.DefaultDisabledModules = disabled
		out.Runtimes = append(out.Runtimes, item.runtime)
	}
	return out, nil
}

func (s *wafEventStore) loadPHPRuntimeInventoryModules(versionID int64, runtimePosition int, table string) ([]string, error) {
	switch table {
	case `php_runtime_modules`, `php_runtime_default_disabled_modules`:
	default:
		return nil, errors.New("invalid php runtime module table")
	}
	rows, err := s.query(`SELECT module FROM `+table+` WHERE version_id = ? AND runtime_position = ? ORDER BY position`, versionID, runtimePosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var module string
		if err := rows.Scan(&module); err != nil {
			return nil, err
		}
		out = append(out, module)
	}
	return out, rows.Err()
}
