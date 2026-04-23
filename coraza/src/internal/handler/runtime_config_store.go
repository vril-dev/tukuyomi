package handler

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
)

const (
	siteConfigDomain                   = "sites"
	siteConfigSchemaVersion            = 1
	vhostConfigDomain                  = "vhosts"
	vhostConfigSchemaVersion           = 1
	scheduledTaskConfigDomain          = "scheduled_tasks"
	scheduledTaskConfigSchemaVersion   = 1
	upstreamRuntimeConfigDomain        = "upstream_runtime"
	upstreamRuntimeConfigSchemaVersion = 1

	vhostBasicAuthScopeVhost      = "vhost"
	vhostBasicAuthScopeAccessRule = "access_rule"
)

func storageKeyHash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func siteConfigHash(cfg SiteConfigFile) string {
	return configContentHash(mustJSON(normalizeSiteConfigFile(cfg)))
}

func (s *wafEventStore) loadActiveSiteConfig() (SiteConfigFile, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(siteConfigDomain)
	if err != nil || !found {
		return SiteConfigFile{}, configVersionRecord{}, false, err
	}
	cfg, err := s.loadSiteConfigVersion(rec.VersionID)
	if err != nil {
		return SiteConfigFile{}, configVersionRecord{}, false, err
	}
	return normalizeSiteConfigFile(cfg), rec, true, nil
}

func (s *wafEventStore) writeSiteConfigVersion(expectedETag string, cfg SiteConfigFile, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, error) {
	normalized := normalizeSiteConfigFile(cfg)
	return s.writeConfigVersion(
		siteConfigDomain,
		siteConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		siteConfigHash(normalized),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			return s.insertSiteConfigRowsTx(tx, versionID, normalized)
		},
	)
}

func (s *wafEventStore) insertSiteConfigRowsTx(tx *sql.Tx, versionID int64, cfg SiteConfigFile) error {
	for i, site := range cfg.Sites {
		enabledSet, enabled := boolPtrToDB(site.Enabled)
		if _, err := s.txExec(tx, `INSERT INTO sites (version_id, position, name, enabled_set, enabled, default_upstream) VALUES (?, ?, ?, ?, ?, ?)`, versionID, i, site.Name, enabledSet, enabled, site.DefaultUpstream); err != nil {
			return err
		}
		for j, host := range site.Hosts {
			if _, err := s.txExec(tx, `INSERT INTO site_hosts (version_id, site_position, position, host) VALUES (?, ?, ?, ?)`, versionID, i, j, host); err != nil {
				return err
			}
		}
		if _, err := s.txExec(tx, `INSERT INTO site_tls (version_id, site_position, mode, cert_file, key_file) VALUES (?, ?, ?, ?, ?)`, versionID, i, site.TLS.Mode, site.TLS.CertFile, site.TLS.KeyFile); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) loadSiteConfigVersion(versionID int64) (SiteConfigFile, error) {
	rows, err := s.query(`SELECT position, name, enabled_set, enabled, default_upstream FROM sites WHERE version_id = ? ORDER BY position`, versionID)
	if err != nil {
		return SiteConfigFile{}, err
	}
	type siteRow struct {
		position int
		site     SiteConfig
	}
	var scanned []siteRow
	for rows.Next() {
		var position, enabledSet, enabled int
		var site SiteConfig
		if err := rows.Scan(&position, &site.Name, &enabledSet, &enabled, &site.DefaultUpstream); err != nil {
			_ = rows.Close()
			return SiteConfigFile{}, err
		}
		site.Enabled = boolPtrFromDB(enabledSet, enabled)
		scanned = append(scanned, siteRow{position: position, site: site})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return SiteConfigFile{}, err
	}
	if err := rows.Close(); err != nil {
		return SiteConfigFile{}, err
	}

	out := SiteConfigFile{Sites: make([]SiteConfig, 0, len(scanned))}
	for _, item := range scanned {
		hosts, err := s.loadSiteHosts(versionID, item.position)
		if err != nil {
			return SiteConfigFile{}, err
		}
		tlsCfg, err := s.loadSiteTLS(versionID, item.position)
		if err != nil {
			return SiteConfigFile{}, err
		}
		item.site.Hosts = hosts
		item.site.TLS = tlsCfg
		out.Sites = append(out.Sites, item.site)
	}
	return out, nil
}

func (s *wafEventStore) loadSiteHosts(versionID int64, sitePosition int) ([]string, error) {
	rows, err := s.query(`SELECT host FROM site_hosts WHERE version_id = ? AND site_position = ? ORDER BY position`, versionID, sitePosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		out = append(out, host)
	}
	return out, rows.Err()
}

func (s *wafEventStore) loadSiteTLS(versionID int64, sitePosition int) (SiteTLSConfig, error) {
	row := s.queryRow(`SELECT mode, cert_file, key_file FROM site_tls WHERE version_id = ? AND site_position = ?`, versionID, sitePosition)
	var out SiteTLSConfig
	if err := row.Scan(&out.Mode, &out.CertFile, &out.KeyFile); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SiteTLSConfig{}, nil
		}
		return SiteTLSConfig{}, err
	}
	return out, nil
}

func vhostConfigHash(cfg VhostConfigFile) string {
	return configContentHash(mustJSON(normalizeVhostConfigFile(cfg)))
}

func (s *wafEventStore) loadActiveVhostConfig() (VhostConfigFile, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(vhostConfigDomain)
	if err != nil || !found {
		return VhostConfigFile{}, configVersionRecord{}, false, err
	}
	cfg, err := s.loadVhostConfigVersion(rec.VersionID)
	if err != nil {
		return VhostConfigFile{}, configVersionRecord{}, false, err
	}
	return normalizeVhostConfigFile(cfg), rec, true, nil
}

func (s *wafEventStore) writeVhostConfigVersion(expectedETag string, cfg VhostConfigFile, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, error) {
	normalized := normalizeVhostConfigFile(cfg)
	return s.writeConfigVersion(
		vhostConfigDomain,
		vhostConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		vhostConfigHash(normalized),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			return s.insertVhostConfigRowsTx(tx, versionID, normalized)
		},
	)
}

func (s *wafEventStore) insertVhostConfigRowsTx(tx *sql.Tx, versionID int64, cfg VhostConfigFile) error {
	for i, vhost := range cfg.Vhosts {
		if _, err := s.txExec(
			tx,
			`INSERT INTO vhosts (version_id, position, name, mode, hostname, listen_port, document_root, runtime_id, generated_target, linked_upstream_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			versionID,
			i,
			vhost.Name,
			vhost.Mode,
			vhost.Hostname,
			vhost.ListenPort,
			vhost.DocumentRoot,
			vhost.RuntimeID,
			vhost.GeneratedTarget,
			vhost.LinkedUpstreamName,
		); err != nil {
			return err
		}
		for j, entry := range vhost.TryFiles {
			if _, err := s.txExec(tx, `INSERT INTO vhost_try_files (version_id, vhost_position, position, try_file) VALUES (?, ?, ?, ?)`, versionID, i, j, entry); err != nil {
				return err
			}
		}
		for j, rule := range vhost.RewriteRules {
			if _, err := s.txExec(tx, `INSERT INTO vhost_rewrite_rules (version_id, vhost_position, position, pattern, replacement, flag, preserve_query) VALUES (?, ?, ?, ?, ?, ?, ?)`, versionID, i, j, rule.Pattern, rule.Replacement, rule.Flag, boolToDB(rule.PreserveQuery)); err != nil {
				return err
			}
		}
		for j, rule := range vhost.AccessRules {
			if _, err := s.txExec(tx, `INSERT INTO vhost_access_rules (version_id, vhost_position, position, path_pattern, action) VALUES (?, ?, ?, ?, ?)`, versionID, i, j, rule.PathPattern, rule.Action); err != nil {
				return err
			}
			for k, cidr := range rule.CIDRs {
				if _, err := s.txExec(tx, `INSERT INTO vhost_access_rule_cidrs (version_id, vhost_position, access_rule_position, position, cidr) VALUES (?, ?, ?, ?, ?)`, versionID, i, j, k, cidr); err != nil {
					return err
				}
			}
			if err := s.insertVhostBasicAuthTx(tx, versionID, i, vhostBasicAuthScopeAccessRule, j, rule.BasicAuth); err != nil {
				return err
			}
		}
		if err := s.insertVhostBasicAuthTx(tx, versionID, i, vhostBasicAuthScopeVhost, -1, vhost.BasicAuth); err != nil {
			return err
		}
		if err := s.insertVhostStringMapTx(tx, `vhost_php_values`, versionID, i, vhost.PHPValues); err != nil {
			return err
		}
		if err := s.insertVhostStringMapTx(tx, `vhost_php_admin_values`, versionID, i, vhost.PHPAdminValues); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) insertVhostBasicAuthTx(tx *sql.Tx, versionID int64, vhostPosition int, scope string, accessRulePosition int, auth *VhostBasicAuth) error {
	if auth == nil {
		return nil
	}
	if _, err := s.txExec(tx, `INSERT INTO vhost_basic_auth (version_id, vhost_position, scope, access_rule_position, realm) VALUES (?, ?, ?, ?, ?)`, versionID, vhostPosition, scope, accessRulePosition, auth.Realm); err != nil {
		return err
	}
	for i, user := range auth.Users {
		if _, err := s.txExec(tx, `INSERT INTO vhost_basic_auth_users (version_id, vhost_position, scope, access_rule_position, position, username, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)`, versionID, vhostPosition, scope, accessRulePosition, i, user.Username, user.PasswordHash); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) insertVhostStringMapTx(tx *sql.Tx, table string, versionID int64, vhostPosition int, values map[string]string) error {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i, key := range keys {
		if _, err := s.txExec(tx, `INSERT INTO `+table+` (version_id, vhost_position, position, name, value) VALUES (?, ?, ?, ?, ?)`, versionID, vhostPosition, i, key, values[key]); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) loadVhostConfigVersion(versionID int64) (VhostConfigFile, error) {
	rows, err := s.query(
		`SELECT position, name, mode, hostname, listen_port, document_root, runtime_id, generated_target, linked_upstream_name
		   FROM vhosts
		  WHERE version_id = ?
		  ORDER BY position`,
		versionID,
	)
	if err != nil {
		return VhostConfigFile{}, err
	}
	type vhostRow struct {
		position int
		vhost    VhostConfig
	}
	var scanned []vhostRow
	for rows.Next() {
		var position int
		var vhost VhostConfig
		if err := rows.Scan(&position, &vhost.Name, &vhost.Mode, &vhost.Hostname, &vhost.ListenPort, &vhost.DocumentRoot, &vhost.RuntimeID, &vhost.GeneratedTarget, &vhost.LinkedUpstreamName); err != nil {
			_ = rows.Close()
			return VhostConfigFile{}, err
		}
		scanned = append(scanned, vhostRow{position: position, vhost: vhost})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return VhostConfigFile{}, err
	}
	if err := rows.Close(); err != nil {
		return VhostConfigFile{}, err
	}

	out := VhostConfigFile{Vhosts: make([]VhostConfig, 0, len(scanned))}
	for _, item := range scanned {
		vhost := item.vhost
		var err error
		if vhost.TryFiles, err = s.loadVhostStringList(versionID, `vhost_try_files`, `try_file`, item.position); err != nil {
			return VhostConfigFile{}, err
		}
		if vhost.RewriteRules, err = s.loadVhostRewriteRules(versionID, item.position); err != nil {
			return VhostConfigFile{}, err
		}
		if vhost.AccessRules, err = s.loadVhostAccessRules(versionID, item.position); err != nil {
			return VhostConfigFile{}, err
		}
		if vhost.BasicAuth, err = s.loadVhostBasicAuth(versionID, item.position, vhostBasicAuthScopeVhost, -1); err != nil {
			return VhostConfigFile{}, err
		}
		if vhost.PHPValues, err = s.loadVhostStringMap(versionID, `vhost_php_values`, item.position); err != nil {
			return VhostConfigFile{}, err
		}
		if vhost.PHPAdminValues, err = s.loadVhostStringMap(versionID, `vhost_php_admin_values`, item.position); err != nil {
			return VhostConfigFile{}, err
		}
		out.Vhosts = append(out.Vhosts, vhost)
	}
	return out, nil
}

func (s *wafEventStore) loadVhostStringList(versionID int64, table string, column string, vhostPosition int) ([]string, error) {
	rows, err := s.query(`SELECT `+column+` FROM `+table+` WHERE version_id = ? AND vhost_position = ? ORDER BY position`, versionID, vhostPosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (s *wafEventStore) loadVhostRewriteRules(versionID int64, vhostPosition int) ([]VhostRewriteRule, error) {
	rows, err := s.query(`SELECT pattern, replacement, flag, preserve_query FROM vhost_rewrite_rules WHERE version_id = ? AND vhost_position = ? ORDER BY position`, versionID, vhostPosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VhostRewriteRule
	for rows.Next() {
		var rule VhostRewriteRule
		var preserveQuery int
		if err := rows.Scan(&rule.Pattern, &rule.Replacement, &rule.Flag, &preserveQuery); err != nil {
			return nil, err
		}
		rule.PreserveQuery = boolFromDB(preserveQuery)
		out = append(out, rule)
	}
	return out, rows.Err()
}

func (s *wafEventStore) loadVhostAccessRules(versionID int64, vhostPosition int) ([]VhostAccessRule, error) {
	rows, err := s.query(`SELECT position, path_pattern, action FROM vhost_access_rules WHERE version_id = ? AND vhost_position = ? ORDER BY position`, versionID, vhostPosition)
	if err != nil {
		return nil, err
	}
	type accessRuleRow struct {
		position int
		rule     VhostAccessRule
	}
	var scanned []accessRuleRow
	for rows.Next() {
		var position int
		var rule VhostAccessRule
		if err := rows.Scan(&position, &rule.PathPattern, &rule.Action); err != nil {
			_ = rows.Close()
			return nil, err
		}
		scanned = append(scanned, accessRuleRow{position: position, rule: rule})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	out := make([]VhostAccessRule, 0, len(scanned))
	for _, item := range scanned {
		var err error
		if item.rule.CIDRs, err = s.loadVhostAccessRuleCIDRs(versionID, vhostPosition, item.position); err != nil {
			return nil, err
		}
		if item.rule.BasicAuth, err = s.loadVhostBasicAuth(versionID, vhostPosition, vhostBasicAuthScopeAccessRule, item.position); err != nil {
			return nil, err
		}
		out = append(out, item.rule)
	}
	return out, nil
}

func (s *wafEventStore) loadVhostAccessRuleCIDRs(versionID int64, vhostPosition int, accessRulePosition int) ([]string, error) {
	rows, err := s.query(`SELECT cidr FROM vhost_access_rule_cidrs WHERE version_id = ? AND vhost_position = ? AND access_rule_position = ? ORDER BY position`, versionID, vhostPosition, accessRulePosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return nil, err
		}
		out = append(out, cidr)
	}
	return out, rows.Err()
}

func (s *wafEventStore) loadVhostBasicAuth(versionID int64, vhostPosition int, scope string, accessRulePosition int) (*VhostBasicAuth, error) {
	row := s.queryRow(`SELECT realm FROM vhost_basic_auth WHERE version_id = ? AND vhost_position = ? AND scope = ? AND access_rule_position = ?`, versionID, vhostPosition, scope, accessRulePosition)
	var out VhostBasicAuth
	if err := row.Scan(&out.Realm); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	rows, err := s.query(`SELECT username, password_hash FROM vhost_basic_auth_users WHERE version_id = ? AND vhost_position = ? AND scope = ? AND access_rule_position = ? ORDER BY position`, versionID, vhostPosition, scope, accessRulePosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var user VhostBasicAuthUser
		if err := rows.Scan(&user.Username, &user.PasswordHash); err != nil {
			return nil, err
		}
		out.Users = append(out.Users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *wafEventStore) loadVhostStringMap(versionID int64, table string, vhostPosition int) (map[string]string, error) {
	rows, err := s.query(`SELECT name, value FROM `+table+` WHERE version_id = ? AND vhost_position = ? ORDER BY position`, versionID, vhostPosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		out[name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func scheduledTaskConfigHash(cfg ScheduledTaskConfigFile) string {
	return configContentHash(mustJSON(cfg))
}

func (s *wafEventStore) loadActiveScheduledTaskConfig() (ScheduledTaskConfigFile, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(scheduledTaskConfigDomain)
	if err != nil || !found {
		return ScheduledTaskConfigFile{}, configVersionRecord{}, false, err
	}
	cfg, err := s.loadScheduledTaskConfigVersion(rec.VersionID)
	if err != nil {
		return ScheduledTaskConfigFile{}, configVersionRecord{}, false, err
	}
	return cfg, rec, true, nil
}

func (s *wafEventStore) writeScheduledTaskConfigVersion(expectedETag string, cfg ScheduledTaskConfigFile, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, error) {
	normalized := cloneScheduledTaskConfigFile(cfg)
	return s.writeConfigVersion(
		scheduledTaskConfigDomain,
		scheduledTaskConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		scheduledTaskConfigHash(normalized),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			return s.insertScheduledTaskConfigRowsTx(tx, versionID, normalized)
		},
	)
}

func (s *wafEventStore) insertScheduledTaskConfigRowsTx(tx *sql.Tx, versionID int64, cfg ScheduledTaskConfigFile) error {
	for i, task := range cfg.Tasks {
		if _, err := s.txExec(tx, `INSERT INTO scheduled_tasks (version_id, position, name, enabled, schedule, timezone, command, timeout_sec) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, versionID, i, task.Name, boolToDB(task.Enabled), task.Schedule, task.Timezone, task.Command, task.TimeoutSec); err != nil {
			return err
		}
		keys := make([]string, 0, len(task.Env))
		for key := range task.Env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for j, key := range keys {
			if _, err := s.txExec(tx, `INSERT INTO scheduled_task_env (version_id, task_position, position, name, value) VALUES (?, ?, ?, ?, ?)`, versionID, i, j, key, task.Env[key]); err != nil {
				return err
			}
		}
		for j, arg := range task.Args {
			if _, err := s.txExec(tx, `INSERT INTO scheduled_task_args (version_id, task_position, position, value) VALUES (?, ?, ?, ?)`, versionID, i, j, arg); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *wafEventStore) loadScheduledTaskConfigVersion(versionID int64) (ScheduledTaskConfigFile, error) {
	rows, err := s.query(`SELECT position, name, enabled, schedule, timezone, command, timeout_sec FROM scheduled_tasks WHERE version_id = ? ORDER BY position`, versionID)
	if err != nil {
		return ScheduledTaskConfigFile{}, err
	}
	type taskRow struct {
		position int
		task     ScheduledTaskRecord
	}
	var scanned []taskRow
	for rows.Next() {
		var position, enabled int
		var task ScheduledTaskRecord
		if err := rows.Scan(&position, &task.Name, &enabled, &task.Schedule, &task.Timezone, &task.Command, &task.TimeoutSec); err != nil {
			_ = rows.Close()
			return ScheduledTaskConfigFile{}, err
		}
		task.Enabled = boolFromDB(enabled)
		scanned = append(scanned, taskRow{position: position, task: task})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return ScheduledTaskConfigFile{}, err
	}
	if err := rows.Close(); err != nil {
		return ScheduledTaskConfigFile{}, err
	}

	out := ScheduledTaskConfigFile{Tasks: make([]ScheduledTaskRecord, 0, len(scanned))}
	for _, item := range scanned {
		env, err := s.loadScheduledTaskEnv(versionID, item.position)
		if err != nil {
			return ScheduledTaskConfigFile{}, err
		}
		args, err := s.loadScheduledTaskArgs(versionID, item.position)
		if err != nil {
			return ScheduledTaskConfigFile{}, err
		}
		item.task.Env = env
		item.task.Args = args
		out.Tasks = append(out.Tasks, item.task)
	}
	return out, nil
}

func (s *wafEventStore) loadScheduledTaskEnv(versionID int64, taskPosition int) (map[string]string, error) {
	rows, err := s.query(`SELECT name, value FROM scheduled_task_env WHERE version_id = ? AND task_position = ? ORDER BY position`, versionID, taskPosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		out[name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (s *wafEventStore) loadScheduledTaskArgs(versionID int64, taskPosition int) ([]string, error) {
	rows, err := s.query(`SELECT value FROM scheduled_task_args WHERE version_id = ? AND task_position = ? ORDER BY position`, versionID, taskPosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func upstreamRuntimeConfigHash(file upstreamRuntimeFile) string {
	payload, err := MarshalUpstreamRuntimeJSON(file)
	if err != nil {
		return configContentHash(upstreamRuntimeVersion)
	}
	return configContentHash(string(payload))
}

func (s *wafEventStore) loadActiveUpstreamRuntimeConfig(knownKeys map[string]struct{}) (upstreamRuntimeFile, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(upstreamRuntimeConfigDomain)
	if err != nil || !found {
		return upstreamRuntimeFile{}, configVersionRecord{}, false, err
	}
	file, err := s.loadUpstreamRuntimeConfigVersion(rec.VersionID)
	if err != nil {
		return upstreamRuntimeFile{}, configVersionRecord{}, false, err
	}
	normalized, err := normalizeUpstreamRuntimeFile(file, knownKeys)
	if err != nil {
		return upstreamRuntimeFile{}, configVersionRecord{}, false, err
	}
	return normalized, rec, true, nil
}

func (s *wafEventStore) writeUpstreamRuntimeConfigVersion(expectedETag string, file upstreamRuntimeFile, knownKeys map[string]struct{}, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, upstreamRuntimeFile, error) {
	normalized, err := normalizeUpstreamRuntimeFile(file, knownKeys)
	if err != nil {
		return configVersionRecord{}, upstreamRuntimeFile{}, err
	}
	rec, err := s.writeConfigVersion(
		upstreamRuntimeConfigDomain,
		upstreamRuntimeConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		upstreamRuntimeConfigHash(normalized),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			return s.insertUpstreamRuntimeRowsTx(tx, versionID, normalized)
		},
	)
	if err != nil {
		return configVersionRecord{}, upstreamRuntimeFile{}, err
	}
	return rec, normalized, nil
}

func (s *wafEventStore) insertUpstreamRuntimeRowsTx(tx *sql.Tx, versionID int64, file upstreamRuntimeFile) error {
	keys := make([]string, 0, len(file.Backends))
	for key := range file.Backends {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		override := file.Backends[key]
		adminSet := 0
		adminState := ""
		if override.AdminState != nil {
			adminSet = 1
			adminState = string(*override.AdminState)
		}
		weightSet := 0
		weight := 0
		if override.WeightOverride != nil {
			weightSet = 1
			weight = *override.WeightOverride
		}
		if _, err := s.txExec(tx, `INSERT INTO upstream_runtime_overrides (version_id, backend_key_hash, backend_key, admin_state_set, admin_state, weight_override_set, weight_override) VALUES (?, ?, ?, ?, ?, ?, ?)`, versionID, storageKeyHash(key), key, adminSet, adminState, weightSet, weight); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) loadUpstreamRuntimeConfigVersion(versionID int64) (upstreamRuntimeFile, error) {
	rows, err := s.query(`SELECT backend_key, admin_state_set, admin_state, weight_override_set, weight_override FROM upstream_runtime_overrides WHERE version_id = ? ORDER BY backend_key`, versionID)
	if err != nil {
		return upstreamRuntimeFile{}, err
	}
	defer rows.Close()
	out := upstreamRuntimeFile{
		Version:  upstreamRuntimeVersion,
		Backends: map[string]upstreamRuntimeOverride{},
	}
	for rows.Next() {
		var key, state string
		var stateSet, weightSet, weight int
		if err := rows.Scan(&key, &stateSet, &state, &weightSet, &weight); err != nil {
			return upstreamRuntimeFile{}, err
		}
		var override upstreamRuntimeOverride
		if stateSet != 0 {
			adminState := upstreamAdminState(state)
			override.AdminState = &adminState
		}
		if weightSet != 0 {
			weightOverride := weight
			override.WeightOverride = &weightOverride
		}
		out.Backends[key] = override
	}
	if err := rows.Err(); err != nil {
		return upstreamRuntimeFile{}, err
	}
	if len(out.Backends) == 0 {
		out.Backends = nil
	}
	return out, nil
}
