package handler

import (
	"database/sql"
	"fmt"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/cacheconf"
)

func (s *wafEventStore) insertCacheRulesConfigTx(tx *sql.Tx, versionID int64, file cacheconf.RulesFile) error {
	for _, scoped := range policyScopedRows(file.Default, file.Hosts) {
		if _, err := s.txExec(tx, `INSERT INTO cache_rule_scopes (version_id, scope_type, host) VALUES (?, ?, ?)`, versionID, scoped.ref.Type, scoped.ref.Host); err != nil {
			return err
		}
		for i, rule := range scoped.scope.Rules {
			if _, err := s.txExec(tx, `INSERT INTO cache_rules (version_id, scope_type, host, position, kind, match_type, match_value, ttl) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				versionID, scoped.ref.Type, scoped.ref.Host, i, rule.Kind, rule.Match.Type, rule.Match.Value, rule.TTL); err != nil {
				return err
			}
			for j, method := range rule.Methods {
				if _, err := s.txExec(tx, `INSERT INTO cache_rule_methods (version_id, scope_type, host, rule_position, position, method) VALUES (?, ?, ?, ?, ?, ?)`, versionID, scoped.ref.Type, scoped.ref.Host, i, j, method); err != nil {
					return err
				}
			}
			for j, header := range rule.Vary {
				if _, err := s.txExec(tx, `INSERT INTO cache_rule_vary_headers (version_id, scope_type, host, rule_position, position, header_name) VALUES (?, ?, ?, ?, ?, ?)`, versionID, scoped.ref.Type, scoped.ref.Host, i, j, header); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *wafEventStore) loadCacheRulesConfigVersion(versionID int64) (cacheconf.RulesFile, error) {
	refs, err := s.loadPolicyScopeRefs(`cache_rule_scopes`, versionID)
	if err != nil {
		return cacheconf.RulesFile{}, err
	}
	out := cacheconf.RulesFile{Hosts: map[string]cacheconf.ScopeDTO{}}
	for _, ref := range refs {
		scope := cacheconf.ScopeDTO{}
		rows, err := s.query(`SELECT position, kind, match_type, match_value, ttl FROM cache_rules WHERE version_id = ? AND scope_type = ? AND host = ? ORDER BY position`, versionID, ref.Type, ref.Host)
		if err != nil {
			return cacheconf.RulesFile{}, err
		}
		type cacheRuleRow struct {
			pos  int
			rule cacheconf.RuleDTO
		}
		var ruleRows []cacheRuleRow
		for rows.Next() {
			var rule cacheconf.RuleDTO
			var pos int
			if err := rows.Scan(&pos, &rule.Kind, &rule.Match.Type, &rule.Match.Value, &rule.TTL); err != nil {
				_ = rows.Close()
				return cacheconf.RulesFile{}, err
			}
			ruleRows = append(ruleRows, cacheRuleRow{pos: pos, rule: rule})
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return cacheconf.RulesFile{}, err
		}
		if err := rows.Close(); err != nil {
			return cacheconf.RulesFile{}, err
		}
		for _, row := range ruleRows {
			methods, err := s.loadCacheRuleStrings(versionID, ref, row.pos, `cache_rule_methods`, `method`)
			if err != nil {
				return cacheconf.RulesFile{}, err
			}
			vary, err := s.loadCacheRuleStrings(versionID, ref, row.pos, `cache_rule_vary_headers`, `header_name`)
			if err != nil {
				return cacheconf.RulesFile{}, err
			}
			row.rule.Methods = methods
			row.rule.Vary = vary
			scope.Rules = append(scope.Rules, row.rule)
		}
		if ref.Type == policyScopeTypeDefault {
			out.Default = scope
		} else {
			out.Hosts[ref.Host] = scope
		}
	}
	if len(out.Hosts) == 0 {
		out.Hosts = nil
	}
	return out, nil
}

func (s *wafEventStore) loadCacheRuleStrings(versionID int64, ref policyScopeRef, rulePosition int, table string, column string) ([]string, error) {
	rows, err := s.query(fmt.Sprintf(`SELECT %s FROM %s WHERE version_id = ? AND scope_type = ? AND host = ? AND rule_position = ? ORDER BY position`, column, table), versionID, ref.Type, ref.Host, rulePosition)
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

func (s *wafEventStore) insertBypassRulesConfigTx(tx *sql.Tx, versionID int64, file bypassconf.File) error {
	for _, scoped := range policyScopedRows(file.Default, file.Hosts) {
		if _, err := s.txExec(tx, `INSERT INTO bypass_scopes (version_id, scope_type, host) VALUES (?, ?, ?)`, versionID, scoped.ref.Type, scoped.ref.Host); err != nil {
			return err
		}
		for i, entry := range scoped.scope.Entries {
			if _, err := s.txExec(tx, `INSERT INTO bypass_entries (version_id, scope_type, host, position, path, extra_rule) VALUES (?, ?, ?, ?, ?, ?)`,
				versionID, scoped.ref.Type, scoped.ref.Host, i, entry.Path, entry.ExtraRule); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *wafEventStore) loadBypassRulesConfigVersion(versionID int64) (bypassconf.File, error) {
	refs, err := s.loadPolicyScopeRefs(`bypass_scopes`, versionID)
	if err != nil {
		return bypassconf.File{}, err
	}
	out := bypassconf.File{Hosts: map[string]bypassconf.Scope{}}
	for _, ref := range refs {
		rows, err := s.query(`SELECT path, extra_rule FROM bypass_entries WHERE version_id = ? AND scope_type = ? AND host = ? ORDER BY position`, versionID, ref.Type, ref.Host)
		if err != nil {
			return bypassconf.File{}, err
		}
		scope := bypassconf.Scope{}
		for rows.Next() {
			var entry bypassconf.Entry
			if err := rows.Scan(&entry.Path, &entry.ExtraRule); err != nil {
				_ = rows.Close()
				return bypassconf.File{}, err
			}
			scope.Entries = append(scope.Entries, entry)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return bypassconf.File{}, err
		}
		if err := rows.Close(); err != nil {
			return bypassconf.File{}, err
		}
		if ref.Type == policyScopeTypeDefault {
			out.Default = scope
		} else {
			out.Hosts[ref.Host] = scope
		}
	}
	if len(out.Hosts) == 0 {
		out.Hosts = nil
	}
	return out, nil
}

func (s *wafEventStore) insertCountryBlockConfigTx(tx *sql.Tx, versionID int64, file countryBlockFile) error {
	for _, scoped := range policyScopedRows(file.Default, file.Hosts) {
		if _, err := s.txExec(tx, `INSERT INTO country_block_scopes (version_id, scope_type, host) VALUES (?, ?, ?)`, versionID, scoped.ref.Type, scoped.ref.Host); err != nil {
			return err
		}
		for i, country := range scoped.scope.BlockedCountries {
			if _, err := s.txExec(tx, `INSERT INTO country_block_countries (version_id, scope_type, host, position, country_code) VALUES (?, ?, ?, ?, ?)`, versionID, scoped.ref.Type, scoped.ref.Host, i, country); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *wafEventStore) loadCountryBlockConfigVersion(versionID int64) (countryBlockFile, error) {
	refs, err := s.loadPolicyScopeRefs(`country_block_scopes`, versionID)
	if err != nil {
		return countryBlockFile{}, err
	}
	out := countryBlockFile{Hosts: map[string]countryBlockScope{}}
	for _, ref := range refs {
		rows, err := s.query(`SELECT country_code FROM country_block_countries WHERE version_id = ? AND scope_type = ? AND host = ? ORDER BY position`, versionID, ref.Type, ref.Host)
		if err != nil {
			return countryBlockFile{}, err
		}
		scope := countryBlockScope{}
		for rows.Next() {
			var country string
			if err := rows.Scan(&country); err != nil {
				_ = rows.Close()
				return countryBlockFile{}, err
			}
			scope.BlockedCountries = append(scope.BlockedCountries, country)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return countryBlockFile{}, err
		}
		if err := rows.Close(); err != nil {
			return countryBlockFile{}, err
		}
		if ref.Type == policyScopeTypeDefault {
			out.Default = scope
		} else {
			out.Hosts[ref.Host] = scope
		}
	}
	if len(out.Hosts) == 0 {
		out.Hosts = nil
	}
	return out, nil
}

func (s *wafEventStore) insertIPReputationConfigTx(tx *sql.Tx, versionID int64, file ipReputationFile) error {
	for _, scoped := range policyScopedRows(file.Default, file.Hosts) {
		cfg := scoped.scope
		if _, err := s.txExec(tx, `INSERT INTO ip_reputation_scopes (version_id, scope_type, host, enabled, refresh_interval_sec, request_timeout_sec, block_status_code, fail_open) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			versionID, scoped.ref.Type, scoped.ref.Host, boolToDB(cfg.Enabled), cfg.RefreshIntervalSec, cfg.RequestTimeoutSec, cfg.BlockStatusCode, boolToDB(cfg.FailOpen)); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `ip_reputation_scope_values`, versionID, scoped.ref, `feed_urls`, cfg.FeedURLs); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `ip_reputation_scope_values`, versionID, scoped.ref, `allowlist`, cfg.Allowlist); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `ip_reputation_scope_values`, versionID, scoped.ref, `blocklist`, cfg.Blocklist); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) loadIPReputationConfigVersion(versionID int64) (ipReputationFile, error) {
	rows, err := s.query(`SELECT scope_type, host, enabled, refresh_interval_sec, request_timeout_sec, block_status_code, fail_open FROM ip_reputation_scopes WHERE version_id = ? ORDER BY CASE scope_type WHEN 'default' THEN 0 ELSE 1 END, host`, versionID)
	if err != nil {
		return ipReputationFile{}, err
	}
	type ipReputationScopeRow struct {
		ref      policyScopeRef
		cfg      ipReputationConfig
		enabled  int
		failOpen int
	}
	var scopeRows []ipReputationScopeRow
	out := ipReputationFile{Hosts: map[string]ipReputationConfig{}}
	for rows.Next() {
		var scopeType, host string
		var enabled, failOpen int
		var cfg ipReputationConfig
		if err := rows.Scan(&scopeType, &host, &enabled, &cfg.RefreshIntervalSec, &cfg.RequestTimeoutSec, &cfg.BlockStatusCode, &failOpen); err != nil {
			return ipReputationFile{}, err
		}
		ref := policyRefFromRow(scopeType, host)
		scopeRows = append(scopeRows, ipReputationScopeRow{ref: ref, cfg: cfg, enabled: enabled, failOpen: failOpen})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return ipReputationFile{}, err
	}
	if err := rows.Close(); err != nil {
		return ipReputationFile{}, err
	}
	for _, row := range scopeRows {
		ref := row.ref
		cfg := row.cfg
		cfg.Enabled = boolFromDB(row.enabled)
		cfg.FailOpen = boolFromDB(row.failOpen)
		cfg.FeedURLs, err = loadPolicyStringList(s, `ip_reputation_scope_values`, versionID, ref, `feed_urls`)
		if err != nil {
			return ipReputationFile{}, err
		}
		cfg.Allowlist, err = loadPolicyStringList(s, `ip_reputation_scope_values`, versionID, ref, `allowlist`)
		if err != nil {
			return ipReputationFile{}, err
		}
		cfg.Blocklist, err = loadPolicyStringList(s, `ip_reputation_scope_values`, versionID, ref, `blocklist`)
		if err != nil {
			return ipReputationFile{}, err
		}
		if ref.Type == policyScopeTypeDefault {
			out.Default = cfg
		} else {
			out.Hosts[ref.Host] = cfg
		}
	}
	if len(out.Hosts) == 0 {
		out.Hosts = nil
	}
	return out, nil
}

func (s *wafEventStore) loadPolicyScopeRefs(table string, versionID int64) ([]policyScopeRef, error) {
	rows, err := s.query(fmt.Sprintf(`SELECT scope_type, host FROM %s WHERE version_id = ? ORDER BY CASE scope_type WHEN 'default' THEN 0 ELSE 1 END, host`, table), versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []policyScopeRef
	for rows.Next() {
		var scopeType, host string
		if err := rows.Scan(&scopeType, &host); err != nil {
			return nil, err
		}
		refs = append(refs, policyRefFromRow(scopeType, host))
	}
	return refs, rows.Err()
}
