package handler

import "database/sql"

func (s *wafEventStore) insertRateLimitConfigTx(tx *sql.Tx, versionID int64, file rateLimitFile) error {
	for _, scoped := range policyScopedRows(file.Default, file.Hosts) {
		cfg := scoped.scope
		if _, err := s.txExec(tx, `INSERT INTO rate_limit_scopes (
			version_id, scope_type, host, enabled,
			adaptive_enabled, adaptive_score_threshold, adaptive_limit_factor_percent, adaptive_burst_factor_percent,
			feedback_enabled, feedback_strikes_required, feedback_strike_window_seconds, feedback_adaptive_only, feedback_dry_run,
			default_enabled, default_limit, default_window_seconds, default_burst, default_key_by, default_action_status, default_action_retry_after_seconds
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			versionID, scoped.ref.Type, scoped.ref.Host, boolToDB(cfg.Enabled),
			boolToDB(cfg.AdaptiveEnabled), cfg.AdaptiveScoreThreshold, cfg.AdaptiveLimitFactorPct, cfg.AdaptiveBurstFactorPct,
			boolToDB(cfg.Feedback.Enabled), cfg.Feedback.StrikesRequired, cfg.Feedback.StrikeWindowSeconds, boolToDB(cfg.Feedback.AdaptiveOnly), boolToDB(cfg.Feedback.DryRun),
			boolToDB(cfg.DefaultPolicy.Enabled), cfg.DefaultPolicy.Limit, cfg.DefaultPolicy.WindowSeconds, cfg.DefaultPolicy.Burst, cfg.DefaultPolicy.KeyBy, cfg.DefaultPolicy.Action.Status, cfg.DefaultPolicy.Action.RetryAfterSeconds,
		); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `rate_limit_scope_values`, versionID, scoped.ref, `allowlist_ips`, cfg.AllowlistIPs); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `rate_limit_scope_values`, versionID, scoped.ref, `allowlist_countries`, cfg.AllowlistCountries); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `rate_limit_scope_values`, versionID, scoped.ref, `session_cookie_names`, cfg.SessionCookieNames); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `rate_limit_scope_values`, versionID, scoped.ref, `jwt_header_names`, cfg.JWTHeaderNames); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `rate_limit_scope_values`, versionID, scoped.ref, `jwt_cookie_names`, cfg.JWTCookieNames); err != nil {
			return err
		}
		for i, rule := range cfg.Rules {
			if _, err := s.txExec(tx, `INSERT INTO rate_limit_rules (
				version_id, scope_type, host, position, name, match_type, match_value,
				policy_enabled, policy_limit, policy_window_seconds, policy_burst, policy_key_by, policy_action_status, policy_action_retry_after_seconds
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				versionID, scoped.ref.Type, scoped.ref.Host, i, rule.Name, rule.MatchType, rule.MatchValue,
				boolToDB(rule.Policy.Enabled), rule.Policy.Limit, rule.Policy.WindowSeconds, rule.Policy.Burst, rule.Policy.KeyBy, rule.Policy.Action.Status, rule.Policy.Action.RetryAfterSeconds,
			); err != nil {
				return err
			}
			for j, method := range rule.Methods {
				if _, err := s.txExec(tx, `INSERT INTO rate_limit_rule_methods (version_id, scope_type, host, rule_position, position, method) VALUES (?, ?, ?, ?, ?, ?)`, versionID, scoped.ref.Type, scoped.ref.Host, i, j, method); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *wafEventStore) loadRateLimitConfigVersion(versionID int64) (rateLimitFile, error) {
	rows, err := s.query(`SELECT
		scope_type, host, enabled,
		adaptive_enabled, adaptive_score_threshold, adaptive_limit_factor_percent, adaptive_burst_factor_percent,
		feedback_enabled, feedback_strikes_required, feedback_strike_window_seconds, feedback_adaptive_only, feedback_dry_run,
		default_enabled, default_limit, default_window_seconds, default_burst, default_key_by, default_action_status, default_action_retry_after_seconds
		FROM rate_limit_scopes
		WHERE version_id = ?
		ORDER BY CASE scope_type WHEN 'default' THEN 0 ELSE 1 END, host`, versionID)
	if err != nil {
		return rateLimitFile{}, err
	}
	type rateLimitScopeRow struct {
		ref                  policyScopeRef
		cfg                  rateLimitConfig
		enabled              int
		adaptiveEnabled      int
		feedbackEnabled      int
		feedbackAdaptiveOnly int
		feedbackDryRun       int
		defaultEnabled       int
	}
	var scopeRows []rateLimitScopeRow
	out := rateLimitFile{Hosts: map[string]rateLimitConfig{}}
	for rows.Next() {
		var scopeType, host string
		var enabled, adaptiveEnabled, feedbackEnabled, feedbackAdaptiveOnly, feedbackDryRun, defaultEnabled int
		var cfg rateLimitConfig
		if err := rows.Scan(
			&scopeType, &host, &enabled,
			&adaptiveEnabled, &cfg.AdaptiveScoreThreshold, &cfg.AdaptiveLimitFactorPct, &cfg.AdaptiveBurstFactorPct,
			&feedbackEnabled, &cfg.Feedback.StrikesRequired, &cfg.Feedback.StrikeWindowSeconds, &feedbackAdaptiveOnly, &feedbackDryRun,
			&defaultEnabled, &cfg.DefaultPolicy.Limit, &cfg.DefaultPolicy.WindowSeconds, &cfg.DefaultPolicy.Burst, &cfg.DefaultPolicy.KeyBy, &cfg.DefaultPolicy.Action.Status, &cfg.DefaultPolicy.Action.RetryAfterSeconds,
		); err != nil {
			return rateLimitFile{}, err
		}
		ref := policyRefFromRow(scopeType, host)
		scopeRows = append(scopeRows, rateLimitScopeRow{
			ref:                  ref,
			cfg:                  cfg,
			enabled:              enabled,
			adaptiveEnabled:      adaptiveEnabled,
			feedbackEnabled:      feedbackEnabled,
			feedbackAdaptiveOnly: feedbackAdaptiveOnly,
			feedbackDryRun:       feedbackDryRun,
			defaultEnabled:       defaultEnabled,
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return rateLimitFile{}, err
	}
	if err := rows.Close(); err != nil {
		return rateLimitFile{}, err
	}
	for _, row := range scopeRows {
		ref := row.ref
		cfg := row.cfg
		cfg.Enabled = boolFromDB(row.enabled)
		cfg.AdaptiveEnabled = boolFromDB(row.adaptiveEnabled)
		cfg.Feedback.Enabled = boolFromDB(row.feedbackEnabled)
		cfg.Feedback.AdaptiveOnly = boolFromDB(row.feedbackAdaptiveOnly)
		cfg.Feedback.DryRun = boolFromDB(row.feedbackDryRun)
		cfg.DefaultPolicy.Enabled = boolFromDB(row.defaultEnabled)
		cfg.AllowlistIPs, err = loadPolicyStringList(s, `rate_limit_scope_values`, versionID, ref, `allowlist_ips`)
		if err != nil {
			return rateLimitFile{}, err
		}
		cfg.AllowlistCountries, err = loadPolicyStringList(s, `rate_limit_scope_values`, versionID, ref, `allowlist_countries`)
		if err != nil {
			return rateLimitFile{}, err
		}
		cfg.SessionCookieNames, err = loadPolicyStringList(s, `rate_limit_scope_values`, versionID, ref, `session_cookie_names`)
		if err != nil {
			return rateLimitFile{}, err
		}
		cfg.JWTHeaderNames, err = loadPolicyStringList(s, `rate_limit_scope_values`, versionID, ref, `jwt_header_names`)
		if err != nil {
			return rateLimitFile{}, err
		}
		cfg.JWTCookieNames, err = loadPolicyStringList(s, `rate_limit_scope_values`, versionID, ref, `jwt_cookie_names`)
		if err != nil {
			return rateLimitFile{}, err
		}
		cfg.Rules, err = s.loadRateLimitRules(versionID, ref)
		if err != nil {
			return rateLimitFile{}, err
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

func (s *wafEventStore) loadRateLimitRules(versionID int64, ref policyScopeRef) ([]rateLimitRule, error) {
	rows, err := s.query(`SELECT
		position, name, match_type, match_value,
		policy_enabled, policy_limit, policy_window_seconds, policy_burst, policy_key_by, policy_action_status, policy_action_retry_after_seconds
		FROM rate_limit_rules
		WHERE version_id = ? AND scope_type = ? AND host = ?
		ORDER BY position`, versionID, ref.Type, ref.Host)
	if err != nil {
		return nil, err
	}
	type rateLimitRuleRow struct {
		pos     int
		enabled int
		rule    rateLimitRule
	}
	var ruleRows []rateLimitRuleRow
	var rules []rateLimitRule
	for rows.Next() {
		var pos int
		var enabled int
		var rule rateLimitRule
		if err := rows.Scan(
			&pos, &rule.Name, &rule.MatchType, &rule.MatchValue,
			&enabled, &rule.Policy.Limit, &rule.Policy.WindowSeconds, &rule.Policy.Burst, &rule.Policy.KeyBy, &rule.Policy.Action.Status, &rule.Policy.Action.RetryAfterSeconds,
		); err != nil {
			return nil, err
		}
		ruleRows = append(ruleRows, rateLimitRuleRow{pos: pos, enabled: enabled, rule: rule})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, row := range ruleRows {
		rule := row.rule
		rule.Policy.Enabled = boolFromDB(row.enabled)
		methods, err := s.loadRateLimitRuleMethods(versionID, ref, row.pos)
		if err != nil {
			return nil, err
		}
		rule.Methods = methods
		rules = append(rules, rule)
	}
	return rules, nil
}

func (s *wafEventStore) loadRateLimitRuleMethods(versionID int64, ref policyScopeRef, rulePosition int) ([]string, error) {
	rows, err := s.query(`SELECT method FROM rate_limit_rule_methods WHERE version_id = ? AND scope_type = ? AND host = ? AND rule_position = ? ORDER BY position`, versionID, ref.Type, ref.Host, rulePosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var methods []string
	for rows.Next() {
		var method string
		if err := rows.Scan(&method); err != nil {
			return nil, err
		}
		methods = append(methods, method)
	}
	return methods, rows.Err()
}
