package handler

import "database/sql"

func (s *wafEventStore) insertBotDefenseConfigTx(tx *sql.Tx, versionID int64, file botDefenseFile) error {
	for _, scoped := range policyScopedRows(file.Default, file.Hosts) {
		cfg := scoped.scope
		if _, err := s.txExec(tx, `INSERT INTO bot_defense_scopes (
			version_id, scope_type, host,
			enabled, dry_run, mode, challenge_cookie_name, challenge_secret, challenge_ttl_seconds, challenge_status_code,
			behavioral_enabled, behavioral_window_seconds, behavioral_burst_threshold, behavioral_path_fanout_threshold, behavioral_ua_churn_threshold, behavioral_missing_cookie_threshold, behavioral_score_threshold, behavioral_risk_score_per_signal,
			browser_enabled, browser_js_cookie_name, browser_score_threshold, browser_risk_score_per_signal,
			device_enabled, device_require_time_zone, device_require_platform, device_require_hardware_concurrency, device_check_mobile_touch, device_invisible_html_injection, device_invisible_max_body_bytes, device_score_threshold, device_risk_score_per_signal,
			header_enabled, header_require_accept_language, header_require_fetch_metadata, header_require_client_hints, header_require_upgrade_insecure, header_score_threshold, header_risk_score_per_signal,
			tls_enabled, tls_require_sni, tls_require_alpn, tls_require_modern_tls, tls_score_threshold, tls_risk_score_per_signal,
			quarantine_enabled, quarantine_threshold, quarantine_strikes_required, quarantine_strike_window_seconds, quarantine_ttl_seconds, quarantine_status_code, quarantine_reputation_feedback_seconds,
			challenge_feedback_enabled, challenge_feedback_reputation_seconds
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			versionID, scoped.ref.Type, scoped.ref.Host,
			boolToDB(cfg.Enabled), boolToDB(cfg.DryRun), cfg.Mode, cfg.ChallengeCookieName, cfg.ChallengeSecret, cfg.ChallengeTTLSeconds, cfg.ChallengeStatusCode,
			boolToDB(cfg.BehavioralDetection.Enabled), cfg.BehavioralDetection.WindowSeconds, cfg.BehavioralDetection.BurstThreshold, cfg.BehavioralDetection.PathFanoutThreshold, cfg.BehavioralDetection.UAChurnThreshold, cfg.BehavioralDetection.MissingCookieThreshold, cfg.BehavioralDetection.ScoreThreshold, cfg.BehavioralDetection.RiskScorePerSignal,
			boolToDB(cfg.BrowserSignals.Enabled), cfg.BrowserSignals.JSCookieName, cfg.BrowserSignals.ScoreThreshold, cfg.BrowserSignals.RiskScorePerSignal,
			boolToDB(cfg.DeviceSignals.Enabled), boolToDB(cfg.DeviceSignals.RequireTimeZone), boolToDB(cfg.DeviceSignals.RequirePlatform), boolToDB(cfg.DeviceSignals.RequireHardwareConcurrency), boolToDB(cfg.DeviceSignals.CheckMobileTouch), boolToDB(cfg.DeviceSignals.InvisibleHTMLInjection), cfg.DeviceSignals.InvisibleMaxBodyBytes, cfg.DeviceSignals.ScoreThreshold, cfg.DeviceSignals.RiskScorePerSignal,
			boolToDB(cfg.HeaderSignals.Enabled), boolToDB(cfg.HeaderSignals.RequireAcceptLanguage), boolToDB(cfg.HeaderSignals.RequireFetchMetadata), boolToDB(cfg.HeaderSignals.RequireClientHints), boolToDB(cfg.HeaderSignals.RequireUpgradeInsecure), cfg.HeaderSignals.ScoreThreshold, cfg.HeaderSignals.RiskScorePerSignal,
			boolToDB(cfg.TLSSignals.Enabled), boolToDB(cfg.TLSSignals.RequireSNI), boolToDB(cfg.TLSSignals.RequireALPN), boolToDB(cfg.TLSSignals.RequireModernTLS), cfg.TLSSignals.ScoreThreshold, cfg.TLSSignals.RiskScorePerSignal,
			boolToDB(cfg.Quarantine.Enabled), cfg.Quarantine.Threshold, cfg.Quarantine.StrikesRequired, cfg.Quarantine.StrikeWindowSeconds, cfg.Quarantine.TTLSeconds, cfg.Quarantine.StatusCode, cfg.Quarantine.ReputationFeedbackSeconds,
			boolToDB(cfg.ChallengeFailureFeedback.Enabled), cfg.ChallengeFailureFeedback.ReputationFeedback,
		); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `bot_defense_scope_values`, versionID, scoped.ref, `path_prefixes`, cfg.PathPrefixes); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `bot_defense_scope_values`, versionID, scoped.ref, `exempt_cidrs`, cfg.ExemptCIDRs); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `bot_defense_scope_values`, versionID, scoped.ref, `suspicious_user_agents`, cfg.SuspiciousUserAgents); err != nil {
			return err
		}
		for i, policy := range cfg.PathPolicies {
			drySet, dryRun := boolPtrToDB(policy.DryRun)
			if _, err := s.txExec(tx, `INSERT INTO bot_defense_path_policies (
				version_id, scope_type, host, position, name, mode, dry_run_set, dry_run,
				risk_score_multiplier_percent, risk_score_offset, telemetry_cookie_required, disable_quarantine
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				versionID, scoped.ref.Type, scoped.ref.Host, i, policy.Name, policy.Mode, drySet, dryRun,
				policy.RiskScoreMultiplierPercent, policy.RiskScoreOffset, boolToDB(policy.TelemetryCookieRequired), boolToDB(policy.DisableQuarantine)); err != nil {
				return err
			}
			for j, prefix := range policy.PathPrefixes {
				if _, err := s.txExec(tx, `INSERT INTO bot_defense_path_policy_prefixes (version_id, scope_type, host, policy_position, position, path_prefix) VALUES (?, ?, ?, ?, ?, ?)`, versionID, scoped.ref.Type, scoped.ref.Host, i, j, prefix); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *wafEventStore) loadBotDefenseConfigVersion(versionID int64) (botDefenseFile, error) {
	rows, err := s.query(`SELECT
		scope_type, host,
		enabled, dry_run, mode, challenge_cookie_name, challenge_secret, challenge_ttl_seconds, challenge_status_code,
		behavioral_enabled, behavioral_window_seconds, behavioral_burst_threshold, behavioral_path_fanout_threshold, behavioral_ua_churn_threshold, behavioral_missing_cookie_threshold, behavioral_score_threshold, behavioral_risk_score_per_signal,
		browser_enabled, browser_js_cookie_name, browser_score_threshold, browser_risk_score_per_signal,
		device_enabled, device_require_time_zone, device_require_platform, device_require_hardware_concurrency, device_check_mobile_touch, device_invisible_html_injection, device_invisible_max_body_bytes, device_score_threshold, device_risk_score_per_signal,
		header_enabled, header_require_accept_language, header_require_fetch_metadata, header_require_client_hints, header_require_upgrade_insecure, header_score_threshold, header_risk_score_per_signal,
		tls_enabled, tls_require_sni, tls_require_alpn, tls_require_modern_tls, tls_score_threshold, tls_risk_score_per_signal,
		quarantine_enabled, quarantine_threshold, quarantine_strikes_required, quarantine_strike_window_seconds, quarantine_ttl_seconds, quarantine_status_code, quarantine_reputation_feedback_seconds,
		challenge_feedback_enabled, challenge_feedback_reputation_seconds
		FROM bot_defense_scopes
		WHERE version_id = ?
		ORDER BY CASE scope_type WHEN 'default' THEN 0 ELSE 1 END, host`, versionID)
	if err != nil {
		return botDefenseFile{}, err
	}
	type botDefenseScopeRow struct {
		ref                      policyScopeRef
		cfg                      botDefenseConfig
		enabled                  int
		dryRun                   int
		behavioralEnabled        int
		browserEnabled           int
		deviceEnabled            int
		deviceRequireTZ          int
		deviceRequirePlatform    int
		deviceRequireHC          int
		deviceCheckMobile        int
		deviceInvisible          int
		headerEnabled            int
		headerRequireAL          int
		headerRequireFM          int
		headerRequireCH          int
		headerRequireUpgrade     int
		tlsEnabled               int
		tlsRequireSNI            int
		tlsRequireALPN           int
		tlsRequireModern         int
		quarantineEnabled        int
		challengeFeedbackEnabled int
	}
	var scopeRows []botDefenseScopeRow
	out := botDefenseFile{Hosts: map[string]botDefenseConfig{}}
	for rows.Next() {
		var scopeType, host string
		var enabled, dryRun int
		var behavioralEnabled, browserEnabled, deviceEnabled, deviceRequireTZ, deviceRequirePlatform, deviceRequireHC, deviceCheckMobile, deviceInvisible int
		var headerEnabled, headerRequireAL, headerRequireFM, headerRequireCH, headerRequireUpgrade int
		var tlsEnabled, tlsRequireSNI, tlsRequireALPN, tlsRequireModern int
		var quarantineEnabled, challengeFeedbackEnabled int
		var cfg botDefenseConfig
		if err := rows.Scan(
			&scopeType, &host,
			&enabled, &dryRun, &cfg.Mode, &cfg.ChallengeCookieName, &cfg.ChallengeSecret, &cfg.ChallengeTTLSeconds, &cfg.ChallengeStatusCode,
			&behavioralEnabled, &cfg.BehavioralDetection.WindowSeconds, &cfg.BehavioralDetection.BurstThreshold, &cfg.BehavioralDetection.PathFanoutThreshold, &cfg.BehavioralDetection.UAChurnThreshold, &cfg.BehavioralDetection.MissingCookieThreshold, &cfg.BehavioralDetection.ScoreThreshold, &cfg.BehavioralDetection.RiskScorePerSignal,
			&browserEnabled, &cfg.BrowserSignals.JSCookieName, &cfg.BrowserSignals.ScoreThreshold, &cfg.BrowserSignals.RiskScorePerSignal,
			&deviceEnabled, &deviceRequireTZ, &deviceRequirePlatform, &deviceRequireHC, &deviceCheckMobile, &deviceInvisible, &cfg.DeviceSignals.InvisibleMaxBodyBytes, &cfg.DeviceSignals.ScoreThreshold, &cfg.DeviceSignals.RiskScorePerSignal,
			&headerEnabled, &headerRequireAL, &headerRequireFM, &headerRequireCH, &headerRequireUpgrade, &cfg.HeaderSignals.ScoreThreshold, &cfg.HeaderSignals.RiskScorePerSignal,
			&tlsEnabled, &tlsRequireSNI, &tlsRequireALPN, &tlsRequireModern, &cfg.TLSSignals.ScoreThreshold, &cfg.TLSSignals.RiskScorePerSignal,
			&quarantineEnabled, &cfg.Quarantine.Threshold, &cfg.Quarantine.StrikesRequired, &cfg.Quarantine.StrikeWindowSeconds, &cfg.Quarantine.TTLSeconds, &cfg.Quarantine.StatusCode, &cfg.Quarantine.ReputationFeedbackSeconds,
			&challengeFeedbackEnabled, &cfg.ChallengeFailureFeedback.ReputationFeedback,
		); err != nil {
			return botDefenseFile{}, err
		}
		ref := policyRefFromRow(scopeType, host)
		scopeRows = append(scopeRows, botDefenseScopeRow{
			ref:                      ref,
			cfg:                      cfg,
			enabled:                  enabled,
			dryRun:                   dryRun,
			behavioralEnabled:        behavioralEnabled,
			browserEnabled:           browserEnabled,
			deviceEnabled:            deviceEnabled,
			deviceRequireTZ:          deviceRequireTZ,
			deviceRequirePlatform:    deviceRequirePlatform,
			deviceRequireHC:          deviceRequireHC,
			deviceCheckMobile:        deviceCheckMobile,
			deviceInvisible:          deviceInvisible,
			headerEnabled:            headerEnabled,
			headerRequireAL:          headerRequireAL,
			headerRequireFM:          headerRequireFM,
			headerRequireCH:          headerRequireCH,
			headerRequireUpgrade:     headerRequireUpgrade,
			tlsEnabled:               tlsEnabled,
			tlsRequireSNI:            tlsRequireSNI,
			tlsRequireALPN:           tlsRequireALPN,
			tlsRequireModern:         tlsRequireModern,
			quarantineEnabled:        quarantineEnabled,
			challengeFeedbackEnabled: challengeFeedbackEnabled,
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return botDefenseFile{}, err
	}
	if err := rows.Close(); err != nil {
		return botDefenseFile{}, err
	}
	for _, row := range scopeRows {
		ref := row.ref
		cfg := row.cfg
		cfg.Enabled = boolFromDB(row.enabled)
		cfg.DryRun = boolFromDB(row.dryRun)
		cfg.BehavioralDetection.Enabled = boolFromDB(row.behavioralEnabled)
		cfg.BrowserSignals.Enabled = boolFromDB(row.browserEnabled)
		cfg.DeviceSignals.Enabled = boolFromDB(row.deviceEnabled)
		cfg.DeviceSignals.RequireTimeZone = boolFromDB(row.deviceRequireTZ)
		cfg.DeviceSignals.RequirePlatform = boolFromDB(row.deviceRequirePlatform)
		cfg.DeviceSignals.RequireHardwareConcurrency = boolFromDB(row.deviceRequireHC)
		cfg.DeviceSignals.CheckMobileTouch = boolFromDB(row.deviceCheckMobile)
		cfg.DeviceSignals.InvisibleHTMLInjection = boolFromDB(row.deviceInvisible)
		cfg.HeaderSignals.Enabled = boolFromDB(row.headerEnabled)
		cfg.HeaderSignals.RequireAcceptLanguage = boolFromDB(row.headerRequireAL)
		cfg.HeaderSignals.RequireFetchMetadata = boolFromDB(row.headerRequireFM)
		cfg.HeaderSignals.RequireClientHints = boolFromDB(row.headerRequireCH)
		cfg.HeaderSignals.RequireUpgradeInsecure = boolFromDB(row.headerRequireUpgrade)
		cfg.TLSSignals.Enabled = boolFromDB(row.tlsEnabled)
		cfg.TLSSignals.RequireSNI = boolFromDB(row.tlsRequireSNI)
		cfg.TLSSignals.RequireALPN = boolFromDB(row.tlsRequireALPN)
		cfg.TLSSignals.RequireModernTLS = boolFromDB(row.tlsRequireModern)
		cfg.Quarantine.Enabled = boolFromDB(row.quarantineEnabled)
		cfg.ChallengeFailureFeedback.Enabled = boolFromDB(row.challengeFeedbackEnabled)
		cfg.PathPrefixes, err = loadPolicyStringList(s, `bot_defense_scope_values`, versionID, ref, `path_prefixes`)
		if err != nil {
			return botDefenseFile{}, err
		}
		cfg.ExemptCIDRs, err = loadPolicyStringList(s, `bot_defense_scope_values`, versionID, ref, `exempt_cidrs`)
		if err != nil {
			return botDefenseFile{}, err
		}
		cfg.SuspiciousUserAgents, err = loadPolicyStringList(s, `bot_defense_scope_values`, versionID, ref, `suspicious_user_agents`)
		if err != nil {
			return botDefenseFile{}, err
		}
		cfg.PathPolicies, err = s.loadBotDefensePathPolicies(versionID, ref)
		if err != nil {
			return botDefenseFile{}, err
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

func (s *wafEventStore) loadBotDefensePathPolicies(versionID int64, ref policyScopeRef) ([]botDefensePathPolicyConfig, error) {
	rows, err := s.query(`SELECT position, name, mode, dry_run_set, dry_run, risk_score_multiplier_percent, risk_score_offset, telemetry_cookie_required, disable_quarantine
		FROM bot_defense_path_policies
		WHERE version_id = ? AND scope_type = ? AND host = ?
		ORDER BY position`, versionID, ref.Type, ref.Host)
	if err != nil {
		return nil, err
	}
	type botDefensePolicyRow struct {
		pos               int
		drySet            int
		dryRun            int
		telemetry         int
		disableQuarantine int
		policy            botDefensePathPolicyConfig
	}
	var policyRows []botDefensePolicyRow
	var policies []botDefensePathPolicyConfig
	for rows.Next() {
		var pos int
		var drySet, dryRun, telemetry, disableQuarantine int
		var policy botDefensePathPolicyConfig
		if err := rows.Scan(&pos, &policy.Name, &policy.Mode, &drySet, &dryRun, &policy.RiskScoreMultiplierPercent, &policy.RiskScoreOffset, &telemetry, &disableQuarantine); err != nil {
			return nil, err
		}
		policyRows = append(policyRows, botDefensePolicyRow{pos: pos, drySet: drySet, dryRun: dryRun, telemetry: telemetry, disableQuarantine: disableQuarantine, policy: policy})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, row := range policyRows {
		policy := row.policy
		policy.DryRun = boolPtrFromDB(row.drySet, row.dryRun)
		policy.TelemetryCookieRequired = boolFromDB(row.telemetry)
		policy.DisableQuarantine = boolFromDB(row.disableQuarantine)
		prefixes, err := s.loadBotDefensePolicyPrefixes(versionID, ref, row.pos)
		if err != nil {
			return nil, err
		}
		policy.PathPrefixes = prefixes
		policies = append(policies, policy)
	}
	return policies, nil
}

func (s *wafEventStore) loadBotDefensePolicyPrefixes(versionID int64, ref policyScopeRef, policyPosition int) ([]string, error) {
	rows, err := s.query(`SELECT path_prefix FROM bot_defense_path_policy_prefixes WHERE version_id = ? AND scope_type = ? AND host = ? AND policy_position = ? ORDER BY position`, versionID, ref.Type, ref.Host, policyPosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var prefixes []string
	for rows.Next() {
		var prefix string
		if err := rows.Scan(&prefix); err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, rows.Err()
}
