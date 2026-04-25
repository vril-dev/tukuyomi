package handler

import (
	"database/sql"
	"sort"
)

func (s *wafEventStore) insertSemanticConfigTx(tx *sql.Tx, versionID int64, file semanticFile) error {
	for _, scoped := range policyScopedRows(file.Default, file.Hosts) {
		cfg := scoped.scope
		if _, err := s.txExec(tx, `INSERT INTO semantic_scopes (
			version_id, scope_type, host, enabled, mode,
			log_threshold, challenge_threshold, block_threshold, max_inspect_body,
			provider_enabled, provider_name, provider_timeout_ms,
			temporal_window_seconds, temporal_max_entries_per_ip, temporal_burst_threshold, temporal_burst_score,
			temporal_path_fanout_threshold, temporal_path_fanout_score, temporal_ua_churn_threshold, temporal_ua_churn_score
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			versionID, scoped.ref.Type, scoped.ref.Host, boolToDB(cfg.Enabled), cfg.Mode,
			cfg.LogThreshold, cfg.ChallengeThreshold, cfg.BlockThreshold, cfg.MaxInspectBody,
			boolToDB(cfg.Provider.Enabled), cfg.Provider.Name, cfg.Provider.TimeoutMS,
			cfg.TemporalWindowSeconds, cfg.TemporalMaxEntriesPerIP, cfg.TemporalBurstThreshold, cfg.TemporalBurstScore,
			cfg.TemporalPathFanoutThreshold, cfg.TemporalPathFanoutScore, cfg.TemporalUAChurnThreshold, cfg.TemporalUAChurnScore,
		); err != nil {
			return err
		}
		if err := insertPolicyStringListTx(s, tx, `semantic_scope_values`, versionID, scoped.ref, `exempt_path_prefixes`, cfg.ExemptPathPrefixes); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) loadSemanticConfigVersion(versionID int64) (semanticFile, error) {
	rows, err := s.query(`SELECT
		scope_type, host, enabled, mode,
		log_threshold, challenge_threshold, block_threshold, max_inspect_body,
		provider_enabled, provider_name, provider_timeout_ms,
		temporal_window_seconds, temporal_max_entries_per_ip, temporal_burst_threshold, temporal_burst_score,
		temporal_path_fanout_threshold, temporal_path_fanout_score, temporal_ua_churn_threshold, temporal_ua_churn_score
		FROM semantic_scopes
		WHERE version_id = ?
		ORDER BY CASE scope_type WHEN 'default' THEN 0 ELSE 1 END, host`, versionID)
	if err != nil {
		return semanticFile{}, err
	}
	type semanticScopeRow struct {
		ref             policyScopeRef
		cfg             semanticConfig
		enabled         int
		providerEnabled int
	}
	var scopeRows []semanticScopeRow
	out := semanticFile{Hosts: map[string]semanticConfig{}}
	for rows.Next() {
		var scopeType, host string
		var enabled, providerEnabled int
		var cfg semanticConfig
		if err := rows.Scan(
			&scopeType, &host, &enabled, &cfg.Mode,
			&cfg.LogThreshold, &cfg.ChallengeThreshold, &cfg.BlockThreshold, &cfg.MaxInspectBody,
			&providerEnabled, &cfg.Provider.Name, &cfg.Provider.TimeoutMS,
			&cfg.TemporalWindowSeconds, &cfg.TemporalMaxEntriesPerIP, &cfg.TemporalBurstThreshold, &cfg.TemporalBurstScore,
			&cfg.TemporalPathFanoutThreshold, &cfg.TemporalPathFanoutScore, &cfg.TemporalUAChurnThreshold, &cfg.TemporalUAChurnScore,
		); err != nil {
			return semanticFile{}, err
		}
		ref := policyRefFromRow(scopeType, host)
		scopeRows = append(scopeRows, semanticScopeRow{ref: ref, cfg: cfg, enabled: enabled, providerEnabled: providerEnabled})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return semanticFile{}, err
	}
	if err := rows.Close(); err != nil {
		return semanticFile{}, err
	}
	for _, row := range scopeRows {
		ref := row.ref
		cfg := row.cfg
		cfg.Enabled = boolFromDB(row.enabled)
		cfg.Provider.Enabled = boolFromDB(row.providerEnabled)
		cfg.ExemptPathPrefixes, err = loadPolicyStringList(s, `semantic_scope_values`, versionID, ref, `exempt_path_prefixes`)
		if err != nil {
			return semanticFile{}, err
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

func (s *wafEventStore) insertNotificationConfigTx(tx *sql.Tx, versionID int64, cfg notificationConfig) error {
	if _, err := s.txExec(tx, `INSERT INTO notification_settings (version_id, enabled, cooldown_seconds) VALUES (?, ?, ?)`, versionID, boolToDB(cfg.Enabled), cfg.CooldownSeconds); err != nil {
		return err
	}
	if _, err := s.txExec(tx, `INSERT INTO notification_triggers (version_id, category, enabled, window_seconds, active_threshold, escalated_threshold) VALUES (?, ?, ?, ?, ?, ?)`,
		versionID, `upstream`, boolToDB(cfg.Upstream.Enabled), cfg.Upstream.WindowSeconds, cfg.Upstream.ActiveThreshold, cfg.Upstream.EscalatedThreshold); err != nil {
		return err
	}
	if _, err := s.txExec(tx, `INSERT INTO notification_triggers (version_id, category, enabled, window_seconds, active_threshold, escalated_threshold) VALUES (?, ?, ?, ?, ?, ?)`,
		versionID, `security`, boolToDB(cfg.Security.Enabled), cfg.Security.WindowSeconds, cfg.Security.ActiveThreshold, cfg.Security.EscalatedThreshold); err != nil {
		return err
	}
	for i, source := range cfg.Security.Sources {
		if _, err := s.txExec(tx, `INSERT INTO notification_security_sources (version_id, position, source) VALUES (?, ?, ?)`, versionID, i, source); err != nil {
			return err
		}
	}
	for i, sink := range cfg.Sinks {
		if _, err := s.txExec(tx, `INSERT INTO notification_sinks (
			version_id, position, name, sink_type, enabled, timeout_seconds,
			webhook_url, smtp_address, smtp_username, smtp_password, from_address, subject_prefix
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			versionID, i, sink.Name, sink.Type, boolToDB(sink.Enabled), sink.TimeoutSec,
			sink.WebhookURL, sink.SMTPAddress, sink.SMTPUsername, sink.SMTPPassword, sink.From, sink.SubjectPrefix); err != nil {
			return err
		}
		headerNames := make([]string, 0, len(sink.Headers))
		for name := range sink.Headers {
			headerNames = append(headerNames, name)
		}
		sort.Strings(headerNames)
		for j, name := range headerNames {
			if _, err := s.txExec(tx, `INSERT INTO notification_sink_headers (version_id, sink_position, position, header_name, header_value) VALUES (?, ?, ?, ?, ?)`, versionID, i, j, name, sink.Headers[name]); err != nil {
				return err
			}
		}
		for j, recipient := range sink.To {
			if _, err := s.txExec(tx, `INSERT INTO notification_sink_recipients (version_id, sink_position, position, recipient) VALUES (?, ?, ?, ?)`, versionID, i, j, recipient); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *wafEventStore) loadNotificationConfigVersion(versionID int64) (notificationConfig, error) {
	var cfg notificationConfig
	var enabled int
	if err := s.queryRow(`SELECT enabled, cooldown_seconds FROM notification_settings WHERE version_id = ?`, versionID).Scan(&enabled, &cfg.CooldownSeconds); err != nil {
		return notificationConfig{}, err
	}
	cfg.Enabled = boolFromDB(enabled)
	triggerRows, err := s.query(`SELECT category, enabled, window_seconds, active_threshold, escalated_threshold FROM notification_triggers WHERE version_id = ? ORDER BY category`, versionID)
	if err != nil {
		return notificationConfig{}, err
	}
	for triggerRows.Next() {
		var category string
		var triggerEnabled int
		var trigger notificationTriggerConfig
		if err := triggerRows.Scan(&category, &triggerEnabled, &trigger.WindowSeconds, &trigger.ActiveThreshold, &trigger.EscalatedThreshold); err != nil {
			_ = triggerRows.Close()
			return notificationConfig{}, err
		}
		trigger.Enabled = boolFromDB(triggerEnabled)
		switch category {
		case "upstream":
			cfg.Upstream = trigger
		case "security":
			cfg.Security.Enabled = trigger.Enabled
			cfg.Security.WindowSeconds = trigger.WindowSeconds
			cfg.Security.ActiveThreshold = trigger.ActiveThreshold
			cfg.Security.EscalatedThreshold = trigger.EscalatedThreshold
		}
	}
	if err := triggerRows.Err(); err != nil {
		_ = triggerRows.Close()
		return notificationConfig{}, err
	}
	if err := triggerRows.Close(); err != nil {
		return notificationConfig{}, err
	}
	sources, err := s.loadNotificationSecuritySources(versionID)
	if err != nil {
		return notificationConfig{}, err
	}
	cfg.Security.Sources = sources
	sinks, err := s.loadNotificationSinks(versionID)
	if err != nil {
		return notificationConfig{}, err
	}
	cfg.Sinks = sinks
	return cfg, nil
}

func (s *wafEventStore) loadNotificationSecuritySources(versionID int64) ([]string, error) {
	rows, err := s.query(`SELECT source FROM notification_security_sources WHERE version_id = ? ORDER BY position`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []string
	for rows.Next() {
		var source string
		if err := rows.Scan(&source); err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

func (s *wafEventStore) loadNotificationSinks(versionID int64) ([]notificationSinkConfig, error) {
	rows, err := s.query(`SELECT position, name, sink_type, enabled, timeout_seconds, webhook_url, smtp_address, smtp_username, smtp_password, from_address, subject_prefix
		FROM notification_sinks WHERE version_id = ? ORDER BY position`, versionID)
	if err != nil {
		return nil, err
	}
	type notificationSinkRow struct {
		pos     int
		enabled int
		sink    notificationSinkConfig
	}
	var sinkRows []notificationSinkRow
	var sinks []notificationSinkConfig
	for rows.Next() {
		var pos int
		var enabled int
		var sink notificationSinkConfig
		if err := rows.Scan(&pos, &sink.Name, &sink.Type, &enabled, &sink.TimeoutSec, &sink.WebhookURL, &sink.SMTPAddress, &sink.SMTPUsername, &sink.SMTPPassword, &sink.From, &sink.SubjectPrefix); err != nil {
			return nil, err
		}
		sinkRows = append(sinkRows, notificationSinkRow{pos: pos, enabled: enabled, sink: sink})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, row := range sinkRows {
		sink := row.sink
		sink.Enabled = boolFromDB(row.enabled)
		headers, err := s.loadNotificationSinkHeaders(versionID, row.pos)
		if err != nil {
			return nil, err
		}
		sink.Headers = headers
		recipients, err := s.loadNotificationSinkRecipients(versionID, row.pos)
		if err != nil {
			return nil, err
		}
		sink.To = recipients
		sinks = append(sinks, sink)
	}
	return sinks, nil
}

func (s *wafEventStore) loadNotificationSinkHeaders(versionID int64, sinkPosition int) (map[string]string, error) {
	rows, err := s.query(`SELECT header_name, header_value FROM notification_sink_headers WHERE version_id = ? AND sink_position = ? ORDER BY position`, versionID, sinkPosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	headers := map[string]string{}
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		headers[name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(headers) == 0 {
		return nil, nil
	}
	return headers, nil
}

func (s *wafEventStore) loadNotificationSinkRecipients(versionID int64, sinkPosition int) ([]string, error) {
	rows, err := s.query(`SELECT recipient FROM notification_sink_recipients WHERE version_id = ? AND sink_position = ? ORDER BY position`, versionID, sinkPosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recipients []string
	for rows.Next() {
		var recipient string
		if err := rows.Scan(&recipient); err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient)
	}
	return recipients, rows.Err()
}
