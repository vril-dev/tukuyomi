package handler

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/cacheconf"
)

const (
	policyScopeTypeDefault = "default"
	policyScopeTypeHost    = "host"
)

type policyScopeRef struct {
	Type string
	Host string
}

func (s *wafEventStore) writeExplicitPolicyConfigVersion(expectedETag string, spec policyJSONConfigSpec, canonicalRaw []byte, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, error) {
	switch spec.Domain {
	case cacheConfigBlobKey:
		file, err := parseCacheRulesFileForDB(canonicalRaw)
		if err != nil {
			return configVersionRecord{}, err
		}
		return s.writeConfigVersion(spec.Domain, policyJSONConfigSchemaVersion, expectedETag, source, actor, reason, configContentHash(string(canonicalRaw)), restoredFromVersionID, func(tx *sql.Tx, versionID int64) error {
			return s.insertCacheRulesConfigTx(tx, versionID, file)
		})
	case bypassConfigBlobKey:
		file, err := bypassconf.Parse(string(canonicalRaw))
		if err != nil {
			return configVersionRecord{}, err
		}
		return s.writeConfigVersion(spec.Domain, policyJSONConfigSchemaVersion, expectedETag, source, actor, reason, configContentHash(string(canonicalRaw)), restoredFromVersionID, func(tx *sql.Tx, versionID int64) error {
			return s.insertBypassRulesConfigTx(tx, versionID, file)
		})
	case countryBlockConfigBlobKey:
		file, err := ParseCountryBlockRaw(string(canonicalRaw))
		if err != nil {
			return configVersionRecord{}, err
		}
		return s.writeConfigVersion(spec.Domain, policyJSONConfigSchemaVersion, expectedETag, source, actor, reason, configContentHash(string(canonicalRaw)), restoredFromVersionID, func(tx *sql.Tx, versionID int64) error {
			return s.insertCountryBlockConfigTx(tx, versionID, file)
		})
	case rateLimitConfigBlobKey:
		rt, err := ValidateRateLimitRaw(string(canonicalRaw))
		if err != nil {
			return configVersionRecord{}, err
		}
		return s.writeConfigVersion(spec.Domain, policyJSONConfigSchemaVersion, expectedETag, source, actor, reason, configContentHash(string(canonicalRaw)), restoredFromVersionID, func(tx *sql.Tx, versionID int64) error {
			return s.insertRateLimitConfigTx(tx, versionID, rt.Raw)
		})
	case botDefenseConfigBlobKey:
		rt, err := ValidateBotDefenseRaw(string(canonicalRaw))
		if err != nil {
			return configVersionRecord{}, err
		}
		return s.writeConfigVersion(spec.Domain, policyJSONConfigSchemaVersion, expectedETag, source, actor, reason, configContentHash(string(canonicalRaw)), restoredFromVersionID, func(tx *sql.Tx, versionID int64) error {
			return s.insertBotDefenseConfigTx(tx, versionID, rt.File)
		})
	case semanticConfigBlobKey:
		rt, err := ValidateSemanticRaw(string(canonicalRaw))
		if err != nil {
			return configVersionRecord{}, err
		}
		return s.writeConfigVersion(spec.Domain, policyJSONConfigSchemaVersion, expectedETag, source, actor, reason, configContentHash(string(canonicalRaw)), restoredFromVersionID, func(tx *sql.Tx, versionID int64) error {
			return s.insertSemanticConfigTx(tx, versionID, rt.File)
		})
	case notificationConfigBlobKey:
		rt, err := ValidateNotificationRaw(string(canonicalRaw))
		if err != nil {
			return configVersionRecord{}, err
		}
		return s.writeConfigVersion(spec.Domain, policyJSONConfigSchemaVersion, expectedETag, source, actor, reason, configContentHash(string(canonicalRaw)), restoredFromVersionID, func(tx *sql.Tx, versionID int64) error {
			return s.insertNotificationConfigTx(tx, versionID, rt.Raw)
		})
	case ipReputationConfigBlobKey:
		rt, err := ValidateIPReputationRaw(string(canonicalRaw))
		if err != nil {
			return configVersionRecord{}, err
		}
		return s.writeConfigVersion(spec.Domain, policyJSONConfigSchemaVersion, expectedETag, source, actor, reason, configContentHash(string(canonicalRaw)), restoredFromVersionID, func(tx *sql.Tx, versionID int64) error {
			return s.insertIPReputationConfigTx(tx, versionID, rt.Raw)
		})
	default:
		return configVersionRecord{}, fmt.Errorf("unknown policy domain: %s", spec.Domain)
	}
}

func (s *wafEventStore) loadExplicitPolicyConfigVersion(spec policyJSONConfigSpec, versionID int64) ([]byte, error) {
	switch spec.Domain {
	case cacheConfigBlobKey:
		file, err := s.loadCacheRulesConfigVersion(versionID)
		if err != nil {
			return nil, err
		}
		return marshalCacheRulesFileForDB(file)
	case bypassConfigBlobKey:
		file, err := s.loadBypassRulesConfigVersion(versionID)
		if err != nil {
			return nil, err
		}
		return bypassconf.MarshalJSON(file)
	case countryBlockConfigBlobKey:
		file, err := s.loadCountryBlockConfigVersion(versionID)
		if err != nil {
			return nil, err
		}
		return MarshalCountryBlockJSON(file)
	case rateLimitConfigBlobKey:
		file, err := s.loadRateLimitConfigVersion(versionID)
		if err != nil {
			return nil, err
		}
		return normalizeRateLimitPolicyRaw(mustJSON(file))
	case botDefenseConfigBlobKey:
		file, err := s.loadBotDefenseConfigVersion(versionID)
		if err != nil {
			return nil, err
		}
		return normalizeBotDefensePolicyRaw(mustJSON(file))
	case semanticConfigBlobKey:
		file, err := s.loadSemanticConfigVersion(versionID)
		if err != nil {
			return nil, err
		}
		return normalizeSemanticPolicyRaw(mustJSON(file))
	case notificationConfigBlobKey:
		cfg, err := s.loadNotificationConfigVersion(versionID)
		if err != nil {
			return nil, err
		}
		return normalizeNotificationPolicyRaw(mustJSON(cfg))
	case ipReputationConfigBlobKey:
		file, err := s.loadIPReputationConfigVersion(versionID)
		if err != nil {
			return nil, err
		}
		return normalizeIPReputationPolicyRaw(mustJSON(file))
	default:
		return nil, fmt.Errorf("unknown policy domain: %s", spec.Domain)
	}
}

func decodePolicyJSONStrict[T any](raw []byte) (T, error) {
	var out T
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return out, fmt.Errorf("invalid trailing json")
	}
	return out, nil
}

func parseCacheRulesFileForDB(raw []byte) (cacheconf.RulesFile, error) {
	rs, err := cacheconf.LoadFromBytes(raw)
	if err != nil {
		return cacheconf.RulesFile{}, err
	}
	normalized, err := cacheconf.RulesetToJSON(rs)
	if err != nil {
		return cacheconf.RulesFile{}, err
	}
	return decodePolicyJSONStrict[cacheconf.RulesFile](normalized)
}

func marshalCacheRulesFileForDB(file cacheconf.RulesFile) ([]byte, error) {
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func sortedPolicyHosts[T any](hosts map[string]T) []string {
	keys := make([]string, 0, len(hosts))
	for host := range hosts {
		keys = append(keys, host)
	}
	sort.Strings(keys)
	return keys
}

func policyScopedRows[T any](defaultScope T, hosts map[string]T) []struct {
	ref   policyScopeRef
	scope T
} {
	rows := []struct {
		ref   policyScopeRef
		scope T
	}{{ref: policyScopeRef{Type: policyScopeTypeDefault}, scope: defaultScope}}
	for _, host := range sortedPolicyHosts(hosts) {
		rows = append(rows, struct {
			ref   policyScopeRef
			scope T
		}{ref: policyScopeRef{Type: policyScopeTypeHost, Host: host}, scope: hosts[host]})
	}
	return rows
}

func insertPolicyStringListTx(s *wafEventStore, tx *sql.Tx, table string, versionID int64, ref policyScopeRef, listName string, values []string) error {
	stmt := fmt.Sprintf(`INSERT INTO %s (version_id, scope_type, host, list_name, position, value_text) VALUES (?, ?, ?, ?, ?, ?)`, table)
	for i, value := range values {
		if _, err := s.txExec(tx, stmt, versionID, ref.Type, ref.Host, listName, i, value); err != nil {
			return err
		}
	}
	return nil
}

func loadPolicyStringList(s *wafEventStore, table string, versionID int64, ref policyScopeRef, listName string) ([]string, error) {
	rows, err := s.query(fmt.Sprintf(`SELECT value_text FROM %s WHERE version_id = ? AND scope_type = ? AND host = ? AND list_name = ? ORDER BY position`, table), versionID, ref.Type, ref.Host, listName)
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

func policyRefFromRow(scopeType, host string) policyScopeRef {
	if scopeType == policyScopeTypeDefault {
		return policyScopeRef{Type: policyScopeTypeDefault}
	}
	return policyScopeRef{Type: policyScopeTypeHost, Host: host}
}

func policyRefKey(ref policyScopeRef) string {
	return ref.Type + "\x00" + ref.Host
}

func splitPolicyRefKey(key string) policyScopeRef {
	parts := strings.SplitN(key, "\x00", 2)
	ref := policyScopeRef{Type: parts[0]}
	if len(parts) == 2 {
		ref.Host = parts[1]
	}
	return ref
}
