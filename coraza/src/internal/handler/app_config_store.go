package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"tukuyomi/internal/config"
)

const (
	appConfigDomain        = "app_config"
	appConfigSchemaVersion = 1

	appConfigValueKindBool   = "bool"
	appConfigValueKindFloat  = "float"
	appConfigValueKindInt    = "int"
	appConfigValueKindString = "string"
)

var appConfigBootstrapOnlyPaths = map[string]struct{}{
	"storage.db_driver": {},
	"storage.db_dsn":    {},
	"storage.db_path":   {},
}

type appConfigScalarValue struct {
	Path string
	Kind string
	Text string
	Int  int64
	Real float64
	Bool int
}

type appConfigListValue struct {
	Path   string
	Values []string
}

func appConfigTypedState(cfg config.AppConfigFile) ([]appConfigScalarValue, []appConfigListValue, error) {
	var scalars []appConfigScalarValue
	var lists []appConfigListValue
	if err := flattenAppConfigValue(reflect.ValueOf(cfg), "", &scalars, &lists); err != nil {
		return nil, nil, err
	}
	sort.Slice(scalars, func(i, j int) bool { return scalars[i].Path < scalars[j].Path })
	sort.Slice(lists, func(i, j int) bool { return lists[i].Path < lists[j].Path })
	return scalars, lists, nil
}

func flattenAppConfigValue(v reflect.Value, prefix string, scalars *[]appConfigScalarValue, lists *[]appConfigListValue) error {
	if !v.IsValid() {
		return nil
	}
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			name := appConfigJSONFieldName(field)
			if name == "" {
				continue
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			if _, skip := appConfigBootstrapOnlyPaths[path]; skip {
				continue
			}
			if err := flattenAppConfigValue(v.Field(i), path, scalars, lists); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("unsupported app config list %s", prefix)
		}
		values := make([]string, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			values = append(values, v.Index(i).String())
		}
		*lists = append(*lists, appConfigListValue{Path: prefix, Values: values})
	case reflect.String:
		*scalars = append(*scalars, appConfigScalarValue{Path: prefix, Kind: appConfigValueKindString, Text: v.String()})
	case reflect.Bool:
		*scalars = append(*scalars, appConfigScalarValue{Path: prefix, Kind: appConfigValueKindBool, Bool: boolToDB(v.Bool())})
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		*scalars = append(*scalars, appConfigScalarValue{Path: prefix, Kind: appConfigValueKindInt, Int: v.Int()})
	case reflect.Float32, reflect.Float64:
		*scalars = append(*scalars, appConfigScalarValue{Path: prefix, Kind: appConfigValueKindFloat, Real: v.Float()})
	default:
		return fmt.Errorf("unsupported app config field %s kind %s", prefix, v.Kind())
	}
	return nil
}

func appConfigJSONFieldName(field reflect.StructField) string {
	if field.PkgPath != "" {
		return ""
	}
	tag := field.Tag.Get("json")
	name := strings.Split(tag, ",")[0]
	if name == "-" {
		return ""
	}
	if name != "" {
		return name
	}
	return field.Name
}

func appConfigTypedStateHash(scalars []appConfigScalarValue, lists []appConfigListValue) string {
	var b strings.Builder
	for _, value := range scalars {
		b.WriteString("S\t")
		b.WriteString(value.Path)
		b.WriteString("\t")
		b.WriteString(value.Kind)
		b.WriteString("\t")
		switch value.Kind {
		case appConfigValueKindString:
			b.WriteString(value.Text)
		case appConfigValueKindBool:
			b.WriteString(strconv.Itoa(value.Bool))
		case appConfigValueKindInt:
			b.WriteString(strconv.FormatInt(value.Int, 10))
		case appConfigValueKindFloat:
			b.WriteString(strconv.FormatFloat(value.Real, 'g', -1, 64))
		}
		b.WriteByte('\n')
	}
	for _, list := range lists {
		b.WriteString("L\t")
		b.WriteString(list.Path)
		for _, value := range list.Values {
			b.WriteString("\t")
			b.WriteString(value)
		}
		b.WriteByte('\n')
	}
	return configContentHash(b.String())
}

func (s *wafEventStore) loadActiveAppConfig(bootstrap config.AppConfigFile) (config.AppConfigFile, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(appConfigDomain)
	if err != nil || !found {
		return config.AppConfigFile{}, configVersionRecord{}, false, err
	}
	cfg, err := s.loadAppConfigVersion(rec.VersionID, bootstrap)
	if err != nil {
		return config.AppConfigFile{}, configVersionRecord{}, false, err
	}
	return cfg, rec, true, nil
}

func (s *wafEventStore) writeAppConfigVersion(expectedETag string, candidate config.AppConfigFile, bootstrap config.AppConfigFile, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, config.AppConfigFile, error) {
	cfg, _, err := appConfigBlobRawFromCandidate(candidate, bootstrap)
	if err != nil {
		return configVersionRecord{}, config.AppConfigFile{}, err
	}
	scalars, lists, err := appConfigTypedState(cfg)
	if err != nil {
		return configVersionRecord{}, config.AppConfigFile{}, err
	}
	rec, err := s.writeConfigVersion(
		appConfigDomain,
		appConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		appConfigTypedStateHash(scalars, lists),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			return s.insertAppConfigRowsTx(tx, versionID, scalars, lists)
		},
	)
	if err != nil {
		return configVersionRecord{}, config.AppConfigFile{}, err
	}
	return rec, cfg, nil
}

func (s *wafEventStore) insertAppConfigRowsTx(tx *sql.Tx, versionID int64, scalars []appConfigScalarValue, lists []appConfigListValue) error {
	for _, value := range scalars {
		if _, err := s.txExec(
			tx,
			`INSERT INTO app_config_values (version_id, path, value_kind, value_text, value_int, value_real, value_bool) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			versionID,
			value.Path,
			value.Kind,
			value.Text,
			value.Int,
			value.Real,
			value.Bool,
		); err != nil {
			return err
		}
	}
	for _, list := range lists {
		if _, err := s.txExec(tx, `INSERT INTO app_config_lists (version_id, path) VALUES (?, ?)`, versionID, list.Path); err != nil {
			return err
		}
		for i, value := range list.Values {
			if _, err := s.txExec(tx, `INSERT INTO app_config_list_values (version_id, path, position, value_text) VALUES (?, ?, ?, ?)`, versionID, list.Path, i, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *wafEventStore) loadAppConfigVersion(versionID int64, bootstrap config.AppConfigFile) (config.AppConfigFile, error) {
	scalars, err := s.loadAppConfigScalarRows(versionID)
	if err != nil {
		return config.AppConfigFile{}, err
	}
	lists, err := s.loadAppConfigListRows(versionID)
	if err != nil {
		return config.AppConfigFile{}, err
	}
	cfg := bootstrap
	if err := applyAppConfigTypedRows(&cfg, scalars, lists); err != nil {
		return config.AppConfigFile{}, err
	}
	preserveBootstrapDBConnection(&cfg, bootstrap)
	normalized, err := config.NormalizeAndValidateAppConfigFile(cfg)
	if err != nil {
		return config.AppConfigFile{}, err
	}
	preserveBootstrapDBConnection(&normalized, bootstrap)
	return normalized, nil
}

func (s *wafEventStore) loadAppConfigScalarRows(versionID int64) (map[string]appConfigScalarValue, error) {
	rows, err := s.query(`SELECT path, value_kind, value_text, value_int, value_real, value_bool FROM app_config_values WHERE version_id = ? ORDER BY path`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]appConfigScalarValue{}
	for rows.Next() {
		var value appConfigScalarValue
		if err := rows.Scan(&value.Path, &value.Kind, &value.Text, &value.Int, &value.Real, &value.Bool); err != nil {
			return nil, err
		}
		out[value.Path] = value
	}
	return out, rows.Err()
}

func (s *wafEventStore) loadAppConfigListRows(versionID int64) (map[string][]string, error) {
	listRows, err := s.query(`SELECT path FROM app_config_lists WHERE version_id = ? ORDER BY path`, versionID)
	if err != nil {
		return nil, err
	}
	paths := map[string][]string{}
	for listRows.Next() {
		var path string
		if err := listRows.Scan(&path); err != nil {
			_ = listRows.Close()
			return nil, err
		}
		paths[path] = nil
	}
	if err := listRows.Err(); err != nil {
		_ = listRows.Close()
		return nil, err
	}
	if err := listRows.Close(); err != nil {
		return nil, err
	}

	valueRows, err := s.query(`SELECT path, value_text FROM app_config_list_values WHERE version_id = ? ORDER BY path, position`, versionID)
	if err != nil {
		return nil, err
	}
	defer valueRows.Close()
	for valueRows.Next() {
		var path, value string
		if err := valueRows.Scan(&path, &value); err != nil {
			return nil, err
		}
		paths[path] = append(paths[path], value)
	}
	return paths, valueRows.Err()
}

func applyAppConfigTypedRows(cfg *config.AppConfigFile, scalars map[string]appConfigScalarValue, lists map[string][]string) error {
	if cfg == nil {
		return errors.New("app config is nil")
	}
	return applyAppConfigValueRows(reflect.ValueOf(cfg).Elem(), "", scalars, lists)
}

func applyAppConfigValueRows(v reflect.Value, prefix string, scalars map[string]appConfigScalarValue, lists map[string][]string) error {
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		name := appConfigJSONFieldName(field)
		if name == "" {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		if _, skip := appConfigBootstrapOnlyPaths[path]; skip {
			continue
		}
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.Struct:
			if err := applyAppConfigValueRows(fv, path, scalars, lists); err != nil {
				return err
			}
		case reflect.Slice:
			values, found := lists[path]
			if !found {
				continue
			}
			if fv.Type().Elem().Kind() != reflect.String {
				return fmt.Errorf("unsupported app config list %s", path)
			}
			next := reflect.MakeSlice(fv.Type(), len(values), len(values))
			for j, value := range values {
				next.Index(j).SetString(value)
			}
			fv.Set(next)
		default:
			value, found := scalars[path]
			if !found {
				continue
			}
			if err := setAppConfigScalarValue(fv, value); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
	}
	return nil
}

func setAppConfigScalarValue(v reflect.Value, value appConfigScalarValue) error {
	if !v.CanSet() {
		return errors.New("field cannot be set")
	}
	switch v.Kind() {
	case reflect.String:
		if value.Kind != appConfigValueKindString {
			return fmt.Errorf("kind=%s want string", value.Kind)
		}
		v.SetString(value.Text)
	case reflect.Bool:
		if value.Kind != appConfigValueKindBool {
			return fmt.Errorf("kind=%s want bool", value.Kind)
		}
		v.SetBool(boolFromDB(value.Bool))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if value.Kind != appConfigValueKindInt {
			return fmt.Errorf("kind=%s want int", value.Kind)
		}
		if v.OverflowInt(value.Int) {
			return fmt.Errorf("integer overflow %d", value.Int)
		}
		v.SetInt(value.Int)
	case reflect.Float32:
		if value.Kind != appConfigValueKindFloat {
			return fmt.Errorf("kind=%s want float", value.Kind)
		}
		if value.Real > math.MaxFloat32 || value.Real < -math.MaxFloat32 {
			return fmt.Errorf("float32 overflow %f", value.Real)
		}
		v.SetFloat(value.Real)
	case reflect.Float64:
		if value.Kind != appConfigValueKindFloat {
			return fmt.Errorf("kind=%s want float", value.Kind)
		}
		v.SetFloat(value.Real)
	default:
		return fmt.Errorf("unsupported kind %s", v.Kind())
	}
	return nil
}
