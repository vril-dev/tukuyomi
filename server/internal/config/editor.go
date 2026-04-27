package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type AppConfigFile = appConfigFile

func LoadAppConfigFile(path string) (AppConfigFile, error) {
	return loadAppConfigFile(path)
}

func DecodeAppConfigRaw(raw []byte) (AppConfigFile, error) {
	cfg := defaultAppConfigFile()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return AppConfigFile{}, fmt.Errorf("decode json: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return AppConfigFile{}, fmt.Errorf("invalid json: multiple JSON values")
		}
		return AppConfigFile{}, fmt.Errorf("invalid json: %w", err)
	}
	return cfg, nil
}

func LoadAppConfigRaw(raw []byte) (AppConfigFile, error) {
	cfg, err := DecodeAppConfigRaw(raw)
	if err != nil {
		return AppConfigFile{}, err
	}
	return NormalizeAndValidateAppConfigFile(cfg)
}

func NormalizeAndValidateAppConfigFile(cfg AppConfigFile) (AppConfigFile, error) {
	normalizeAppConfigFile(&cfg)
	if err := validateAppConfigFile(cfg); err != nil {
		return AppConfigFile{}, err
	}
	return cfg, nil
}

func MarshalAppConfigFile(cfg AppConfigFile) (string, error) {
	normalized, err := NormalizeAndValidateAppConfigFile(cfg)
	if err != nil {
		return "", err
	}
	body, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body) + "\n", nil
}

func ApplyAppConfigFile(cfg AppConfigFile) error {
	normalized, err := NormalizeAndValidateAppConfigFile(cfg)
	if err != nil {
		return err
	}
	applyAppConfig(normalized)
	enforceSecureDefaults()
	emitAdminExposureWarnings()
	return nil
}
