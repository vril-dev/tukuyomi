package config

import "encoding/json"

type AppConfigFile = appConfigFile

func LoadAppConfigFile(path string) (AppConfigFile, error) {
	return loadAppConfigFile(path)
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
