package handler

import (
	"encoding/json"
	"fmt"
	"time"
)

func importRequestCountryStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}

	if raw, found, err := readFileMaybe(managedRequestCountryMMDBPath()); err != nil {
		return fmt.Errorf("read managed country mmdb seed file: %w", err)
	} else if found {
		if _, _, err := store.writeRequestCountryMMDBAssetVersion("", requestCountryMMDBAssetVersion{
			Present: true,
			Raw:     raw,
		}, configVersionSourceImport, "", "request country mmdb seed import", 0); err != nil {
			return fmt.Errorf("import managed country mmdb: %w", err)
		}
	}

	if raw, found, err := readFileMaybe(managedRequestCountryGeoIPConfigPath()); err != nil {
		return fmt.Errorf("read managed GeoIP.conf seed file: %w", err)
	} else if found {
		summary, parseErr := parseRequestCountryGeoIPConfig(raw)
		if parseErr != nil {
			return fmt.Errorf("validate managed GeoIP.conf seed file: %w", parseErr)
		}
		if _, _, err := store.writeRequestCountryGeoIPConfigVersion("", requestCountryGeoIPConfigVersion{
			Present: true,
			Raw:     raw,
			Summary: summary,
		}, configVersionSourceImport, "", "request country GeoIP config seed import", 0); err != nil {
			return fmt.Errorf("import managed GeoIP.conf: %w", err)
		}
	}

	if raw, found, err := readFileMaybe(managedRequestCountryUpdateStatusPath()); err != nil {
		return fmt.Errorf("read managed GeoIP update status seed file: %w", err)
	} else if found {
		var state requestCountryUpdateState
		if err := json.Unmarshal(raw, &state); err != nil {
			return fmt.Errorf("decode managed GeoIP update status seed file: %w", err)
		}
		if err := store.upsertRequestCountryUpdateState(state, zeroOrNowRequestCountryUpdateState(state)); err != nil {
			return fmt.Errorf("import managed GeoIP update status: %w", err)
		}
	}

	return nil
}

func zeroOrNowRequestCountryUpdateState(state requestCountryUpdateState) (tsTime time.Time) {
	if state.LastAttempt != "" {
		if ts, err := time.Parse(time.RFC3339Nano, state.LastAttempt); err == nil {
			return ts.UTC()
		}
	}
	return time.Now().UTC()
}
