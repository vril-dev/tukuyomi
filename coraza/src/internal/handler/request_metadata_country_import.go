package handler

import "fmt"

func importRequestCountryStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	return nil
}
