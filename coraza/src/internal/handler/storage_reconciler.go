package handler

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

var storageSyncMu sync.Mutex

func SyncAllStorageFromDB() error {
	storageSyncMu.Lock()
	defer storageSyncMu.Unlock()

	type task struct {
		name string
		run  func() error
	}
	tasks := []task{
		{name: "sites", run: SyncSiteStorage},
		{name: "scheduled-tasks", run: SyncScheduledTaskStorage},
		{name: "upstream-runtime", run: SyncUpstreamRuntimeStorage},
		{name: "rules", run: SyncRuleFilesStorage},
		{name: "override-rules", run: SyncManagedOverrideRulesStorage},
		{name: "crs-disabled", run: SyncCRSDisabledStorage},
		{name: "bypass", run: SyncBypassStorage},
		{name: "country-block", run: SyncCountryBlockStorage},
		{name: "rate-limit", run: SyncRateLimitStorage},
		{name: "notifications", run: SyncNotificationStorage},
		{name: "bot-defense", run: SyncBotDefenseStorage},
		{name: "semantic", run: SyncSemanticStorage},
		{name: "cache-rules", run: SyncCacheRulesStorage},
		{name: "cache-store", run: SyncResponseCacheStoreStorage},
	}

	var errs []error
	for _, t := range tasks {
		if err := t.run(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.name, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func StartStorageSyncLoop(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := SyncAllStorageFromDB(); err != nil {
				log.Printf("[DB][SYNC][WARN] periodic sync failed: %v", err)
			}
		}
	}()
}
