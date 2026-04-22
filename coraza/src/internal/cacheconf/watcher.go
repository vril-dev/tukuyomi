package cacheconf

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

func Watch(target, legacyTarget string, onReload func(*Ruleset)) (func() error, error) {
	abs, _ := filepath.Abs(target)
	legacyAbs := ""
	if legacyTarget != "" {
		legacyAbs, _ = filepath.Abs(legacyTarget)
	}
	dirs := []string{filepath.Dir(abs)}
	if legacyAbs != "" {
		legacyDir := filepath.Dir(legacyAbs)
		if legacyDir != dirs[0] {
			dirs = append(dirs, legacyDir)
		}
	}
	file := filepath.Base(abs)
	legacyFile := ""
	if legacyAbs != "" {
		legacyFile = filepath.Base(legacyAbs)
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	for _, dir := range dirs {
		if err := w.Add(dir); err != nil {
			_ = w.Close()
			return nil, err
		}
	}
	_ = w.Add(abs)
	if legacyAbs != "" {
		_ = w.Add(legacyAbs)
	}

	loadPath := resolveWatchLoadPath(abs, legacyAbs)
	rs, err := Load(loadPath)
	if err == nil {
		Set(rs)
		onReload(rs)
		log.Printf("[CACHE] loaded %d rules (initial path=%s)", RuleCount(rs), loadPath)
	} else {
		log.Printf("[CACHE] initial load skipped: %v", err)
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		var timer *time.Timer
		fire := func() {
			loadPath := resolveWatchLoadPath(abs, legacyAbs)
			rs, err := Load(loadPath)
			if err != nil {
				log.Printf("[CACHE] reload failed: %v (keeping previous rules)", err)
				return
			}

			Set(rs)
			onReload(rs)
			log.Printf("[CACHE] reloaded: %d rules path=%s", RuleCount(rs), loadPath)
		}

		schedule := func() {
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
			timer = time.AfterFunc(200*time.Millisecond, fire)
		}

		for {
			select {
			case ev, ok := <-w.Events:
				if !ok {
					return
				}

				base := filepath.Base(ev.Name)
				if base != file && base != legacyFile {
					continue
				}

				switch {
				case ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove|fsnotify.Chmod) != 0:
					schedule()
				}
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				log.Printf("[CACHE] watcher error: %v", err)
			}
		}
	}()

	stop := func() error {
		_ = w.Close()
		<-done
		return nil
	}

	return stop, nil
}

func resolveWatchLoadPath(primary, legacy string) string {
	if _, err := os.Stat(primary); err == nil {
		return primary
	}
	if legacy != "" {
		if _, err := os.Stat(legacy); err == nil {
			return legacy
		}
	}
	return primary
}

func EnsureFile(path string) error {
	_, statErr := os.Stat(path)
	if statErr == nil {
		return nil
	}

	if !os.IsNotExist(statErr) {
		return statErr
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	return f.Close()
}
