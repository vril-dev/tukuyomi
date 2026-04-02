package cacheconf

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

func Watch(target string, onReload func(*Ruleset)) (func() error, error) {
	abs, _ := filepath.Abs(target)
	dir := filepath.Dir(abs)
	file := filepath.Base(abs)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	if err := w.Add(dir); err != nil {
		_ = w.Close()
		return nil, err
	}
	_ = w.Add(abs)

	rs, err := Load(abs)
	if err == nil {
		Set(rs)
		onReload(rs)
		log.Printf("[CACHE] loaded %d rules (initial)", len(rs.Rules))
	} else {
		log.Printf("[CACHE] initial load skipped: %v", err)
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		var timer *time.Timer
		fire := func() {
			rs, err := Load(abs)
			if err != nil {
				log.Printf("[CACHE] reload failed: %v (keeping previous rules)", err)
				return
			}

			Set(rs)
			onReload(rs)
			log.Printf("[CACHE] reloaded: %d rules", len(rs.Rules))
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

				if filepath.Base(ev.Name) != file {
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
