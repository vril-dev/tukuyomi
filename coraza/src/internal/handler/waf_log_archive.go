package handler

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"tukuyomi/internal/config"
)

type archivedWAFLogFile struct {
	Path    string
	Size    int64
	ModTime time.Time
	Active  bool
}

type wafLogArchive struct {
	mu        sync.Mutex
	lastPrune map[string]time.Time
}

var runtimeWAFLogArchive = &wafLogArchive{}

const wafLogArchivePruneInterval = time.Second

var jsonLineBreak = []byte{'\n'}

func appendEncodedWAFEvent(raw []byte, path string) error {
	return runtimeWAFLogArchive.AppendEncoded(raw, path)
}

func appendEncodedWAFEvents(raws [][]byte, path string) error {
	if len(raws) == 0 {
		return nil
	}
	if len(raws) == 1 {
		return appendEncodedWAFEvent(raws[0], path)
	}
	return runtimeWAFLogArchive.AppendEncodedBatch(raws, path)
}

func appendWAFEventRawLine(raw []byte, path string) error {
	return appendWAFEventRawLines([][]byte{raw}, path)
}

func appendWAFEventRawLines(raws [][]byte, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, raw := range raws {
		if err := writeJSONLine(f, raw); err != nil {
			return err
		}
	}
	return nil
}

func (a *wafLogArchive) Append(obj map[string]any, path string) error {
	raw, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return a.AppendEncoded(raw, path)
}

func (a *wafLogArchive) AppendEncoded(raw []byte, path string) error {
	return a.AppendEncodedBatch([][]byte{raw}, path)
}

func (a *wafLogArchive) AppendEncodedBatch(raws [][]byte, path string) error {
	if a == nil {
		return appendWAFEventRawLines(raws, path)
	}
	if len(raws) == 0 {
		return nil
	}
	lineLen := 0
	for _, raw := range raws {
		lineLen += len(raw) + len(jsonLineBreak)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC()
	rotated := false

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if config.FileRotateBytes > 0 {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 && info.Size()+int64(lineLen) > config.FileRotateBytes {
			if err := rotateWAFLogFile(path); err != nil {
				return err
			}
			rotated = true
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	for _, raw := range raws {
		if err := writeJSONLine(f, raw); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if !a.pruneDueLocked(path, now, rotated) {
		return nil
	}
	if err := pruneWAFLogArchives(path, now); err != nil {
		return err
	}
	a.markPrunedLocked(path, now)
	return nil
}

func writeJSONLine(w io.Writer, raw []byte) error {
	if _, err := w.Write(raw); err != nil {
		return err
	}
	_, err := w.Write(jsonLineBreak)
	return err
}

func (a *wafLogArchive) pruneDueLocked(path string, now time.Time, rotated bool) bool {
	if config.FileRetention <= 0 && config.FileMaxBytes <= 0 {
		return false
	}
	if rotated {
		return true
	}
	if a.lastPrune == nil {
		return true
	}
	last := a.lastPrune[path]
	return last.IsZero() || !now.Before(last.Add(wafLogArchivePruneInterval))
}

func (a *wafLogArchive) markPrunedLocked(path string, now time.Time) {
	if a.lastPrune == nil {
		a.lastPrune = make(map[string]time.Time, 1)
	}
	a.lastPrune[path] = now
}

func rotateWAFLogFile(path string) error {
	src, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer src.Close()

	archivePath := fmt.Sprintf("%s.%d.gz", path, time.Now().UTC().UnixNano())
	dst, err := os.OpenFile(archivePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(dst)
	if _, err := io.Copy(gz, src); err != nil {
		_ = gz.Close()
		_ = dst.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		_ = dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func pruneWAFLogArchives(path string, now time.Time) error {
	files, err := listManagedWAFLogFiles(path)
	if err != nil {
		return err
	}
	if config.FileRetention > 0 {
		cutoff := now.Add(-config.FileRetention)
		for _, file := range files {
			if file.Active {
				continue
			}
			if file.ModTime.Before(cutoff) {
				_ = os.Remove(file.Path)
			}
		}
		files, err = listManagedWAFLogFiles(path)
		if err != nil {
			return err
		}
	}
	if config.FileMaxBytes > 0 {
		total := int64(0)
		for _, file := range files {
			total += file.Size
		}
		if total > config.FileMaxBytes {
			sort.Slice(files, func(i, j int) bool {
				if files[i].ModTime.Equal(files[j].ModTime) {
					return files[i].Path < files[j].Path
				}
				return files[i].ModTime.Before(files[j].ModTime)
			})
			for _, file := range files {
				if total <= config.FileMaxBytes {
					break
				}
				if file.Active {
					continue
				}
				total -= file.Size
				_ = os.Remove(file.Path)
			}
		}
	}
	return nil
}

func listManagedWAFLogFiles(path string) ([]archivedWAFLogFile, error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]archivedWAFLogFile, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name != base && !strings.HasPrefix(name, base+".") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		out = append(out, archivedWAFLogFile{
			Path:    filepath.Join(dir, name),
			Size:    info.Size(),
			ModTime: info.ModTime().UTC(),
			Active:  name == base,
		})
	}
	return out, nil
}
