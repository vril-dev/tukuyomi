package bypassconf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"tukuyomi/internal/policyhost"
)

var (
	confPath   string
	legacyPath string
	activePath string
	mu         sync.RWMutex
	fileState  File
	watcher    *fsnotify.Watcher
	watcherMu  sync.Mutex
	watchStop  chan struct{}
	watchDone  chan struct{}
)

func Init(path, legacy string) error {
	stopWatcher()

	mu.Lock()
	confPath = path
	legacyPath = strings.TrimSpace(legacy)
	activePath = ""
	mu.Unlock()

	if err := reload(); err != nil {
		return err
	}

	return startWatch()
}

func GetPath() string {
	mu.RLock()
	defer mu.RUnlock()
	return confPath
}

func GetActivePath() string {
	mu.RLock()
	defer mu.RUnlock()
	return activePath
}

func Get() []Entry {
	mu.RLock()
	defer mu.RUnlock()
	return flattenFile(fileState)
}

func GetEntries(file File) []Entry {
	return flattenFile(file)
}

func GetFile() File {
	mu.RLock()
	defer mu.RUnlock()
	return cloneFile(fileState)
}

func Match(reqHost, reqPath string, tls bool) MatchResult {
	p := normalize(reqPath)
	mu.RLock()
	cfg := cloneFile(fileState)
	defer mu.RUnlock()

	matchedEntries := scopedEntries(cfg, reqHost, tls)
	bypassHit := false
	for _, e := range matchedEntries {
		if !pathMatches(p, e.Path) {
			continue
		}
		if e.ExtraRule != "" {
			return MatchResult{Action: ACTION_RULE, ExtraRule: e.ExtraRule}
		}
		bypassHit = true
	}
	if bypassHit {
		return MatchResult{Action: ACTION_BYPASS}
	}

	return MatchResult{Action: ACTION_NONE}
}

func pathMatches(reqPath, rulePath string) bool {
	normalizedRulePath := normalize(rulePath)
	if eqLoosely(reqPath, normalizedRulePath) {
		return true
	}

	return strings.HasSuffix(normalizedRulePath, "/") && strings.HasPrefix(reqPath, normalizedRulePath)
}

func reload() error {
	path := resolveLoadPath()

	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	cfg, err := Parse(string(b))
	if err != nil {
		return err
	}

	mu.Lock()
	fileState = cfg
	activePath = path
	mu.Unlock()
	log.Printf("[BYPASS][RELOAD] path=%s entries=%d hosts=%d", path, len(flattenFile(cfg)), len(cfg.Hosts))

	return nil
}

func resolveLoadPath() string {
	mu.RLock()
	path := confPath
	legacy := legacyPath
	mu.RUnlock()

	if _, err := os.Stat(path); err == nil {
		return path
	}
	if strings.TrimSpace(legacy) != "" {
		if _, err := os.Stat(legacy); err == nil {
			return legacy
		}
	}
	return path
}

func Parse(s string) (File, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return File{Default: Scope{Entries: []Entry{}}}, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		return parseJSON(trimmed)
	}

	sc := bufio.NewScanner(strings.NewReader(s))
	var out []Entry
	lineNo := 0

	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		if len(parts) > 2 {
			return File{}, fmt.Errorf("line %d: expected '<path>' or '<path> <rule.conf>'", lineNo)
		}
		e := Entry{Path: normalize(parts[0])}
		if len(parts) == 2 {
			rule := strings.TrimSpace(parts[1])
			e.ExtraRule = rule
		}
		if e.Path != parts[0] {
			return File{}, fmt.Errorf("line %d: path must start with '/'", lineNo)
		}
		if err := validateEntry(e, fmt.Sprintf("line %d", lineNo)); err != nil {
			return File{}, err
		}

		out = append(out, e)
	}

	if err := sc.Err(); err != nil {
		return File{}, err
	}
	return File{Default: Scope{Entries: out}}, nil
}

func parseJSON(raw string) (File, error) {
	var file struct {
		Default *Scope           `json:"default,omitempty"`
		Hosts   map[string]Scope `json:"hosts,omitempty"`
		Entries []Entry          `json:"entries,omitempty"`
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return File{}, err
	}

	if len(file.Entries) > 0 && (file.Default != nil || len(file.Hosts) > 0) {
		return File{}, fmt.Errorf("entries is legacy-only; use default.entries with hosts")
	}

	next := File{Default: Scope{Entries: []Entry{}}}
	if len(file.Entries) > 0 {
		next.Default.Entries = make([]Entry, 0, len(file.Entries))
		for i, entry := range file.Entries {
			entry.Path = normalize(entry.Path)
			entry.ExtraRule = strings.TrimSpace(entry.ExtraRule)
			if err := validateEntry(entry, fmt.Sprintf("entries[%d]", i)); err != nil {
				return File{}, err
			}
			next.Default.Entries = append(next.Default.Entries, entry)
		}
		return next, nil
	}

	if file.Default != nil {
		entries, err := normalizeEntries(file.Default.Entries, "default.entries")
		if err != nil {
			return File{}, err
		}
		next.Default.Entries = entries
	}
	if len(file.Hosts) == 0 {
		return next, nil
	}
	next.Hosts = make(map[string]Scope, len(file.Hosts))
	for rawHost, scope := range file.Hosts {
		hostKey, err := policyhost.NormalizePattern(rawHost)
		if err != nil {
			return File{}, fmt.Errorf("hosts[%q]: %w", rawHost, err)
		}
		entries, err := normalizeEntries(scope.Entries, fmt.Sprintf("hosts[%q].entries", rawHost))
		if err != nil {
			return File{}, err
		}
		next.Hosts[hostKey] = Scope{Entries: entries}
	}
	return next, nil
}

func validateEntry(e Entry, field string) error {
	if !strings.HasPrefix(e.Path, "/") {
		return fmt.Errorf("%s: path must start with '/'", field)
	}
	if e.ExtraRule != "" && !strings.HasSuffix(strings.ToLower(e.ExtraRule), ".conf") {
		return fmt.Errorf("%s: extra rule must be .conf file", field)
	}
	return nil
}

func MarshalJSON(file File) ([]byte, error) {
	file = cloneFile(file)
	if file.Default.Entries == nil {
		file.Default.Entries = []Entry{}
	}
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func normalizeEntries(entries []Entry, field string) ([]Entry, error) {
	if entries == nil {
		return []Entry{}, nil
	}
	out := make([]Entry, 0, len(entries))
	for i, entry := range entries {
		entry.Path = normalize(entry.Path)
		entry.ExtraRule = strings.TrimSpace(entry.ExtraRule)
		if err := validateEntry(entry, fmt.Sprintf("%s[%d]", field, i)); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

func cloneFile(in File) File {
	out := File{
		Default: Scope{Entries: append([]Entry(nil), in.Default.Entries...)},
	}
	if len(in.Hosts) > 0 {
		out.Hosts = make(map[string]Scope, len(in.Hosts))
		for host, scope := range in.Hosts {
			out.Hosts[host] = Scope{Entries: append([]Entry(nil), scope.Entries...)}
		}
	}
	return out
}

func flattenFile(in File) []Entry {
	out := append([]Entry(nil), in.Default.Entries...)
	if len(in.Hosts) == 0 {
		return out
	}
	for _, scope := range in.Hosts {
		out = append(out, scope.Entries...)
	}
	return out
}

func scopedEntries(in File, reqHost string, tls bool) []Entry {
	for _, candidate := range policyhost.Candidates(reqHost, tls) {
		if scope, ok := in.Hosts[candidate]; ok {
			return scope.Entries
		}
	}
	return in.Default.Entries
}

func startWatch() error {
	watcherMu.Lock()
	defer watcherMu.Unlock()

	if watcher != nil {
		return nil
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	path := GetPath()
	legacy := strings.TrimSpace(legacyPath)
	primaryBase := filepath.Base(path)
	legacyBase := ""
	dirs := []string{filepath.Dir(path)}
	if legacy != "" {
		legacyBase = filepath.Base(legacy)
		legacyDir := filepath.Dir(legacy)
		if legacyDir != dirs[0] {
			dirs = append(dirs, legacyDir)
		}
	}
	for _, dir := range dirs {
		if err := w.Add(dir); err != nil {
			return err
		}
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	watcher = w
	watchStop = stop
	watchDone = done

	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}

				base := filepath.Base(ev.Name)
				if filepath.Clean(ev.Name) == filepath.Clean(path) ||
					(legacy != "" && filepath.Clean(ev.Name) == filepath.Clean(legacy)) ||
					base == primaryBase ||
					(legacyBase != "" && base == legacyBase) {
					_ = reload()
				}
			case err := <-w.Errors:
				log.Printf("[BYPASS][WATCH][ERR] %v", err)
			}
		}
	}()

	return nil
}

func Reload() error { return reload() }

func stopWatcher() {
	watcherMu.Lock()
	w := watcher
	stop := watchStop
	done := watchDone
	watcher = nil
	watchStop = nil
	watchDone = nil
	watcherMu.Unlock()

	if stop != nil {
		close(stop)
	}
	if w != nil {
		_ = w.Close()
	}
	if done != nil {
		<-done
	}
}
