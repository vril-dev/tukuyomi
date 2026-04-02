package bypassconf

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
)

var (
	confPath  string
	mu        sync.RWMutex
	entries   []Entry
	watcher   *fsnotify.Watcher
	watcherMu sync.Mutex
	watchStop chan struct{}
	watchDone chan struct{}
)

func Init(path string) error {
	stopWatcher()

	mu.Lock()
	confPath = path
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

func Get() []Entry {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Entry, len(entries))
	copy(out, entries)

	return out
}

func Match(reqPath string) MatchResult {
	p := normalize(reqPath)
	mu.RLock()
	defer mu.RUnlock()
	bypassHit := false
	for _, e := range entries {
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
	path := GetPath()

	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	es, err := Parse(string(b))
	if err != nil {
		return err
	}

	mu.Lock()
	entries = es
	mu.Unlock()
	log.Printf("[BYPASS][RELOAD] path=%s entries=%d", path, len(es))

	return nil
}

func Parse(s string) ([]Entry, error) {
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
			return nil, fmt.Errorf("line %d: expected '<path>' or '<path> <rule.conf>'", lineNo)
		}
		if !strings.HasPrefix(parts[0], "/") {
			return nil, fmt.Errorf("line %d: path must start with '/'", lineNo)
		}

		e := Entry{Path: normalize(parts[0])}
		if len(parts) == 2 {
			rule := strings.TrimSpace(parts[1])
			if !strings.HasSuffix(strings.ToLower(rule), ".conf") {
				return nil, fmt.Errorf("line %d: extra rule must be .conf file", lineNo)
			}
			e.ExtraRule = rule
		}

		out = append(out, e)
	}

	return out, sc.Err()
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
	dir := filepath.Dir(path)
	if err := w.Add(dir); err != nil {
		return err
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

				if filepath.Clean(ev.Name) == filepath.Clean(path) ||
					filepath.Base(ev.Name) == filepath.Base(path) {
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
