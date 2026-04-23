package waf

import (
	"bytes"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

type RuleAsset struct {
	Path string
	Raw  []byte
}

type RuleAssetBundle struct {
	ETag   string
	Assets []RuleAsset
}

type RuleAssetProvider func() (RuleAssetBundle, bool, error)

type CRSDisabledProvider func() (map[string]struct{}, bool, error)

type OverrideRuleSource struct {
	Raw  []byte
	ETag string
	Name string
}

type OverrideRuleLoader func(rule string) (OverrideRuleSource, bool, error)

var (
	ruleAssetProviderMu sync.RWMutex
	ruleAssetProvider   RuleAssetProvider

	crsDisabledProviderMu sync.RWMutex
	crsDisabledProvider   CRSDisabledProvider

	overrideRuleLoaderMu sync.RWMutex
	overrideRuleLoader   OverrideRuleLoader
)

func SetRuleAssetProvider(provider RuleAssetProvider) {
	ruleAssetProviderMu.Lock()
	ruleAssetProvider = provider
	ruleAssetProviderMu.Unlock()
}

func SetCRSDisabledProvider(provider CRSDisabledProvider) {
	crsDisabledProviderMu.Lock()
	crsDisabledProvider = provider
	crsDisabledProviderMu.Unlock()
}

func SetOverrideRuleLoader(loader OverrideRuleLoader) {
	overrideRuleLoaderMu.Lock()
	overrideRuleLoader = loader
	overrideRuleLoaderMu.Unlock()
}

func currentRuleAssetProvider() RuleAssetProvider {
	ruleAssetProviderMu.RLock()
	provider := ruleAssetProvider
	ruleAssetProviderMu.RUnlock()
	return provider
}

func currentCRSDisabledProvider() CRSDisabledProvider {
	crsDisabledProviderMu.RLock()
	provider := crsDisabledProvider
	crsDisabledProviderMu.RUnlock()
	return provider
}

func currentOverrideRuleLoader() OverrideRuleLoader {
	overrideRuleLoaderMu.RLock()
	loader := overrideRuleLoader
	overrideRuleLoaderMu.RUnlock()
	return loader
}

type memoryRuleFS struct {
	files map[string][]byte
	dirs  map[string][]fs.DirEntry
}

func newMemoryRuleFS(assets []RuleAsset) *memoryRuleFS {
	files := make(map[string][]byte, len(assets))
	dirNames := map[string]map[string]fs.DirEntry{}
	ensureDir := func(dir string) {
		dir = normalizeRuleFSName(dir)
		if _, ok := dirNames[dir]; !ok {
			dirNames[dir] = map[string]fs.DirEntry{}
		}
	}
	ensureDir(".")

	for _, asset := range assets {
		name := normalizeRuleFSName(asset.Path)
		if name == "." || name == "" {
			continue
		}
		raw := append([]byte(nil), asset.Raw...)
		files[name] = raw

		dir := path.Dir(name)
		base := path.Base(name)
		ensureDir(dir)
		dirNames[dir][base] = memoryRuleDirEntry{name: base, isDir: false, size: int64(len(raw))}
		for dir != "." && dir != "/" {
			parent := path.Dir(dir)
			ensureDir(parent)
			dirNames[parent][path.Base(dir)] = memoryRuleDirEntry{name: path.Base(dir), isDir: true}
			dir = parent
		}
	}

	dirs := make(map[string][]fs.DirEntry, len(dirNames))
	for dir, entries := range dirNames {
		names := make([]string, 0, len(entries))
		for name := range entries {
			names = append(names, name)
		}
		sort.Strings(names)
		list := make([]fs.DirEntry, 0, len(names))
		for _, name := range names {
			list = append(list, entries[name])
		}
		dirs[dir] = list
	}

	return &memoryRuleFS{files: files, dirs: dirs}
}

func normalizeRuleFSName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "." {
		return "."
	}
	clean := path.Clean(strings.ReplaceAll(name, "\\", "/"))
	if clean == "" {
		return "."
	}
	return clean
}

func (m *memoryRuleFS) Open(name string) (fs.File, error) {
	name = normalizeRuleFSName(name)
	if raw, ok := m.files[name]; ok {
		return &memoryRuleFile{
			name:   path.Base(name),
			reader: bytes.NewReader(raw),
			size:   int64(len(raw)),
		}, nil
	}
	if entries, ok := m.dirs[name]; ok {
		return &memoryRuleDir{name: path.Base(name), entries: entries}, nil
	}
	return nil, fs.ErrNotExist
}

func (m *memoryRuleFS) ReadFile(name string) ([]byte, error) {
	name = normalizeRuleFSName(name)
	raw, ok := m.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), raw...), nil
}

func (m *memoryRuleFS) ReadDir(name string) ([]fs.DirEntry, error) {
	name = normalizeRuleFSName(name)
	entries, ok := m.dirs[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	out := make([]fs.DirEntry, len(entries))
	copy(out, entries)
	return out, nil
}

type memoryRuleFile struct {
	name   string
	reader *bytes.Reader
	size   int64
}

func (f *memoryRuleFile) Stat() (fs.FileInfo, error) {
	return memoryRuleFileInfo{name: f.name, size: f.size}, nil
}

func (f *memoryRuleFile) Read(p []byte) (int, error) {
	return f.reader.Read(p)
}

func (f *memoryRuleFile) Close() error { return nil }

type memoryRuleDir struct {
	name    string
	entries []fs.DirEntry
	offset  int
}

func (d *memoryRuleDir) Stat() (fs.FileInfo, error) {
	return memoryRuleFileInfo{name: d.name, dir: true}, nil
}

func (d *memoryRuleDir) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (d *memoryRuleDir) Close() error { return nil }

func (d *memoryRuleDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.offset >= len(d.entries) && n > 0 {
		return nil, io.EOF
	}
	if n <= 0 || d.offset+n > len(d.entries) {
		n = len(d.entries) - d.offset
	}
	out := make([]fs.DirEntry, n)
	copy(out, d.entries[d.offset:d.offset+n])
	d.offset += n
	return out, nil
}

type memoryRuleDirEntry struct {
	name  string
	isDir bool
	size  int64
}

func (e memoryRuleDirEntry) Name() string { return e.name }
func (e memoryRuleDirEntry) IsDir() bool  { return e.isDir }
func (e memoryRuleDirEntry) Type() fs.FileMode {
	if e.isDir {
		return fs.ModeDir
	}
	return 0
}
func (e memoryRuleDirEntry) Info() (fs.FileInfo, error) {
	return memoryRuleFileInfo{name: e.name, dir: e.isDir, size: e.size}, nil
}

type memoryRuleFileInfo struct {
	name string
	dir  bool
	size int64
}

func (i memoryRuleFileInfo) Name() string { return i.name }
func (i memoryRuleFileInfo) Size() int64  { return i.size }
func (i memoryRuleFileInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
func (i memoryRuleFileInfo) ModTime() time.Time { return time.Time{} }
func (i memoryRuleFileInfo) IsDir() bool        { return i.dir }
func (i memoryRuleFileInfo) Sys() any           { return nil }
