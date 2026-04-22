package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type PHPRuntimeMaterializedStatus struct {
	RuntimeID       string   `json:"runtime_id"`
	BinaryPath      string   `json:"binary_path"`
	RunUser         string   `json:"run_user,omitempty"`
	RunGroup        string   `json:"run_group,omitempty"`
	RuntimeDir      string   `json:"runtime_dir"`
	ConfigFile      string   `json:"config_file"`
	PoolFiles       []string `json:"pool_files,omitempty"`
	DocumentRoots   []string `json:"document_roots,omitempty"`
	GeneratedTarget []string `json:"generated_targets,omitempty"`
}

type phpRuntimeMaterialization struct {
	RuntimeID       string
	BinaryPath      string
	RunUser         string
	RunGroup        string
	RuntimeDir      string
	ConfigFile      string
	PoolFiles       []string
	DocumentRoots   []string
	GeneratedTarget []string
	ConfigBody      string
	Pools           map[string]string
}

var (
	phpRuntimeMaterializationMu sync.RWMutex
	phpRuntimeMaterialized      map[string]PHPRuntimeMaterializedStatus
)

func RefreshPHPRuntimeMaterialization() error {
	return refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), currentVhostConfig())
}

func PHPRuntimeMaterializationSnapshot() []PHPRuntimeMaterializedStatus {
	phpRuntimeMaterializationMu.RLock()
	defer phpRuntimeMaterializationMu.RUnlock()
	out := make([]PHPRuntimeMaterializedStatus, 0, len(phpRuntimeMaterialized))
	for _, status := range phpRuntimeMaterialized {
		cp := status
		cp.PoolFiles = append([]string(nil), status.PoolFiles...)
		cp.DocumentRoots = append([]string(nil), status.DocumentRoots...)
		cp.GeneratedTarget = append([]string(nil), status.GeneratedTarget...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RuntimeID < out[j].RuntimeID
	})
	return out
}

func generatedVhostUpstreams(cfg VhostConfigFile) []ProxyUpstream {
	out := make([]ProxyUpstream, 0, len(cfg.Vhosts))
	for _, vhost := range cfg.Vhosts {
		appendAlias := func(name string, url string, kind string) {
			name = strings.TrimSpace(name)
			if name == "" {
				return
			}
			out = append(out, ProxyUpstream{
				Name:           name,
				URL:            url,
				Weight:         1,
				Enabled:        true,
				GeneratedKind:  kind,
				ProviderClass:  proxyUpstreamProviderClassVhostManaged,
				ManagedByVhost: vhost.Name,
			})
		}
		switch normalizeVhostMode(vhost.Mode) {
		case "php-fpm":
			targetURL := fmt.Sprintf("fcgi://127.0.0.1:%d", vhost.ListenPort)
			appendAlias(vhost.GeneratedTarget, targetURL, proxyUpstreamGeneratedKindVhostTarget)
		case "static":
			targetURL := fmt.Sprintf("static://%s", vhost.GeneratedTarget)
			appendAlias(vhost.GeneratedTarget, targetURL, proxyUpstreamGeneratedKindVhostTarget)
		}
	}
	return out
}

func vhostLinkedUpstreamTargetURL(vhost VhostConfig, upstream ProxyUpstream, upstreamIndex int) (string, bool, error) {
	switch normalizeVhostMode(vhost.Mode) {
	case "php-fpm":
		raw := strings.TrimSpace(upstream.URL)
		if raw != "" {
			target, err := parseProxyUpstreamURL(fmt.Sprintf("upstreams[%d].url", upstreamIndex), raw)
			if err != nil {
				return "", false, err
			}
			if strings.EqualFold(strings.TrimSpace(target.Scheme), "fcgi") {
				return target.String(), true, nil
			}
		}
		return fmt.Sprintf("fcgi://127.0.0.1:%d", vhost.ListenPort), true, nil
	case "static":
		return fmt.Sprintf("static://%s", vhost.GeneratedTarget), true, nil
	default:
		return "", false, nil
	}
}

func refreshPHPRuntimeMaterializationWithConfig(inventory PHPRuntimeInventoryFile, vhosts VhostConfigFile) error {
	desired, rootDir, err := buildPHPRuntimeMaterializations(inventory, vhosts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return err
	}
	for runtimeID, materialized := range desired {
		if err := writePHPRuntimeMaterialization(materialized); err != nil {
			return err
		}
		if err := deleteStalePoolFiles(materialized); err != nil {
			return err
		}
		desired[runtimeID] = materialized
	}

	entries, err := os.ReadDir(rootDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			runtimeID := entry.Name()
			if _, ok := desired[runtimeID]; ok {
				continue
			}
			if err := os.RemoveAll(filepath.Join(rootDir, runtimeID)); err != nil {
				return err
			}
		}
	}

	next := make(map[string]PHPRuntimeMaterializedStatus, len(desired))
	for runtimeID, materialized := range desired {
		next[runtimeID] = PHPRuntimeMaterializedStatus{
			RuntimeID:       runtimeID,
			BinaryPath:      materialized.BinaryPath,
			RunUser:         materialized.RunUser,
			RunGroup:        materialized.RunGroup,
			RuntimeDir:      materialized.RuntimeDir,
			ConfigFile:      materialized.ConfigFile,
			PoolFiles:       append([]string(nil), materialized.PoolFiles...),
			DocumentRoots:   append([]string(nil), materialized.DocumentRoots...),
			GeneratedTarget: append([]string(nil), materialized.GeneratedTarget...),
		}
	}
	phpRuntimeMaterializationMu.Lock()
	phpRuntimeMaterialized = next
	phpRuntimeMaterializationMu.Unlock()
	return nil
}

func buildPHPRuntimeMaterializations(inventory PHPRuntimeInventoryFile, vhosts VhostConfigFile) (map[string]phpRuntimeMaterialization, string, error) {
	rootDir := filepath.Join(phpRuntimeRootDirFromInventoryPath(currentPHPRuntimeInventoryPath()), "runtime")
	runtimes := make(map[string]PHPRuntimeRecord, len(inventory.Runtimes))
	for _, runtime := range inventory.Runtimes {
		runtimes[runtime.RuntimeID] = runtime
	}
	out := make(map[string]phpRuntimeMaterialization)
	for _, vhost := range vhosts.Vhosts {
		if normalizeVhostMode(vhost.Mode) != "php-fpm" {
			continue
		}
		runtime, ok := runtimes[vhost.RuntimeID]
		if !ok {
			return nil, rootDir, fmt.Errorf("vhost %q references unknown runtime %q", vhost.Name, vhost.RuntimeID)
		}
		mat, ok := out[vhost.RuntimeID]
		if !ok {
			runtimeDir := filepath.Join(rootDir, vhost.RuntimeID)
			mat = phpRuntimeMaterialization{
				RuntimeID:       vhost.RuntimeID,
				BinaryPath:      runtime.BinaryPath,
				RunUser:         runtime.RunUser,
				RunGroup:        runtime.RunGroup,
				RuntimeDir:      runtimeDir,
				ConfigFile:      filepath.Join(runtimeDir, "php-fpm.conf"),
				PoolFiles:       []string{},
				DocumentRoots:   []string{},
				GeneratedTarget: []string{},
				Pools:           map[string]string{},
			}
		}
		poolName := vhost.GeneratedTarget
		poolFile := filepath.Join(mat.RuntimeDir, "pools", poolName+".conf")
		mat.PoolFiles = append(mat.PoolFiles, poolFile)
		mat.GeneratedTarget = append(mat.GeneratedTarget, vhost.GeneratedTarget)
		if !containsString(mat.DocumentRoots, vhost.DocumentRoot) {
			mat.DocumentRoots = append(mat.DocumentRoots, vhost.DocumentRoot)
		}
		mat.Pools[poolFile] = buildPHPRuntimePoolConfig(vhost, poolName)
		out[vhost.RuntimeID] = mat
	}
	for runtimeID, mat := range out {
		sort.Strings(mat.PoolFiles)
		sort.Strings(mat.DocumentRoots)
		sort.Strings(mat.GeneratedTarget)
		mat.ConfigBody = buildPHPRuntimeMasterConfig(mat)
		out[runtimeID] = mat
	}
	return out, rootDir, nil
}

func writePHPRuntimeMaterialization(mat phpRuntimeMaterialization) error {
	if err := os.MkdirAll(filepath.Join(mat.RuntimeDir, "pools"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(mat.ConfigFile, []byte(mat.ConfigBody), 0o644); err != nil {
		return err
	}
	for poolFile, body := range mat.Pools {
		if err := os.WriteFile(poolFile, []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func deleteStalePoolFiles(mat phpRuntimeMaterialization) error {
	poolDir := filepath.Join(mat.RuntimeDir, "pools")
	entries, err := os.ReadDir(poolDir)
	if err != nil {
		return err
	}
	keep := make(map[string]struct{}, len(mat.PoolFiles))
	for _, poolFile := range mat.PoolFiles {
		keep[filepath.Base(poolFile)] = struct{}{}
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if _, ok := keep[entry.Name()]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(poolDir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func buildPHPRuntimeMasterConfig(mat phpRuntimeMaterialization) string {
	pidPath := absoluteRuntimePath(filepath.Join(mat.RuntimeDir, "php-fpm.pid"))
	errorLogPath := absoluteRuntimePath(filepath.Join(mat.RuntimeDir, "php-fpm-error.log"))
	includePath := absoluteRuntimePath(filepath.Join(mat.RuntimeDir, "pools", "*.conf"))
	return strings.TrimSpace(fmt.Sprintf(`
[global]
daemonize = no
pid = %s
error_log = %s
include = %s
`, pidPath, errorLogPath, includePath)) + "\n"
}

func buildPHPRuntimePoolConfig(vhost VhostConfig, poolName string) string {
	docroot := absoluteRuntimePath(vhost.DocumentRoot)
	base := strings.TrimSpace(fmt.Sprintf(`
[%s]
listen = 127.0.0.1:%d
listen.allowed_clients = 127.0.0.1
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 10s
pm.max_requests = 200
clear_env = no
catch_workers_output = yes
decorate_workers_output = no
chdir = %s
`, poolName, vhost.ListenPort, docroot)) + "\n"
	var b strings.Builder
	b.WriteString(base)
	appendPHPRuntimeINIOverrides(&b, "php_value", vhost.PHPValues)
	appendPHPRuntimeINIOverrides(&b, "php_admin_value", vhost.PHPAdminValues)
	return b.String()
}

func absoluteRuntimePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func appendPHPRuntimeINIOverrides(b *strings.Builder, directive string, values map[string]string) {
	if b == nil || len(values) == 0 {
		return
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		b.WriteString(directive)
		b.WriteString("[")
		b.WriteString(key)
		b.WriteString("] = ")
		b.WriteString(strconv.Quote(values[key]))
		b.WriteString("\n")
	}
}

func currentPHPRuntimeInventoryPath() string {
	rt := phpRuntimeInventoryInstance()
	if rt != nil {
		return rt.configPath
	}
	return "data/php-fpm/inventory.json"
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
