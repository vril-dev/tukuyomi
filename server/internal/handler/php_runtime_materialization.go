package handler

import (
	"fmt"
	"net/netip"
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
			targetURL := "fcgi://" + runtimeListenEndpoint(vhost.Hostname, vhost.ListenPort)
			appendAlias(vhost.GeneratedTarget, targetURL, proxyUpstreamGeneratedKindVhostTarget)
		case "psgi":
			targetURL := "psgi://" + runtimeListenEndpoint(vhost.Hostname, vhost.ListenPort)
			appendAlias(vhost.GeneratedTarget, targetURL, proxyUpstreamGeneratedKindVhostTarget)
		case "static":
			targetURL := fmt.Sprintf("static://%s", vhost.GeneratedTarget)
			appendAlias(vhost.GeneratedTarget, targetURL, proxyUpstreamGeneratedKindVhostTarget)
		}
	}
	return out
}

func vhostGeneratedRoutes(cfg VhostConfigFile) []ProxyRoute {
	_ = cfg
	return nil
}

func refreshPHPRuntimeMaterializationWithConfig(inventory PHPRuntimeInventoryFile, vhosts VhostConfigFile) error {
	desired, rootDir, err := buildPHPRuntimeMaterializations(inventory, vhosts)
	if err != nil {
		return err
	}
	if len(desired) == 0 {
		if err := os.RemoveAll(rootDir); err != nil {
			return err
		}
		phpRuntimeMaterializationMu.Lock()
		phpRuntimeMaterialized = map[string]PHPRuntimeMaterializedStatus{}
		phpRuntimeMaterializationMu.Unlock()
		return nil
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
			return nil, rootDir, fmt.Errorf("Runtime App %q references unknown runtime %q", vhost.Name, vhost.RuntimeID)
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
	listenEndpoint := runtimeListenEndpoint(vhost.Hostname, vhost.ListenPort)
	allowedClients := phpFPMListenAllowedClients(vhost.Hostname)
	base := strings.TrimSpace(fmt.Sprintf(`
[%s]
listen = %s
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 10s
pm.max_requests = 200
clear_env = no
catch_workers_output = yes
decorate_workers_output = no
chdir = %s
`, poolName, listenEndpoint, docroot)) + "\n"
	var b strings.Builder
	b.WriteString(base)
	if allowedClients != "" {
		b.WriteString("listen.allowed_clients = ")
		b.WriteString(allowedClients)
		b.WriteString("\n")
	}
	appendPHPRuntimeINIOverrides(&b, "php_value", vhost.PHPValues)
	appendPHPRuntimeINIOverrides(&b, "php_admin_value", vhost.PHPAdminValues)
	return b.String()
}

func phpFPMListenAllowedClients(host string) string {
	host = normalizeRuntimeListenHost(host)
	if strings.EqualFold(host, "localhost") {
		return "127.0.0.1"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() || !addr.Is4() {
		return ""
	}
	return addr.String()
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

type PSGIRuntimeMaterializedStatus struct {
	ProcessID       string            `json:"process_id"`
	VhostName       string            `json:"vhost_name"`
	RuntimeID       string            `json:"runtime_id"`
	PerlPath        string            `json:"perl_path"`
	StarmanPath     string            `json:"starman_path"`
	RunUser         string            `json:"run_user,omitempty"`
	RunGroup        string            `json:"run_group,omitempty"`
	RuntimeDir      string            `json:"runtime_dir"`
	ManifestFile    string            `json:"manifest_file"`
	AppRoot         string            `json:"app_root"`
	DocumentRoot    string            `json:"document_root"`
	PSGIFile        string            `json:"psgi_file"`
	PSGIPath        string            `json:"psgi_path"`
	ListenHost      string            `json:"listen_host"`
	ListenPort      int               `json:"listen_port"`
	Workers         int               `json:"workers"`
	MaxRequests     int               `json:"max_requests"`
	IncludeExtlib   bool              `json:"include_extlib"`
	Env             map[string]string `json:"env,omitempty"`
	GeneratedTarget string            `json:"generated_target"`
}

var (
	psgiRuntimeMaterializationMu sync.RWMutex
	psgiRuntimeMaterialized      map[string]PSGIRuntimeMaterializedStatus
)

func RefreshPSGIRuntimeMaterialization() error {
	return refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), currentVhostConfig())
}

func PSGIRuntimeMaterializationSnapshot() []PSGIRuntimeMaterializedStatus {
	psgiRuntimeMaterializationMu.RLock()
	defer psgiRuntimeMaterializationMu.RUnlock()
	out := make([]PSGIRuntimeMaterializedStatus, 0, len(psgiRuntimeMaterialized))
	for _, status := range psgiRuntimeMaterialized {
		cp := status
		cp.Env = cloneStringMap(status.Env)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ProcessID < out[j].ProcessID
	})
	return out
}

func refreshPSGIRuntimeMaterializationWithConfig(inventory PSGIRuntimeInventoryFile, vhosts VhostConfigFile) error {
	desired, rootDir, err := buildPSGIRuntimeMaterializations(inventory, vhosts)
	if err != nil {
		return err
	}
	if len(desired) == 0 {
		if err := os.RemoveAll(rootDir); err != nil {
			return err
		}
		psgiRuntimeMaterializationMu.Lock()
		psgiRuntimeMaterialized = map[string]PSGIRuntimeMaterializedStatus{}
		psgiRuntimeMaterializationMu.Unlock()
		return nil
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return err
	}
	for processID, materialized := range desired {
		if err := writePSGIRuntimeMaterialization(materialized); err != nil {
			return err
		}
		desired[processID] = materialized
	}

	entries, err := os.ReadDir(rootDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			processID := entry.Name()
			if _, ok := desired[processID]; ok {
				continue
			}
			if err := os.RemoveAll(filepath.Join(rootDir, processID)); err != nil {
				return err
			}
		}
	}

	next := make(map[string]PSGIRuntimeMaterializedStatus, len(desired))
	for processID, materialized := range desired {
		cp := materialized
		cp.Env = cloneStringMap(materialized.Env)
		next[processID] = cp
	}
	psgiRuntimeMaterializationMu.Lock()
	psgiRuntimeMaterialized = next
	psgiRuntimeMaterializationMu.Unlock()
	return nil
}

func buildPSGIRuntimeMaterializations(inventory PSGIRuntimeInventoryFile, vhosts VhostConfigFile) (map[string]PSGIRuntimeMaterializedStatus, string, error) {
	rootDir := filepath.Join(psgiRuntimeRootDirFromInventoryPath(currentPSGIRuntimeInventoryPath()), "runtime")
	runtimes := make(map[string]PSGIRuntimeRecord, len(inventory.Runtimes))
	for _, runtime := range inventory.Runtimes {
		runtimes[runtime.RuntimeID] = runtime
	}
	out := make(map[string]PSGIRuntimeMaterializedStatus)
	for _, vhost := range vhosts.Vhosts {
		if normalizeVhostMode(vhost.Mode) != "psgi" {
			continue
		}
		runtime, ok := runtimes[vhost.RuntimeID]
		if !ok {
			return nil, rootDir, fmt.Errorf("Runtime App %q references unknown psgi runtime %q", vhost.Name, vhost.RuntimeID)
		}
		processID := normalizeConfigToken(vhost.Name)
		if processID == "" {
			processID = vhost.GeneratedTarget
		}
		includeExtlib := true
		if vhost.IncludeExtlib != nil {
			includeExtlib = *vhost.IncludeExtlib
		}
		runtimeDir := filepath.Join(rootDir, processID)
		psgiPath := filepath.Join(vhost.AppRoot, filepath.FromSlash(vhost.PSGIFile))
		out[processID] = PSGIRuntimeMaterializedStatus{
			ProcessID:       processID,
			VhostName:       vhost.Name,
			RuntimeID:       vhost.RuntimeID,
			PerlPath:        runtime.PerlPath,
			StarmanPath:     runtime.StarmanPath,
			RunUser:         runtime.RunUser,
			RunGroup:        runtime.RunGroup,
			RuntimeDir:      runtimeDir,
			ManifestFile:    filepath.Join(runtimeDir, "process.json"),
			AppRoot:         vhost.AppRoot,
			DocumentRoot:    vhost.DocumentRoot,
			PSGIFile:        vhost.PSGIFile,
			PSGIPath:        psgiPath,
			ListenHost:      normalizeRuntimeListenHost(vhost.Hostname),
			ListenPort:      vhost.ListenPort,
			Workers:         vhost.Workers,
			MaxRequests:     vhost.MaxRequests,
			IncludeExtlib:   includeExtlib,
			Env:             cloneStringMap(vhost.Env),
			GeneratedTarget: vhost.GeneratedTarget,
		}
	}
	return out, rootDir, nil
}

func writePSGIRuntimeMaterialization(mat PSGIRuntimeMaterializedStatus) error {
	if err := os.MkdirAll(mat.RuntimeDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(mat.ManifestFile, []byte(mustJSON(mat)), 0o644)
}

func currentMaterializedPSGIProcess(vhostName string) (PSGIRuntimeMaterializedStatus, bool) {
	vhostName = normalizeConfigToken(vhostName)
	for _, mat := range PSGIRuntimeMaterializationSnapshot() {
		if normalizeConfigToken(mat.VhostName) == vhostName || normalizeConfigToken(mat.ProcessID) == vhostName {
			return mat, true
		}
	}
	return PSGIRuntimeMaterializedStatus{}, false
}

func materializedPSGIProcessByPort(port int) (PSGIRuntimeMaterializedStatus, bool) {
	for _, mat := range PSGIRuntimeMaterializationSnapshot() {
		if mat.ListenPort == port {
			return mat, true
		}
	}
	return PSGIRuntimeMaterializedStatus{}, false
}

func psgiRuntimeExtlibPath(mat PSGIRuntimeMaterializedStatus) string {
	return filepath.Join(mat.AppRoot, "extlib")
}

func psgiRuntimeLaunchEnv(mat PSGIRuntimeMaterializedStatus) []string {
	env := os.Environ()
	keys := make([]string, 0, len(mat.Env))
	for key := range mat.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = upsertRuntimeEnv(env, key, mat.Env[key])
	}
	return upsertRuntimeEnv(env, "PATH", strings.Join(psgiRuntimePathEntries(mat, runtimeEnvValue(env, "PATH")), string(os.PathListSeparator)))
}

func psgiRuntimeStarmanArgs(mat PSGIRuntimeMaterializedStatus) []string {
	args := make([]string, 0, 12)
	if mat.IncludeExtlib {
		extlib := psgiRuntimeExtlibPath(mat)
		if info, err := os.Stat(extlib); err == nil && info.IsDir() {
			args = append(args, "-I", absoluteRuntimePath(extlib))
		}
	}
	args = append(args,
		"--preload-app",
		"--listen", runtimeListenEndpoint(psgiRuntimeListenHost(mat), mat.ListenPort),
		"--pid", absoluteRuntimePath(psgiRuntimePidPath(mat)),
		"--workers", fmt.Sprintf("%d", mat.Workers),
		"--max-requests", fmt.Sprintf("%d", mat.MaxRequests),
		absoluteRuntimePath(mat.PSGIPath),
	)
	return args
}

func psgiRuntimePidPath(mat PSGIRuntimeMaterializedStatus) string {
	return filepath.Join(mat.RuntimeDir, "starman.pid")
}

func psgiRuntimeListenHost(mat PSGIRuntimeMaterializedStatus) string {
	host := normalizeRuntimeListenHost(mat.ListenHost)
	if host == "" {
		return "127.0.0.1"
	}
	return host
}

func psgiRuntimePathEntries(mat PSGIRuntimeMaterializedStatus, inheritedPath string) []string {
	entries := make([]string, 0, 5)
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		for _, existing := range entries {
			if existing == path {
				return
			}
		}
		entries = append(entries, path)
	}
	bundleDir := filepath.Dir(absoluteRuntimePath(mat.PerlPath))
	add(bundleDir)
	rootfs := filepath.Join(bundleDir, "rootfs")
	for _, dir := range []string{
		filepath.Join(rootfs, "usr", "local", "bin"),
		filepath.Join(rootfs, "usr", "bin"),
		filepath.Join(rootfs, "bin"),
	} {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			add(dir)
		}
	}
	for _, entry := range filepath.SplitList(inheritedPath) {
		add(entry)
	}
	return entries
}

func runtimeEnvValue(env []string, key string) string {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(env[i], prefix) {
			return strings.TrimPrefix(env[i], prefix)
		}
	}
	return ""
}

func upsertRuntimeEnv(env []string, key string, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			out = append(out, entry)
			continue
		}
		if replaced {
			continue
		}
		out = append(out, prefix+value)
		replaced = true
	}
	if !replaced {
		out = append(out, prefix+value)
	}
	return out
}

func psgiRuntimeArgsSignature(mat PSGIRuntimeMaterializedStatus) string {
	return strings.Join(psgiRuntimeStarmanArgs(mat), "\x00")
}
