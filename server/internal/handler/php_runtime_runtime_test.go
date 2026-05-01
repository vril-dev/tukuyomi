package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func TestValidateVhostConfigRawRequiresKnownRuntime(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring", "redis"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "generated_target": "app-php",
      "runtime_id": "missing",
      "linked_upstream_name": "app"
    }
  ]
}`
	if _, err := ValidateVhostConfigRawWithInventory(raw, inventory); err == nil {
		t.Fatal("expected missing runtime validation error")
	} else if !strings.Contains(err.Error(), `references unknown runtime "missing"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateVhostConfigRawAcceptsKnownRuntimeWithoutSupportToggle(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring", "redis"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "generated_target": "app-php",
      "runtime_id": "php82",
      "linked_upstream_name": "app"
    }
  ]
}`
	if _, err := ValidateVhostConfigRawWithInventory(raw, inventory); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizePSGIRuntimeModulesAllowsPerlModuleNames(t *testing.T) {
	got := normalizePSGIRuntimeModules([]string{
		"GD",
		"XMLRPC::Transport::HTTP::Plack",
		"Crypt::DSA",
		"Digest::SHA1",
		"bad-module",
		"Bad::",
		"XMLRPC::Transport::HTTP::Plack",
	})
	want := []string{
		"gd",
		"xmlrpc::transport::http::plack",
		"crypt::dsa",
		"digest::sha1",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("modules=%v want=%v", got, want)
	}
}

func TestReadPSGIRuntimeModuleManifestPreservesNestedModuleNames(t *testing.T) {
	tmp := t.TempDir()
	perlPath := filepath.Join(tmp, "perl")
	if err := os.WriteFile(perlPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write perl: %v", err)
	}
	raw, err := json.Marshal([]string{
		"GD",
		"Imager",
		"XMLRPC::Transport::HTTP::Plack",
		"Crypt::SSLeay",
		"bad-module",
	})
	if err != nil {
		t.Fatalf("marshal modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "modules.json"), raw, 0o600); err != nil {
		t.Fatalf("write modules.json: %v", err)
	}
	got, err := readPSGIRuntimeModuleManifest(perlPath)
	if err != nil {
		t.Fatalf("readPSGIRuntimeModuleManifest: %v", err)
	}
	want := []string{"gd", "imager", "xmlrpc::transport::http::plack", "crypt::ssleay"}
	if !slices.Equal(got, want) {
		t.Fatalf("modules=%v want=%v", got, want)
	}
}

func TestValidateVhostConfigRawAcceptsPSGIRuntime(t *testing.T) {
	raw := `{
  "vhosts": [{
    "name": "mt-site",
    "mode": "psgi",
    "hostname": "127.0.0.1",
    "listen_port": 9501,
    "document_root": "data/mt/mt-static",
    "runtime_id": "perl538",
    "app_root": "data/mt/MT-9.0.7",
    "psgi_file": "mt.psgi",
    "try_files": ["$uri", "$uri/", "@psgi"]
  }]
}`
	cfg, err := ValidateVhostConfigRawWithInventories(raw, PHPRuntimeInventoryFile{}, PSGIRuntimeInventoryFile{
		Runtimes: []PSGIRuntimeRecord{{RuntimeID: "perl538", PerlPath: "perl", StarmanPath: "starman"}},
	})
	if err != nil {
		t.Fatalf("ValidateVhostConfigRawWithInventories: %v", err)
	}
	vhost := cfg.Vhosts[0]
	if vhost.Workers != 2 || vhost.MaxRequests != 200 || vhost.IncludeExtlib == nil || !*vhost.IncludeExtlib {
		t.Fatalf("unexpected PSGI defaults: workers=%d max=%d include=%v", vhost.Workers, vhost.MaxRequests, vhost.IncludeExtlib)
	}
	upstreams := generatedVhostUpstreams(cfg)
	if len(upstreams) != 1 || upstreams[0].URL != "psgi://127.0.0.1:9501" {
		t.Fatalf("generated upstreams=%+v", upstreams)
	}
	routes := vhostGeneratedRoutes(cfg)
	if len(routes) != 0 {
		t.Fatalf("generated routes=%+v want none", routes)
	}
}

func TestPSGIVhostRuntimePreflightRequiresPSGIFile(t *testing.T) {
	tmp := t.TempDir()
	appRoot := filepath.Join(tmp, "app")
	docRoot := filepath.Join(tmp, "public")
	if err := os.MkdirAll(appRoot, 0o755); err != nil {
		t.Fatalf("mkdir app root: %v", err)
	}
	if err := os.MkdirAll(docRoot, 0o755); err != nil {
		t.Fatalf("mkdir document root: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	raw := `{
  "vhosts": [{
    "name": "mt-site",
    "mode": "psgi",
    "hostname": "mt.example.test",
    "listen_port": 9501,
    "document_root": "` + filepath.ToSlash(docRoot) + `",
    "runtime_id": "perl538",
    "app_root": "` + filepath.ToSlash(appRoot) + `",
    "psgi_file": "mt.psgi"
  }]
}`
	inventory := PSGIRuntimeInventoryFile{
		Runtimes: []PSGIRuntimeRecord{{RuntimeID: "perl538", PerlPath: exe, StarmanPath: exe}},
	}
	cfg, err := ValidateVhostConfigRawWithInventories(raw, PHPRuntimeInventoryFile{}, inventory)
	if err != nil {
		t.Fatalf("ValidateVhostConfigRawWithInventories: %v", err)
	}
	err = validatePSGIVhostRuntimePreflight(cfg, inventory)
	if err == nil || !strings.Contains(err.Error(), "psgi_path") {
		t.Fatalf("err=%v want missing psgi_path", err)
	}
}

func TestPSGIVhostRuntimePreflightDoesNotRequireMovableTypeConfig(t *testing.T) {
	tmp := t.TempDir()
	appRoot := filepath.Join(tmp, "app")
	docRoot := filepath.Join(tmp, "public")
	if err := os.MkdirAll(appRoot, 0o755); err != nil {
		t.Fatalf("mkdir app root: %v", err)
	}
	if err := os.MkdirAll(docRoot, 0o755); err != nil {
		t.Fatalf("mkdir document root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appRoot, "mt.psgi"), []byte("use strict;\n"), 0o644); err != nil {
		t.Fatalf("write mt.psgi: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	raw := `{
  "vhosts": [{
    "name": "mt-site",
    "mode": "psgi",
    "hostname": "mt.example.test",
    "listen_port": 9501,
    "document_root": "` + filepath.ToSlash(docRoot) + `",
    "runtime_id": "perl538",
    "app_root": "` + filepath.ToSlash(appRoot) + `",
    "psgi_file": "mt.psgi"
  }]
}`
	inventory := PSGIRuntimeInventoryFile{
		Runtimes: []PSGIRuntimeRecord{{RuntimeID: "perl538", PerlPath: exe, StarmanPath: exe}},
	}
	cfg, err := ValidateVhostConfigRawWithInventories(raw, PHPRuntimeInventoryFile{}, inventory)
	if err != nil {
		t.Fatalf("ValidateVhostConfigRawWithInventories: %v", err)
	}
	if err := validatePSGIVhostRuntimePreflight(cfg, inventory); err != nil {
		t.Fatalf("preflight should not require mt-config.cgi: %v", err)
	}
}

func TestValidateVhostConfigRawRejectsUnknownPSGIRuntime(t *testing.T) {
	raw := `{
  "vhosts": [{
    "name": "mt-site",
    "mode": "psgi",
    "hostname": "mt.example.test",
    "listen_port": 9501,
    "document_root": "data/mt/mt-static",
    "runtime_id": "perl538",
    "app_root": "data/mt/MT-9.0.7",
    "psgi_file": "mt.psgi"
  }]
}`
	_, err := ValidateVhostConfigRawWithInventories(raw, PHPRuntimeInventoryFile{}, PSGIRuntimeInventoryFile{})
	if err == nil || !strings.Contains(err.Error(), `unknown psgi runtime "perl538"`) {
		t.Fatalf("err=%v want unknown psgi runtime", err)
	}
}

func TestPSGIRuntimeStarmanArgsPreloadApp(t *testing.T) {
	tmp := t.TempDir()
	appRoot := filepath.Join(tmp, "app")
	if err := os.MkdirAll(filepath.Join(appRoot, "extlib"), 0o755); err != nil {
		t.Fatalf("mkdir app extlib: %v", err)
	}
	mat := PSGIRuntimeMaterializedStatus{
		AppRoot:       appRoot,
		RuntimeDir:    filepath.Join(tmp, "runtime"),
		PSGIPath:      filepath.Join(appRoot, "app.psgi"),
		ListenHost:    "127.0.0.1",
		ListenPort:    9401,
		Workers:       2,
		MaxRequests:   200,
		IncludeExtlib: true,
	}
	args := psgiRuntimeStarmanArgs(mat)
	joined := strings.Join(args, " ")
	if !containsString(args, "--preload-app") {
		t.Fatalf("starman args=%q missing --preload-app", joined)
	}
	if !strings.Contains(joined, "-I "+absoluteRuntimePath(filepath.Join(appRoot, "extlib"))) {
		t.Fatalf("starman args=%q missing extlib include", joined)
	}
}

func TestPSGIRuntimeLogErrorSummaryPrefersLoadError(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "starman-supervisor.log"), []byte(strings.Join([]string{
		"Starman::Server starting",
		"Compilation failed in require at /srv/app/app.psgi line 3.",
		"Error while loading /srv/app/app.psgi: Can't locate CGI/PSGI.pm in @INC",
		"Child process exited with status 2",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	got := psgiRuntimeLogErrorSummary(tmp, "fallback")
	if !strings.Contains(got, "Can't locate CGI/PSGI.pm") {
		t.Fatalf("summary=%q want CGI::PSGI load error", got)
	}
}

func TestPSGIRuntimeStatusErrorUsesRelativePaths(t *testing.T) {
	psgiPath := filepath.ToSlash(absoluteRuntimePath("data/vhosts/samples/perl-site/MT-9.0.7/mt.psgi"))
	got := trimStatusError("Error while loading " + psgiPath + ": Bad CGIPath config")
	if strings.Contains(got, filepath.ToSlash(absoluteRuntimePath("data"))) {
		t.Fatalf("summary=%q still contains absolute data path", got)
	}
	if !strings.Contains(got, "data/vhosts/samples/perl-site/MT-9.0.7/mt.psgi") {
		t.Fatalf("summary=%q missing relative psgi path", got)
	}
	if !strings.Contains(got, "Bad CGIPath config") {
		t.Fatalf("summary=%q missing app error", got)
	}
}

func TestPSGIExplicitStartupWaitReturnsFastFailure(t *testing.T) {
	sup := &psgiRuntimeSupervisor{
		processes: map[string]*psgiRuntimeManagedProcess{},
		statuses: map[string]PSGIRuntimeProcessStatus{
			"vhost-1": {LastAction: "start_failed", LastError: "Bad CGIPath config"},
		},
		manuallyStopped: map[string]bool{},
	}
	err := sup.waitForExplicitStartup(PSGIRuntimeMaterializedStatus{ProcessID: "vhost-1"})
	if err == nil || !strings.Contains(err.Error(), "Bad CGIPath config") {
		t.Fatalf("err=%v want Bad CGIPath config", err)
	}
}

func TestPSGIHandleExitTreatsUnreadyExitAsStartFailure(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "starman-supervisor.log"), []byte("Error while loading /app/data/vhosts/app/app.psgi: DB unavailable\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	mat := PSGIRuntimeMaterializedStatus{
		ProcessID:  "vhost-1",
		VhostName:  "vhost-1",
		RuntimeID:  "perl538",
		RuntimeDir: tmp,
	}
	proc := &psgiRuntimeManagedProcess{
		processID: "vhost-1",
		desired:   true,
		startedAt: time.Now().Add(-10 * time.Second),
	}
	sup := &psgiRuntimeSupervisor{
		processes:       map[string]*psgiRuntimeManagedProcess{"vhost-1": proc},
		statuses:        map[string]PSGIRuntimeProcessStatus{},
		manuallyStopped: map[string]bool{},
	}
	sup.handleExit(mat, proc, os.ErrInvalid)
	status := sup.statuses["vhost-1"]
	if status.LastAction != "start_failed" {
		t.Fatalf("last_action=%q want start_failed", status.LastAction)
	}
	if strings.Contains(status.LastError, "/app/") {
		t.Fatalf("last_error=%q should not expose container root", status.LastError)
	}
	if !strings.Contains(status.LastError, "DB unavailable") {
		t.Fatalf("last_error=%q missing load error", status.LastError)
	}
	if _, ok := sup.processes["vhost-1"]; ok {
		t.Fatal("unready process should not stay registered")
	}
}

func TestValidateVhostConfigRawGeneratesHiddenTargetWhenOmitted(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring", "redis"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "linked_upstream_name": "app"
    },
    {
      "name": "app php",
      "mode": "php-fpm",
      "hostname": "app-php.example.com",
      "listen_port": 9082,
      "document_root": "apps/app-php/public",
      "runtime_id": "php82",
      "linked_upstream_name": "app-upstream"
    }
  ]
}`
	cfg, err := ValidateVhostConfigRawWithInventory(raw, inventory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Vhosts) != 2 {
		t.Fatalf("vhost count=%d want=2", len(cfg.Vhosts))
	}
	if cfg.Vhosts[0].GeneratedTarget != "app-php" {
		t.Fatalf("first generated_target=%q want app-php", cfg.Vhosts[0].GeneratedTarget)
	}
	if cfg.Vhosts[1].GeneratedTarget != "app-php-2" {
		t.Fatalf("second generated_target=%q want app-php-2", cfg.Vhosts[1].GeneratedTarget)
	}
}

func TestValidateVhostConfigRawAllowsOmittedLinkedUpstreamName(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring", "redis"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "generated_target": "app-php"
    }
  ]
}`
	cfg, err := ValidateVhostConfigRawWithInventory(raw, inventory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Vhosts[0].LinkedUpstreamName != "" {
		t.Fatalf("linked_upstream_name=%q want empty", cfg.Vhosts[0].LinkedUpstreamName)
	}
}

func TestValidateVhostConfigRawRejectsDuplicateLinkedUpstreamNames(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring", "redis"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app1",
      "mode": "php-fpm",
      "hostname": "app1.example.com",
      "listen_port": 9081,
      "document_root": "apps/app1/public",
      "runtime_id": "php82",
      "generated_target": "app1-php",
      "linked_upstream_name": "app"
    },
    {
      "name": "app2",
      "mode": "php-fpm",
      "hostname": "app2.example.com",
      "listen_port": 9082,
      "document_root": "apps/app2/public",
      "runtime_id": "php82",
      "generated_target": "app2-php",
      "linked_upstream_name": "app"
    }
  ]
}`
	if _, err := ValidateVhostConfigRawWithInventory(raw, inventory); err == nil || !strings.Contains(err.Error(), `duplicates "app"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateVhostConfigRawAllowsSamePortOnDifferentListenHosts(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app1",
      "mode": "php-fpm",
      "hostname": "192.0.2.10",
      "listen_port": 9081,
      "document_root": "apps/app1/public",
      "runtime_id": "php82",
      "generated_target": "app1-php"
    },
    {
      "name": "app2",
      "mode": "php-fpm",
      "hostname": "192.0.2.11",
      "listen_port": 9081,
      "document_root": "apps/app2/public",
      "runtime_id": "php82",
      "generated_target": "app2-php"
    }
  ]
}`
	cfg, err := ValidateVhostConfigRawWithInventory(raw, inventory)
	if err != nil {
		t.Fatalf("ValidateVhostConfigRawWithInventory: %v", err)
	}
	upstreams := generatedVhostUpstreams(cfg)
	if len(upstreams) != 2 {
		t.Fatalf("generated upstream count=%d want=2: %+v", len(upstreams), upstreams)
	}
	if upstreams[0].URL != "fcgi://192.0.2.10:9081" || upstreams[1].URL != "fcgi://192.0.2.11:9081" {
		t.Fatalf("generated upstreams=%+v", upstreams)
	}
}

func TestValidateVhostConfigRawRejectsDuplicateListenTarget(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app1",
      "mode": "php-fpm",
      "hostname": "127.0.0.1",
      "listen_port": 9081,
      "document_root": "apps/app1/public",
      "runtime_id": "php82",
      "generated_target": "app1-php"
    },
    {
      "name": "app2",
      "mode": "php-fpm",
      "hostname": "127.0.0.1",
      "listen_port": 9081,
      "document_root": "apps/app2/public",
      "runtime_id": "php82",
      "generated_target": "app2-php"
    }
  ]
}`
	if _, err := ValidateVhostConfigRawWithInventory(raw, inventory); err == nil || !strings.Contains(err.Error(), "listen target duplicates") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPHPRuntimeInventoryListsOnlyBuiltArtifacts(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(defaultVhostConfigRaw), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php83", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.3",
		Version:     "PHP 8.3.21 (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})

	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	_, _, cfg, _ := PHPRuntimeInventorySnapshot()
	if len(cfg.Runtimes) != 1 {
		t.Fatalf("runtime count=%d want=1", len(cfg.Runtimes))
	}
	runtime := cfg.Runtimes[0]
	if runtime.RuntimeID != "php83" {
		t.Fatalf("runtime_id=%q want=php83", runtime.RuntimeID)
	}
	if !runtime.Available {
		t.Fatalf("runtime available=%v want=true (%s)", runtime.Available, runtime.AvailabilityMessage)
	}
	if got, want := runtime.CLIBinaryPath, filepath.ToSlash(filepath.Join(filepath.Dir(runtime.BinaryPath), "php")); got != want {
		t.Fatalf("cli_binary_path=%q want=%q", got, want)
	}
	if got, want := runtime.Modules, []string{"mbstring", "fileinfo", "redis"}; !slices.Equal(got, want) {
		t.Fatalf("modules=%v want=%v", got, want)
	}
	if got, want := runtime.DefaultDisabledModules, []string{}; !slices.Equal(got, want) {
		t.Fatalf("default_disabled_modules=%v want=%v", got, want)
	}
}

func TestApplyPHPRuntimeInventoryRawDoesNotDeadlockOnMaterializationRefresh(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(defaultVhostConfigRaw), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php83", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.3",
		Version:     "PHP 8.3.21 (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})
	initConfigDBStoreForTest(t)
	inventoryCfg := importPHPRuntimeInventoryDBForTest(t, defaultPHPRuntimeInventoryRaw, inventoryPath)
	importVhostRuntimeDBForTest(t, defaultVhostConfigRaw, inventoryCfg)
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	_, etag, _, _ := PHPRuntimeInventorySnapshot()
	nextInventory := "{}"

	done := make(chan error, 1)
	go func() {
		_, _, err := ApplyPHPRuntimeInventoryRaw(etag, nextInventory)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ApplyPHPRuntimeInventoryRaw: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ApplyPHPRuntimeInventoryRaw timed out; possible self-deadlock while refreshing materialization")
	}
}

func TestApplyAndRollbackVhostConfigRaw(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(defaultVhostConfigRaw), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "marketing-app-upstream", URL: "http://127.0.0.1:8081", Weight: 1, Enabled: true},
			{Name: "static-docs-upstream", URL: "http://127.0.0.1:8082", Weight: 1, Enabled: true},
			{Name: "primary", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
		},
	}))
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
	})
	initConfigDBStoreForTest(t)
	inventoryCfg := importPHPRuntimeInventoryDBForTest(t, defaultPHPRuntimeInventoryRaw, inventoryPath)
	importVhostRuntimeDBForTest(t, defaultVhostConfigRaw, inventoryCfg)
	importProxyRuntimeDBForTest(t, proxyRaw)
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	_, etag, _, _ := VhostConfigSnapshot()
	nextVhosts := `{
  "vhosts": [
    {
      "name": "marketing app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "linked_upstream_name": "marketing-app-upstream"
    },
    {
      "name": "static docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9082,
      "document_root": "apps/docs/public",
      "linked_upstream_name": "static-docs-upstream"
    }
  ]
}`
	newETag, cfg, err := ApplyVhostConfigRaw(etag, nextVhosts)
	if err != nil {
		t.Fatalf("ApplyVhostConfigRaw: %v", err)
	}
	if newETag == "" || newETag == etag {
		t.Fatalf("unexpected etag transition old=%q new=%q", etag, newETag)
	}
	if len(cfg.Vhosts) != 2 {
		t.Fatalf("vhost count=%d want=2", len(cfg.Vhosts))
	}
	if cfg.Vhosts[0].GeneratedTarget != "marketing-app" {
		t.Fatalf("generated_target=%q want=%q", cfg.Vhosts[0].GeneratedTarget, "marketing-app")
	}
	if cfg.Vhosts[1].RuntimeID != "" {
		t.Fatalf("static runtime_id=%q want empty", cfg.Vhosts[1].RuntimeID)
	}

	rolledETag, rolledCfg, restored, err := RollbackVhostConfig()
	if err != nil {
		t.Fatalf("RollbackVhostConfig: %v", err)
	}
	if rolledETag == "" {
		t.Fatal("rollback etag should not be empty")
	}
	if restored.ETag != etag {
		t.Fatalf("restored etag=%q want=%q", restored.ETag, etag)
	}
	if len(rolledCfg.Vhosts) != 0 {
		t.Fatalf("vhost count after rollback=%d want=0", len(rolledCfg.Vhosts))
	}

	reappliedETag, _, err := ApplyVhostConfigRaw(etag, nextVhosts)
	if err != nil {
		t.Fatalf("ApplyVhostConfigRaw with stale equivalent etag after rollback: %v", err)
	}
	if reappliedETag == "" || reappliedETag == rolledETag || reappliedETag == etag {
		t.Fatalf("unexpected reapply etag transition original=%q rolled=%q reapplied=%q", etag, rolledETag, reappliedETag)
	}
}

func TestGetPHPRuntimesAndRuntimeAppsHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	docroot := filepath.Join(tmp, "apps", "app", "public")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}

	initialInventory := defaultPHPRuntimeInventoryRaw
	initialVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app"
    },
    {
      "name": "static",
      "mode": "static",
      "hostname": "static.example.com",
      "listen_port": 9082,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "app-static",
      "linked_upstream_name": "static"
    }
  ]
}`
	if err := os.WriteFile(inventoryPath, []byte(initialInventory), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(initialVhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
	})
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	runtimeRec := httptest.NewRecorder()
	runtimeCtx, _ := gin.CreateTestContext(runtimeRec)
	runtimeCtx.Request = httptest.NewRequest(http.MethodGet, "/php-runtimes", nil)
	GetPHPRuntimes(runtimeCtx)
	if runtimeRec.Code != http.StatusOK {
		t.Fatalf("GetPHPRuntimes status=%d body=%s", runtimeRec.Code, runtimeRec.Body.String())
	}
	var runtimeResp struct {
		ETag         string                         `json:"etag"`
		Raw          string                         `json:"raw"`
		Runtimes     PHPRuntimeInventoryFile        `json:"runtimes"`
		Materialized []PHPRuntimeMaterializedStatus `json:"materialized"`
	}
	if err := json.Unmarshal(runtimeRec.Body.Bytes(), &runtimeResp); err != nil {
		t.Fatalf("runtime response json: %v", err)
	}
	if runtimeResp.ETag == "" || runtimeResp.Raw == "" {
		t.Fatalf("runtime response missing etag/raw: %s", runtimeRec.Body.String())
	}
	if len(runtimeResp.Runtimes.Runtimes) != 1 || runtimeResp.Runtimes.Runtimes[0].RuntimeID != "php82" {
		t.Fatalf("runtime listing mismatch: %+v", runtimeResp.Runtimes)
	}
	if !slices.Contains(runtimeResp.Runtimes.Runtimes[0].Modules, "redis") {
		t.Fatalf("modules=%v want redis", runtimeResp.Runtimes.Runtimes[0].Modules)
	}
	if len(runtimeResp.Runtimes.Runtimes[0].DefaultDisabledModules) != 0 {
		t.Fatalf("default_disabled_modules=%v want empty", runtimeResp.Runtimes.Runtimes[0].DefaultDisabledModules)
	}
	if len(runtimeResp.Materialized) != 1 || runtimeResp.Materialized[0].RuntimeID != "php82" {
		t.Fatalf("materialized runtime mismatch: %+v", runtimeResp.Materialized)
	}

	runtimeAppsRec := httptest.NewRecorder()
	runtimeAppsCtx, _ := gin.CreateTestContext(runtimeAppsRec)
	runtimeAppsCtx.Request = httptest.NewRequest(http.MethodGet, "/runtime-apps", nil)
	GetRuntimeApps(runtimeAppsCtx)
	if runtimeAppsRec.Code != http.StatusOK {
		t.Fatalf("GetRuntimeApps status=%d body=%s", runtimeAppsRec.Code, runtimeAppsRec.Body.String())
	}
	var runtimeAppsResp struct {
		ETag        string          `json:"etag"`
		Raw         string          `json:"raw"`
		RuntimeApps VhostConfigFile `json:"runtime_apps"`
	}
	if err := json.Unmarshal(runtimeAppsRec.Body.Bytes(), &runtimeAppsResp); err != nil {
		t.Fatalf("runtime apps response json: %v", err)
	}
	if runtimeAppsResp.ETag == "" || runtimeAppsResp.Raw == "" {
		t.Fatalf("runtime apps response missing etag/raw: %s", runtimeAppsRec.Body.String())
	}
	if len(runtimeAppsResp.RuntimeApps.Vhosts) != 2 {
		t.Fatalf("runtime app count=%d want=2", len(runtimeAppsResp.RuntimeApps.Vhosts))
	}
}

func TestValidatePHPRuntimeInventoryRawIgnoresLegacyPHPSupportFlag(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(defaultVhostConfigRaw), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	cfg, err := ValidatePHPRuntimeInventoryRaw(`{
  "php_enabled": true
}`)
	if err != nil {
		t.Fatalf("ValidatePHPRuntimeInventoryRaw: %v", err)
	}
	if len(cfg.Runtimes) != 0 {
		t.Fatalf("runtime count=%d want=0", len(cfg.Runtimes))
	}
}

func TestDefaultPHPRuntimeInventoryStartsEmptyUntilRuntimeIsBuilt(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	prepared, err := preparePHPRuntimeInventoryRaw(defaultPHPRuntimeInventoryRaw, inventoryPath)
	if err != nil {
		t.Fatalf("preparePHPRuntimeInventoryRaw(default): %v", err)
	}
	if len(prepared.cfg.Runtimes) != 0 {
		t.Fatalf("runtime count=%d want=0", len(prepared.cfg.Runtimes))
	}
}

func TestValidatePHPRuntimeInventoryRawLoadsBuiltArtifactModulesAndDefaults(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(defaultVhostConfigRaw), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php83", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.3",
		Version:     "PHP 8.3.21 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis", "fileinfo"},
	})
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	cfg, err := ValidatePHPRuntimeInventoryRaw("{}")
	if err != nil {
		t.Fatalf("ValidatePHPRuntimeInventoryRaw: %v", err)
	}
	if len(cfg.Runtimes) != 1 {
		t.Fatalf("runtime count=%d want=1", len(cfg.Runtimes))
	}
	runtime := cfg.Runtimes[0]
	if !runtime.Available {
		t.Fatalf("runtime available=%v want=true (%s)", runtime.Available, runtime.AvailabilityMessage)
	}
	if got, want := runtime.Modules, []string{"mbstring", "redis", "fileinfo"}; !slices.Equal(got, want) {
		t.Fatalf("modules=%v want=%v", got, want)
	}
	if got, want := runtime.DefaultDisabledModules, []string{}; !slices.Equal(got, want) {
		t.Fatalf("default_disabled_modules=%v want=%v", got, want)
	}
}

func TestPHPRuntimeInventoryDBLoadsWithoutInventoryOrManifestJSON(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	binaryPath := writeTestPHPRuntimeArtifact(t, inventoryPath, "php83", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.3",
		Version:     "PHP 8.3.21 (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})
	explicitInventory := mustJSON(PHPRuntimeInventoryFile{Runtimes: []PHPRuntimeRecord{{
		RuntimeID:              "php83",
		DisplayName:            "PHP 8.3",
		DetectedVersion:        "PHP 8.3.21 (fpm-fcgi)",
		BinaryPath:             filepath.ToSlash(binaryPath),
		CLIBinaryPath:          filepath.ToSlash(filepath.Join(filepath.Dir(binaryPath), "php")),
		Modules:                []string{"mbstring", "fileinfo", "redis"},
		DefaultDisabledModules: []string{},
		Source:                 "bundled",
	}}})
	if err := os.WriteFile(inventoryPath, []byte(explicitInventory), 0o600); err != nil {
		t.Fatalf("write explicit inventory: %v", err)
	}

	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	oldInventoryPath := config.PHPRuntimeInventoryFile
	config.PHPRuntimeInventoryFile = inventoryPath
	t.Cleanup(func() {
		config.PHPRuntimeInventoryFile = oldInventoryPath
	})
	if err := importPHPRuntimeInventoryStorage(); err != nil {
		t.Fatalf("import php runtime inventory: %v", err)
	}

	runtimeDir := filepath.Dir(binaryPath)
	for _, path := range []string{
		inventoryPath,
		filepath.Join(runtimeDir, "runtime.json"),
		filepath.Join(runtimeDir, "modules.json"),
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove %s: %v", path, err)
		}
	}

	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	raw, _, cfg, _ := PHPRuntimeInventorySnapshot()
	if strings.Contains(raw, "runtime.json") || strings.Contains(raw, "modules.json") {
		t.Fatalf("raw inventory should not reference deleted manifest paths: %s", raw)
	}
	if len(cfg.Runtimes) != 1 {
		t.Fatalf("runtime count=%d want=1", len(cfg.Runtimes))
	}
	runtime := cfg.Runtimes[0]
	if runtime.RuntimeID != "php83" {
		t.Fatalf("runtime_id=%q want php83", runtime.RuntimeID)
	}
	if !runtime.Available {
		t.Fatalf("runtime available=%v want=true (%s)", runtime.Available, runtime.AvailabilityMessage)
	}
	if got, want := runtime.Modules, []string{"mbstring", "fileinfo", "redis"}; !slices.Equal(got, want) {
		t.Fatalf("modules=%v want=%v", got, want)
	}
	if _, err := os.Stat(inventoryPath); !os.IsNotExist(err) {
		t.Fatalf("inventory json should not be recreated, stat err=%v", err)
	}
}

func TestPHPRuntimeInventoryDBAutoDiscoveryReflectsBuiltArtifactsAfterStartup(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}

	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	oldInventoryPath := config.PHPRuntimeInventoryFile
	config.PHPRuntimeInventoryFile = inventoryPath
	t.Cleanup(func() {
		config.PHPRuntimeInventoryFile = oldInventoryPath
	})
	if err := importPHPRuntimeInventoryStorage(); err != nil {
		t.Fatalf("import php runtime inventory: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}

	_, _, cfg, _ := PHPRuntimeInventorySnapshot()
	if len(cfg.Runtimes) != 0 {
		t.Fatalf("runtime count before build=%d want=0", len(cfg.Runtimes))
	}

	writeTestPHPRuntimeArtifact(t, inventoryPath, "php85", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.5",
		Version:     "PHP 8.5.0-dev (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})

	_, _, cfg, _ = PHPRuntimeInventorySnapshot()
	if len(cfg.Runtimes) != 1 {
		t.Fatalf("runtime count after build=%d want=1", len(cfg.Runtimes))
	}
	if got := cfg.Runtimes[0].RuntimeID; got != "php85" {
		t.Fatalf("runtime_id=%q want php85", got)
	}
	if !cfg.Runtimes[0].Available {
		t.Fatalf("runtime available=%v want=true (%s)", cfg.Runtimes[0].Available, cfg.Runtimes[0].AvailabilityMessage)
	}
}

func TestPHPRuntimeInventoryDBExplicitEmptyDoesNotAutoDiscover(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(`{"runtimes":[]}`), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}

	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	oldInventoryPath := config.PHPRuntimeInventoryFile
	config.PHPRuntimeInventoryFile = inventoryPath
	t.Cleanup(func() {
		config.PHPRuntimeInventoryFile = oldInventoryPath
	})
	if err := importPHPRuntimeInventoryStorage(); err != nil {
		t.Fatalf("import php runtime inventory: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}

	writeTestPHPRuntimeArtifact(t, inventoryPath, "php85", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.5",
		Version:     "PHP 8.5.0-dev (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})

	_, _, cfg, _ := PHPRuntimeInventorySnapshot()
	if len(cfg.Runtimes) != 0 {
		t.Fatalf("runtime count=%d want=0 for explicit empty inventory", len(cfg.Runtimes))
	}
}

func TestPHPRuntimeInventoryDBLegacyImportWithoutStateAutoDiscovers(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}

	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	oldInventoryPath := config.PHPRuntimeInventoryFile
	config.PHPRuntimeInventoryFile = inventoryPath
	t.Cleanup(func() {
		config.PHPRuntimeInventoryFile = oldInventoryPath
	})
	if err := importPHPRuntimeInventoryStorage(); err != nil {
		t.Fatalf("import php runtime inventory: %v", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	if _, err := store.exec(`DELETE FROM php_runtime_inventory_state`); err != nil {
		t.Fatalf("delete php runtime inventory state: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}

	writeTestPHPRuntimeArtifact(t, inventoryPath, "php85", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.5",
		Version:     "PHP 8.5.0-dev (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})

	_, _, cfg, _ := PHPRuntimeInventorySnapshot()
	if len(cfg.Runtimes) != 1 {
		t.Fatalf("runtime count=%d want=1 for legacy import without inventory state", len(cfg.Runtimes))
	}
	if got := cfg.Runtimes[0].RuntimeID; got != "php85" {
		t.Fatalf("runtime_id=%q want php85", got)
	}
}

func TestInitPHPRuntimeInventoryRuntimeDoesNotDeleteMaterializedRuntimesBeforeVhostsLoad(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	runtimeDir := filepath.Join(filepath.Dir(inventoryPath), "runtime", "php85")
	sentinel := filepath.Join(runtimeDir, "php-fpm.conf")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	if err := os.WriteFile(sentinel, []byte("[global]\n"), 0o600); err != nil {
		t.Fatalf("write sentinel runtime config: %v", err)
	}

	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	oldInventoryPath := config.PHPRuntimeInventoryFile
	config.PHPRuntimeInventoryFile = inventoryPath
	t.Cleanup(func() {
		config.PHPRuntimeInventoryFile = oldInventoryPath
	})
	if err := importPHPRuntimeInventoryStorage(); err != nil {
		t.Fatalf("import php runtime inventory: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("materialized runtime config should remain until vhost runtime owns refresh: %v", err)
	}
}

func resetPHPFoundationRuntimesForTest(t *testing.T) func() {
	t.Helper()

	phpRuntimeInventoryMu.Lock()
	prevInventory := phpRuntimeInventoryRt
	phpRuntimeInventoryRt = nil
	phpRuntimeInventoryMu.Unlock()

	psgiRuntimeInventoryMu.Lock()
	prevPSGIInventory := psgiRuntimeInventoryRt
	psgiRuntimeInventoryRt = nil
	psgiRuntimeInventoryMu.Unlock()

	vhostRuntimeMu.Lock()
	prevVhost := vhostRt
	vhostRt = nil
	vhostRuntimeMu.Unlock()

	proxyRuntimeMu.Lock()
	prevProxy := proxyRt
	proxyRt = nil
	proxyRuntimeMu.Unlock()

	siteRuntimeMu.Lock()
	prevSite := siteRt
	siteRt = nil
	siteRuntimeMu.Unlock()

	phpRuntimeSupervisorMu.Lock()
	prevSupervisor := phpRuntimeSupervisorRt
	phpRuntimeSupervisorRt = nil
	phpRuntimeSupervisorMu.Unlock()

	psgiRuntimeSupervisorMu.Lock()
	prevPSGISupervisor := psgiRuntimeSupervisorRt
	psgiRuntimeSupervisorRt = nil
	psgiRuntimeSupervisorMu.Unlock()

	phpRuntimeMaterializationMu.Lock()
	prevMaterialized := phpRuntimeMaterialized
	phpRuntimeMaterialized = nil
	phpRuntimeMaterializationMu.Unlock()

	psgiRuntimeMaterializationMu.Lock()
	prevPSGIMaterialized := psgiRuntimeMaterialized
	psgiRuntimeMaterialized = nil
	psgiRuntimeMaterializationMu.Unlock()

	scheduledTaskRuntimeMu.Lock()
	prevScheduledTasks := scheduledTaskRt
	scheduledTaskRt = nil
	scheduledTaskRuntimeMu.Unlock()

	return func() {
		phpRuntimeInventoryMu.Lock()
		phpRuntimeInventoryRt = prevInventory
		phpRuntimeInventoryMu.Unlock()

		psgiRuntimeInventoryMu.Lock()
		psgiRuntimeInventoryRt = prevPSGIInventory
		psgiRuntimeInventoryMu.Unlock()

		vhostRuntimeMu.Lock()
		vhostRt = prevVhost
		vhostRuntimeMu.Unlock()

		proxyRuntimeMu.Lock()
		proxyRt = prevProxy
		proxyRuntimeMu.Unlock()

		siteRuntimeMu.Lock()
		siteRt = prevSite
		siteRuntimeMu.Unlock()

		phpRuntimeSupervisorMu.Lock()
		currentSupervisor := phpRuntimeSupervisorRt
		phpRuntimeSupervisorRt = prevSupervisor
		phpRuntimeSupervisorMu.Unlock()
		if currentSupervisor != nil {
			_ = currentSupervisor.shutdown()
		}

		psgiRuntimeSupervisorMu.Lock()
		currentPSGISupervisor := psgiRuntimeSupervisorRt
		psgiRuntimeSupervisorRt = prevPSGISupervisor
		psgiRuntimeSupervisorMu.Unlock()
		if currentPSGISupervisor != nil {
			_ = currentPSGISupervisor.shutdown()
		}

		phpRuntimeMaterializationMu.Lock()
		phpRuntimeMaterialized = prevMaterialized
		phpRuntimeMaterializationMu.Unlock()

		psgiRuntimeMaterializationMu.Lock()
		psgiRuntimeMaterialized = prevPSGIMaterialized
		psgiRuntimeMaterializationMu.Unlock()

		scheduledTaskRuntimeMu.Lock()
		scheduledTaskRt = prevScheduledTasks
		scheduledTaskRuntimeMu.Unlock()
	}
}
