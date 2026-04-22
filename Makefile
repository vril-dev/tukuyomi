SHELL := /bin/bash

.DEFAULT_GOAL := help

GO ?= go
NPM ?= npm
DOCKER ?= docker
ROOT_DIR := $(abspath .)

PUID ?= $(shell id -u)
GUID ?= $(shell id -g)

CORAZA_PORT ?= 9090
HOST_CORAZA_PORT ?= 19090
WAF_LISTEN_PORT ?= 9090
WAF_API_KEY_PRIMARY ?= dev-only-change-this-key-please
PROTECTED_HOST ?= protected.example.test

BENCH_REQUESTS ?= 120
WARMUP_REQUESTS ?= 20
BENCH_CONCURRENCY ?= 1,10,50
BENCH_PATH ?= /bench
BENCH_TIMEOUT_SEC ?= 30
BENCH_MAX_FAIL_RATE_PCT ?=
BENCH_MIN_RPS ?=
BENCH_DISABLE_RATE_LIMIT ?= 1
BENCH_DISABLE_REQUEST_GUARDS ?= 1
BENCH_ACCESS_LOG_MODE ?= full
BENCH_CLIENT_KEEPALIVE ?= 1
BENCH_PROXY_MODE ?= current
BENCH_PROXY_ENGINE ?= tukuyomi_proxy
BENCH_PROFILE ?= 0
BENCH_PROFILE_ADDR ?= 127.0.0.1:6060
BENCH_PROFILE_SECONDS ?= 10
UPSTREAM_PORT ?=

CORAZA_SRC := coraza/src
UI_DIR := web/tukuyomi-admin
UI_EMBED_DIR := coraza/src/internal/handler/admin_ui_dist
BIN_DIR ?= bin
APP_NAME ?= tukuyomi
APP_PKG ?= ./cmd/server
VERSION ?= dev
RELEASE_DIR ?= dist/release
RELEASE_DOCKERFILE ?= build/Dockerfile.release
PRESET ?= minimal
PRESET_DIR := presets/$(PRESET)
PRESET_OVERWRITE ?= 0

export PUID GUID CORAZA_PORT HOST_CORAZA_PORT WAF_LISTEN_PORT WAF_API_KEY_PRIMARY PROTECTED_HOST

.PHONY: \
	help setup env-init crs-install \
	go-test go-build build \
	release-linux-amd64 release-linux-arm64 release-linux-all \
	ui-install ui-test ui-build ui-sync ui-build-sync \
	ui-preview-up ui-preview-down ui-preview-smoke php-fpm-build php-fpm-copy php-fpm-prune php-fpm-remove php-fpm-up php-fpm-down php-fpm-reload php-fpm-test php-fpm-smoke \
	scheduled-tasks-smoke container-platform-smoke dual-listener-smoke \
	compose-config compose-config-mysql compose-config-scheduled-tasks compose-up compose-up-scheduled-tasks compose-down mysql-up mysql-down \
	preset-list preset-apply preset-check preset-check-minimal \
	migrate-proxy-config migrate-proxy-config-check \
	smoke smoke-extended binary-deployment-smoke container-deployment-smoke deployment-smoke release-binary-smoke http3-public-entry-smoke bench bench-proxy bench-waf bench-full gotestwaf \
	check ci-local ci-local-extended clean

help:
	@echo "Targets:"
	@echo "  make setup                      Prepare local dev baseline (.env + CRS)"
	@echo "  make env-init                   Create .env from .env.example if missing"
	@echo "  make crs-install                Install OWASP CRS into data/rules/crs"
	@echo ""
	@echo "  make go-test                    Run Go tests (coraza/src)"
	@echo "  make go-build                   Build single binary into ./bin/$(APP_NAME)"
	@echo "  make build                      One-shot build (ui-build-sync + go-build)"
	@echo "  make release-linux-amd64        Build release tarball for linux/amd64 via docker buildx"
	@echo "  make release-linux-arm64        Build release tarball for linux/arm64 via docker buildx"
	@echo "  make release-linux-all          Build linux/amd64 + linux/arm64 and combined checksums"
	@echo ""
	@echo "  make ui-install                 Install admin UI dependencies"
	@echo "  make ui-test                    Run admin UI tests"
	@echo "  make ui-build                   Build admin UI static assets"
	@echo "  make ui-sync                    Sync web dist -> go:embed assets"
	@echo "  make ui-build-sync              Build and sync embedded UI assets"
	@echo "  make ui-preview-up              Build/sync UI and start preview runtime + scheduled-task sidecar"
	@echo "    - optional: UI_PREVIEW_PERSIST=1 keeps preview config/state across down/up"
	@echo "  make ui-preview-down            Stop screenshot preview runtime and remove temp config"
	@echo "  make ui-preview-smoke           Validate preview persistence, split-port publish, and loopback reject"
	@echo "  make php-fpm-build VER=8.3      Build PHP-FPM runtime bundle under data/php-fpm/binaries/php83"
	@echo "    - alias: RUNTIME=php83|php84|php85"
	@echo "  make php-fpm-copy RUNTIME=php83 Stage built PHP-FPM runtime bundle into /opt/tukuyomi"
	@echo "    - override destination with DEST=/srv/tukuyomi"
	@echo "  make php-fpm-prune RUNTIME=php83 Remove a staged PHP-FPM runtime bundle from /opt/tukuyomi when safe"
	@echo "    - override destination with DEST=/srv/tukuyomi"
	@echo "  make php-fpm-remove RUNTIME=php83 Remove a built PHP-FPM runtime bundle when safe"
	@echo "  make php-fpm-up RUNTIME=php83   Start a materialized PHP-FPM runtime through admin API"
	@echo "  make php-fpm-down RUNTIME=php83 Stop a running PHP-FPM runtime through admin API"
	@echo "  make php-fpm-reload RUNTIME=php83 Reload a running PHP-FPM runtime through admin API"
	@echo "  make php-fpm-test               Run dedicated php-fpm focused handler/admin tests"
	@echo "  make php-fpm-smoke              Run dedicated php-fpm build/lifecycle smoke"
	@echo "  make scheduled-tasks-smoke      Validate binary + docker + preview scheduled-task flows"
	@echo "  make container-platform-smoke   Validate single-instance support plus replicated read-only prerequisites"
	@echo "  make dual-listener-smoke        Validate split public/admin listener topology"
	@echo ""
	@echo "  make compose-config             Validate docker compose config"
	@echo "  make compose-config-mysql       Validate compose config with mysql profile"
	@echo "  make compose-config-scheduled-tasks Validate compose config with scheduled-tasks profile"
	@echo "  make compose-up                 Build embedded UI and start coraza service"
	@echo "  make compose-up-scheduled-tasks Build embedded UI and start coraza + scheduled-task sidecar (proxy-owned paths only)"
	@echo "  make compose-down               Stop stack"
	@echo "  make mysql-up                   Start local mysql profile service"
	@echo "  make mysql-down                 Stop local mysql profile service"
	@echo ""
	@echo "  make preset-list                List available config presets"
	@echo "  make preset-apply               Copy preset files into local workspace"
	@echo "    - optional: PRESET=$(PRESET) PRESET_OVERWRITE=1"
	@echo "  make preset-check               Validate preset files without modifying local files"
	@echo "    - optional: PRESET=$(PRESET)"
	@echo "  make preset-check-minimal       Validate the bundled minimal preset"
	@echo ""
	@echo "  make migrate-proxy-config       Generate data/conf/proxy.json from legacy env"
	@echo "  make migrate-proxy-config-check Validate proxy config file"
	@echo "  make smoke                      Run embedded UI + proxy-rules smoke checks"
	@echo "  make smoke-extended             Run smoke + deployment-smoke"
	@echo "  make binary-deployment-smoke    Validate docs/build binary deployment flow"
	@echo "  make container-deployment-smoke Validate docs/build container deployment flow"
	@echo "  make deployment-smoke           Run binary + container deployment smokes"
	@echo "  make release-binary-smoke       Build/extract a public tarball and run bundle smoke"
	@echo "  make http3-public-entry-smoke   Validate built-in HTTPS + HTTP/3 public entry"
	@echo "  make bench                      Run proxy tuning benchmark presets"
	@echo "  make bench-waf                  Run WAF allow/block performance benchmark"
	@echo "  make bench-full                 Run proxy and WAF benchmarks"
	@echo "  make gotestwaf                  Run GoTestWAF regression"
	@echo ""
	@echo "  make check                      Run go-test + ui-test + compose + minimal preset checks"
	@echo "  make ci-local                   Run local CI baseline (check + smoke)"
	@echo "  make ci-local-extended          Run local CI baseline + deployment docs smokes"
	@echo "  make clean                      Remove local build/test artifacts"
	@echo ""
	@echo "Key variables (override as needed):"
	@echo "  CORAZA_PORT=$(CORAZA_PORT) HOST_CORAZA_PORT=$(HOST_CORAZA_PORT) WAF_LISTEN_PORT=$(WAF_LISTEN_PORT)"
	@echo "  VERSION=$(VERSION) RELEASE_DIR=$(RELEASE_DIR)"
	@echo "  PROTECTED_HOST=$(PROTECTED_HOST)"
	@echo "  WAF_API_KEY_PRIMARY=<api-key> BENCH_REQUESTS=$(BENCH_REQUESTS) WARMUP_REQUESTS=$(WARMUP_REQUESTS)"
	@echo "  BENCH_CONCURRENCY=$(BENCH_CONCURRENCY) BENCH_PATH=$(BENCH_PATH) BENCH_TIMEOUT_SEC=$(BENCH_TIMEOUT_SEC)"
	@echo "  BENCH_MAX_FAIL_RATE_PCT=<pct> BENCH_MIN_RPS=<value> BENCH_DISABLE_RATE_LIMIT=$(BENCH_DISABLE_RATE_LIMIT)"
	@echo "  BENCH_DISABLE_REQUEST_GUARDS=$(BENCH_DISABLE_REQUEST_GUARDS) BENCH_ACCESS_LOG_MODE=$(BENCH_ACCESS_LOG_MODE)"
	@echo "  BENCH_CLIENT_KEEPALIVE=$(BENCH_CLIENT_KEEPALIVE) UPSTREAM_PORT=<auto>"
	@echo "  BENCH_PROXY_MODE=$(BENCH_PROXY_MODE) BENCH_PROXY_ENGINE=$(BENCH_PROXY_ENGINE) BENCH_PROFILE=$(BENCH_PROFILE) BENCH_PROFILE_ADDR=$(BENCH_PROFILE_ADDR) BENCH_PROFILE_SECONDS=$(BENCH_PROFILE_SECONDS)"

env-init:
	@if [[ ! -f .env ]]; then \
		cp .env.example .env; \
		echo "[env-init] created .env from .env.example"; \
	else \
		echo "[env-init] .env already exists (skip)"; \
	fi

preset-list:
	@find presets -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort

preset-apply:
	@set -euo pipefail; \
	preset_dir="$(PRESET_DIR)"; \
	for pair in "$$preset_dir/.env:.env" "$$preset_dir/config.json:data/conf/config.json" "$$preset_dir/proxy.json:data/conf/proxy.json" "$$preset_dir/sites.json:data/conf/sites.json"; do \
		src="$${pair%%:*}"; \
		dst="$${pair#*:}"; \
		if [[ ! -f "$$src" ]]; then \
			echo "[preset-apply][ERROR] missing $$src" >&2; \
			exit 1; \
		fi; \
		mkdir -p "$$(dirname "$$dst")"; \
		if [[ -f "$$dst" && "$(PRESET_OVERWRITE)" != "1" ]]; then \
			if cmp -s "$$src" "$$dst"; then \
				echo "[preset-apply] $$dst already matches $(PRESET)"; \
				continue; \
			fi; \
			echo "[preset-apply] $$dst already exists (set PRESET_OVERWRITE=1 to replace)"; \
			continue; \
		fi; \
		cp "$$src" "$$dst"; \
		echo "[preset-apply] applied $(PRESET) -> $$dst"; \
	done

preset-check:
	@set -euo pipefail; \
	preset_dir="$(PRESET_DIR)"; \
	for src in "$$preset_dir/.env" "$$preset_dir/config.json" "$$preset_dir/proxy.json" "$$preset_dir/sites.json"; do \
		if [[ ! -f "$$src" ]]; then \
			echo "[preset-check][ERROR] missing $$src" >&2; \
			exit 1; \
		fi; \
	done; \
	docker compose --env-file "$$preset_dir/.env" config >/dev/null; \
	python3 -m json.tool "$$preset_dir/config.json" >/dev/null; \
	python3 -m json.tool "$$preset_dir/proxy.json" >/dev/null; \
	python3 -m json.tool "$$preset_dir/sites.json" >/dev/null; \
	preset_mode="$$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("admin", {}).get("external_mode", "").strip().lower())' "$$preset_dir/config.json")"; \
	if [[ -z "$$preset_mode" ]]; then \
		echo "[preset-check][ERROR] $$preset_dir/config.json is missing admin.external_mode" >&2; \
		exit 1; \
	fi; \
	default_mode="$$(grep -m 1 'ExternalMode:' coraza/src/internal/config/app_config_file.go | sed -E 's/.*"([^"]+)".*/\1/' | tr '[:upper:]' '[:lower:]')"; \
	if [[ -z "$$default_mode" ]]; then \
		echo "[preset-check][ERROR] could not read default admin.external_mode from coraza/src/internal/config/app_config_file.go" >&2; \
		exit 1; \
	fi; \
	if [[ "$$preset_mode" != "$$default_mode" ]]; then \
		echo "[preset-check][ERROR] $$preset_dir/config.json admin.external_mode=$$preset_mode does not match [proxy] default admin.external_mode=$$default_mode" >&2; \
		exit 1; \
		fi; \
	echo "[preset-check] $(PRESET) ok"

preset-check-minimal:
	@$(MAKE) --no-print-directory preset-check PRESET=minimal

crs-install:
	./scripts/install_crs.sh

setup: env-init crs-install

go-test:
	cd $(CORAZA_SRC) && $(GO) test ./...

go-build:
	mkdir -p $(abspath $(BIN_DIR))
	cd $(CORAZA_SRC) && $(GO) build -o "$(abspath $(BIN_DIR))/$(APP_NAME)" $(APP_PKG)
	@echo "[go-build] built $(abspath $(BIN_DIR))/$(APP_NAME)"

build: ui-build-sync go-build

release-linux-amd64:
	@set -euo pipefail; \
	out_dir="$(abspath $(RELEASE_DIR))"; \
	tmp_dir="$$out_dir/.tmp-linux-amd64"; \
	rm -rf "$$tmp_dir"; \
	mkdir -p "$$tmp_dir" "$$out_dir"; \
	$(DOCKER) buildx build \
		--platform linux/amd64 \
		--build-arg APP_NAME="$(APP_NAME)" \
		--build-arg VERSION="$(VERSION)" \
		--output type=local,dest="$$tmp_dir" \
		-f "$(RELEASE_DOCKERFILE)" .; \
	find "$$tmp_dir" -maxdepth 1 -type f -exec mv {} "$$out_dir"/ \; ; \
	rm -rf "$$tmp_dir"; \
	echo "[release] built linux/amd64 into $$out_dir"

release-linux-arm64:
	@set -euo pipefail; \
	out_dir="$(abspath $(RELEASE_DIR))"; \
	tmp_dir="$$out_dir/.tmp-linux-arm64"; \
	rm -rf "$$tmp_dir"; \
	mkdir -p "$$tmp_dir" "$$out_dir"; \
	$(DOCKER) buildx build \
		--platform linux/arm64 \
		--build-arg APP_NAME="$(APP_NAME)" \
		--build-arg VERSION="$(VERSION)" \
		--output type=local,dest="$$tmp_dir" \
		-f "$(RELEASE_DOCKERFILE)" .; \
	find "$$tmp_dir" -maxdepth 1 -type f -exec mv {} "$$out_dir"/ \; ; \
	rm -rf "$$tmp_dir"; \
	echo "[release] built linux/arm64 into $$out_dir"

release-linux-all: release-linux-amd64 release-linux-arm64
	@set -euo pipefail; \
	out_dir="$(abspath $(RELEASE_DIR))"; \
	sums_file="$$out_dir/$(APP_NAME)_$(VERSION)_SHA256SUMS"; \
	cat \
		"$$out_dir/$(APP_NAME)_$(VERSION)_linux_amd64.tar.gz.sha256" \
		"$$out_dir/$(APP_NAME)_$(VERSION)_linux_arm64.tar.gz.sha256" \
		> "$$sums_file"; \
	echo "[release] wrote $$sums_file"

ui-install:
	cd $(UI_DIR) && $(NPM) ci

ui-test: ui-install
	cd $(UI_DIR) && $(NPM) test -- --runInBand

ui-build: ui-install
	cd $(UI_DIR) && $(NPM) run build

ui-sync:
	@if [[ ! -d "$(UI_DIR)/dist" ]]; then \
		echo "[ui-sync] missing $(UI_DIR)/dist (run: make ui-build)"; \
		exit 1; \
	fi
	@mkdir -p $(UI_EMBED_DIR)
	find "$(UI_EMBED_DIR)" -mindepth 1 \
		! -name '.gitignore' \
		! -name 'placeholder.html' \
		-exec rm -rf {} +
	cp -a $(UI_DIR)/dist/. $(UI_EMBED_DIR)/
	@echo "[ui-sync] synced $(UI_DIR)/dist -> $(UI_EMBED_DIR)"

ui-build-sync: ui-build ui-sync

ui-preview-up: ui-build-sync
	bash ./scripts/ui_preview.sh up

ui-preview-down:
	bash ./scripts/ui_preview.sh down

ui-preview-smoke:
	bash ./scripts/run_ui_preview_smoke.sh

php-fpm-build:
	VER="$(VER)" RUNTIME="$(RUNTIME)" ./scripts/php_fpm_runtime_build.sh

php-fpm-copy:
	RUNTIME="$(RUNTIME)" DEST="$(DEST)" ./scripts/php_fpm_runtime_copy.sh

php-fpm-prune:
	RUNTIME="$(RUNTIME)" DEST="$(DEST)" ./scripts/php_fpm_runtime_prune.sh

php-fpm-remove:
	RUNTIME="$(RUNTIME)" ./scripts/php_fpm_runtime_remove.sh

php-fpm-up:
	RUNTIME="$(RUNTIME)" CORAZA_PORT="$(CORAZA_PORT)" WAF_API_KEY_PRIMARY="$(WAF_API_KEY_PRIMARY)" ./scripts/php_fpm_runtime_ctl.sh up

php-fpm-down:
	RUNTIME="$(RUNTIME)" CORAZA_PORT="$(CORAZA_PORT)" WAF_API_KEY_PRIMARY="$(WAF_API_KEY_PRIMARY)" ./scripts/php_fpm_runtime_ctl.sh down

php-fpm-reload:
	RUNTIME="$(RUNTIME)" CORAZA_PORT="$(CORAZA_PORT)" WAF_API_KEY_PRIMARY="$(WAF_API_KEY_PRIMARY)" ./scripts/php_fpm_runtime_ctl.sh reload

php-fpm-test:
	cd $(CORAZA_SRC) && $(GO) test ./internal/handler -run 'Test(PHPRuntimeInventoryListsOnlyBuiltArtifacts|ApplyPHPRuntimeInventoryRawDoesNotDeadlockOnMaterializationRefresh|GetPHPRuntimesAndVhostsHandlers|ValidatePHPRuntimeInventoryRawIgnoresLegacyPHPSupportFlag|DefaultPHPRuntimeInventoryStartsEmptyUntilRuntimeIsBuilt|ValidatePHPRuntimeInventoryRawLoadsBuiltArtifactModulesAndDefaults|ValidateVhostConfigRawRequiresKnownRuntime|ValidateVhostConfigRawAcceptsKnownRuntimeWithoutSupportToggle|ApplyAndRollbackVhostConfigRaw|PHPRuntimeSupervisorStartsRestartsAndStopsRuntime|ResolvePHPRuntimeIdentityUsesConfiguredCurrentUserAndGroup|ValidatePHPRuntimeLaunchRejectsPrivilegeTransitionWithoutRoot|ValidatePHPRuntimeLaunchRejectsUnreadableDocumentRoot|ServeProxyServesStaticVhostAssets|ServeProxyRunsFastCGITryFilesAndStaticAssets|ServeProxyRunsFastCGIOverUnixSocket|ServeProxyAppliesVhostRewriteAccessAndBasicAuth|BuildPHPRuntimePoolConfigIncludesINIOverrides|ValidateVhostConfigRejectsPlaintextBasicAuthHash)'

php-fpm-smoke: ui-build-sync
	VER="$(VER)" CORAZA_PORT="$(CORAZA_PORT)" WAF_LISTEN_PORT="$(WAF_LISTEN_PORT)" WAF_API_KEY_PRIMARY="$(WAF_API_KEY_PRIMARY)" ./scripts/run_php_fpm_smoke.sh

scheduled-tasks-smoke: build
	SCHEDULED_TASKS_SMOKE_SKIP_BUILD=1 ./scripts/run_scheduled_tasks_smoke.sh

container-platform-smoke: build
	CONTAINER_PLATFORM_SMOKE_SKIP_BUILD=1 ./scripts/run_container_platform_smoke.sh

compose-config:
	docker compose config >/dev/null
	@echo "[compose-config] ok"

compose-config-mysql:
	docker compose --profile mysql config >/dev/null
	@echo "[compose-config-mysql] ok"

compose-config-scheduled-tasks:
	docker compose --profile scheduled-tasks config >/dev/null
	@echo "[compose-config-scheduled-tasks] ok"

compose-up: ui-build-sync
	PUID="$(PUID)" GUID="$(GUID)" CORAZA_PORT="$(CORAZA_PORT)" WAF_LISTEN_PORT="$(WAF_LISTEN_PORT)" docker compose up -d --build coraza

compose-up-scheduled-tasks: ui-build-sync
	PUID="$(PUID)" GUID="$(GUID)" CORAZA_PORT="$(CORAZA_PORT)" WAF_LISTEN_PORT="$(WAF_LISTEN_PORT)" docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner

compose-down:
	PUID="$(PUID)" GUID="$(GUID)" CORAZA_PORT="$(CORAZA_PORT)" docker compose --profile mysql --profile scheduled-tasks down --remove-orphans

mysql-up:
	PUID="$(PUID)" GUID="$(GUID)" docker compose --profile mysql up -d mysql

mysql-down:
	PUID="$(PUID)" GUID="$(GUID)" docker compose --profile mysql down -v

migrate-proxy-config:
	./scripts/migrate_proxy_config.sh

migrate-proxy-config-check:
	./scripts/migrate_proxy_config.sh --check

smoke: ui-build-sync
	@set -euo pipefail; \
	backup="$$(mktemp)"; \
	cp data/conf/proxy.json "$$backup"; \
	trap 'cp "$$backup" data/conf/proxy.json >/dev/null 2>&1 || true; rm -f "$$backup"; PUID="$(PUID)" GUID="$(GUID)" CORAZA_PORT="$(HOST_CORAZA_PORT)" docker compose down --remove-orphans >/dev/null 2>&1 || true' EXIT; \
	PUID="$(PUID)" GUID="$(GUID)" CORAZA_PORT="$(HOST_CORAZA_PORT)" WAF_LISTEN_PORT="$(WAF_LISTEN_PORT)" docker compose up -d --build coraza >/dev/null; \
	HOST_CORAZA_PORT="$(HOST_CORAZA_PORT)" WAF_LISTEN_PORT="$(WAF_LISTEN_PORT)" WAF_API_KEY_PRIMARY="$(WAF_API_KEY_PRIMARY)" PROTECTED_HOST="$(PROTECTED_HOST)" PROXY_ECHO_PORT="18080" PROXY_ECHO_URL="http://host.docker.internal:18080" ./scripts/ci_proxy_admin_smoke.sh

binary-deployment-smoke:
	./scripts/run_binary_deployment_smoke.sh

container-deployment-smoke:
	./scripts/run_container_deployment_smoke.sh

dual-listener-smoke: build
	DUAL_LISTENER_SMOKE_SKIP_BUILD=1 ./scripts/run_dual_listener_smoke.sh

deployment-smoke: build
	BINARY_DEPLOYMENT_SKIP_BUILD=1 ./scripts/run_binary_deployment_smoke.sh
	DUAL_LISTENER_SMOKE_SKIP_BUILD=1 ./scripts/run_dual_listener_smoke.sh
	CONTAINER_PLATFORM_SMOKE_SKIP_BUILD=1 ./scripts/run_container_platform_smoke.sh

release-binary-smoke:
	VERSION="$(VERSION)" APP_NAME="$(APP_NAME)" RELEASE_DIR="$(RELEASE_DIR)" RELEASE_BINARY_SMOKE_ARCH="$(RELEASE_BINARY_SMOKE_ARCH)" RELEASE_BINARY_SMOKE_SKIP_BUILD="$(RELEASE_BINARY_SMOKE_SKIP_BUILD)" RELEASE_BINARY_SMOKE_AUTO_DOWN="$(RELEASE_BINARY_SMOKE_AUTO_DOWN)" RELEASE_BINARY_SMOKE_KEEP_EXTRACTED="$(RELEASE_BINARY_SMOKE_KEEP_EXTRACTED)" ./scripts/run_release_binary_smoke.sh

http3-public-entry-smoke:
	./scripts/run_http3_public_entry_smoke.sh

smoke-extended: smoke deployment-smoke

bench: bench-proxy

bench-proxy:
	GO="$(GO)" HOST_CORAZA_PORT="$(HOST_CORAZA_PORT)" WAF_LISTEN_PORT="$(WAF_LISTEN_PORT)" WAF_API_KEY_PRIMARY="$(WAF_API_KEY_PRIMARY)" BENCH_REQUESTS="$(BENCH_REQUESTS)" WARMUP_REQUESTS="$(WARMUP_REQUESTS)" BENCH_CONCURRENCY="$(BENCH_CONCURRENCY)" BENCH_PATH="$(BENCH_PATH)" BENCH_TIMEOUT_SEC="$(BENCH_TIMEOUT_SEC)" BENCH_MAX_FAIL_RATE_PCT="$(BENCH_MAX_FAIL_RATE_PCT)" BENCH_MIN_RPS="$(BENCH_MIN_RPS)" BENCH_DISABLE_RATE_LIMIT="$(BENCH_DISABLE_RATE_LIMIT)" BENCH_DISABLE_REQUEST_GUARDS="$(BENCH_DISABLE_REQUEST_GUARDS)" BENCH_ACCESS_LOG_MODE="$(BENCH_ACCESS_LOG_MODE)" BENCH_CLIENT_KEEPALIVE="$(BENCH_CLIENT_KEEPALIVE)" BENCH_PROXY_MODE="$(BENCH_PROXY_MODE)" BENCH_PROXY_ENGINE="$(BENCH_PROXY_ENGINE)" BENCH_PROFILE="$(BENCH_PROFILE)" BENCH_PROFILE_ADDR="$(BENCH_PROFILE_ADDR)" BENCH_PROFILE_SECONDS="$(BENCH_PROFILE_SECONDS)" UPSTREAM_PORT="$(UPSTREAM_PORT)" ./scripts/benchmark_proxy_tuning.sh

bench-waf:
	GO="$(GO)" HOST_CORAZA_PORT="$(HOST_CORAZA_PORT)" WAF_LISTEN_PORT="$(WAF_LISTEN_PORT)" WAF_API_KEY_PRIMARY="$(WAF_API_KEY_PRIMARY)" BENCH_REQUESTS="$(BENCH_REQUESTS)" WARMUP_REQUESTS="$(WARMUP_REQUESTS)" BENCH_CONCURRENCY="$(BENCH_CONCURRENCY)" BENCH_PATH="$(BENCH_PATH)" BENCH_TIMEOUT_SEC="$(BENCH_TIMEOUT_SEC)" BENCH_MAX_FAIL_RATE_PCT="$(BENCH_MAX_FAIL_RATE_PCT)" BENCH_MIN_RPS="$(BENCH_MIN_RPS)" BENCH_DISABLE_RATE_LIMIT="$(BENCH_DISABLE_RATE_LIMIT)" BENCH_DISABLE_REQUEST_GUARDS="$(BENCH_DISABLE_REQUEST_GUARDS)" UPSTREAM_PORT="$(UPSTREAM_PORT)" ./scripts/benchmark_waf.sh

bench-full: bench-proxy bench-waf

gotestwaf:
	@set -euo pipefail; \
	backup="$$(mktemp)"; \
	cp data/conf/proxy.json "$$backup"; \
	trap 'cp "$$backup" data/conf/proxy.json >/dev/null 2>&1 || true; rm -f "$$backup"' EXIT; \
	tmp_proxy="$$(mktemp)"; \
	jq '.upstreams = [{"name":"gotestwaf-unreachable","url":"http://127.0.0.1:9081","weight":1,"enabled":true}]' data/conf/proxy.json > "$$tmp_proxy"; \
	mv "$$tmp_proxy" data/conf/proxy.json; \
	HOST_CORAZA_PORT="$(HOST_CORAZA_PORT)" WAF_LISTEN_PORT="$(WAF_LISTEN_PORT)" ./scripts/run_gotestwaf.sh

check: go-test ui-test compose-config compose-config-mysql preset-check-minimal

ci-local: check smoke

ci-local-extended: check smoke-extended

clean:
	rm -rf $(BIN_DIR) $(RELEASE_DIR) $(UI_DIR)/.tmp-test
	@echo "[clean] done"
