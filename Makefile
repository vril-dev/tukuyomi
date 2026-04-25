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
BENCH_RUNNER ?= docker
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
DB_MIGRATE_BIN ?= $(abspath $(BIN_DIR))/$(APP_NAME)
DB_MIGRATE_WORKDIR ?= data
DB_MIGRATE_CONFIG ?= conf/config.json
VERSION ?= dev
RELEASE_DIR ?= dist/release
RELEASE_DOCKERFILE ?= build/Dockerfile.release
PRESET ?= minimal
PRESET_DIR := presets/$(PRESET)
PRESET_OVERWRITE ?= 0
TARGET ?=
INSTALL_TARGET ?= linux-systemd
INSTALL_PREFIX ?= $(if $(PREFIX),$(PREFIX),/opt/tukuyomi)
INSTALL_USER ?=
INSTALL_GROUP ?=
INSTALL_CREATE_USER ?= auto
INSTALL_ENABLE_SYSTEMD ?= 1
INSTALL_ENABLE_SCHEDULED_TASKS ?= 0
INSTALL_DB_SEED ?= auto
DEPLOY_TARGET ?=
DEPLOY_RENDER_OUT_DIR ?= dist/deploy
DEPLOY_RENDER_OVERWRITE ?= 0
IMAGE_URI ?=

export PUID GUID CORAZA_PORT HOST_CORAZA_PORT WAF_LISTEN_PORT WAF_API_KEY_PRIMARY PROTECTED_HOST

.PHONY: \
	help setup env-init crs-install crs-ensure \
	install deploy-render install-smoke deploy-render-smoke \
	go-test go-fuzz-short go-build db-migrate db-import db-import-waf-rule-assets build \
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
	@echo "  make setup                      Prepare local dev baseline (.env + DB migration + DB config/rule assets)"
	@echo "  make env-init                   Create .env from .env.example if missing"
	@echo "  make crs-install                Run db-migrate, install OWASP CRS seed files, and import WAF rule assets into DB"
	@echo "  make crs-ensure                 Run db-migrate, install CRS only when missing, and import WAF rule assets into DB"
	@echo "  make install TARGET=linux-systemd Install binary runtime onto this Linux host"
	@echo "    - optional: PREFIX=/opt/tukuyomi INSTALL_USER=<user> INSTALL_ENABLE_SCHEDULED_TASKS=1 INSTALL_DB_SEED=auto|always|never"
	@echo "  make deploy-render TARGET=ecs|kubernetes|azure-container-apps|container-image IMAGE_URI=... Render deploy artifacts"
	@echo "    - optional: DEPLOY_RENDER_OUT_DIR=dist/deploy DEPLOY_RENDER_OVERWRITE=1"
	@echo ""
	@echo "  make go-test                    Run Go tests (coraza/src)"
	@echo "  make go-fuzz-short              Run short native HTTP/1 fuzz passes"
	@echo "  make go-build                   Build single binary into ./bin/$(APP_NAME)"
	@echo "  make db-migrate                 Build binary and apply configured DB schema migrations"
	@echo "  make db-import                  Import startup seed/export files into DB"
	@echo "  make db-import-waf-rule-assets  Import base WAF and CRS rule/data assets into DB"
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
	@echo "    - optional: UI_PREVIEW_PERSIST=1 keeps preview DB state across down/up"
	@echo "  make ui-preview-down            Stop screenshot preview runtime and remove temp override"
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
	@echo "    - optional: BENCH_RUNNER=local runs the benchmark without Docker"
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
	for pair in "$$preset_dir/.env:.env" "$$preset_dir/config.json:data/conf/config.json"; do \
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
	for src in "$$preset_dir/.env" "$$preset_dir/config.json"; do \
		if [[ ! -f "$$src" ]]; then \
			echo "[preset-check][ERROR] missing $$src" >&2; \
			exit 1; \
		fi; \
	done; \
	docker compose --env-file "$$preset_dir/.env" config >/dev/null; \
	python3 -m json.tool "$$preset_dir/config.json" >/dev/null; \
	top_keys="$$(python3 -c 'import json, sys; print("\n".join(sorted(json.load(open(sys.argv[1], encoding="utf-8")).keys())))' "$$preset_dir/config.json")"; \
	if [[ "$$top_keys" != "storage" ]]; then \
		echo "[preset-check][ERROR] $$preset_dir/config.json must contain only the storage bootstrap block" >&2; \
		exit 1; \
	fi; \
	storage_keys="$$(python3 -c 'import json, sys; obj=json.load(open(sys.argv[1], encoding="utf-8")); storage=obj.get("storage"); print("\n".join(sorted(storage.keys())) if isinstance(storage, dict) else "")' "$$preset_dir/config.json")"; \
	expected_storage_keys=$$'db_driver\ndb_dsn\ndb_path\ndb_retention_days\ndb_sync_interval_sec'; \
	if [[ "$$storage_keys" != "$$expected_storage_keys" ]]; then \
		echo "[preset-check][ERROR] $$preset_dir/config.json storage keys must be: db_driver, db_path, db_dsn, db_retention_days, db_sync_interval_sec" >&2; \
		exit 1; \
	fi; \
	db_driver="$$(python3 -c 'import json, sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["storage"]["db_driver"]).strip().lower())' "$$preset_dir/config.json")"; \
	db_path="$$(python3 -c 'import json, sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["storage"]["db_path"]).strip())' "$$preset_dir/config.json")"; \
	db_dsn="$$(python3 -c 'import json, sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["storage"]["db_dsn"]).strip())' "$$preset_dir/config.json")"; \
	if [[ "$$db_driver" != "sqlite" && "$$db_driver" != "mysql" && "$$db_driver" != "pgsql" ]]; then \
		echo "[preset-check][ERROR] $$preset_dir/config.json storage.db_driver must be sqlite, mysql, or pgsql" >&2; \
		exit 1; \
	fi; \
	if [[ "$$db_driver" == "sqlite" && -z "$$db_path" ]]; then \
		echo "[preset-check][ERROR] $$preset_dir/config.json storage.db_path is required for sqlite" >&2; \
		exit 1; \
	fi; \
	if [[ "$$db_driver" != "sqlite" && -z "$$db_dsn" ]]; then \
		echo "[preset-check][ERROR] $$preset_dir/config.json storage.db_dsn is required for mysql/pgsql" >&2; \
		exit 1; \
	fi; \
	if ! python3 -c 'import json, sys; storage=json.load(open(sys.argv[1], encoding="utf-8"))["storage"]; ok=type(storage["db_retention_days"]) is int and storage["db_retention_days"] >= 0 and type(storage["db_sync_interval_sec"]) is int and storage["db_sync_interval_sec"] >= 0; raise SystemExit(0 if ok else 1)' "$$preset_dir/config.json"; then \
		echo "[preset-check][ERROR] $$preset_dir/config.json storage retention/sync values must be non-negative integers" >&2; \
		exit 1; \
	fi; \
	echo "[preset-check] $(PRESET) ok"

preset-check-minimal:
	@$(MAKE) --no-print-directory preset-check PRESET=minimal

install:
	@TARGET="$(or $(TARGET),$(INSTALL_TARGET))" \
	PREFIX="$(INSTALL_PREFIX)" \
	INSTALL_USER="$(INSTALL_USER)" \
	INSTALL_GROUP="$(INSTALL_GROUP)" \
	INSTALL_CREATE_USER="$(INSTALL_CREATE_USER)" \
	INSTALL_ENABLE_SYSTEMD="$(INSTALL_ENABLE_SYSTEMD)" \
	INSTALL_ENABLE_SCHEDULED_TASKS="$(INSTALL_ENABLE_SCHEDULED_TASKS)" \
	INSTALL_DB_SEED="$(INSTALL_DB_SEED)" \
	./scripts/install_tukuyomi.sh

deploy-render:
	@TARGET="$(or $(TARGET),$(DEPLOY_TARGET))" \
	IMAGE_URI="$(IMAGE_URI)" \
	DEPLOY_RENDER_OUT_DIR="$(DEPLOY_RENDER_OUT_DIR)" \
	DEPLOY_RENDER_OVERWRITE="$(DEPLOY_RENDER_OVERWRITE)" \
	./scripts/render_deploy_artifacts.sh

install-smoke: build
	@set -euo pipefail; \
	tmp="$$(mktemp -d "$(ROOT_DIR)/.tmp-install-smoke.XXXXXX")"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	TARGET=linux-systemd \
	DESTDIR="$$tmp" \
	PREFIX=/opt/tukuyomi \
	INSTALL_SKIP_BUILD=1 \
	INSTALL_ENABLE_SYSTEMD=0 \
	INSTALL_DB_SEED=always \
	./scripts/install_tukuyomi.sh; \
	test -x "$$tmp/opt/tukuyomi/bin/tukuyomi"; \
	test -f "$$tmp/opt/tukuyomi/conf/config.json"; \
	test -d "$$tmp/opt/tukuyomi/data/persistent"; \
	test -f "$$tmp/opt/tukuyomi/db/tukuyomi.db"; \
	echo "[install-smoke] ok"

deploy-render-smoke:
	@set -euo pipefail; \
	tmp="$$(mktemp -d "$(ROOT_DIR)/.tmp-deploy-render-smoke.XXXXXX")"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	for target in ecs kubernetes azure-container-apps container-image; do \
		TARGET="$$target" IMAGE_URI="registry.example.test/tukuyomi:smoke" DEPLOY_RENDER_OUT_DIR="$$(basename "$$tmp")" DEPLOY_RENDER_OVERWRITE=1 ./scripts/render_deploy_artifacts.sh; \
	done; \
	jq empty "$$tmp/ecs/task-definition.json"; \
	jq empty "$$tmp/ecs/service.json"; \
	test -f "$$tmp/kubernetes/single-instance.yaml"; \
	test -f "$$tmp/azure-container-apps/single-instance.yaml"; \
	test -x "$$tmp/container-image/build.sh"; \
	echo "[deploy-render-smoke] ok"

crs-install: db-migrate
	@set -euo pipefail; \
	workdir="$(DB_MIGRATE_WORKDIR)"; \
	config_file="$${WAF_CONFIG_FILE:-$(DB_MIGRATE_CONFIG)}"; \
	if [[ "$$config_file" != /* && ! -f "$$workdir/$$config_file" && -f "$(ROOT_DIR)/$$config_file" ]]; then \
		config_file="$(ROOT_DIR)/$$config_file"; \
	fi; \
	stage_root="$$workdir/tmp/waf-rule-assets"; \
	rm -rf "$$stage_root"; \
	mkdir -p "$$stage_root"; \
	trap 'rm -rf "$$stage_root"' EXIT; \
	./scripts/stage_waf_rule_assets.sh "$$stage_root"; \
	echo "[crs-install] importing WAF rule assets into DB"; \
	cd "$$workdir"; \
	WAF_RULE_ASSET_FS_ROOT="tmp/waf-rule-assets" WAF_CONFIG_FILE="$$config_file" "$(DB_MIGRATE_BIN)" db-import-waf-rule-assets

crs-ensure: db-migrate
	@set -euo pipefail; \
	workdir="$(DB_MIGRATE_WORKDIR)"; \
	config_file="$${WAF_CONFIG_FILE:-$(DB_MIGRATE_CONFIG)}"; \
	if [[ "$$config_file" != /* && ! -f "$$workdir/$$config_file" && -f "$(ROOT_DIR)/$$config_file" ]]; then \
		config_file="$(ROOT_DIR)/$$config_file"; \
	fi; \
	stage_root="$$workdir/tmp/waf-rule-assets"; \
	rm -rf "$$stage_root"; \
	mkdir -p "$$stage_root"; \
	trap 'rm -rf "$$stage_root"' EXIT; \
	./scripts/stage_waf_rule_assets.sh "$$stage_root"; \
	echo "[crs-ensure] importing WAF rule assets into DB"; \
	cd "$$workdir"; \
	WAF_RULE_ASSET_FS_ROOT="tmp/waf-rule-assets" WAF_CONFIG_FILE="$$config_file" "$(DB_MIGRATE_BIN)" db-import-waf-rule-assets

setup: env-init crs-install db-import

go-test:
	cd $(CORAZA_SRC) && $(GO) test ./...

go-fuzz-short:
	cd $(CORAZA_SRC) && set -e; for target in \
		FuzzNativeHTTP1ParseStatusLine \
		FuzzNativeHTTP1ReadHeaderBlock \
		FuzzNativeHTTP1ChunkedRead \
		FuzzNativeHTTP1ReadResponse \
		FuzzNativeHTTP1WriteRequest \
		FuzzNativeHTTP2FrameReader \
		FuzzNativeHTTP2HPACKDecode \
		FuzzNativeHTTP2StreamState \
		FuzzNativeHTTP2FlowControlAccounting; do \
		$(GO) test ./internal/handler -run '^$$' -fuzz "$$target" -fuzztime=5s; \
	done

go-build:
	mkdir -p $(abspath $(BIN_DIR))
	cd $(CORAZA_SRC) && $(GO) build -o "$(abspath $(BIN_DIR))/$(APP_NAME)" $(APP_PKG)
	@echo "[go-build] built $(abspath $(BIN_DIR))/$(APP_NAME)"

db-migrate: go-build
	@set -euo pipefail; \
	workdir="$(DB_MIGRATE_WORKDIR)"; \
	config_file="$${WAF_CONFIG_FILE:-$(DB_MIGRATE_CONFIG)}"; \
	if [[ ! -d "$$workdir" ]]; then \
		echo "[db-migrate][ERROR] DB_MIGRATE_WORKDIR does not exist: $$workdir" >&2; \
		exit 1; \
	fi; \
	if [[ "$$config_file" != /* && ! -f "$$workdir/$$config_file" && -f "$(ROOT_DIR)/$$config_file" ]]; then \
		config_file="$(ROOT_DIR)/$$config_file"; \
	fi; \
	if [[ "$$config_file" != /* && ! -f "$$workdir/$$config_file" ]]; then \
		echo "[db-migrate][ERROR] config not found: $$workdir/$$config_file" >&2; \
		exit 1; \
	fi; \
	echo "[db-migrate] workdir=$$workdir config=$$config_file"; \
	cd "$$workdir"; \
	WAF_CONFIG_FILE="$$config_file" "$(DB_MIGRATE_BIN)" db-migrate

db-import: db-migrate
	@set -euo pipefail; \
	workdir="$(DB_MIGRATE_WORKDIR)"; \
	config_file="$${WAF_CONFIG_FILE:-$(DB_MIGRATE_CONFIG)}"; \
	seed_conf_dir="$${WAF_DB_IMPORT_SEED_CONF_DIR-$(ROOT_DIR)/seeds/conf}"; \
	if [[ "$$config_file" != /* && ! -f "$$workdir/$$config_file" && -f "$(ROOT_DIR)/$$config_file" ]]; then \
		config_file="$(ROOT_DIR)/$$config_file"; \
	fi; \
	echo "[db-import] workdir=$$workdir config=$$config_file seed_conf=$$seed_conf_dir"; \
	cd "$$workdir"; \
	WAF_DB_IMPORT_SEED_CONF_DIR="$$seed_conf_dir" WAF_CONFIG_FILE="$$config_file" "$(DB_MIGRATE_BIN)" db-import

db-import-waf-rule-assets: db-migrate
	@set -euo pipefail; \
	workdir="$(DB_MIGRATE_WORKDIR)"; \
	config_file="$${WAF_CONFIG_FILE:-$(DB_MIGRATE_CONFIG)}"; \
	if [[ "$$config_file" != /* && ! -f "$$workdir/$$config_file" && -f "$(ROOT_DIR)/$$config_file" ]]; then \
		config_file="$(ROOT_DIR)/$$config_file"; \
	fi; \
	echo "[db-import-waf-rule-assets] workdir=$$workdir config=$$config_file"; \
	cd "$$workdir"; \
	WAF_CONFIG_FILE="$$config_file" "$(DB_MIGRATE_BIN)" db-import-waf-rule-assets

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

ui-preview-up: crs-ensure ui-build-sync
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
	cd $(CORAZA_SRC) && $(GO) test ./internal/handler -run 'Test(PHPRuntimeInventoryListsOnlyBuiltArtifacts|PHPRuntimeInventoryDBAutoDiscoveryReflectsBuiltArtifactsAfterStartup|PHPRuntimeInventoryDBExplicitEmptyDoesNotAutoDiscover|PHPRuntimeInventoryDBLegacyImportWithoutStateAutoDiscovers|PHPRuntimeInventoryDBLoadsWithoutInventoryOrManifestJSON|ApplyPHPRuntimeInventoryRawDoesNotDeadlockOnMaterializationRefresh|GetPHPRuntimesAndVhostsHandlers|ValidatePHPRuntimeInventoryRawIgnoresLegacyPHPSupportFlag|DefaultPHPRuntimeInventoryStartsEmptyUntilRuntimeIsBuilt|ValidatePHPRuntimeInventoryRawLoadsBuiltArtifactModulesAndDefaults|ValidateVhostConfigRawRequiresKnownRuntime|ValidateVhostConfigRawAcceptsKnownRuntimeWithoutSupportToggle|ApplyAndRollbackVhostConfigRaw|PHPRuntimeSupervisorStartsRestartsAndStopsRuntime|ResolvePHPRuntimeIdentityUsesConfiguredCurrentUserAndGroup|ValidatePHPRuntimeLaunchRejectsPrivilegeTransitionWithoutRoot|ValidatePHPRuntimeLaunchRejectsUnreadableDocumentRoot|ServeProxyServesStaticVhostAssets|ServeProxyRunsFastCGIOverUnixSocket|ServeProxyRunsFastCGITryFilesAndStaticAssets|ServeProxyAppliesVhostRewriteAccessAndBasicAuth|BuildPHPRuntimePoolConfigIncludesINIOverrides|ValidateVhostConfigRejectsPlaintextBasicAuthHash)'

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

smoke: db-import ui-build-sync
	@set -euo pipefail; \
	backup="$$(mktemp)"; \
	had_proxy_seed=0; \
	if [ -f data/conf/proxy.json ]; then cp data/conf/proxy.json "$$backup"; had_proxy_seed=1; fi; \
	trap 'if [ "$$had_proxy_seed" = "1" ]; then cp "$$backup" data/conf/proxy.json >/dev/null 2>&1 || true; fi; rm -f "$$backup"; PUID="$(PUID)" GUID="$(GUID)" CORAZA_PORT="$(HOST_CORAZA_PORT)" docker compose down --remove-orphans >/dev/null 2>&1 || true' EXIT; \
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
	GO="$(GO)" HOST_CORAZA_PORT="$(HOST_CORAZA_PORT)" WAF_LISTEN_PORT="$(WAF_LISTEN_PORT)" WAF_API_KEY_PRIMARY="$(WAF_API_KEY_PRIMARY)" BENCH_REQUESTS="$(BENCH_REQUESTS)" WARMUP_REQUESTS="$(WARMUP_REQUESTS)" BENCH_CONCURRENCY="$(BENCH_CONCURRENCY)" BENCH_PATH="$(BENCH_PATH)" BENCH_TIMEOUT_SEC="$(BENCH_TIMEOUT_SEC)" BENCH_MAX_FAIL_RATE_PCT="$(BENCH_MAX_FAIL_RATE_PCT)" BENCH_MIN_RPS="$(BENCH_MIN_RPS)" BENCH_DISABLE_RATE_LIMIT="$(BENCH_DISABLE_RATE_LIMIT)" BENCH_DISABLE_REQUEST_GUARDS="$(BENCH_DISABLE_REQUEST_GUARDS)" BENCH_ACCESS_LOG_MODE="$(BENCH_ACCESS_LOG_MODE)" BENCH_CLIENT_KEEPALIVE="$(BENCH_CLIENT_KEEPALIVE)" BENCH_PROXY_MODE="$(BENCH_PROXY_MODE)" BENCH_PROXY_ENGINE="$(BENCH_PROXY_ENGINE)" BENCH_RUNNER="$(BENCH_RUNNER)" BENCH_PROFILE="$(BENCH_PROFILE)" BENCH_PROFILE_ADDR="$(BENCH_PROFILE_ADDR)" BENCH_PROFILE_SECONDS="$(BENCH_PROFILE_SECONDS)" UPSTREAM_PORT="$(UPSTREAM_PORT)" ./scripts/benchmark_proxy_tuning.sh

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
