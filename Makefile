SHELL := /bin/bash

.DEFAULT_GOAL := help

GO ?= go
NPM ?= npm

PUID ?= $(shell id -u)
GUID ?= $(shell id -g)

HOST_CORAZA_PORT ?= 19090
HOST_NGINX_PORT ?= 18080
MYSQL_ROOT_PASSWORD ?= tukuyomi-root
WAF_TEST_MYSQL_DSN ?= tukuyomi:tukuyomi@tcp(127.0.0.1:13306)/tukuyomi?charset=utf8mb4&parseTime=true

MIN_BLOCKED_RATIO ?= 70
WAF_STORAGE_BACKEND ?= file
WAF_DB_ENABLED ?= false
WAF_DB_RETENTION_DAYS ?= 30
GOTESTWAF_AUTO_DOWN ?= 1
TOPOLOGY ?= front
SCENARIO ?= pass

CORAZA_SRC := coraza/src
UI_DIR := web/tukuyomi-admin
UI_EMBED_DIR := coraza/src/internal/handler/admin_ui_dist
BIN_DIR ?= bin
APP_NAME ?= tukuyomi
APP_PKG ?= ./cmd/server
EXAMPLES := api-gateway nextjs wordpress
EXAMPLE ?= api-gateway
PRESET ?= minimal
PRESET_DIR := presets/$(PRESET)
PRESET_OVERWRITE ?= 0

DOCKER_ENV = PUID="$(PUID)" GUID="$(GUID)"
STACK_ENV = $(DOCKER_ENV) NGINX_PORT="$(HOST_NGINX_PORT)" OPENRESTY_PORT="$(HOST_NGINX_PORT)" CORAZA_PORT="$(HOST_CORAZA_PORT)"

.PHONY: \
	help setup env-init crs-install \
	go-test go-build mysql-logstore-test \
	ui-install ui-test ui-build ui-sync ui-build-sync \
	compose-config compose-config-mysql compose-build compose-up compose-down web-up web-down mysql-up mysql-down \
	preset-list preset-apply preset-check \
	gotestwaf gotestwaf-file gotestwaf-sqlite \
	example-smoke example-smoke-all standalone-smoke standalone-smoke-all standalone-policy-fixture standalone-regression-fast standalone-regression-extended \
	binary-deployment-smoke container-deployment-smoke deployment-smoke \
	benchmark-scenario benchmark-baseline \
	check ci-local clean

help:
	@echo "Targets:"
	@echo "  make setup                  Prepare local baseline (.env + CRS)"
	@echo "  make env-init               Create .env from .env.example if missing"
	@echo "  make crs-install            Install OWASP CRS into ./data/rules/crs"
	@echo ""
	@echo "  make go-test                Run Go tests (coraza/src)"
	@echo "  make go-build               Build single binary into ./bin/$(APP_NAME)"
	@echo "  make mysql-logstore-test    Run MySQL log-store integration test"
	@echo ""
	@echo "  make ui-install             Install admin UI dependencies"
	@echo "  make ui-test                Run admin UI tests"
	@echo "  make ui-build               Build admin UI assets"
	@echo "  make ui-sync                Sync web dist -> go:embed assets"
	@echo "  make ui-build-sync          Build and sync embedded admin UI assets"
	@echo ""
	@echo "  make compose-config         Validate docker compose config"
	@echo "  make compose-config-mysql   Validate compose config with mysql profile"
	@echo "  make compose-build          Build coraza/nginx images"
	@echo "  make compose-up             Start coraza/nginx in background"
	@echo "  make compose-down           Stop coraza/nginx stack"
	@echo "  make web-up                 Start optional Vite admin UI dev container"
	@echo "  make web-down               Stop optional Vite admin UI dev container"
	@echo "  make mysql-up               Start local mysql profile service"
	@echo "  make mysql-down             Stop local mysql profile service"
	@echo ""
	@echo "  make preset-list            List available config presets"
	@echo "  make preset-apply           Copy preset config into local workspace"
	@echo "    - optional: PRESET=$(PRESET) PRESET_OVERWRITE=1"
	@echo "  make preset-check           Validate preset without modifying local files"
	@echo "    - optional: PRESET=$(PRESET)"
	@echo ""
	@echo "  make gotestwaf             Run GoTestWAF with current backend flags"
	@echo "  make gotestwaf-file        Run GoTestWAF in file backend mode"
	@echo "  make gotestwaf-sqlite      Run GoTestWAF in sqlite backend mode"
	@echo "  make example-smoke         Run one protected-host example smoke"
	@echo "    - optional: EXAMPLE=$(EXAMPLE) (choices: $(EXAMPLES))"
	@echo "  make example-smoke-all     Run protected-host smoke for all examples"
	@echo "  make standalone-smoke      Run direct-tukuyomi standalone smoke for one example"
	@echo "    - optional: EXAMPLE=$(EXAMPLE) (choices: $(EXAMPLES))"
	@echo "  make standalone-smoke-all  Run direct-tukuyomi standalone smoke for all examples"
	@echo "  make standalone-policy-fixture       Run extended standalone policy fixtures for one example"
	@echo "    - optional: EXAMPLE=$(EXAMPLE) (default: api-gateway)"
	@echo "  make standalone-regression-fast      Run fast standalone regression baseline"
	@echo "  make standalone-regression-extended  Run heavier standalone regression baseline"
	@echo "  make binary-deployment-smoke         Validate the docs/build binary deployment flow"
	@echo "    - optional: EXAMPLE=$(EXAMPLE) (default: api-gateway)"
	@echo "  make container-deployment-smoke      Validate the docs/build container deployment flow"
	@echo "    - optional: EXAMPLE=$(EXAMPLE) (default: api-gateway)"
	@echo "  make deployment-smoke                Run the binary + container deployment smoke bundle"
	@echo "    - optional: DEPLOYMENT_SMOKE_EXAMPLE=api-gateway"
	@echo "  make benchmark-scenario    Run one benchmark scenario"
	@echo "    - optional: EXAMPLE=$(EXAMPLE) TOPOLOGY=$(TOPOLOGY) SCENARIO=$(SCENARIO)"
	@echo "  make benchmark-baseline    Run the standard benchmark matrix"
	@echo ""
	@echo "  make check                 Run go-test + ui-test + compose config checks"
	@echo "  make ci-local              Run local CI baseline (check + mysql + examples + GoTestWAF)"
	@echo "  make clean                 Remove local test artifacts"
	@echo ""
	@echo "Key variables (override as needed):"
	@echo "  HOST_CORAZA_PORT=$(HOST_CORAZA_PORT) HOST_NGINX_PORT=$(HOST_NGINX_PORT)"
	@echo "  PUID=$(PUID) GUID=$(GUID)"
	@echo "  WAF_STORAGE_BACKEND=$(WAF_STORAGE_BACKEND) WAF_DB_ENABLED=$(WAF_DB_ENABLED)"
	@echo "  MIN_BLOCKED_RATIO=$(MIN_BLOCKED_RATIO)"

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
	src="$$preset_dir/.env"; \
	dst=".env"; \
	if [[ ! -f "$$src" ]]; then \
		echo "[preset-apply][ERROR] missing $$src" >&2; \
		exit 1; \
	fi; \
	if [[ -f "$$dst" && "$(PRESET_OVERWRITE)" != "1" ]]; then \
		echo "[preset-apply] $$dst already exists (set PRESET_OVERWRITE=1 to replace)"; \
		exit 0; \
	fi; \
	cp "$$src" "$$dst"; \
	echo "[preset-apply] applied $(PRESET) -> $$dst"

preset-check:
	@set -euo pipefail; \
	preset_dir="$(PRESET_DIR)"; \
	src="$$preset_dir/.env"; \
	if [[ ! -f "$$src" ]]; then \
		echo "[preset-check][ERROR] missing $$src" >&2; \
		exit 1; \
	fi; \
	docker compose --env-file "$$src" config >/dev/null; \
	echo "[preset-check] $(PRESET) ok"

crs-install:
	./scripts/install_crs.sh

setup: env-init crs-install

go-test:
	cd $(CORAZA_SRC) && $(GO) test ./...

go-build:
	mkdir -p $(abspath $(BIN_DIR))
	cd $(CORAZA_SRC) && $(GO) build -o "$(abspath $(BIN_DIR))/$(APP_NAME)" $(APP_PKG)
	@echo "[go-build] built $(abspath $(BIN_DIR))/$(APP_NAME)"

mysql-logstore-test: env-init
	@set -euo pipefail; \
	trap '$(DOCKER_ENV) docker compose --profile mysql down -v >/dev/null 2>&1 || true' EXIT; \
	$(DOCKER_ENV) docker compose --profile mysql up -d mysql; \
	for i in $$(seq 1 60); do \
		if $(DOCKER_ENV) docker compose --profile mysql exec -T mysql mysqladmin ping -h 127.0.0.1 -uroot -p"$(MYSQL_ROOT_PASSWORD)" --silent >/dev/null 2>&1; then \
			echo "[mysql-logstore-test] mysql is ready"; \
			break; \
		fi; \
		sleep 2; \
		if [[ "$$i" -eq 60 ]]; then \
			echo "[mysql-logstore-test][ERROR] mysql did not become healthy in time" >&2; \
			$(DOCKER_ENV) docker compose --profile mysql ps mysql >&2 || true; \
			$(DOCKER_ENV) docker compose --profile mysql logs mysql >&2 || true; \
			exit 1; \
		fi; \
	done; \
	cd $(CORAZA_SRC) && WAF_TEST_MYSQL_DSN="$(WAF_TEST_MYSQL_DSN)" $(GO) test ./internal/handler -run TestLogsStatsMySQLStoreAggregatesAndIngestsIncrementally -count=1

ui-install:
	cd $(UI_DIR) && $(NPM) ci

ui-test: ui-install
	cd $(UI_DIR) && $(NPM) test

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

compose-config: env-init
	docker compose config >/dev/null
	@echo "[compose-config] ok"

compose-config-mysql: env-init
	docker compose --profile mysql config >/dev/null
	@echo "[compose-config-mysql] ok"

compose-build: env-init
	$(STACK_ENV) docker compose build coraza nginx

compose-up: env-init
	$(STACK_ENV) docker compose up -d coraza nginx

compose-down:
	$(STACK_ENV) docker compose down --remove-orphans

web-up: env-init
	$(STACK_ENV) docker compose --profile dev-ui up -d web

web-down:
	$(STACK_ENV) docker compose --profile dev-ui stop web

mysql-up: env-init
	$(DOCKER_ENV) docker compose --profile mysql up -d mysql

mysql-down:
	$(DOCKER_ENV) docker compose --profile mysql down -v

gotestwaf: env-init
	MIN_BLOCKED_RATIO="$(MIN_BLOCKED_RATIO)" \
	WAF_STORAGE_BACKEND="$(WAF_STORAGE_BACKEND)" \
	WAF_DB_ENABLED="$(WAF_DB_ENABLED)" \
	WAF_DB_RETENTION_DAYS="$(WAF_DB_RETENTION_DAYS)" \
	GOTESTWAF_AUTO_DOWN="$(GOTESTWAF_AUTO_DOWN)" \
	HOST_NGINX_PORT="$(HOST_NGINX_PORT)" \
	HOST_CORAZA_PORT="$(HOST_CORAZA_PORT)" \
	PUID="$(PUID)" \
	GUID="$(GUID)" \
	./scripts/run_gotestwaf.sh

gotestwaf-file:
	$(MAKE) gotestwaf WAF_STORAGE_BACKEND=file WAF_DB_ENABLED=false

gotestwaf-sqlite:
	$(MAKE) gotestwaf WAF_STORAGE_BACKEND=db WAF_DB_ENABLED=true

example-smoke:
	./scripts/ci_example_smoke.sh "$(EXAMPLE)"

example-smoke-all:
	@set -euo pipefail; \
	for example in $(EXAMPLES); do \
		echo "[example-smoke-all] running $$example"; \
		$(MAKE) example-smoke EXAMPLE="$$example"; \
	done

standalone-smoke:
	./scripts/run_standalone_regression.sh "$(EXAMPLE)" fast

standalone-smoke-all:
	@set -euo pipefail; \
	for example in $(EXAMPLES); do \
		echo "[standalone-smoke-all] running $$example"; \
		$(MAKE) standalone-smoke EXAMPLE="$$example"; \
	done

standalone-policy-fixture:
	./scripts/run_standalone_regression.sh "$(EXAMPLE)" extended

standalone-regression-fast: go-test compose-config
	$(MAKE) standalone-smoke EXAMPLE="$(EXAMPLE)"

standalone-regression-extended: check standalone-smoke-all standalone-policy-fixture deployment-smoke

binary-deployment-smoke:
	./scripts/run_binary_deployment_smoke.sh "$(EXAMPLE)"

container-deployment-smoke:
	./scripts/run_container_deployment_smoke.sh "$(EXAMPLE)"

deployment-smoke:
	$(MAKE) binary-deployment-smoke EXAMPLE="$${DEPLOYMENT_SMOKE_EXAMPLE:-api-gateway}"
	$(MAKE) container-deployment-smoke EXAMPLE="$${DEPLOYMENT_SMOKE_EXAMPLE:-api-gateway}"

benchmark-scenario:
	./scripts/run_capacity_baseline.sh "$(EXAMPLE)" "$(TOPOLOGY)" "$(SCENARIO)"

benchmark-baseline:
	@set -euo pipefail; \
	run_id="$$(date +%Y%m%d-%H%M%S)"; \
	echo "[benchmark-baseline] run_id=$$run_id"; \
	BENCH_RUN_ID="$$run_id" $(MAKE) benchmark-scenario EXAMPLE=api-gateway TOPOLOGY=front SCENARIO=pass; \
	BENCH_RUN_ID="$$run_id" $(MAKE) benchmark-scenario EXAMPLE=api-gateway TOPOLOGY=direct SCENARIO=pass; \
	BENCH_RUN_ID="$$run_id" $(MAKE) benchmark-scenario EXAMPLE=api-gateway TOPOLOGY=front SCENARIO=block; \
	BENCH_RUN_ID="$$run_id" $(MAKE) benchmark-scenario EXAMPLE=api-gateway TOPOLOGY=direct SCENARIO=block; \
	BENCH_RUN_ID="$$run_id" $(MAKE) benchmark-scenario EXAMPLE=nextjs TOPOLOGY=front SCENARIO=cache; \
	BENCH_RUN_ID="$$run_id" $(MAKE) benchmark-scenario EXAMPLE=nextjs TOPOLOGY=direct SCENARIO=cache; \
	BENCH_RUN_ID="$$run_id" BENCH_ADMIN_SIDE_TRAFFIC=1 $(MAKE) benchmark-scenario EXAMPLE=nextjs TOPOLOGY=front SCENARIO=cache

check: go-test ui-test compose-config compose-config-mysql

ci-local: check mysql-logstore-test example-smoke-all gotestwaf-file gotestwaf-sqlite

clean:
	rm -rf $(UI_DIR)/.tmp-test
	@echo "[clean] done"
