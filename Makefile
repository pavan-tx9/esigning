# E-signing service. `make check` is the gate: it must pass before anything is called done.

SHELL := /bin/bash
BACKEND := backend
FRONTEND := frontend
DEMO_HOST := demo-host
UV := uv --directory $(BACKEND)
UV_DEMO := uv --directory $(DEMO_HOST)
BUN := cd $(FRONTEND) &&

.DEFAULT_GOAL := help
.PHONY: help up down logs psql migrate migrate-status install check check-backend check-frontend \
        check-demo-host test test-backend test-frontend test-demo-host e2e e2e-demo demo fmt lint \
        dev dev-api dev-web clean-db

help:  ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- infrastructure
up:  ## Start Postgres (port 54329) and wait for it to be healthy
	docker compose up -d db
	@printf 'waiting for postgres'
	@for i in $$(seq 1 60); do \
		if docker compose exec -T db pg_isready -U esign_owner -d esign >/dev/null 2>&1; then \
			echo ' ready'; exit 0; \
		fi; \
		printf '.'; sleep 1; \
	done; \
	echo ' timed out'; docker compose logs --tail=40 db; exit 1

down:  ## Stop the containers (keeps the data volume)
	docker compose down

logs:  ## Tail the database log
	docker compose logs -f db

psql:  ## Open a psql shell as the owner role
	docker compose exec -it db psql -U esign_owner -d esign

clean-db:  ## Destroy the database volume and start again
	docker compose down -v
	$(MAKE) up
	$(MAKE) migrate

# ---------------------------------------------------------------- setup
install:  ## Install backend, frontend and demo-host dependencies
	$(UV) sync
	$(UV_DEMO) sync
	$(BUN) bun install

# ---------------------------------------------------------------- migrations
migrate:  ## Apply backend/migrations/*.sql as the owner role
	$(UV) run python -m esign.migrate

migrate-status:  ## Show applied and pending migrations
	$(UV) run python -m esign.migrate --status

# ---------------------------------------------------------------- checks
check: check-backend check-frontend check-demo-host  ## Everything: ruff, mypy, pytest, and the frontend checks

check-backend:
	$(UV) run ruff format --check .
	$(UV) run ruff check .
	$(UV) run mypy
	$(UV) run pytest

check-frontend:
	$(BUN) bun run typecheck
	$(BUN) bun run check
	$(BUN) bun run test

check-demo-host:
	$(UV_DEMO) run ruff format --check .
	$(UV_DEMO) run ruff check .
	$(UV_DEMO) run mypy
	$(UV_DEMO) run pytest

test: test-backend test-frontend test-demo-host  ## Tests only

test-backend:
	$(UV) run pytest

test-frontend:
	$(BUN) bun run test

test-demo-host:
	$(UV_DEMO) run pytest

lint:  ## Lint without fixing
	$(UV) run ruff check .
	$(UV_DEMO) run ruff check .
	$(BUN) bun run lint

e2e:  ## Playwright specs against the mocked API (starts the dev server itself)
	$(BUN) bun run e2e

e2e-demo:  ## Playwright specs against the real stack through the demo host
	$(BUN) bunx playwright test -c playwright.demo.config.ts

fmt:  ## Format and autofix
	$(UV) run ruff format .
	$(UV) run ruff check --fix .
	$(UV_DEMO) run ruff format .
	$(UV_DEMO) run ruff check --fix .
	$(BUN) bun run check:fix

# ---------------------------------------------------------------- the demo
demo:  ## Everything a human needs to click through: database, API, worker, UI and the stand-in EHR
	@bash $(DEMO_HOST)/demo.sh

# ---------------------------------------------------------------- dev servers
dev:  ## Run the API and the signing UI together (Ctrl-C stops both)
	@trap 'kill 0' INT TERM; \
	$(MAKE) dev-api & \
	$(MAKE) dev-web & \
	wait

dev-api:  ## API on :8000. Proxy headers are the app's job (TRUSTED_PROXY_CIDRS), not uvicorn's.
	$(UV) run uvicorn esign.api:app --reload --port 8000 --no-proxy-headers --no-server-header

dev-web:  ## Signing UI on :5273, proxying /v1 to :8000
	$(BUN) bun run dev
