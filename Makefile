# E-signing service. `make check` is the gate: it must pass before anything is called done.

SHELL := /bin/bash
BACKEND := backend
FRONTEND := frontend
UV := uv --directory $(BACKEND)
BUN := cd $(FRONTEND) &&

.DEFAULT_GOAL := help
.PHONY: help up down logs psql migrate migrate-status install check check-backend check-frontend \
        test test-backend test-frontend e2e fmt lint dev dev-api dev-web clean-db

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
install:  ## Install backend and frontend dependencies
	$(UV) sync
	$(BUN) bun install

# ---------------------------------------------------------------- migrations
migrate:  ## Apply backend/migrations/*.sql as the owner role
	$(UV) run python -m esign.migrate

migrate-status:  ## Show applied and pending migrations
	$(UV) run python -m esign.migrate --status

# ---------------------------------------------------------------- checks
check: check-backend check-frontend  ## Everything: ruff, mypy, pytest, and the frontend checks

check-backend:
	$(UV) run ruff format --check .
	$(UV) run ruff check .
	$(UV) run mypy
	$(UV) run pytest

check-frontend:
	$(BUN) bun run typecheck
	$(BUN) bun run check
	$(BUN) bun run test

test: test-backend test-frontend  ## Tests only

test-backend:
	$(UV) run pytest

test-frontend:
	$(BUN) bun run test

lint:  ## Lint without fixing
	$(UV) run ruff check .
	$(BUN) bun run lint

e2e:  ## Playwright end-to-end specs (starts the dev server itself)
	$(BUN) bun run e2e

fmt:  ## Format and autofix
	$(UV) run ruff format .
	$(UV) run ruff check --fix .
	$(BUN) bun run check:fix

# ---------------------------------------------------------------- dev servers
dev:  ## Run the API and the signing UI together (Ctrl-C stops both)
	@trap 'kill 0' INT TERM; \
	$(MAKE) dev-api & \
	$(MAKE) dev-web & \
	wait

dev-api:  ## API on :8000 (needs esign.api, which the integration step adds)
	$(UV) run uvicorn esign.api:app --reload --port 8000

dev-web:  ## Signing UI on :5273, proxying /v1 to :8000
	$(BUN) bun run dev
