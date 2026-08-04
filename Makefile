.DEFAULT_GOAL := help
PY := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: help setup corpus up down logs load test lint fmt clean reset ps shell-db

help:  ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.venv:
	python3 -m venv .venv
	$(PIP) install -q -U pip
	$(PIP) install -q -r requirements-dev.txt

setup:  ## First run: start everything (no host Python needed)
	@test -f .env || cp .env.example .env
	@$(MAKE) up
	@echo
	@echo "Open http://localhost:8080"
	@echo "For the CLI and test suite as well, run: make dev"

dev: .venv  ## Developer extras: virtualenv with the loaders, CLI and test suite

corpus:  ## Refresh the bundled RFC corpus from rfc-editor.org (needs network)
	./scripts/fetch-corpus.sh

up:  ## Build and start db, api and web (http://localhost:8080)
	docker compose up -d --build
	@echo "waiting for the api to become healthy…"
	@for i in $$(seq 1 30); do \
		[ "$$(docker inspect -f '{{.State.Health.Status}}' siptrace-api 2>/dev/null)" = healthy ] \
			&& { echo "ready: http://localhost:8080"; exit 0; }; sleep 2; done; \
		echo "api did not become healthy; try 'make logs'" >&2; exit 1

down:  ## Stop the stack, keeping all data
	docker compose down

logs:  ## Follow the api logs
	docker compose logs -f api

load:  ## Rebuild the knowledge base inside the api container (safe to re-run)
	docker compose exec -T api python /app/ingest/load_rfcs.py
	docker compose exec -T api python /app/ingest/load_protocol.py

test: .venv  ## Run the analyser test suite
	$(PY) -m pytest tests/ -q

lint: .venv  ## Check Python style and the frontend types
	$(PY) -m ruff check .
	cd web && npm run build >/dev/null && echo "web: typecheck + build ok"

fmt: .venv  ## Apply the safe automatic fixes
	$(PY) -m ruff check --fix .

ps:  ## Show container status
	docker compose ps

shell-db:  ## Open psql against the knowledge base
	docker exec -it siptrace-db psql -U siptrace -d siptrace

clean:  ## Remove caches and generated test fixtures
	rm -rf .pytest_cache .ruff_cache tests/data
	find . -name __pycache__ -type d -not -path './.venv/*' -exec rm -rf {} + 2>/dev/null || true

reset:  ## Destroy the database and uploads, then rebuild from scratch
	docker compose down -v
	$(MAKE) up
