.PHONY: help setup dev test lint verify gate clean test-baseline product-smoke product-acceptance product-journeys lifecycle lifecycle-dry-run lifecycle-check images sbom drill

help:
	@echo "Available commands for skillbench:"
	@echo "  make setup   - Create venv and install all dependencies"
	@echo "  make dev     - Run FastAPI development server on port 8000"
	@echo "  make test    - Run pytest test suite"
	@echo "  make lint    - Run code linting"
	@echo "  make verify  - Run contract integrity manifest verification"
	@echo "  make gate    - Run release gate verification"
	@echo "  make lifecycle      - Run expiry/purge/pruning once (needs LIFECYCLE_DATABASE_URL)"
	@echo "  make lifecycle-dry-run - Report what expiry/purge would do, changing nothing"
	@echo "  make lifecycle-check   - Validate the lifecycle process configuration"
	@echo "  make images  - Check the deployable-image policy and print build commands"
	@echo "  make sbom    - Regenerate evidence/sbom/*.cdx.json from the lockfiles"
	@echo "  make drill   - Backup/restore drill (pg_dump/pg_restore round trip)"
	@echo "  make clean   - Remove cache files"

setup:
	python3 -m venv .venv
	. .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt -r requirements-baseline.txt

dev:
	uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest -v tests/

lint:
	flake8 src tests --max-line-length=120

verify:
	python scripts/verify_manifest.py

gate:
	python scripts/release_gate.py

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +

test-baseline:
	pytest -v tests/test_baseline.py

product-smoke:
	python scripts/product_smoke.py

product-acceptance:
	python scripts/product_acceptance.py

product-journeys:
	python scripts/product_journeys.py

# The lifecycle process runs under its own role (baseline_lifecycle). It is the
# only runtime identity allowed to destroy content; see docs/SKB_Operations.md §5.
lifecycle:
	python -m src.lifecycle.main --once

lifecycle-dry-run:
	python -m src.lifecycle.main --dry-run

lifecycle-check:
	python -m src.lifecycle.main --check

# Images cannot be built without a container runtime; the policy check still runs.
images:
	python scripts/build_images.py --check

sbom:
	python scripts/build_sbom.py --runtime --npm-lock apps/web/package-lock.json \
		--component-name skillbench-api --output evidence/sbom/skillbench-api.cdx.json
	python scripts/build_sbom.py --npm-lock apps/web/package-lock.json \
		--component-name skillbench-web --output evidence/sbom/skillbench-web.cdx.json

drill:
	pytest -q tests/db/test_backup_restore.py
