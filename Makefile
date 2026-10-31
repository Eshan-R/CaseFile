.PHONY: install run test lint reset fmt check

PYTHON := .venv/Scripts/python
VENV   := .venv

install:
	python -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt

run:
	cd backend && ../$(PYTHON) -m uvicorn app.main:app --reload --port 8000

test:
	cd backend && ../$(PYTHON) -m pytest tests/ -v

lint:
	$(PYTHON) -m ruff check backend/

fmt:
	$(PYTHON) -m ruff format backend/

check: lint test

reset:
	$(PYTHON) -c "from app.store.duck import reset_all; reset_all()" 2>/dev/null || true
	rm -f data/casefile.duckdb
	@echo "Database reset."

