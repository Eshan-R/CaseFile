.PHONY: install run test lint reset fmt check demo

PYTHON ?= .venv/Scripts/python
ifeq ($(OS),Windows_NT)
    PYTHON_BIN := $(PYTHON)
else
    PYTHON_BIN := python3
endif
VENV   := .venv
LOG ?= data/firex-30G.log
MANIFEST ?= data/firex-30G.log.manifest.json

install:
	python -m venv $(VENV)
	$(PYTHON_BIN) -m pip install --upgrade pip
	$(PYTHON_BIN) -m pip install -r requirements.txt

demo:
	PYTHONPATH=backend $(PYTHON_BIN) scripts/run_all.py $(LOG) $(MANIFEST)

run:
	cd backend && ../$(PYTHON_BIN) -m uvicorn app.main:app --reload --port 8000

test:
	cd backend && ../$(PYTHON_BIN) -m pytest tests/ -v

lint:
	$(PYTHON_BIN) -m ruff check backend/ scripts/

fmt:
	$(PYTHON_BIN) -m ruff format backend/ scripts/

check: lint test

reset:
	$(PYTHON_BIN) -c "import sys; sys.path.insert(0, 'backend'); from app.store.duck import reset_all; reset_all()" 2>/dev/null || true
	rm -f data/casefile.duckdb
	@echo "Database reset."
