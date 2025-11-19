PYTHON?=python
VENV=.venv

.PHONY: install fmt lint test scan

install:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -r requirements.txt

fmt:
	ruff format src tests

lint:
	ruff check src tests

test:
	pytest

scan:
	$(PYTHON) src/main.py scan data/sboms/sample_app.json --project sample-app --context data/sboms/sample_context.json --offline
