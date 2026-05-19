.PHONY: install install-llm install-all test lint lint-fix coverage clean bump sync-data help

VENV := .venv
PYTHON := $(VENV)/bin/python

help:
	@echo "Available commands:"
	@echo "  make install      — create venv and install core + dev deps"
	@echo "  make install-llm  — add LLM support (OpenAI, Anthropic, Ollama)"
	@echo "  make install-all  — install everything"
	@echo "  make test         — run test suite"
	@echo "  make lint         — run ruff check + format check"
	@echo "  make lint-fix     — auto-fix lint and format issues"
	@echo "  make coverage     — run tests with coverage report"
	@echo "  make sync-data    — copy data/ files into package"
	@echo "  make bump         — bump version to YYYY.MMDD.hhmm"
	@echo "  make clean        — remove venv and caches"

$(VENV):
	uv venv $(VENV)

install: $(VENV)
	uv pip install -e ".[dev,collect]"
	@echo ""
	@echo "✅ Done. Activate with: source $(VENV)/bin/activate"

install-llm: $(VENV)
	uv pip install -e ".[dev,collect,llm]"
	@echo ""
	@echo "✅ Done. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OLLAMA_MODEL."

install-all: install-llm

test:
	$(PYTHON) -m pytest tests/ -v

lint:
	$(VENV)/bin/ruff check .
	$(VENV)/bin/ruff format --check .

lint-fix:
	$(VENV)/bin/ruff check . --fix
	$(VENV)/bin/ruff format .

coverage:
	$(PYTHON) -m pytest tests/ --cov=legitifier_pkg --cov-report=term-missing

sync-data:
	$(PYTHON) scripts/sync_data.py

bump:
	$(PYTHON) scripts/bump_version.py

clean:
	rm -rf $(VENV) .coverage __pycache__ .pytest_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "✅ Cleaned."
