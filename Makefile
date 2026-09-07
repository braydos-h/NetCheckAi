# Convenience targets for the BreachPilot engine.
# Thin wrappers -- no real logic lives here. On Windows use the equivalent
# `python`/`python -m` commands directly (see README / docs/getting-started.md).

PYTHON ?= python3
VENV   ?= .venv
BIN    := $(VENV)/bin

.PHONY: venv install install-dev doctor self-test eval test test-focused run mcp-defensive mcp-exploit mcp-engine clean

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -r requirements.txt

install-dev: venv
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -e ".[dev]"

doctor:
	$(BIN)/python main.py --doctor $(if $(filter --json,$(MAKECMDGOALS)),--json)

# Support `make doctor --json` for CI machine-readable output
--json:
	@:

self-test:
	$(BIN)/python main.py --self-test

eval:
	$(BIN)/python main.py --eval

test:
	$(BIN)/python -m pytest tests/ -v

# Parallel suite (~4x faster locally; needs pip install -e ".[dev]" for pytest-xdist)
test-fast:
	$(BIN)/python -m pytest tests/ -q -n 2

# Run a focused file, e.g. `make test-one F=tests/test_scope_gate.py`
test-one:
	$(BIN)/python -m pytest $(F) -v

run:
	$(BIN)/python main.py

mcp-defensive:
	$(BIN)/python mcp_server.py

mcp-exploit:
	$(BIN)/python mcp_exploit_server.py

mcp-engine:
	$(BIN)/python mcp_engine_server.py

clean:
	rm -rf $(VENV)
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
