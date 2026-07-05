# passkit developer tasks. Cross-platform (Windows / macOS / Linux).
#
# Targets:
#   make install   create .venv and install passkit (editable, dev+yaml extras)
#   make test      run the test suite
#   make demo      run every demo
#   make lint      lint (ruff if available, else byte-compile check)
#   make clean     remove venv, build artifacts, caches
#
# The venv Python is used when present so targets work after `make install`
# without manual activation.

ifeq ($(OS),Windows_NT)
  VENV_PY := .venv/Scripts/python.exe
  RM_RF   := rmdir /s /q
else
  VENV_PY := .venv/bin/python
  RM_RF   := rm -rf
endif

# Use the venv interpreter if it exists, otherwise fall back to system python.
PY := $(shell test -x "$(VENV_PY)" && echo "$(VENV_PY)" || (command -v python3 || command -v python))
# A system Python for clean (which deletes .venv, so it can't run from it).
SYSPY := $(shell command -v python3 || command -v python)

.PHONY: install test demo lint clean help

help:
	@echo "targets: install  test  demo  lint  clean"

install:
	python -m venv .venv || python3 -m venv .venv
	$(VENV_PY) -m pip install --upgrade pip
	$(VENV_PY) -m pip install -e ".[dev,yaml]"
	$(VENV_PY) -m passkit --version

test:
	$(PY) -m pytest -q

demo:
	$(PY) demos/run_all.py

lint:
	@$(PY) -m ruff --version >/dev/null 2>&1 && $(PY) -m ruff check passkit demos tests \
		|| ( echo "ruff not installed; running byte-compile check" && \
		     $(PY) -m compileall -q passkit demos tests )

clean:
	-$(SYSPY) -c "import shutil; [shutil.rmtree(p,ignore_errors=True) for p in ['.venv','build','dist','.pytest_cache','.ruff_cache','.mypy_cache']]"
	-$(SYSPY) -c "import shutil,glob; [shutil.rmtree(p,ignore_errors=True) for p in glob.glob('**/__pycache__',recursive=True)+glob.glob('**/*.egg-info',recursive=True)]"
	@echo "cleaned build artifacts and caches"
