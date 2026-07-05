#!/usr/bin/env bash
# passkit setup for macOS / Linux.
# Creates (or reuses) a .venv, installs passkit in editable mode with dev
# extras, and verifies the CLI runs. Idempotent: safe to run repeatedly.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# --- locate a Python interpreter (3.10+) ---------------------------------
PYTHON=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    PYTHON="$cand"
    break
  fi
done
if [ -z "$PYTHON" ]; then
  echo "error: no python3 interpreter found on PATH. Install Python 3.10+." >&2
  exit 1
fi

PYVER="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo ">> Using $PYTHON (Python $PYVER)"
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 10) else 1)' || {
  echo "error: Python 3.10+ required, found $PYVER." >&2
  exit 1
}

# --- create / reuse virtualenv -------------------------------------------
VENV="$HERE/.venv"
if [ -d "$VENV" ]; then
  echo ">> Reusing existing virtualenv at .venv"
else
  echo ">> Creating virtualenv at .venv"
  "$PYTHON" -m venv "$VENV"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"

# --- install --------------------------------------------------------------
echo ">> Upgrading pip"
python -m pip install --upgrade pip >/dev/null

echo ">> Installing passkit (editable) with dev + yaml extras"
python -m pip install -e ".[dev,yaml]"

# --- verify ---------------------------------------------------------------
echo ">> Verifying CLI"
passkit --version
passkit --help >/dev/null

cat <<'EOF'

============================================================
 passkit is installed. Next steps:
============================================================
 Activate the environment in a new shell:
     source .venv/bin/activate

 Try the CLI:
     passkit challenge --ttl 120
     passkit --help

 Run the tests:
     pytest -q            # or:  make test

 Run the demos:
     python demos/run_all.py   # or:  make demo
============================================================
EOF
