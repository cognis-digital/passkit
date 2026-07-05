"""Enable ``python -m passkit`` as an alias for the ``passkit`` console script.

Useful when the console script is not on PATH (e.g. an unactivated venv) or on
locked-down systems; behaves identically to the installed ``passkit`` command.
"""

from __future__ import annotations

import sys

from passkit.cli import main

if __name__ == "__main__":
    sys.exit(main())
