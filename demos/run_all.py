"""Run every passkit demo in sequence; exit non-zero if any fails.

Usage:  python demos/run_all.py
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _load(path):
    spec = importlib.util.spec_from_file_location(
        os.path.splitext(os.path.basename(path))[0], path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    demos = sorted(
        f for f in os.listdir(HERE)
        if f.startswith("demo_") and f.endswith(".py")
    )
    failures = []
    for name in demos:
        print(f"\n{'=' * 70}\nRUNNING {name}\n{'=' * 70}")
        module = _load(os.path.join(HERE, name))
        try:
            rc = module.main()
        except Exception as exc:  # noqa: BLE001
            print(f"[{name}] EXCEPTION: {exc}")
            rc = 1
        if rc != 0:
            failures.append(name)

    print(f"\n{'=' * 70}")
    print(f"RESULT: {len(demos) - len(failures)}/{len(demos)} demos passed")
    if failures:
        print("FAILED:", ", ".join(failures))
        return 1
    print("ALL DEMOS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
