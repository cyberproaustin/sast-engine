"""CLI: lower a Python source tree into Program IR on stdout.

    python3 src/main.py <rootDir> [--out <file>]

The frontend emits IR and exits. It never reports a finding (ADR-001).
"""

from __future__ import annotations

import json
import os
import sys

from lower import lower_program

SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", "node_modules", "dist", "build"}


def collect_sources(root: str) -> list[str]:
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        found.extend(
            os.path.join(dirpath, name) for name in filenames if name.endswith(".py")
        )
    return sorted(found)


def main() -> int:
    argv = sys.argv[1:]
    positional = [a for a in argv if not a.startswith("--")]
    if not positional:
        sys.stderr.write("usage: python3 src/main.py <rootDir> [--out <file>]\n")
        return 2

    root = os.path.abspath(positional[0])
    if not os.path.isdir(root):
        sys.stderr.write(f"not a directory: {root}\n")
        return 2

    files = collect_sources(root)
    if not files:
        sys.stderr.write(f"no Python sources under {root}\n")
        return 2

    try:
        doc = lower_program(root, files)
    except SyntaxError as err:
        sys.stderr.write(f"lowering failed: {err}\n")
        return 1

    payload = json.dumps(doc, indent=2) + "\n"
    if "--out" in argv:
        out = argv[argv.index("--out") + 1]
        with open(out, "w", encoding="utf-8") as handle:
            handle.write(payload)
        sys.stderr.write(
            f"lowered {len(doc['functions'])} function(s), "
            f"{len(doc['entryPoints'])} entry point(s) -> {out}\n"
        )
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
