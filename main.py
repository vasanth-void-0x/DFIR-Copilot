"""DFIR Copilot application entry point."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from dfir_copilot.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())

