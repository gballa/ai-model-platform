#!/usr/bin/env python3
"""Convenience executable script aliasing tests/e2e/test_runner.py."""
from __future__ import annotations

from pathlib import Path
import sys

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from tests.e2e.test_runner import main

if __name__ == "__main__":
    sys.exit(main())
