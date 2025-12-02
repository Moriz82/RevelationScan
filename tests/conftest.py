"""Test configuration for Revelation Scan."""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_src_on_path() -> None:
    root = Path(__file__).resolve().parent.parent
    src_dir = root / "src"
    if src_dir.is_dir():
        src_path = str(src_dir)
        if src_path not in sys.path:
            sys.path.insert(0, src_path)


_ensure_src_on_path()
