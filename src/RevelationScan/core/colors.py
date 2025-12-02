"""Terminal color helpers."""
from __future__ import annotations

import os
import sys


class Palette:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def supports_color(stream: object = sys.stdout) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("TERM", "") != "dumb"


SUPPORTS_COLOR = supports_color()
ENABLE_COLOR = SUPPORTS_COLOR


def apply_color(text: str, *codes: str) -> str:
    if not text or not ENABLE_COLOR:
        return text
    return "".join(codes) + text + Palette.RESET


def set_color_enabled(enabled: bool) -> None:
    global ENABLE_COLOR
    ENABLE_COLOR = enabled
