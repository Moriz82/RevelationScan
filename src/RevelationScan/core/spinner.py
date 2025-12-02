"""TTY spinner animation."""
from __future__ import annotations

import sys
import threading
import time

from .colors import Palette, apply_color, ENABLE_COLOR


class Spinner:
    def __init__(self, prefix: str = "    ", frames: list[str] | None = None, interval: float = 0.1) -> None:
        self.prefix = prefix
        self.frames = frames or ["|", "/", "-", "\\"]
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None or not ENABLE_COLOR:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._thread is None or not ENABLE_COLOR:
            return
        self._stop.set()
        self._thread.join(timeout=1)
        self._thread = None
        sys.stdout.write("\r" + " " * (len(self.prefix) + 4) + "\r")
        sys.stdout.flush()

    def _animate(self) -> None:
        idx = 0
        while not self._stop.is_set():
            frame = self.frames[idx % len(self.frames)]
            sys.stdout.write(f"\r{self.prefix}{apply_color(frame, Palette.DIM)} ")
            sys.stdout.flush()
            time.sleep(self.interval)
            idx += 1
