"""Trumpet discovery and plugin loading."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Iterable

from .base import Trumpet, TrumpetRegistry


def load_plugins(plugin_paths: Iterable[Path], registry: TrumpetRegistry) -> None:
    for path in plugin_paths:
        if path.is_dir():
            for file in sorted(path.glob("*.py")):
                _load_plugin_module(file, registry)
        elif path.is_file() and path.suffix == ".py":
            _load_plugin_module(path, registry)


def _load_plugin_module(path: Path, registry: TrumpetRegistry) -> None:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        return
    module = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = module
    spec.loader.exec_module(module)  # type: ignore[call-arg]
    trumpet_classes = [
        getattr(module, attr)
        for attr in dir(module)
        if isinstance(getattr(module, attr), type) and issubclass(getattr(module, attr), Trumpet) and getattr(module, attr) is not Trumpet
    ]
    registry.extend(trumpet_classes)


def register_builtin_trumpets(registry: TrumpetRegistry) -> None:
    from RevelationScan.trumpets import builtin_trumpets

    registry.extend(builtin_trumpets())
