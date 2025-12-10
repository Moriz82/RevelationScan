# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the registry module. This module will allow the application to:

# 1. Load plugin modules from file paths (dynamic loading, very fancy!)

# 2. Discover and register trumpet classes from plugin modules

# 3. Register all the built-in trumpets that come with the package

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Iterable

from .base import Trumpet, TrumpetRegistry

###########################################################################

"""

Name: load_plugins

Function: Load plugin modules from file paths and register any trumpet classes

found in them. It can handle both individual Python files and directories

full of Python files.

Arguments: plugin_paths - iterable of paths to plugin files or directories

            registry - the TrumpetRegistry to register classes into

Returns: No value returned

"""

def load_plugins(plugin_paths: Iterable[Path], registry: TrumpetRegistry) -> None:
    ### Loop through each path provided
    for path in plugin_paths:
        ### If it's a directory, look for all .py files in it
        if path.is_dir():
            for file in sorted(path.glob("*.py")):
                _load_plugin_module(file, registry)
        ### If it's a Python file, load it directly
        elif path.is_file() and path.suffix == ".py":
            _load_plugin_module(path, registry)

#$ End load_plugins

###########################################################################

"""

Name: _load_plugin_module

Function: Load a single Python module from a file path and register any trumpet

classes found in it. This is the magic that makes dynamic plugin loading work!

Arguments: path - path to the Python file to load

            registry - the TrumpetRegistry to register classes into

Returns: No value returned

"""

def _load_plugin_module(path: Path, registry: TrumpetRegistry) -> None:
    ### Create a module spec from the file location
    spec = importlib.util.spec_from_file_location(path.stem, path)
    ### If we couldn't create a spec or it has no loader, give up
    if spec is None or spec.loader is None:
        return
    ### Create a module object from the spec
    module = importlib.util.module_from_spec(spec)
    ### Add it to sys.modules so Python knows about it
    sys.modules[path.stem] = module
    ### Execute the module code (this runs all the code in the file!)
    spec.loader.exec_module(module)  # type: ignore[call-arg]
    ### Find all classes in the module that are Trumpet subclasses (but not Trumpet itself)
    trumpet_classes = [
        getattr(module, attr)
        for attr in dir(module)
        if isinstance(getattr(module, attr), type) and issubclass(getattr(module, attr), Trumpet) and getattr(module, attr) is not Trumpet
    ]
    ### Register all the trumpet classes we found
    registry.extend(trumpet_classes)

#$ End _load_plugin_module

###########################################################################

"""

Name: register_builtin_trumpets

Function: Register all the built-in trumpet classes that come with the package.

These are the trumpets that are included by default, not loaded from plugins.

Arguments: registry - the TrumpetRegistry to register classes into

Returns: No value returned

"""

def register_builtin_trumpets(registry: TrumpetRegistry) -> None:
    ### Import the builtin_trumpets function from the trumpets package
    from RevelationScan.trumpets import builtin_trumpets

    ### Get all built-in trumpet classes and register them
    registry.extend(builtin_trumpets())

#$ End register_builtin_trumpets
