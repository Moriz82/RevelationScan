# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the core base module. This module will allow the application to:

# 1. Define the base classes for scanning modules (trumpets)

# 2. Manage a registry of all available scan modules

# 3. Provide context for scan operations

# 4. Summarize findings by severity

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Type

from .findings import Finding, SeverityCounts

###########################################################################

"""

Name: ScanContext

Function: A data class that holds all the configuration and context info for a scan.

Arguments: None (it's a dataclass, so it's just fields)

Returns: No value returned (it's a class definition)

"""

@dataclass
class ScanContext:
    ### Configuration dictionary that holds all the scan settings
    config: Dict[str, object]
    ### Path to the CVE feed file, or None if we're using defaults
    cve_feed: Path | None
    ### How we want to format our output (probably json or text)
    output_format: str
    ### Whether we should suggest exploits (because we're helpful like that)
    suggest_exploits: bool
    ### Sequence of paths to plugin files we want to load
    plugins: Sequence[Path]

#$ End ScanContext

###########################################################################

"""

Name: Trumpet

Function: Base class for all Revelation Scan modules. Think of it like a musical

instrument - each trumpet makes a different sound (finds different issues).

Arguments: None (it's a class definition)

Returns: No value returned

"""

class Trumpet:
    """Base class for Revelation Scan modules."""

    ### The unique identifier for this trumpet (like a slug, but not slimy)
    slug: str = ""
    ### A human-readable title for what this trumpet does
    title: str = ""
    ### Description of what kind of issues this trumpet looks for
    description: str = ""

    ###########################################################################

    """

    Name: blow

    Function: The main method that each trumpet implements to do its scanning.

    Think of it like blowing into a trumpet - it makes noise (finds issues).

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects that represent security issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### Default implementation just prints a joke message
        print("sound the alarm? jk, module not implemented")

#$ End blow

#$ End Trumpet

###########################################################################

"""

Name: TrumpetRegistry

Function: A registry that keeps track of all available trumpet classes. It's like

a phone book, but for security scanners instead of phone numbers.

Arguments: None (it's a class definition)

Returns: No value returned

"""

class TrumpetRegistry:
    ###########################################################################

    """

    Name: __init__

    Function: Constructor that initializes an empty registry dictionary.

    Arguments: None

    Returns: No value returned

    """

    def __init__(self) -> None:
        ### Create an empty dictionary to store our trumpets (slug -> class mapping)
        self._registry: Dict[str, Type[Trumpet]] = {}

#$ End __init__

    ###########################################################################

    """

    Name: register

    Function: Register a trumpet class in our registry. If the slug already exists,

    we throw a fit (raise ValueError) because duplicates are bad, mmkay?

    Arguments: trumpet_cls - the Trumpet class we want to register

    Returns: No value returned

    """

    def register(self, trumpet_cls: Type[Trumpet]) -> None:
        ### Get the slug from the class, or make one up from the class name if it's empty
        slug = trumpet_cls.slug or trumpet_cls.__name__.lower()
        ### Check if we already have this slug registered (no duplicates allowed!)
        if slug in self._registry:
            ### If we do, throw an error because we don't like duplicates
            raise ValueError(f"Duplicate trumpet: {slug}")
        ### Store the class in our registry dictionary
        self._registry[slug] = trumpet_cls

#$ End register

    ###########################################################################

    """

    Name: extend

    Function: Register multiple trumpet classes at once. It's like register, but

    for lazy people who don't want to call register a bunch of times.

    Arguments: trumpet_classes - an iterable of Trumpet classes to register

    Returns: No value returned

    """

    def extend(self, trumpet_classes: Iterable[Type[Trumpet]]) -> None:
        ### Loop through each trumpet class and register it one by one
        for trumpet_cls in trumpet_classes:
            self.register(trumpet_cls)

#$ End extend

    ###########################################################################

    """

    Name: create_all

    Function: Create an instance of every registered trumpet class. It's like

    spawning an army of scanners ready to find security issues.

    Arguments: None

    Returns: List of Trumpet instances

    """

    def create_all(self) -> List[Trumpet]:
        ### Create a new instance of each registered class and return them all
        return [cls() for cls in self._registry.values()]

#$ End create_all

    ###########################################################################

    """

    Name: slugs

    Function: Get a list of all the slugs (identifiers) for registered trumpets.

    Arguments: None

    Returns: List of strings (the slugs)

    """

    def slugs(self) -> List[str]:
        ### Return all the keys from our registry (which are the slugs)
        return list(self._registry.keys())

#$ End slugs

    ###########################################################################

    """

    Name: get

    Function: Retrieve a trumpet class by its slug. It's like looking up a

    phone number in the phone book, but for security scanners.

    Arguments: slug - the identifier string for the trumpet we want

    Returns: The Trumpet class associated with that slug

    """

    def get(self, slug: str) -> Type[Trumpet]:
        ### Look up and return the class from our registry
        return self._registry[slug]

#$ End get

#$ End TrumpetRegistry

###########################################################################

"""

Name: summarize

Function: Count up all the findings by their severity level. It's like counting

how many red, yellow, and green traffic lights you saw on your drive.

Arguments: findings - list of Finding objects to summarize

Returns: Dictionary with counts for each severity level

"""

def summarize(findings: List[Finding]) -> SeverityCounts:
    ### Initialize our counter dictionary with zeros for each severity
    counts: SeverityCounts = {"critical": 0, "warning": 0, "info": 0}
    ### Loop through each finding and increment the appropriate counter
    for finding in findings:
        ### Only count if the severity is one we're tracking
        if finding.severity in counts:
            counts[finding.severity] += 1
    ### Return the final counts
    return counts

#$ End summarize
