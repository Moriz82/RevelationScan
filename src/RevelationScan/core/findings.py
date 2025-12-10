# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the findings module. This module will allow the application to:

# 1. Define the Finding data structure (how we represent security issues)

# 2. Define the SeverityCounts type (for counting issues by severity)

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

###########################################################################

"""

Name: Finding

Function: A data class that represents a single security finding. It's like

a report card for a security issue - it tells you what's wrong, how bad it is,

and how to fix it.

Arguments: None (it's a dataclass, so it's just fields)

Returns: No value returned (it's a class definition)

"""

@dataclass
class Finding:
    ### How serious is this issue? (critical, warning, or info)
    severity: str
    ### A short title describing the issue (like "World-writable file found")
    title: str
    ### List of detail strings with more information about the issue
    details: List[str] = field(default_factory=list)
    ### Optional CVE identifier if this is related to a known vulnerability
    cve: Optional[str] = None
    ### Optional remediation advice (how to fix the problem)
    remediation: Optional[str] = None
    ### Optional exploit information (how bad guys might abuse this)
    exploit: Optional[str] = None

#$ End Finding

###########################################################################

"""

Name: SeverityCounts

Function: Type alias for a dictionary that counts findings by severity level.

It's like a scoreboard that shows how many critical, warning, and info issues

we found.

Arguments: None (it's a type alias)

Returns: No value returned

"""

SeverityCounts = dict[str, int]
