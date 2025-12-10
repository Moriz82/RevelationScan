# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the setuid trumpet. This module will allow the application to:

# 1. Find binaries with the setuid bit set (run as owner, not user)

# 2. Identify setuid binaries owned by non-root users (suspicious!)

# 3. Detect world-writable setuid binaries (very dangerous!)

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable, List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode

###########################################################################

"""

Name: SetuidTrumpet

Function: A trumpet that scans for setuid binaries. Setuid binaries run with

the owner's privileges, so if they're owned by non-root or are writable, that's

a security risk!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class SetuidTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "setuid"
    ### Human-readable title
    title = "Setuid Enumeration"
    ### Description of what this trumpet does
    description = "Surface setuid binaries with suspicious ownership or permissions."

    ### Directories to search for setuid binaries
    TARGETS: Iterable[Path] = (
        Path("/bin"),
        Path("/sbin"),
        Path("/usr/bin"),
        Path("/usr/sbin"),
        Path("/usr/local/bin"),
        Path("/usr/local/sbin"),
    )

    ### Maximum number of findings to return
    LIMIT = 50

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that walks through system directories

    looking for setuid binaries. It flags ones with suspicious ownership or

    permissions.

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing suspicious setuid binaries found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### List to collect our findings
        findings: List[Finding] = []
        ### Loop through each directory we want to search
        for target in self.TARGETS:
            ### Skip if the directory doesn't exist
            if not target.exists():
                continue
            ### Walk through all files in the directory
            for root, _, filenames in os.walk(target, followlinks=False):
                for name in filenames:
                    path = Path(root) / name
                    try:
                        ### Use lstat to avoid following symlinks
                        st = path.lstat()
                    except (FileNotFoundError, PermissionError, OSError):
                        ### If we can't stat it, skip it
                        continue
                    ### Check if the setuid bit is set
                    if not (st.st_mode & stat.S_ISUID):
                        continue
                    ### List to collect issues for this binary
                    issues: List[str] = []
                    severity = None
                    ### Check if it's owned by someone other than root
                    if st.st_uid != 0:
                        severity = severity or "warning"
                        issues.append(f"setuid owned by UID {st.st_uid}")
                    ### Check if it's world-writable (very dangerous!)
                    if st.st_mode & stat.S_IWOTH:
                        severity = "critical"
                        issues.append("world-writable")
                    ### If we found any issues, create a finding
                    if issues:
                        findings.append(
                            Finding(
                                severity=severity or "info",
                                title="Suspicious setuid binary",
                                details=[f"{path} ({'; '.join(issues)}; mode {human_mode(st.st_mode)})"],
                                remediation="Audit binary provenance and restrict permissions if not required.",
                            )
                        )
                        ### If we've hit our limit, stop searching
                        if len(findings) >= self.LIMIT:
                            return findings
        ### Return all findings we collected
        return findings

#$ End blow

#$ End SetuidTrumpet
