# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the world writable trumpet. This module will allow the application to:

# 1. Scan critical system directories for world-writable files and directories

# 2. Find files that anyone can modify (security risk!)

# 3. Report on insecure permissions in important system paths

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode

###########################################################################

"""

Name: WorldWritableTrumpet

Function: A trumpet that scans critical system directories for world-writable

files and directories. If anyone can write to system files, that's bad!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class WorldWritableTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "world_writable"
    ### Human-readable title
    title = "World Writable Files / Dir's"
    ### Description of what this trumpet does
    description = "Detect critical directories and files that anyone can alter."

    ### List of critical paths to check: (path, description)
    TARGETS = [
        (Path("/etc"), "system configuration"),
        (Path("/usr/local/bin"), "local executables"),
        (Path("/usr/local/sbin"), "local administrative executables"),
    ]

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that checks each target directory for

    world-writable files and directories. It's like checking if your house

    doors are locked!

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing world-writable issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### List to collect our findings
        findings: List[Finding] = []
        ### Loop through each target directory
        for root_path, label in self.TARGETS:
            ### Skip if the path doesn't exist
            if not root_path.exists():
                continue
            ### Collect all insecure files/directories under this path
            insecure = self._collect_insecure(root_path)
            ### If we found any, create a finding
            if insecure:
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"World-writable content under {root_path}",
                        details=[f"{entry} ({item_type}, mode {mode})" for entry, item_type, mode in insecure],
                        remediation="Tighten permissions with chmod/chown and audit the files for tampering.",
                    )
                )
        ### Return all findings we collected
        return findings

#$ End blow

    ###########################################################################

    """

    Name: _collect_insecure

    Function: Walk through a directory tree and collect all world-writable

    files and directories. Stops when we hit the limit.

    Arguments: target - the root path to scan

                limit - maximum number of items to collect

    Returns: List of tuples: (path, type, mode) for insecure items

    """

    def _collect_insecure(self, target: Path, limit: int = 30) -> List[tuple[str, str, str]]:
        ### List to collect insecure items
        insecure: List[tuple[str, str, str]] = []
        ### Walk through the directory tree
        for root, dirnames, filenames in os.walk(target, followlinks=False):
            ### Check directories first
            for name in dirnames:
                candidate = Path(root) / name
                ### If it's insecure, add it to our list
                if self._is_insecure(candidate):
                    insecure.append((str(candidate), "directory", human_mode(candidate.lstat().st_mode)))
                ### If we've hit the limit, stop searching
                if len(insecure) >= limit:
                    return insecure
            ### Check files
            for name in filenames:
                candidate = Path(root) / name
                ### If it's insecure, add it to our list
                if self._is_insecure(candidate):
                    insecure.append((str(candidate), "file", human_mode(candidate.lstat().st_mode)))
                ### If we've hit the limit, stop searching
                if len(insecure) >= limit:
                    return insecure
        ### Return all insecure items we found
        return insecure

#$ End _collect_insecure

    ###########################################################################

    """

    Name: _is_insecure

    Function: Check if a path is world-writable. Skips symlinks because we

    check the target separately.

    Arguments: path - the path to check

    Returns: Boolean - True if world-writable, False otherwise

    """

    @staticmethod
    def _is_insecure(path: Path) -> bool:
        try:
            ### Get file stats (use lstat to avoid following symlinks)
            st = path.lstat()
        except (FileNotFoundError, PermissionError, OSError):
            ### If we can't stat it, assume it's not insecure
            return False
        ### Skip symlinks (we check the target separately)
        if stat.S_ISLNK(st.st_mode):
            return False
        ### Check if world-writable bit is set
        return bool(st.st_mode & stat.S_IWOTH)

#$ End _is_insecure

#$ End WorldWritableTrumpet
