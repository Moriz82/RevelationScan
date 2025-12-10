# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the path hygiene trumpet. This module will allow the application to:

# 1. Check PATH environment variable for security issues

# 2. Find relative paths (like ".") that allow command hijacking

# 3. Identify world-writable directories in PATH (security risk!)

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import List, Set

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode

###########################################################################

"""

Name: PathHygieneTrumpet

Function: A trumpet that checks the PATH environment variable for security issues.

If PATH has weak entries, attackers can hijack commands by placing malicious

binaries in those directories!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class PathHygieneTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "path_hygiene"
    ### Human-readable title
    title = "Path Hygiene Enumeration"
    ### Description of what this trumpet does
    description = "Highlight risky PATH entries that enable hijacking."

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that checks each entry in PATH for issues.

    It looks for relative paths, world-writable directories, and other problems.

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing PATH security issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### List to collect our findings
        findings: List[Finding] = []
        ### Set to track which paths we've already checked (avoid duplicates)
        seen: Set[Path] = set()
        ### Loop through each entry in the PATH environment variable
        for raw in os.environ.get("PATH", "").split(os.pathsep):
            ### Skip empty entries
            if not raw:
                continue
            ### Check for "." in PATH (very dangerous - allows hijacking!)
            if raw == ".":
                findings.append(
                    Finding(
                        severity="critical",
                        title="PATH contains relative entry",
                        details=["'.' allows command hijacking from the working directory."],
                        remediation="Remove '.' from PATH and reference binaries explicitly when needed.",
                    )
                )
                continue
            ### Expand ~ to home directory and create Path object
            path = Path(raw).expanduser()
            ### Check if it's not an absolute path (relative paths are risky)
            if not path.is_absolute():
                findings.append(
                    Finding(
                        severity="warning",
                        title="Non-absolute PATH entry",
                        details=[f"{raw} resolves to {path}"],
                        remediation="Use absolute paths to avoid unexpected resolution.",
                    )
                )
            try:
                ### Try to resolve the path (follow symlinks)
                resolved = path.resolve(strict=False)
            except RuntimeError:
                ### If resolution fails, just use the original path
                resolved = path
            ### Skip if we've already checked this resolved path
            if resolved in seen:
                continue
            ### Mark this path as seen
            seen.add(resolved)
            ### Check if the path doesn't exist (stale PATH entry)
            if not path.exists():
                findings.append(
                    Finding(
                        severity="warning",
                        title="Missing PATH directory",
                        details=[f"{path} does not exist"],
                        remediation="Prune stale PATH entries to speed up lookups and reduce confusion.",
                    )
                )
                continue
            try:
                ### Get file stats to check permissions
                st = path.stat()
            except (FileNotFoundError, PermissionError, OSError):
                ### If we can't stat it, skip it
                continue
            ### Skip if it's not a directory
            if not stat.S_ISDIR(st.st_mode):
                continue
            ### Initialize severity and details
            severity = None
            details: List[str] = []
            title = "PATH directory with weak permissions"
            ### Check if it's world-writable (very dangerous!)
            if st.st_mode & stat.S_IWOTH:
                severity = "critical"
                details.append("world-writable")
                title = "World-writable directory in PATH"
            ### Check ownership
            if st.st_uid != 0:
                context_note = f"owned by UID {st.st_uid}"
                ### If we're running as root, non-root ownership is more concerning
                if os.geteuid() == 0:
                    severity = "critical"
                else:
                    severity = severity or "info"
                    context_note += " (expected for user-local PATH)"
                details.append(context_note)
                ### If it's just info, update the title
                if severity == "info":
                    title = "User-owned directory in PATH"
            ### If we found any issues, create a finding
            if details:
                findings.append(
                    Finding(
                        severity=severity or "warning",
                        title=title,
                        details=[f"{path} ({', '.join(details)}; mode {human_mode(st.st_mode)})"],
                        remediation="Restrict permissions and ensure critical PATH entries are root-owned and non-writable.",
                    )
                )
        ### Return all findings we collected
        return findings

#$ End blow

#$ End PathHygieneTrumpet
