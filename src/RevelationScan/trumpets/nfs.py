# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the NFS trumpet. This module will allow the application to:

# 1. Scan NFS export configuration for security issues

# 2. Find exports with no_root_squash (allows root access - bad!)

# 3. Identify exports that allow wildcard clients (too permissive!)

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding

###########################################################################

"""

Name: NFSTrumpet

Function: A trumpet that checks NFS export configuration. NFS can be dangerous

if misconfigured - it can allow root access or expose files to everyone!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class NFSTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "nfs"
    ### Human-readable title
    title = "Network File Shares (NFS)"
    ### Description of what this trumpet does
    description = "Highlight NFS exports that weaken root or allow wildcards."

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that reads /etc/exports and looks for

    insecure configurations. It's like checking if your file server is properly

    locked down!

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing NFS security issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### Path to the NFS exports configuration file
        exports_path = Path("/etc/exports")
        ### If the file doesn't exist, NFS probably isn't configured
        if not exports_path.exists():
            return []
        try:
            ### Read all lines from the exports file
            lines = exports_path.read_text(errors="ignore").splitlines()
        except (FileNotFoundError, PermissionError, OSError):
            ### If we can't read it, give up
            return []
        ### List to collect our findings
        findings: List[Finding] = []
        ### Loop through each line with its line number
        for idx, line in enumerate(lines, start=1):
            ### Strip whitespace
            stripped = line.strip()
            ### Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue
            ### Create a display string with file path and line number
            display = f"{exports_path}:{idx} {stripped}"
            ### Check for no_root_squash (very dangerous - allows root access!)
            if "no_root_squash" in stripped:
                findings.append(
                    Finding(
                        severity="critical",
                        title="NFS export without root squashing",
                        details=[display],
                        remediation="Add 'root_squash' to prevent clients from mapping root to root.",
                        exploit="Mount export and escalate privileges using preserved root permissions.",
                    )
                )
            ### Check for wildcard clients (too permissive - allows anyone!)
            elif re.search(r"\*(\s*\(|\s)", stripped):
                findings.append(
                    Finding(
                        severity="warning",
                        title="NFS export allows wildcard clients",
                        details=[display],
                        remediation="Restrict allowed hosts to explicit addresses or subnets.",
                    )
                )
        ### Return all findings we collected
        return findings

#$ End blow

#$ End NFSTrumpet
