# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the systemd trumpet. This module will allow the application to:

# 1. Check systemd service files for unquoted ExecStart paths

# 2. Find paths with spaces that aren't quoted (can lead to hijacking!)

# 3. Report on potentially unsafe systemd configurations

from __future__ import annotations

from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding

###########################################################################

"""

Name: SystemdExecTrumpet

Function: A trumpet that checks systemd service files for unquoted ExecStart

paths. If a path has spaces and isn't quoted, it can be hijacked!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class SystemdExecTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "systemd_exec"
    ### Human-readable title
    title = "Systemd Hijacking"
    ### Description of what this trumpet does
    description = "Check for unquoted ExecStart paths that contain spaces."

    ### Directories where systemd service files are stored
    DIRECTORIES = [
        Path("/etc/systemd/system"),
        Path("/lib/systemd/system"),
        Path("/usr/lib/systemd/system"),
    ]

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that searches for systemd service files

    and checks ExecStart directives for unquoted paths with spaces.

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing systemd issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### List to collect our findings
        findings: List[Finding] = []
        ### Loop through each directory where service files might be
        for directory in self.DIRECTORIES:
            ### Skip if the directory doesn't exist
            if not directory.exists():
                continue
            ### Find all .service files recursively
            for service_file in directory.rglob("*.service"):
                try:
                    ### Read all lines from the service file
                    lines = service_file.read_text(errors="ignore").splitlines()
                except (FileNotFoundError, PermissionError, OSError):
                    ### If we can't read it, skip it
                    continue
                ### Check each line
                for line in lines:
                    stripped = line.strip()
                    ### Only care about ExecStart lines
                    if not stripped.startswith("ExecStart="):
                        continue
                    ### Get the command part (everything after =)
                    command = stripped.split("=", 1)[1].lstrip()
                    ### Skip if it starts with - (that's a flag, not the command)
                    if command.startswith("-"):
                        command = command[1:].lstrip()
                    ### Skip if it's empty or already quoted
                    if not command or command.startswith("\""):
                        continue
                    ### Get the first token (the path/command)
                    first_token = command.split()[0]
                    ### If the first token has spaces, it's not quoted (problem!)
                    if " " in first_token:
                        findings.append(
                            Finding(
                                severity="warning",
                                title="Potentially unsafe ExecStart path",
                                details=[f"{service_file}: {first_token} contains spaces but is not quoted"],
                                remediation="Quote paths with spaces in service unit ExecStart directives.",
                            )
                        )
        ### Return all findings we collected
        return findings

#$ End blow

#$ End SystemdExecTrumpet
