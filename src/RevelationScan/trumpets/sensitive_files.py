# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the sensitive files trumpet. This module will allow the application to:

# 1. Check critical system files for overly permissive permissions

# 2. Verify /etc/passwd, /etc/shadow, and /etc/sudoers are properly protected

# 3. Report when these sensitive files are writable by non-root users

from __future__ import annotations

from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode

###########################################################################

"""

Name: SensitiveFilesTrumpet

Function: A trumpet that checks critical system files for insecure permissions.

Files like /etc/shadow should NEVER be writable by anyone except root!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class SensitiveFilesTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "sensitive_files"
    ### Human-readable title
    title = "File Permissions"
    ### Description of what this trumpet does
    description = "Confirm critical system files have restrictive permissions."

    ### List of files to check: (path, forbidden permission bits, description)
    TARGETS = [
        (Path("/etc/passwd"), 0o022, "should not be writable by group/others"),
        (Path("/etc/shadow"), 0o077, "should only be readable by root"),
        (Path("/etc/sudoers"), 0o022, "must remain immutable to non-root accounts"),
    ]

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that checks each sensitive file for

    overly permissive permissions. If these files are writable, bad things happen!

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing permission issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### List to collect our findings
        findings: List[Finding] = []
        ### Loop through each file we want to check
        for path, forbidden_bits, guidance in self.TARGETS:
            ### Skip if the file doesn't exist
            if not path.exists():
                continue
            try:
                ### Get file stats to check permissions
                st = path.stat()
            except (FileNotFoundError, PermissionError, OSError):
                ### If we can't stat it, skip it
                continue
            ### Check if the file has any of the forbidden permission bits set
            if st.st_mode & forbidden_bits:
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"Permissions too broad on {path}",
                        details=[f"Mode {human_mode(st.st_mode)} - {guidance}"],
                        remediation="Run 'chmod' to enforce least privilege and verify file integrity.",
                    )
                )
        ### Return all findings we collected
        return findings

#$ End blow

#$ End SensitiveFilesTrumpet
