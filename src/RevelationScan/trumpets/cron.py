# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the cron trumpet. This module will allow the application to:

# 1. Scan cron configuration files and directories for permission issues

# 2. Find cron jobs that are writable by non-root users (security risk!)

# 3. Check ownership of cron files (they should be owned by root)

from __future__ import annotations

from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode, owner_label

###########################################################################

"""

Name: CronTrumpet

Function: A trumpet that checks cron configuration files and directories for

insecure permissions. Cron jobs run as root, so if they're writable by others,

that's a big problem!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class CronTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "cron"
    ### Human-readable title
    title = "CronJobs Enumeration"
    ### Description of what this trumpet does
    description = "Review cron artifacts for permissive ownership or modes."

    ### List of cron-related paths to check (path and description)
    TARGETS = [
        (Path("/etc/crontab"), "system crontab"),
        (Path("/etc/cron.allow"), "cron allow list"),
        (Path("/etc/cron.deny"), "cron deny list"),
        (Path("/etc/cron.d"), "cron.d directory"),
        (Path("/etc/cron.daily"), "daily jobs"),
        (Path("/etc/cron.hourly"), "hourly jobs"),
        (Path("/etc/cron.weekly"), "weekly jobs"),
        (Path("/etc/cron.monthly"), "monthly jobs"),
    ]

    ### Maximum number of findings to return (don't overwhelm the user!)
    LIMIT = 60

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that checks all cron-related files and

    directories for permission issues. It's like being a security guard checking

    who has keys to the server room!

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing cron permission issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### List to collect our findings
        findings: List[Finding] = []
        ### Loop through each target path we want to check
        for target, label in self.TARGETS:
            ### Skip if the path doesn't exist
            if not target.exists():
                continue
            try:
                ### Get file stats (permissions, ownership, etc.)
                st = target.stat()
            except (FileNotFoundError, PermissionError, OSError):
                ### If we can't stat it, skip it
                continue
            ### List to collect issues found for this target
            issues: List[str] = []
            severity = None
            ### Check if it's owned by someone other than root (bad!)
            if st.st_uid != 0:
                severity = "critical"
                issues.append("owned by non-root user")
            ### Check if it's world-writable (very bad!)
            if st.st_mode & 0o002:
                severity = "critical"
                issues.append("world-writable")
            ### Check if it's group-writable (less bad, but still concerning)
            elif st.st_mode & 0o020:
                severity = severity or "warning"
                issues.append("group-writable")
            ### If we found any issues, create a finding
            if issues:
                findings.append(
                    Finding(
                        severity=severity or "warning",
                        title="Insecure cron metadata",
                        details=[
                            f"{target} ({label}) owner {owner_label(st.st_uid, st.st_gid)} mode {human_mode(st.st_mode)} - {', '.join(issues)}",
                        ],
                        remediation="Reset ownership to root:root and chmod 600/700 as appropriate.",
                    )
                )
                ### If we've hit our limit, stop scanning
                if len(findings) >= self.LIMIT:
                    return findings
            ### If this is a directory, check all files inside it
            if target.is_dir():
                for entry in sorted(target.iterdir()):
                    ### Check limit again
                    if len(findings) >= self.LIMIT:
                        return findings
                    ### Skip subdirectories
                    if entry.is_dir():
                        continue
                    try:
                        ### Get stats for this entry
                        st_entry = entry.stat()
                    except (FileNotFoundError, PermissionError, OSError):
                        ### If we can't stat it, skip it
                        continue
                    ### List to collect issues for this entry
                    entry_issues: List[str] = []
                    entry_severity = None
                    ### Check ownership
                    if st_entry.st_uid != 0:
                        entry_severity = entry_severity or "warning"
                        entry_issues.append("owned by non-root user")
                    ### Check world-writable
                    if st_entry.st_mode & 0o002:
                        entry_severity = "critical"
                        entry_issues.append("world-writable")
                    ### Check group-writable
                    elif st_entry.st_mode & 0o020:
                        entry_severity = entry_severity or "warning"
                        entry_issues.append("group-writable")
                    ### If we found issues, create a finding
                    if entry_issues:
                        findings.append(
                            Finding(
                                severity=entry_severity or "warning",
                                title="Cron job with weak permissions",
                                details=[
                                    f"{entry} owner {owner_label(st_entry.st_uid, st_entry.st_gid)} mode {human_mode(st_entry.st_mode)} - {', '.join(entry_issues)}",
                                ],
                                remediation="Ensure cron jobs are root-owned and not writable by untrusted users.",
                            )
                        )
        ### Return all findings we collected
        return findings

#$ End blow

#$ End CronTrumpet
