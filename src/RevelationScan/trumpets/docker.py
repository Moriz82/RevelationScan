# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the docker trumpet. This module will allow the application to:

# 1. Check if the Docker socket is accessible to non-root users

# 2. Detect if the current user is in the docker group (security risk!)

# 3. Report on Docker socket permissions (should be root-only!)

from __future__ import annotations

import os
from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode, owner_label

###########################################################################

"""

Name: DockerTrumpet

Function: A trumpet that checks Docker socket permissions. If the Docker socket

is accessible to non-root users, they can basically become root! That's bad!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class DockerTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "docker"
    ### Human-readable title
    title = "Docker Detection and Enumeration"
    ### Description of what this trumpet does
    description = "Detect broad access to the Docker sockets"

    ### Path to the Docker socket (where Docker listens for commands)
    socket_path = Path("/var/run/docker.sock")

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that checks Docker socket permissions.

    If anyone can access it, they can run containers as root. Yikes!

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing Docker access issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### If the socket doesn't exist, Docker probably isn't running
        if not self.socket_path.exists():
            return []
        try:
            ### Get file stats to check permissions
            st = self.socket_path.stat()
        except (FileNotFoundError, PermissionError, OSError):
            ### If we can't stat it, give up
            return []
        ### List to collect issues we find
        issues: List[str] = []
        severity = None
        ### Check if it's world-writable (anyone can write to it - very bad!)
        if st.st_mode & 0o002:
            severity = "critical"
            issues.append("world-writable")
        ### Check if it's group-writable (less bad, but still concerning)
        if st.st_mode & 0o020:
            severity = severity or "warning"
            issues.append("group-writable")
        ### Get the current user's effective UID (if available)
        current_euid = os.geteuid() if hasattr(os, "geteuid") else None
        ### If we're not root, check if we have access
        if current_euid not in {None, 0}:
            ### Get the current user's groups
            groups = set(os.getgroups()) if hasattr(os, "getgroups") else set()
            ### Check if we're in the docker group (gives us access!)
            if st.st_gid in groups:
                severity = severity or "warning"
                issues.append("current user in docker group")
            ### Check if we own the socket (also gives us access!)
            if st.st_uid == current_euid:
                severity = severity or "info"
                issues.append("current user owns docker socket")
        ### If we didn't find any issues, return empty list
        if not issues:
            return []
        ### Return a finding about the Docker socket access
        return [
            Finding(
                severity=severity or "info",
                title="Docker socket accessible",
                details=[
                    f"{self.socket_path} owner {owner_label(st.st_uid, st.st_gid)} mode {human_mode(st.st_mode)} - {', '.join(issues)}",
                ],
                remediation="Restrict docker.sock to root-only or use rootless Docker.",
                exploit="gaining docker group access often grants root via mounting the host filesystem",
            )
        ]

#$ End blow

#$ End DockerTrumpet
