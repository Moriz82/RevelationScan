# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the writable devices trumpet. This module will allow the application to:

# 1. Scan /dev for world-writable device nodes

# 2. Find device files that anyone can write to (security risk!)

# 3. Report on potentially dangerous device permissions

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding
from RevelationScan.core.utils import human_mode, owner_label

###########################################################################

"""

Name: WritableDevicesTrumpet

Function: A trumpet that scans /dev for world-writable device nodes. Device

nodes that are writable by anyone can be dangerous - they give direct hardware access!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class WritableDevicesTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "writable_devices"
    ### Human-readable title
    title = "Writable / Mountable Devices"
    ### Description of what this trumpet does
    description = "Identify world-writable device nodes that could grant direct hardware access."

    ### Root directory to scan (where all device nodes live)
    ROOT = Path("/dev")
    ### Maximum number of findings to return
    LIMIT = 80
    ### List of device nodes that are normally world-writable (these are OK)
    BASELINE = {
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
        "/dev/ptmx",
        "/dev/net/tun",
    }

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that walks through /dev looking for

    world-writable device nodes. Some devices are OK to be writable, but most aren't!

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing device permission issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### List to collect our findings
        findings: List[Finding] = []
        ### Walk through the /dev directory
        for root, _, filenames in os.walk(self.ROOT, followlinks=False):
            for name in filenames:
                path = Path(root) / name
                ### If we've hit our limit, stop searching
                if len(findings) >= self.LIMIT:
                    return findings
                try:
                    ### Get file stats (use lstat to avoid following symlinks)
                    st = path.lstat()
                except (FileNotFoundError, PermissionError, OSError):
                    ### If we can't stat it, skip it
                    continue
                ### Only care about character devices and block devices
                if not stat.S_ISCHR(st.st_mode) and not stat.S_ISBLK(st.st_mode):
                    continue
                ### Check if it's world-writable
                if st.st_mode & 0o002:
                    canonical = str(path)
                    ### Character devices are more dangerous than block devices
                    severity = "critical" if stat.S_ISCHR(st.st_mode) else "warning"
                    ### If it's a baseline device (normally writable), downgrade to info
                    if canonical in self.BASELINE:
                        severity = "info"
                    ### Some devices like nvidia, dri, fuse are often writable (less concerning)
                    elif "nvidia" in canonical or "dri" in canonical or "fuse" in canonical:
                        severity = "warning"
                    ### vhost devices are also often writable
                    elif "vhost" in canonical:
                        severity = "warning"
                    ### Create a finding for this device
                    findings.append(
                        Finding(
                            severity=severity,
                            title="World-writable device node",
                            details=[
                                f"{path} owner {owner_label(st.st_uid, st.st_gid)} mode {human_mode(st.st_mode)}",
                            ],
                            remediation="Restrict device permissions or remove unneeded device nodes.",
                        )
                    )
        ### Return all findings we collected
        return findings

#$ End blow

#$ End WritableDevicesTrumpet
