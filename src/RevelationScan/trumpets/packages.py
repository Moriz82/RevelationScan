# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the packages trumpet. This module will allow the application to:

# 1. Check when package metadata was last updated

# 2. Warn if package lists are stale (older than 30 days)

# 3. Remind users to run apt update to get latest vulnerability info

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding

###########################################################################

"""

Name: PackageMetadataTrumpet

Function: A trumpet that checks if APT package lists are up to date. Stale

package lists mean you might not know about the latest vulnerabilities!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class PackageMetadataTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "package_metadata"
    ### Human-readable title
    title = "Installed Packages Metadata"
    ### Description of what this trumpet does
    description = "Warn when local package indices appear stale."

    ### Path to the APT lists directory (where package metadata is stored)
    apt_lists = Path("/var/lib/apt/lists")

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that checks the age of APT package lists.

    If they're older than 30 days, it's time to update them!

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects (empty if lists are fresh, or one warning if stale)

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### If the apt lists directory doesn't exist, this isn't a Debian/Ubuntu system
        if not self.apt_lists.exists():
            return []
        ### Track the newest modification time we find
        newest_mtime = None
        ### Loop through all files in the apt lists directory
        for path in self.apt_lists.glob("**/*"):
            ### Skip directories
            if not path.is_file():
                continue
            try:
                ### Get the modification time of this file
                mtime = path.stat().st_mtime
            except (FileNotFoundError, PermissionError, OSError):
                ### If we can't stat it, skip it
                continue
            ### Update newest_mtime if this file is newer
            if newest_mtime is None or mtime > newest_mtime:
                newest_mtime = mtime
        ### If we didn't find any files, give up
        if newest_mtime is None:
            return []
        ### Get the current time
        now = datetime.now(timezone.utc).timestamp()
        ### Calculate how many days old the newest file is
        age_days = (now - newest_mtime) / 86400.0
        ### If it's less than 30 days old, we're good!
        if age_days <= 30:
            return []
        ### Otherwise, warn the user that their package lists are stale
        return [
            Finding(
                severity="warning",
                title="APT package lists appear stale",
                details=[f"Last update about {int(age_days)} days ago"],
                remediation="Run 'apt update' (or distribution equivalent) to refresh vulnerability data.",
            )
        ]

#$ End blow

#$ End PackageMetadataTrumpet
