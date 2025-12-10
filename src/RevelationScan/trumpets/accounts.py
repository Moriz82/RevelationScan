# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the accounts trumpet. This module will allow the application to:

# 1. Scan /etc/passwd for account misconfigurations

# 2. Find accounts with UID 0 (root privileges) that aren't actually root

# 3. Identify service accounts with interactive shells (bad practice!)

# 4. Report on user accounts that might be security risks

from __future__ import annotations

from pathlib import Path
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding

###########################################################################

"""

Name: AccountsTrumpet

Function: A trumpet that checks /etc/passwd for suspicious account configurations.

It looks for things like extra root accounts, service accounts with shells, etc.

Arguments: None (it's a class definition)

Returns: No value returned

"""

class AccountsTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "accounts"
    ### Human-readable title
    title = "Account Misconfigurations"
    ### Description of what this trumpet does
    description = "Inspect /etc/passwd for privileged or login-capable service accounts."

    ### Path to the passwd file (where all the user accounts are stored)
    passwd_path = Path("/etc/passwd")

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that reads /etc/passwd and finds account

    misconfigurations. It's like being a security guard checking IDs at the door.

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing account issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### If the passwd file doesn't exist, we can't do anything
        if not self.passwd_path.exists():
            return []
        try:
            ### Read all the lines from the passwd file
            lines = self.passwd_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except (FileNotFoundError, PermissionError, OSError):
            ### If we can't read it, just return empty list
            return []
        ### List to collect our findings
        findings: List[Finding] = []
        ### Shells that are considered "safe" for service accounts (non-interactive)
        allowed_shells = {"/usr/sbin/nologin", "/bin/false", "", "/usr/bin/nologin"}
        ### Loop through each line in the passwd file
        for line in lines:
            ### Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            ### Split the line by colons (passwd format is colon-separated)
            parts = line.split(":")
            ### Need at least 7 fields (user:pass:uid:gid:desc:home:shell)
            if len(parts) < 7:
                continue
            ### Unpack the fields (we ignore the password field with _)
            user, _, uid, gid, desc, home, shell = parts
            try:
                ### Convert UID to integer so we can compare it
                uid_int = int(uid)
            except ValueError:
                ### If it's not a number, skip this line
                continue
            ### Strip whitespace from the shell field
            shell = shell.strip()
            ### Check if this is a UID 0 account that isn't root (very suspicious!)
            if uid_int == 0 and user != "root":
                findings.append(
                    Finding(
                        severity="critical",
                        title="Additional UID 0 account",
                        details=[f"{user} ({desc}) shell={shell}"],
                        remediation="Remove extra UID 0 accounts or adjust UID to non-privileged value.",
                        exploit="Use alternate root account to bypass sudo policies.",
                    )
                )
                continue
            ### Check if this is a regular user (UID >= 1000) with an interactive shell
            if uid_int >= 1000 and shell not in allowed_shells:
                ### If it's a service account, it's more concerning
                if desc.lower().startswith("service"):
                    severity = "warning"
                else:
                    severity = "info"
                findings.append(
                    Finding(
                        severity=severity,
                        title="Interactive user account",
                        details=[f"{user} home={home} shell={shell}"],
                        remediation="Verify onboarding/offboarding and enforce strong credentials.",
                    )
                )
            ### Check if a daemon/service account has an interactive shell (bad!)
            if shell in {"/bin/sh", "/bin/bash"} and desc.lower().startswith("daemon"):
                findings.append(
                    Finding(
                        severity="warning",
                        title="Service account with interactive shell",
                        details=[f"{user} shell={shell}"],
                        remediation="Set shell to /usr/sbin/nologin for service accounts.",
                    )
                )
        ### Return all the findings we collected
        return findings

#$ End blow

#$ End AccountsTrumpet
