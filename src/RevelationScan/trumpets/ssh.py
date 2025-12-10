# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the SSH trumpet. This module will allow the application to:

# 1. Check SSH daemon configuration for insecure settings

# 2. Find if root login is allowed (bad practice!)

# 3. Detect password authentication and empty password settings

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding

###########################################################################

"""

Name: SSHConfigTrumpet

Function: A trumpet that checks SSH daemon configuration. SSH is how most people

access servers, so misconfigurations can be a big security risk!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class SSHConfigTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "ssh_config"
    ### Human-readable title
    title = "SSH Misconfiguration"
    ### Description of what this trumpet does
    description = "Report permissive sshd_config options."

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that reads sshd_config and checks for

    insecure settings. It looks for things like root login, password auth, etc.

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing SSH misconfigurations found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### Path to the SSH daemon configuration file
        config_path = Path("/etc/ssh/sshd_config")
        ### If the file doesn't exist, SSH probably isn't configured
        if not config_path.exists():
            return []
        try:
            ### Read all lines from the config file
            lines = config_path.read_text(errors="ignore").splitlines()
        except (FileNotFoundError, PermissionError, OSError):
            ### If we can't read it, give up
            return []
        ### Dictionary to store parsed settings
        settings: Dict[str, str] = {}
        ### Parse each line
        for line in lines:
            ### Remove comments (everything after #)
            trimmed = line.split("#", 1)[0].strip()
            ### Skip empty lines
            if not trimmed:
                continue
            ### Split into key and value
            parts = trimmed.split(None, 1)
            if not parts:
                continue
            ### Normalize key to lowercase
            key = parts[0].lower()
            ### Get value (also lowercase) or empty string if no value
            value = parts[1].strip().lower() if len(parts) > 1 else ""
            ### Store the setting
            settings[key] = value
        ### List to collect our findings
        findings: List[Finding] = []
        ### Check PermitRootLogin setting
        root_login = settings.get("permitrootlogin")
        ### If root login is explicitly allowed with passwords, that's critical!
        if root_login == "yes":
            findings.append(
                Finding(
                    severity="critical",
                    title="SSH permits direct root login",
                    details=[f"PermitRootLogin {root_login}"],
                    remediation="Set PermitRootLogin prohibit-password or no and use sudo escalation instead.",
                )
            )
        ### If root login is allowed with keys only, it's less bad but still concerning
        elif root_login in {"without-password", "withoutpassword"}:
            findings.append(
                Finding(
                    severity="warning",
                    title="SSH root login allowed with keys",
                    details=[f"PermitRootLogin {root_login}"],
                    remediation="Consider disabling direct root SSH access entirely.",
                )
            )
        ### Check PasswordAuthentication setting
        password_auth = settings.get("passwordauthentication")
        ### If password authentication is enabled, that's a warning
        if password_auth == "yes":
            findings.append(
                Finding(
                    severity="warning",
                    title="SSH password authentication enabled",
                    details=["PasswordAuthentication yes"],
                    remediation="Set PasswordAuthentication no after ensuring key-based access is configured.",
                )
            )
        ### Check PermitEmptyPasswords setting
        if settings.get("permitemptypasswords") == "yes":
            findings.append(
                Finding(
                    severity="critical",
                    title="SSH allows empty passwords",
                    details=["PermitEmptyPasswords yes"],
                    remediation="Set PermitEmptyPasswords no and audit user accounts.",
                )
            )
        ### Return all findings we collected
        return findings

#$ End blow

#$ End SSHConfigTrumpet
