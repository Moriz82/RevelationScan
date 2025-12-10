# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the capabilities trumpet. This module will allow the application to:

# 1. Find binaries with Linux capabilities (special permissions)

# 2. Identify dangerous capabilities that could allow privilege escalation

# 3. Report on files that have capabilities set (which is often unnecessary)

from __future__ import annotations

import shutil
import subprocess
from typing import List

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding

###########################################################################

"""

Name: CapabilitiesTrumpet

Function: A trumpet that scans for binaries with Linux capabilities set. Capabilities

are like superpowers for binaries - they can do things without being root!

Arguments: None (it's a class definition)

Returns: No value returned

"""

class CapabilitiesTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "capabilities"
    ### Human-readable title
    title = "Capabilities Enumeration"
    ### Description of what this trumpet does
    description = "Detect binaries granted ambient Linux capabilities that may allow privilege escalation."

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that uses getcap to find binaries with

    capabilities. It's like using a metal detector to find hidden superpowers!

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing capability issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### Check if getcap command is available (we need it to scan)
        if not shutil.which("getcap"):
            return []
        try:
            ### Run getcap recursively on the root directory to find all capabilities
            completed = subprocess.run(
                ["getcap", "-r", "/"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.SubprocessError, PermissionError) as exc:
            ### If getcap fails, report it as an info finding
            return [
                Finding(
                    severity="info",
                    title="Unable to enumerate capabilities",
                    details=[f"getcap failed: {exc}"],
                )
            ]
        ### Split the output into lines
        entries = completed.stdout.splitlines()
        ### List to collect our findings
        findings: List[Finding] = []
        ### Process each line from getcap output
        for line in entries:
            ### Strip whitespace
            line = line.strip()
            ### Skip empty lines
            if not line:
                continue
            ### Split by " = " to separate path from capabilities
            parts = line.split(" = ", 1)
            ### Need exactly 2 parts (path and capabilities)
            if len(parts) != 2:
                continue
            path, caps = parts
            ### Default to warning severity
            severity = "warning"
            ### Check for really dangerous capabilities that could lead to root
            if any(flag in caps for flag in ("cap_dac_read_search", "cap_setuid", "cap_sys_admin")):
                severity = "critical"
            findings.append(
                Finding(
                    severity=severity,
                    title="Binary with elevated capabilities",
                    details=[f"{path} => {caps}"],
                    remediation="Review necessity of capabilities or drop them with setcap -r.",
                    exploit="Leverage capability to bypass DAC or escalate privileges.",
                )
            )
        ### Return findings, but limit to first 100 (don't spam the user!)
        return findings[:100]

#$ End blow

#$ End CapabilitiesTrumpet
