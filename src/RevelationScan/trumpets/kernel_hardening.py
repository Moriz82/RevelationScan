# -*- coding: utf-8 -*-

"""

@author: Will D

"""

# This is the kernel hardening trumpet. This module will allow the application to:

# 1. Check kernel sysctl settings for security hardening

# 2. Verify ASLR is enabled (Address Space Layout Randomization)

# 3. Check other kernel security flags (ptrace, module loading, etc.)

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from RevelationScan.core.base import ScanContext, Trumpet
from RevelationScan.core.findings import Finding

###########################################################################

"""

Name: KernelHardeningTrumpet

Function: A trumpet that checks kernel hardening settings. The kernel has lots

of security features, but they need to be enabled! This checks if they are.

Arguments: None (it's a class definition)

Returns: No value returned

"""

class KernelHardeningTrumpet(Trumpet):
    ### The unique identifier for this trumpet
    slug = "kernel_hardening"
    ### Human-readable title
    title = "Kernal flags"
    ### Description of what this trumpet does
    description = "Evaluate kernel sysctl flags tied to hardening and attack surface reduction."

    ### Dictionary mapping sysctl paths to (severity, title, remediation, expected_value)
    CHECKS = {
        Path("/proc/sys/kernel/randomize_va_space"): (
            "critical",
            "ASLR disabled",
            "Enable ASLR by setting kernel.randomize_va_space=2.",
            "2",
        ),
        Path("/proc/sys/kernel/kptr_restrict"): (
            "warning",
            "Kernel pointer exposure",
            "Set kernel.kptr_restrict=1 to hide kernel addresses from unprivileged users.",
            {"1", "2"},
        ),
        Path("/proc/sys/kernel/yama/ptrace_scope"): (
            "warning",
            "ptrace scope permissive",
            "Set kernel.yama.ptrace_scope=1 or higher to restrict cross-process debugging.",
            {"1", "2", "3"},
        ),
        Path("/proc/sys/kernel/modules_disabled"): (
            "info",
            "Kernel modules can be loaded",
            "Consider disabling module loading in hardened environments (modules_disabled=1).",
            {"1"},
        ),
        Path("/proc/sys/net/ipv4/ip_forward"): (
            "warning",
            "IPv4 forwarding enabled",
            "Disable ipv4 forwarding unless system acts as router (net.ipv4.ip_forward=0).",
            {"0"},
        ),
    }

    ###########################################################################

    """

    Name: blow

    Function: The main scanning method that checks all kernel hardening settings.

    It reads values from /proc/sys and compares them to expected secure values.

    Arguments: context - the ScanContext object with all our config

    Returns: List of Finding objects representing kernel hardening issues found

    """

    def blow(self, context: ScanContext) -> List[Finding]:
        ### List to collect our findings
        findings: List[Finding] = []
        ### Loop through each sysctl setting we want to check
        for path, (severity, title, remediation, expected) in self.CHECKS.items():
            ### Read the current value from the sysctl file
            value = self._read_value(path)
            ### If we couldn't read it, skip it
            if value is None:
                continue
            desired = expected
            ### If expected is a set, check if value is in the set
            if isinstance(desired, set):
                compliant = value in desired
            else:
                ### Otherwise, check if value equals expected
                compliant = value == desired
            ### If the setting is not compliant (not secure), create a finding
            if not compliant:
                findings.append(
                    Finding(
                        severity=severity,
                        title=title,
                        details=[f"{path}: current={value}"],
                        remediation=remediation,
                    )
                )
        ### Return all findings we collected
        return findings

#$ End blow

    ###########################################################################

    """

    Name: _read_value

    Function: Helper method to read a value from a sysctl file in /proc/sys.

    Arguments: path - path to the sysctl file to read

    Returns: String value from the file, or None if we can't read it

    """

    @staticmethod
    def _read_value(path: Path) -> Optional[str]:
        try:
            ### Read the file and strip whitespace
            return path.read_text(encoding="utf-8").strip()
        except (FileNotFoundError, PermissionError, OSError):
            ### If we can't read it, return None
            return None

#$ End _read_value

#$ End KernelHardeningTrumpet
